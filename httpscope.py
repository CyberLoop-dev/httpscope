#!/usr/bin/env python3
"""httpscope: see where every millisecond of an HTTP request goes."""
import argparse
import json
import socket
import ssl
import statistics
import sys
import time
import urllib.parse

PHASES = ["dns", "connect", "tls", "wait", "download"]
LABELS = {"dns": "dns", "connect": "connect", "tls": "tls", "wait": "wait (ttfb)", "download": "download"}
COLORS = {"dns": "\033[95m", "connect": "\033[94m", "tls": "\033[96m",
          "wait": "\033[93m", "download": "\033[92m"}
RESET, DIM, RED = "\033[0m", "\033[2m", "\033[91m"


def probe(url, timeout):
    u = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    https = u.scheme == "https"
    host, port = u.hostname, u.port or (443 if https else 80)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    t = {p: 0.0 for p in PHASES}
    sock = None
    try:
        t0 = time.perf_counter()
        family, stype, proto, _, addr = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
        t["dns"] = time.perf_counter() - t0

        sock = socket.socket(family, stype, proto)
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.connect(addr)
        t["connect"] = time.perf_counter() - t0

        tls_version = None
        if https:
            t0 = time.perf_counter()
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            t["tls"] = time.perf_counter() - t0
            tls_version = sock.version()

        req = (f"GET {path} HTTP/1.1\r\nHost: {u.netloc}\r\nUser-Agent: httpscope/1.0\r\n"
               "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
        t0 = time.perf_counter()
        sock.sendall(req.encode())
        first = sock.recv(65536)
        t["wait"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        size = len(first)
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            size += len(chunk)
        t["download"] = time.perf_counter() - t0

        status = first.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return {"ok": True, "phases": t, "total": sum(t.values()), "status": status,
                "bytes": size, "ip": addr[0], "tls": tls_version}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        if sock:
            sock.close()


def pct(values, p):
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p * (len(s) - 1))))]


def summarize(url, runs):
    good = [r for r in runs if r["ok"]]
    if not good:
        return {"url": url, "ok": False, "error": runs[-1]["error"]}
    med = {p: statistics.median(r["phases"][p] for r in good) for p in PHASES}
    totals = [r["total"] for r in good]
    last = good[-1]
    return {"url": url, "ok": True, "runs": len(good), "failed": len(runs) - len(good),
            "status": last["status"], "ip": last["ip"], "tls": last["tls"], "bytes": last["bytes"],
            "median_ms": {p: round(v * 1000, 1) for p, v in med.items()},
            "total_median_ms": round(statistics.median(totals) * 1000, 1),
            "total_p95_ms": round(pct(totals, 0.95) * 1000, 1)}


def show(s):
    if not s["ok"]:
        print(f"\n{s['url']}\n  {RED}failed: {s['error']}{RESET}")
        return
    tls = f"  {s['tls']}" if s["tls"] else ""
    print(f"\n{s['url']}  {s['status']}  {DIM}{s['ip']}{tls}  {s['bytes']:,} bytes  "
          f"(median of {s['runs']}){RESET}")
    total = s["total_median_ms"] or 1
    for p in PHASES:
        v = s["median_ms"][p]
        if p == "tls" and not s["tls"]:
            continue
        bar = "█" * (max(1, round(v / total * 40)) if v > 0 else 0)
        print(f"  {LABELS[p]:<12} {v:>8.1f} ms  {COLORS[p]}{bar}{RESET}")
    print(f"  {'total':<12} {s['total_median_ms']:>8.1f} ms  {DIM}p95 {s['total_p95_ms']} ms{RESET}")


def main():
    ap = argparse.ArgumentParser(description="Break an HTTP request into timed phases.")
    ap.add_argument("urls", nargs="+")
    ap.add_argument("-n", "--runs", type=int, default=5, help="requests per URL (default 5)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--max-total", type=float, help="exit 1 if median total exceeds this many ms")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    results = [summarize(u, [probe(u, a.timeout) for _ in range(max(1, a.runs))]) for u in a.urls]
    if a.json:
        print(json.dumps(results, indent=2))
    else:
        for s in results:
            show(s)
    bad = any(not s["ok"] for s in results)
    slow = a.max_total is not None and any(s["ok"] and s["total_median_ms"] > a.max_total for s in results)
    sys.exit(1 if bad or slow else 0)


if __name__ == "__main__":
    main()
