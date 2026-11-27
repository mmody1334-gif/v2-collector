#!/usr/bin/env python3
"""
Clean IP — بيجمع آي بيهات كلاودفلير النظيفة: بيختبر إنها شغالة فعلاً (TLS على 443)،
وبيسأل قاعدة كشف VPN/Proxy إذا كانت متعلمة عليها ولا لأ، وبيطلع cleanip.txt و cleanip.json.

Usage:
  python scripts/cleanip.py --manual cleanip-manual.txt --sources cleanip-sources.txt --out out

المصادر:
  1) cleanip-manual.txt  — آي بيهاتك اللي جربتها بنفسك (بتتثبت أول القايمة).
  2) cleanip-sources.txt — لينكات قوايم عامة بتتنشر دوريًا (بنطلع الآي بيهات منها بريجيكس).
  3) سامبلنج من رينجات كلاودفلير الرسمية (احتياطي لو القوايم وقعت).
"""
import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.request
from datetime import datetime, timezone

# ---- limits (عدّلها براحتك) ----
TCP_TIMEOUT = 3.0        # ثواني
MAX_CANDIDATES = 3000    # أقصى عدد مرشحين يتختبروا
CONCURRENCY = 400
LIMIT = 100              # أقصى عدد آي بيهات في الناتج
TRACE_HOST = "www.cloudflare.com"

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# رينجات كلاودفلير الرسمية (https://www.cloudflare.com/ips-v4)
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
# رينجات WARP المعروفة — بتتفحص كاملة لأنها صغيرة
WARP_24 = ["162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24",
           "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24"]
SAMPLE_HOSTS = (1, 17, 53, 101, 157, 233)

CTX = ssl.create_default_context()


def log(*a):
    print(*a, flush=True)


def ok_ip(s):
    try:
        return ipaddress.IPv4Address(s).is_global
    except Exception:
        return False


# ---------------------------------------------------------------- candidates
def read_manual(path):
    ips = []
    if not os.path.exists(path):
        return ips
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if line and ok_ip(line):
                ips.append(line)
    return ips


def read_sources(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def fetch_ips(url):
    req = urllib.request.Request(url, headers={"User-Agent": "v2-collector/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        text = r.read(10 * 1024 * 1024).decode("utf-8", "ignore")
    return [m for m in IPV4_RE.findall(text) if ok_ip(m)]


def sample_cf():
    out = []
    for cidr in WARP_24:
        net = ipaddress.ip_network(cidr)
        out.extend(str(ip) for ip in net.hosts())
    for cidr in CF_RANGES:
        net = ipaddress.ip_network(cidr)
        subs = list(net.subnets(new_prefix=24))
        for s in subs[:8] + subs[-2:]:          # أول ٨ وآخر ٢ شبكات /24 من كل رينج
            base = int(s.network_address)
            for h in SAMPLE_HOSTS:
                out.append(str(ipaddress.IPv4Address(base + h)))
    return out


# ---------------------------------------------------------------- testing
def test(ip):
    """TLS على 443 بـ SNI كلاودفلير وطلب /cdn-cgi/trace — بيرجع البينج بالـ ms أو None."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, 443), timeout=TCP_TIMEOUT) as sock:
            with CTX.wrap_socket(sock, server_hostname=TRACE_HOST) as tls:
                tls.settimeout(TCP_TIMEOUT)
                tls.sendall((
                    f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {TRACE_HOST}\r\n"
                    "Connection: close\r\nUser-Agent: v2-collector/1.0\r\n\r\n"
                ).encode())
                data = b""
                while len(data) < 4096:
                    chunk = tls.recv(2048)
                    if not chunk:
                        break
                    data += chunk
        head = data.split(b"\r\n", 1)[0]
        if b" 200 " not in head or b"fl=" not in data:
            return None
        return round((time.monotonic() - t0) * 1000)
    except Exception:
        return None


# ---------------------------------------------------------------- VPN/proxy detection
def detect(ips):
    """ip-api.com/batch: proxy أو hosting = متكشف. بيرجع {ip: True/False} (ناقص لو الخدمة وقعت)."""
    flags = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,query,proxy,hosting",
            data=json.dumps(chunk).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "v2-collector/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                arr = json.loads(r.read().decode())
            for row in arr:
                if row.get("status") == "success" and row.get("query"):
                    # المتكشف = متعلم Proxy. Hosting لوحده طبيعي (كلاودفلير كله hosting)
                    # والمواقع اللي بتمنع VPN/Proxy بتبص على علامة البروكسي.
                    flags[row["query"]] = {"vpn": bool(row.get("proxy")),
                                           "hosting": bool(row.get("hosting"))}
        except Exception as e:
            log(f"  ⚠️ كشف الـVPN فشل للدفعة {i // 100 + 1}: {e}")
        if i + 100 < len(ips):
            time.sleep(4.5)      # الحد المجاني: ١٥ طلب في الدقيقة
    return flags


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manual", default="cleanip-manual.txt")
    ap.add_argument("--sources", default="cleanip-sources.txt")
    ap.add_argument("--out", default="out")
    a = ap.parse_args()

    manual = read_manual(a.manual)
    seen = set(manual)
    candidates = []

    for u in read_sources(a.sources):
        try:
            got = fetch_ips(u)
            log(f"  ✓ {len(got):5d}  {u}")
            for ip in got:
                if ip not in seen:
                    seen.add(ip)
                    candidates.append(ip)
        except Exception as e:
            log(f"  ✗ {u}: {e}")

    for ip in sample_cf():
        if ip not in seen:
            seen.add(ip)
            candidates.append(ip)

    candidates = candidates[:MAX_CANDIDATES]
    log(f"مرشحين: {len(candidates)} (+ {len(manual)} من ملفك)")

    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futs = {ex.submit(test, ip): ip for ip in manual + candidates}
        for fut in concurrent.futures.as_completed(futs):
            ip = futs[fut]
            ms = fut.result()
            if ms is not None:
                alive.append((ip, ms, ip in set(manual)))
    log(f"شغالين: {len(alive)}")

    flags = detect([ip for ip, _, _ in alive])
    rows = [{"ip": ip, "ms": ms, "src": "manual" if m else "auto",
             "vpn": (flags.get(ip) or {}).get("vpn"),
             "hosting": (flags.get(ip) or {}).get("hosting")}
            for ip, ms, m in alive]
    # اليدوي الأول، بعدين المش متكشف، مترتبين بالبينج
    rows.sort(key=lambda r: (r["src"] != "manual", r["vpn"] is True,
                             r["hosting"] is True, r["ms"]))
    top = rows[:LIMIT]

    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "cleanip.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(r["ip"] for r in top) + "\n")
    payload = {
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "count": len(top),
        "undetected": sum(1 for r in top if r["vpn"] is False),
        "ips": top,
    }
    with open(os.path.join(a.out, "cleanip.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    log(f"اتنشر {len(top)} آي بي — مش متكشف: {payload['undetected']}")


if __name__ == "__main__":
    main()
