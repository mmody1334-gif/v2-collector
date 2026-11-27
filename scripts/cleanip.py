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
import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# ---- limits (عدّلها براحتك) ----
TCP_TIMEOUT = 3.0        # ثواني
MAX_CANDIDATES = 3000    # أقصى عدد مرشحين يتختبروا
CONCURRENCY = 400
LIMIT = 100              # أقصى عدد آي بيهات في الناتج
TRACE_HOST = "www.cloudflare.com"
WARP_LIMIT = 10            # عدد كونفيجات WARP الجاهزة
WARP_PORT = 2408
WARP_REG_URL = "https://api.cloudflareclient.com/v0a2158/reg"
CLEAN_COUNTRY = "ZC"      # كود وهمي (مش ISO) لصف "آي بي نظيف" — التطبيق بيعرضه جنب الدول من غير تحديث

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


# ---------------------------------------------------------------- WARP
_WARP_NETS = [ipaddress.ip_network(c) for c in WARP_24]


def x25519_public(priv_b64):
    """WireGuard public key من الـ private (RFC 7748 — من غير مكتبات خارجية)."""
    k = bytearray(base64.b64decode(priv_b64))
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    n = int.from_bytes(k, "little")
    p = 2 ** 255 - 19
    x1, x2, z2, x3, z3 = 9, 1, 0, 9, 1
    swap = 0
    for t in reversed(range(255)):
        kt = (n >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % p
        aa = a * a % p
        b = (x2 - z2) % p
        bb = b * b % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = d * a % p
        cb = c * b % p
        x3 = (da + cb) ** 2 % p
        z3 = x1 * ((da - cb) ** 2 % p) % p
        x2 = aa * bb % p
        z2 = e * ((aa + 121665 * e) % p) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    pub = x2 * pow(z2, p - 2, p) % p
    return base64.b64encode(pub.to_bytes(32, "little")).decode()


def wg_keypair():
    """مفتاح WireGuard عشوائي — بيعيد المحاولة لو فيه '/' (بيكسر الـ URI)."""
    for _ in range(50):
        priv = base64.b64encode(os.urandom(32)).decode()
        if "/" not in priv:
            return priv, x25519_public(priv)
    raise RuntimeError("مش قادر أطلع مفتاح نضيف")


def warp_register(pubkey):
    """تسجيل جهاز WARP مجاني من غير حساب (نفس API بتاع wgcf) — بيرجع (v4, v6, peer_pubkey, reserved)."""
    body = json.dumps({
        "install_id": "", "fcm_token": "", "type": "Android",
        "model": "v2rayNG", "locale": "en_US",
        "tos": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "key": pubkey,
    }).encode()
    req = urllib.request.Request(WARP_REG_URL, data=body, headers={
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/3.12.1",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        j = json.loads(r.read().decode())
    cfg = j.get("result", j).get("config", {})
    v4 = cfg["interface"]["addresses"]["v4"]
    v6 = cfg["interface"]["addresses"]["v6"]
    peer = cfg["peers"][0]["public_key"]
    try:
        reserved = list(base64.b64decode(cfg.get("client_id", "")))[:3]
    except Exception:
        reserved = []
    if len(reserved) != 3:
        reserved = [0, 0, 0]
    return v4, v6, peer, reserved


def warp_link(priv, ip, v4, v6, peer, reserved, name):
    q = urllib.parse.quote
    params = (f"address={q(v4)}%2C{q(v6)}&publickey={q(peer, safe='')}"
              f"&mtu=1280&reserved={reserved[0]}%2C{reserved[1]}%2C{reserved[2]}&dns=1.1.1.1")
    return f"wireguard://{priv}@{ip}:{WARP_PORT}?{params}#{q(name)}"


def write_sub(path, links):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode("utf-8")).decode())


def build_warp(rows, out):
    """كونفيجات WARP جاهزة بأنضف آي بيهات WARP — بتتنشر كاشتراك عادي بيفتح في v2rayNG والتطبيق."""
    endpoints = [r["ip"] for r in rows
                 if any(ipaddress.IPv4Address(r["ip"]) in n for n in _WARP_NETS)][:WARP_LIMIT]
    if not endpoints:
        log("  ⚠️ مفيش آي بيهات WARP شغالة — اتخطّى توليد الكونفيجات")
        return 0
    priv, pub = wg_keypair()
    v4, v6, peer, reserved = warp_register(pub)
    links = [warp_link(priv, ip, v4, v6, peer, reserved, f"🧼 WARP نظيف {i + 1} | {ip}")
             for i, ip in enumerate(endpoints)]
    write_sub(os.path.join(out, "warp.txt"), links)
    write_sub(os.path.join(out, "country", f"{CLEAN_COUNTRY}.txt"), links)
    write_sub(os.path.join(out, "protocol", "wireguard.txt"), links)

    # حدّث data.json اللي collect.py كتبه: ملف جديد + صف دولة + بروتوكول wireguard
    data_path = os.path.join(out, "data.json")
    if os.path.exists(data_path):
        with open(data_path, encoding="utf-8") as f:
            data = json.load(f)
        best = min((r["ms"] for r in rows if r["ip"] in endpoints), default=0)
        data.setdefault("files", {})["warp"] = len(links)
        countries = [c for c in data.get("countries", []) if c.get("code") != CLEAN_COUNTRY]
        countries.append({
            "code": CLEAN_COUNTRY, "flag": "🧼", "count": len(links), "total": len(links),
            "best": best, "avg": best, "clean": 0, "tg": 0, "protocols": ["wireguard"],
        })
        countries.sort(key=lambda x: (x["code"] == "XX", x["best"]))
        data["countries"] = countries
        protos = [p for p in data.get("protocols", []) if p.get("name") != "wireguard"]
        protos.append({"name": "wireguard", "count": len(links), "total": len(links), "best": best})
        data["protocols"] = protos
        with open(data_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
    log(f"  🧼 {len(links)} كونفيج WARP جاهز (أفضل بينج {best}ms)")
    return len(links)


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

    try:
        build_warp(rows, a.out)
    except Exception as e:
        log(f"  ⚠️ توليد WARP فشل (الآي بيهات نفسها اتنشرت عادي): {e}")


if __name__ == "__main__":
    main()
