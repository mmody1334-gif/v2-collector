#!/usr/bin/env python3
"""
V2 Collector — يجمع سيرفرات V2Ray المجانية، يقيس البينج، يقسمها حسب الدولة،
ويطلع ملفات اشتراك (subscription) جاهزة لـ V2Box وأي عميل V2Ray.

Usage:
  python scripts/collect.py --sources sources.txt --mmdb Country.mmdb --out out
"""
import argparse
import asyncio
import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mmdb  # noqa: E402
import realtest  # noqa: E402

PROTOCOLS = ("vmess", "vless", "trojan", "ss", "hysteria2", "hy2", "tuic")
LINK_RE = re.compile(r"(?:vmess|vless|trojan|ss|hysteria2|hy2|tuic)://[^\s\"'<>`]+", re.I)

# ---- limits (عدّلها براحتك) ----
MAX_UNIQUE = 60000        # أقصى عدد كونفيجات فريدة يتم اختبارها
TCP_TIMEOUT = 3.0         # ثواني
MAX_PING = 1500           # أي سيرفر أبطأ من كده يتشال (ms)
ALL_LIMIT = 3000          # أقصى عدد في ملف "الكل"
FAST_LIMIT = 300          # عدد السيرفرات في ملف "الأسرع"
COUNTRY_LIMIT = 200       # أقصى عدد لكل دولة
PROTOCOL_LIMIT = 1000     # أقصى عدد لكل بروتوكول
CONCURRENCY = 600
PRIORITY_COUNTRIES = {"EG", "SA", "AE", "OM", "QA", "KW", "BH", "JO", "IQ", "LB", "MA", "TN", "DZ"}
REAL_MAX = 45000           # أقصى عدد يتعمله اختبار حقيقي عبر Xray
REAL_MAX_DELAY = 5000     # أقصى real delay مقبول (ms)


def log(*a):
    print(*a, flush=True)


# ---------------------------------------------------------------- fetching
def b64decode_loose(s):
    s = s.strip().replace("\n", "").replace("\r", "")
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "v2-collector/1.0"})
    with urllib.request.urlopen(req, timeout=40) as r:
        data = r.read(60 * 1024 * 1024)
    text = data.decode("utf-8", "ignore")
    if "://" not in text[:5000]:
        try:
            dec = b64decode_loose(text).decode("utf-8", "ignore")
            if "://" in dec:
                text = dec
        except Exception:
            pass
    return text


def read_sources(path):
    urls = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def fetch_all(urls):
    links = []
    stats = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(fetch, u): u for u in urls}
        for fut in concurrent.futures.as_completed(futs):
            u = futs[fut]
            try:
                text = fut.result()
                found = LINK_RE.findall(text)
                links.extend(found)
                stats[u] = len(found)
                log(f"  ✓ {len(found):6d}  {u}")
            except Exception as e:
                stats[u] = 0
                log(f"  ✗ {u}: {e}")
    return links, stats


# ---------------------------------------------------------------- parsing
class Config:
    __slots__ = ("proto", "host", "port", "raw", "key", "vmess", "ip", "cc", "ms", "exit_ip")

    def __init__(self, proto, host, port, raw, key, vmess=None):
        self.proto, self.host, self.port = proto, host, port
        self.raw, self.key, self.vmess = raw, key, vmess
        self.ip = self.cc = self.ms = self.exit_ip = None

    def with_remark(self, remark):
        if self.proto == "vmess":
            d = dict(self.vmess)
            d["ps"] = remark
            js = json.dumps(d, ensure_ascii=False, separators=(",", ":"))
            return "vmess://" + base64.b64encode(js.encode()).decode()
        base = self.raw.split("#", 1)[0]
        return base + "#" + urllib.parse.quote(remark, safe="")


def _host_port(netloc):
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if netloc.startswith("["):
        host, _, rest = netloc[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, _, port = netloc.rpartition(":")
    port = re.match(r"\d+", port or "")
    return host.strip().lower(), int(port.group()) if port else None


def parse(link):
    link = link.strip().rstrip(",;")
    proto = link.split("://", 1)[0].lower()
    if proto not in PROTOCOLS:
        return None
    body = link.split("://", 1)[1]
    try:
        if proto == "vmess":
            d = json.loads(b64decode_loose(body.split("#", 1)[0]).decode("utf-8", "ignore"))
            host = str(d.get("add", "")).strip().lower()
            port = int(str(d.get("port", "0")).strip() or 0)
            if not d.get("id"):
                return None
            kd = {k: v for k, v in d.items() if k != "ps"}
            key = "vmess|" + json.dumps(kd, sort_keys=True)
            return Config("vmess", host, port, link, key, d) if host and port else None

        main = body.split("#", 1)[0]
        if proto == "ss":
            netpart = main.split("?", 1)[0].split("/", 1)[0]
            if "@" in netpart:  # توحيد الشكل عشان المكرر يتشال
                ui = urllib.parse.unquote(netpart.rsplit("@", 1)[0])
                if ":" not in ui:
                    ui = b64decode_loose(ui).decode("utf-8", "ignore")
                if ":" not in ui:
                    return None
                hp = netpart.rsplit("@", 1)[1]
                main = ui + "@" + hp
                link = "ss://" + base64.urlsafe_b64encode(ui.encode()).decode().rstrip("=") + "@" + hp
            if "@" not in netpart:  # ss://BASE64(method:pass@host:port)
                dec = b64decode_loose(netpart).decode("utf-8", "ignore")
                if "@" not in dec:
                    return None
                netpart = dec
                main = dec
                link = "ss://" + base64.urlsafe_b64encode(dec.rsplit("@", 1)[0].encode()).decode().rstrip("=") + "@" + dec.rsplit("@", 1)[1]
            host, port = _host_port(netpart)
        else:
            netloc = urllib.parse.urlsplit(link).netloc
            host, port = _host_port(netloc)
        if not host or not port or port > 65535:
            return None
        if proto == "hy2":
            proto = "hysteria2"
            link = "hysteria2://" + link.split("://", 1)[1]
        key = proto + "|" + main
        return Config(proto, host, port, link, key)
    except Exception:
        return None


# ---------------------------------------------------------------- network
def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def bad_ip(ip):
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_unspecified or a.is_reserved or a.is_multicast or a.is_link_local


async def resolve_all(hosts):
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(200)
    out = {}

    async def one(h):
        async with sem:
            try:
                res = await asyncio.wait_for(loop.getaddrinfo(h, None, type=socket.SOCK_STREAM), 6)
                ips = [r[4][0] for r in res]
                v4 = [i for i in ips if ":" not in i]
                out[h] = (v4 or ips)[0]
            except Exception:
                pass

    await asyncio.gather(*(one(h) for h in hosts))
    return out


async def tcp_ping_all(targets):
    sem = asyncio.Semaphore(CONCURRENCY)
    out = {}

    async def attempt(ip, port):
        t0 = time.perf_counter()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), TCP_TIMEOUT)
            ms = (time.perf_counter() - t0) * 1000
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), 1)
            except Exception:
                pass
            return ms
        except Exception:
            return None

    async def one(ip, port):
        async with sem:
            a = await attempt(ip, port)
            if a is None:
                return
            b = await attempt(ip, port)  # محاولة تانية عشان نتأكد ونقلل التذبذب
            out[(ip, port)] = int(min(a, b if b is not None else a))

    await asyncio.gather(*(one(ip, p) for ip, p in targets))
    return out


# ---------------------------------------------------------------- output
def flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())


def write_sub(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(data.encode("utf-8")).decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="sources.txt")
    ap.add_argument("--mmdb", default="Country.mmdb")
    ap.add_argument("--out", default="out")
    ap.add_argument("--xray", help="مسار Xray-core للاختبار الحقيقي (من غيره بيستخدم TCP بس)")
    ap.add_argument("--links-file", help="(للتجربة) ملف فيه لينكات بدل التحميل")
    args = ap.parse_args()
    t_start = time.time()

    log("① تحميل المصادر…")
    if args.links_file:
        with open(args.links_file, encoding="utf-8") as f:
            raw_links = LINK_RE.findall(f.read())
        src_stats = {args.links_file: len(raw_links)}
    else:
        raw_links, src_stats = fetch_all(read_sources(args.sources))
    log(f"   إجمالي اللينكات: {len(raw_links)}")

    log("② تحليل وإزالة المكرر…")
    uniq = {}
    for l in raw_links:
        c = parse(l)
        if c and c.key not in uniq:
            uniq[c.key] = c
    configs = list(uniq.values())[:MAX_UNIQUE]
    log(f"   فريد: {len(configs)}")

    log("③ DNS…")
    hosts = {c.host for c in configs if not is_ip(c.host)}
    resolved = asyncio.run(resolve_all(hosts))
    log(f"   تم حل {len(resolved)}/{len(hosts)} دومين")
    for c in configs:
        c.ip = c.host if is_ip(c.host) else resolved.get(c.host)
    configs = [c for c in configs if c.ip and not bad_ip(c.ip)]

    log("④ قياس البينج (TCP)…")
    targets = {(c.ip, c.port) for c in configs}
    pings = asyncio.run(tcp_ping_all(targets))
    log(f"   شغال: {len(pings)}/{len(targets)} عنوان")

    geo = mmdb.Reader(args.mmdb)
    tcp_alive = []
    for c in configs:
        ms = pings.get((c.ip, c.port))
        if ms is not None:
            c.ms = ms
            tcp_alive.append(c)
    tcp_alive.sort(key=lambda c: c.ms)
    diag = None

    if args.xray:
        log("⑤ اختبار حقيقي عبر Xray (real delay + دولة الخروج)…")
        # مصر والخليج الأول عشان مايتقطعوش لو الوقت خلص
        def prio(c):
            cc = cc_entry.get(c.ip)
            return (0 if cc in PRIORITY_COUNTRIES else 1, c.ms)
        cc_entry = {c.ip: geo.country(c.ip) for c in tcp_alive}
        tcp_alive.sort(key=prio)
        found = {}
        for c in tcp_alive:
            cc = cc_entry.get(c.ip)
            if cc in PRIORITY_COUNTRIES:
                found[cc] = found.get(cc, 0) + 1
        log(f"   سيرفرات مصر/الخليج قبل الاختبار: {found}")
        cand = tcp_alive[:REAL_MAX]
        for c in cand:
            c.ms = None
        diag = realtest.real_test(args.xray, cand, log)
        diag["priority_candidates"] = found
        alive = [c for c in cand if c.ms is not None and c.ms <= REAL_MAX_DELAY]
        for c in alive:
            if not c.cc or len(c.cc) != 2 or c.cc in ("T1", "XX"):
                c.cc = geo.country(c.exit_ip or c.ip) if (c.exit_ip or c.ip) else None
            c.cc = c.cc or "XX"
    else:
        log("⑤ تحديد الدول (GeoIP)…")
        alive = []
        for c in tcp_alive:
            if c.ms > MAX_PING:
                continue
            c.cc = geo.country(c.ip) or "XX"
            alive.append(c)
    alive.sort(key=lambda c: c.ms)
    log(f"   سيرفرات شغالة: {len(alive)}")

    # تسمية كل سيرفر: 🇩🇪 DE 12 | 85ms | vless
    counters = {}
    final = {}
    for c in alive:
        counters[c.cc] = counters.get(c.cc, 0) + 1
        remark = f"{flag(c.cc)} {c.cc} {counters[c.cc]} | {c.ms}ms | {c.proto}"
        final[id(c)] = c.with_remark(remark)

    out = args.out
    os.makedirs(out, exist_ok=True)
    used = set()

    def emit(rel, items):
        write_sub(os.path.join(out, rel), [final[id(c)] for c in items])
        used.update(id(c) for c in items)
        return len(items)

    files = {}
    files["all"] = emit("all.txt", alive[:ALL_LIMIT])
    files["fast"] = emit("fast.txt", alive[:FAST_LIMIT])

    by_cc, by_proto = {}, {}
    for c in alive:
        by_cc.setdefault(c.cc, []).append(c)
        by_proto.setdefault(c.proto, []).append(c)

    countries = []
    for cc, items in by_cc.items():
        n = emit(f"country/{cc}.txt", items[:COUNTRY_LIMIT])
        ms = [c.ms for c in items]
        countries.append({
            "code": cc, "flag": flag(cc), "count": n, "total": len(items),
            "best": min(ms), "avg": int(sum(ms) / len(ms)),
            "protocols": sorted({c.proto for c in items}),
        })
    countries.sort(key=lambda x: (x["code"] == "XX", x["best"]))

    protocols = []
    for p, items in by_proto.items():
        n = emit(f"protocol/{p}.txt", items[:PROTOCOL_LIMIT])
        protocols.append({"name": p, "count": n, "total": len(items), "best": items[0].ms})
    protocols.sort(key=lambda x: -x["total"])

    # ملف للصفحة: كل الكونفيجات المستخدمة مع بياناتها (للنسخ والفلترة بالبينج)
    rows = [[final[id(c)], c.cc, c.proto, c.ms] for c in alive if id(c) in used]
    with open(os.path.join(out, "configs.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, separators=(",", ":"))

    data = {
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_sec": int(time.time() - t_start),
        "stats": {
            "raw": len(raw_links), "unique": len(uniq), "tested": len(targets), "tcp_alive": len(tcp_alive),
            "alive": len(alive), "countries": len([c for c in countries if c["code"] != "XX"]),
        },
        "files": files,
        "countries": countries,
        "protocols": protocols,
        "sources": src_stats,
        "test_mode": "real" if args.xray else "tcp",
        "real_test": diag,
    }
    with open(os.path.join(out, "data.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    with open(os.path.join(out, "README.md"), "w", encoding="utf-8") as f:
        f.write(f"# Subscriptions\n\nUpdated: {data['updated']}\n\n"
                f"Alive: {len(alive)} — Countries: {data['stats']['countries']}\n")

    log(f"✔ خلصنا في {data['duration_sec']} ثانية — {len(alive)} سيرفر من {data['stats']['countries']} دولة")


if __name__ == "__main__":
    main()
