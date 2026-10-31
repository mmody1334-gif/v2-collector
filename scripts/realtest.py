"""
اختبار حقيقي: بيشغّل Xray-core ويعدّي طلب فعلي من خلال كل سيرفر لـ Cloudflare trace.
النتيجة: real delay (زي اللي V2Box بيقيسه) + دولة الخروج الحقيقية (loc) — مش دولة الـ CDN.
"""
import asyncio
import base64
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse

TRACE_HOST = "www.cloudflare.com"
TRACE_PATH = "/cdn-cgi/trace"
BASE_PORT = 21000
BATCH = 400
REQ_TIMEOUT = 8.0
ALLOW_INSECURE = os.environ.get("XRAY_LEGACY", "1") == "1"  # Xray < 26 بيقبل allowInsecure
PARALLEL = 150            # طلبات متزامنة جوه كل دفعة
REASONS = {}


def _why(k):
    REASONS[k] = REASONS.get(k, 0) + 1

MAX_SECONDS = 38 * 60     # أقصى وقت للاختبار الحقيقي


def _q(link):
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(link).query, keep_blank_values=True).items()}


def _userinfo(link):
    netloc = urllib.parse.urlsplit(link).netloc
    return urllib.parse.unquote(netloc.rsplit("@", 1)[0]) if "@" in netloc else ""


FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn"}
FLOWS = {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}
XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}
SS_METHODS = {"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
              "xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
              "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}


def _b64len(v):
    v = v.replace("-", "+").replace("_", "/")
    return len(base64.b64decode(v + "=" * (-len(v) % 4)))


def _stream(net, security, host, path, sni, fp, alpn, pbk=None, sid=None, spx=None,
            header=None, service=None, mode=None, allow_insecure=False):
    net = (net or "tcp").lower()
    if net in ("splithttp",):
        net = "xhttp"
    if net in ("h2", "http"):
        net = "xhttp"  # http/h2 اتشالت من Xray الجديد
    s = {"network": net}
    security = (security or "none").lower()
    if security in ("tls", "xtls"):
        t = {"serverName": sni or host or ""}
        if fp:
            t["fingerprint"] = fp if fp.lower() in FPS else "chrome"
        if alpn:
            t["alpn"] = [a for a in alpn.split(",") if a]
        if allow_insecure and ALLOW_INSECURE:
            t["allowInsecure"] = True
        s["security"] = "tls"
        s["tlsSettings"] = t
    elif security == "reality":
        if not pbk or _b64len(pbk) != 32:
            raise ValueError("bad reality pbk")
        if sid and (len(sid) > 16 or any(ch not in "0123456789abcdefABCDEF" for ch in sid)):
            raise ValueError("bad shortId")
        if fp and fp.lower() not in FPS:
            fp = "chrome"
        s["security"] = "reality"
        s["realitySettings"] = {"serverName": sni or "", "fingerprint": fp or "chrome",
                                "publicKey": pbk, "shortId": sid or "", "spiderX": spx or ""}
    else:
        s["security"] = "none"

    path = path or "/"
    if net == "ws":
        ws = {"path": path}
        if host:
            ws["host"] = host
        s["wsSettings"] = ws
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": service or (path.strip("/") if path != "/" else ""),
                             "multiMode": mode == "multi"}
    elif net == "httpupgrade":
        hu = {"path": path}
        if host:
            hu["host"] = host
        s["httpupgradeSettings"] = hu
    elif net == "xhttp":
        xh = {"path": path}
        if host:
            xh["host"] = host
        if mode in XHTTP_MODES:
            xh["mode"] = mode
        s["xhttpSettings"] = xh
    elif net == "tcp" and header == "http":
        s["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path], "headers": {"Host": [h for h in (host or "").split(",") if h] or [""]}}}}
    elif net in ("tcp", "raw"):
        s["network"] = "tcp"
    elif net == "kcp":
        if header not in (None, "", "none", "srtp", "utp", "wechat-video", "dtls", "wireguard"):
            header = "none"
        s["kcpSettings"] = {"header": {"type": header or "none"}}
        if path and path != "/":
            s["kcpSettings"]["seed"] = path
    else:
        raise ValueError(f"unsupported net {net}")
    return s


def to_outbound(cfg, tag):
    """cfg: Config from collect.py"""
    p = cfg.proto
    if p == "vmess":
        d = cfg.vmess
        st = _stream(d.get("net"), d.get("tls"), d.get("host"), d.get("path"), d.get("sni"),
                     d.get("fp"), d.get("alpn"), header=d.get("type"),
                     service=d.get("path"), mode=d.get("mode"),
                     allow_insecure=str(d.get("allowInsecure", d.get("skip-cert-verify", ""))).lower() in ("1", "true"))
        user = {"id": d["id"], "alterId": int(d.get("aid") or 0), "security": d.get("scy") or "auto"}
        return {"tag": tag, "protocol": "vmess",
                "settings": {"vnext": [{"address": cfg.host, "port": cfg.port, "users": [user]}]},
                "streamSettings": st}

    if p in ("vless", "trojan"):
        q = _q(cfg.raw)
        security = q.get("security") or ("tls" if p == "trojan" else "none")
        st = _stream(q.get("type"), security, q.get("host"), q.get("path"), q.get("sni") or q.get("peer"),
                     q.get("fp"), q.get("alpn"), q.get("pbk"), q.get("sid"), q.get("spx"),
                     q.get("headerType"), q.get("serviceName"), q.get("mode"),
                     allow_insecure=q.get("allowInsecure") in ("1", "true") or q.get("insecure") in ("1", "true"))
        ui = _userinfo(cfg.raw)
        if not ui:
            raise ValueError("no user")
        if p == "vless":
            if (q.get("encryption") or "none") != "none":
                raise ValueError("vless encryption")
            user = {"id": ui, "encryption": "none"}
            if q.get("flow") in FLOWS:
                user["flow"] = q["flow"]
            return {"tag": tag, "protocol": "vless",
                    "settings": {"vnext": [{"address": cfg.host, "port": cfg.port, "users": [user]}]},
                    "streamSettings": st}
        return {"tag": tag, "protocol": "trojan",
                "settings": {"servers": [{"address": cfg.host, "port": cfg.port, "password": ui}]},
                "streamSettings": st}

    if p == "ss":
        ui = urllib.parse.urlsplit(cfg.raw).netloc.rsplit("@", 1)[0]
        ui = urllib.parse.unquote(ui)
        if ":" not in ui:
            s = ui.replace("-", "+").replace("_", "/")
            ui = base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")
        method, _, password = ui.partition(":")
        method = method.lower()
        if not method or not password or method not in SS_METHODS:
            raise ValueError("bad ss")
        if method.startswith("2022"):
            need = 16 if "128" in method else 32
            if any(_b64len(k) != need for k in password.split(":")):
                raise ValueError("bad ss2022 key")
        return {"tag": tag, "protocol": "shadowsocks",
                "settings": {"servers": [{"address": cfg.host, "port": cfg.port, "method": method, "password": password}]}}

    raise ValueError(f"unsupported proto {p}")


def build_config(items):
    """items: list of (idx, outbound) -> xray json"""
    inbounds, outbounds, rules = [], [], []
    for i, (_, ob) in enumerate(items):
        port = BASE_PORT + i
        inbounds.append({"tag": f"in{i}", "listen": "127.0.0.1", "port": port, "protocol": "socks",
                         "settings": {"udp": False}})
        ob = dict(ob)
        ob["tag"] = f"out{i}"
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"out{i}"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})
    return {"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"rules": rules}, "dns": {"servers": ["1.1.1.1", "8.8.8.8"]}}


async def _socks_http(port, host, path, timeout):
    """طلب HTTP بسيط من خلال SOCKS5 بتاع Xray — يرجع (status, body)"""
    loop = asyncio.get_running_loop()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        await loop.sock_connect(s, ("127.0.0.1", port))
        await loop.sock_sendall(s, b"\x05\x01\x00")
        if await loop.sock_recv(s, 2) != b"\x05\x00":
            _why("socks_auth")
            raise OSError("socks auth")
        hb = host.encode()
        await loop.sock_sendall(s, b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + (80).to_bytes(2, "big"))
        r = await loop.sock_recv(s, 10)
        if len(r) < 2 or r[1] != 0:
            _why(f"socks_rep_{r[1] if len(r) > 1 else 'x'}")
            raise OSError("socks connect")
        await loop.sock_sendall(s, f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n".encode())
        data = b""
        need = None
        while len(data) < 8192:
            try:
                chunk = await asyncio.wait_for(loop.sock_recv(s, 4096), timeout)
            except (ConnectionResetError, BrokenPipeError):
                if b"\r\n\r\n" in data:
                    break  # البيانات وصلت والسيرفر قفل بـ reset — عادي
                raise
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                head_b, _, body_b = data.partition(b"\r\n\r\n")
                if need is None:
                    m = re.search(rb"(?i)content-length:\s*(\d+)", head_b)
                    code = head_b.split(b" ", 2)[1:2]
                    if code == [b"204"]:
                        need = 0
                    elif m:
                        need = int(m.group(1))
                    else:
                        need = -1
                if need >= 0 and len(body_b) >= need:
                    break  # خلصنا من غير ما نستنى قفل الاتصال
        text = data.decode("utf-8", "ignore")
        head, _, body = text.partition("\r\n\r\n")
        parts = head.split(" ", 2)
        return (int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0), body
    finally:
        s.close()


async def _probe(port, ctx=None):
    try:
        t0 = time.perf_counter()
        st, _ = await _socks_http(port, "www.gstatic.com", "/generate_204", REQ_TIMEOUT)
        if st != 204:
            _why(f"status_{st}")
            return None
        ms = int((time.perf_counter() - t0) * 1000)
    except asyncio.TimeoutError:
        _why("timeout")
        return None
    except Exception as e:
        _why(type(e).__name__)
        return None
    ip = None
    try:  # IP الخروج الحقيقي (من Amazon مش Cloudflare)
        st, body = await asyncio.wait_for(_socks_http(port, "checkip.amazonaws.com", "/", 6), 7)
        cand = body.strip().split()[0] if st == 200 and body.strip() else ""
        socket.inet_pton(socket.AF_INET6 if ":" in cand else socket.AF_INET, cand)
        ip = cand
    except Exception:
        pass
    return ms, None, ip


async def _probe_all(n):
    ctx = ssl.create_default_context()
    sem = asyncio.Semaphore(min(n, PARALLEL))

    async def one(i):
        async with sem:
            try:
                return await asyncio.wait_for(_probe(BASE_PORT + i, ctx), REQ_TIMEOUT + 8)
            except Exception:
                _why("outer_timeout")
                return None
    return await asyncio.gather(*(one(i) for i in range(n)))


def _xray_ok(xray, items, diag):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(build_config(items), f)
    try:
        r = subprocess.run([xray, "run", "-test", "-c", path], capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(path)
    if r.returncode != 0 and len(diag["samples"]) < 6:
        diag["samples"].append((r.stdout + r.stderr)[-300:])
    return r.returncode == 0


def _valid(xray, items, diag):
    """يرجع الكونفيجات اللي Xray بيقبلها (تقسيم ثنائي بـ -test بس، سريع)"""
    if not items:
        return []
    if _xray_ok(xray, items, diag):
        return items
    if len(items) == 1:
        diag["config_errors"] += 1
        return []
    mid = len(items) // 2
    return _valid(xray, items[:mid], diag) + _valid(xray, items[mid:], diag)


def _run_batch(xray, items, diag):
    items = _valid(xray, items, diag)
    if not items:
        return {}
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(build_config(items), f)
    proc = subprocess.Popen([xray, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        results = asyncio.run(_probe_all(len(items)))
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except Exception:
            proc.kill()
        os.unlink(path)
    return {items[i][0]: r for i, r in enumerate(results) if r}


def real_test(xray, configs, log=print):
    """configs: list of Config. Sets c.ms / c.cc / c.exit_ip for working ones; returns diag."""
    diag = {"convert_errors": 0, "config_errors": 0, "samples": [], "tested": 0, "ok": 0}
    items = []
    for idx, c in enumerate(configs):
        try:
            items.append((idx, to_outbound(c, "x")))
        except Exception as e:
            diag["convert_errors"] += 1
            k = "conv:" + str(e)[:40]
            REASONS[k] = REASONS.get(k, 0) + 1
    diag["tested"] = len(items)
    t0 = time.time()
    deadline = t0 + MAX_SECONDS
    for b in range(0, len(items), BATCH):
        if time.time() > deadline:
            log("   ⏱ وصلنا للحد الأقصى للوقت — هنكتفي بالنتايج دي")
            diag["stopped_early"] = True
            break
        res = _run_batch(xray, items[b:b + BATCH], diag)
        for idx, (ms, loc, ip) in res.items():
            c = configs[idx]
            c.ms, c.cc, c.exit_ip = ms, (loc or "").upper() or None, ip
        diag["ok"] += len(res)
        log(f"   دفعة {b // BATCH + 1}: {len(res)}/{len(items[b:b + BATCH])} شغال — إجمالي {diag['ok']} ({int(time.time() - t0)}s)")
    diag["fail_reasons"] = dict(REASONS)
    return diag
