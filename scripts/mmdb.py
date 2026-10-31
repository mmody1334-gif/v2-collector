"""Minimal pure-Python MaxMind DB (.mmdb) reader — no external dependencies.
Only what is needed for country lookups."""
import ipaddress
import struct

_META_MARKER = b"\xab\xcd\xefMaxMind.com"


class Reader:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.buf = f.read()
        idx = self.buf.rfind(_META_MARKER)
        if idx < 0:
            raise ValueError("not an mmdb file")
        meta_start = idx + len(_META_MARKER)
        meta, _ = self._decode(meta_start, meta_start)
        self.node_count = meta["node_count"]
        self.record_size = meta["record_size"]
        self.ip_version = meta["ip_version"]
        self.node_bytes = self.record_size * 2 // 8
        self.tree_size = self.node_bytes * self.node_count
        self.data_start = self.tree_size + 16
        self._ipv4_start = None

    # ---------- search tree ----------
    def _read_node(self, node, bit):
        off = node * self.node_bytes
        b = self.buf
        rs = self.record_size
        if rs == 24:
            o = off + bit * 3
            return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
        if rs == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]
            return ((b[off + 3] & 0x0F) << 24) | (b[off + 4] << 16) | (b[off + 5] << 8) | b[off + 6]
        if rs == 32:
            return struct.unpack_from(">I", b, off + bit * 4)[0]
        raise ValueError("bad record size")

    def _ipv4_node(self):
        if self._ipv4_start is None:
            node = 0
            if self.ip_version == 6:
                for _ in range(96):
                    if node >= self.node_count:
                        break
                    node = self._read_node(node, 0)
            self._ipv4_start = node
        return self._ipv4_start

    def get(self, ip):
        addr = ipaddress.ip_address(ip)
        packed = addr.packed
        bits = len(packed) * 8
        if addr.version == 4 and self.ip_version == 6:
            node = self._ipv4_node()
        else:
            node = 0
        for i in range(bits):
            if node >= self.node_count:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = self._read_node(node, bit)
        if node == self.node_count:
            return None
        if node > self.node_count:
            off = node - self.node_count + self.tree_size
            val, _ = self._decode(off, self.data_start)
            return val
        return None

    # ---------- data section ----------
    def _decode(self, off, base):
        b = self.buf
        ctrl = b[off]
        off += 1
        t = ctrl >> 5
        if t == 1:  # pointer
            size = (ctrl >> 3) & 3
            v = ctrl & 7
            if size == 0:
                p = (v << 8) | b[off]
                off += 1
            elif size == 1:
                p = ((v << 16) | (b[off] << 8) | b[off + 1]) + 2048
                off += 2
            elif size == 2:
                p = ((v << 24) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]) + 526336
                off += 3
            else:
                p = struct.unpack_from(">I", b, off)[0]
                off += 4
            val, _ = self._decode(base + p, base)
            return val, off
        if t == 0:
            t = 7 + b[off]
            off += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + b[off]
            off += 1
        elif size == 30:
            size = 285 + ((b[off] << 8) | b[off + 1])
            off += 2
        elif size == 31:
            size = 65821 + ((b[off] << 16) | (b[off + 1] << 8) | b[off + 2])
            off += 3

        if t == 2:
            return b[off:off + size].decode("utf-8", "replace"), off + size
        if t == 3:
            return struct.unpack_from(">d", b, off)[0], off + 8
        if t == 4:
            return bytes(b[off:off + size]), off + size
        if t in (5, 6, 9, 10):
            return int.from_bytes(b[off:off + size], "big"), off + size
        if t == 8:
            return int.from_bytes(b[off:off + size], "big", signed=True), off + size
        if t == 7:
            d = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                d[k] = v
            return d, off
        if t == 11:
            arr = []
            for _ in range(size):
                v, off = self._decode(off, base)
                arr.append(v)
            return arr, off
        if t == 14:
            return bool(size), off
        if t == 15:
            return struct.unpack_from(">f", b, off)[0], off + 4
        raise ValueError(f"unknown mmdb type {t}")

    def country(self, ip):
        try:
            rec = self.get(ip)
        except ValueError:
            return None
        if not rec:
            return None
        for key in ("country", "registered_country"):
            c = rec.get(key)
            if c and c.get("iso_code"):
                return c["iso_code"]
        return None
