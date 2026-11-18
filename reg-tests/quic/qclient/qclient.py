"""Minimal QUIC v1 + TLS 1.3 + HTTP/3 client for local testing (no cert check).

QClient(addr).handshake() completes the handshake, then send_1rtt()/request()
can be used. Hooks allow a fuzzer to tamper with frames and packets.
"""
import os, socket, struct, hashlib, hmac, time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from qcrypto import (Keys, initial_keys, varint, read_varint, protect_long,
                     protect_short, unprotect, hkdf_extract, hkdf_label)

H = hashlib.sha256
ZERO = b"\x00" * 32

def tls_hs(t, body):
    return bytes([t]) + struct.pack(">I", len(body))[1:] + body

def ext(t, data):
    return struct.pack(">HH", t, len(data)) + data

def tp_encode(params):
    out = b""
    for k, v in params:
        out += varint(k) + varint(len(v)) + v
    return out

def client_hello(pub, scid, sni=b"localhost", alpn=b"h3", tp=None, extra_ext=b""):
    if tp is None:
        tp = tp_encode([(0x0f, scid), (0x04, varint(1 << 20)), (0x05, varint(1 << 18)),
                        (0x06, varint(1 << 18)), (0x07, varint(1 << 18)), (0x08, varint(100)),
                        (0x09, varint(100)), (0x01, varint(30000)), (0x03, varint(1500))])
    exts = (ext(0, struct.pack(">HBH", len(sni) + 3, 0, len(sni)) + sni) +
            ext(10, b"\x00\x02\x00\x1d") +
            ext(13, b"\x00\x08\x04\x03\x08\x04\x04\x01\x05\x03") +
            ext(16, struct.pack(">HB", len(alpn) + 1, len(alpn)) + alpn) +
            ext(43, b"\x02\x03\x04") +
            ext(51, struct.pack(">HHH", 36, 0x1d, 32) + pub) +
            ext(0x39, tp) + extra_ext)
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    return tls_hs(1, body)

def parse_frames(pt):
    """Yield (type, info) for the frames in a decrypted payload."""
    i = 0; out = []
    while i < len(pt):
        t, i = read_varint(pt, i)
        if t == 0x00:
            continue
        if t == 0x01 or t == 0x1e:
            out.append((t, None)); continue
        if t in (0x02, 0x03):
            la, i = read_varint(pt, i); adelay, i = read_varint(pt, i); rc, i = read_varint(pt, i); _, i = read_varint(pt, i)
            for _ in range(rc):
                _, i = read_varint(pt, i); _, i = read_varint(pt, i)
            if t == 0x03:
                for _ in range(3): _, i = read_varint(pt, i)
            out.append((t, (la, adelay))); continue
        if t == 0x06:
            off, i = read_varint(pt, i); ln, i = read_varint(pt, i)
            out.append((t, (off, pt[i:i + ln]))); i += ln; continue
        if t == 0x07:
            ln, i = read_varint(pt, i); i += ln; out.append((t, None)); continue
        if 0x08 <= t <= 0x0f:
            sid, i = read_varint(pt, i); off = 0
            if t & 4: off, i = read_varint(pt, i)
            if t & 2: ln, i = read_varint(pt, i)
            else: ln = len(pt) - i
            out.append((t, (sid, off, pt[i:i + ln], bool(t & 1)))); i += ln; continue
        if t in (0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19):
            v, i = read_varint(pt, i); out.append((t, v)); continue
        if t in (0x11, 0x15):
            a, i = read_varint(pt, i); b, i = read_varint(pt, i); out.append((t, (a, b))); continue
        if t == 0x04:
            for _ in range(3): _, i = read_varint(pt, i)
            out.append((t, None)); continue
        if t == 0x05:
            for _ in range(2): _, i = read_varint(pt, i)
            out.append((t, None)); continue
        if t == 0x18:
            seq, i = read_varint(pt, i); rpt, i = read_varint(pt, i); l = pt[i]
            cid = pt[i + 1:i + 1 + l]; tok = pt[i + 1 + l:i + 1 + l + 16]; i += 1 + l + 16
            out.append((t, (seq, rpt, cid, tok))); continue
        if t in (0x1a, 0x1b):
            out.append((t, pt[i:i + 8])); i += 8; continue
        if t in (0x1c, 0x1d):
            ec, i = read_varint(pt, i)
            if t == 0x1c: _, i = read_varint(pt, i)
            ln, i = read_varint(pt, i); out.append((t, (ec, pt[i:i + ln]))); i += ln; continue
        out.append(("unknown", t)); break
    return out

class QClient:
    def __init__(self, addr, timeout=1.0):
        self.addr = addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.dcid = os.urandom(8); self.scid = os.urandom(8)
        self.ck_init, self.sk_init = initial_keys(self.dcid)
        self.pn = {0: 0, 2: 0, 3: 0}
        self.largest = {0: -1, 2: -1, 3: -1}
        self.crypto = {0: {}, 2: {}, 3: {}}
        self.closed = None
        self.streams = {}
        self.ck_hs = self.sk_hs = self.ck_ap = self.sk_ap = None
        self.server_cid = None
        self.events = []
        self.socks = [self.sock]
        self.rx_pns = {0: set(), 2: set(), 3: set()}
        self.kp_send = 0
        self.challenges = []
        self.peer_cids = {}

    # ---- sending ----
    def send_long(self, ptype, payload, pad_to=0, token=b"", dcid=None, raw_hook=None):
        keys = self.ck_init if ptype == 0 else self.ck_hs
        pn = self.pn[ptype]; self.pn[ptype] += 1
        if pad_to:
            est = 1 + 4 + 1 + 8 + 1 + 8 + 1 + len(token) + 2 + 4 + 16
            if est + len(payload) < pad_to:
                payload = payload + b"\x00" * (pad_to - est - len(payload))
        pkt = protect_long(keys, ptype, dcid or self.server_cid or self.dcid, self.scid, pn, payload, token)
        if raw_hook: pkt = raw_hook(pkt)
        self.sock.sendto(pkt, self.addr)
        return pkt

    def send_1rtt(self, payload, raw_hook=None, dcid=None):
        pn = self.pn[3]; self.pn[3] += 1
        if len(payload) < 4: payload += b"\x00" * (4 - len(payload))
        pkt = protect_short(self.ck_ap, dcid or self.server_cid, pn, payload, key_phase=self.kp_send)
        if raw_hook: pkt = raw_hook(pkt)
        self.sock.sendto(pkt, self.addr)

    @staticmethod
    def next_keys(k):
        from qcrypto import hkdf_label as hl
        n = Keys(hl(k.secret, b"quic ku", b"", 32)); n.hp = k.hp; return n

    def key_update(self):
        """Switch to the next 1-RTT send keys (RFC 9001 6.1)."""
        self.ck_ap = self.next_keys(self.ck_ap); self.kp_send ^= 1

    def migrate(self):
        """Continue sending from a new local UDP port."""
        ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ns.settimeout(self.sock.gettimeout())
        self.socks.append(ns); self.sock = ns

    def ack_frame(self, space):
        la = self.largest[space]
        if la < 0: return b""
        return b"\x02" + varint(la) + varint(0) + varint(0) + varint(la)

    @staticmethod
    def ack_for(pns, delay=0):
        """ACK frame acknowledging exactly the packet numbers in <pns>."""
        p = sorted(set(pns), reverse=True)
        if not p: return b""
        ranges = []; hi = lo = p[0]
        for x in p[1:]:
            if x == lo - 1: lo = x
            else: ranges.append((hi, lo)); hi = lo = x
        ranges.append((hi, lo))
        f = b"\x02" + varint(ranges[0][0]) + varint(delay) + varint(len(ranges) - 1) + varint(ranges[0][0] - ranges[0][1])
        prev_lo = ranges[0][1]
        for hi, lo in ranges[1:]:
            f += varint(prev_lo - hi - 2) + varint(hi - lo); prev_lo = lo
        return f

    # ---- receiving ----
    def recv_all(self, wait=0.5, until=None):
        end = time.time() + wait
        while time.time() < end:
            import select
            try:
                r, _, _ = select.select(self.socks, [], [], max(0.01, end - time.time()))
            except ValueError:
                return
            if not r:
                break
            for sk in r:
                try:
                    d, _ = sk.recvfrom(65536)
                except (ConnectionRefusedError, BlockingIOError, socket.timeout):
                    continue
                self.on_datagram(d)
            if until and until(): return

    def on_datagram(self, d):
        i = 0
        while i < len(d):
            first = d[i]
            if first & 0x80:
                ver = struct.unpack(">I", d[i + 1:i + 5])[0]
                j = i + 5; dl = d[j]; dcid = d[j + 1:j + 1 + dl]; j += 1 + dl
                sl = d[j]; scid = d[j + 1:j + 1 + sl]; j += 1 + sl
                ptype = (first >> 4) & 3
                if ver == 0:
                    self.events.append(("vneg", None)); return
                if ptype == 3:
                    self.events.append(("retry", d[j:])); return
                if ptype == 0:
                    tl, j = read_varint(d, j); j += tl
                ln, j = read_varint(d, j)
                end = j + ln
                keys = {0: self.sk_init, 2: self.sk_hs}.get(ptype)
                if self.server_cid is None: self.server_cid = scid
                if keys is None:
                    i = end; continue
                try:
                    pn, pt, _ = unprotect(keys, d[i:end], j - i, True, end - i, max(self.largest[ptype], 0))
                except Exception as e:
                    self.events.append(("decrypt-fail", ptype)); i = end; continue
                self.largest[ptype] = max(self.largest[ptype], pn)
                self.rx_pns[ptype].add(pn)
                self.on_frames(ptype, parse_frames(pt))
                # Derive the next keys as soon as the CRYPTO data allowing
                # it has been consumed: the following packets may be
                # coalesced in the same datagram and need them.
                if ptype == 0:
                    self._try_sh()
                elif ptype == 2:
                    self._try_fin()
                i = end
            else:
                if not self.sk_ap: return
                try:
                    pn, pt, _ = unprotect(self.sk_ap, d[i:], i + 1 + len(self.scid), False, len(d) - i, max(self.largest[3], 0))
                except Exception:
                    try:
                        nk = self.next_keys(self.sk_ap)
                        pn, pt, _ = unprotect(nk, d[i:], i + 1 + len(self.scid), False, len(d) - i, max(self.largest[3], 0))
                        self.sk_ap = nk; self.events.append(("peer-key-update", None))
                    except Exception:
                        self.events.append(("decrypt-fail", 3)); return
                self.largest[3] = max(self.largest[3], pn)
                self.rx_pns[3].add(pn)
                self.on_frames(3, parse_frames(pt))
                return

    def on_frames(self, space, frames):
        for t, info in frames:
            if t == 0x06:
                off, data = info; self.crypto[space][off] = data
            elif 0x08 <= (t if isinstance(t, int) else 0) <= 0x0f:
                sid, off, data, fin = info
                st = self.streams.setdefault(sid, {"data": {}, "fin": None})
                st["data"][off] = data
                if fin: st["fin"] = off + len(data)
            elif t in (0x1c, 0x1d):
                self.closed = info
            elif t == 0x1e:
                self.events.append(("hs_done", None))
            elif t == 0x18:
                self.events.append(("ncid", info)); self.peer_cids[info[0]] = info[2]
            elif t == 0x1a:
                self.challenges.append(info)
            elif t in (0x02, 0x03):
                self.events.append(("ack", space, info))
            elif t == "unknown":
                self.events.append(("unknown-frame", info))

    def crypto_stream(self, space):
        buf = b""; parts = self.crypto[space]
        while len(buf) in parts:
            nxt = parts[len(buf)]
            if not nxt: break
            buf += nxt
        # handle overlaps
        for off in sorted(parts):
            if off < len(buf) < off + len(parts[off]):
                buf += parts[off][len(buf) - off:]
        return buf

    def stream_data(self, sid):
        st = self.streams.get(sid)
        if not st: return b"", False
        buf = b""
        while True:
            for off, data in st["data"].items():
                if off <= len(buf) < off + len(data):
                    buf += data[len(buf) - off:]; break
            else:
                break
        return buf, st["fin"] is not None and len(buf) >= st["fin"]

    # ---- handshake ----
    def handshake(self, ch_hook=None, wait=2.0):
        self.priv = X25519PrivateKey.generate()
        pub = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.ch = client_hello(pub, self.scid)
        if ch_hook:
            ch_hook(self)
        else:
            self.send_long(0, b"\x06" + varint(0) + varint(len(self.ch)) + self.ch, pad_to=1200)
        # wait for ServerHello
        self.recv_all(wait, until=lambda: self._try_sh())
        if not self._try_sh():
            print("handshake: no ServerHello crypto0=%d events=%r" %
                  (len(self.crypto_stream(0)), self.events), flush=True)
            return False
        # wait for server Finished
        self.recv_all(wait, until=lambda: self._try_fin())
        if not self._try_fin():
            print("handshake: no Finished crypto0=%d crypto2=%d events=%r" %
                  (len(self.crypto_stream(0)), len(self.crypto_stream(2)),
                   self.events), flush=True)
            return False
        # send client Finished
        fk = hkdf_label(self.c_hs, b"finished", b"", 32)
        vd = hmac.new(fk, self.th_sfin, H).digest()
        fin = tls_hs(20, vd)
        self.send_long(0, self.ack_frame(0), pad_to=0) if self.largest[0] >= 0 else None
        self.send_long(2, self.ack_frame(2) + b"\x06" + varint(0) + varint(len(fin)) + fin)
        return True

    def _try_sh(self):
        if self.ck_hs: return True
        b = self.crypto_stream(0)
        if len(b) < 4: return False
        ln = struct.unpack(">I", b"\x00" + b[1:4])[0]
        if b[0] != 2 or len(b) < 4 + ln: return False
        sh = b[:4 + ln]
        body = sh[4:]
        i = 2 + 32; sl = body[i]; i += 1 + sl + 2 + 1
        el = struct.unpack(">H", body[i:i + 2])[0]; i += 2; end = i + el
        spub = None
        while i < end:
            t, l = struct.unpack(">HH", body[i:i + 4]); i += 4
            if t == 51: spub = body[i + 4:i + 4 + 32]
            i += l
        if spub is None: return False
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        shared = self.priv.exchange(X25519PublicKey.from_public_bytes(spub))
        self.transcript = self.ch + sh
        early = hkdf_extract(ZERO, ZERO)
        derived = hkdf_label(early, b"derived", H(b"").digest(), 32)
        hs = hkdf_extract(derived, shared)
        th = H(self.transcript).digest()
        self.c_hs = hkdf_label(hs, b"c hs traffic", th, 32)
        s_hs = hkdf_label(hs, b"s hs traffic", th, 32)
        self.ck_hs, self.sk_hs = Keys(self.c_hs), Keys(s_hs)
        self.master = hkdf_extract(hkdf_label(hs, b"derived", H(b"").digest(), 32), ZERO)
        return True

    def _try_fin(self):
        if self.ck_ap: return True
        b = self.crypto_stream(2); i = 0; msgs = b""
        while i + 4 <= len(b):
            ln = struct.unpack(">I", b"\x00" + b[i + 1:i + 4])[0]
            if i + 4 + ln > len(b): return False
            t = b[i]; msgs += b[i:i + 4 + ln]; i += 4 + ln
            if t == 20:
                self.transcript += msgs
                th = H(self.transcript).digest()
                c_ap = hkdf_label(self.master, b"c ap traffic", th, 32)
                s_ap = hkdf_label(self.master, b"s ap traffic", th, 32)
                self.ck_ap, self.sk_ap = Keys(c_ap), Keys(s_ap)
                self.th_sfin = th
                return True
        return False

    # ---- HTTP/3 ----
    @staticmethod
    def stream_frame(sid, data, off=0, fin=True):
        t = 0x08 | 0x02 | (0x04 if off else 0) | (0x01 if fin else 0)
        return bytes([t]) + varint(sid) + (varint(off) if off else b"") + varint(len(data)) + data

    @staticmethod
    def qpack_get(path=b"/", authority=b"localhost", extra=b""):
        def lit_nameref(idx, val):  # 0101NNNN static name ref, never-indexed=0
            assert idx < 15
            return bytes([0x50 | idx]) + bytes([len(val)]) + val if len(val) < 127 else None
        return b"\x00\x00" + b"\xd1" + b"\xd7" + lit_nameref(0, authority) + lit_nameref(1, path) + extra

    @staticmethod
    def h3_frame(t, payload):
        return varint(t) + varint(len(payload)) + payload

    def h3_setup(self):
        ctrl = b"\x00" + self.h3_frame(0x04, b"")
        self.send_1rtt(self.ack_frame(3) + self.stream_frame(2, ctrl, fin=False))

    def request(self, sid=0, path=b"/", body=None, wait=1.0):
        hdrs = self.h3_frame(0x01, self.qpack_get(path))
        data = hdrs + (self.h3_frame(0x00, body) if body else b"")
        self.send_1rtt(self.ack_frame(3) + self.stream_frame(sid, data))
        self.recv_all(wait, until=lambda: self.stream_data(sid)[1] or self.closed)
        return self.stream_data(sid)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19443
    c = QClient(("127.0.0.1", port))
    ok = c.handshake()
    print("handshake", ok, "events", c.events, "closed", c.closed)
    if ok:
        c.h3_setup()
        data, fin = c.request(0)
        print("stream0 fin=%s len=%d data=%r" % (fin, len(data), data[:80]))
        print("closed", c.closed, "events", c.events)
