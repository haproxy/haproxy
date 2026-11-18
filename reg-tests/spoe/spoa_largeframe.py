# SPOA for the large-frame SPOE regression test.
# Handshakes, then on every NOTIFY decodes args; the "chunk" arg is a
# 14000-byte binary payload. Logs NOTIFY_OK when a complete NOTIFY with the
# full chunk was received and ACKed.

import socket, sys, struct, threading

def enc_varint(i):
    out = bytearray()
    if i < 240:
        out.append(i)
        return bytes(out)
    out.append(240 | (i & 0x0F))
    i = (i - 240) >> 4
    while i >= 128:
        out.append((i | 128) & 0xFF)
        i = (i - 128) >> 7
    out.append(i & 0xFF)
    return bytes(out)

def dec_varint(buf, off):
    v = buf[off]; off += 1
    if v < 240:
        return v, off
    r = 4
    while True:
        v += buf[off] << r
        r += 7
        off += 1
        if buf[off-1] < 128:
            return v, off

def enc_str(s):
    if isinstance(s, str): s = s.encode()
    return enc_varint(len(s)) + s

def read_frame(sock):
    hdr = b""
    while len(hdr) < 4:
        d = sock.recv(4 - len(hdr))
        if not d: return None
        hdr += d
    ln = int.from_bytes(hdr, 'big')
    body = b""
    while len(body) < ln:
        d = sock.recv(ln - len(body))
        if not d: return None
        body += d
    return hdr + body

def send_frame(sock, payload):
    sock.sendall(len(payload).to_bytes(4, 'big') + payload)

HAPROXY_HELLO = 1
AGENT_HELLO = 101
HAPROXY_NOTIFY = 3
AGENT_ACK = 103
HAPROXY_DISCON = 2
T_STR = 8
T_UINT32 = 3
SET_VAR = 1
SCOPE_TXN = 0x30

def parse_typed(buf, off):
    t = buf[off]; off += 1
    m = t & 0x0F
    if m == 0: return None, off
    if m == 1: return (t & 0x10) != 0, off
    if 2 <= m <= 7:
        v, off = dec_varint(buf, off); return v, off
    if m in (8, 9):
        l, off = dec_varint(buf, off)
        v = buf[off:off+l]; off += l
        return (m, v), off
    return None, off

def handle(c):
    try:
        while True:
            f = read_frame(c)
            if f is None: return
            ftype = f[4]
            off = 9
            sid, off = dec_varint(f, off)
            fid, off = dec_varint(f, off)

            if ftype == HAPROXY_HELLO:
                payload = bytes([AGENT_HELLO]) + (1).to_bytes(4, 'big') + enc_varint(0) + enc_varint(0)
                payload += enc_str("version") + bytes([T_STR]) + enc_str("2.0")
                payload += enc_str("max-frame-size") + bytes([T_UINT32]) + enc_varint(16380)
                payload += enc_str("capabilities") + bytes([T_STR]) + enc_str("")
                send_frame(c, payload)

            elif ftype == HAPROXY_NOTIFY:
                moff = off
                nlen, moff = dec_varint(f, moff)
                moff += nlen  # skip message name
                nb = f[moff]; moff += 1
                kv = {}
                for _ in range(nb):
                    klen, moff = dec_varint(f, moff)
                    k = f[moff:moff+klen].decode(); moff += klen
                    v, moff = parse_typed(f, moff)
                    kv[k] = v
                chunk = kv.get("chunk")
                ok = chunk is not None and chunk[0] == 9 and len(chunk[1]) == 14000
                print("NOTIFY reqlen=%s chunk_len=%s" % (
                    kv.get("reqlen"), len(chunk[1]) if chunk else None), flush=True)
                if ok:
                    print("NOTIFY_OK", flush=True)
                ack = bytes([AGENT_ACK]) + (1).to_bytes(4, 'big') + enc_varint(sid) + enc_varint(fid)
                if ok:
                    ack += bytes([SET_VAR, 3, SCOPE_TXN]) + enc_str("bigok") + bytes([T_UINT32]) + enc_varint(1)
                send_frame(c, ack)

            elif ftype == HAPROXY_DISCON:
                return
    except Exception as e:
        print("ERR %s" % e, flush=True)
    finally:
        c.close()

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1]))); srv.listen(5)
print("READY", flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
