#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Minimal SPOA (Stream Processing Offload Agent) for the
# on-switching-rules reg-test.
#
# It performs the SPOP HELLO/AGENT-HELLO handshake, then on every NOTIFY:
#   - decodes the message args (in particular "reqlen"),
#   - replies with an AGENT-ACK carrying a set-var action that sets
#     sess.<var-prefix>.backend_name = "be_spoe",
#   - appends a line to a marker file so the test can assert what the
#     agent actually received (proving the event fired *with* request data).
#
# This is intentionally a minimal, self-contained SPOP implementation so the
# reg-test has no external dependencies beyond python3. SPOA reference
# implementations are maintained out of the haproxy tree (they do not depend
# on haproxy's version); see https://github.com/haproxy/spoa-example for a
# full-featured agent.
#
# Usage: spoa.py <listen_port> <marker_file>
import socket, struct, sys, threading

def enc_varint(v):
    if v < 240:
        return bytes([v])
    out = bytearray()
    out.append(0xF0 | (v & 0x0F))
    v = (v >> 4) - 16
    while v >= 128:
        out.append(0x80 | (v & 0x7F))
        v = (v >> 7) - 1
    out.append(v & 0x7F)
    return bytes(out)

def dec_varint(buf, off):
    b = buf[off]; off += 1
    if b < 240:
        return b, off
    val = b & 0x0F
    shift = 4
    while True:
        b = buf[off]; off += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if b < 128:
            break
    return val, off

def enc_str(s):
    b = s.encode() if isinstance(s, str) else s
    return enc_varint(len(b)) + b

def read_frame(sock):
    hdr = b''
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c: return None
        hdr += c
    (length,) = struct.unpack(">I", hdr)
    body = b''
    while len(body) < length:
        c = sock.recv(length - len(body))
        if not c: return None
        body += c
    return body

def send_frame(sock, body):
    sock.sendall(struct.pack(">I", len(body)) + body)

# frame types
HAPROXY_HELLO = 1
HAPROXY_DISCON = 2
HAPROXY_NOTIFY = 3
AGENT_HELLO = 101
AGENT_ACK = 103

# data types
T_NULL=0; T_BOOL=1; T_INT32=2; T_UINT32=3; T_INT64=4; T_UINT64=5
T_IPV4=6; T_IPV6=7; T_STR=8; T_BIN=9
FL_TRUE=0x10

SET_VAR = 1
SCOPE_SESS = 1

MARKER = None

def parse_typed(buf, off):
    t = buf[off]; off += 1
    dt = t & 0x0F
    if dt in (T_STR, T_BIN):
        vlen, off = dec_varint(buf, off)
        v = buf[off:off+vlen]; off += vlen; return v, off
    if dt in (T_INT32, T_UINT32, T_INT64, T_UINT64):
        v, off = dec_varint(buf, off); return v, off
    if dt == T_IPV4:
        v = buf[off:off+4]; off += 4; return v, off
    if dt == T_IPV6:
        v = buf[off:off+16]; off += 16; return v, off
    if dt == T_BOOL:
        return bool(t & FL_TRUE), off
    return None, off

def handle(sock, addr):
    try:
        while True:
            body = read_frame(sock)
            if body is None:
                return
            ftype = body[0]
            off = 1
            off += 4  # flags
            sid, off = dec_varint(body, off)
            fid, off = dec_varint(body, off)

            if ftype == HAPROXY_HELLO:
                # parse HELLO kv to echo back max-frame-size
                mfs = 16380
                o = off
                while o < len(body):
                    klen, o = dec_varint(body, o)
                    k = body[o:o+klen].decode(); o += klen
                    v, o = parse_typed(body, o)
                    if k == "max-frame-size":
                        mfs = v
                # flags=1 sets the SPOP FIN bit (this is a complete frame).
                payload = bytes([AGENT_HELLO]) + struct.pack(">I", 1) + enc_varint(0) + enc_varint(0)
                payload += enc_str("version") + bytes([T_STR]) + enc_str("2.0")
                payload += enc_str("max-frame-size") + bytes([T_UINT32]) + enc_varint(mfs)
                payload += enc_str("capabilities") + bytes([T_STR]) + enc_str("")
                send_frame(sock, payload)

            elif ftype == HAPROXY_NOTIFY:
                moff = off
                kv = {}
                while moff < len(body):
                    nlen, moff = dec_varint(body, moff)
                    name = body[moff:moff+nlen].decode(); moff += nlen
                    nbargs = body[moff]; moff += 1
                    for _ in range(nbargs):
                        klen, moff = dec_varint(body, moff)
                        k = body[moff:moff+klen].decode(); moff += klen
                        v, moff = parse_typed(body, moff)
                        kv[k] = v
                if MARKER:
                    with open(MARKER, "a") as f:
                        f.write("NOTIFY reqlen=%s\n" % kv.get("reqlen"))
                        f.flush()
                # ACK: set-var sess.<prefix>.backend_name = "be_spoe"
                # flags=1 sets the SPOP FIN bit (this is a complete frame).
                payload = bytes([AGENT_ACK]) + struct.pack(">I", 1) + enc_varint(sid) + enc_varint(fid)
                payload += bytes([SET_VAR, 3, SCOPE_SESS]) + enc_str("backend_name")
                payload += bytes([T_STR]) + enc_str("be_spoe")
                send_frame(sock, payload)

            elif ftype == HAPROXY_DISCON:
                return
    except Exception:
        pass
    finally:
        sock.close()

def main():
    port = int(sys.argv[1])
    global MARKER
    MARKER = sys.argv[2] if len(sys.argv) > 2 else None
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    # Signal readiness so the test harness can synchronize before starting
    # HAProxy (mirrors the "READY" convention used by other reg-test fixtures).
    print("READY", flush=True)
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()

if __name__ == "__main__":
    main()
