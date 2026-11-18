#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

"""Fake QUIC backend answering haproxy's Initial with a long header packet
using an unsupported version. A single datagram is enough to reach
quic_rx_pkt_parse() on the backend side of the connection: it must be
dropped instead of being parsed with a QUIC_PACKET_TYPE_UNKNOWN type, which
resolves to a NULL encryption level.
"""
import argparse
import socket
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(args.timeout)
    s.bind(("127.0.0.1", args.port))
    print("READY", flush=True)

    try:
        data, peer = s.recvfrom(65535)
    except socket.timeout:
        print("no Initial packet received", flush=True)
        return 1

    if not data[0] & 0x80:
        print("not a long header packet", flush=True)
        return 1

    dcid_len = data[5]
    scid_off = 6 + dcid_len
    scid_len = data[scid_off]
    hap_scid = data[scid_off + 1:scid_off + 1 + scid_len]

    payload = b"\x00" * 40
    pkt = (bytes([0xC0]) + (0x1A2A3A4A).to_bytes(4, "big") +
           bytes([len(hap_scid)]) + hap_scid + b"\x00" +
           bytes([0x40 | (len(payload) >> 8), len(payload) & 0xFF]) + payload)
    s.sendto(pkt, peer)
    s.close()
    print("sent %d bytes long header packet with unsupported version" % len(pkt), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
