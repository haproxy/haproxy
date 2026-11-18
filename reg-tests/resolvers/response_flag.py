#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

# DNS fixture answering with or without the QR (response) bit.

import argparse
import socket
import struct

TEST_ADDRESS = "192.0.2.123"


def parse_question(query):
    offset = 12
    labels = []
    while query[offset]:
        length = query[offset]
        offset += 1
        labels.append(query[offset : offset + length].decode())
        offset += length
    offset += 1
    return ".".join(labels), query[12 : offset + 4]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(("127.0.0.1", args.port))
    print("READY", flush=True)

    while True:
        query, peer = udp.recvfrom(65535)
        name, question = parse_question(query)
        # same answer in both cases, only the QR bit differs
        flags = 0x0180 if name == "no-qr.test" else 0x8180
        header = query[:2] + struct.pack("!HHHHH", flags, 1, 1, 0, 0)
        address = socket.inet_aton(TEST_ADDRESS)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, len(address)) + address
        udp.sendto(header + question + answer, peer)


if __name__ == "__main__":
    main()
