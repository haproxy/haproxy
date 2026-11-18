#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

"""Feed haproxy 0-RTT packets it can never decrypt.

A 0-RTT packet whose header protection cannot be removed, because no 0-RTT
RX secret exists (early data rejected by the TLS stack, or a TLS library
without 0-RTT support), is queued in eel->rx.pqpkts with a reference on
qc->rx.buf. The Rx buffer is reclaimed in order, stopping at the first
referenced packet: past ~64 kB, every packet is dropped until the idle
timeout, accounted as quic_dropped_pkt_bufoverrun and shown as dropbuff= in
"show quic".

The packets below are built synthetically as long-header packets of the
0-RTT type, with a payload encrypted with keys haproxy does not know, which
is exactly the state reached when 0-RTT keys are absent.
"""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "qclient"))

from qclient import QClient
from qcrypto import Keys, protect_long


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--count", type=int, default=120)
    args = ap.parse_args()

    c = QClient((args.addr, args.port), timeout=1.0)
    print("READY", flush=True)

    if not c.handshake(wait=2.0):
        print("RESULT handshake failed events=%r closed=%r"
              % (c.events, c.closed), flush=True)
        return

    # Keep the connection healthy, so that what is measured below is not the
    # consequence of a failed handshake.
    c.h3_setup()
    _, fin = c.request(0)
    if not fin:
        print("RESULT request failed", flush=True)
        return

    # 0-RTT long header packets encrypted with unknown keys: haproxy cannot
    # remove their header protection and queues them.
    fake = Keys(hashlib.sha256(b"fake-0rtt").digest())
    payload = b"\x01" * 1100
    for i in range(args.count):
        c.sock.sendto(protect_long(fake, 1, c.server_cid, c.scid, i, payload),
                      c.addr)

    print("SENT %d" % args.count, flush=True)


if __name__ == "__main__":
    main()
