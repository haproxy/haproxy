#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

"""Trigger the NEW_CONNECTION_ID-after-RETIRE bug from haproxy.

A NEW_CONNECTION_ID frame used to store pointers to the CID and the
stateless reset token of its quic_connection_id. A RETIRE_CONNECTION_ID
for that sequence number frees the object immediately, while the frame may
still be queued or be duplicated later for a retransmission: it was then
built from freed memory.

Retiring sequence numbers 1 and 2 in the same packet is enough: the second
RETIRE frees the quic_connection_id the first NEW_CONNECTION_ID frame still
points to. With the pool cache, the freed object is handed back to the next
CID of the connection, so two frames carry the same CID. Without the cache
(ASan, DEBUG_DONT_SHARE_POOLS), the freed heap content is sent instead.

The script reports "RESULT OK" on success, or "RESULT <reason>" otherwise.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "qclient"))

from qclient import QClient, varint


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", required=True)
    ap.add_argument("--port", type=int, required=True)
    args = ap.parse_args()

    c = QClient((args.addr, args.port), timeout=1.0)
    print("READY", flush=True)

    if not c.handshake(wait=2.0):
        print("RESULT handshake failed events=%r closed=%r"
              % (c.events, c.closed), flush=True)
        return

    # Let haproxy advertise its CID, then stop as soon as one is received.
    c.recv_all(2.0, until=lambda: any(e[0] == "ncid" for e in c.events))
    cids = [e[1] for e in c.events if e[0] == "ncid"]
    c.events.clear()

    # RETIRE seq 1 then 2 in the same packet: the second RETIRE frees the
    # quic_connection_id the NEW_CONNECTION_ID frame built for the first one
    # still points to. seq 2 was never sent, hence PROTOCOL_VIOLATION.
    c.send_1rtt(c.ack_frame(3) + b"\x19" + varint(1) + b"\x19" + varint(2))
    c.recv_all(2.0, until=lambda: c.closed is not None)
    cids += [e[1] for e in c.events if e[0] == "ncid"]

    # Bug: the frame built after the first RETIRE references the CID freed
    # by the second one, so the same CID ends up advertised under two
    # different sequence numbers. The same frame retransmitted for the same
    # sequence number is normal and must not be reported.
    # ncid events are (seq, retire_prior_to, cid, stateless_reset_token).
    by_seq = {}
    for seq, _rpt, cid, _tok in cids:
        by_seq.setdefault(seq, set()).add(cid)

    seen = {}
    for seq, seq_cids in sorted(by_seq.items()):
        for cid in seq_cids:
            if cid in seen:
                print("RESULT duplicate CID %s in seq %d and %d"
                      % (cid.hex(), seen[cid], seq), flush=True)
                return
            seen[cid] = seq

    # A CONNECTION_CLOSE frame is only received if haproxy survived the
    # RETIRE storm: a crash would leave nothing but silence.
    if not c.closed or c.closed[0] != 10:
        print("RESULT expected PROTOCOL_VIOLATION after RETIRE seq 1 and 2, "
              "got %r" % (c.closed,), flush=True)
        return

    print("RESULT OK (alive, PROTOCOL_VIOLATION, %d CID(s) seen)"
          % len(cids), flush=True)


if __name__ == "__main__":
    main()
