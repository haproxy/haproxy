#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

# DNS UDP/TCP fallback regression fixture.

import argparse
import socket
import struct
import threading


TRUNCATED_NAMES = {
    "fallback.test",
    "disabled.test",
    "family-prefix.test",
    "unavailable.test",
}
LATE_A_NAME = "late-a.test"
WRONG_QUESTION_NAME = "wrong-question.test"
WRONG_TYPE_NAME = "wrong-type.test"
WRONG_CLASS_NAME = "wrong-class.test"
SRV_NAME = "_service._tcp.srv.test"
TRUNCATED_SRV_NAME = "_truncated._tcp.srv.test"
SRV_TARGET = "node.srv.test"
TEST_ADDRESS = "192.0.2.123"


def encode_name(name):
    return b"".join(bytes((len(label),)) + label.encode() for label in name.split(".")) + b"\0"


def parse_question(query):
    offset = 12
    labels = []
    while query[offset]:
        length = query[offset]
        offset += 1
        labels.append(query[offset : offset + length].decode())
        offset += length
    offset += 1
    qtype, qclass = struct.unpack("!HH", query[offset : offset + 4])
    return ".".join(labels), qtype, qclass, query[12 : offset + 4]


def truncated_response(query, question):
    return query[:2] + struct.pack("!HHHHH", 0x8380, 1, 0, 0, 0) + question


def empty_response(query, question):
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + question


def a_response(query, question, answer_count):
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, answer_count, 0, 0)
    address = socket.inet_aton(TEST_ADDRESS)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, len(address)) + address
    response = header + question + answer * answer_count
    if answer_count > 1:
        assert len(response) > 1232
    return response


def srv_response(query, question, port, truncated=False):
    target = encode_name(SRV_TARGET)
    rdata = struct.pack("!HHH", 0, 10, port) + target
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 33, 1, 30, len(rdata)) + rdata
    additional = encode_name(SRV_TARGET)
    additional += struct.pack("!HHIH", 1, 1, 30, 4)
    additional += socket.inet_aton("127.0.0.1")
    flags = 0x8380 if truncated else 0x8180
    header = query[:2] + struct.pack("!HHHHH", flags, 1, 1, 0, 1)
    return header + question + answer + additional


class Fixture:
    def __init__(self, host, port, log_path, srv_port, udp_only):
        self.host = host
        self.port = port
        self.log_path = log_path
        self.srv_port = srv_port
        self.log_lock = threading.Lock()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind((host, port))
        self.tcp = None
        if not udp_only:
            self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp.bind((host, port))
            self.tcp.listen()

    def log(self, transport, name, qtype, response):
        with self.log_lock:
            with open(self.log_path, "a", encoding="ascii") as stream:
                stream.write(f"{transport} {name} {qtype} {len(response)}\n")

    def responses(self, transport, query):
        name, qtype, qclass, question = parse_question(query)
        if transport == "udp" and name == WRONG_QUESTION_NAME:
            wrong_question = encode_name("wrong.test")
            wrong_question += struct.pack("!HH", qtype, qclass)
            responses = [truncated_response(query, wrong_question)]
        elif transport == "udp" and name == WRONG_TYPE_NAME:
            wrong_question = question[:-4] + struct.pack("!HH", 33, qclass)
            responses = [truncated_response(query, wrong_question)]
        elif transport == "udp" and name == WRONG_CLASS_NAME:
            wrong_question = question[:-4] + struct.pack("!HH", qtype, 3)
            responses = [truncated_response(query, wrong_question)]
        elif transport == "udp" and name == LATE_A_NAME and qtype == 1:
            responses = [
                empty_response(query, question),
                truncated_response(query, question),
            ]
        elif transport == "udp" and name == LATE_A_NAME:
            responses = []
        elif transport == "udp" and (
            name in TRUNCATED_NAMES or name == SRV_NAME
        ):
            responses = [truncated_response(query, question)]
        elif name == TRUNCATED_SRV_NAME and qtype == 33:
            responses = [srv_response(query, question, self.srv_port, True)]
        elif name == SRV_NAME and qtype == 33:
            responses = [srv_response(query, question, self.srv_port)]
        elif name == "fallback.test":
            responses = [a_response(query, question, 80)]
        else:
            responses = [a_response(query, question, 1)]
        for response in responses:
            self.log(transport, name, qtype, response)
        return responses

    def serve_tcp_client(self, conn):
        with conn:
            while True:
                length = self.recv_exact(conn, 2)
                if not length:
                    return
                query = self.recv_exact(conn, struct.unpack("!H", length)[0])
                if not query:
                    return
                for response in self.responses("tcp", query):
                    conn.sendall(struct.pack("!H", len(response)) + response)

    @staticmethod
    def recv_exact(conn, length):
        data = b""
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def accept_tcp(self):
        while True:
            conn, _addr = self.tcp.accept()
            thread = threading.Thread(target=self.serve_tcp_client, args=(conn,), daemon=True)
            thread.start()

    def run(self):
        if self.tcp:
            threading.Thread(target=self.accept_tcp, daemon=True).start()
        while True:
            query, addr = self.udp.recvfrom(65535)
            for response in self.responses("udp", query):
                self.udp.sendto(response, addr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--log", required=True)
    parser.add_argument("--srv-port", type=int, default=80)
    parser.add_argument("--udp-only", action="store_true")
    args = parser.parse_args()
    fixture = Fixture(args.host, args.port, args.log, args.srv_port, args.udp_only)
    print("READY", flush=True)
    fixture.run()


if __name__ == "__main__":
    main()
