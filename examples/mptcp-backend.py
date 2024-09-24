# =============================================================================
# Example of a simple backend server using mptcp in python, used with mptcp.cfg
# =============================================================================

import socket

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_MPTCP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# dual stack IPv4/IPv6
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

sock.bind(("::", 4331))
sock.listen()

while True:
    (conn, address) = sock.accept()
    req = conn.recv(1024)
    print(F"Received request : {req}")
    conn.send(b"HTTP/1.0 200 OK\r\n\r\nHello\n")
    conn.close()

sock.close()
