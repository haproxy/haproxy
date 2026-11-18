import socket, sys, time

host = sys.argv[1]
port = int(sys.argv[2])
body = b"x" * 30000
req = b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: %d\r\n\r\n" % len(body) + body

c = socket.create_connection((host, port), timeout=8)
c.sendall(req)
time.sleep(1)
c.settimeout(5)
resp = b""
try:
    while True:
        d = c.recv(65536)
        if not d:
            break
        resp += d
except Exception:
    pass
sys.exit(0 if resp.startswith(b"HTTP/1.1 200") else 1)
