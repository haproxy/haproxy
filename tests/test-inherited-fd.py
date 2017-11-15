#!/usr/bin/python
"""
Python wrapper example to test the fd@ function,
You have to bind on fd@${NEWFD} in your haproxy configuration

The configuration parsing should still work upon a reload with the master-worker
mode.

"""

import socket, subprocess, fcntl

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
flags = fcntl.fcntl(s.fileno(), fcntl.F_GETFD)
flags &= ~fcntl.FD_CLOEXEC
fcntl.fcntl(s.fileno(), fcntl.F_SETFD, flags)

s.bind((socket.gethostname(), 5555))
s.listen(1)
FD = s.fileno()

subprocess.Popen('NEWFD={} ./haproxy -W -f haproxy.cfg'.format(FD), shell=True, close_fds=False)
