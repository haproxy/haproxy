#!/usr/bin/python
"""
Python wrapper example to test socketpair protocol
./test-socketpair.py test.cfg

use sockpair@${FD1} and sockpair@${FD2} in your configuration file

"""

import socket, os, sys

s = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
os.set_inheritable(s[0].fileno(), 1)
os.set_inheritable(s[1].fileno(), 1)

FD1 = s[0].fileno()
FD2 = s[1].fileno()

print("FD1={} FD2={}".format(FD1, FD2))

os.environ["FD1"] = str(FD1)
os.environ["FD2"] = str(FD2)

cmd = ["./haproxy",
       "-f",
       "{}".format(sys.argv[1])
]
os.execve(cmd[0], cmd, os.environ)
