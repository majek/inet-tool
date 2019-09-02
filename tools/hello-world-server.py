#!/usr/bin/python3
import errno
import itertools
import select
import socket


MAXCONTIGOUSFDGAP=32

gap = 0
SOCKETS = {}
for fd in itertools.count(3):
    # We can call getsockopt only on a socket object, this dup()s the fd.
    try:
        tmp_sd = socket.fromfd(fd, 0, 0, 0)
    except OSError as e:
        if e.errno == errno.EBADF:
            gap += 1
            if gap > MAXCONTIGOUSFDGAP:
                break
            continue
        else:
            raise e
    gap = 0

    try:
        # Trigger EBADF
        domain = tmp_sd.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN)
        sock_type = tmp_sd.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        protocol = tmp_sd.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL)
    except OSError as e:
        # not a socket
        tmp_sd.close()
        continue

    tmp_sd.close()

    if domain in (socket.AF_INET, socket.AF_INET6):
        SOCKETS[fd] = socket.socket(domain, sock_type, protocol, fd)


p = select.poll()
for s in SOCKETS.values():
    p.register(s, select.POLLIN)

while True:
    sockets = p.poll()
    for fd, _ in sockets:
        s = SOCKETS[fd]
        sd, _ = s.accept()
        sd.send(b"Hello world!\r\n")
        sd.close()
