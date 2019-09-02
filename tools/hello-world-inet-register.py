#!/usr/bin/python3
import argparse
import errno
import itertools
import os
import select
import socket
import sys


def main(argv):
    parser = argparse.ArgumentParser(description='Execute binary with some inherited sockets')
    parser.add_argument('-f', '--fdname', default='hello-world-svc',
                        help='fdnames of socket')
    args = parser.parse_args(argv)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.set_inheritable(True)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(('127.0.0.1', 0))
    s.listen(16)

    os.system('inet-tool register %s' % (args.fdname))


    p = select.poll()
    p.register(s, select.POLLIN)

    while True:
        sockets = p.poll()
        for fd, _ in sockets:
            sd, _ = s.accept()
            sd.send(b"Hello world!\r\n")
            sd.close()

if __name__ == '__main__':
    i = main(sys.argv[1:])
    os.exit(i)
