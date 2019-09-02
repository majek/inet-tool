#!/usr/bin/env python3
import argparse
import os
import socket
import sys
import urllib.parse


def main(argv):
    parser = argparse.ArgumentParser(description='Execute binary with some inherited sockets')
    parser.add_argument('-l', '--listen', action='append', default=[],
                        help='Open this sockets')
    parser.add_argument('cmd', metavar='COMMAND', nargs='+',
                        help='command to run')
    args = parser.parse_args(argv)

    S = []
    for a in args.listen:
        o =  urllib.parse.urlparse(a)
        if o.scheme in ['tcp', 'tcp4'] and ':' not in o.hostname:
            #print('[ ] Binding AF_INET SOCK_STREAM to %r' % ((o.hostname, o.port),))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif o.scheme in ['tcp','tcp6']:
            #print('[ ] Binding AF_INET6 SOCK_STREAM to %r' % ((o.hostname, o.port),))
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        elif o.scheme in ['udp', 'udp4'] and ':' not in o.hostname:
            #print('[ ] Binding AF_INET SOCK_DGRAM to %r' % ((o.hostname, o.port),))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif o.scheme in ['udp','udp6']:
            #print('[ ] Binding AF_INET6 SOCK_DGRAM to %r' % ((o.hostname, o.port),))
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            raise ValueError("use tcp:// udp:// scheme")
        s.set_inheritable(True)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        ## TODO make it an option
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        if s.family == socket.AF_INET6:
            if o.scheme[-1] == '6':
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            else:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        s.bind((o.hostname, o.port))
        try:
            s.listen(16)
        except socket.error:
            pass
        S.append(s)

    # print("[+] Running %r" % (args.cmd,))
    os.execv(args.cmd[0], args.cmd)



if __name__ == '__main__':
    i = main(sys.argv[1:])
    os.exit(i)
