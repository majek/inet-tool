import ctypes
import errno
import os
import shlex
import signal
import socket
import subprocess
import sys
import unittest
import fcntl

LIBC = ctypes.CDLL("libc.so.6")
INETTOOLBIN = os.environ.get('INETTOOLBIN')
IP_FREEBIND = 15
CLONE_NEWNET = 0x40000000
original_net_ns = open("/proc/self/ns/net", 'rb')

HELLO_WORLD_SERVER='./tools/hello-world-server.py'

if True:
    r = LIBC.unshare(CLONE_NEWNET)
    if r != 0:
        print("[!] Are you root? Need unshare() syscall.")
        sys.exit(-1)
    LIBC.setns(original_net_ns.fileno(), CLONE_NEWNET)


RUN_CMD_BUFFER = []

class Process(object):
    def __init__(self, argv, close_fds=True):
        self.p = subprocess.Popen(argv,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  close_fds=close_fds)
        self.rc = None
        RUN_CMD_BUFFER.append((' '.join(argv), self))

    def stdout_line(self):
        while True:
            o = self.p.stdout.readline().decode('utf8')
            if o == 'PASS\n' or o.startswith("coverage: "):
                continue
            return o

    def stderr_line(self):
        while True:
            e = self.p.stderr.readline().decode('utf8')
            if not e:
                continue
            if e.startswith('[o]'):
                print(e)
                continue
            return e

    def close(self, kill=False):
        '''Returns process return code.'''
        if self.p:
            if kill:
                self.p.send_signal(signal.SIGINT)
                self.p.send_signal(signal.SIGTERM)
            self.rc = self.p.wait()
            self.p.stdout.close()
            self.p.stderr.close()
            self.p = None
        return self.rc


class TestCase(unittest.TestCase):
    prev_errors = 0
    prev_failures = 0

    def run(self, result = None):
        # remember result for use in tearDown
        self.currentResult = result
        unittest.TestCase.run(self, result)

    def setUp(self):
        r = LIBC.unshare(CLONE_NEWNET)
        if r != 0:
            print("[!] Are you root? Need unshare() syscall.")
            sys.exit(-1)
        os.system("ip link set lo up")

        while RUN_CMD_BUFFER:
            _, p = RUN_CMD_BUFFER.pop()
            if getattr(p, '__class__') == Process:
                p.close(kill=True)
            else:
                p.close()
        if self.currentResult:
            self.prev_errors = len(self.currentResult.errors)
            self.prev_failures = len(self.currentResult.failures)

    def tearDown(self):
        # Clean up /sys/fs/bpf after test. Easiest to just call unload
        p = inet_tool("unload")
        p.close()

        LIBC.setns(original_net_ns.fileno(), CLONE_NEWNET)
        if len(self.currentResult.errors) > self.prev_errors or len(self.currentResult.failures) > self.prev_failures:
            print("\n[!] Test Failed. Executed programs:")
            for cmd, p in RUN_CMD_BUFFER:
                print("\t%s" % (cmd,))
                p.close(kill=True)

    def inet_tool_list(self):
        p = inet_tool('list')
        list_of_services = []
        list_of_bindings = []

        self.assertIn("List of services:", p.stdout_line())
        while True:
            line = p.stdout_line()
            if "List of" in line:
                break
            self.assertEqual(line[0], '\t')
            list_of_services.append(line[1:-1])
        self.assertIn("List of bindings:", line)
        while True:
            line = p.stdout_line()
            if not  line:
                break
            self.assertEqual(line[0], '\t')
            list_of_bindings.append(line[1:-1])
        rc = p.close()
        self.assertEqual(rc, 0)
        return list_of_services, list_of_bindings

    def assertTcpConnRefused(self, ip="127.0.0.1", port=0):
        if len(ip.split(':')) <= 2:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(2)

        with self.assertRaises(socket.error) as e:
            s.connect((ip, port))
        s.close()
        self.assertEqual(e.exception.errno, errno.ECONNREFUSED)

    def assertTcpConnSuccess(self, ip="127.0.0.1", port=0):
        if len(ip.split(':')) <= 2:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(2)

        s.connect((ip, port))
        s.close()

    def assertTcpHelloWorld(self, ip="127.0.0.1", port=0):
        if len(ip.split(':')) <= 2:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(2)

        s.connect((ip, port))
        data = s.recv(2048)
        self.assertEqual(b'Hello world!\r\n', data)
        s.close()

execno = 0
last_cmd = ""

def inet_tool(argv1=[], close_fds=True):
    global execno, last_cmd
    execno += 1
    argv0 = shlex.split(INETTOOLBIN % {"nr": execno})

    if isinstance(argv1, str):
        argv1 = shlex.split(argv1)

    a = argv0 + argv1

    return Process(a, close_fds=close_fds)



def bind_tcp(ip='127.0.0.1', port=0, cloexec=True, reuseaddr=True, reuseport=True, cleanup=True, backlog=8):
    if len(ip.split(':')) <= 2:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    s.settimeout(2)

    if cleanup:
        RUN_CMD_BUFFER.append(("bind_tcp", s))

    flags = fcntl.fcntl(s, fcntl.F_GETFD)
    if cloexec:
        flags |= fcntl.FD_CLOEXEC
    else:
        flags &= ~fcntl.FD_CLOEXEC
    fcntl.fcntl(s, fcntl.F_SETFD, flags)

    if reuseaddr:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if reuseport:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    s.setsockopt(socket.IPPROTO_IP, IP_FREEBIND, 1)

    s.bind((ip, port))
    s.listen(backlog)

    addr = s.getsockname()
    return s, addr[1]
