from . import base
import errno


class BasicTest(base.TestCase):
    def test_no_param(self):
        ''' Verify message on no CLI parameter '''
        p = base.inet_tool()
        self.assertIn("Select a command", p.stderr_line())
        rc = p.close()
        self.assertEqual(rc, 255)

    def test_wrong_command(self):
        ''' Verify message on wrong CLI command '''
        p = base.inet_tool("sregister")
        self.assertIn('[!] Unknown operation "sregister"', p.stderr_line())
        rc = p.close()
        self.assertEqual(rc, 3)

    def test_help(self):
        ''' Verify message on --help '''
        p = base.inet_tool('--help')
        self.assertIn("Usage: inet-tool", p.stdout_line())
        rc = p.close()
        self.assertEqual(rc, 0)

    def test_basic_lifecycle(self):
        ''' Verify 'info' before and after 'load', verify 'unload' '''
        p = base.inet_tool('info')
        self.assertIn("SK_LOOKUP program absent", p.stdout_line())
        rc = p.close()
        self.assertEqual(rc, 1)

        p = base.inet_tool('load')
        self.assertIn("SK_LOOKUP program loaded", p.stdout_line())
        rc = p.close()
        self.assertEqual(rc, 0)

        p = base.inet_tool('load')
        self.assertIn("SK_LOOKUP program loaded", p.stdout_line())
        rc = p.close()
        self.assertEqual(rc, 0)

        p = base.inet_tool('info')
        self.assertIn("SK_LOOKUP program present", p.stdout_line())
        rc = p.close()
        self.assertEqual(rc, 0)

        p = base.inet_tool('unload')
        self.assertIn("Unpinned SK_LOOKUP link", p.stdout_line())
        rc = p.close()
        self.assertEqual(rc, 0)

        p = base.inet_tool('info')
        self.assertIn("SK_LOOKUP program absent", p.stdout_line())
        rc = p.close()
        self.assertEqual(rc, 1)

        p = base.inet_tool('unload')
        self.assertIn("Failed to unpin SK_LOOKUP link", p.stdout_line())
        rc = p.close()
        self.assertEqual(rc, errno.ENOENT)


    def test_basic_tcp_bind(self):
        ''' Veify creation and removal of simple tcp binding '''
        p = base.inet_tool('load')
        self.assertIn("SK_LOOKUP program loaded", p.stdout_line())

        svcs, bdgs = self.inet_tool_list()
        self.assertFalse(svcs)
        self.assertFalse(bdgs)

        p = base.inet_tool('bind 6 0.0.0.0:1234 x')
        self.assertIn("6 0.0.0.0:1234 -> x", p.stdout_line())
        rc = p.close()
        self.assertEqual(rc, 0)

        svcs, bdgs = self.inet_tool_list()
        self.assertFalse(svcs)
        self.assertEqual(bdgs, ['6 0.0.0.0:1234 -> x'])

        p = base.inet_tool('unbind 6 0.0.0.0:1234 x')
        self.assertIn("6 0.0.0.0:1234", p.stdout_line())
        rc = p.close()
        self.assertEqual(rc, 0)

        svcs, bdgs = self.inet_tool_list()
        self.assertFalse(svcs)
        self.assertFalse(bdgs)


    def test_basic_tcp_echo_2_tuple(self):
        ''' Verify if basic binding actually work '''
        base.inet_tool('load').close()
        base.inet_tool('bind 6 127.0.0.1:1234 x').close()
        sd, srv_port = base.bind_tcp(cloexec=False)
        self.assertTcpConnSuccess('127.0.0.1', srv_port)
        self.assertTcpConnRefused('127.0.0.1', 1234)

        p = base.inet_tool('register x', close_fds=False)
        self.assertIn("[+] x -> #0", p.stderr_line())
        svcs, bdgs = self.inet_tool_list()
        self.assertIn('x\t= #0 sk:', svcs[0])
        self.assertEqual(len(bdgs), 1)

        self.assertTcpConnSuccess('127.0.0.1', srv_port)
        self.assertTcpConnSuccess('127.0.0.1', 1234)

        # Socket shall be closed - SOCKARRAY shall not hold a reference.
        sd.close()

        self.assertTcpConnRefused('127.0.0.1', srv_port)
        self.assertTcpConnRefused('127.0.0.1', 1234)

        svcs, bdgs = self.inet_tool_list()
        self.assertEqual(svcs, ['x\t= #0 sk:(nil)'])
        self.assertEqual(bdgs, ['6 127.0.0.1:1234 -> x'])


    def test_basic_tcp_echo_1_tuple(self):
        ''' Verify if basic binding actually work '''
        base.inet_tool('load').close()
        base.inet_tool('bind 6 127.0.0.1:0 x').close()
        sd, srv_port = base.bind_tcp(cloexec=False)
        self.assertTcpConnSuccess('127.0.0.1', srv_port)
        self.assertTcpConnRefused('127.0.0.1', 1)

        p = base.inet_tool('register x', close_fds=False)
        self.assertIn("[+] x -> #0", p.stderr_line())
        svcs, bdgs = self.inet_tool_list()
        self.assertIn('x\t= #0 sk:', svcs[0])
        self.assertEqual(len(bdgs), 1)

        self.assertTcpConnSuccess('127.0.0.1', 1)
        self.assertTcpConnSuccess('127.0.0.1', 2)
        self.assertTcpConnRefused('127.0.0.2', 1)
        self.assertTcpConnRefused('127.0.0.2', 2)

        # Socket shall be closed - SOCKARRAY shall not hold a reference.
        sd.close()

        self.assertTcpConnRefused('127.0.0.1', 1)


    def test_basic_register(self):
        ''' Verify 'register' and 'unregister' '''
        base.inet_tool('load').close()

        p = base.inet_tool('register a')
        self.assertIn("[+] a -> #0 (sk:nil)", p.stderr_line())
        rc = p.close()
        self.assertEqual(rc, 0)

        svcs, bdgs = self.inet_tool_list()
        self.assertEqual(svcs, ['a\t= #0 sk:(nil)'])
        self.assertFalse(bdgs)

        p = base.inet_tool('unregister a')
        self.assertIn("[-] a ->", p.stderr_line())
        rc = p.close()
        self.assertEqual(rc, 0)

        svcs, bdgs = self.inet_tool_list()
        self.assertFalse(svcs)
        self.assertFalse(bdgs)


    def test_basic_tcp_echo_subnet(self):
        ''' Verify if binding subnets actually work '''
        base.inet_tool('load').close()
        base.inet_tool('bind 6 127.0.0.0/24:0 x').close()
        sd, srv_port = base.bind_tcp(cloexec=False)
        p = base.inet_tool('register x', close_fds=False)
        self.assertIn("[+] x -> #0", p.stderr_line())

        self.assertTcpConnSuccess('127.0.0.1', 1)
        self.assertTcpConnSuccess('127.0.0.2', 2)
        self.assertTcpConnRefused('127.0.1.1', 1)
        self.assertTcpConnRefused('127.0.2.2', 2)


    def test_basic_tcp_clear_subnet(self):
        ''' Verify if bottom of IP is masked on adding subnets '''
        base.inet_tool('load').close()

        base.inet_tool('bind 6 255.255.255.255/24:0 x').close()
        svcs, bdgs = self.inet_tool_list()
        self.assertFalse(svcs)
        self.assertEqual(bdgs, ['6 255.255.255.0/24:0 -> x'])
        base.inet_tool('unbind 6 255.255.255.255/24:0').close()

        base.inet_tool('bind 6 255.255.255.255/1:0 x').close()
        svcs, bdgs = self.inet_tool_list()
        self.assertFalse(svcs)
        self.assertEqual(bdgs, ['6 128.0.0.0/1:0 -> x'])
        base.inet_tool('unbind 6 128.0.0.0/1:0').close()

        base.inet_tool('bind 6 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/127:0 x').close()
        svcs, bdgs = self.inet_tool_list()
        self.assertFalse(svcs)
        self.assertEqual(bdgs, ['6 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]/127:0 -> x'])
        base.inet_tool('unbind 6 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/127:0').close()

        base.inet_tool('bind 6 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/126:0 x').close()
        svcs, bdgs = self.inet_tool_list()
        self.assertFalse(svcs)
        self.assertEqual(bdgs, ['6 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc]/126:0 -> x'])
        base.inet_tool('unbind 6 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc]/126:0').close()

        base.inet_tool('bind 6 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/119:0 x').close()
        svcs, bdgs = self.inet_tool_list()
        self.assertFalse(svcs)
        self.assertEqual(bdgs, ['6 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:fe00]/119:0 -> x'])
        base.inet_tool('unbind 6 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:fe00]/119:0').close()

        base.inet_tool('bind 6 [ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/1:0 x').close()
        svcs, bdgs = self.inet_tool_list()
        self.assertFalse(svcs)
        self.assertEqual(bdgs, ['6 [8000::]/1:0 -> x'])
        base.inet_tool('unbind 6 [8000:]/1:0').close()


    def test_basic_tcp_register(self):
        ''' Verify if register and command work '''
        base.inet_tool('load').close()
        base.inet_tool('bind 6 127.0.0.1:1234 x').close()
        sd, srv_port = base.bind_tcp(cloexec=False)

        p = base.inet_tool('register x -- %s' % base.HELLO_WORLD_SERVER, close_fds=False)
        self.assertIn("[+] x -> #0", p.stderr_line())
        self.assertIn("running: ", p.stderr_line())

        self.assertTcpHelloWorld(port=srv_port)
        self.assertTcpHelloWorld(port=1234)
        p.close(kill=True)


    def test_basic_tcp_echo_1_tuple_inet6(self):
        ''' Verify if basic binding actually work on ipv6 '''
        base.inet_tool('load').close()
        base.inet_tool('bind 6 [::1]:0 x').close()
        sd, srv_port = base.bind_tcp(ip='::1',cloexec=False)
        self.assertTcpConnSuccess('::1', srv_port)
        self.assertTcpConnRefused('::1', 1)

        p = base.inet_tool('register x', close_fds=False)
        self.assertIn("[+] x -> #0", p.stderr_line())
        svcs, bdgs = self.inet_tool_list()
        self.assertIn('x\t= #0 sk:', svcs[0])
        self.assertEqual(len(bdgs), 1)

        self.assertTcpConnSuccess('::1', 1)
        self.assertTcpConnSuccess('::1', 2)

        # Socket shall be closed - SOCKARRAY shall not hold a reference.
        sd.close()

        self.assertTcpConnRefused('::1', 1)


    def test_basic_scm_register(self):
        ''' Verify if scm register works '''
        base.inet_tool('load').close()
        scm_serve = base.inet_tool('scm_serve --unix=@test')
        self.assertIn("Waiting for SCM_RIGHTS", scm_serve.stdout_line())

        sd, srv_port = base.bind_tcp(cloexec=False)
        p = base.inet_tool('scm_register --unix=@test x -- /bin/echo xxx', close_fds=False)
        self.assertIn("Registering service \"x\"", p.stderr_line())
        self.assertIn("fd=", scm_serve.stdout_line())

        svcs, bdgs = self.inet_tool_list()
        self.assertNotIn('nil', svcs[0])
        self.assertIn('x\t= #0 sk:', svcs[0])
        self.assertFalse(bdgs)
