# Copyright 2005 Divmod, Inc.  See LICENSE file for details


from vertex import juice
from twisted.trial import unittest
from twisted.internet import protocol, defer
from cStringIO import StringIO

class IOPump:
    """Utility to pump data between clients and servers for protocol testing.

    Perhaps this is a utility worthy of being in protocol.py?
    """
    def __init__(self, client, server, clientIO, serverIO, debug):
        self.client = client
        self.server = server
        self.clientIO = clientIO
        self.serverIO = serverIO
        self.debug = debug

    def flush(self, debug=False):
        """Pump until there is no more input or output.

        Returns whether any data was moved.
        """
        result = False
        for x in range(1000):
            if self.pump(debug):
                result = True
            else:
                break
        else:
            assert 0, "Too long"
        return result


    def pump(self, debug=False):
        """Move data back and forth.

        Returns whether any data was moved.
        """
        self.clientIO.seek(0)
        self.serverIO.seek(0)
        cData = self.clientIO.read()
        sData = self.serverIO.read()
        self.clientIO.seek(0)
        self.serverIO.seek(0)
        self.clientIO.truncate()
        self.serverIO.truncate()
        self.client.transport._checkProducer()
        self.server.transport._checkProducer()
        if self.debug or debug:
            print '.'
            # XXX slightly buggy in the face of incremental output
            if cData:
                for line in cData.split('\r\n')[:-1]:
                    print 'C: '+line
            if sData:
                for line in sData.split('\r\n')[:-1]:
                    print 'S: '+line
        if cData:
            self.server.dataReceived(cData)
        if sData:
            self.client.dataReceived(sData)
        return bool(cData or sData)


class TestProto(protocol.Protocol):
    def __init__(self, onConnLost, dataToSend):
        self.onConnLost = onConnLost
        self.dataToSend = dataToSend

    def connectionMade(self):
        self.data = []
        self.transport.write(self.dataToSend)

    def dataReceived(self, bytes):
        self.data.append(bytes)

    def connectionLost(self, reason):
        self.onConnLost.callback(self.data)

class SimpleSymmetricProtocol(juice.Juice):

    def sendHello(self, text):
        return self.sendCommand("hello",
                                hello=text)

    def sendGoodbye(self):
        return self.sendCommand("goodbye")

    def juice_HELLO(self, box):
        return juice.Box(hello=box['hello'])

    def juice_GOODBYE(self, box):
        return juice.QuitBox(goodbye='world')

class UnfriendlyGreeting(Exception):
    """Greeting was insufficiently kind.
    """

class UnknownProtocol(Exception):
    """Asked to switch to the wrong protocol.
    """

class Hello(juice.Command):
    commandName = 'hello'
    arguments = [('hello', juice.String())]
    response = [('hello', juice.String())]

    errors = {UnfriendlyGreeting: 'UNFRIENDLY'}

class Goodbye(juice.Command):
    commandName = 'goodbye'
    responseType = juice.QuitBox

class GetList(juice.Command):
    commandName = 'getlist'
    arguments = [('length', juice.Integer())]
    response = [('body', juice.JuiceList([('x', juice.Integer())]))]

class TestSwitchProto(juice.ProtocolSwitchCommand):
    commandName = 'Switch-Proto'

    arguments = [
        ('name', juice.String()),
        ]
    errors = {UnknownProtocol: 'UNKNOWN'}

class SimpleSymmetricCommandProtocol(juice.Juice):
    def __init__(self, issueGreeting, onConnLost=None):
        juice.Juice.__init__(self, issueGreeting)
        self.onConnLost = onConnLost

    def sendHello(self, text):
        return Hello(hello=text).do(self)
    def sendGoodbye(self):
        return Goodbye().do(self)
    def command_HELLO(self, hello):
        if hello.startswith('fuck'):
            raise UnfriendlyGreeting("Don't be a dick.")
        return dict(hello=hello)
    def command_GETLIST(self, length):
        return {'body': [dict(x=1)] * length}
    def command_GOODBYE(self):
        return dict(goodbye='world')
    command_HELLO.command = Hello
    command_GOODBYE.command = Goodbye
    command_GETLIST.command = GetList

    def switchToTestProtocol(self):
        p = TestProto(self.onConnLost, SWITCH_CLIENT_DATA)
        return TestSwitchProto(p, name='test-proto').do(self).addCallback(lambda ign: p)

    def command_SWITCH_PROTO(self, name):
        if name == 'test-proto':
            self.switchTo(TestProto(self.onConnLost, SWITCH_SERVER_DATA))
            return {}
        raise UnknownProtocol(name)
    command_SWITCH_PROTO.command = TestSwitchProto

class SSPF: protocol = SimpleSymmetricProtocol
class SSSF(SSPF, protocol.ServerFactory): pass
class SSCF(SSPF, protocol.ClientFactory): pass

def connectedServerAndClient(ServerClass=lambda: SimpleSymmetricProtocol(True),
                             ClientClass=lambda: SimpleSymmetricProtocol(False),
                             clientTransportWrapper=protocol.FileWrapper,
                             serverTransportWrapper=protocol.FileWrapper,
                             debug=False):
    """Returns a 3-tuple: (client, server, pump)
    """
    c = ClientClass()
    s = ServerClass()
    cio = StringIO()
    sio = StringIO()
    c.makeConnection(clientTransportWrapper(cio))
    s.makeConnection(serverTransportWrapper(sio))
    pump = IOPump(c, s, cio, sio, debug)
    # kick off server greeting, etc
    pump.flush()
    return c, s, pump

class TotallyDumbProtocol(protocol.Protocol):
    buf = ''
    def dataReceived(self, data):
        self.buf += data

class LiteralJuice(juice.Juice):
    def __init__(self, issueGreeting):
        juice.Juice.__init__(self, issueGreeting)
        self.boxes = []

    def juiceBoxReceived(self, box):
        self.boxes.append(box)
        return

class LiteralParsingTest(unittest.TestCase):
    def testBasicRequestResponse(self):
        c, s, p = connectedServerAndClient(ClientClass=TotallyDumbProtocol)
        HELLO = 'abcdefg'
        ASKTOK = 'hand-crafted-ask'
        c.transport.write(("""-Command: HeLlO
-Ask: %s
Hello: %s
World: this header is ignored

""" % (ASKTOK, HELLO,)).replace('\n','\r\n'))
        p.flush()
        asserts = {'hello': HELLO,
                   '-answer': ASKTOK}
        hdrs = [j.split(': ') for j in c.buf.split('\r\n')[:-2]]
        self.assertEquals(len(asserts), len(hdrs))
        for hdr in hdrs:
            k, v = hdr
            self.assertEquals(v, asserts[k.lower()])

    def testParsingRoundTrip(self):
        c, s, p = connectedServerAndClient(ClientClass=lambda: LiteralJuice(False),
                                           ServerClass=lambda: LiteralJuice(True))

        SIMPLE = ('simple', 'test')
        CE = ('ceq', ': ')
        CR = ('crtest', 'test\r')
        LF = ('lftest', 'hello\n')
        NEWLINE = ('newline', 'test\r\none\r\ntwo')
        NEWLINE2 = ('newline2', 'test\r\none\r\n two')
        BLANKLINE = ('newline3', 'test\r\n\r\nblank\r\n\r\nline')
        BODYTEST = (juice.BODY, 'blah\r\n\r\ntesttest')

        testData = [
            [SIMPLE],
            [SIMPLE, BODYTEST],
            [SIMPLE, CE],
            [SIMPLE, CR],
            [SIMPLE, CE, CR, LF],
            [CE, CR, LF],
            [SIMPLE, NEWLINE, CE, NEWLINE2],
            [BODYTEST, SIMPLE, NEWLINE]
            ]

        for test in testData:
            jb = juice.Box()
            jb.update(dict(test))
            jb.sendTo(c)
            p.flush()
            self.assertEquals(s.boxes[-1], jb)

SWITCH_CLIENT_DATA = 'Success!'
SWITCH_SERVER_DATA = 'No, really.  Success.'

class AppLevelTest(unittest.TestCase):
    def testHelloWorld(self):
        c, s, p = connectedServerAndClient()
        L = []
        HELLO = 'world'
        c.sendHello(HELLO).addCallback(L.append)
        p.flush()
        self.assertEquals(L[0]['hello'], HELLO)

    def testHelloWorldCommand(self):
        c, s, p = connectedServerAndClient(
            ServerClass=lambda: SimpleSymmetricCommandProtocol(True),
            ClientClass=lambda: SimpleSymmetricCommandProtocol(False))
        L = []
        HELLO = 'world'
        c.sendHello(HELLO).addCallback(L.append)
        p.flush()
        self.assertEquals(L[0]['hello'], HELLO)

    def testHelloErrorHandling(self):
        L=[]
        c, s, p = connectedServerAndClient(ServerClass=lambda: SimpleSymmetricCommandProtocol(True),
                                           ClientClass=lambda: SimpleSymmetricCommandProtocol(False))
        HELLO = 'fuck you'
        c.sendHello(HELLO).addErrback(L.append)
        p.flush()
        L[0].trap(UnfriendlyGreeting)
        self.assertEquals(str(L[0].value), "Don't be a dick.")

    def testJuiceListCommand(self):
        c, s, p = connectedServerAndClient(ServerClass=lambda: SimpleSymmetricCommandProtocol(True),
                                           ClientClass=lambda: SimpleSymmetricCommandProtocol(False))
        L = []
        GetList(length=10).do(c).addCallback(L.append)
        p.flush()
        values = L.pop().get('body')
        self.assertEquals(values, [{'x': 1}] * 10)

    def testFailEarlyOnArgSending(self):
        okayCommand = Hello(Hello="What?")
        self.assertRaises(RuntimeError, Hello)

    def testSupportsVersion1(self):
        c, s, p = connectedServerAndClient(ServerClass=lambda: juice.Juice(True),
                                           ClientClass=lambda: juice.Juice(False))
        negotiatedVersion = []
        s.renegotiateVersion(1).addCallback(negotiatedVersion.append)
        p.flush()
        self.assertEquals(negotiatedVersion[0], 1)
        self.assertEquals(c.protocolVersion, 1)
        self.assertEquals(s.protocolVersion, 1)

    def testProtocolSwitch(self):
        serverDeferred = defer.Deferred()
        serverProto = SimpleSymmetricCommandProtocol(True, serverDeferred)
        clientDeferred = defer.Deferred()
        clientProto = SimpleSymmetricCommandProtocol(False, clientDeferred)
        c, s, p = connectedServerAndClient(ServerClass=lambda: serverProto,
                                           ClientClass=lambda: clientProto)

        switchDeferred = c.switchToTestProtocol()

        def cbConnsLost(((serverSuccess, serverData), (clientSuccess, clientData))):
            self.failUnless(serverSuccess)
            self.failUnless(clientSuccess)
            self.assertEquals(''.join(serverData), SWITCH_CLIENT_DATA)
            self.assertEquals(''.join(clientData), SWITCH_SERVER_DATA)

        def cbSwitch(proto):
            return defer.DeferredList([serverDeferred, clientDeferred]).addCallback(cbConnsLost)

        switchDeferred.addCallback(cbSwitch)
        p.flush()
