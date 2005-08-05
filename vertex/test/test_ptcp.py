
from twisted.internet import reactor, protocol, defer
from twisted.trial import unittest

from vertex import ptcp

class TestProtocol(protocol.Protocol):
    buffer = None
    def __init__(self):
        self.onConnect = defer.Deferred()
        self.onDisconn = defer.Deferred()
        self._waiting = None
        self.buffer = []

    def connectionMade(self):
        # print 'CONNECTION MADE'
        self.onConnect.callback(None)

    def connectionLost(self, reason):
        # print 'DISCO INFERNO'
        self.onDisconn.callback(None)

    def gotBytes(self, bytes):
        assert self._waiting is None
        if self.buffer == bytes:
            return defer.succeed(None)
        self._waiting = (defer.Deferred(), bytes)
        return self._waiting[0]

    def dataReceived(self, bytes):
        # print 'yay', len(bytes)
        self.buffer.append(bytes)
        if self._waiting is not None:
            bytes = ''.join(self.buffer)
            if bytes == self._waiting[1]:
                self._waiting[0].callback(None)
                self._waiting = None

class TestProducerProtocol(protocol.Protocol):
    NUM_WRITES = 3
    WRITE_SIZE = 2

    def connectionMade(self):
        self.count = -1
        self.transport.registerProducer(self, False)

    def resumeProducing(self):
        self.count += 1
        # print 'Resumed producing for the', self.count, 'th time.'
        if self.count < self.NUM_WRITES:
            self.transport.write(chr(self.count) * self.WRITE_SIZE)
            if self.count == self.NUM_WRITES - 1:
                # Last time through, intentionally drop the connection before
                # the buffer is empty to ensure we handle this case properly.
                self.transport.loseConnection()
        else:
            self.transport.unregisterProducer()


class PtcpTransportTestCase(unittest.TestCase):
    def setUpForATest(self,
                      ServerProtocol=TestProtocol, ClientProtocol=TestProtocol):
        serverProto = ServerProtocol()
        clientProto = ClientProtocol()
        sf = protocol.ServerFactory()
        sf.protocol = lambda: serverProto

        cf = protocol.ClientFactory()
        cf.protocol = lambda: clientProto

        serverTransport = ptcp.Ptcp(sf)
        clientTransport = ptcp.Ptcp(None)
        serverPort = reactor.listenUDP(0, serverTransport)
        clientPort = reactor.listenUDP(0, clientTransport)

        return (
            serverProto, clientProto,
            sf, cf,
            serverTransport, clientTransport,
            serverPort, clientPort
            )


    def testVerySimpleConnection(self):
        (serverProto, clientProto,
         sf, cf,
         serverTransport, clientTransport,
         serverPort, clientPort) = self.setUpForATest()

        def tearDown(ign):
            # print 'TEST TEARING DOWN'
            return defer.DeferredList([
                    serverPort.stopListening(),
                    clientPort.stopListening()
                    ])

        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port)

        def sendSomeBytes(ignored, n=10, server=False):
            if n:
                bytes = 'not a lot of bytes' * 1000
                if server:
                    serverProto.transport.write(bytes)
                else:
                    clientProto.transport.write(bytes)
                if server:
                    clientProto.buffer = []
                    d = clientProto.gotBytes(bytes)
                else:
                    serverProto.buffer = []
                    d = serverProto.gotBytes(bytes)
                return d.addCallback(sendSomeBytes, n - 1, not server)

        def loseConnections(ignored):
            serverProto.transport.loseConnection()
            clientProto.transport.loseConnection()
            return defer.DeferredList([
                    serverProto.onDisconn,
                    clientProto.onDisconn
                    ])

        dl = defer.DeferredList([serverProto.onConnect, clientProto.onConnect])
        dl.addCallback(sendSomeBytes)
        dl.addCallback(loseConnections)
        return dl.addCallback(tearDown)


    def testProducerConsumer(self):
        (serverProto, clientProto,
         sf, cf,
         serverTransport, clientTransport,
         serverPort, clientPort) = self.setUpForATest(
            ServerProtocol=TestProducerProtocol)

        def disconnected(ignored):
            # print 'Disconnected'
            self.assertEquals(
                ''.join(clientProto.buffer),
                ''.join([chr(n) * serverProto.WRITE_SIZE for n in range(serverProto.NUM_WRITES)]))
            # print 'Disconnect Done'

        def tearDown(ign):
            # print 'TEST TEARING DOWN'
            return defer.DeferredList([
                    serverPort.stopListening(),
                    clientPort.stopListening()
                    ])

        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port)
        return clientProto.onDisconn.addCallback(disconnected).addCallback(tearDown)


