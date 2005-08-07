
import random

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
        self.onConnect.callback(None)

    def connectionLost(self, reason):
        self.onDisconn.callback(None)

    def gotBytes(self, bytes):
        assert self._waiting is None
        if self.buffer == bytes:
            return defer.succeed(None)
        self._waiting = (defer.Deferred(), bytes)
        return self._waiting[0]

    def dataReceived(self, bytes):
        self.buffer.append(bytes)
        if self._waiting is not None:
            bytes = ''.join(self.buffer)
            if bytes == self._waiting[1]:
                self._waiting[0].callback(None)
                self._waiting = None

class TestProducerProtocol(protocol.Protocol):
    NUM_WRITES = 32
    WRITE_SIZE = 32

    def connectionMade(self):
        self.count = -1
        self.transport.registerProducer(self, False)

    def resumeProducing(self):
        self.count += 1
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

        self.serverProto = serverProto
        self.clientProto = clientProto

        sf = protocol.ServerFactory()
        sf.protocol = lambda: serverProto

        cf = protocol.ClientFactory()
        cf.protocol = lambda: clientProto

        serverTransport = ptcp.Ptcp(sf)
        clientTransport = ptcp.Ptcp(None)
        serverPort = reactor.listenUDP(0, serverTransport)
        clientPort = reactor.listenUDP(0, clientTransport)

        self.clientPort = clientPort
        self.serverPort = serverPort

        return (
            serverProto, clientProto,
            sf, cf,
            serverTransport, clientTransport,
            serverPort, clientPort
            )


    def tearDown(self):
        self.serverPort.stopListening()
        self.clientPort.stopListening()
        for p in self.serverProto, self.clientProto:
            p.transport._stopRetransmitting()

    def testVerySimpleConnection(self):
        (serverProto, clientProto,
         sf, cf,
         serverTransport, clientTransport,
         serverPort, clientPort) = self.setUpForATest()


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
        return dl


    def testProducerConsumer(self):
        (serverProto, clientProto,
         sf, cf,
         serverTransport, clientTransport,
         serverPort, clientPort) = self.setUpForATest(
            ServerProtocol=TestProducerProtocol)

        def disconnected(ignored):
            self.assertEquals(
                ''.join(clientProto.buffer),
                ''.join([chr(n) * serverProto.WRITE_SIZE for n in range(serverProto.NUM_WRITES)]))

        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port)
        return clientProto.onDisconn.addCallback(disconnected)



def randomLossy(method):
    def worseMethod(*a, **kw):
        if random.choice((True, False, False, False)):
            method(*a, **kw)
    return worseMethod

class RandomLossyTransportTestCase(PtcpTransportTestCase):
    def setUpForATest(self, *a, **kw):
        results = PtcpTransportTestCase.setUpForATest(self, *a, **kw)
        results[-2].write = randomLossy(results[-2].write)
        results[-2].writeSequence = randomLossy(results[-2].writeSequence)
        results[-1].write = randomLossy(results[-1].write)
        results[-1].writeSequence = randomLossy(results[-1].writeSequence)
        return results

