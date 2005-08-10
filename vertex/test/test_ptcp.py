# -*- test-case-name: vertex.test.test_ptcp -*-

import random, os

from twisted.internet import reactor, protocol, defer, task
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
        if ''.join(self.buffer) == bytes:
            return defer.succeed(None)
        self._waiting = (defer.Deferred(), bytes)
        return self._waiting[0]

    def dataReceived(self, bytes):
        self.buffer.append(bytes)
        if self._waiting is not None:
            bytes = ''.join(self.buffer)
            if not self._waiting[1].startswith(bytes):
                x = len(os.path.commonprefix([bytes, self._waiting[1]]))
                print x
                print 'it goes wrong starting with', repr(bytes[x:x+100]), repr(self._waiting[1][x:x+100])
            if bytes == self._waiting[1]:
                self._waiting[0].callback(None)
                self._waiting = None

class TestProducerProtocol(protocol.Protocol):
    NUM_WRITES = 32
    WRITE_SIZE = 32

    def __init__(self):
        self.onConnect = defer.Deferred()
        self.onPaused = defer.Deferred()

    def connectionMade(self):
        self.onConnect.callback(None)
        self.count = -1
        self.transport.registerProducer(self, False)

    def pauseProducing(self):
        if self.onPaused is not None:
            self.onPaused.callback(None)
            self.onPaused = None

    def resumeProducing(self):
        self.count += 1
        if self.count < self.NUM_WRITES:
            bytes = chr(self.count) * self.WRITE_SIZE
            # print 'Issuing a write', len(bytes)
            self.transport.write(bytes)
            if self.count == self.NUM_WRITES - 1:
                # Last time through, intentionally drop the connection before
                # the buffer is empty to ensure we handle this case properly.
                # print 'Disconnecting'
                self.transport.loseConnection()
        else:
            # print 'Unregistering'
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


    def testWhoAmI(self):
        (serverProto, clientProto,
         sf, cf,
         serverTransport, clientTransport,
         serverPort, clientPort) = self.setUpForATest()

        def gotAddress(results):
            (serverSuccess, serverAddress), (clientSuccess, clientAddress) = results
            self.failUnless(serverSuccess)
            self.failUnless(clientSuccess)

            self.assertEquals(serverAddress[1], serverPort.getHost().port)
            self.assertEquals(clientAddress[1], clientPort.getHost().port)

        def connectionsMade(ignored):
            return defer.DeferredList([serverProto.transport.whoami(), clientProto.transport.whoami()]).addCallback(gotAddress)

        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port)

        return defer.DeferredList([serverProto.onConnect, clientProto.onConnect]).addCallback(connectionsMade)

    testWhoAmI.skip = 'arglebargle'

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
                ''.join([chr(n) * serverProto.WRITE_SIZE
                         for n in range(serverProto.NUM_WRITES)]))

        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port)
        return clientProto.onDisconn.addCallback(disconnected)


    def testTransportProducer(self):
        (serverProto, clientProto,
         sf, cf,
         serverTransport, clientTransport,
         serverPort, clientPort) = self.setUpForATest()

        resumed = []
        def resumeProducing():
            resumed.append(True)
            clientProto.transport.resumeProducing()

        def cbBytes(ignored):
            self.failUnless(resumed)

        def cbConnect(ignored):
            BYTES = 'Here are bytes'
            clientProto.transport.pauseProducing()
            serverProto.transport.write(BYTES)
            reactor.callLater(2, resumeProducing)
            return clientProto.gotBytes(BYTES).addCallback(cbBytes)


        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port)
        connD = defer.DeferredList([clientProto.onConnect, serverProto.onConnect])
        connD.addCallback(cbConnect)
        return connD

    def testTransportProducerProtocolProducer(self):
        (serverProto, clientProto,
         sf, cf,
         serverTransport, clientTransport,
         serverPort, clientPort) = self.setUpForATest(
            ServerProtocol=TestProducerProtocol)

        paused = []
        def cbPaused(ignored):
            # print 'Paused'
            paused.append(True)
            clientProto.transport.resumeProducing()
        serverProto.onPaused.addCallback(cbPaused)

        def cbBytes(ignored):
            # print 'Disconnected'
            self.assertEquals(
                ''.join(clientProto.buffer),
                ''.join([chr(n) * serverProto.WRITE_SIZE
                         for n in range(serverProto.NUM_WRITES)]))

        def cbConnect(ignored):
            # The server must write enough to completely fill the outgoing buffer,
            # since our peer isn't ACKing /anything/ and our server waits for
            # writes to be acked before proceeding.
            serverProto.WRITE_SIZE = serverProto.transport.sendWindow * 2

            # print 'Connected'
            clientProto.transport.pauseProducing()
            return clientProto.onDisconn.addCallback(cbBytes)

        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port)
        connD = defer.DeferredList([clientProto.onConnect, serverProto.onConnect])
        connD.addCallback(cbConnect)
        return connD


def randomLossy(method):
    def worseMethod(*a, **kw):
        if random.choice((True, False, False)):
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


def insufficientTransmitter(method,  mtu):
    def worseMethod(bytes, addr):
        method(bytes[:mtu], addr)
    return worseMethod

class SmallMTUTransportTestCase(PtcpTransportTestCase):
    def setUpForATest(self, *a, **kw):
        results = PtcpTransportTestCase.setUpForATest(self, *a, **kw)
        results[-2].write = insufficientTransmitter(results[-2].write, 512)
        results[-1].write = insufficientTransmitter(results[-1].write, 512)
        return results
