# -*- test-case-name: vertex.test.test_ptcp -*-

import random, os

from twisted.internet import reactor, protocol, defer, error
from twisted.trial import unittest

from vertex import ptcp

def reallyLossy(method):
    r = random.Random()
    r.seed(42)
    def worseMethod(*a, **kw):
        if r.choice([True, True, False]):
            method(*a, **kw)
    return worseMethod

def insufficientTransmitter(method,  mtu):
    def worseMethod(bytes, addr):
        method(bytes[:mtu], addr)
    return worseMethod


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

class Django(protocol.ClientFactory):
    def __init__(self):
        self.onConnect = defer.Deferred()

    def buildProtocol(self, addr):
        p = protocol.ClientFactory.buildProtocol(self, addr)
        self.onConnect.callback(p)
        return p

    def clientConnectionFailed(self, conn, err):
        self.onConnect.errback(err)

class ConnectedPTCPMixin:
    serverPort = None

    def setUpForATest(self,
                      ServerProtocol=TestProtocol, ClientProtocol=TestProtocol):
        serverProto = ServerProtocol()
        clientProto = ClientProtocol()


        self.serverProto = serverProto
        self.clientProto = clientProto

        sf = protocol.ServerFactory()
        sf.protocol = lambda: serverProto

        cf = Django()
        cf.protocol = lambda: clientProto

        serverTransport = ptcp.PTCP(sf)
        clientTransport = ptcp.PTCP(None)

        self.serverTransport = serverTransport
        self.clientTransport = clientTransport

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
        td = []

        for ptcp in (self.serverTransport, self.clientTransport):
            td.append(ptcp.waitForAllConnectionsToClose())
        d = defer.DeferredList(td)
        return d


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

class PTCPTransportTestCase(ConnectedPTCPMixin, unittest.TestCase):
    def setUp(self):
        """
        I have no idea why one of these values is divided by 10 and the
        other is multiplied by 10.  -exarkun
        """
        self.patch(
            ptcp.PTCPConnection, '_retransmitTimeout',
            ptcp.PTCPConnection._retransmitTimeout / 10)
        self.patch(
            ptcp.PTCPPacket, 'retransmitCount',
            ptcp.PTCPPacket.retransmitCount * 10)


    def xtestWhoAmI(self):
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

    #testWhoAmI.skip = 'arglebargle'

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
            clientProto.transport.loseConnection()

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
            # print 'RESUMING', clientProto, clientTransport, clientPort
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
            serverProto.WRITE_SIZE = serverProto.transport.sendWindow * 5

            # print 'Connected'
            # print 'PAUSING CLIENT PROTO', clientProto, clientTransport, clientPort
            clientProto.transport.pauseProducing()
            return clientProto.onDisconn.addCallback(cbBytes)

        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port)
        connD = defer.DeferredList([clientProto.onConnect, serverProto.onConnect])
        connD.addCallback(cbConnect)
        return connD


class LossyTransportTestCase(PTCPTransportTestCase):
    def setUpForATest(self, *a, **kw):
        results = PTCPTransportTestCase.setUpForATest(self, *a, **kw)
        results[-2].write = reallyLossy(results[-2].write)
        results[-1].write = reallyLossy(results[-1].write)
        return results


class SmallMTUTransportTestCase(PTCPTransportTestCase):
    def setUpForATest(self, *a, **kw):
        results = PTCPTransportTestCase.setUpForATest(self, *a, **kw)
        results[-2].write = insufficientTransmitter(results[-2].write, 128)
        results[-1].write = insufficientTransmitter(results[-1].write, 128)
        return results



class TimeoutTestCase(ConnectedPTCPMixin, unittest.TestCase):
    def setUp(self):
        """
        Shorten the retransmit timeout so that tests finish more quickly.
        """
        self.patch(
            ptcp.PTCPConnection, '_retransmitTimeout',
            ptcp.PTCPConnection._retransmitTimeout / 10)


    def testConnectTimeout(self):
        (serverProto, clientProto,
         sf, cf,
         serverTransport, clientTransport,
         serverPort, clientPort) = self.setUpForATest()

        clientTransport.sendPacket = lambda *a, **kw: None
        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port)
        return cf.onConnect.addBoth(lambda result: result.trap(error.TimeoutError) and None)

    def testDataTimeout(self):
        (serverProto, clientProto,
         sf, cf,
         serverTransport, clientTransport,
         serverPort, clientPort) = self.setUpForATest()

        def cbConnected(ignored):
            serverProto.transport.ptcp.sendPacket = lambda *a, **kw: None
            clientProto.transport.write('Receive this data.')
            serverProto.transport.write('Send this data.') # have to send data
                                                           # or the server will
                                                           # never time out:
                                                           # need a
                                                           # SO_KEEPALIVE
                                                           # option somewhere
            return clientProto.onDisconn

        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port)

        d = defer.DeferredList([serverProto.onConnect, clientProto.onConnect])
        d.addCallback(cbConnected)
        return d
