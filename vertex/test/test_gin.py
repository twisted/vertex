
from twisted.internet import reactor, protocol, defer
from twisted.trial import unittest

from vertex import gin

class TestProtocol(protocol.Protocol):
    buffer = ''
    def __init__(self):
        self.onConnect = defer.Deferred()
        self.onDisconn = defer.Deferred()
        self._waiting = None

    def connectionMade(self):
        print 'CONNECTION MADE'
        self.onConnect.callback(None)

    def connectionLost(self, reason):
        print 'DISCO INFERNO'
        self.onDisconn.callback(None)

    def gotBytes(self, bytes):
        assert self._waiting is None
        if self.buffer == bytes:
            return defer.succeed(None)
        self._waiting = (defer.Deferred(), bytes)
        return self._waiting[0]

    def dataReceived(self, bytes):
        print 'yay', len(bytes)
        self.buffer += bytes
        if self._waiting is not None:
            if self.buffer == self._waiting[1]:
                self._waiting[0].callback(None)
                self._waiting = None


class GinTransportTestCase(unittest.TestCase):
    def testVerySimpleConnection(self):
        print
        serverTransport = gin.Gin()
        clientTransport = gin.Gin()
        serverPort = reactor.listenUDP(0, serverTransport)
        clientPort = reactor.listenUDP(0, clientTransport)

        def tearDown(ign):
            print 'TEST TEARING DOWN'
            return defer.DeferredList([
                    serverPort.stopListening(),
                    clientPort.stopListening()
                    ])

        serverProto = TestProtocol()
        clientProto = TestProtocol()
        sf = protocol.ServerFactory()
        sf.protocol = lambda: serverProto

        cf = protocol.ClientFactory()
        cf.protocol = lambda: clientProto

        serverConnID = serverTransport.listen(sf)
        clientConnID = clientTransport.connect(cf, '127.0.0.1', serverPort.getHost().port, serverConnID)

        def sendSomeBytes(ignored, n=10, server=False):
            if n:
                bytes = 'not a lot of bytes' * 1000
                if server:
                    serverProto.transport.write(bytes)
                else:
                    clientProto.transport.write(bytes)
                if server:
                    clientProto.buffer = ''
                    d = clientProto.gotBytes(bytes)
                else:
                    serverProto.buffer = ''
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
