# Copyright 2005 Divmod, Inc.  See LICENSE file for details
# -*- test-case-name: vertex.test.test_q2q.TCPConnection.testSendingFiles -*-

"""
Connect between two endpoints using a message-based protocol to exchange
messages lazily in response to UI events, caching the protocol as necessary.
Using connection-oriented protocols, you will most likely not want to use this
class - you might end up retrieving a cached connection in the middle of a
chunk of data being sent.  For the purposes of this distinction, a
'message-oriented' protocol is one which has an API which either::

  a) writes only whole messages to its transport so there is never an
     opportunity to insert data into the middle of a message, or

  b) provides an API on the Protocol instance for queuing whole messages such
     that if partial messages are sent, calling the API multiple times will
     queue them internally so that clients do not need to care whether the
     connection is made or not.

It is worth noting that all Juice-derived protocols meet constraint (b).
"""

from zope.interface import implements

from twisted.internet.defer import maybeDeferred, DeferredList, Deferred
from twisted.internet.main import CONNECTION_LOST
from twisted.internet import interfaces
from twisted.internet.protocol import ClientFactory


class ConnectionCache:
    def __init__(self):
        """
        """
        # map (fromAddress, toAddress, protoName): protocol instance
        self.cachedConnections = {}
        # map (fromAddress, toAddress, protoName): list of Deferreds
        self.inProgress = {}

    def connectCached(self, endpoint, protocolFactory,
                      extraWork=lambda x: x,
                      extraHash=None):
        """See module docstring
        """
        key = endpoint, extraHash
        D = Deferred()
        if key in self.cachedConnections:
            D.callback(self.cachedConnections[key])
        elif key in self.inProgress:
            self.inProgress[key].append(D)
        else:
            self.inProgress[key] = [D]
            endpoint.connect(
                _CachingClientFactory(
                    self, key, protocolFactory,
                    extraWork))
        return D

    def cacheUnrequested(self, endpoint, extraHash, protocol):
        self.connectionMadeForKey((endpoint, extraHash), protocol)

    def connectionMadeForKey(self, key, protocol):
        deferreds = self.inProgress.pop(key, [])
        self.cachedConnections[key] = protocol
        for d in deferreds:
            d.callback(protocol)

    def connectionLostForKey(self, key):
        if key in self.cachedConnections:
            del self.cachedConnections[key]

    def connectionFailedForKey(self, key, reason):
        deferreds = self.inProgress.pop(key)
        for d in deferreds:
            d.errback(reason)

    def shutdown(self):
        return DeferredList(
            [maybeDeferred(p.transport.loseConnection)
             for p in self.cachedConnections.values()])


class _CachingClientFactory(ClientFactory):
    debug = False

    def __init__(self, cache, key, subFactory, extraWork):
        """
        @param cache: a Q2QService

        @param key: a 2-tuple of (endpoint, extra) that represents what
        connections coming from this factory are for.

        @param subFactory: a ClientFactory which I forward methods to.

        @param extraWork: extraWork(proto) -> Deferred which fires when the
        connection has been prepared sufficiently to be used by subsequent
        connections and can be counted as a success.
        """

        self.cache = cache
        self.key = key
        self.subFactory = subFactory
        self.finishedExtraWork = False
        self.extraWork = extraWork

    lostAsFailReason = CONNECTION_LOST

    def clientConnectionMade(self, protocol):
        def success(reason):
            self.cache.connectionMadeForKey(self.key, protocol)
            self.finishedExtraWork = True
            return protocol

        def failed(reason):
            self.lostAsFailReason = reason
            protocol.transport.loseConnection()
            return reason
        maybeDeferred(self.extraWork, protocol).addCallbacks(
            success, failed)

    def clientConnectionLost(self, connector, reason):
        if self.finishedExtraWork:
            self.cache.connectionLostForKey(self.key)
        else:
            self.cache.connectionFailedForKey(self.key,
                                              self.lostAsFailReason)
        self.subFactory.clientConnectionLost(connector, reason)

    def clientConnectionFailed(self, connector, reason):
        self.cache.connectionFailedForKey(self.key, reason)
        self.subFactory.clientConnectionFailed(connector, reason)

    def buildProtocol(self, addr):
        return _CachingTransportShim(self, self.subFactory.buildProtocol(addr))


class _CachingTransportShim:
    disconnecting = property(lambda self: self.transport.disconnecting)

    implements(interfaces.IProtocol)

    def __init__(self, factory, protocol):
        self.factory = factory
        self.protocol = protocol

        # IProtocol
        self.dataReceived = protocol.dataReceived
        self.connectionLost = protocol.connectionLost


    def makeConnection(self, transport):
        self.transport = transport
        self.protocol.makeConnection(transport)
        self.factory.clientConnectionMade(self.protocol)


    def __repr__(self):
        return 'Q2Q-Cached<%r, %r>' % (self.transport,
                                       self.protocol)

