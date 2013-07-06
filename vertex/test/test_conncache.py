# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Tests for L{vertex.conncache}.
"""

from twisted.internet.protocol import ClientFactory, Protocol
from twisted.internet.defer import Deferred
from twisted.trial.unittest import TestCase
from twisted.test.proto_helpers import StringTransport

from vertex import conncache


class FakeEndpoint(object):
    """
    Fake vertex endpoint for tesing.

    @ivar factories: factories endpoint has been connected to.
    @type factories: L{list} of
        L{ClientFactory<twisted.internet.protocol.ClientFactory>}s.
    """

    def __init__(self):
        self.factories = []


    def connect(self, factory):
        """
        Record factory used for connection.

        @param factory: factory to connect
        """
        self.factories.append(factory)



class DisconnectingTransport(StringTransport):
    def loseConnection(self):
        self.loseConnectionDeferred = Deferred()
        return self.loseConnectionDeferred



class TestConnectionCache(TestCase):
    """
    Tests for L{conncache.ConnectionCache}.

    @ivar cache: cache to use for testing.
    @type cache: L{conncache.ConnectionCache}
    """

    def setUp(self):
        """
        Create a L{conncache.ConnectionCache}, endpoint and protocol to test
        against.
        """
        self.cache = conncache.ConnectionCache()
        self.endpoint = FakeEndpoint()
        self.protocol = Protocol()


    def getCachedConnection(self):
        """
        Ask the L{conncache.ConnectionCache} for a connection to the endpoint
        created in L{setUp}.
        """
        factory = ClientFactory()
        factory.protocol = lambda: self.protocol
        return self.cache.connectCached(self.endpoint, factory)


    def test_connectCached(self):
        """
        When called with an endpoint it isn't connected to,
        L{conncache.ConnectionCache.connectCache} connects
        to that endpoint and returns a deferred that fires
        with that protocol.
        """
        d = self.getCachedConnection()

        self.assertEqual(len(self.endpoint.factories), 1)
        connectedFactory = self.endpoint.factories.pop(0)
        connectedProtocol = connectedFactory.buildProtocol(None)
        self.assertNoResult(d)
        connectedProtocol.makeConnection(object())

        self.assertEqual(self.successResultOf(d), self.protocol)


    def test_connectCached_cachedConnection(self):
        """
        When called with an endpoint it is connected to,
        L{conncache.ConnectionCache.connectCache} returns
        a deferred that has been fired with that protocol.
        """
        self.getCachedConnection()

        connectedFactory = self.endpoint.factories.pop(0)
        connectedProtocol = connectedFactory.buildProtocol(None)
        connectedProtocol.makeConnection(object())

        d = self.getCachedConnection()

        self.assertEqual(len(self.endpoint.factories), 0)
        self.assertEqual(self.successResultOf(d), self.protocol)


    def test_connectCached_inProgressConnection(self):
        """
        When called with an endpoint it is connecting to,
        L{conncache.ConnectionCache.connectCache} returns
        a deferred that fires with that protocol.
        """
        self.getCachedConnection()
        connectedFactory = self.endpoint.factories.pop(0)

        d = self.getCachedConnection()
        self.assertEqual(len(self.endpoint.factories), 0)
        self.assertNoResult(d)

        connectedProtocol = connectedFactory.buildProtocol(None)
        connectedProtocol.makeConnection(object())

        self.assertEqual(self.successResultOf(d), self.protocol)


    def test_shutdown_waitsForConnectionLost(self):
        """
        L{conncache.ConnectionCache.shutdown} returns a
        deferred that fires after all protocols have been
        completely disconnected.

        @see: U{http://mumak.net/stuff/twisted-disconnect.html}
        """
        self.getCachedConnection()

        connectedFactory = self.endpoint.factories.pop(0)
        connectedProtocol = connectedFactory.buildProtocol(None)
        transport = DisconnectingTransport()
        connectedProtocol.makeConnection(transport)

        d = self.cache.shutdown()
        self.assertNoResult(d)
        transport.loseConnectionDeferred.callback(None)
        self.assertNoResult(d)
        connectedFactory.clientConnectionLost(None, None)
        self.successResultOf(d)
