# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Tests for L{vertex.conncache}.
"""

from twisted.internet.protocol import ClientFactory, Protocol
from twisted.trial.unittest import TestCase

from vertex import conncache


class FakeEndpoint(object):
    """
    Fake vertex endpoint for tesing.

    @ivar factories: factories endpoint has been connected to.
    @type factories: L{list} of L{ClientFactory<twisted.internet.protocol.ClientFactory>}s.
    """

    def __init__(self):
        self.factories = []


    def connect(self, factory):
        """
        Record factory used for connection.

        @param factory: factory to connect
        """
        self.factories.append(factory)



class TestConnectionCache(TestCase):
    """
    Tests for L{conncache.ConnectionCache}.

    @ivar cache: cache to use for testing.
    @type cache: L{conncache.ConnectionCache}
    """

    def setUp(self):
        """
        Create a L{conncache.ConnectionCache} to test against.
        """
        self.cache = conncache.ConnectionCache()


    def test_connectCached(self):
        """
        When called with an endpoint it isn't connected to,
        L{conncache.ConnectionCache.connectCache} connects
        to that endpoint and returns a deferred that fires
        with that protocol.
        """
        endpoint = FakeEndpoint()
        protocol = Protocol()
        factory = ClientFactory()
        factory.protocol = lambda: protocol
        d = self.cache.connectCached(endpoint, factory)

        self.assertEqual(len(endpoint.factories), 1)
        connectedFactory = endpoint.factories.pop(0)
        connectedProtocol = connectedFactory.buildProtocol(None)
        self.assertNoResult(d)
        connectedProtocol.makeConnection(object())

        self.assertEqual(self.successResultOf(d), protocol)


    def test_connectCached_cachedConnection(self):
        """
        When called with an endpoint it is connected to,
        L{conncache.ConnectionCache.connectCache} returns
        a deferred that has been fired with that protocol.
        """
        endpoint = FakeEndpoint()
        protocol = Protocol()
        factory = ClientFactory()
        factory.protocol = lambda: protocol
        self.cache.connectCached(endpoint, factory)

        connectedFactory = endpoint.factories.pop(0)
        connectedProtocol = connectedFactory.buildProtocol(None)
        connectedProtocol.makeConnection(object())

        d = self.cache.connectCached(endpoint, object())

        self.assertEqual(len(endpoint.factories), 0)
        self.assertEqual(self.successResultOf(d), protocol)


    def test_connectCached_inProgressConnection(self):
        """
        When called with an endpoint it is connecting to,
        L{conncache.ConnectionCache.connectCache} returns
        a deferred that fires with that protocol.
        """
        endpoint = FakeEndpoint()
        protocol = Protocol()
        factory = ClientFactory()
        factory.protocol = lambda: protocol
        self.cache.connectCached(endpoint, factory)
        connectedFactory = endpoint.factories.pop(0)

        d = self.cache.connectCached(endpoint, object())
        self.assertEqual(len(endpoint.factories), 0)
        self.assertNoResult(d)

        connectedProtocol = connectedFactory.buildProtocol(None)
        connectedProtocol.makeConnection(object())

        self.assertEqual(self.successResultOf(d), protocol)
