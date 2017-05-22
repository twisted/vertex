# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
Tests for L{vertex.q2qstandalone}
"""

from pretend import call_recorder, call, stub

from twisted.internet import defer
from twisted.python.filepath import FilePath
from twisted.protocols.amp import AMP
from twisted.test.iosim import connect, makeFakeClient, makeFakeServer
from twisted.trial.unittest import TestCase, SynchronousTestCase

from vertex.q2q import Q2QAddress
from vertex.q2qadmin import AddUser, NotAllowed
from vertex.q2qstandalone import IdentityAdmin
from vertex.q2qstandalone import _UserStore
from vertex import ivertex

from zope.interface.verify import verifyObject

from ._fakes import _makeStubTxscrypt


class AddUserAdminTests(TestCase):
    """
    Tests that IdentityAdmin can successfully add a user
    """
    def setUp(self):
        self.addUser = call_recorder(
            lambda *args, **kwargs: defer.succeed("ignored")
        )
        store = stub(addUser=self.addUser)
        self.adminFactory = stub(store=store)


    def test_IdentityAdmin_responder_adds_user(self):
        """
        L{IdentityAdmin} has a L{AddUser} responder.
        """
        responder = IdentityAdmin().locateResponder(AddUser.commandName)
        self.assertIsNotNone(responder)


    def test_adds_user(self):
        """
        When L{UserAdder} is connected to L{IdentityAdmin}, the L{AddUser}
        command is called and L{IdentityAdmin} adds the user to its factory's
        store.
        """
        admin = IdentityAdmin()
        admin.factory = self.adminFactory

        serverTransport = makeFakeServer(admin)
        serverTransport.getQ2QHost = lambda: Q2QAddress('Q2Q Host')

        client = AMP()
        pump = connect(admin, serverTransport, client, makeFakeClient(client))

        d = client.callRemote(AddUser, name='q2q username',
                              password='q2q password')
        pump.flush()

        # The username and password are added, along with the domain=q2q
        # host, to the IdentityAdmin's factory's store
        self.assertEqual([call('Q2Q Host', 'q2q username', 'q2q password')],
                         self.addUser.calls)

        # The server responds with {}
        self.assertEqual({}, self.successResultOf(d))



class UserStoreTests(SynchronousTestCase):
    """
    Tests for L{_UserStore}
    """

    def setUp(self):
        self.userPath = FilePath(self.mktemp())
        self.userPath.makedirs()
        self.addCleanup(self.userPath.remove)
        self.makeUsers(self.userPath.path)


    def makeUsers(self, path):
        """
        Create a L{_UserStore} instance pointed at C{path}.

        @param path: The path where the instance will store its
            per-user files.
        @type path: L{str}
        """

        self.computeKeyReturns = defer.Deferred()

        self.fakeTxscrypt = _makeStubTxscrypt(
            computeKeyReturns=self.computeKeyReturns,
            checkPasswordReturns=defer.Deferred(),
        )

        self.users = _UserStore(
            path=path,
            keyDeriver=self.fakeTxscrypt,
        )


    def test_providesIQ2QUserStore(self):
        """
        The store provides L{ivertex.IQ2QUserStore}
        """
        verifyObject(ivertex.IQ2QUserStore, self.users)


    def assertStored(self, domain, username, password, key):
        """
        Assert that C{password} is stored under C{user} and C{domain}.

        @param domain: The user's 'domain.
        @type domain: L{str}

        @param username: The username.
        @type username: L{str}

        @param password: The password.
        @type password: L{str}

        @param key: The key "derived" from C{password}
        @type key: L{str}
        """
        storedDeferred = self.users.store(domain, username, password)

        self.assertNoResult(storedDeferred)
        self.computeKeyReturns.callback(key)
        self.assertEqual(self.successResultOf(storedDeferred),
                         (domain, username))


    def test_storeAndRetrieveKey(self):
        """
        A key is derived for a password and stored under the domain
        and user.
        """
        domain, username, password, key = "domain", "user", "password", "key"

        self.assertStored(domain, username, password, key)
        self.assertEqual(self.users.key(domain, username), key)


    def test_missingKey(self):
        """
        The derived key for an unknown domain and user combination is
        L{None}.
        """
        self.assertIsNone(self.users.key("mystery domain", "mystery user"))


    def test_storeExistingUser(self):
        """
        Attempting to overwrite an existing user fails with
        L{NotAllowed}
        """
        domain, username, password, key = "domain", "user", "password", "key"

        self.assertStored(domain, username, password, key)

        self.makeUsers(self.userPath.path)

        failure = self.failureResultOf(self.users.store(domain,
                                                        username,
                                                        password))
        self.assertIsInstance(failure.value, NotAllowed)
