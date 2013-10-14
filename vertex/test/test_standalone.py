# Copyright 2013 Twisted Matrix Laboratories.  See LICENSE file for details

"""
Tests for L{vertex.q2qstandalone}
"""

from pretend import stub

from twisted.protocols.amp import AMP
from twisted.test.iosim import connect, makeFakeClient, makeFakeServer
from twisted.trial.unittest import TestCase

from vertex.q2qadmin import AddUser
from vertex.q2qstandalone import IdentityAdmin


class AddUserAdminTests(TestCase):
    """
    Tests that IdentityAdmin can successfully add a user
    """
    def setUp(self):
        self.added = []

        def addUser(domain, username, password):
            self.added.append({'domain': domain,
                               'username': username,
                               'password': password})

        store = stub(addUser=addUser)
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
        serverTransport.getQ2QHost = lambda: stub(domain='Q2Q Host')

        client = AMP()
        pump = connect(admin, serverTransport, client, makeFakeClient(client))

        d = client.callRemote(AddUser, name='q2q username',
                              password='q2q password')
        pump.flush()

        # the username and password are added, along with the domain=q2q
        # host, to the IdentityAdmin's factory's store
        expected = {'domain': 'Q2Q Host',
                    'username': 'q2q username',
                    'password': 'q2q password'}
        self.assertEqual([expected], self.added)

        # the server responds with {}
        self.assertEqual({}, self.successResultOf(d))
