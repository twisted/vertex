# Copyright 2013 Twisted Matrix Laboratories.  See LICENSE file for details

"""
Tests for the AddUser (AMP Command) responder and client parts of vertex.
"""

from pretend import stub

from twisted.protocols.loopback import loopbackAsync
from twisted.test.proto_helpers import StringTransport
from twisted.trial.unittest import TestCase

from vertex.q2qadmin import AddUser
from vertex.q2qstandalone import IdentityAdmin
from vertex.q2qclient import UserAdder


class AddUserTests(TestCase):
    """
    Tests for the AMP AddUser command client and responder
    """
    def setUp(self):
        self.added = []

        def addUser(domain, username, password):
            self.added.append({'domain': domain,
                               'username': username,
                               'password': password})

        store = stub(addUser=addUser)
        self.adminFactory = stub(store=store)

        self.clientFactory = stub(name='q2q username',
                                  password='q2q password')

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

        class StringTransportWithQ2QStuff(StringTransport):
            def getQ2QAddress(self):
                return "Q2QAdress"

        admin.makeConnection(StringTransportWithQ2QStuff())

        client = UserAdder()
        client.factory = self.clientFactory

        loopbackAsync(client, admin)

        # upon connection being made, the UserAdder's factory's username and
        # password are added, along with the domain=q2q host, to the
        # IdentityAdmin's factory's store
        expected = {'domain': 'Q2QAddress',
                    'username': 'q2q username',
                    'password': 'q2q password'}
        self.assertEqual([expected], self.added)
