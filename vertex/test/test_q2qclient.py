# Copyright 2005-2008 Divmod, Inc.  See LICENSE file for details
# -*- vertex.test.test_q2q.UDPConnection -*-

"""
Tests for L{vertex.q2qclient}.
"""

from twisted.trial import unittest
from twisted.internet.protocol import Factory

from twisted.protocols.amp import AMP, AmpBox

from vertex import q2q, q2qclient

from vertex.test.helpers import FakeQ2QService


class TestCase(unittest.TestCase):
    def test_stuff(self):
        svc = FakeQ2QService()

        serverAddr = q2q.Q2QAddress("domain", "accounts")

        server = AMP()
        def respond(box):
            self.assertEqual(box['_command'], "add_user")
            self.assertEqual(box['name'], "user")
            self.assertEqual(box['password'], "password")
            return AmpBox()
        server.amp_ADD_USER = respond
        factory = Factory.forProtocol(lambda: server)
        chooser = {"identity-admin": factory}

        svc.listenQ2Q(serverAddr, chooser, "Admin")

        d = q2qclient.enregister(svc, q2q.Q2QAddress("domain", "user"), "password")
        svc.flush()

        self.successResultOf(d)
