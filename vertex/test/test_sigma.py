# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from twisted.python.failure import Failure
from twisted.python.filepath import FilePath
from twisted.internet.error import ConnectionDone

from twisted.trial import unittest

from vertex.q2q import Q2QAddress
from vertex import sigma, conncache

from vertex.test.mock_data import data as TEST_DATA
from vertex.test.test_conncache import DisconnectingTransport

from vertex.test.helpers import FakeQ2QService

sender = Q2QAddress("sending-data.net", "sender")
receiver = Q2QAddress("receiving-data.org", "receiver")

class TestBase(unittest.TestCase):
    def setUp(self):
        self.realChunkSize = sigma.CHUNK_SIZE
        sigma.CHUNK_SIZE = 100
        svc = self.service = FakeQ2QService()
        fname = self.mktemp()

        sf = self.sfile = FilePath(fname)
        if not sf.parent().isdir():
            sf.parent().makedirs()
        sf.open('w').write(TEST_DATA)
        self.senderNexus = sigma.Nexus(svc, sender,
                                       sigma.BaseNexusUI(self.mktemp()),
                                       svc.callLater)

    def tearDown(self):
        self.senderNexus.stopService()
        sigma.CHUNK_SIZE = self.realChunkSize


class BasicTransferTest(TestBase):
    def setUp(self):
        TestBase.setUp(self)
        self.stoppers = []
        self.receiverNexus = sigma.Nexus(self.service, receiver,
                                         sigma.BaseNexusUI(self.mktemp()),
                                         self.service.callLater)
        self.stoppers.append(self.receiverNexus)


    def tearDown(self):
        TestBase.tearDown(self)
        for stopper in self.stoppers:
            stopper.stopService()


    def testOneSenderOneRecipient(self):
        self.senderNexus.push(self.sfile, 'TESTtoTEST', [receiver])
        self.service.flush()
        peerThingyoes = childrenOf(self.receiverNexus.ui.basepath)
        self.assertEquals(len(peerThingyoes), 1)
        rfiles = childrenOf(peerThingyoes[0])
        self.assertEquals(len(rfiles), 1)
        rfile = rfiles[0]
        rfdata = rfile.open().read()
        self.assertEquals(len(rfdata),
                          len(TEST_DATA))
        self.assertEquals(rfdata, TEST_DATA,
                          "file values unequal")

    def testOneSenderManyRecipients(self):
        raddresses = [Q2QAddress("receiving-data.org", "receiver%d" % (x,))
                      for x in range(10)]

        nexi = [sigma.Nexus(self.service,
                            radr,
                            sigma.BaseNexusUI(self.mktemp()),
                            self.service.callLater) for radr in raddresses]

        self.stoppers.extend(nexi)

        self.senderNexus.push(self.sfile, 'TESTtoTEST', raddresses)
        self.service.flush()

        receivedIntroductions = 0

        for nexium in nexi:
            receivedIntroductions += nexium.ui.receivedIntroductions
        self.failUnless(receivedIntroductions > 1)

        for nexium in nexi:
            peerFiles = childrenOf(nexium.ui.basepath)
            self.assertEquals(len(peerFiles), 1)
            rfiles = childrenOf(peerFiles[0])
            self.assertEquals(len(rfiles), 1, rfiles)
            rfile = rfiles[0]
            self.assertEquals(rfile.open().read(),
                              TEST_DATA,
                              "file value mismatch")


class TestSigmaConnectionCache(unittest.TestCase):
    """
    Tests for the interaction of L{sigma.SigmaProtocol} and
    L{conncache.ConnectionCache}.
    """

    def test_connectionLost_unregistersFromConnectionCache(self):
        """
        L{sigma.SigmaProtocol.connectionLost} notifies the connection
        cache that the connection is lost.
        """
        cache = conncache.ConnectionCache()

        class FakeNexus(object):
            conns = cache
            addr = object()
            svc = object()

        protocol = sigma.SigmaProtocol(FakeNexus())
        transport = DisconnectingTransport()
        q2qPeer = object()
        transport.getQ2QPeer = lambda: q2qPeer

        protocol.makeConnection(transport)
        d = cache.shutdown()
        transport.loseConnectionDeferred.callback(None)
        self.assertNoResult(d)
        protocol.connectionLost(Failure(ConnectionDone))
        self.successResultOf(d)


def childrenOf(x):
    # this should be a part of FilePath, but hey
    return map(x.child, x.listdir())
