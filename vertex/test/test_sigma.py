# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from cStringIO import StringIO

from twisted.internet.protocol import FileWrapper
from twisted.internet import defer
from twisted.python.failure import Failure
from twisted.python.filepath import FilePath

from twisted.trial import unittest

from epsilon.test.iosim import IOPump

from vertex.q2q import Q2QAddress
from vertex import sigma

from vertex.test.mock_data import data as TEST_DATA

class FakeQ2QTransport(FileWrapper):

    def __init__(self, stringio, q2qhost, q2qpeer):
        FileWrapper.__init__(self, stringio)
        self.q2qhost = q2qhost
        self.q2qpeer = q2qpeer

    def getQ2QPeer(self):
        return self.q2qpeer

    def getQ2QHost(self):
        return self.q2qhost

class FakeDelayedCall:
    def __init__(self, fqs, tup):
        self.fqs = fqs
        self.tup = tup

    def cancel(self):
        self.fqs.calls.remove(self.tup)

class FakeQ2QService:
    # XXX TODO: move this into test_q2q and make sure that all the q2q tests
    # run with it in order to verify that the test harness is not broken.

    def __init__(self):
        self.listeners = {}     # map listening {(q2qid, protocol name):(protocol
                                # factory, protocol description)}
        self.pumps = []         # a list of IOPumps that we have to flush
        self.calls = []
        self.time = 0

    def callLater(self, s, f, *a, **k):
        # XXX TODO: return canceller
        assert f is not None
        tup = (self.time + s, f, a, k)
        self.calls.append(tup)
        self.calls.sort()
        return FakeDelayedCall(self, tup)

    def flush(self, debug=False):
        result = True
        while result:
            self.time += 1
            result = False
            for x in range(2):
                # run twice so that timed functions can interact with I/O
                for pump in self.pumps:
                    if pump.flush(debug):
                        result = True
                if debug:
                    print 'iteration finished.  continuing?', result
                c = self.calls
                self.calls = []
                for s, f, a, k in c:
                    if debug:
                        print 'timed event', s, f, a, k
                    f(*a,**k)
        return result

    def listenQ2Q(self, fromAddress, protocolsToFactories, serverDescription):
        for pname, pfact in protocolsToFactories.items():
            self.listeners[fromAddress, pname] = pfact, serverDescription
        return defer.succeed(None)

    def connectQ2Q(self, fromAddress, toAddress,
                   protocolName, protocolFactory,
                   chooser=lambda x: x and [x[0]]):
        # XXX update this when q2q is updated to return a connector rather than
        # a Deferred.

        # XXX this isn't really dealing with the multiple-connectors use case
        # now.  sigma doesn't need this functionality, but we will need to
        # update this class to do it properly before using it to test other Q2Q
        # code.

        listener, description = self.listeners.get((toAddress, protocolName))
        if listener is None:
            print 'void listener', fromAddress, toAddress, self.listeners, self.listener
            reason = Failure(KeyError())
            protocolFactory.clientConnectionFailed(None, reason)
            return defer.fail(reason)
        else:
            cio = StringIO()
            sio = StringIO()

            server = listener.buildProtocol(fromAddress)
            client = protocolFactory.buildProtocol(toAddress)

            servertpt = FakeQ2QTransport(sio, toAddress, fromAddress)
            clienttpt = FakeQ2QTransport(cio, fromAddress, toAddress)

            server.makeConnection(servertpt)
            client.makeConnection(clienttpt)
            pump = IOPump(client, server, cio, sio, False)
            self.pumps.append(pump)

            return defer.succeed(client)


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


def childrenOf(x):
    # this should be a part of FilePath, but hey
    return map(x.child, x.listdir())
