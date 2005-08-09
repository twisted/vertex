# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from cStringIO import StringIO

from twisted.internet.protocol import FileWrapper
from twisted.internet import defer
from twisted.python.failure import Failure

from twisted.trial import unittest

from vertex.q2q import Q2QAddress
from vertex import sigma

from vertex.test.test_juice import IOPump
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

class TestBase(unittest.TestCase, sigma.BaseNexusUI):
    def setUp(self):
        self.realChunkSize = sigma.CHUNK_SIZE
        sigma.CHUNK_SIZE = 100
        svc = self.service = FakeQ2QService()

        self.sfile = StringIO(TEST_DATA)
        self.senderNexus = sigma.Nexus(svc, sender, self, svc.callLater)

    def tearDown(self):
        self.senderNexus.stopService()
        sigma.CHUNK_SIZE = self.realChunkSize


class BasicTransferTest(TestBase):
    def setUp(self):
        TestBase.setUp(self)
        self.rfiles = []
        self.stoppers = []
        self.receiverNexus = sigma.Nexus(self.service, receiver,
                                         self,
                                         self.service.callLater)
        self.stoppers.append(self.receiverNexus)


    def tearDown(self):
        TestBase.tearDown(self)
        for stopper in self.stoppers:
            stopper.stopService()


    def allocateFile(self, sharename, peer):
        s = StringIO()
        self.rfiles.append(s)
        return s


    def testOneSenderOneRecipient(self):
        self.senderNexus.push(self.sfile, 'TEST->TEST', [receiver])
        self.service.flush()
        self.assertEquals(len(self.rfiles), 1)
        rfile = self.rfiles[0]
        self.assertEquals(len(rfile.getvalue()),
                          len(self.sfile.getvalue()))
        self.assertEquals(rfile.getvalue(),
                          self.sfile.getvalue(),
                          "file values unequal")

    def testOneSenderManyRecipients(self):
        raddresses = [Q2QAddress("receiving-data.org", "receiver%d" % (x,))
                      for x in range(10)]

        nexi = [sigma.Nexus(self.service,
                            radr,
                            self,
                            self.service.callLater) for radr in raddresses]

        self.stoppers.extend(nexi)

        self.senderNexus.push(self.sfile, 'TEST->TEST', raddresses)
        self.service.flush()

        self.failUnless(self.receivedIntroductions > 1)

        for rfile in self.rfiles:
            self.assertEquals(rfile.getvalue(),
                              self.sfile.getvalue(),
                              "file value mismatch")

