# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from twisted.internet import defer
from twisted.python.failure import Failure
#from twisted.internet.task import Clock

from twisted.test.iosim import connectedServerAndClient, FakeTransport



class FakeDelayedCall:
    def __init__(self, fqs, tup):
        self.fqs = fqs
        self.tup = tup

    def cancel(self):
        self.fqs.calls.remove(self.tup)



class FakeQ2QTransport(FakeTransport):

    def __init__(self, protocol, isServer, q2qhost, q2qpeer):
        FakeTransport.__init__(self, protocol, isServer)
        self.q2qhost = q2qhost
        self.q2qpeer = q2qpeer

    def getQ2QPeer(self):
        return self.q2qpeer

    def getQ2QHost(self):
        return self.q2qhost



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
            def makeFakeClient(c):
                ft = FakeQ2QTransport(c, False, fromAddress, toAddress)
                return ft

            def makeFakeServer(s):
                ft = FakeQ2QTransport(s, True, toAddress, fromAddress)
                return ft

            client, server, pump = connectedServerAndClient(
                lambda: listener.buildProtocol(fromAddress),
                lambda: protocolFactory.buildProtocol(toAddress),
                makeFakeClient,
                makeFakeServer)
            self.pumps.append(pump)

            return defer.succeed(client)
