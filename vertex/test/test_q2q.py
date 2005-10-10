# Copyright 2005 Divmod, Inc.  See LICENSE file for details
# -*- vertex.test.test_q2q.UDPConnection -*-

import os
from cStringIO import StringIO

from twisted.trial import unittest, util
from twisted.application import service
from twisted.internet import reactor, protocol, defer
from twisted.protocols import basic
from twisted.python import log
from twisted.python import failure
from twisted.cred import checkers
from twisted.internet.error import ConnectionDone
# from twisted.internet.main import CONNECTION_DONE

from zope.interface import implements
from twisted.internet.interfaces import IResolverSimple

from vertex import q2q, q2qclient, sslverify, juice
def noResources(*a):
    return []

class FakeConnectTCP:
    implements(IResolverSimple)

    def __init__(self, connectTCP):
        self._connectTCP = connectTCP
        self.hostPortToHostPort = {}
        self.hostToLocalHost = {}
        self.counter = 1

    def addHostPort(self, hostname, fakePortNumber, realPortNumber):
        if hostname in self.hostToLocalHost:
            localIP = self.hostToLocalHost[hostname]
        else:
            localIP = '127.0.0.%d' % (self.counter,)
            self.counter += 1
            self.hostToLocalHost[hostname] = localIP

        self.hostPortToHostPort[(localIP, fakePortNumber)] = (localIP, realPortNumber)
        self.hostPortToHostPort[(hostname, fakePortNumber)] = (hostname, realPortNumber)

    def connectTCP(self, host, port, *args, **kw):
        localhost, localport = self.hostPortToHostPort.get((host,port), (host, port))
        return self._connectTCP(localhost, localport, *args, **kw)

    def getHostSync(self,name):
        result = self.hostToLocalHost[name]
        return result

    def getHostByName(self, name, timeout):
        return defer.maybeDeferred(self.getHostSync, name)

def runOneDeferred(d):
    L = []
    d.addBoth(L.append)
    reactor.callLater(0, d.addCallback, lambda ign: reactor.crash())
    reactor.run()
    if L:
        if isinstance(L[0], failure.Failure):
            L[0].trap()
        return L[0]
    raise unittest.FailTest("Keyboard Interrupt")

class Utility(unittest.TestCase):
    def testServiceInitialization(self):
        svc = q2q.Q2QService(noResources)
        svc.certificateStorage.addPrivateCertificate("test.domain")

        cert = svc.certificateStorage.getPrivateCertificate("test.domain")
        self.failUnless(cert.getPublicKey().matches(cert.privateKey))

class OneTrickPony(juice.Juice):
    def juice_TRICK(self, box):
        return juice.QuitBox(tricked='True')

class OneTrickPonyServerFactory(juice.JuiceServerFactory):
    protocol = OneTrickPony

class OneTrickPonyClient(juice.Juice):
    def connectionMade(self):
        self.sendCommand('trick').chainDeferred(self.factory.ponged)

class OneTrickPonyClientFactory(juice.JuiceClientFactory):
    protocol = OneTrickPonyClient

    def __init__(self, ponged):
        self.ponged = ponged

    def buildProtocol(self, addr):
        result = juice.JuiceClientFactory.buildProtocol(self, addr)
        self.proto = result
        return result

    def clientConnectionFailed(self, connector, reason):
        self.ponged.errback(reason)


class DataEater(protocol.Protocol):
    def __init__(self):
        self.waiters = []
        self.data = []
        self.count = 0

    def dataReceived(self, data):
        if not data:
            raise RuntimeError("Empty string delivered to DataEater")
        self.data.append(data)
        self.count += len(data)
        for count, waiter in self.waiters[:]:
            if self.count >= count:
                waiter.callback(self.count)

    def removeD(self, result, size, d):
        # XXX done as a callback because 1.3 util.wait actually calls a
        # callback on the deferred
        self.waiters.remove((size, d))
        return result

    def waitForCount(self, size):
        D = defer.Deferred()
        self.waiters.append((size, D))
        self.waiters.sort()
        self.waiters.reverse()
        return D.addBoth(self.removeD, size, D)

    def buildProtocol(self, addr):
        return self

class DataFeeder(protocol.Protocol):
    def __init__(self, fobj):
        self.fobj = fobj

    def clientConnectionFailed(self, connector, reason):
        log.msg("DataFeeder client connection failed:")
        log.err(reason)

    def clientConnectionLost(self, connector, reason):
        pass

    def connectionMade(self):
        basic.FileSender().beginFileTransfer(self.fobj, self.transport)

    def buildProtocol(self, addr):
        return self

class StreamingDataFeeder(protocol.Protocol):
    DELAY = 0.01
    CHUNK = 1024
    paused = False
    pauseCount = 0
    resumeCount = 0
    stopCount = 0
    outCount = 0
    call = None

    def __init__(self, infile):
        self.file = infile

    def clientConnectionFailed(sef, connector, reason):
        log.msg("StreamingDataFeeder client connection failed:")
        log.err(reason)

    def clientConnectionLost(self, connector, reason):
        pass

    def connectionMade(self):
        self.nextChunk = self.file.read(self.CHUNK)
        self.transport.registerProducer(self, True)
        self.call = reactor.callLater(self.DELAY, self._keepGoing)

    def _keepGoing(self):
        self.call = None
        if self.paused:
            return
        chunk = self.nextChunk
        self.nextChunk = self.file.read(self.CHUNK)
        self.outCount += len(chunk)
        if chunk:
            self.transport.write(chunk)
        if self.nextChunk:
            self.call = reactor.callLater(self.DELAY, self._keepGoing)


    def pauseProducing(self):
        self.paused = True
        self.pauseCount += 1
        if self.call is not None:
            self.cancelMe()

    def resumeProducing(self):
        self.paused = False
        if self.call is not None:
            self.cancelMe()
        self.call = reactor.callLater(self.DELAY, self._keepGoing)
        self.resumeCount += 1

    def cancelMe(self):
        self.call.cancel()
        self.call = None

    def stopProducing(self):
        self.paused = True
        self.stopCount += 1
        if self.call is not None:
            self.cancelMe()

    def buildProtocol(self, addr):
        return self


class ErroneousClientError(Exception):
    pass

class EngenderError(juice.Command):
    commandName = 'Engender-Error'

class Break(juice.Command):
    commandName = 'Break'

class Flag(juice.Command):
    commandName = 'Flag'

class Erroneous(juice.Juice):
    flag = False
    def command_BREAK(self):
        raise ErroneousClientError("Zoop")
    command_BREAK.command = Break

    def command_ENGENDER_ERROR(self):
        return Break().do(self)
    command_ENGENDER_ERROR.command = EngenderError

    def command_FLAG(self):
        self.flag = True
    command_FLAG.command = Flag

class ErroneousServerFactory(juice.JuiceServerFactory):
    protocol = Erroneous

class ErroneousClientFactory(juice.JuiceClientFactory):
    protocol = Erroneous

class Greet(juice.Command):
    commandName = 'Greet'

class Greeter(juice.Juice, protocol.ServerFactory, protocol.ClientFactory):
    def __init__(self, issueGreeting, startupD):
        juice.Juice.__init__(self, issueGreeting)
        self.startupD = startupD

    def buildProtocol(self, addr):
        return self

    def connectionMade(self):
        Greet().do(self).chainDeferred(self.startupD)

    def command_GREET(self):
        self.greeted = True
        return dict()
    command_GREET.command = Greet

class Q2QConnectionTestCase(unittest.TestCase):
    streamer = None

    fromResource = 'clientResource'
    toResource = 'serverResource'

    fromDomain = 'origin.domain.example.com'
    spoofedDomain = 'spoofed.domain.example.com'
    toDomain = 'destination.domain.example.org'

    userReverseDNS = 'i.watch.too.much.tv'
    inboundTCPPortnum = 0
    udpEnabled = False
    virtualEnabled = False

    def _makeQ2QService(self, certificateEntity, pff=None):
        svc = q2q.Q2QService(pff, q2qPortnum=0,
                             inboundTCPPortnum=self.inboundTCPPortnum)
        svc.udpEnabled = self.udpEnabled
        svc.virtualEnabled = self.virtualEnabled
        if '@' not in certificateEntity:
            svc.certificateStorage.addPrivateCertificate(certificateEntity)
        svc.debugName = certificateEntity
        return svc


    def _addQ2QProtocol(self, name, factory):
        resourceKey = (self.fromAddress,
                       self.toAddress, name)
        self.resourceMap[resourceKey] = factory

    def protocolFactoryFactory(self, *key):
        if key in self.resourceMap:
            return [(self.resourceMap[key], 'test-description')]
        return []


    def setUp(self):
        log.ignoreErrors(ConnectionDone)
        self.fromAddress = q2q.Q2QAddress(self.fromDomain, self.fromResource)
        self.toAddress = q2q.Q2QAddress(self.toDomain, self.toResource)

        # A mapping of host names to port numbers Our connectTCP will always
        # connect to 127.0.0.1 and on a port which is a value in this
        # dictionary.
        fakeDNS = FakeConnectTCP(reactor.connectTCP)
        reactor.connectTCP = fakeDNS.connectTCP

        # ALSO WE MUST DO OTHER SIMILAR THINGS
        self._oldResolver = reactor.resolver
        reactor.installResolver(fakeDNS)

        # Set up a know-nothing service object for the client half of the
        # conversation.
        self.serverService2 = self._makeQ2QService(self.fromDomain, noResources)

        # Do likewise for the server half of the conversation.  Also, allow
        # test methods to set up some trivial resources which we can attempt to
        # access from the client.
        self.resourceMap = {}
        self.serverService = self._makeQ2QService(self.toDomain,
                                                  self.protocolFactoryFactory)

        self.msvc = service.MultiService()
        self.serverService2.setServiceParent(self.msvc)
        self.serverService.setServiceParent(self.msvc)

        # Let the kernel allocate a random port for each of these service's listeners
        self.msvc.startService()

        fakeDNS.addHostPort(
            self.fromDomain, 8788,
            self.serverService2.q2qPort.getHost().port)

        fakeDNS.addHostPort(
            self.toDomain, 8788,
            self.serverService.q2qPort.getHost().port)

        self._addQ2QProtocol('pony', OneTrickPonyServerFactory())

        self.dataEater = DataEater()
        self._addQ2QProtocol('eat', self.dataEater)

        self._addQ2QProtocol('error', ErroneousServerFactory())

    def tearDown(self):
        reactor.installResolver(self._oldResolver)
        del reactor.connectTCP
        return self.msvc.stopService()
        # log.clearIgnores()

class ConnectionTestMixin:

    def testConnectWithIntroduction(self):
        ponged = defer.Deferred()
        self.serverService2.connectQ2Q(self.fromAddress,
                                      self.toAddress,
                                      'pony',
                                      OneTrickPonyClientFactory(ponged))
        return ponged.addCallback(lambda answerBox: self.failUnless('tricked' in answerBox))

    def addClientService(self, toAddress, secret, serverService):
        return self._addClientService(
            toAddress.resource, secret, serverService, toAddress.domain)

    def _addClientService(self, username,
                          privateSecret, serverService,
                          serverDomain):
        svc = self._makeQ2QService(username + '@' + serverDomain)
        serverService.certificateStorage.addUser(serverDomain,
                                                 username,
                                                 privateSecret)
        svc.setServiceParent(self.msvc)
        return svc.authorize(q2q.Q2QAddress(serverDomain, username),
                             privateSecret).addCallback(lambda x: svc)


    def testListening(self):

        self.clientServerService = util.wait(self.addClientService(
                self.toAddress, 'aaaa', self.serverService))


        ponyFactory = OneTrickPonyServerFactory()
        ponged = defer.Deferred()
        util.wait(self.clientServerService.listenQ2Q(self.toAddress,
                                                {'pony2': ponyFactory},
                                                'ponies suck'))


        self.clientClientService = util.wait(self.addClientService(
                self.fromAddress, 'bbbb', self.serverService2))
        otpcf = OneTrickPonyClientFactory(ponged)
        self.clientClientService.connectQ2Q(self.fromAddress,
                                            self.toAddress,
                                            'pony2',
                                            otpcf)

        answerBox = util.wait(ponged)

        T = otpcf.proto.transport
        self.assertEquals(T.getQ2QPeer(), self.toAddress)
        self.assertEquals(T.getQ2QHost(), self.fromAddress)
        self.failUnless('tricked' in answerBox)

    def testChooserGetsThreeChoices(self):
        ponyFactory = OneTrickPonyServerFactory()
        self.testListening()

        # print 'dang yo'

        self.clientServerService2 = util.wait(self.addClientService(
                self.toAddress, 'aaaa', self.serverService))

        # print 'ultra frack'

        util.wait(self.clientServerService2.listenQ2Q(self.toAddress,
                                                      {'pony': ponyFactory},
                                                      'ponies are weird'))

        # print 'frack'

        ponged = defer.Deferred()
        util.wait(self.clientServerService.listenQ2Q(self.toAddress,
                                                     {'pony': ponyFactory},
                                                     'ponies rule'))

        # print 'WAITING IS DONE'

        expectedList = ['ponies rule', 'ponies are weird', 'test-description']
        def chooser(servers):
            self.failUnlessEqual(len(servers), 3)
            for server in servers:
                expectedList.remove(server['description'])
                if server['description'] == 'ponies rule':
                    self.assertEquals(
                        self.clientServerService.certificateStorage.getPrivateCertificate(str(self.toAddress)),
                        server['certificate'])
                    yield server

        util.wait(self.clientClientService.connectQ2Q(
                self.fromAddress,
                self.toAddress,
                'pony',
                OneTrickPonyClientFactory(ponged),
                chooser=chooser))

        self.failUnlessEqual(expectedList, [])

    def testTwoGreetings(self):
        d1 = defer.Deferred()
        d2 = defer.Deferred()
        client = Greeter(False, d1)
        server = Greeter(True, d2)
        self._addQ2QProtocol('greet', server)
        self.serverService2.connectQ2Q(self.fromAddress,
                                      self.toAddress,
                                      'greet',
                                      client)
        util.wait(defer.DeferredList([d1, d2]))
        self.failUnless(client.greeted)
        self.failUnless(server.greeted)


    def testSendingFiles(self):
        SIZE = 1024 * 500
        self.streamer = StreamingDataFeeder(StringIO('x' * SIZE))
        self.streamer.CHUNK = 8192
        util.wait(self.serverService2.connectQ2Q(self.fromAddress,
                                                 self.toAddress, 'eat',
                                                 DataFeeder(StringIO('y' * SIZE))))
        util.wait(self.serverService2.connectQ2Q(self.fromAddress,
                                                 self.toAddress, 'eat',
                                                 self.streamer))

        # self.assertEquals( len(self.serverService.liveConnections), 1)
        # XXX currently there are 2 connections but there should only be 1: the
        # connection cache is busted, need a separate test for that
        for liveConnection in self.serverService.iterconnections():
            liveConnection.transport.pauseProducing()
        wfc = self.dataEater.waitForCount(SIZE * 2)
        self.assertRaises(defer.TimeoutError, util.wait, wfc, timeout=3)
        for liveConnection in self.serverService.iterconnections():
            liveConnection.transport.resumeProducing()
        util.wait(self.dataEater.waitForCount(SIZE * 2), 30)
        self.failUnless(self.streamer.pauseCount > 0)
        self.failUnless(self.streamer.resumeCount > 0)

    def testBadIssuerOnSelfSignedCert(self):
        x = self.testConnectWithIntroduction()
        def actualTest(result):
            ponged = defer.Deferred()
            signer = self.serverService2.certificateStorage.getPrivateCertificate(
                self.fromDomain).privateKey
            req = signer.requestObject(sslverify.DN(commonName=self.toDomain))
            sreq = signer.signRequestObject(sslverify.DN(commonName=self.fromDomain),
                                                       req, 12345)
            selfSignedLie = sslverify.PrivateCertificate.fromCertificateAndKeyPair(
                sreq, signer)
            self.serverService2.connectQ2Q(self.fromAddress,
                                          self.toAddress,
                                          'pony',
                                          OneTrickPonyClientFactory(ponged),
                                          selfSignedLie,
                                          fakeFromDomain=self.toDomain).addErrback(
                lambda e: e.trap(sslverify.VerifyError))

            return self.assertFailure(ponged, sslverify.VerifyError)
        return x.addCallback(actualTest)


    def testBadCertRequestSubject(self):
        kp = sslverify.KeyPair.generate()
        subject = sslverify.DN(commonName='HACKERX',
                               localityName='INTERNETANIA')
        reqobj = kp.requestObject(subject)

        fakereq = kp.requestObject(subject)
        ssigned = kp.signRequestObject(subject, fakereq, 1)
        certpair = sslverify.PrivateCertificate.fromCertificateAndKeyPair
        fakecert = certpair(ssigned, kp)
        apc = self.serverService2.certificateStorage.addPrivateCertificate

        def _2(secured):
            D = q2q.Sign(certificate_request=reqobj,
                         password='itdoesntmatter').do(secured)
            def _1(dcert):
                cert = dcert['certificate']
                privcert = certpair(cert, kp)
                apc(str(self.fromAddress), privcert)
            return D.addCallback(_1)

        d = self.serverService2.getSecureConnection(
            self.fromAddress, self.fromAddress.domainAddress(), authorize=False,
            usePrivateCertificate=fakecert,
            ).addCallback(_2)

        def unexpectedSuccess(result):
            self.fail("Expected BadCertificateRequest, got %r" % (result,))
        def expectedFailure(err):
            err.trap(q2q.BadCertificateRequest)
        d.addCallbacks(unexpectedSuccess, expectedFailure)
        util.wait(d)

    def testClientSideUnhandledException(self):
        d = self.serverService2.connectQ2Q(
            self.fromAddress, self.toAddress, 'error',
            ErroneousClientFactory())
        def connected(proto):
            return EngenderError().do(proto)
        def exploded(err):
            err.trap(ConnectionDone)
        d.addCallback(connected)
        d.addCallbacks(self.successIsFailure, exploded)
        d.addCallback(lambda ign: log.flushErrors(ErroneousClientError))
        util.wait(d)

    def successIsFailure(self, success):
        self.fail()

    def testTwoBadWrites(self):
        d = self.serverService2.connectQ2Q(
            self.fromAddress, self.toAddress, 'error',
            ErroneousClientFactory())

        def connected(proto):
            def trapit(what):
                what.trap(juice.UnhandledRemoteJuiceError)
            Break().do(proto).addCallbacks(self.successIsFailure, trapit)
            return Flag().do(proto)
        def err(x):
            x.trap(ConnectionDone)

        d.addCallback(connected)
        d.addCallbacks(self.successIsFailure, err)
        d.addCallback(lambda ign: log.flushErrors(ErroneousClientError))
        util.wait(d)




class VirtualConnection(Q2QConnectionTestCase, ConnectionTestMixin):
    inboundTCPPortnum = None
    udpEnabled = False
    virtualEnabled = True

    def testListening(self):
        pass

    def testChooserGetsThreeChoices(self):
        pass

    testListening.skip = 'virtual port forwarding not implemented'
    testChooserGetsThreeChoices.skip = 'cant do this without testListening'

class UDPConnection(Q2QConnectionTestCase, ConnectionTestMixin):
    # skip = 'yep'
    inboundTCPPortnum = None
    udpEnabled = True
    virtualEnabled = False

class TCPConnection(Q2QConnectionTestCase, ConnectionTestMixin):
    inboundTCPPortnum = 0
    udpEnabled = False
    virtualEnabled = False

class TestProtocol(juice.Juice):
    def juice_GETADDRESSINFO(self, request):
        h = self.transport.getHost()
        p = self.transport.getPeer()
        return juice.Box(
            Host_Resource=h.resource,
            Host_Domain=h.domain,
            Peer_Resource=p.resource,
            Peer_Domain=p.domain)

class TestServerFactory(juice.JuiceClientFactory):
    protocol = TestProtocol

# A special treat for Glyph to enjoy later.

def _findService(svc, matcher):
    try:
        truth = matcher(svc)
    except:
        log.err()
        truth = False
    if truth:
        yield svc
    try:
        i = iter(svc)
    except:
        # print 'Not iterable:', svc
        return
    for subsvc in i:
        for blah in _findService(subsvc, matcher):
            yield blah

# class LiveServerMixin:
#     serverDomain = 'test.domain.example.com'

#     def jackDNS(self, *info):
#         self.fakeDNS = FakeConnectTCP(reactor.connectTCP)
#         reactor.connectTCP = self.fakeDNS.connectTCP
#         self._oldResolver = reactor.resolver
#         reactor.installResolver(self.fakeDNS)

#         for (hostname, oldport, newport) in info:
#             self.fakeDNS.addHostPort(hostname, oldport, newport)

#     def unjackDNS(self):
#         del reactor.connectTCP
#         reactor.installResolver(self._oldResolver)

# class AuthorizeTestCase(unittest.TestCase, LiveServerMixin):
#     authUser = 'authtestuser'
#     authPass = 'p4ssw0rd'

#     def setUp(self):
#         self.testDir, serverService = self.deploy()
#         self.serverService = service.IServiceCollection(serverService)
#         self.serverService.startService()
#         self.clientDir = os.path.join(self.testDir, 'client')
#         self.clientService = q2qclient.ClientQ2QService(self.clientDir)

#         q2qPort = self.getQ2QService().q2qPort.getHost().port
#         self.jackDNS((self.serverDomain, 8788, q2qPort))

#     def tearDown(self):
#         self.unjackDNS()
#         util.wait(self.serverService.stopService())
#         util.wait(self.clientService.stopService())

#     def testAuthorize(self):
#         self.createUser(self.authUser, self.authPass)

#         d = self.clientService.authorize(
#             q2q.Q2QAddress(self.serverDomain, self.authUser),
#             self.authPass)

#         result = runOneDeferred(d)

#         self.failUnless(os.path.exists(os.path.join(self.clientDir, 'public')))
#         self.failUnless(os.path.exists(os.path.join(self.clientDir, 'public', self.serverDomain + '.pem')))
#         self.failUnless(os.path.exists(os.path.join(self.clientDir, 'private')))
#         self.failUnless(os.path.exists(os.path.join(self.clientDir, 'private', self.authUser + '@' + self.serverDomain + '.pem')))
