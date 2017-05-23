# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
# -*- vertex.test.test_q2q.UDPConnection -*-

"""
Tests for L{vertex.q2q}.
"""
from pretend import call

from cStringIO import StringIO

from twisted.trial import unittest
from twisted.application import service
from twisted.cred.error import UnauthorizedLogin
from twisted.internet import reactor, protocol, defer
from twisted.internet.task import deferLater
from twisted.internet.ssl import DistinguishedName, PrivateCertificate, KeyPair
from twisted.protocols import basic
from twisted.python import log
from twisted.python import failure
from twisted.internet.error import ConnectionDone

from zope.interface import implements
from zope.interface.verify import verifyObject
from twisted.internet.interfaces import IResolverSimple

from twisted.protocols.amp import UnknownRemoteError, QuitBox, Command, AMP

import txscrypt

from ._fakes import (_makeStubTxscrypt,
                     _makeStubCredentials,
                     _makeStubIQ2QUserStore)

from vertex import q2q
from vertex import ivertex


def noResources(*a):
    return []



class FakeConnectTCP:
    implements(IResolverSimple)

    def __init__(self, connectTCP):
        self._connectTCP = connectTCP
        self._hostToFakeIP = {}
        self._fakeIPToReal = {}
        self.counter = 1


    def addHostPort(self, hostname, fakePortNumber, realPortNumber):
        fakeIP = '0.%d.%d.%d' % ((self.counter,) * 3)
        localIP = '127.0.0.1'
        self.counter += 1
        self._hostToFakeIP[hostname] = fakeIP
        self._fakeIPToReal[(fakeIP, fakePortNumber)] = (
            localIP, realPortNumber)


    def _translateAddress(self, host, port):
        """
        Translate a potentially fake host and port into a real host and port.
        """
        if host in self._hostToFakeIP:
            host = self._hostToFakeIP[host]
        if (host, port) in self._fakeIPToReal:
            return self._fakeIPToReal[(host, port)]
        # This happens because we aren't intermediating the transport itself,
        # and q2q is determining what IPs and ports to connect to via
        # transport.getHost().port.  this should be fixed by getting rid of
        # this fixture entirely and going with proto_helpers...
        return host, port


    def connectTCP(self, host, port, *args, **kw):
        localhost, localport = self._translateAddress(host, port)
        return self._connectTCP(localhost, localport, *args, **kw)


    def getHostByName(self, name, timeout):
        def _getHostSync(name):
            result = self._hostToFakeIP[name]
            return result
        return defer.maybeDeferred(_getHostSync, name)



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



class UtilityTests(unittest.TestCase):
    def test_ServiceInitialization(self):
        svc = q2q.Q2QService(noResources)
        svc.certificateStorage.addPrivateCertificate("test.domain")

        cert = svc.certificateStorage.getPrivateCertificate("test.domain")
        self.failUnless(cert.getPublicKey().matches(cert.privateKey))



class OneTrickPony(AMP):
    def amp_TRICK(self, box):
        return QuitBox(tricked='True')



class OneTrickPonyServerFactory(protocol.ServerFactory):
    protocol = OneTrickPony



class OneTrickPonyClient(AMP):
    def connectionMade(self):
        self.callRemoteString('trick').chainDeferred(self.factory.ponged)



class OneTrickPonyClientFactory(protocol.ClientFactory):
    protocol = OneTrickPonyClient

    def __init__(self, ponged):
        self.ponged = ponged


    def buildProtocol(self, addr):
        result = protocol.ClientFactory.buildProtocol(self, addr)
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



class EngenderError(Command):
    commandName = 'Engender-Error'



class Break(Command):
    commandName = 'Break'



class Flag(Command):
    commandName = 'Flag'



class FatalError(Exception):
    pass



class Fatal(Command):
    fatalErrors = {FatalError: "quite bad"}



class Erroneous(AMP):
    def _fatal(self):
        raise FatalError("This is fatal.")
    Fatal.responder(_fatal)

    flag = False


    def _break(self):
        raise ErroneousClientError("Zoop")
    Break.responder(_break)


    def _engenderError(self):
        def ebBroken(err):
            err.trap(ConnectionDone)
            # This connection is dead.  Avoid having an error logged by turning
            # this into success; the result can't possibly get to the other
            # side, anyway. -exarkun
            return {}
        return self.callRemote(Break).addErrback(ebBroken)
    EngenderError.responder(_engenderError)


    def _flag(self):
        self.flag = True
        return {}
    Flag.responder(_flag)



class ErroneousServerFactory(protocol.ServerFactory):
    protocol = Erroneous



class ErroneousClientFactory(protocol.ClientFactory):
    protocol = Erroneous



class Greet(Command):
    commandName = 'Greet'



class Greeter(AMP, protocol.ServerFactory, protocol.ClientFactory):
    def __init__(self, isServer, startupD):
        self.isServer = isServer
        AMP.__init__(self)
        self.startupD = startupD


    def buildProtocol(self, addr):
        return self


    def connectionMade(self):
        self.callRemote(Greet).chainDeferred(self.startupD)


    def _greet(self):
        self.greeted = True
        return dict()
    Greet.responder(_greet)



class Q2QConnectionTestCase(unittest.TestCase):
    streamer = None

    fromResource = 'clientResource'
    toResource = 'serverResource'

    fromDomain = 'origin.domain.example.com'
    fromIP = '127.0.0.1'
    spoofedDomain = 'spoofed.domain.example.com'
    toDomain = 'destination.domain.example.org'
    toIP = '127.0.0.1'

    userReverseDNS = 'i.watch.too.much.tv'
    inboundTCPPortnum = 0
    udpEnabled = False
    virtualEnabled = False

    def _makeQ2QService(self, certificateEntity, publicIP, pff=None):
        svc = q2q.Q2QService(pff, q2qPortnum=0,
                             inboundTCPPortnum=self.inboundTCPPortnum,
                             publicIP=publicIP)
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


    def protocolFactoryLookup(self, *key):
        if key in self.resourceMap:
            return [(self.resourceMap[key], 'test-description')]
        return []


    def setUp(self):
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
        self.serverService2 = self._makeQ2QService(
            self.fromDomain, self.fromIP, noResources
        )

        # Do likewise for the server half of the conversation.  Also, allow
        # test methods to set up some trivial resources which we can attempt to
        # access from the client.
        self.resourceMap = {}
        self.serverService = self._makeQ2QService(
            self.toDomain, self.toIP, self.protocolFactoryLookup
        )

        self.msvc = service.MultiService()
        self.serverService2.setServiceParent(self.msvc)
        self.serverService.setServiceParent(self.msvc)

        # Let the kernel allocate a random port for each of
        # these service's listeners
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



class ConnectionTestMixin:

    def test_ConnectWithIntroduction(self):
        ponged = defer.Deferred()
        self.serverService2.connectQ2Q(self.fromAddress,
                                       self.toAddress,
                                       'pony',
                                       OneTrickPonyClientFactory(ponged))
        return ponged.addCallback(
            lambda answerBox: self.failUnless('tricked' in answerBox)
        )


    def addClientService(self, toAddress, secret, serverService):
        return self._addClientService(
            toAddress.resource, secret, serverService, toAddress.domain)


    def _addClientService(self, username,
                          privateSecret, serverService,
                          serverDomain):
        svc = self._makeQ2QService(username + '@' + serverDomain, None)
        svc.setServiceParent(self.msvc)

        added = serverService.certificateStorage.addUser(serverDomain,
                                                         username,
                                                         privateSecret)

        def _cbAuthorize(_):
            return svc.authorize(q2q.Q2QAddress(serverDomain, username),
                                 privateSecret).addCallback(lambda x: svc)

        added.addCallback(_cbAuthorize)
        return added


    def test_Listening(self):
        _1 = self.addClientService(self.toAddress, 'aaaa', self.serverService)
        def _1c(_1result):
            self.clientServerService = _1result
            ponyFactory = OneTrickPonyServerFactory()
            _2 = self.clientServerService.listenQ2Q(self.toAddress,
                                                    {'pony2': ponyFactory},
                                                    'ponies suck')

            def _2c(ignored):
                _3 = self.addClientService(
                        self.fromAddress, 'bbbb', self.serverService2)
                def _3c(_3result):
                    self.clientClientService = _3result

                    _4 = defer.Deferred()
                    otpcf = OneTrickPonyClientFactory(_4)
                    self.clientClientService.connectQ2Q(self.fromAddress,
                                                        self.toAddress,
                                                        'pony2',
                                                        otpcf)
                    def _4c(answerBox):
                        T = otpcf.proto.transport
                        self.assertEquals(T.getQ2QPeer(), self.toAddress)
                        self.assertEquals(T.getQ2QHost(), self.fromAddress)
                        self.failUnless('tricked' in answerBox)

                    return _4.addCallback(_4c)
                return _3.addCallback(_3c)
            return _2.addCallback(_2c)
        return _1.addCallback(_1c)


    def test_ChooserGetsThreeChoices(self):

        def actualTest(ign):
            ponyFactory = OneTrickPonyServerFactory()
            _1 = self.addClientService(
                self.toAddress, 'aaaa', self.serverService)
            def _1c(_1result):
                self.clientServerService2 = _1result

                _2 = self.clientServerService2.listenQ2Q(self.toAddress,
                                                         {'pony': ponyFactory},
                                                         'ponies are weird')
                def _2c(ign):
                    _3 = self.clientServerService.listenQ2Q(
                        self.toAddress, {'pony': ponyFactory}, 'ponies rule'
                    )
                    def _3c(ign):
                        expectedList = [
                            'ponies rule',
                            'ponies are weird',
                            'test-description'
                        ]
                        def chooser(servers):
                            self.failUnlessEqual(len(servers), 3)
                            for server in servers:
                                expectedList.remove(server['description'])
                                if server['description'] == 'ponies rule':
                                    self.assertEquals(
                                        self.clientServerService.certificateStorage.getPrivateCertificate(str(self.toAddress)),
                                        server['certificate'])
                                    yield server

                        factory = protocol.ClientFactory()
                        factory.protocol = AMP
                        _4 = self.clientClientService.connectQ2Q(
                            self.fromAddress,
                            self.toAddress,
                            'pony',
                            factory,
                            chooser=chooser)
                        def _4c(ign):
                            self.failUnlessEqual(expectedList, [])
                        return _4.addCallback(_4c)
                    return _3.addCallback(_3c)
                return _2.addCallback(_2c)
            return _1.addCallback(_1c)
        return self.test_Listening().addCallback(actualTest)


    def test_TwoGreetings(self):
        d1 = defer.Deferred()
        d2 = defer.Deferred()
        client = Greeter(False, d1)
        server = Greeter(True, d2)
        self._addQ2QProtocol('greet', server)
        self.serverService2.connectQ2Q(self.fromAddress,
                                      self.toAddress,
                                      'greet',
                                      client)
        def _(x):
            self.failUnless(client.greeted)
            self.failUnless(server.greeted)
        return defer.DeferredList([d1, d2]).addCallback(_)


    def test_SendingFiles(self):
        SIZE = 1024 * 500
        self.streamer = StreamingDataFeeder(StringIO('x' * SIZE))
        self.streamer.CHUNK = 8192
        a = self.serverService2.connectQ2Q(
            self.fromAddress,
            self.toAddress, 'eat',
            DataFeeder(StringIO('y' * SIZE))
        )
        b = self.serverService2.connectQ2Q(self.fromAddress,
                                           self.toAddress, 'eat',
                                           self.streamer)

        def dotest(ign):
            # For:
            # self.assertEquals( len(self.serverService.liveConnections), 1)
            # XXX currently there are 2 connections but there should only be 1:
            # the connection cache is busted, need a separate test for that
            for liveConnection in self.serverService.iterconnections():
                liveConnection.transport.pauseProducing()
            wfc = self.dataEater.waitForCount(SIZE * 2)
            resumed = [False]
            def shouldntHappen(x):
                if resumed[0]:
                    return x
                else:
                    self.fail("wfc fired with: " + repr(x))
            wfc.addBoth(shouldntHappen)
            def keepGoing(ign):
                resumed[0] = True
                for liveConnection in self.serverService.iterconnections():
                    liveConnection.transport.resumeProducing()
                def assertSomeStuff(ign):
                    self.failUnless(self.streamer.pauseCount > 0)
                    self.failUnless(self.streamer.resumeCount > 0)
                return self.dataEater.waitForCount(
                    SIZE * 2
                ).addCallback(assertSomeStuff)
            return deferLater(reactor, 3, lambda: None).addCallback(keepGoing)
        return defer.DeferredList([a, b]).addCallback(dotest)
    test_SendingFiles.skip = "hangs forever"


    def test_BadIssuerOnSelfSignedCert(self):
        x = self.test_ConnectWithIntroduction()
        def actualTest(result):
            ponged = defer.Deferred()
            signer = self.serverService2.certificateStorage.getPrivateCertificate(
                self.fromDomain).privateKey
            req = signer.requestObject(
                DistinguishedName(commonName=self.toDomain)
            )
            sreq = signer.signRequestObject(
                DistinguishedName(commonName=self.fromDomain), req, 12345)
            selfSignedLie = PrivateCertificate.fromCertificateAndKeyPair(
                sreq, signer)
            def report(result):
                return result
            self.serverService2.connectQ2Q(
                self.fromAddress,
                self.toAddress,
                'pony',
                OneTrickPonyClientFactory(ponged),
                usePrivateCertificate=selfSignedLie,
                fakeFromDomain=self.toDomain
            ).addErrback(lambda e: e.trap(q2q.VerifyError))

            return self.assertFailure(ponged, q2q.VerifyError)
        return x.addCallback(actualTest)


    def test_BadCertRequestSubject(self):
        kp = KeyPair.generate()
        subject = DistinguishedName(commonName='HACKERX',
                                    localityName='INTERNETANIA')
        reqobj = kp.requestObject(subject)

        fakereq = kp.requestObject(subject)
        ssigned = kp.signRequestObject(subject, fakereq, 1)
        certpair = PrivateCertificate.fromCertificateAndKeyPair
        fakecert = certpair(ssigned, kp)
        apc = self.serverService2.certificateStorage.addPrivateCertificate

        def _2(secured):
            D = secured.callRemote(
                q2q.Sign,
                certificate_request=reqobj,
                password='itdoesntmatter')
            def _1(dcert):
                cert = dcert['certificate']
                privcert = certpair(cert, kp)
                apc(str(self.fromAddress), privcert)
            return D.addCallback(_1)

        d = self.serverService2.getSecureConnection(
            self.fromAddress, self.fromAddress.domainAddress(),
            authorize=False,
            usePrivateCertificate=fakecert,
            ).addCallback(_2)

        def unexpectedSuccess(result):
            self.fail("Expected BadCertificateRequest, got %r" % (result,))
        def expectedFailure(err):
            err.trap(q2q.BadCertificateRequest)
        d.addCallbacks(unexpectedSuccess, expectedFailure)
        return d


    def test_ClientSideUnhandledException(self):
        d = self.serverService2.connectQ2Q(
            self.fromAddress, self.toAddress, 'error',
            ErroneousClientFactory())
        def connected(proto):
            return proto.callRemote(EngenderError)
        d.addCallback(connected)
        # The unhandled, undeclared error causes the connection to be closed
        # from the other side.
        d = self.assertFailure(d, ConnectionDone, UnknownRemoteError)
        def cbDisconnected(err):
            self.assertEqual(
                len(self.flushLoggedErrors(ErroneousClientError)),
                1)
        d.addCallback(cbDisconnected)
        return d


    def successIsFailure(self, success):
        self.fail()


    def test_TwoBadWrites(self):
        d = self.serverService2.connectQ2Q(
            self.fromAddress, self.toAddress, 'error',
            ErroneousClientFactory())

        def connected(proto):
            d1 = self.assertFailure(proto.callRemote(Fatal), FatalError)
            def noMoreCalls(_):
                self.assertFailure(proto.callRemote(Flag), ConnectionDone)
            d1.addCallback(noMoreCalls)
            return d1
        d.addCallback(connected)
        return d



class DefaultCertificateStoreTests(unittest.SynchronousTestCase):
    """
    Tests for L{q2q.DefaultCertificateStore}.
    """

    def setUp(self):
        self.store = q2q.DefaultCertificateStore()
        self.username = "username@domain"

        self.checkPasswordReturns = defer.Deferred()
        self.credentials = _makeStubCredentials(
            username=self.username,
            password="password",
            checkPasswordReturns=self.checkPasswordReturns,
        )


    def test_requestAvatarIdUnknownUser(self):
        """
        A L{Deferred} failed with L{UnauthorizedLogin} is returned
        when an unknown user is requested.
        """
        self.store.users = _makeStubIQ2QUserStore(
            keyReturns=None,
            storeReturns=defer.Deferred(),
        )

        failure = self.failureResultOf(
            self.store.requestAvatarId(self.credentials),
        )
        self.assertIsInstance(failure.value, UnauthorizedLogin)


    def test_requestAvatarIdWrongPassword(self):
        """
        A L{Deferred} that fires with with L{UnauthorizedLogin} is returned
        when the wrong password is provided.
        """
        self.store.users = _makeStubIQ2QUserStore(
            keyReturns="key",
            storeReturns=defer.Deferred(),
        )

        wrongPasswordDeferred = self.store.requestAvatarId(self.credentials)

        self.assertNoResult(wrongPasswordDeferred)
        self.checkPasswordReturns.callback(False)
        failure = self.failureResultOf(wrongPasswordDeferred)
        self.assertIsInstance(failure.value, UnauthorizedLogin)


    def test_requestAvatarId(self):
        """
        A L{Deferred} that fires with with the username is returned
        when the the right password is provided.
        """
        self.store.users = _makeStubIQ2QUserStore(
            keyReturns="key",
            storeReturns=defer.Deferred(),
        )

        wrongPasswordDeferred = self.store.requestAvatarId(self.credentials)

        self.assertNoResult(wrongPasswordDeferred)
        self.checkPasswordReturns.callback(True)
        self.assertEqual(self.successResultOf(wrongPasswordDeferred),
                         self.username)



class VirtualConnectionTests(Q2QConnectionTestCase, ConnectionTestMixin):
    inboundTCPPortnum = None
    udpEnabled = False
    virtualEnabled = True

    def test_Listening(self):
        pass


    def test_ChooserGetsThreeChoices(self):
        pass

    test_Listening.skip = 'virtual port forwarding not implemented'
    test_ChooserGetsThreeChoices.skip = 'cant do this without test_Listening'



class UDPConnection(Q2QConnectionTestCase, ConnectionTestMixin):
    inboundTCPPortnum = None
    udpEnabled = True
    virtualEnabled = False



class TCPConnection(Q2QConnectionTestCase, ConnectionTestMixin):
    inboundTCPPortnum = 0
    udpEnabled = False
    virtualEnabled = False



class UsernameShadowPasswordTests(unittest.SynchronousTestCase):
    """
    Tests for L{q2q.UsernameShadowPassword}.
    """

    def setUp(self):
        self.username = "username"
        self.password = "password"

        self.checkPasswordReturns = defer.Deferred()

        self.fakeTxscrypt = _makeStubTxscrypt(
            computeKeyReturns=defer.Deferred(),
            checkPasswordReturns=self.checkPasswordReturns,
        )

        self.credentials = q2q.UsernameShadowPassword(
            username=self.username,
            password=self.password,
            keyDeriver=self.fakeTxscrypt,
        )


    def test_checkPassword(self):
        """
        The provided key is checked against the credentials'
        plain-text password, and the result returned
        """
        key = "key"
        result = self.credentials.checkPassword(key)
        self.assertEqual(
            self.fakeTxscrypt.checkPassword.calls,
            [call(key, self.password)],
        )
        self.assertIs(result, self.checkPasswordReturns)


    def test_txscryptIsdefaultKeyDeriver(self):
        """
        L{txscrypt} is the default key deriver.
        """
        credentials = q2q.UsernameShadowPassword(
            username=self.username,
            password=self.password,
        )
        self.assertIs(credentials._keyDeriver, txscrypt)



class InMemoryUserStoreTests(unittest.SynchronousTestCase):
    """
    Tests for L{q2q._InMemoryUserStore}
    """

    def setUp(self):
        self.computeKeyReturns = defer.Deferred()

        self.fakeTxscrypt = _makeStubTxscrypt(
            computeKeyReturns=self.computeKeyReturns,
            checkPasswordReturns=defer.Deferred(),
        )

        self.users = q2q._InMemoryUserStore(
            keyDeriver=self.fakeTxscrypt,
        )


    def test_providesIQ2QUserStore(self):
        """
        The store provides L{ivertex.IQ2QUserStore}
        """
        verifyObject(ivertex.IQ2QUserStore, self.users)


    def test_storeAndRetrieveKey(self):
        """
        A key is derived for a password and stored under the domain
        and user.
        """
        domain, username, password, key = "domain", "user", "password", "key"

        storedDeferred = self.users.store(domain, username, password)

        self.assertNoResult(storedDeferred)
        self.computeKeyReturns.callback(key)
        self.assertEqual(self.successResultOf(storedDeferred),
                         (domain, username))

        self.assertEqual(self.users.key(domain, username), key)


    def test_missingKey(self):
        """
        The derived key for an unknown domain and user combination is
        L{None}.
        """
        self.assertIsNone(self.users.key("mystery domain", "mystery user"))
