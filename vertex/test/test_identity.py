# Copyright 2005 Divmod, Inc.  See LICENSE file for details
"""
Tests for Vertex's identity layer.
"""

from twisted.trial import unittest

from twisted.internet.defer import succeed
from twisted.internet.ssl import DN, KeyPair, CertificateRequest
from twisted.protocols import amp
from twisted.test.iosim import connectedServerAndClient
from twisted.test.test_amp import (OKCert, PretendRemoteCertificateAuthority,
                                   SecurableProto, SecuredPing)

from vertex.ivertex import IQ2QUser
from vertex.q2q import Q2Q, Q2QAddress, Identify, Sign

def makeCert(cn):
    """
    Create a self-signed cert.
    """
    sharedDN = DN(CN=cn)
    key = KeyPair.generate()
    cr = key.certificateRequest(sharedDN)
    sscrd = key.signCertificateRequest(sharedDN, cr, lambda dn: True, 1)
    return key.newCertificate(sscrd)


def makeCertRequest(cn):
    """
    Create a certificate request.
    """
    key = KeyPair.generate()
    return key.certificateRequest(DN(CN=cn))


def callResponder(command, args, responder):
    """
    Create an AMP command object, invoke its responder, and return a
    deferred that fires with its decoded result.
    """
    box = command.makeArguments(args, None)
    d = responder.locateResponder(command.commandName)(box)
    return d.addCallback(amp._stringsToObjects, command.response, None)


class IdentityTests(unittest.TestCase):
    """
    Tests for basic responses to identity-layer messages.
    """
    def test_identify(self):
        """
        A presence server responds to Identify messages with the cert
        stored for the requested domain.
        """
        target = "example.com"
        fakeCert = makeCert("fake certificate")

        class FakeStorage(object):
            def getPrivateCertificate(cs, subject):
                self.assertEqual(subject, target)
                return fakeCert
        class FakeService(object):
            certificateStorage = FakeStorage()

        q = Q2Q()
        q.service = FakeService()

        d = callResponder(Identify, {'subject': Q2QAddress(target)}, q)
        response = self.successResultOf(d)
        self.assertEqual(response, {'certificate': fakeCert})
        self.assertFalse(hasattr(response['certificate'], 'privateKey'))


    def test_cantSign(self):
        """
        Vertex nodes with no portal will not sign cert requests.
        """
        cr = CertificateRequest.load(makeCertRequest("example.com"))
        class FakeService(object):
            portal = None

        q = Q2Q()
        q.service = FakeService()

        d = callResponder(Sign, {'certificate_request': cr,
                                 'password': 'hunter2'},
                          q)
        self.failureResultOf(d, amp.RemoteAmpError)

    def test_sign(self):
        """
        'Sign' messages with a cert request result in a cred login with
        the given password. The avatar returned is then asked to sign
        the cert request with the presence server's certificate. The
        resulting certificate is returned as a response.
        """
        user = 'jethro@example.com'
        passwd = 'hunter2'

        issuerName = "fake certificate"
        domainCert = makeCert(issuerName)

        class FakeAvatar(object):
            def signCertificateRequest(fa, certificateRequest, hostcert,
                                       suggestedSerial):
                self.assertEqual(hostcert, domainCert)
                return hostcert.signRequestObject(certificateRequest,
                                                  suggestedSerial)

        class FakeStorage(object):
            def getPrivateCertificate(cs, subject):
                return domainCert

            def genSerial(cs, domain):
                return 1

        cr = CertificateRequest.load(makeCertRequest(user))
        class FakePortal(object):
            def login(fp, creds, proto, iface):
                self.assertEqual(iface, IQ2QUser)
                self.assertEqual(creds.username, user)
                self.assertEqual(creds.password, passwd)
                return succeed([None, FakeAvatar(), None])

        class FakeService(object):
            portal = FakePortal()
            certificateStorage = FakeStorage()

        q = Q2Q()
        q.service = FakeService()
        d = callResponder(Sign, {'certificate_request': cr,
                                  'password': passwd},
                          q)

        response = self.successResultOf(d)
        self.assertEqual(response['certificate'].getIssuer().commonName,
                         issuerName)

    def test_handshake(self):
        """
        Verify that starting TLS and succeeding at handshaking sends all the
        notifications to all the right places.
        """
        cli, svr, p = connectedServerAndClient(
            ServerClass=SecurableProto,
            ClientClass=SecurableProto)

        okc = OKCert()
        svr.certFactory = lambda : okc

        cli.callRemote(
            amp.StartTLS, tls_localCertificate=okc,
            tls_verifyAuthorities=[PretendRemoteCertificateAuthority()])

        # let's buffer something to be delivered securely
        L = []
        cli.callRemote(SecuredPing).addCallback(L.append)
        p.flush()
        # once for client once for server
        self.assertEqual(okc.verifyCount, 2)
        L = []
        cli.callRemote(SecuredPing).addCallback(L.append)
        p.flush()
        self.assertEqual(L[0], {'pinged': True})

