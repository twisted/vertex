# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Tests for I{AMP} commands related to identity.
"""

from twisted.trial import unittest

from twisted.protocols import amp
from twisted.internet.defer import succeed
from twisted.internet.ssl import DN, KeyPair, CertificateRequest

from vertex.ivertex import IQ2QUser
from vertex.q2q import Q2Q, Q2QAddress, Identify, Sign

from vertex.test.amphelpers import callResponder


def makeCert(cn):
    """
    Create a self-signed certificate with the given common name.

    @param cn: Common Name to use in certificate.
    @type cn: L{bytes}

    @return: Self-signed certificate.
    @rtype: L{Certificate<twisted.internet.ssl.Certificate>}
    """
    sharedDN = DN(CN=cn)
    key = KeyPair.generate()
    cr = key.certificateRequest(sharedDN)
    sscrd = key.signCertificateRequest(sharedDN, cr, lambda dn: True, 1)
    return key.newCertificate(sscrd)


def makeCertRequest(cn):
    """
    Create a certificate request with the given common name.

    @param cn: Common Name to use in certificate request.
    @type cn: L{bytes}

    @return: Certificate request.
    @rtype: L{CertificateRequest}
    """
    key = KeyPair.generate()
    return key.certificateRequest(DN(CN=cn))



class IdentityTests(unittest.TestCase):
    """
    Tests for L{Identify}.
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

        d = callResponder(q, Identify, subject=Q2QAddress(target))
        response = self.successResultOf(d)
        self.assertEqual(response, {'certificate': fakeCert})
        self.assertFalse(hasattr(response['certificate'], 'privateKey'))



class SignTests(unittest.TestCase):
    """
    Tests for L{Sign}.
    """

    def test_cannotSign(self):
        """
        Vertex nodes with no portal will not sign cert requests.
        """
        cr = CertificateRequest.load(makeCertRequest("example.com"))
        class FakeService(object):
            portal = None

        q = Q2Q()
        q.service = FakeService()

        d = callResponder(q, Sign,
                          certificate_request=cr,
                          password='hunter2')
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

        d = callResponder(q, Sign,
                          certificate_request=cr,
                          password=passwd)
        response = self.successResultOf(d)
        self.assertEqual(response['certificate'].getIssuer().commonName,
                         issuerName)
