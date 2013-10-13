# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Certificate Stores
"""

from hashlib import md5
import struct
import os

from zope.interface import implements

from twisted.internet import defer
from twisted.python import log

from twisted.internet.ssl import (
    Certificate, PrivateCertificate, KeyPair,
    DistinguishedName)

from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.portal import IRealm
from twisted.cred.credentials import IUsernamePassword
from twisted.cred.error import UnauthorizedLogin

from vertex import ivertex
from vertex.errors import BadCertificateRequest



class DefaultQ2QAvatar:
    implements(ivertex.IQ2QUser)

    def __init__(self, username, domain):
        self.username = username
        self.domain = domain

    def signCertificateRequest(self, certificateRequest,
                               domainCert, suggestedSerial):
        keyz = certificateRequest.getSubject().keys()
        if keyz != ['commonName']:
            raise BadCertificateRequest(
                "Don't know how to verify fields other than CN: " +
                repr(keyz))
        newCert = domainCert.signRequestObject(
            certificateRequest,
            suggestedSerial)
        log.msg('signing certificate for user %s@%s: %s' % (
                self.username, self.domain, newCert.digest()))
        return newCert



class DefaultCertificateStore:

    implements(ICredentialsChecker, IRealm)

    credentialInterfaces = [IUsernamePassword]

    def requestAvatar(self, avatarId, mind, interface):
        assert interface is ivertex.IQ2QUser, (
            "default certificate store only supports one interface")
        return interface, DefaultQ2QAvatar(*avatarId.split("@")), lambda : None

    def requestAvatarId(self, credentials):
        username, domain = credentials.username.split("@")
        pw = self.users.get((domain, username))
        if pw is None:
            return defer.fail(UnauthorizedLogin())
        def _(passwordIsCorrect):
            if passwordIsCorrect:
                return username + '@' + domain
            else:
                raise UnauthorizedLogin()
        return defer.maybeDeferred(
            credentials.checkPassword, pw).addCallback(_)

    def __init__(self):
        self.remoteStore = {}
        self.localStore = {}
        self.users = {}

    def getSelfSignedCertificate(self, domainName):
        return defer.maybeDeferred(self.remoteStore.__getitem__, domainName)

    def addUser(self, domain, username, privateSecret):
        self.users[domain, username] = privateSecret

    def checkUser(self, domain, username, privateSecret):
        if self.users.get((domain, username)) != privateSecret:
            return defer.fail(KeyError())
        return defer.succeed(True)

    def storeSelfSignedCertificate(self, domainName, mainCert):
        """

        @return: a Deferred which will fire when the certificate has been
        stored successfully.
        """
        assert not isinstance(mainCert, str)
        return defer.maybeDeferred(self.remoteStore.__setitem__, domainName, mainCert)

    def getPrivateCertificate(self, domainName):
        """

        @return: a PrivateCertificate instance, e.g. a certificate including a
        private key, for 'domainName'.
        """
        return self.localStore[domainName]


    def genSerial(self, name):
        return abs(struct.unpack('!i', md5(name).digest()[:4])[0])

    def addPrivateCertificate(self, subjectName, existingCertificate=None):
        """
        Add a PrivateCertificate object to this store for this subjectName.

        If existingCertificate is None, add a new self-signed certificate.
        """
        if existingCertificate is None:
            assert '@' not in subjectName, "Don't self-sign user certs!"
            mainDN = DistinguishedName(commonName=subjectName)
            mainKey = KeyPair.generate()
            mainCertReq = mainKey.certificateRequest(mainDN)
            mainCertData = mainKey.signCertificateRequest(mainDN, mainCertReq,
                                                          lambda dn: True,
                                                          self.genSerial(subjectName))
            mainCert = mainKey.newCertificate(mainCertData)
        else:
            mainCert = existingCertificate
        self.localStore[subjectName] = mainCert

class _pemmap(object):
    def __init__(self, pathname, certclass):
        self.pathname = pathname
        try:
            os.makedirs(pathname)
        except (OSError, IOError):
            pass
        self.certclass = certclass

    def file(self, name, mode):
        try:
            return file(os.path.join(self.pathname, name)+'.pem', mode)
        except IOError, ioe:
            raise KeyError(name, ioe)

    def __setitem__(self, key, cert):
        kn = cert.getSubject().commonName
        assert kn == key
        self.file(kn, 'wb').write(cert.dumpPEM())

    def __getitem__(self, cn):
        return self.certclass.loadPEM(self.file(cn, 'rb').read())

    def iteritems(self):
        files = os.listdir(self.pathname)
        for file in files:
            if file.endswith('.pem'):
                key = file[:-4]
                value = self[key]
                yield key, value

    def items(self):
        return list(self.iteritems())

    def iterkeys(self):
        for k, v in self.iteritems():
            yield k

    def keys(self):
        return list(self.iterkeys())

    def itervalues(self):
        for k, v in self.iteritems():
            yield v

    def values(self):
        return list(self.itervalues())



class DirectoryCertificateStore(DefaultCertificateStore):
    def __init__(self, filepath):
        self.remoteStore = _pemmap(os.path.join(filepath, 'public'),
                                   Certificate)
        self.localStore = _pemmap(os.path.join(filepath, 'private'),
                                  PrivateCertificate)


__all__ = [
        'DefaultQ2QAvatar',
        'DefaultCertificateStore', 'DirectoryCertificateStore',
        ]
