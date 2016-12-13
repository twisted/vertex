# -*- test-case-name:vertex.test.test_standalone -*-

# Copyright 2005 Divmod, Inc.  See LICENSE file for details

import os

from twisted.cred.portal import Portal

from twisted.internet import defer
from twisted.protocols.amp import AMP, Box, parseString
from twisted.python.filepath import FilePath

from vertex import q2q
from vertex.ivertex import IQ2QUserStore
from vertex.depserv import DependencyService, Conf
from vertex.q2qadmin import AddUser, NotAllowed

import attr
import txscrypt

from zope.interface import implementer


class IdentityAdmin(AMP):

    @AddUser.responder
    def command_ADD_USER(self, name, password):
        # all security is transport security
        theDomain = self.transport.getQ2QHost().domain
        userDeferred = self.factory.store.addUser(theDomain, name, password)
        userDeferred.addCallback(lambda _: {})
        return userDeferred


class IdentityAdminFactory:
    def __init__(self, certstore):
        self.store = certstore

    def buildProtocol(self, addr):
        p = IdentityAdmin()
        p.factory = self
        return p

    def examineRequest(self, fromAddress, toAddress, protocolName):
        if toAddress.resource == "accounts" and protocolName == "identity-admin":
            return [(self, "identity admin")]
        return []



@implementer(IQ2QUserStore)
@attr.s
class _UserStore(object):
    """
    A L{IQ2QUserStore} implementation that stores usernames, domains,
    and keys derived from passwords in files.

    @param path: Where to write user information.
    @type path: L{str}

    @param keyDeriver: An object whose C{computeKey} method
        matches L{txscrypt.computeKey}
    @type keyDeriver: L{txscrypt}
    """

    path = attr.ib(convert=FilePath)
    _keyDeriver = attr.ib(default=txscrypt)


    def store(self, domain, username, password):
        """
        Store a key derived from this password, for this user, in this
        domain.

        @param domain: The domain for this user.
        @type domain: L{str}

        @param username: The name of this user.
        @type username: L{str}

        @param password: This user's password.
        @type password: L{str}

        @return: A L{defer.Deferred} that fires with the domain,
            username pair if this user has never been seen before, and
            L{NotAllowed} if it has.
        @rtype: L{defer.Deferred}
        """
        domainpath = self.path.child(domain)
        domainpath.makedirs(ignoreExistingDirectory=True)
        userpath = domainpath.child(username + ".info")
        if userpath.exists():
            return defer.fail(NotAllowed())

        def _cbWriteIdentity(key):
            with userpath.open('w') as f:
                f.write(Box(username=username,
                            key=key).serialize())
            return (domain, username)

        keyDeferred = self._keyDeriver.computeKey(password)
        keyDeferred.addCallback(_cbWriteIdentity)
        return keyDeferred


    def key(self, domain, username):
        """
        Retrieve the derived key for user with this name, in this
        domain.

        @param domain: This user's domain.
        @type domain: L{str}

        @param username: This user's name.
        @type username: L{str}

        @return: The user's key if they exist; otherwise L{None}.
        @rtype: L{str} or L{None}
        """
        userpath = self.path.child(domain).child(username + ".info")
        if userpath.exists():
            with userpath.open() as f:
                data = parseString(f.read())[0]
            return data['key']



class DirectoryCertificateAndUserStore(q2q.DirectoryCertificateStore):
    def __init__(self, filepath):
        q2q.DirectoryCertificateStore.__init__(self, filepath)
        self.users = _UserStore(os.path.join(filepath, "users"))

    def getPrivateCertificate(self, domain):
        try:
            return q2q.DirectoryCertificateStore.getPrivateCertificate(self, domain)
        except KeyError:
            if len(self.localStore.keys()) > 10:
                # avoid DoS; nobody is going to need autocreated certs for more
                # than 10 domains
                raise
            self.addPrivateCertificate(domain)
        return q2q.DirectoryCertificateStore.getPrivateCertificate(self, domain)

class StandaloneQ2Q(DependencyService):
    def setup_Q2Q(self, path,
                  q2qPortnum=q2q.port,
                  inboundTCPPortnum=q2q.port+1,
                  publicIP=None
                  ):
        """Set up a Q2Q service.
        """
        store = DirectoryCertificateAndUserStore(path)
        # store.addPrivateCertificate("kazekage")
        # store.addUser("kazekage", "username", "password1234")

        self.attach(q2q.Q2QService(
                protocolFactoryFactory=IdentityAdminFactory(store).examineRequest,
                certificateStorage=store,
                portal=Portal(store, checkers=[store]),
                q2qPortnum=q2qPortnum,
                inboundTCPPortnum=inboundTCPPortnum,
                publicIP=publicIP,
                ))

def defaultConfig():
    # Put this into a .tac file< and customize to your heart's content
    c = Conf()
    s = c.section
    s('q2q',
      path='q2q-data')
    application = deploy(**c)
    return application

deploy = StandaloneQ2Q.deploy
