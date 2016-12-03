# -*- test-case-name:vertex.test.test_standalone -*-

# Copyright 2005 Divmod, Inc.  See LICENSE file for details

import os

from twisted.cred.portal import Portal

from twisted.protocols.amp import AMP, Box, parseString

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
    path = attr.ib()
    _keyDeriver = attr.ib(default=txscrypt)

    def store(self, domain, username, password):
        domainpath = os.path.join(self.path, domain)
        if not os.path.exists(domainpath):
            os.makedirs(domainpath)
        userpath = os.path.join(domainpath, username+".info")
        if os.path.exists(userpath):
            raise NotAllowed()

        def _cbWriteIdentity(key):
            with open(userpath, 'w') as f:
                f.write(Box(username=username,
                            key=key).serialize())

        keyDeferred = self._keyDeriver.computeKey(password)
        keyDeferred.addCallback(_cbWriteIdentity)
        return keyDeferred

    def key(self, domain, username):
        domainpath = os.path.join(self.path, domain)

        if os.path.exists(domainpath):
            filepath = os.path.join(domainpath, username+".info")
            if os.path.exists(filepath):
                data = parseString(open(filepath).read())[0]
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
