# Copyright 2005 Divmod, Inc.  See LICENSE file for details

import os

from twisted.cred.portal import Portal

from epsilon import juice

from vertex import q2q
from vertex.depserv import DependencyService, Conf
from vertex.q2qadmin import AddUser, NotAllowed

class IdentityAdmin(juice.Juice):

    def __init__(self):
        juice.Juice.__init__(self, True)

    def command_ADD_USER(self, name, password):
        # all security is transport security
        theDomain = self.transport.getQ2QHost().domain
        self.factory.store.addUser(theDomain, name, password)
        return dict()

    command_ADD_USER.command = AddUser

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

class _usermap:
    def __init__(self, path):
        self.path = path

    def __setitem__(self, (domain, username), password):
        domainpath = os.path.join(self.path, domain)
        if not os.path.exists(domainpath):
            os.makedirs(domainpath)
        userpath = os.path.join(domainpath, username+".info")
        if os.path.exists(userpath):
            raise NotAllowed()
        f = open(userpath, 'w')
        f.write(juice.Box(username=username,
                          password=password.encode('hex')).serialize())
        f.close()

    def get(self, (domain, username)):
        domainpath = os.path.join(self.path, domain)
        if os.path.exists(domainpath):
            filepath = os.path.join(domainpath, username+".info")
            if os.path.exists(filepath):
                data = juice.parseString(open(filepath).read())[0]
                return data['password'].decode('hex')

class DirectoryCertificateAndUserStore(q2q.DirectoryCertificateStore):
    def __init__(self, filepath):
        q2q.DirectoryCertificateStore.__init__(self, filepath)
        self.users = _usermap(os.path.join(filepath, "users"))

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
        iaf = IdentityAdminFactory(store)

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
