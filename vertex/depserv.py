# Copyright 2005 Divmod, Inc.  See LICENSE file for details

"""
This module is no longer supported for use outside Vertex.
"""

from twisted.python import log
from sets import Set
from twisted.persisted import sob
from twisted.application import service, internet

from zope.interface import implements

class Conf(dict):
    """A class to help in construction the configuration for delpoy().

    Typical usage::

        from vertex.depserv import Conf
        conf = Conf()
        s = conf.section
        s('pop',
            port = 110,
            sslPort = 995)
        ...
    """
    def section(self, name, **kw):
        self.setdefault(name, {}).update(kw)


class NotPersistable:
    implements(sob.IPersistable)
    def __init__(self, original):
        self.original = original

    def setStyle(self, style):
        self.style = style

    def save(self, tag=None, filename=None, passphrase=None):
        pass


class StartupError(Exception):
    pass


class DependencyService(service.MultiService):
    """A MultiService that can start multiple services with interdependencies.

    Each keyword parameter is a dict which serves as the options for that
    service.

    Each service defines a method setup_SERVICE, which is called with the
    matching parameters (the service name must be all caps). If there is no key
    for SERVICE in the class parameters, the setup method is not called. The
    return value is ignored, and DependencyService makes no assumptions about
    any side effects.

    Each service may also optionally define depends_SERVICE which is called
    before the setup method with the same parameters as the setup method. This
    method returns a list of names of services on which SERVICE depends.
    DependencyService will then initialize the service is the correct order. If
    circular dependencies result, or a service depends on another service which
    does not exist or is not configured to run, StartupError is raised.

    The class can define required services by setting 'requiredServices' to a
    list of service names. These services will be initialized first in the
    order they appear in the list, ignoring all dependency information. If
    there are no parameters for a required service (consequently, the setup
    method would not normally be called), StartupError is raised.
    """


    requiredServices = []


    def __init__(self, **kw):
        service.MultiService.__init__(self)

        # this makes it possible for one service to change the configuration of
        # another. Avoid if possible, there if you need it. Be sure to properly
        # set the dependencies.
        self.config = kw
        self.servers = []

        services = kw.keys()
        initedServices = Set()
        uninitedServices = Set(services)

        # build dependencies
        dependencies = {}
        for serv in services:
            try:
                dependMethod = self._getDependsMethod(serv)
            except AttributeError:
                continue
            dependencies[serv] = dependMethod(**kw[serv])

        def initializeService(svc):
            self._getServiceMethod(svc)(**kw[svc])
            initedServices.add(svc)
            uninitedServices.remove(svc)

        for svc in self.requiredServices:
            if dependencies.get(svc):
                raise StartupError(
                    '%r is a required service but has unsatisfied '
                    'dependency on %r' % (svc, dependencies[svc]))
            initializeService(svc)

        while uninitedServices:
            # iterate over the uninitialized services, adding those with no
            # outstanding dependencies to initThisRound.
            initThisRound = []
            for serv in uninitedServices:
                for dep in dependencies.get(serv, []):
                    if dep not in initedServices:
                        if dep not in uninitedServices:
                            raise StartupError(
                                'service %r depends on service %r, which is not '
                                'configured or does not exist.' % (serv, dep))
                        break
                else:
                    initThisRound.append(serv)
            if not initThisRound:
                raise StartupError(
                    'Can not initialize all services. Circular dependencies '
                    'between setup methods?')
            for svc in initThisRound:
                initializeService(svc)


    def _getServiceMethod(self, service):
        return getattr(self, 'setup_%s' % (service.upper(),))


    def _getDependsMethod(self, service):
        return getattr(self, 'depends_%s' % (service.upper(),))


    def deploy(Class, name=None, uid=None, gid=None, **kw):
        """Create an application with the give name, uid, and gid.

        The application has one child service, an instance of Class
        configured based on the additional keyword arguments passed.

        The application is not persistable.
        """
        svc = Class(**kw)

        if name is None:
            name = Class.__name__
        # Make it easier (possible) to find this service by name later on
        svc.setName(name)

        app = service.Application(name, uid=uid, gid=gid)
        app.addComponent(NotPersistable(app), ignoreClass=True)
        svc.setServiceParent(app)

        return app
    deploy = classmethod(deploy)

    def attach(self, subservice):
        subservice.setServiceParent(self)
        return subservice

    def detach(self, subservice):
        subservice.disownServiceParent()

    def addServer(self, normalPort, sslPort, f, name):
        """Add a TCP and an SSL server. Name them `name` and `name`+'s'."""
        tcp = internet.TCPServer(normalPort,f)
        tcp.setName(name)
        self.servers.append(tcp)
        if sslPort is not None:
            ssl = internet.SSLServer(sslPort, f, contextFactory=self.sslfac)
            ssl.setName(name+'s')
            self.servers.append(ssl)

    def discernPrivilegedServers(self):
        return [srv for srv in self.servers if srv.args[0] <= 1024]

    def discernUnprivilegedServers(self):
        return [srv for srv in self.servers if srv.args[0] > 1024]

    def privilegedStartService(self):
        for server in self.discernPrivilegedServers():
            log.msg("privileged attach %r" % server)
            self.attach(server)
        return service.MultiService.privilegedStartService(self)

    def startService(self):
        for server in self.discernUnprivilegedServers():
            log.msg("attaching %r" % server)
            self.attach(server)

        return service.MultiService.startService(self)
