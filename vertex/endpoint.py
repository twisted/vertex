# Copyright 2005 Divmod, Inc.  See LICENSE file for details

def stablesort(self, other):
    return cmp(self.__class__, getattr(other, '__class__', type(other)))

class TCPEndpoint:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def __hash__(self):
        return hash((self.host, self.port)) + 5

    def connect(self, protocolFactory):
        from twisted.internet import reactor
        return reactor.connectTCP(self.host, self.port, protocolFactory)

    def __repr__(self):
        return '<TCP@%s,%d>' % (self.host, self.port)

    def __cmp__(self, other):
        if isinstance(other, TCPEndpoint):
            return cmp((self.host, self.port),
                       (other.host, other.port))
        return stablesort(self, other)


class Q2QEndpoint:
    def __init__(self, service, fromAddress, toAddress, protocolName):
        self.service = service
        self.fromAddress = fromAddress
        self.toAddress = toAddress
        self.protocolName = protocolName

    def __repr__(self):
        return '<Q2Q from <%s> to <%s> on %r>' % (
            self.fromAddress, self.toAddress, self.protocolName)

    def __cmp__(self, other):
        if isinstance(other, Q2QEndpoint):
            return cmp((self.fromAddress, self.toAddress, self.protocolName),
                       (other.fromAddress, other.toAddress, other.protocolName))
        return stablesort(self, other)

    def __hash__(self):
        return hash((self.fromAddress,
                     self.toAddress,
                     self.protocolName)) + 7

    def connect(self, protocolFactory):
        # from twisted.python.context import get
        # get("q2q-service")
        return self.service.connectQ2Q(
            self.fromAddress, self.toAddress, self.protocolName,
            protocolFactory)

