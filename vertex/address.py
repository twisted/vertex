# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
from functools import total_ordering

@total_ordering
class Q2QAddress(object):
    def __init__(self, domain, resource=None):
        self.resource = resource
        self.domain = domain


    def domainAddress(self):
        """
        Return an Address object which is the same as this one with ONLY
        the 'domain' attribute set, not 'resource'.

        May return 'self' if 'resource' is already None.

        @return:
        """
        if self.resource is None:
            return self
        else:
            return Q2QAddress(self.domain)


    def claimedAsIssuerOf(self, cert):
        """
        Check if the information in a provided certificate *CLAIMS* to be
        issued by this address.

        PLEASE NOTE THAT THIS METHOD IS IN NO WAY AUTHORITATIVE.  It does not
        perform any cryptographic checks.

        Currently this check is if L{Q2QAddress.__str__}C{(self)} is equivalent
        to the commonName on the certificate's issuer.

        @param cert:

        @return:
        """
        return cert.getIssuer().commonName == str(self)


    def claimedAsSubjectOf(self, cert):
        """
        Check if the information in a provided certificate *CLAIMS* to be
        provided for use by this address.

        PLEASE NOTE THAT THIS METHOD IS IN NO WAY AUTHORITATIVE.  It does not
        perform any cryptographic checks.

        Currently this check is if L{Q2QAddress.__str__}C{(self)} is equivalent
        to the commonName on the certificate's subject.

        @param cert:

        @return:
        """
        return cert.getSubject().commonName == str(self)


    def _tupleme(self):
        """
        L{Q2QAddress}es sort by domain, then by resource.
        """
        return (self.domain, self.resource)


    def __lt__(self, other):
        """
        Is this less than something?

        @param other: the thing that this is maybe less than
        @type other: maybe L{Q2QAddress}?  who knows

        @return: L{True} or L{False}
        """
        if not isinstance(other, Q2QAddress):
            return NotImplemented
        return (self._tupleme() < other._tupleme())


    def __eq__(self, other):
        """
        Is this equal to something?

        @param other: the thing that this is maybe equal to
        @type other: maybe L{Q2QAddress}?  who knows

        @return: L{True} or L{False}
        """
        if not isinstance(other, Q2QAddress):
            return NotImplemented
        return (self._tupleme() == other._tupleme())


    def __iter__(self):
        return iter((self.resource, self.domain))


    def __str__(self):
        """
        Return a string of the normalized form of this address.  e.g.::

            glyph@divmod.com    # for a user
            divmod.com          # for a domain
        """
        if self.resource:
            resource = self.resource + '@'
        else:
            resource = ''
        return (resource + self.domain).encode('utf-8')


    def __repr__(self):
        return '<Q2Q at %s>' % self.__str__()


    def __hash__(self):
        return hash(str(self))


    def fromString(cls, string):
        args = string.split("@", 1)
        args.reverse()
        return cls(*args)
    fromString = classmethod(fromString)



class VirtualTransportAddress:
    def __init__(self, underlying):
        self.underlying = underlying


    def __repr__(self):
        return 'VirtualTransportAddress(%r)' % (self.underlying,)



class Q2QTransportAddress:
    """
    The return value of getPeer() and getHost() for Q2Q-enabled transports.
    Passed to buildProtocol of factories passed to listenQ2Q.

    @ivar underlying: The return value of the underlying transport's getPeer()
    or getHost(); an address which indicates the path which the bytes carrying
    Q2Q traffic are travelling over.  It is tempting to think of this as a
    'physical' layer but that it not necessarily accurate; there are
    potentially multiple layers of wrapping on any Q2Q transport, as an SSL
    transport may be tunnelled over a UDP NAT-traversal layer.  Implements
    C{IAddress} from Twisted, for all the good that will do you.

    @ivar logical: a L{Q2QAddress}, The logical peer; the user ostensibly
    listening to data on the other end of this transport.

    @ivar protocol: a L{str}, the name of the protocol that is connected.
    """

    def __init__(self, underlying, logical, protocol):
        self.underlying = underlying
        self.logical = logical
        self.protocol = protocol


    def __repr__(self):
        return 'Q2QTransportAddress(%r, %r, %r)' % (
            self.underlying,
            self.logical,
            self.protocol)
