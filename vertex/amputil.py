# -*- test-case-name: vertex.test.test_bits -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
AMP arguments for (de-)serializing various types that Vertex needs to
communicate over the wire.
"""

import datetime

from twisted.internet.ssl import CertificateRequest, Certificate

from twisted.protocols.amp import Argument, String

from vertex.address import Q2QAddress

class AmpTime(Argument):
    """
    AMP argument for serializing a L{datetime.datetime} object.
    """

    def toString(self, inObject):
        """
        Convert the given L{datetime.datetime} into some bytes to serialize to
        AMP.

        @param inObject:

        @return:
        """
        return inObject.strftime("%Y-%m-%dT%H:%M:%S")


    def fromString(self, inString):
        """
        Convert the given string (produced by L{toString}) to a
        L{datetime.datetime}.

        @param inString:

        @return:
        """
        return datetime.datetime.strptime(inString, "%Y-%m-%dT%H:%M:%S")



class Q2QAddressArgument(Argument):
    """
    AMP argument for serializing a L{Q2QAddress} object.
    """
    fromString = Q2QAddress.fromString
    toString = Q2QAddress.__str__



class HostPort(Argument):
    """
    AMP argument for serializing a host name and port number as a
    colon-separated pair.
    """

    def toString(self, inObj):
        """
        Convert the given C{(host, port)} tuple into some bytes for
        serialization on the wire.

        @param inObj: a C{(host, port)} tuple
        @type inObj: 2-L{tuple} of L{bytes}, L{int}

        @return: bytes in the format C{host:port}
        @rtype: L{bytes}
        """
        host, port = inObj
        return "%s:%d" % (host, port)


    def fromString(self, inStr):
        """
        Convert the given bytes into a C{(host, port)} tuple.

        @param inStr: bytes in the format C{host:port}
        @type inStr: L{bytes}

        @return: a C{(host, port)} tuple
        @rtype: 2-L{tuple} of L{bytes}, L{int}
        """
        host, sPort = inStr.split(":")
        return (host, int(sPort))



def _argumentForLoader(loaderClass):
    """
    Create an AMP argument for (de-)serializing instances of C{loaderClass}.

    @param loaderClass: A type object with a L{load} class method that takes
        some bytes and returns an instance of itself, and a L{dump} instance
        method that returns some bytes.

    @return: a class decorator which decorates an AMP argument class by
        replacing it with the one defined for loading and saving C{loaderClass}
        instances.
    """
    def decorator(argClass):
        class LoadableArgument(String):
            def toString(self, arg):
                assert isinstance(arg, loaderClass), \
                    ("%r not %r" % (arg, loaderClass))
                return String.toString(self, arg.dump())

            def fromString(self, arg):
                return loaderClass.load(String.fromString(self, arg))

        LoadableArgument.__name__ = argClass.__name__
        return LoadableArgument
    return decorator



@_argumentForLoader(CertificateRequest)
class CertReq(Argument):
    """
    AMP Argument that serializes and deserializes L{CertificateRequest}s.
    """



@_argumentForLoader(Certificate)
class Cert(Argument):
    """
    AMP Argument that serializes and deserializes L{Certificate}s.
    """
