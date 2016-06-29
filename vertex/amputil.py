# stdlib
import datetime

# ssl
from twisted.internet.ssl import CertificateRequest, Certificate

# amp
from twisted.protocols.amp import Argument, String

# vertex
from vertex.address import  Q2QAddress

class AmpTime(Argument):
    def toString(self, inObject):
        return inObject.strftime("%Y-%m-%dT%H:%M:%S")

    def fromString(self, inString):
        return datetime.datetime.strptime(inString, "%Y-%m-%dT%H:%M:%S")

class Q2QAddressArgument(Argument):
    fromString = Q2QAddress.fromString
    toString = Q2QAddress.__str__

class HostPort(Argument):
    def toString(self, inObj):
        return "%s:%d" % tuple(inObj)

    def fromString(self, inStr):
        host, sPort = inStr.split(":")
        return (host, int(sPort))

class _BinaryLoadable(String):
    def toString(self, arg):
        assert isinstance(arg, self.loader), "%r not %r" % (arg, self.loader)
        return String.toString(self, arg.dump())

    def fromString(self, arg):
        return self.loader.load(String.fromString(self, arg))

class CertReq(_BinaryLoadable):
    """
    Amp Argument that serializes and deserializes L{CertificateRequest}s 
    """

    loader = CertificateRequest

class Cert(_BinaryLoadable):
    """
    Amp Argument that serializes and deserializes L{Certificate}s 
    """
    loader = Certificate