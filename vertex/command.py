# twisted
from twisted.protocols.amp import (
    AmpBox, String, Unicode, ListOf, Command,
    Integer, _objectsToStrings
    )

# vertex
from vertex.amputil import (
    Cert, CertReq, HostPort, Q2QAddressArgument
    )
from vertex.exceptions import ConnectionError, BadCertificateRequest

class ConnectionStartBox(AmpBox):
    def __init__(self, __transport):
        super(ConnectionStartBox, self).__init__()
        self.virtualTransport = __transport

    # XXX Overriding a private interface
    def _sendTo(self, proto):
        super(ConnectionStartBox, self)._sendTo(proto)
        self.virtualTransport.startProtocol()

class Listen(Command):
    """
    A simple command for registering interest with an active Q2Q connection
    to hear from a server when others come calling.  An occurrence of this
    command might have this appearance on the wire::

        C: -Command: Listen
        C: -Ask: 1
        C: From: glyph@divmod.com
        C: Protocols: q2q-example, q2q-example2
        C: Description: some simple protocols
        C:
        S: -Answer: 1
        S:

    This puts some state on the server side that will affect any Connect
    commands with q2q-example or q2q-example2 in the Protocol: header.
    """

    commandName = 'listen'
    arguments = [
        ('From', Q2QAddressArgument()),
        ('protocols', ListOf(String())),
        ('description', Unicode())]

    result = []

class Virtual(Command):
    commandName = 'virtual'
    result = []

    arguments = [('id', Integer())]

    def makeResponse(cls, objects, proto):
        tpt = objects.pop('__transport__')
        # XXX Using a private API
        return _objectsToStrings(
            objects, cls.response,
            ConnectionStartBox(tpt),
            proto)

    makeResponse = classmethod(makeResponse)

class Identify(Command):
    """
    Respond to an IDENTIFY command with a self-signed certificate for the
    domain requested, assuming we are an authority for said domain.  An
    occurrence of this command might have this appearance on the wire::

        C: -Command: Identify
        C: -Ask: 1
        C: Domain: divmod.com
        C:
        S: -Answer: 1
        S: Certificate: <<<base64-encoded self-signed certificate of divmod.com>>>
        S:

    """

    commandName = 'identify'

    arguments = [('subject', Q2QAddressArgument())]

    response = [('certificate', Cert())]

class BindUDP(Command):
    """
    See L{PTCPMethod}
    """

    commandName = 'bind-udp'

    arguments = [
        ('protocol', String()),
        ('q2qsrc', Q2QAddressArgument()),
        ('q2qdst', Q2QAddressArgument()),
        ('udpsrc', HostPort()),
        ('udpdst', HostPort()),
        ]

    errors = {ConnectionError: 'ConnectionError'}

    response = []

class SourceIP(Command):
    """
    Ask a server on the public internet what my public IP probably is.  An
    occurrence of this command might have this appearance on the wire::

        C: -Command: Source-IP
        C: -Ask: 1
        C:
        S: -Answer: 1
        S: IP: 4.3.2.1
        S:

    """

    commandName = 'source-ip'

    arguments = []

    response = [('ip', String())]

class Sign(Command):
    commandName = 'sign'
    arguments = [('certificate_request', CertReq()),
                 ('password', String())]

    response = [('certificate', Cert())]

    errors = {KeyError: "NoSuchUser",
              BadCertificateRequest: "BadCertificateRequest"}

class Choke(Command):
    """Ask our peer to be quiet for a while.
    """
    commandName = 'Choke'
    arguments = [('id', Integer())]
    requiresAnswer = False

class Unchoke(Command):
    """Reverse the effects of a choke.
    """
    commandName = 'Unchoke'
    arguments = [('id', Integer())]
    requiresAnswer = False

class WhoAmI(Command):
    commandName = 'Who-Am-I'

    response = [
        ('address', HostPort()),
        ]

class YourAddress(Command):
    arguments = [
        ('address', HostPort()),
        ]
