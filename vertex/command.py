# -*- test-case-name: vertex.test.test_q2q -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
AMP command definitions for the Q2Q protocol spoken by Vertex.
"""

# Twisted
from twisted.protocols.amp import (
    AmpBox, String, Unicode, ListOf, Command,
    Integer, _objectsToStrings
    )

# Vertex
from vertex.amputil import (
    Cert, CertReq, HostPort, Q2QAddressArgument
    )
from vertex.exceptions import ConnectionError, BadCertificateRequest

class ConnectionStartBox(AmpBox):
    """
    An L{AmpBox} that, when sent, calls C{startProtocol} on the transport it
    was sent on.
    """

    def __init__(self, transport):
        """
        Create a L{ConnectionStartBox}.
        """
        super(ConnectionStartBox, self).__init__()
        self.virtualTransport = transport


    def _sendTo(self, proto):
        """
        When sent, call the C{startProtocol} method on the virtual transport
        object.

        @see: L{vertex.ptcp.PTCP.startProtocol}

        @see: L{vertex.q2q.VirtualTransport.startProtocol}

        @param proto: the AMP protocol that this is being sent on.
        """
        # XXX This is overriding a private interface
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
    """
    Initiate a virtual multiplexed connection over this TCP connection.
    """
    commandName = 'virtual'
    result = []

    arguments = [('id', Integer())]

    def makeResponse(cls, objects, proto):
        """
        Create a response dictionary using this L{Virtual} command's schema; do
        the same thing as L{Command.makeResponse}, but additionally do
        addition.

        @param objects: The dictionary of strings mapped to Python objects.

        @param proto: The AMP protocol that this command is serialized to.

        @return: A L{ConnectionStartBox} containing the serialized form of
            C{objects}.
        """
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
        S: Certificate: <<<base64-encoded self-signed certificate>>>
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
    """
    Request a certificate signature.
    """
    commandName = 'sign'
    arguments = [('certificate_request', CertReq()),
                 ('password', String())]

    response = [('certificate', Cert())]

    errors = {KeyError: "NoSuchUser",
              BadCertificateRequest: "BadCertificateRequest"}



class Write(Command):
    """
    Write the given bytes to a multiplexed virtual connection.
    """
    commandName = 'write'
    arguments = [('id', Integer()),
                 ('body', String())]
    requiresAnswer = False



class Close(Command):
    """
    Close the given multiplexed virtual connetion.
    """
    commandName = 'close'
    arguments = [('id', Integer())]
    requiresAnswer = True



class Choke(Command):
    """
    Flow control: ask the peer to stop sending data over this virtual channel.
    """
    commandName = 'Choke'
    arguments = [('id', Integer())]
    requiresAnswer = False



class Unchoke(Command):
    """
    Reverse of L{Choke}; flow may resume over this virtual channel.
    """
    commandName = 'Unchoke'
    arguments = [('id', Integer())]
    requiresAnswer = False



class WhoAmI(Command):
    """
    Send a response identifying TCP host and port of the sender.  This is used
    for NATed machines to identify themselves from the perspective of the
    public Internet.
    """
    commandName = 'Who-Am-I'

    response = [
        ('address', HostPort()),
        ]
