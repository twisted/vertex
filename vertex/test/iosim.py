
"""Utilities and helpers for simulating a network
"""

from cStringIO import StringIO

from twisted.internet import error

from vertex.test import utils


def readAndDestroy(iodata):
    try:
        iodata.seek(0)
        result = iodata.read()
        iodata.seek(0)
        iodata.truncate()
    except ValueError:
        print '<bug in FileTransport, early close>'
        result = ''
    return result


class IOPump:
    """Utility to pump data between clients and servers for protocol testing.

    Perhaps this is a utility worthy of being in protocol.py?
    """
    def __init__(self, client, server, clientIO, serverIO, debug):
        self.client = client
        self.server = server
        self.clientIO = clientIO
        self.serverIO = serverIO
        self.debug = debug

    def flush(self, debug=False):
        """Pump until there is no more input or output.

        Returns whether any data was moved.
        """
        result = False
        for x in range(1000):
            if self.pump(debug):
                result = True
            else:
                break
        else:
            assert 0, "Too long"
        return result


    def pump(self, debug=False):
        """Move data back and forth.

        Returns whether any data was moved.
        """
        if self.debug or debug:
            print '-- GLUG --'
        sData = readAndDestroy(self.serverIO)
        cData = readAndDestroy(self.clientIO)
        self.client.transport._checkProducer()
        self.server.transport._checkProducer()
        if self.debug or debug:
            print '.'
            # XXX slightly buggy in the face of incremental output
            if cData:
                for line in cData.split('\r\n'):
                    print 'C: '+line
            if sData:
                for line in sData.split('\r\n'):
                    print 'S: '+line
        if cData:
            self.server.dataReceived(cData)
        if sData:
            self.client.dataReceived(sData)
        if cData or sData:
            return True
        if self.server.transport.disconnecting and not self.server.transport.disconnected:
            if self.debug or debug:
                print '* C'
            self.server.transport.disconnected = True
            self.client.transport.disconnecting = True
            self.client.connectionLost(error.ConnectionDone("Connection done"))
            return True
        if self.client.transport.disconnecting and not self.client.transport.disconnected:
            if self.debug or debug:
                print '* S'
            self.client.transport.disconnected = True
            self.server.transport.disconnecting = True
            self.server.connectionLost(error.ConnectionDone("Connection done"))
            return True
        return False


def connectedServerAndClient(ServerClass, ClientClass,
                             clientTransportWrapper=utils.FileWrapper,
                             serverTransportWrapper=utils.FileWrapper,
                             debug=False):
    """Returns a 3-tuple: (client, server, pump)
    """
    c = ClientClass()
    s = ServerClass()
    cio = StringIO()
    sio = StringIO()
    c.makeConnection(clientTransportWrapper(cio))
    s.makeConnection(serverTransportWrapper(sio))
    pump = IOPump(c, s, cio, sio, debug)
    # kick off server greeting, etc
    pump.flush()
    return c, s, pump
