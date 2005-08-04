# -*- test-case-name: vertex.test.test_gin -*-

import struct, zlib

from twisted.internet import protocol

from vertex import tcpdfa

_packetFormat = '!4LBLH'
_fixedSize = struct.calcsize(_packetFormat)

_SYN, _ACK, _FIN, _RST, _NAT = [1 << n for n in range(5)]

def _flagprop(flag):
    def setter(self, value):
        if value:
            self.flags |= flag
        else:
            self.flags &= ~flag
    return property(lambda self: self.flags & flag, setter)

class GinPacket(object):
    syn = _flagprop(_SYN)
    ack = _flagprop(_ACK)
    fin = _flagprop(_FIN)
    rst = _flagprop(_RST)
    nat = _flagprop(_NAT)

    def originate(cls, connID, seqNum, ackNum, data,
                  window=1 << 15,
                  syn=False, ack=False, fin=False,
                  rst=False, nat=False):
        i = cls(connID, seqNum, seqNum, ackNum,
                0, zlib.crc32(data), len(data), data)
        i.syn = syn
        i.ack = ack
        i.fin = fin
        i.nat = nat
        i.rst = rst
        return i

    def __init__(self, connID, seqNum, ackNum, window, flags,
                 checksum, dlen, data, peerAddressTuple=None):
        self.connID = connID
        self.seqNum = seqNum
        self.ackNum = ackNum
        self.window = window
        self.flags = flags
        self.checksum = checksum
        self.dlen = dlen
        self.data = data
        self.peerAddressTuple = peerAddressTuple # None if local

    def verify(self):
        return (
            len(self.data) == self.dlen and
            zlib.crc32(self.data) == self.checksum)

    def decode(cls, bytes, hostPortPair):
        fields = struct.unpack(_packetFormat, bytes)
        connID, seq, ack, window, flags, checksum, dlen = fields
        data = bytes[_fixedSize:]
        return cls(connID, seq, ack, window, flags,
                   checksum, dlen, data, hostPortPair)
    decode = classmethod(decode)

    def encode(self):
        dlen = len(self.data)
        checksum = zlib.crc32(self.data)
        return struct.pack(
            _packetFormat,
            self.connID, self.seq, self.ack, self.window,
            self.flags, checksum, dlen) + self.data

class GinConnection(tcpdfa.TCP):
    """
    @ivar peerSequence: The peer's current sequence number
    @ivar hostSequence: Our current sequence number
    """

    def __init__(self, connID, gin, factory):
        tcpdfa.TCP.__init__(self)
        self.connID = connID
        self.gin = gin
        self.factory = factory

    def packetReceived(self, packet):
        if packet.syn:
            if packet.ack:
                self.input(tcpdfa.SYN_ACK, packet)
            else:
                self.input(tcpdfa.SYN, packet)
        elif packet.fin:
            if packet.ack:
                self.input(tcpdfa.FIN_ACK, packet)
            else:
                self.input(tcpdfa.FIN, packet)
        elif packet.ack:
            self.input(tcpdfa.ACK, packet)
        elif packet.rst:
            self.input(tcpdfa.RST, packet)

    def originate(self, data='', syn=False, ack=False, fin=False):
        return GinPacket.originate(self.connID, self.hostSequence,
                                   self.peerSequence, data, syn, ack, fin)

    def stopListening(self):
        del self.gin._connections[self.connID]

    # State machine transition definitions, hooray.
    def transition_CLOSED_to_LISTEN(self):
        """
        Starting up as a server.  Nothing actually needs to be done
        here.
        """

    def transition_CLOSED_to_SYN_SENT(self):
        """
        Starting up as a client.  Bounce some traffic off the server.
        """
        self.peerSequence = 0
        self.hostSequence = random.randrange(2 ** 31)
        self.gin.sendPacket(self.originate(syn=True))

    def transition_SYN_SENT_to_CLOSED(self):
        """
        The connection never got anywhere.  Goodbye.
        """
        del self.gin._connections[self.connID]
        self.factory.clientConnectionFailed(error.Timeout())

    def transition_SYN_SENT_to_ESTABLISHED(self, packet):
        """
        The peer ACK'd our SYN.  Phase Two complete!
        """
        self.peerSequence = packet.seq
        self.gin.sendPacket(self.originate(ack=True))

    def transition_SYN_SENT_to_SYN_RCVD(self, packet):
        """
        Simultaneous TCP connect.  I don't think this applies to Gin.
        """
        raise RuntimeError("exarkun is wrong!")
        self.peerSequence = packet.seq
        self.gin.sendPacket(self.originate(syn=True, ack=True))

    def transition_LISTEN_to_SYN_RCVD(self, packet):
        """
        A passive connection succeeded (we were listening, they sent
        us a SYN).  Do the second part of the handshake.
        """
        self.peerSequence = packet.seq
        self.gin.sendPacket(self.originate(syn=True, ack=True))

    def transition_LISTEN_to_SYN_SENT(self, packet):
        """
        Uh, what?  We were listening and we tried to send some bytes.
        This is an error for Gin.
        """
        raise StateError("You can't write anything until someone connects to you.")

    def transition_SYN_RCVD_to_ESTABLISHED(self, packet):
        """
        We sent out SYN, they acknowledged it.  Congratulations, you
        have a new baby connection.
        """
        try:
            p = self.factory.buildProtocol(GinAddress(
                    packet.peerAddressTuple, self.connID))
            p.makeConnection(self)
        except:
            log.msg("Exception during Gin connection setup.")
            log.err()
            self.loseConnection()
        else:
            self.protocol = p

    def transition_SYN_RCVD_to_FIN_WAIT_1(self):
        """
        I think this is an impossible state for Gin.
        """
        raise RuntimeError("exarkun is stupid.")
        self.gin.sendPacket(self.originate(fin=True))

    def transition_SYN_RCVD_to_CLOSED(self):
        """
        A timeout expired.  Oh well, sucks to this connection.
        """
        self.gin.sendPacket(self.originate(rst=True))

    def transition_SYN_RCVD_to_LISTEN(self, packet):
        """
        A peer's timeout expired.  They told us they weren't going to
        bother finishing the connection.  Go back to listening (ie, do
        nothing).
        """

    def transition_ESTABLISHED_to_FIN_WAIT_1(self):
        """
        The application asked us to close.  So we're closing.  There's
        no packet associated with this transition.
        """
        self.gin.sendPacket(self.originate(fin=True))

    def transition_ESTABLISHED_to_CLOSE_WAIT(self, packet):
        """
        The remote end told us to shut down the connection.  Goodbye.
        """
        self.gin.sendPacket(self.originate(fin=True, ack=True))

    def transition_ESTABLISHED_to_ESTABLISHED(self, packet):
        """
        We received an ACK.  Take note.
        """
        self.peerAcknowledgment = packet.ackNum

    def transition_ESTABLISHED_to_BROKEN(self):
        """
        Crud.  Something timed out.  We're going away now.
        """
        self.protocol.connectionLost(error.TimeoutError())
        self.protocol = None

    def transition_CLOSE_WAIT_to_LAST_ACK(self):
        """
        We were going to close and the application told us to really,
        really do it.  Really.
        """
        self.gin.sendPacket(self.originate(fin=True))

    def transition_CLOSE_WAIT_to_BROKEN(self):
        """
        We tried to close cleanly.  Really, we did.  The peer did not
        cooperate, so we time out the connection.
        """
        self.protocol.connectionLost(error.TimeoutError())
        self.protocol = None

    def transition_LAST_ACK_to_NOTHING(self, packet):
        """
        We were waiting for them to ack our last packet.  They did.
        The connection is going away nice and clean now.
        """
        self.protocol.connectionLost(error.ConnectionDone())
        self.protocol = None

    def transition_LAST_ACK_to_BROKEN(self):
        """
        They didn't ack our last packet.  How disappointing.  Time out
        the connection uncleanly.
        """
        self.protocol.connectionLost(error.TimeoutError())
        self.protocol = protocol

    def transition_FIN_WAIT_1_to_FIN_WAIT_2(self, packet):
        """
        They ack'd out fin.  That's part one of the teardown.
        """
        

class GinAddress(object):
    # garbage

    def __init__(self, (host, port), connid):
        self.host = host
        self.port = port
        self.connid = connid

class Gin(protocol.DatagramProtocol):
    # External API
    def listen(self, factory):
        self._connID += 827
        self._connID %= 2 ** (struct.calcsize('L') * 8)
        conn = self._connections[self._connID] = GinConnection(
            self._connID, self, factory)
        conn.input(tcpdfa.APP_PASSIVE_OPEN)
        return self._connID


    def sendPacket(self, packet):
        self.transport.write(packet.encode())


    # Internal stuff
    def startProtocol(self):
        self._connections = {}

    def stopProtocol(self):
        for conn in self._connections:
            pass

    def datagramReceived(self, bytes, addr):
        if len(bytes) < _fixedSize:
            # It can't be any good.
            return

        pkt = GinPacket.decode(bytes, addr)
        if not pkt.verify():
            # Booo.
            return

        self.packetReceived(pkt)

    def packetReceived(self, packet):
        if packet.nat:
            if packet.syn:
                # Send them stuff about their address
                pass
            elif packet.ack:
                # Parse stuff about our address
                pass
            else:
                # Uh, what?
                pass
        else:
            if packet.connID in self._connections:
                self._connections[packet.connID].packetReceived(packet)
            else:
                # Errrrr
                pass


