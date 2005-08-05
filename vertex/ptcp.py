# -*- test-case-name: vertex.test.test_ptcp -*-

import struct, zlib
import random

from twisted.internet import protocol, error, reactor
from twisted.python import log, util

from vertex import tcpdfa
from vertex.statemachine import StateError

_packetFormat = '!4LBlH'
_fixedSize = struct.calcsize(_packetFormat)

_SYN, _ACK, _FIN, _RST, _NAT, _STB = [1 << n for n in range(6)]

def _flagprop(flag):
    def setter(self, value):
        if value:
            self.flags |= flag
        else:
            self.flags &= ~flag
    return property(lambda self: self.flags & flag, setter)

class PtcpPacket(util.FancyStrMixin, object):
    showAttributes = (
        ('connID', 'connID', '%d'),
        ('data', 'data', '%r'),
        ('flags', 'flags', '%x'),
        ('dlen', 'dlen', '%d'),
        ('checksum', 'checksum', '%x'),
        ('peerAddressTuple', 'peerAddress', '%r'),
        )

    syn = _flagprop(_SYN)
    ack = _flagprop(_ACK)
    fin = _flagprop(_FIN)
    rst = _flagprop(_RST)
    nat = _flagprop(_NAT)
    stb = _flagprop(_STB)

    def create(cls, connID, seqNum, ackNum, data,
                  window=(1 << 15),
                  syn=False, ack=False, fin=False,
                  rst=False, nat=False, stb=False,
                  destination=None):
        i = cls(connID, seqNum, ackNum, window,
                0, zlib.crc32(data), len(data), data)
        i.syn = syn
        i.ack = ack
        i.fin = fin
        i.nat = nat
        i.rst = rst
        i.stb = stb
        i.destination = destination
        return i
    create = classmethod(create)


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


    def verifyChecksum(self):
        return len(self.data) == self.dlen and self.checksum == zlib.crc32(self.data)


    def decode(cls, bytes, hostPortPair):
        fields = struct.unpack(_packetFormat, bytes[:_fixedSize])
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
            self.connID, self.seqNum, self.ackNum, self.window,
            self.flags, checksum, dlen) + self.data

class PtcpConnection(tcpdfa.TCP):
    """
    @ivar selfSequence: An index into our outgoing stream: the value
    which will be included in the next new outgoing packet as the
    sequence number.

    @ivar selfAcknowledged: An index into the peer's outgoing stream:
    the highest sequence number we have actually acknowledged; also,
    the highest sequence number associated with a packet we have
    delivered to our protocol.
    """

    mtu = 16384

    protocol = None

    def __init__(self, connID, ptcp, factory):
        tcpdfa.TCP.__init__(self)
        self.connID = connID
        self.ptcp = ptcp
        self.factory = factory
        self._pending = []
        self._writeBufferEmptyCallbacks = []
        self.selfAcknowledged = 0


    def packetReceived(self, packet):
        # print 'packet received', packet
        if packet.syn:
            self.selfAcknowledged = packet.seqNum
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
        elif packet.stb:
            [self.mtu] = struct.unpack('!H', packet.data)
            print 'I CHANGED THE MTU TO', self.mtu
            self._writeLater()
            return

        acknowledgedByteCount = packet.ackNum - self.selfSequence
        if acknowledgedByteCount > 0:
            self._outgoingBytes = self._outgoingBytes[acknowledgedByteCount:]
            self.selfSequence = packet.ackNum
            if self._outgoingBytes:
                self._writeLater()
            else:
                self._notifyWriteBufferEmpty()
        if packet.data:
            self._maybeDeliver(packet.seqNum, packet.data)

    _outgoingBytes = ''
    _nagle = None
    def write(self, bytes):
        self._outgoingBytes += bytes
        self._writeLater()

    def writeSequence(self, seq):
        self.write(''.join(seq))

    def _writeLater(self):
        if self._nagle is None:
            self._nagle = reactor.callLater(0, self._reallyWrite)

    def _reallyWrite(self):
        self._nagle = None
        self.ptcp.sendPacket(self.originate(data=self._outgoingBytes[:self.mtu]))

    disconnecting = False       # This is *TWISTED* level state-machine stuff,
                                # not TCP-level.

    def loseConnection(self):
        self.disconnecting = True
        self._whenWriteBufferEmpty(self.input, tcpdfa.APP_CLOSE)

    def _whenWriteBufferEmpty(self, f, *a, **kw):
        if not self._outgoingBytes:
            f(*a, **kw)
        else:
            self._writeBufferEmptyCallbacks.append((f, a, kw))

    def _notifyWriteBufferEmpty(self):
        wbec = self._writeBufferEmptyCallbacks
        if wbec:
            self._writeBufferEmptyCallbacks = []
            for f, a, k in wbec:
                f(*a, **k)

    protocolDied = False

    def _maybeDeliver(self, seq, data):
        if seq >= self.selfAcknowledged:
            self._pending.append((seq, data))
            self._pending.sort(key=lambda (seq, data): -seq)
            count = 0
            while self._pending and self._pending[-1][0] == self.selfAcknowledged:
                data = self._pending.pop()[1]
                count += len(data)
                if self.protocol is not None:
                    try:
                        self.protocol.dataReceived(data)
                    except:
                        log.err()
                        self.input(tcpdfa.APP_CLOSE)
                        return
            self.selfAcknowledged += count
            print 'Acking due to delivered packets'
            self._writeLater()

    def originate(self, data='', syn=False, ack=False, fin=False):
        p = PtcpPacket.create(self.connID,
                                self.selfSequence,
                                self.selfAcknowledged, data,
                                syn=syn, ack=ack, fin=fin,
                                destination=self.peerAddressTuple)
        s = (syn and 'syn' or '') + (ack and 'ack' or '') + (fin and 'fin' or '')
        if s:
            print s
        return p

    def stopListening(self):
        del self.ptcp._connections[self.connID]

    # State machine transition definitions, hooray.

    def transition_SYN_SENT_to_CLOSED(self, packet=None):
        """
        The connection never got anywhere.  Goodbye.
        """
        self.factory.clientConnectionFailed(error.TimeoutError())

    def enter_CLOSED(self, packet=None):
        del self.ptcp._connections[self.connID]

    peerAddressTuple = None

    def enter_SYN_RCVD(self, packet):
        self.selfAcknowledged = packet.seqNum
        if self.peerAddressTuple is None:
            # we're a server
            self.peerAddressTuple = packet.peerAddressTuple
        else:
            # we're a client
            assert self.peerAddressTuple == packet.peerAddressTuple

    def transition_LISTEN_to_SYN_SENT(self, packet):
        """
        Uh, what?  We were listening and we tried to send some bytes.
        This is an error for Ptcp.
        """
        raise StateError("You can't write anything until someone connects to you.")

    def enter_ESTABLISHED(self, packet):
        """
        We sent out SYN, they acknowledged it.  Congratulations, you
        have a new baby connection.
        """
        try:
            p = self.factory.buildProtocol(PtcpAddress(
                    packet.peerAddressTuple, self.connID))
            p.makeConnection(self)
        except:
            log.msg("Exception during Ptcp connection setup.")
            log.err()
            self.loseConnection()
        else:
            self.protocol = p

    def exit_ESTABLISHED(self, packet=None):
        print 'LEAVING ESTABLISHED AND CLOSING THE CONNECTION'
        try:
            self.protocol.connectionLost(error.ConnectionLost())
        except:
            log.err()
        self.protocol = None

    def output_FIN_ACK(self, packet=None):
        self.ptcp.sendPacket(self.originate(ack=True, fin=True))

    def output_ACK(self, packet=None):
        self.ptcp.sendPacket(self.originate(ack=True))

    def output_FIN(self, packet=None):
        self.ptcp.sendPacket(self.originate(fin=True))

    def output_SYN_ACK(self, packet=None):
        self.selfSequence = 200
        self.ptcp.sendPacket(self.originate(syn=True, ack=True))

    def output_SYN(self, packet=None):
        self.selfSequence = 100
        self.ptcp.sendPacket(self.originate(syn=True))

class PtcpAddress(object):
    # garbage

    def __init__(self, (host, port), connid):
        self.host = host
        self.port = port
        self.connid = connid


class Ptcp(protocol.DatagramProtocol):
    # External API
    def listen(self, factory):
        self._lastConnID += 5 # random.randrange(2 ** 32)
        self._lastConnID %= 2 ** (struct.calcsize('L') * 8)
        conn = self._connections[self._lastConnID] = PtcpConnection(
            self._lastConnID, self, factory)
        conn.input(tcpdfa.APP_PASSIVE_OPEN)
        return self._lastConnID


    def connect(self, factory, host, port, connID):
        assert connID not in self._connections
        conn = self._connections[connID] = PtcpConnection(
            connID, self, factory)
        conn.peerAddressTuple = (host, port)
        conn.input(tcpdfa.APP_ACTIVE_OPEN)
        return connID

    def sendPacket(self, packet):
        self.transport.write(packet.encode(), packet.destination)


    # Internal stuff
    def startProtocol(self):
        self._lastConnID = 10 # random.randrange(2 ** 32)
        self._connections = {}

    def stopProtocol(self):
        for conn in self._connections:
            pass

    def datagramReceived(self, bytes, addr):
        if len(bytes) < _fixedSize:
            # It can't be any good.
            return

        pkt = PtcpPacket.decode(bytes, addr)

        if pkt.dlen > len(pkt.data):
            self.sendPacket(
                PtcpPacket.create(
                    pkt.connID,
                    0,
                    0,
                    struct.pack('!H', len(pkt.data)),
                    stb=True,
                    destination=addr))
        elif not pkt.verifyChecksum():
            print "bad packet", pkt
            print pkt.dlen, len(pkt.data)
            print repr(pkt.data)
            print hex(pkt.checksum), hex(zlib.crc32(pkt.data))
        else:
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
