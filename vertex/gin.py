# -*- test-case-name: vertex.test.test_gin -*-

import struct, zlib

from twisted.internet import protocol

from vertex import tcpdfa

_packetFormat = '!3LBLH'
_fixedSize = struct.calcsize(_packetFormat)

_SYN, _ACK, _FIN, _NAT = [1 << n for n in range(4)]

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
    nat = _flagprop(_NAT)

    def originate(cls, connID, seqNum, ackNum, data,
                  syn=False, ack=False, fin=False, nat=False):
        i = cls(connID, seqNum, seqNum, ackNum,
                0, zlib.crc32(data), len(data), data)
        i.syn = syn
        i.ack = ack
        i.fin = fin
        i.nat = nat
        return i

    def __init__(self, connID, seqNum, ackNum, flags, checksum, dlen, data,
                 peerAddressTuple=None):
        self.connID = connID
        self.seqNum = seqNum
        self.ackNum = ackNum
        self.flags = flags
        self.checksum = checksum
        self.dlen = dlen
        self.data = data
        self.peerAddressTuple = peerAddressTuple # None if local

    def verify(self):
        return len(self.data) == self.dlen and zlib.crc32(self.data) == self.checksum

    def decode(cls, bytes, hostPortPair):
        connID, seq, ack, flags, checksum, dlen = struct.unpack(_packetFormat, bytes)
        data = bytes[_fixedSize:]

        return cls(connID, seq, ack, flags, checksum, dlen, data, hostPortPair)
    decode = classmethod(decode)

    def encode(self):
        dlen = len(self.data)
        checksum = zlib.crc32(self.data)
        return struct.pack(
            _packetFormat,
            self.connID, self.seq, self.ack, self.flags, checksum, dlen) + self.data

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

    def originate(self, data='', syn=False, ack=False, fin=False):
        return GinPacket.originate(self.connID, self.hostSequence,
                                   self.peerSequence, data, syn, ack, fin)

    def stopListening(self):
        del self.gin._connections[self.connID]


    def enter_SYN_RCVD(self, packet):
        self.peerSequence = packet.seq
        self.gin.sendPacket(self.originate(syn=True, ack=True))

    def enter_ESTABLISHED(self, packet):
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

    def output_ACK(self, packet):
        self.peerSequence += len(packet.data)
        self.gin.sendPacket(self.originate(ack=True))


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


