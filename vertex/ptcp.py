# -*- test-case-name: vertex.test.test_ptcp -*-

import struct

from binascii import crc32  # used to use zlib.crc32 - but that gives different
                            # results on 64-bit platforms!!

import itertools

from epsilon.pending import PendingEvent

from twisted.internet import protocol, error, reactor, defer
from twisted.internet.main import CONNECTION_DONE
from twisted.python import log, util

from vertex import tcpdfa
from vertex.statemachine import StateError


genConnID = itertools.count(8).next

MAX_PSEUDO_PORT = (2 ** 16)

_packetFormat = ('!' # WTF did you think
                 'H' # sourcePseudoPort
                 'H' # destPseudoPort
                 'L' # sequenceNumber
                 'L' # acknowledgementNumber
                 'L' # window
                 'B' # flags
                 'l' # checksum
                     # (signed because of binascii.crc32)
                 'H' # dlen
                 )
_fixedSize = struct.calcsize(_packetFormat)

_SYN, _ACK, _FIN, _RST, _STB = [1 << n for n in range(5)]

def _flagprop(flag):
    def setter(self, value):
        if value:
            self.flags |= flag
        else:
            self.flags &= ~flag
    return property(lambda self: bool(self.flags & flag), setter)

def relativeSequence(wireSequence, initialSequence, lapNumber):
    """ Compute a relative sequence number from a wire sequence number so that we
    can use natural Python comparisons on it, such as <, >, ==.

    @param wireSequence: the sequence number received on the wire.

    @param initialSequence: the ISN for this sequence, negotiated at SYN time.

    @param lapNumber: the number of times that this value has wrapped around
    2**32.
    """
    return (wireSequence + (lapNumber * (2**32))) - initialSequence

class PTCPPacket(util.FancyStrMixin, object):
    showAttributes = (
        ('sourcePseudoPort', 'sourcePseudoPort', '%d'),
        ('destPseudoPort', 'destPseudoPort', '%d'),
        ('shortdata', 'data', '%r'),
        ('niceflags', 'flags', '%s'),
        ('dlen', 'dlen', '%d'),
        ('seqNum', 'seq', '%d'),
        ('ackNum', 'ack', '%d'),
        ('checksum', 'checksum', '%x'),
        ('peerAddressTuple', 'peerAddress', '%r'),
        ('retransmitCount', 'retransmitCount', '%d'),
        )

    syn = _flagprop(_SYN)
    ack = _flagprop(_ACK)
    fin = _flagprop(_FIN)
    rst = _flagprop(_RST)
    stb = _flagprop(_STB)

    # Number of retransmit attempts left for this segment.  When it reaches
    # zero, this segment is dead.
    retransmitCount = 50

    def shortdata():
        def get(self):
            if len(self.data) > 13:
                return self.data[:5] + '...' + self.data[-5:]
            else:
                return self.data
        return get,
    shortdata = property(*shortdata())

    def niceflags():
        def get(self):
            res = []
            for (f, v) in [
                (self.syn, 'S'), (self.ack, 'A'), (self.fin, 'F'),
                (self.rst, 'R'), (self.stb, 'T')]:
                res.append(f and v or '.')
            return ''.join(res)
        return get,
    niceflags = property(*niceflags())

    def create(cls,
               sourcePseudoPort, destPseudoPort,
               seqNum, ackNum, data,
               window=(1 << 15),
               syn=False, ack=False, fin=False,
               rst=False, stb=False,
               destination=None):
        i = cls(sourcePseudoPort, destPseudoPort,
                seqNum, ackNum, window,
                0, 0, len(data), data)
        i.syn = syn
        i.ack = ack
        i.fin = fin
        i.rst = rst
        i.stb = stb
        i.checksum = i.computeChecksum()
        i.destination = destination
        return i
    create = classmethod(create)


    def __init__(self,
                 sourcePseudoPort,
                 destPseudoPort,
                 seqNum, ackNum, window, flags,
                 checksum, dlen, data, peerAddressTuple=None,
                 seqOffset=0, ackOffset=0, seqLaps=0, ackLaps=0):
        self.sourcePseudoPort = sourcePseudoPort
        self.destPseudoPort = destPseudoPort
        self.seqNum = seqNum
        self.ackNum = ackNum
        self.window = window
        self.flags = flags
        self.checksum = checksum
        self.dlen = dlen
        self.data = data
        self.peerAddressTuple = peerAddressTuple # None if local

        self.seqOffset = seqOffset
        self.ackOffset = ackOffset
        self.seqLaps = seqLaps
        self.ackLaps = ackLaps

    def segmentLength(self):
        """RFC page 26: 'The segment length (SEG.LEN) includes both data and sequence
        space occupying controls'
        """
        return self.dlen + self.syn + self.fin

    def relativeSeq(self):
        return relativeSequence(self.seqNum, self.seqOffset, self.seqLaps)

    def relativeAck(self):
        return relativeSequence(self.ackNum, self.ackOffset, self.ackLaps)


    def verifyChecksum(self):
        if len(self.data) != self.dlen:
            if len(self.data) > self.dlen:
                raise GarbageDataError(self)
            else:
                raise TruncatedDataError(self)
        expected = self.computeChecksum()
        received = self.checksum
        if expected != received:
            raise ChecksumMismatchError(expected, received)

    def computeChecksum(self):
        return crc32(self.data)

    def decode(cls, bytes, hostPortPair):
        fields = struct.unpack(_packetFormat, bytes[:_fixedSize])
        sourcePseudoPort, destPseudoPort, seq, ack, window, flags, checksum, dlen = fields
        data = bytes[_fixedSize:]
        pkt = cls(sourcePseudoPort, destPseudoPort, seq, ack, window, flags,
                  checksum, dlen, data, hostPortPair)
        return pkt
    decode = classmethod(decode)

    def mustRetransmit(self):
        """Check to see if this packet must be retransmitted until it was received.
        """
        if self.syn or self.fin or self.dlen:
            return True
        return False

    def encode(self):
        dlen = len(self.data)
        checksum = self.computeChecksum()
        return struct.pack(
            _packetFormat,
            self.sourcePseudoPort, self.destPseudoPort,
            self.seqNum, self.ackNum, self.window,
            self.flags, checksum, dlen) + self.data

    def fragment(self, mtu):
        if self.dlen < mtu:
            return [self]
        assert not self.syn, "should not be originating syn packets w/ data"
        seqOfft = 0
        L = []
        # XXX TODO: need to take seqLaps into account, etc.
        for chunk in iterchunks(self.data, mtu):
            last = self.create(self.sourcePseudoPort,
                               self.destPseudoPort,
                               self.seqNum + seqOfft,
                               self.ackNum,
                               chunk,
                               self.window,
                               destination=self.destination,
                               ack=self.ack)
            L.append(last)
            seqOfft += len(chunk)
        if self.fin:
            last.fin = self.fin
            last.checksum = last.computeChecksum()
        return L


def iterchunks(data, chunksize):
    """iterate chunks of data
    """
    offt = 0
    while offt < len(data):
        yield data[offt:offt+chunksize]
        offt += chunksize


def ISN():
    """
    Initial Sequence Number generator.
    """
    # return int((time.time() * 1000000) / 4) % 2**32
    return 0


def segmentAcceptable(RCV_NXT, RCV_WND, SEG_SEQ, SEG_LEN):
    # RFC page 26.
    if SEG_LEN == 0 and RCV_WND == 0:
        return SEG_SEQ == RCV_NXT
    if SEG_LEN == 0 and RCV_WND > 0:
        return ((RCV_NXT <= SEG_SEQ) and (SEG_SEQ < RCV_NXT + RCV_WND))
    if SEG_LEN > 0 and RCV_WND == 0:
        return False
    if SEG_LEN > 0 and RCV_WND > 0:
        return ((  (RCV_NXT <= SEG_SEQ) and (SEG_SEQ < RCV_NXT + RCV_WND))
                or ((RCV_NXT <= SEG_SEQ+SEG_LEN-1) and
                    (SEG_SEQ+SEG_LEN-1 < RCV_NXT + RCV_WND)))
    assert 0, 'Should be impossible to get here.'
    return False

class BadPacketError(Exception):
    """
    A packet was bad for some reason.
    """

class ChecksumMismatchError(Exception):
    """
    The checksum and data received did not match.
    """

class TruncatedDataError(Exception):
    """
    The packet was truncated in transit, and all of the data did not arrive.
    """

class GarbageDataError(Exception):
    """
    Too much data was received (???)
    """

class PTCPConnection(tcpdfa.TCP):
    """
    Implementation of RFC 793 state machine.

    @ivar oldestUnackedSendSeqNum: (TCP RFC: SND.UNA) The oldest (relative)
    sequence number referring to an octet which we have sent or may send which
    is unacknowledged.  This begins at 0, which is special because it is not
    for an octet, but rather for the initial SYN packet.  Unless it is 0, this
    represents the sequence number of self._outgoingBytes[0].

    @ivar nextSendSeqNum: (TCP RFC: SND.NXT) The next (relative) sequence
    number that we will send to our peer after the current buffered segments
    have all been acknowledged.  This is the sequence number of the
    not-yet-extant octet in the stream at
    self._outgoingBytes[len(self._outgoingBytes)].

    @ivar nextRecvSeqNum: (TCP RFC: RCV.NXT) The next (relative) sequence
    number that the peer should send to us if they want to send more data;
    their first unacknowledged sequence number as far as we are concerned; the
    left or lower edge of the receive window; the sequence number of the first
    octet that has not been delivered to the application.  changed whenever we
    receive an appropriate ACK.

    @ivar peerSendISN: the initial sequence number that the peer sent us during
    the negotiation phase.  All peer-relative sequence numbers are computed
    using this.  (see C{relativeSequence}).

    @ivar hostSendISN: the initial sequence number that the we sent during the
    negotiation phase.  All host-relative sequence numbers are computed using
    this.  (see C{relativeSequence})

    @ivar retransmissionQueue: a list of packets to be re-sent until their
    acknowledgements come through.

    @ivar recvWindow: (TCP RFC: RCV.WND) - the size [in octets] of the current
    window allowed by this host, to be in transit from the other host.

    @ivar sendWindow: (TCP RFC: SND.WND) - the size [in octets] of the current
    window allowed by our peer, to be in transit from us.

    """

    mtu = 512 - _fixedSize

    recvWindow = mtu
    sendWindow = mtu
    sendWindowRemaining = mtu * 2

    protocol = None

    def __init__(self,
                 hostPseudoPort, peerPseudoPort,
                 ptcp, factory, peerAddressTuple):
        tcpdfa.TCP.__init__(self)
        self.hostPseudoPort = hostPseudoPort
        self.peerPseudoPort = peerPseudoPort
        self.ptcp = ptcp
        self.factory = factory
        self._receiveBuffer = []
        self.retransmissionQueue = []
        self.peerAddressTuple = peerAddressTuple

        self.oldestUnackedSendSeqNum = 0
        self.nextSendSeqNum = 0
        self.hostSendISN = 0
        self.nextRecvSeqNum = 0
        self.peerSendISN = 0
        self.setPeerISN = False

    peerSendISN = None

    def packetReceived(self, packet):
        # XXX TODO: probably have to do something to the packet here to
        # identify its relative sequence number.

        # print 'received', self, packet

        if packet.stb:
            # Shrink the MTU
            [self.mtu] = struct.unpack('!H', packet.data)
            rq = []
            for pkt in self.retransmissionQueue:
                rq.extend(pkt.fragment(self.mtu))
            self.retransmissionQueue = rq
            return

        if self._paused:
            return

        generatedStateMachineInput = False
        if packet.syn:
            if packet.dlen:
                # Whoops, what?  SYNs probably can contain data, I think, but I
                # certainly don't see anything in the spec about how to deal
                # with this or in ethereal for how linux deals with it -glyph
                raise BadPacketError(
                    "currently no data allowed in SYN packets: %r"
                    % (packet,))
            else:
                assert packet.segmentLength() == 1
            if self.peerAddressTuple is None:
                # we're a server
                assert self.wasEverListen, "Clients must specify a connect address."
                self.peerAddressTuple = packet.peerAddressTuple
            else:
                # we're a client
                assert self.peerAddressTuple == packet.peerAddressTuple
            if self.setPeerISN:
                if self.peerSendISN != packet.seqNum:
                    raise BadPacketError(
                        "Peer ISN was already set to %s but incoming packet "
                        "tried to set it to %s" % (
                            self.peerSendISN, packet.seqNum))
                if not self.retransmissionQueue:
                    # If our retransmissionQueue is hot, we are going to send
                    # them an ACK to this with the next packet we send them
                    # anyway; as a bonus, this will properly determine whether
                    # we're sending a SYN+ACK or merely an ACK; the only time
                    # we send an ACK is when we have nothing to say to them and
                    # they're blocked on getting a response to their SYN+ACK
                    # from us. -glyph
                    self.originate(ack=True)
                return
            self.setPeerISN = True
            self.peerSendISN = packet.seqNum
            # syn, fin, and data are mutually exclusive, so this relative
            # sequence-number increment is done both here, and below in the
            # data/fin processing block.
            self.nextRecvSeqNum += packet.segmentLength()
            if not packet.ack:
                generatedStateMachineInput = True
                self.input(tcpdfa.SYN)

        SEG_ACK = packet.relativeAck() # aliasing this for easier reading w/
                                       # the RFC
        if packet.ack:
            if (self.oldestUnackedSendSeqNum < SEG_ACK and
                SEG_ACK <= self.nextSendSeqNum):
                # According to the spec, an 'acceptable ack
                rq = self.retransmissionQueue
                while rq:
                    segmentOnQueue = rq[0]
                    qSegSeq = segmentOnQueue.relativeSeq()
                    if qSegSeq + segmentOnQueue.segmentLength() <= SEG_ACK:
                        # fully acknowledged, as per RFC!
                        rq.pop(0)
                        sminput = None
                        self.sendWindowRemaining += segmentOnQueue.segmentLength()
                        # print 'inc send window', self, self.sendWindowRemaining
                        if segmentOnQueue.syn:
                            if packet.syn:
                                sminput = tcpdfa.SYN_ACK
                            else:
                                sminput = tcpdfa.ACK
                        elif segmentOnQueue.fin:
                            sminput = tcpdfa.ACK
                        if sminput is not None:
                            # print 'ack input:', segmentOnQueue, packet, sminput
                            generatedStateMachineInput = True
                            self.input(sminput)
                    else:
                        break
                else:
                    # write buffer is empty; alert the application layer.
                    self._writeBufferEmpty()
                self.oldestUnackedSendSeqNum = SEG_ACK

        if packet.syn:
            assert generatedStateMachineInput
            return

        # XXX TODO: examine 'window' field and adjust sendWindowRemaining
        # is it 'occupying a portion of valid receive sequence space'?  I think
        # this means 'packet which might acceptably contain useful data'
        if not packet.segmentLength():
            assert packet.ack, "What the _HELL_ is wrong with this packet:" +str(packet)
            return

        if not segmentAcceptable(self.nextRecvSeqNum,
                                 self.recvWindow,
                                 packet.relativeSeq(),
                                 packet.segmentLength()):
            # We have to transmit an ack here since it's old data.  We probably
            # need to ack in more states than just ESTABLISHED... but which
            # ones?
            if not self.retransmissionQueue:
                self.originate(ack=True)
            return

        # OK!  It's acceptable!  Let's process the various bits of data.
        # Where is the useful data in the packet?
        if packet.relativeSeq() > self.nextRecvSeqNum:
            # XXX: Here's what's going on.  Data can be 'in the window', but
            # still in the future.  For example, if I have a window of length 3
            # and I send segments DATA1(len 1) DATA2(len 1) FIN and you receive
            # them in the order FIN DATA1 DATA2, you don't actually want to
            # process the FIN until you've processed the data.

            # For the moment we are just dropping anything that isn't exactly
            # the next thing we want to process.  This is perfectly valid;
            # these packets might have been dropped, so the other end will have
            # to retransmit them anyway.
            return

        if packet.dlen:
            assert not packet.syn, 'no seriously I _do not_ know how to handle this'
            usefulData = packet.data[self.nextRecvSeqNum - packet.relativeSeq():]
            # DONT check/slice the window size here, the acceptability code
            # checked it, we can over-ack if the other side is buggy (???)
            if self.protocol is not None:
                try:
                    self.protocol.dataReceived(usefulData)
                except:
                    log.err()
                    self.loseConnection()

        self.nextRecvSeqNum += packet.segmentLength()
        if self.state == tcpdfa.ESTABLISHED:
            # In all other states, the state machine takes care of sending ACKs
            # in its output process.
            self.originate(ack=True)

        if packet.fin:
            self.input(tcpdfa.FIN)


    def getHost(self):
        tupl = self.ptcp.transport.getHost()
        return PTCPAddress((tupl.host, tupl.port),
                           self.pseudoPortPair)

    def getPeer(self):
        return PTCPAddress(self.peerAddressTuple,
                           self.pseudoPortPair)

    _outgoingBytes = ''
    _nagle = None

    def write(self, bytes):
        assert not self.disconnected, 'Writing to a transport that was already disconnected.'
        self._outgoingBytes += bytes
        self._writeLater()


    def writeSequence(self, seq):
        self.write(''.join(seq))


    def _writeLater(self):
        if self._nagle is None:
            self._nagle = reactor.callLater(0.001, self._reallyWrite)

    def _originateOneData(self):
        amount = min(self.sendWindowRemaining, self.mtu)
        sendOut = self._outgoingBytes[:amount]
        # print 'originating data packet', len(sendOut)
        self._outgoingBytes = self._outgoingBytes[amount:]
        self.sendWindowRemaining -= len(sendOut)
        self.originate(ack=True, data=sendOut)

    def _reallyWrite(self):
        # print self, 'really writing', self._paused
        self._nagle = None
        if self._outgoingBytes:
            # print 'window and bytes', self.sendWindowRemaining, len(self._outgoingBytes)
            while self.sendWindowRemaining and self._outgoingBytes:
                self._originateOneData()

    _retransmitter = None
    _retransmitTimeout = 0.5

    def _retransmitLater(self):
        assert self.state != tcpdfa.CLOSED
        if self._retransmitter is None:
            self._retransmitter = reactor.callLater(self._retransmitTimeout, self._reallyRetransmit)

    def _stopRetransmitting(self):
        # used both as a quick-and-dirty test shutdown hack and a way to shut
        # down when we die...
        if self._retransmitter is not None:
            self._retransmitter.cancel()
            self._retransmitter = None
        if self._nagle is not None:
            self._nagle.cancel()
            self._nagle = None
        if self._closeWaitLoseConnection is not None:
            self._closeWaitLoseConnection.cancel()
            self._closeWaitLoseConnection = None

    def _reallyRetransmit(self):
        # XXX TODO: packet fragmentation & coalescing.
        # print 'Wee a retransmit!  What I got?', self.retransmissionQueue
        self._retransmitter = None
        if self.retransmissionQueue:
            for packet in self.retransmissionQueue:
                packet.retransmitCount -= 1
                if packet.retransmitCount:
                    packet.ackNum = self.currentAckNum()
                    self.ptcp.sendPacket(packet)
                else:
                    self.input(tcpdfa.TIMEOUT)
                    return
            self._retransmitLater()

    disconnecting = False       # This is *TWISTED* level state-machine stuff,
                                # not TCP-level.

    def loseConnection(self):
        if not self.disconnecting:
            self.disconnecting = True
            if not self._outgoingBytes:
                self._writeBufferEmpty()


    def _writeBufferEmpty(self):
        if self._outgoingBytes:
            self._reallyWrite()
        elif self.producer is not None:
            if (not self.streamingProducer) or self.producerPaused:
                self.producerPaused = False
                self.producer.resumeProducing()
        elif self.disconnecting and (not self.disconnected
                                     or self.state == tcpdfa.CLOSE_WAIT):
            self.input(tcpdfa.APP_CLOSE)


    def _writeBufferFull(self):
        # print 'my write buffer is full'
        if (self.producer is not None
            and not self.producerPaused):
            self.producerPaused = True
            # print 'producer pausing'
            self.producer.pauseProducing()
            # print 'producer paused'
        else:
            # print 'but I am not telling my producer to pause!'
            # print '  ', self.producer, self.streamingProducer, self.producerPaused
            pass


    disconnected = False
    producer = None
    producerPaused = False
    streamingProducer = False

    def registerProducer(self, producer, streaming):
        if self.producer is not None:
            raise RuntimeError(
                "Cannot register producer %s, "
                "because producer %s was never unregistered."
                % (producer, self.producer))
        if self.disconnected:
            producer.stopProducing()
        else:
            self.producer = producer
            self.streamingProducer = streaming
            if not streaming and not self._outgoingBytes:
                producer.resumeProducing()

    def unregisterProducer(self):
        self.producer = None
        if not self._outgoingBytes:
            self._writeBufferEmpty()

    _paused = False
    def pauseProducing(self):
        self._paused = True

    def resumeProducing(self):
        self._paused = False

    def currentAckNum(self):
        return (self.nextRecvSeqNum + self.peerSendISN) % (2**32)

    def originate(self, data='', syn=False, ack=False, fin=False):
        if syn:
            # We really should be randomizing the ISN but until we finish the
            # implementations of the various bits of wraparound logic that were
            # started with relativeSequence
            assert self.nextSendSeqNum == 0
            assert self.hostSendISN == 0
        p = PTCPPacket.create(self.hostPseudoPort,
                              self.peerPseudoPort,
                              seqNum=(self.nextSendSeqNum + self.hostSendISN) % (2**32),
                              ackNum=self.currentAckNum(),
                              data=data,
                              window=self.recvWindow,
                              syn=syn, ack=ack, fin=fin,
                              destination=self.peerAddressTuple)
        # do we want to enqueue this packet for retransmission?
        sl = p.segmentLength()
        self.nextSendSeqNum += sl

        if p.mustRetransmit():
            # print self, 'originating retransmittable packet', len(self.retransmissionQueue)
            if self.retransmissionQueue:
                if self.retransmissionQueue[-1].fin:
                    raise AssertionError("Sending %r after FIN??!" % (p,))
            # print 'putting it on the queue'
            self.retransmissionQueue.append(p)
            # print 'and sending it later'
            self._retransmitLater()
            if not self.sendWindowRemaining: # len(self.retransmissionQueue) > 5:
                # print 'oh no my queue is too big'
                # This is a random number (5) because I ought to be summing the
                # packet lengths or something.
                self._writeBufferFull()
            else:
                # print 'my queue is still small enough', len(self.retransmissionQueue), self, self.sendWindowRemaining
                pass
        self.ptcp.sendPacket(p)

    # State machine transition definitions, hooray.
    def transition_SYN_SENT_to_CLOSED(self):
        """
        The connection never got anywhere.  Goodbye.
        """
        # XXX CONNECTOR API OMFG
        self.factory.clientConnectionFailed(None, error.TimeoutError())


    wasEverListen = False

    def enter_LISTEN(self):
        # Spec says this is necessary for RST handling; we need it for making
        # sure it's OK to bind port numbers.
        self.wasEverListen = True

    def enter_CLOSED(self):
        self.ptcp.connectionClosed(self)
        self._stopRetransmitting()
        if self._timeWaitCall is not None:
            self._timeWaitCall.cancel()
            self._timeWaitCall = None

    _timeWaitCall = None
    _timeWaitTimeout = 0.01     # REALLY fast timeout, right now this is for
                                # the tests...

    def enter_TIME_WAIT(self):
        self._stopRetransmitting()
        self._timeWaitCall = reactor.callLater(self._timeWaitTimeout, self._do2mslTimeout)

    def _do2mslTimeout(self):
        self._timeWaitCall = None
        self.input(tcpdfa.TIMEOUT)

    peerAddressTuple = None

    def transition_LISTEN_to_SYN_SENT(self):
        """
        Uh, what?  We were listening and we tried to send some bytes.
        This is an error for PTCP.
        """
        raise StateError("You can't write anything until someone connects to you.")

#     def invalidInput(self, datum):
#         print self, self.protocol, 'invalid input', datum

    def pseudoPortPair():
        def get(self):
            return (self.hostPseudoPort,
                    self.peerPseudoPort)
        return get,
    pseudoPortPair = property(*pseudoPortPair())

    def enter_ESTABLISHED(self):
        """
        We sent out SYN, they acknowledged it.  Congratulations, you
        have a new baby connection.
        """
        assert not self.disconnecting
        assert not self.disconnected
        try:
            p = self.factory.buildProtocol(PTCPAddress(
                    self.peerAddressTuple, self.pseudoPortPair))
            p.makeConnection(self)
        except:
            log.msg("Exception during PTCP connection setup.")
            log.err()
            self.loseConnection()
        else:
            self.protocol = p

    def exit_ESTABLISHED(self):
        assert not self.disconnected
        self.disconnected = True
        try:
            self.protocol.connectionLost(CONNECTION_DONE)
        except:
            log.err()
        self.protocol = None

        if self.producer is not None:
            try:
                self.producer.stopProducing()
            except:
                log.err()
            self.producer = None


    _closeWaitLoseConnection = None

    def enter_CLOSE_WAIT(self):
        # Twisted automatically reacts to network half-close by issuing a full
        # close.
        self._closeWaitLoseConnection = reactor.callLater(0.01, self._loseConnectionBecauseOfCloseWait)

    def _loseConnectionBecauseOfCloseWait(self):
        self._closeWaitLoseConnection = None
        self.loseConnection()

    def immediateShutdown(self):
        """_IMMEDIATELY_ shut down this connection, sending one (non-retransmitted)
        app-close packet, emptying our buffers, clearing our producer and
        getting ready to die right after this call.
        """
        self._outgoingBytes = ''
        if self.state == tcpdfa.ESTABLISHED:
            self.input(tcpdfa.APP_CLOSE)
            self._stopRetransmitting()
            self._reallyRetransmit()

        # All states that we can reasonably be in handle a timeout; force our
        # connection to think that it's become desynchronized with the other
        # end so that it will totally shut itself down.

        self.input(tcpdfa.TIMEOUT)
        assert self._retransmitter is None
        assert self._nagle is None

    def output_ACK(self):
        self.originate(ack=True)

    def output_FIN(self):
        self.originate(fin=True)

    def output_SYN_ACK(self):
        self.originate(syn=True, ack=True)

    def output_SYN(self):
        self.originate(syn=True)

class PTCPAddress(object):
    # garbage

    def __init__(self, (host, port), (pseudoHostPort, pseudoPeerPort)):
        self.host = host
        self.port = port
        self.pseudoHostPort = pseudoHostPort
        self.pseudoPeerPort = pseudoPeerPort

    def __repr__(self):
        return 'PTCPAddress((%r, %r), (%r, %r))' % (
            self.host, self.port,
            self.pseudoHostPort,
            self.pseudoPeerPort)

class PTCP(protocol.DatagramProtocol):
    # External API

    def __init__(self, factory):
        self.factory = factory
        self._allConnectionsClosed = PendingEvent()

    def connect(self, factory, host, port, pseudoPort=1):
        sourcePseudoPort = genConnID() % MAX_PSEUDO_PORT
        conn = self._connections[(pseudoPort, sourcePseudoPort, (host, port))
                                 ] = PTCPConnection(
            sourcePseudoPort, pseudoPort, self, factory, (host, port))
        conn.input(tcpdfa.APP_ACTIVE_OPEN)
        return conn

    def sendPacket(self, packet):
        if self.transportGoneAway:
            return
        self.transport.write(packet.encode(), packet.destination)


    # Internal stuff
    def startProtocol(self):
        self.transportGoneAway = False
        self._lastConnID = 10 # random.randrange(2 ** 32)
        self._connections = {}

    def _finalCleanup(self):
        """
        Clean up all of our connections by issuing application-level close and
        stop notifications, sending hail-mary final FIN packets (which may not
        reach the other end, but nevertheless can be useful) when possible.
        """
        for conn in self._connections.values():
            conn.immediateShutdown()
        assert not self._connections

    def stopProtocol(self):
        """
        Notification from twisted that our underlying port has gone away;
        make sure we're not going to try to send any packets through our
        transport and blow up, then shut down all of our protocols, issuing
        appr
        opriate application-level messages.
        """
        self.transportGoneAway = True
        self._finalCleanup()

    def cleanupAndClose(self):
        """
        Clean up all remaining connections, then close our transport.

        Although in a pinch we will do cleanup after our socket has gone away
        (if it does so unexpectedly, above in stopProtocol), we would really
        prefer to do cleanup while we still have access to a transport, since
        that way we can force out a few final packets and save the remote
        application an awkward timeout (if it happens to get through, which
        is generally likely).
        """
        self._finalCleanup()
        return self._stop()

    def datagramReceived(self, bytes, addr):
        if len(bytes) < _fixedSize:
            # It can't be any good.
            return

        pkt = PTCPPacket.decode(bytes, addr)
        try:
            pkt.verifyChecksum()
        except TruncatedDataError:
#             print '(ptcp packet truncated: %r)' % (pkt,)
            self.sendPacket(
                PTCPPacket.create(
                    pkt.destPseudoPort,
                    pkt.sourcePseudoPort,
                    0,
                    0,
                    struct.pack('!H', len(pkt.data)),
                    stb=True,
                    destination=addr))
        except GarbageDataError:
            print "garbage data!", pkt
        except ChecksumMismatchError, cme:
            print "bad checksum", pkt, cme
            print repr(pkt.data)
            print hex(pkt.checksum), hex(pkt.computeChecksum())
        else:
            self.packetReceived(pkt)

    stopped = False
    def _stop(self, result=None):
        if not self.stopped:
            self.stopped = True
            return self.transport.stopListening()
        else:
            return defer.succeed(None)

    def waitForAllConnectionsToClose(self):
        """
        Wait for all currently-open connections to enter the 'CLOSED' state.
        Currently this is only usable from test fixtures.
        """
        if not self._connections:
            return self._stop()
        return self._allConnectionsClosed.deferred().addBoth(self._stop)

    def connectionClosed(self, ptcpConn):
        packey = (ptcpConn.peerPseudoPort, ptcpConn.hostPseudoPort,
                  ptcpConn.peerAddressTuple)
        del self._connections[packey]
        if ((not self.transportGoneAway) and
            (not self._connections) and
            self.factory is None):
            self._stop()
        if not self._connections:
            self._allConnectionsClosed.callback(None)

    def packetReceived(self, packet):
        packey = (packet.sourcePseudoPort, packet.destPseudoPort, packet.peerAddressTuple)
        if packey not in self._connections:
            if packet.flags == _SYN and packet.destPseudoPort == 1: # SYN and _ONLY_ SYN set.
                conn = PTCPConnection(packet.destPseudoPort,
                                      packet.sourcePseudoPort, self,
                                      self.factory, packet.peerAddressTuple)
                conn.input(tcpdfa.APP_PASSIVE_OPEN)
                self._connections[packey] = conn
            else:
                log.msg("corrupted packet? %r %r %r" % (packet,packey, self._connections))
                return
        try:
            self._connections[packey].packetReceived(packet)
        except:
            log.msg("PTCPConnection error on %r:" % (packet,))
            log.err()
            del self._connections[packey]
