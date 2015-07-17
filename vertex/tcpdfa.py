# -*- test-case-name: vertex.test.test_ptcp -*-
# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from automat import MethodicalMachine


class TCP(object):
    """
    
    """

    _machine = MethodicalMachine()

    def __init__(self, impl):
        """
        
        """
        self._impl = impl
        self.ackPredicate = lambda packet: False

    @_machine.state(initial=True)
    def closed(self):
        """
        
        """

    # This isn't detailed by the spec in the diagram, so we use a different
    # identifier, but in various places it does make references to going
    # straight to the 'closed' state.
    broken = closed

    @_machine.state()
    def synSent(self):
        """
        
        """

    @_machine.state()
    def synRcvd(self):
        """
        
        """

    @_machine.state()
    def listen(self):
        """
        
        """


    @_machine.state()
    def established(self):
        """
        
        """


    @_machine.state()
    def closeWait(self):
        """
        
        """

    @_machine.state()
    def lastAck(self):
        """
        
        """

    @_machine.state()
    def finWait1(self):
        """
        
        """
    @_machine.state()
    def finWait2(self):
        """
        
        """

    @_machine.state()
    def closing(self):
        """
        
        """

    @_machine.state()
    def timeWait(self):
        """
        
        """

    @_machine.input()
    def appPassiveOpen(self):
        """
        
        """
        

    @_machine.input()
    def appActiveOpen(self):
        """
        
        """

    @_machine.input()
    def timeout(self):
        """
        
        """

    @_machine.input()
    def appClose(self):
        """
        
        """

    @_machine.input()
    def synAck(self):
        """
        
        """

    @_machine.input()
    def ack(self):
        """
        
        """

    @_machine.input()
    def rst(self):
        """
        
        """
        

    @_machine.input()
    def appSendData(self):
        """
        
        """
        

    @_machine.input()
    def syn(self):
        """
        
        """

    @_machine.input()
    def fin(self):
        """
        
        """


    @_machine.input()
    def segmentReceived(self):
        """
        Bonus input!  This is when the segment length of an incoming packet is
        non-zero; in other words, some data has arrived, probably (hopefully?)
        in ESTABLISHED, and we have to send an acknowledgement.
        """


    @_machine.output()
    def expectAck(self):
        """
        When the most recent packet produced as an output of this state machine
        is acknowledged by our peer, generate a single 'ack' input.
        """
        last = self.lastTransmitted
        self.ackPredicate = lambda ackPacket: (
            ackPacket.relativeAck() >= last.relativeSeq()
        )


    def originate(self, **kw):
        """
        Originate a packet.
        """
        self.lastTransmitted = self._impl.originate(**kw)


    @_machine.output()
    def sendSyn(self):
        """
        
        """
        self.originate(syn=True)


    @_machine.output()
    def sendFin(self):
        """
        
        """
        self.originate(fin=True)


    @_machine.output()
    def sendSynAck(self):
        """
        
        """
        self.originate(syn=True, ack=True)


    @_machine.output()
    def sendAck(self):
        """
        Send an ACK-only packet, immediately.
        """
        # You never need to ACK the ACK, so don't record it as lastTransmitted.
        self._impl.originate(ack=True)


    def sendAckSoon(self):
        """
        Send an ACK-only packet, but, give it a second; some more data might be
        coming shortly.
        """
        self._impl.ackSoon()


    @_machine.output()
    def sendRst(self):
        """
        
        """
        # note: unused / undefined in original impl, need test
        self.originate(rst=True)


    def maybeReceiveAck(self, ackPacket):
        """
        Receive an L{ack} or L{synAck} input from the given packet.
        """
        ackPredicate = self.ackPredicate
        self.ackPredicate = lambda packet: False
        if ackPacket.syn:
            # New SYN packets are always news.
            self.synAck()
            return
        if ackPredicate(ackPacket):
            self.ack()


    @_machine.output()
    def appNotifyConnected(self):
        """
        
        """
        # we just entered the 'established' state so clear the ack-expectation
        # high water mark
        self.ackReceiveHighWaterMark = None
        self._impl.connectionJustEstablished()


    @_machine.output()
    def appNotifyDisconnected(self):
        """
        
        """
        self._impl.connectionJustEnded()


    @_machine.output()
    def releaseResources(self):
        """
        
        """
        self._impl.releaseConnectionResources()


    @_machine.output()
    def startTimeWaiting(self):
        """
        
        """
        self._impl.scheduleTimeWaitTimeout()

    @_machine.output()
    def appNotifyListen(self):
        """
        
        """
        self._impl.nowListeningSocket()

    @_machine.output()
    def appNotifyHalfClose(self):
        """
        Input ended.
        """
        self._impl.nowHalfClosed()


    @_machine.output()
    def appNotifyAttemptFailed(self):
        """
        
        """
        self._impl.outgoingConnectionFailed()


    # invariant: if a state has .upon(ack) in it, all enter=that-state edges
    # here must produce the "expectAck" output.
    closed.upon(appPassiveOpen, enter=listen, outputs=[appNotifyListen])
    closed.upon(appActiveOpen, enter=synSent, outputs=[sendSyn,
                                                       expectAck])

    synSent.upon(timeout, enter=closed,
                 outputs=[appNotifyAttemptFailed, releaseResources])
    synSent.upon(appClose, enter=closed,
                 outputs=[appNotifyAttemptFailed, releaseResources])
    synSent.upon(synAck, enter=established,
                 outputs=[sendAck, appNotifyConnected])

    synRcvd.upon(ack, enter=established,
                 outputs=[appNotifyConnected])
    synRcvd.upon(appClose, enter=finWait1,
                 outputs=[sendFin, expectAck])
    synRcvd.upon(timeout, enter=closed,
                 outputs=[sendRst, releaseResources])
    synRcvd.upon(rst, enter=broken,
                 outputs=[releaseResources])

    listen.upon(appSendData, enter=synSent,
                outputs=[sendSyn, expectAck])
    listen.upon(syn, enter=synRcvd,
                outputs=[sendSynAck, expectAck])

    established.upon(appClose, enter=finWait1,
                     outputs=[appNotifyDisconnected,
                              sendFin,
                              expectAck])
    established.upon(fin, enter=closeWait,
                     outputs=[appNotifyHalfClose,
                              sendAck])
    established.upon(timeout, enter=broken, outputs=[appNotifyDisconnected,
                                                     releaseResources])

    established.upon(segmentReceived, enter=established,
                     outputs=[sendAckSoon])


    closeWait.upon(appClose, enter=lastAck,
                   outputs=[sendFin,
                            expectAck,
                            appNotifyDisconnected])
    closeWait.upon(timeout, enter=broken,
                   outputs=[appNotifyDisconnected,
                            releaseResources])

    lastAck.upon(ack, enter=closed, outputs=[releaseResources])
    lastAck.upon(timeout, enter=broken, outputs=[releaseResources])

    # TODO: is this actually just "ack" or is it ack _of_ something in
    # particular?  ack of the fin we sent upon transitioning to this state?
    finWait1.upon(ack, enter=finWait2, outputs=[])
    finWait1.upon(fin, enter=closing, outputs=[sendAck])
    finWait1.upon(timeout, enter=broken, outputs=[releaseResources])

    finWait2.upon(timeout, enter=broken, outputs=[releaseResources])
    finWait2.upon(fin, enter=timeWait, outputs=[sendAck, startTimeWaiting])

    closing.upon(timeout, enter=broken, outputs=[releaseResources])
    closing.upon(ack, enter=timeWait, outputs=[startTimeWaiting])

    timeWait.upon(timeout, enter=closed, outputs=[releaseResources])

    for noDataState in [finWait1, finWait2, closing]:
        noDataState.upon(segmentReceived, enter=noDataState, outputs=[])
