# -*- test-case-name: vertex.test.test_subproducer -*-
# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from twisted.python import log

class SuperProducer:
    """I am a mixin which provides support for mixing in several producers to one
    producer.  I act as a consumer for my producers and as a producer for one
    consumer.

    I must be mixed into a protocol, or something else with a 'transport' attribute.
    """

    producersPaused = False

    def __init__(self):
        self.producingTransports = {}

    def pauseProducing(self):
        self.producersPaused = True
        for transport in self.producingTransports.keys():
            try:
                transport.parentPauseProducing()
            except:
                del self.producingTransports[transport]
                log.err()

    def resumeProducing(self):
        producersWerePaused = self.producersPaused
        if producersWerePaused:
            self.producersPaused = False
        for transport in self.producingTransports.keys():
            try:
                transport.parentResumeProducing()
            except:
                del self.producingTransports[transport]
                log.err()

    def stopProducing(self):
        for transport in self.producingTransports.keys():
            try:
                transport.parentStopProducing()
            except:
                log.err()
        self.producingTransports = {}

    def registerProducerFor(self, trans):
        if not self.producersPaused:
            trans.parentResumeProducing()
        wasProducing = bool(self.producingTransports)
        assert trans not in self.producingTransports
        self.producingTransports[trans] = 1
        if not wasProducing:
            self.transport.registerProducer(self, False)

    def unregisterProducerFor(self, trans):
        if trans in self.producingTransports:
            del self.producingTransports[trans]
            if not self.producingTransports:
                self.transport.unregisterProducer()


class SubProducer:
    """ I am a mixin that provides upwards-registration of my producer to a
    SuperProducer instance.
    """
    def __init__(self, superproducer):
        self.superproducer = superproducer
        self.producer = None
        self.parentAcceptingData = True
        self.peerAcceptingData = True
        self.producerPaused = False
        self.parentStopped = False

    def maybeResumeProducing(self):
        if ((self.producer is not None) and
            ((not self.streamingProducer) or
             (self.producerPaused)) and
            (self.peerAcceptingData) and
            (self.parentAcceptingData)):
            self.producerPaused = False
            self.producer.resumeProducing()

    def maybePauseProducing(self):
        if ((self.producer is not None) and
            ((not self.peerAcceptingData) or
             (not self.parentAcceptingData)) and
            (not self.producerPaused)):
            self.producerPaused = True
            self.producer.pauseProducing()

    def parentResumeProducing(self):
        self.parentAcceptingData = True
        self.maybeResumeProducing()

    def parentPauseProducing(self):
        self.parentAcceptingData = False
        self.maybePauseProducing()

    def parentStopProducing(self):
        self.parentStopped = True
        if self.producer is not None:
            self.producer.stopProducing()

    def choke(self):
        self.peerAcceptingData = False
        self.maybePauseProducing()

    def unchoke(self):
        self.peerAcceptingData = True
        self.maybeResumeProducing()

    def registerProducer(self, producer, streaming):
        if self.parentStopped:
            producer.stopProducing()
            return
        self.producer = producer
        self.streamingProducer = streaming
        self.superproducer.registerProducerFor(self)

    def unregisterProducer(self):
        if not self.parentStopped:
            self.superproducer.unregisterProducerFor(self)
        self.producer = None

