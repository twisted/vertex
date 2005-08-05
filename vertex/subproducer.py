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
        for transport, (producer, streaming) in self.producingTransports.items():
            if streaming:
                try:
                    producer.pauseProducing()
                except:
                    del self.producingTransports[transport]
                    log.err()

    def resumeProducing(self):
        producersWerePaused = self.producersPaused
        if producersWerePaused:
            self.producersPaused = False
        for transport, (producer, streaming) in self.producingTransports.items():
            if producersWerePaused or not streaming:
                try:
                    producer.resumeProducing()
                except:
                    del self.producingTransports[transport]
                    log.err()

    def stopProducing(self):
        for transport, (producer, streaming) in self.producingTransports.items():
            try:
                producer.stopProducing()
            except:
                log.err()
        self.producingTransports = {}

    def registerProducerFor(self, trans, prod, strm):
        if not strm:
            prod.resumeProducing()
        wasProducing = bool(self.producingTransports)
        assert trans not in self.producingTransports
        self.producingTransports[trans] = prod, strm
        if not wasProducing:
            self.transport.registerProducer(self, False)

    def unregisterProducerFor(self, trans):
        if trans in self.producingTransports:
            self.producingTransports[trans]
            if not self.producingTransports:
                self.transport.unregisterProducer()


class SubProducer:
    """ I am a mixin that provides upwards-registration of my producer to a
    SuperProducer instance.
    """
    def __init__(self, superproducer):
        self.superproducer = superproducer
        self.producer = None

    def registerProducer(self, producer, streaming):
        self.producer = producer
        self.superproducer.registerProducerFor(self, producer, streaming)

    def unregisterProducer(self):
        self.superproducer.unregisterProducerFor(self)
        self.producer = None

