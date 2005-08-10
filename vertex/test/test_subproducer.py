
from twisted.trial import unittest

from vertex.subproducer import SuperProducer, SubProducer

class TestSuper(SuperProducer):
    transport = property(lambda self: self)

    def registerProducer(self, producer, streaming):
        self.producer = producer
        self.streamingProducer = streaming

    def unregisterProducer(self):
        self.producer = None

class TestProducer:
    def __init__(self):
        self.calls = []

    def resumeProducing(self):
        self.calls.append('resume')

    def pauseProducing(self):
        self.calls.append('pause')

    def stopProducing(self):
        self.calls.append('stop')

    def clear(self):
        del self.calls[:]


class SuperProducerTest(unittest.TestCase):

    def testBasicNotification(self):
        sup = TestSuper()
        sub = SubProducer(sup)

        tp1 = TestProducer()
        sub.registerProducer(tp1, False)
        self.assertEquals(tp1.calls, ['resume'])
        sub.unregisterProducer()

        tp2 = TestProducer()
        sub.registerProducer(tp2, True)
        self.assertEquals(tp2.calls, [])
        sub.unregisterProducer()

    def testPauseSuperBeforeRegister(self):
        sup = TestSuper()
        sub1 = SubProducer(sup)
        sub2 = SubProducer(sup)

        tp1 = TestProducer()
        tp2 = TestProducer()

        sub1.registerProducer(tp1, False)
        sub2.registerProducer(tp2, False)

        self.assertEquals(sup.producer, sup) # Make sure it's registered with
                                             # itself; IOW it has called
                                             # self.transport.registerProducer(self).

        sup.pauseProducing()
        sup.resumeProducing()

        self.assertEquals(tp1.calls, ['resume', 'pause', 'resume'])
        self.assertEquals(tp2.calls, ['resume', 'pause', 'resume'])

        sup.stopProducing()
        self.assertEquals(tp1.calls, ['resume', 'pause', 'resume', 'stop'])
        self.assertEquals(tp2.calls, ['resume', 'pause', 'resume', 'stop'])


    def testNonStreamingChoke(self):
        sup = TestSuper()
        sub1 = SubProducer(sup)
        sub2 = SubProducer(sup)

        tp1 = TestProducer()
        tp2 = TestProducer()

        sub1.registerProducer(tp1, False)
        sub2.registerProducer(tp2, False)

        self.assertEquals(tp1.calls, ['resume'])
        self.assertEquals(tp2.calls, ['resume'])

        tp1.clear()
        tp2.clear()

        self.assertEquals(sup.producer, sup)

        sub1.choke()
        self.assertEquals(tp1.calls, ['pause'])
        self.assertEquals(tp2.calls, [])

        sup.pauseProducing()
        self.assertEquals(tp1.calls, ['pause'])
        self.assertEquals(tp2.calls, ['pause'])

        sup.resumeProducing()
        self.assertEquals(tp1.calls, ['pause'])
        self.assertEquals(tp2.calls, ['pause', 'resume'])

        sup.pauseProducing()
        sup.resumeProducing()
        self.assertEquals(tp1.calls, ['pause'])
        self.assertEquals(tp2.calls, ['pause', 'resume', 'pause', 'resume'])
        sub1.unchoke()

        self.assertEquals(tp1.calls, ['pause', 'resume'])
        self.assertEquals(tp2.calls, ['pause', 'resume', 'pause', 'resume'])

        sup.pauseProducing()
        sub1.choke()
        sub1.choke()
        sub1.choke()
        self.assertEquals(tp1.calls, ['pause', 'resume', 'pause'])
        self.assertEquals(tp2.calls, ['pause', 'resume', 'pause', 'resume',
                                      'pause'])

        sub1.unchoke()
        self.assertEquals(tp1.calls, ['pause', 'resume', 'pause'])
        self.assertEquals(tp2.calls, ['pause', 'resume', 'pause', 'resume',
                                      'pause'])

        sup.resumeProducing()
        self.assertEquals(tp1.calls, ['pause', 'resume', 'pause', 'resume'])
        self.assertEquals(tp2.calls, ['pause', 'resume', 'pause', 'resume',
                                      'pause', 'resume'])
        tp1.clear()
        tp2.clear()
        sup.stopProducing()

        self.assertEquals(tp1.calls, ['stop'])
        self.assertEquals(tp2.calls, ['stop'])

    def testStreamingChoke(self):
        sup = TestSuper()
        sub1 = SubProducer(sup)
        sub2 = SubProducer(sup)

        tp1 = TestProducer()
        tp2 = TestProducer()

        sub1.registerProducer(tp1, True)
        sub2.registerProducer(tp2, True)

        self.assertEquals(tp1.calls, [])
        self.assertEquals(tp2.calls, [])

        sub1.choke()
        self.assertEquals(tp1.calls, ['pause'])
        self.assertEquals(tp2.calls, [])

        sup.pauseProducing()
        self.assertEquals(tp1.calls, ['pause'])
        self.assertEquals(tp2.calls, ['pause'])

        sup.resumeProducing()
        self.assertEquals(tp1.calls, ['pause'])
        self.assertEquals(tp2.calls, ['pause', 'resume'])

        sub1.unchoke()
        self.assertEquals(tp1.calls, ['pause', 'resume'])
        self.assertEquals(tp2.calls, ['pause', 'resume'])

        tp1.clear()
        tp2.clear()
        sup.stopProducing()
        self.assertEquals(tp1.calls, ['stop'])
        self.assertEquals(tp2.calls, ['stop'])
