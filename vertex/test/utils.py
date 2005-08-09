from zope.interface import implements
from twisted.internet import interfaces

class FileWrapper:
    """A wrapper around a file-like object to make it behave as a Transport.

    This doesn't actually stream the file to the attached protocol,
    and is thus useful mainly as a utility for debugging protocols.
    """

    implements(interfaces.ITransport)

    closed = 0
    disconnecting = 0
    disconnected = 0
    producer = None
    streamingProducer = 0

    def __init__(self, file):
        self.file = file

    def write(self, data):
        try:
            self.file.write(data)
        except:
            self.handleException()
        # self._checkProducer()

    def _checkProducer(self):
        # Cheating; this is called at "idle" times to allow producers to be
        # found and dealt with
        if self.producer:
            self.producer.resumeProducing()

    def registerProducer(self, producer, streaming):
        """From abstract.FileDescriptor
        """
        self.producer = producer
        self.streamingProducer = streaming
        if not streaming:
            producer.resumeProducing()

    def unregisterProducer(self):
        self.producer = None

    def stopConsuming(self):
        self.unregisterProducer()
        self.loseConnection()

    def writeSequence(self, iovec):
        self.write("".join(iovec))

    def loseConnection(self):
        self.disconnecting = True

    def getPeer(self):
        # XXX: According to ITransport, this should return an IAddress!
        return 'file', 'file'

    def getHost(self):
        # XXX: According to ITransport, this should return an IAddress!
        return 'file'

    def handleException(self):
        pass

    def resumeProducing(self):
        # Never sends data anyways
        pass

    def pauseProducing(self):
        # Never sends data anyways
        pass

    def stopProducing(self):
        self.loseConnection()

