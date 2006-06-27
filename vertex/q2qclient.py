# Copyright 2005 Divmod, Inc.  See LICENSE file for details

import os
import sys
import struct
import getpass

from epsilon import juice

from vertex import q2q, sigma
from twisted.python.usage import Options, UsageError

from twisted.python import log
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.internet.task import LoopingCall
from twisted.internet import error
from vertex.q2qadmin import AddUser

class Q2QAuthorize(Options):
    def parseArgs(self, who, password=None):
        self.who = who
        self.password = password

    def reportNoCertificate(self, error):
        print "No certificate retrieved:", error.getErrorMessage(), "(see ~/.q2q-client-log for details)"
        log.err(error)
        return None

    def postOptions(self):
        def go():
            self.parent.getService().authorize(
                q2q.Q2QAddress.fromString(self.who),
                self.password).addErrback(self.reportNoCertificate).addCallback(lambda x: reactor.stop())

        if self.password is None:
            self.password = getpass.getpass()

        reactor.callWhenRunning(go)
        self.parent.start()


class BandwidthEstimator:
    bufsize = 20
    totalBytes = 0
    def __init__(self, message, length):
        self.length = length
        self.message = message
        self.estim = []
        self.bytes = 0
        self.call = LoopingCall(self.estimateBandwidth)
        self.call.start(1)

    def estimateBandwidth(self):
        bytes = self.bytes
        self.totalBytes += bytes
        self.estim.append(bytes)
        self.message("%0.2f k/s (%0.2d%%)"
                     % ((sum(self.estim) / len(self.estim)) / 1024.,
                        (float(self.totalBytes) / self.length) * 100))
        if len(self.estim) > self.bufsize:
            self.estim.pop(0)
        self.bytes = 0

    def stop(self):
        self.call.stop()
        self.estimateBandwidth()
        self.message("Finished receiving: %d bytes (%d%%)" % (
                self.totalBytes, (float(self.totalBytes) / self.length) * 100))

class FileReceiver(protocol.Protocol):
    gotLength = False
    estimator = None

    def connectionMade(self):
        self.f = open(self.factory.program.filename, 'wb')
        self.factory.program.parent.info("Started receiving...")

    def dataReceived(self, data):
        if not self.gotLength:
            self.length ,= struct.unpack("!Q", data[:8])
            data = data[8:]
            self.estimator = BandwidthEstimator(self.factory.program.parent.info,
                                                self.length)
            self.gotLength = True

        self.estimator.bytes += len(data)
        self.f.write(data)

    def connectionLost(self, reason):
        self.f.close()
        if self.estimator:
            self.estimator.stop()
        reactor.stop()

from twisted.protocols.basic import FileSender as fsdr

class FileSender(protocol.Protocol):
    def connectionMade(self):
        self.file = self.factory.openFile()
        self.file.seek(0, 2)
        self.length = self.file.tell()
        self.file.seek(0)
        self.estimator = BandwidthEstimator(self.factory.program.parent.info,
                                            self.length)
        self.transport.write(struct.pack("!Q", self.length))
        fsdr().beginFileTransfer(
            self.file, self).addCallback(
            lambda x: self.done())

    def done(self):
        self.factory.program.parent.info("Done sending data: %d bytes" % (
                self.file.tell(),))
        self.transport.loseConnection()

    def dataReceived(self, data):
        print "WTF THE CLIENT IS GETTING DATA", repr(data)

    def registerProducer(self, producer, streaming):
        self.transport.registerProducer(producer, streaming)

    def unregisterProducer(self):
        self.transport.unregisterProducer()

    def write(self, data):
        self.estimator.bytes += len(data)
        self.transport.write(data)

    def connectionLost(self, reason):
        reactor.stop()

class FileSenderFactory(protocol.ClientFactory):
    protocol = FileSender

    def __init__(self, sendprogram):
        self.program = sendprogram

    def openFile(self):
        return file(self.program.filename, 'r')

    def clientConnectionFailed(self, connector, reason):
        self.program.parent.info(
            "Could not connect: %r" % (reason.getErrorMessage(),))
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        reason.trap(error.ConnectionDone)

class FileReceiverFactory(protocol.Factory):
    def __init__(self, program):
        self.program = program
    protocol = FileReceiver


class ClientCertificateStore(q2q.DirectoryCertificateStore):
    def __init__(self, filepath):
        q2q.DirectoryCertificateStore.__init__(self, os.path.expanduser(filepath))


class ClientQ2QService(q2q.Q2QService):
    def __init__(self, certspath, *a, **kw):
        q2q.Q2QService.__init__(self,
                                certificateStorage=ClientCertificateStore(certspath),
                                q2qPortnum=0,
                                *a, **kw)

    def getDefaultFrom(self, default=None):
        i = self.certificateStorage.localStore.iterkeys()
        try:
            return i.next()
        except StopIteration:
            return default


class TunnelProtocol(protocol.Protocol):
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.buffer = []

    def connectionMade(self):
        if self.tunnel is not None:
            self.tunnel.setTunnel(self)

    def dataReceived(self, data):
        if self.tunnel is not None:
            self.tunnel.transport.write(data)
        else:
            self.buffer.append(data)

    def setTunnel(self, tunnel):
        if self.tunnel is None:
            self.tunnel = tunnel
            self.dataReceived(''.join(self.buffer))
            del self.buffer
            self.tunnel.setTunnel(self)

class TunnelFactory(protocol.ClientFactory):
    def __init__(self, tunnel):
        self.tunnel = tunnel

    def buildProtocol(self, addr):
        return TunnelProtocol(self.tunnel)

    def clientConnectionFailed(self, connector, reason):
        self.tunnel.transport.loseConnection()
        reactor.stop()

    clientConnectionLost = clientConnectionFailed

class Q2QTunnel(Options):
    optParameters = [
        ['port', 'p', '13000', 'Port on which to start the TCP server'],
        ['destination', 'd', None, 'Q2Q address to which to create the tunnel'],
        ['protocol', 'r', None, 'Q2Q protocol which will operate over the tunnel']]

    def postOptions(self):
        self.toAddr = q2q.Q2QAddress.fromString(self['destination'])

        reactor.listenTCP(int(self['port']), self, interface='127.0.0.1')
        self.parent.start()

    def doStart(self):
        pass

    def doStop(self):
        pass

    def buildProtocol(self, addr):
        p = TunnelProtocol(None)
        svc = self.parent.getService()
        svc.connectQ2Q(self.parent.getFrom(), self.toAddr,
                       self['protocol'], TunnelFactory(p))
        return p

class Q2QReceive(Options):
    optParameters = [["port", "p", "41235", "Port to start the listening server on."]]

    def parseArgs(self, filename):
        self.filename = filename

    def postOptions(self):
        serv = self.parent.getService()
        def pr(x):
            return x
        def stopit(err):
            print "Couldn't Register for File Transfer:", err.getErrorMessage()
            log.err(err)
            reactor.stop()
        serv.listenQ2Q(self.parent.getFrom(),
                       {'file-transfer': FileReceiverFactory(self)},
                       "simple file transfer test").addCallback(pr).addErrback(stopit)
        self.parent.start()

class Q2QSend(Options):

    def parseArgs(self, to, filename):
        self.to = to
        self.filename = filename

    def postOptions(self):
        fs = q2q.Q2QAddress.fromString
        toAddress = fs(self.to)
        fromAddress = self.parent.getFrom()

        toDomain = toAddress.domainAddress()
        svc = self.parent.getService()
        svc.connectQ2Q(fromAddress, toAddress, 'file-transfer',
                       FileSenderFactory(self))
        self.parent.start()


class TextNexusUI(sigma.BaseNexusUI):
    def __init__(self):
        sigma.BaseNexusUI.__init__(self)
        self.call = LoopingCall(self.report)
        self.call.start(5)

    def report(self):
        print 'Transloads:', len(self.transloads)
        for transloadui in self.transloads:
            print '---', transloadui.name, '---'
            print transloadui.bits.percent()
            for peer, mask in transloadui.masks.items():
                print peer, mask.percent()
        print 'end report'

class Q2QSigma(Options):

    def __init__(self, *a, **k):
        Options.__init__(self,*a,**k)
        self.pushers = []

    def opt_push(self, filename):
        self.pushers.append([file(filename), filename, []])

    def opt_to(self, q2qid):
        fs = q2q.Q2QAddress.fromString
        addr = fs(q2qid)
        self.pushers[-1][-1].append(addr)

    def postOptions(self):
        nex = sigma.Nexus(self.parent.getService(),
                          self.parent.getFrom(),
                          TextNexusUI())
        # XXX TODO: there has _GOT_ to be a smarter way to handle text UI for
        # this.
        for sharefile, sharename, sharepeers in self.pushers:
            nex.push(sharefile, sharename, sharepeers)
        self.parent.start()

class UserAdder(juice.Juice):
    def __init__(self):
        juice.Juice.__init__(self, False)

    def connectionMade(self):
        self.d = AddUser(name=self.factory.name,
                         password=self.factory.password).do(self)


class UserAdderFactory(protocol.ClientFactory):
    protocol = UserAdder

    def __init__(self, name, password):
        self.name, self.password = name, password


def enregister(svc, newAddress, password):
    """
    Register a new account and return a Deferred that fires if it worked.

    @param svc: a Q2QService

    @param newAddress: a Q2QAddress object

    @param password: a shared secret (str)
    """
    def trapit(x):
        x.trap(error.ConnectionDone)
    return svc.connectQ2Q(q2q.Q2QAddress("",""),
                       q2q.Q2QAddress(newAddress.domain, "accounts"),
                       'identity-admin',
                       UserAdderFactory(newAddress.resource, password)
                       ).addCallback(
            lambda proto: proto.d).addErrback(
            trapit)

class Q2QRegister(Options):
    synopsis = "<new Q2Q address> <password>"
    def parseArgs(self, newaddress, password):
        self.newaddress = newaddress
        self.password = password

    def postOptions(self):
        fs = q2q.Q2QAddress.fromString
        newAddress = fs(self.newaddress)
        svc = self.parent.getService()

        def showit(x):
            print "%s: %s" % (x.value.__class__, x.getErrorMessage())

        enregister(svc, newAddress, self.password).addErrback(
            showit).addBoth(lambda nothing: reactor.stop())
        self.parent.start()


class Q2QClientProgram(Options):
    subCommands = [
        ['authorize', 'a', Q2QAuthorize, 'Authorize a user'],
        ['register', 'r', Q2QRegister, 'Create a new user '],
        ['tunnel', 't', Q2QTunnel, 'Create an SSL tunnel to a given resource'],
        ['receive', 'l', Q2QReceive, 'Receive for a filetransfer connection'],
        ['send', 's', Q2QSend, 'Send'],
        ['sigma', 'g', Q2QSigma, 'Sigma swarming file-transfer']
        ]

    optParameters = [
        ['from', 'f', None, "Who to send as?"],
        ['tcp', 'p', None, 'TCP port number'],
        ['udp', 'u', 0, 'UDP port number'],
        ['certspath', 'c', "~/.q2qcerts",
         "Path to directory full of public/private certificates."],
        ['logfile', 'l', "~/.q2q-client-log",
         "Path to file where logs of client activity will be written."]
        ]

    optFlags = []

    service = None

    def postOptions(self):
        if not self.subCommand:
            self.opt_help()

    def info(self, message):
        sys.stderr.write(">> %s\n" % (message,))

    def getService(self):
        if self.service is None:
            u = self['udp']
            if u is not None:
                u = int(u)
            t = self['tcp']
            if t is not None:
                t = int(t)
            self.service = ClientQ2QService(self['certspath'],
                                            inboundTCPPortnum=t)
        return self.service

    def getDefaultPath(self):
        return os.path.expanduser(os.path.join(self['certspath'], 'default-address'))

    def getFrom(self):
        fr = self['from']
        if not fr:
            defpath = self.getDefaultPath()
            if os.path.exists(defpath):
                fr = file(defpath).read()
            else:
                fr = self.getService().getDefaultFrom()
                if fr is None:
                    self.info("No default address available, exiting.")
                    self.info(
                        " (Try 'q2q register yourself@divmod.net; "
                        "q2q authorize yourself@divmod.net')")
                    sys.exit(19)
                self.info("Selected default address:"  +fr)
                f = file(defpath, 'wb')
                f.write(fr)
                f.close()

        return q2q.Q2QAddress.fromString(fr)

    def start(self, portno=None):
        import sys
        lfname = self['logfile']
        if lfname == '-':
            lf = sys.stdout
        else:
            lf = file(os.path.expanduser(lfname), 'ab+')
        log.startLogging(lf,
                         setStdout=False)
        srv = self.getService()
        from twisted.application.app import startApplication
        startApplication(srv, False)
        reactor.run()

    verbosity = 0

    def verboseLogger(self, messageDict):
        self.info(' '.join([str(x) for x in messageDict.get('message', [])]))

    def opt_verbose(self):
        self.verbosity += 1
        log.addObserver(log.FileLogObserver(sys.stderr).emit)

    opt_v = opt_verbose
