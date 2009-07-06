# -*- test-case-name: vertex.test.test_sigma -*-
# Copyright 2005 Divmod, Inc.  See LICENSE file for details

"""
%file transfer protocol, a-la bittorrent.
"""

import array
import random
import sha
import os
import sets

from twisted.internet import protocol

from twisted.python.filepath import FilePath

from epsilon import juice

from vertex import q2q
from vertex import bits
from vertex import conncache
from vertex import endpoint

__metaclass__ = type

# protocol below

PROTOCOL_NAME = 'sigma'

class VerifyError(Exception):
    pass

class BitArrayArgument(juice.String):
    def toString(self, arr):
        return str(arr.size) + ':' + arr.bytes.tostring()

    def fromString(self, st):
        size, bytes = st.split(":", 1)
        b = array.array("B")
        b.fromstring(bytes)
        return bits.BitArray(b, int(size))

class Put(juice.Command):
    """
    Tells the remote end it should request a file from me.
    """

    arguments = [("name", juice.String())]


class Get(juice.Command):
    """
    Tells the remote it should start sending me chunks of a file.
    """

    arguments = [("name", juice.String()),
                 ('mask', BitArrayArgument(optional=True))]

    response = [("size", juice.Integer())] # number of octets!!


class Data(juice.Command):
    """
    Sends some data for a transfer.
    """

    arguments = [('name', juice.String()),
                 ('chunk', juice.Integer()),
                 (juice.BODY, juice.String())]

class Introduce(juice.Command):
    """
    Tells the remote end about another node which should have information about
    this transfer.

    Peer: the address of the peer
    Name: the name of the file given.
    """

    arguments = [('peer', q2q.Q2QAddressArgument()),
                 ('name', juice.String())]

class Verify(juice.Command):
    """
    Verify that the checksum of the given chunk is correct.

    Errors:

      - chunk checksum incorrect
      - host hasn't computed checksum for that chunk yet.
    """

    arguments = [('name', juice.String()),
                 ('peer', q2q.Q2QAddressArgument()),
                 ('chunk', juice.Integer()),
                 ('sha1sum', juice.String())]



# this is a fixed, protocol-level constant
CHUNK_SIZE = 1024 * 16

DONE = {}                       # perhaps Juice should map this to None?

def countChunks(bytes):
    div, mod = divmod(bytes, CHUNK_SIZE)
    div += bool(mod)
    return div

class SigmaProtocol(juice.Juice):
    """I am a connection to a peer who has some resources I want in the
    file-swarming network.
    """

    def __init__(self, issueGreeting, nexus):
        juice.Juice.__init__(self, issueGreeting)
        self.nexus = nexus
        self.sentTransloads = []

    def command_GET(self, name, mask=None):
        peer = self.transport.getQ2QPeer()
        tl = self.nexus.transloads[name]
        size = tl.getSize()
        if mask is None:
            # all zeroes!
            mask = bits.BitArray(size=countChunks(size))
        # retrieve persistent scoring and such?
        tl.updatePeerMask(peer, mask)
        peerK = tl.peers[peer]
        if (not peerK.sentGet) and peerK.mask.any(0):
            # send a reciprocal GET
            self.get(name, tl.mask)
        return dict(size=size)

    command_GET.command = Get

    def command_DATA(self, name, chunk, body):
        self.nexus.transloads[name].chunkReceived(
            self.transport.getQ2QPeer(), chunk, body)
        return DONE

    command_DATA.command = Data

    def command_PUT(self, name):
        peer = self.transport.getQ2QPeer()
        incompleteFilePath, fullFilePath = self.nexus.ui.allocateFile(
            name, peer)
        self.nexus.pull(incompleteFilePath, fullFilePath, name, peer)
        return DONE

    command_PUT.command = Put

    def command_VERIFY(self, peer, name, chunk, sha1sum):
        if self.nexus.transloads[name].verifyLocalChunk(peer, chunk, sha1sum):
            return dict()
        raise RuntimeError("checksum incorrect")

    command_VERIFY.command = Verify

    def data(self, name, chunk, body):
        """
        Issue a DATA command

        return None

        Sends a chunk of data to a peer.
        """
        Data(name=name,
             chunk=chunk,
             body=body).do(self,
                           requiresAnswer=False)

    def introduce(self, name, peerToIntroduce):
        Introduce(peer=peerToIntroduce,
                  name=name).do(self, requiresAnswer=False)

    def command_INTRODUCE(self, peer, name):
        # Like a PUT, really, but assuming the transload is already
        # established.

        self.nexus.ui.receivedIntroduction(peer, name)

        t = self.nexus.transloads[name]
        if peer in t.peers:
            return {}

        # all bits are set until he responds that he wants something.

        t.updatePeerMask(peer, bits.BitArray(default=1, size=len(t.mask)))

        self.nexus.connectPeer(peer).addCallback(
            lambda peerProto: peerProto.get(name, t.mask))
        return {}

    command_INTRODUCE.command = Introduce

    def get(self, name, mask=None):
        """
        Issue a GET command

        Return a Deferred which fires with the size of the name being requested
        """
        mypeer = self.transport.getQ2QPeer()
        tl = self.nexus.transloads[name]
        peerz = tl.peers
        if mypeer in peerz:
            peerk = peerz[mypeer]
        else:
            # all turned on initially; we aren't going to send them anything.
            peerk = PeerKnowledge(bits.BitArray(size=len(tl.mask), default=1))
            peerz[mypeer] = peerk
        peerk.sentGet = True
        return Get(name=name, mask=mask).do(self).addCallback(lambda r: r['size'])

    def verify(self, name, peer, chunkNumber, sha1sum):
        return Verify(name=name,
                      peer=peer,
                      chunk=chunkNumber,
                      sha1sum=sha1sum).do(self)


    def connectionMade(self):
        self.nexus.conns.cacheUnrequested(endpoint.Q2QEndpoint(
                self.nexus.svc,
                self.nexus.addr,
                self.transport.getQ2QPeer(),
                PROTOCOL_NAME), None, self)
        self.transport.registerProducer(self, 0)

    def stopProducing(self):
        ""

    pauses = 0

    def pauseProducing(self):
        self.pauses += 1

    def resumeProducing(self):
        """
        algorithm needed here: determine the proportion of my bandwidth that
        should be going to _ALL_ consumers based on the proportion of the sum
        of all scores that are available.  then determine how long I need to
        wait before I send data to my peer.
        """
        self.nexus.callLater(0.0001, self.sendSomeData, 2)

    def sendSomeData(self, howMany):
        """
        Send some DATA commands to my peer(s) to relay some data.

        @param howMany: an int, the number of chunks to send out.
        """
        # print 'sending some data', howMany
        if self.transport is None:
            return
        peer = self.transport.getQ2QPeer()
        while howMany > 0:
            # sort transloads so that the least-frequently-serviced ones will
            # come first
            tloads = [
                (findin(tl.name, self.sentTransloads),
                 tl) for tl in self.nexus.transloadsForPeer(peer)]
            tloads.sort()
            tloads = [tl for (idx, tl) in tloads if tl.peerNeedsData(peer)]
            if not tloads:
                break

            wasHowMany = howMany

            for myTransload in tloads:
                # move this transload to the end so it will be sorted last next
                # time.
                name = myTransload.name
                if name in self.sentTransloads:
                    self.sentTransloads.remove(name)
                self.sentTransloads.append(name)

                knowledge = myTransload.peers[peer]
                chunkNumber, chunkData = myTransload.selectOptimalChunk(peer)
                if chunkNumber is None:
                    continue

                peerToIntroduce = knowledge.selectPeerToIntroduce(
                    myTransload.peers.keys())

                if peerToIntroduce is not None:
                    self.introduce(myTransload.name, peerToIntroduce)

                self.data(name, chunkNumber, chunkData)
                # Don't re-send that chunk again unless they explicitly tell us
                # they need it for some reason
                knowledge.mask[chunkNumber] = 1
                howMany -= 1
                if howMany <= 0:
                    break

            if wasHowMany == howMany:
                # couldn't find anything to send.
                break


def findin(item, list):
    """
    Find C{item} in C{list}.
    """
    try:
        return list.index(item)
    except ValueError:
        # x not in list
        return -1

class PeerKnowledge:
    """
    Local representation of a peer's knowledge of a transload.
    """

    sentGet = False

    def __init__(self, mask):
        self.mask = mask
        self.otherPeers = []

    def selectPeerToIntroduce(self, otherPeers):
        """
        Choose a peer to introduce.  Return a q2q address or None, if there are
        no suitable peers to introduce at this time.
        """
        for peer in otherPeers:
            if peer not in self.otherPeers:
                self.otherPeers.append(peer)
                return peer


class Transload:
    """
    An upload/download currently in progress

    @ivar maximumMaskUpdateDelayAfterChange: the maximum amount of time to wait
          after a change to the bitmask before sending out an updated mask to
          our peers.

    @ivar maximumChangeCountBeforeMaskUpdate: the maximum number of bits we
          will allow to change in our mask before sending an update to our
          peers.

    """

    maximumMaskUpdateDelayAfterChange = 30.0
    maximumChangeCountBeforeMaskUpdate = 25

    def __init__(self, authority, nexus, name,
                 incompletePath, fullPath, ui,
                 seed=False):
        """
        Create a Transload.

        @param authority: the q2q address of the first authority on this file.
        """

        self.incompletePath = incompletePath
        self.fullPath = fullPath

        self.ui = ui
        self.authorities = [authority] # q2q address(es) that you send VERIFYs to

        self.seed = seed

        if not seed:
            self.file = openReadWrite(incompletePath.path)
        else:
            self.file = fullPath.open()

        chunkCount = countChunks(self.getSize())
        mask = bits.BitArray(size=chunkCount, default=int(seed))
        if seed:
            maskfile = None
        else:
            maskfile = openMaskFile(incompletePath.path)

        self.mask = mask        # BitArray object representing which chunks of
                                # the file I've got
        self.maskfile = maskfile # ugh - open file object that keeps a record
                                 # of the bitmask
        self.sha1sums = {}       # map {chunk-number: sha1sum}
        self.nexus = nexus         # Nexus instance that I belong to
        self.name = name         # the name of the file object being
                                 # transferred.

        self.changes = 0        # the number of mask changes since the last update
        self.peers = {}         # map {q2q address: [PeerKnowledge]}

        # We want to retransmit GET every so often
        self.call = self.nexus.callLater(0.002, self.maybeUpdateMask)

    def stop(self):
        if self.call is not None:
            self.call.cancel()
            self.call = None

    def changeSize(self, size):
        assert len(self.mask) == 0
        self.file.seek(size-1)
        assert self.file.read(1) == ''
        self.file.write("\x00")
        chunkCount = countChunks(size)
        self.mask = bits.BitArray(size=chunkCount)
        self.writeMaskFile()

    def writeMaskFile(self):
        self.maskfile.seek(0)
        self.maskfile.write(buffer(self.mask.bytes))
        self.maskfile.flush()

    def updatePeerMask(self, peer, mask):
        if peer in self.peers:
            self.peers[peer].mask = mask
        else:
            self.peers[peer] = PeerKnowledge(mask)
        self.ui.updatePeerMask(peer, mask)

    def verifyLocalChunk(self, peer, chunkNumber, remoteSum):
        assert self.mask[chunkNumber] # XXX legit exception(?)
        localSum = self.sha1sums.get(chunkNumber)
        if localSum is None:
            self.file.seek(chunkNumber * CHUNK_SIZE)
            localChunk = self.file.read(CHUNK_SIZE)
            localSum = self.sha1sums[chunkNumber] = sha.new(localChunk).digest()
        return remoteSum == localSum

    def getSize(self):
        """
        return the size of my file in bytes
        """
        self.file.seek(0, 2)
        return self.file.tell()

    def chunkReceived(self, who, chunkNumber, chunkData):
        """
        A chunk was received from the peer.
        """
        def verifyError(error):
            error.trap(VerifyError)
            self.nexus.decreaseScore(who, self.authorities)
        return self.nexus.verifyChunk(self.name,
                                      who,
                                      chunkNumber,
                                      sha.new(chunkData).digest(),
                                      self.authorities).addCallbacks(
            lambda whatever: self.chunkVerified(who, chunkNumber, chunkData),
            verifyError)

    def chunkVerified(self, who, chunkNumber, chunkData):
        """A chunk (#chunkNumber) containing the data C{chunkData} was verified, sent
        to us by the Q2QAddress C{who}.
        """
        if self.mask[chunkNumber]:
            # already received that chunk.
            return
        self.file.seek(chunkNumber * CHUNK_SIZE)
        self.file.write(chunkData)
        self.file.flush()
        self.sha1sums[chunkNumber] = sha.new(chunkData).digest()

        if not self.mask[chunkNumber]:
            self.nexus.increaseScore(who)
            self.mask[chunkNumber] = 1
            self.writeMaskFile()
            self.changes += 1

            if self.changes > self.maximumChangeCountBeforeMaskUpdate:
                self.call.cancel()
                self.sendMaskUpdate()
                self.call = self.nexus.callLater(
                    self.maximumChangeCountBeforeMaskUpdate,
                    self.maybeUpdateMask)

            if not self.seed and not self.mask.countbits(0):
                # we're done, let's let other people get at that file.
                self.file.close()
                os.rename(self.incompletePath.path,
                          self.fullPath.path)
                self.file = self.fullPath.open()
                self.maskfile.close()
                os.unlink(self.maskfile.name)

            self.ui.updateHostMask(self.mask)


    def maybeUpdateMask(self):
        if self.changes:
            self.sendMaskUpdate()
        self.call = self.nexus.callLater(
            self.maximumMaskUpdateDelayAfterChange,
            self.maybeUpdateMask)


    def selectOptimalChunk(self, peer):
        """
        select an optimal chunk to send to a peer.

        @return: int(chunkNumber), str(chunkData) if there is data to be sent,
        otherwise None, None
        """

        # stuff I have
        have = sets.Set(self.mask.positions(1))
        # stuff that this peer wants
        want = sets.Set(self.peers[peer].mask.positions(0))
        exchangeable = have.intersection(want)
        finalSet = dict.fromkeys(exchangeable, 0)

        # taking a page from bittorrent, rarest-first
        for chunkNumber in exchangeable:
            for otherPeer in self.peers.itervalues():
                finalSet[chunkNumber] += not otherPeer.mask[chunkNumber]
        rarityList = [(rarity, random.random(), chunkNumber)
                      for (chunkNumber, rarity)
                      in finalSet.iteritems()]
        if not rarityList:
            return None, None
        rarityList.sort()
        chunkNumber = rarityList[-1][-1] # sorted in ascending order of rarity

        # sanity check
        assert self.mask[chunkNumber], "I wanted to send a chunk I didn't have"

        self.file.seek(chunkNumber * CHUNK_SIZE)
        chunkData = self.file.read(CHUNK_SIZE)
        self.sha1sums[chunkNumber] = sha.new(chunkData).digest()
        return chunkNumber, chunkData


    def sendMaskUpdate(self):
        # xxx magic
        self.changes = 0
        for peer in self.peers:
            self.nexus.connectPeer(peer).addCallback(
                self._connectedPeer, peer)

    def _connectedPeer(self, proto, peer):
        knowledge = self.peers[peer]
        proto.get(self.name, self.mask)

    def peerNeedsData(self, peer):
        mask = self.peers[peer].mask
        return bool(list(mask.positions(0)))

    def putToPeers(self, peers):
        def eachPeer(proto):
            Put(name=self.name).do(proto)
            return proto

        for peer in peers:
            self.nexus.connectPeer(peer).addCallback(eachPeer)




def openReadWrite(filename):
    """
    Return a 2-tuple of: (whether the file existed before, open file object)
    """
    try:
        os.makedirs(os.path.dirname(filename))
    except OSError:
        pass
    try:
        return file(filename, 'rb+')
    except IOError:
        return file(filename, 'wb+')

def existed(fileobj):
    """
    Returns a boolean indicating whether a file opened by openReadWrite existed
    in the filesystem before it was opened.
    """
    return 'r' in getattr(fileobj, "mode", '')

def openMaskFile(filename):
    """
    Open the bitmask file sitting next to a file in the filesystem.
    """
    dirname, basename = os.path.split(filename)
    newbasename = '_%s_.sbm' % (basename,)
    maskfname = os.path.join(dirname, newbasename)
    maskfile = openReadWrite(maskfname)
    return maskfile


class SigmaServerFactory(protocol.ServerFactory):
    def __init__(self, nexus):
        self.nexus = nexus
    def buildProtocol(self, addr):
        return SigmaProtocol(True, self.nexus)

class SigmaClientFactory(protocol.ClientFactory):
    def __init__(self, nexus):
        self.nexus = nexus
    def buildProtocol(self, addr):
        return SigmaProtocol(True, self.nexus)

class BaseTransloadUI:

    def __init__(self, nexusUI, name, sender):
        self.name = name
        self.sender = sender
        self.nexusUI = nexusUI
        self.masks = {}
        self.bits = bits.BitArray()

    def updatePeerMask(self, q2qid, bits):
        self.masks[q2qid] = bits

    def updateHostMask(self, bits):
        self.bits = bits

class BaseNexusUI:

    transloadFactory = BaseTransloadUI
    receivedIntroductions = 0

    def __init__(self, basepath=os.path.expanduser("~/Sigma/Downloads")):
        self.basepath = FilePath(basepath)
        self.transloads = []

    def allocateFile(self, sharename, peer):
        """
        return a 2-tuple of incompletePath, fullPath
        """
        peerDir = self.basepath.child(str(peer))
        if not peerDir.isdir():
            peerDir.makedirs()
        return (peerDir.child(sharename+'.incomplete'),
                peerDir.child(sharename))

    def receivedIntroduction(self, peer, name):
        self.receivedIntroductions += 1

    def startTransload(self, *a, **kw):
        tl = self.transloadFactory(self, *a, **kw)
        self.transloads.append(tl)
        return tl

class Nexus(object):
    """Orchestrator & factory
    """

    def __init__(self, svc, addr, ui, callLater=None):
        """
        Create a Sigma Nexus

        @param svc: a Q2QService

        @param addr: a Q2QAddress

        @param ui: an ISigmaNexusUI implementor.

        @param callLater: a callable with the signature and semantics of
        IReactorTime.callLater
        """

        # callLater is for testing purposes.
        self.scores = {} # map q2qaddress to score
        self.transloads = {} # map filename to active transloads
        self.svc = svc
        self.addr = addr
        self.conns = conncache.ConnectionCache()
        if callLater is None:
            from twisted.internet import reactor
            callLater = reactor.callLater
        self.callLater = callLater
        self.ui = ui

        self.serverFactory = SigmaServerFactory(self)
        self.clientFactory = SigmaClientFactory(self)

        svc.listenQ2Q(addr, {PROTOCOL_NAME: self.serverFactory},
                      'Nexus device description')

    def stopService(self):
        # XXX Not really a service, but maybe it should be?  hmm.
        for transload in self.transloads.values():
            transload.stop()

    def transloadsForPeer(self, peer):
        """
        Returns an iterator of transloads that apply to a particular peer.
        """
        for tl in self.transloads.itervalues():
            if peer in tl.peers:
                yield tl

    def seed(self, path, name):
        """Create a transload from an existing file that is complete.
        """
        t = self.transloads[name] = Transload(self.addr, self, name,
                                              None, path,
                                              self.ui.startTransload(name,
                                                                     self.addr),
                                              seed=True)
        return t

    def connectPeer(self, peer):
        """Establish a SIGMA connection to the given peer.

        @param peer: a Q2QAddress of a peer which has a file that I want

        @return: a Deferred which fires a SigmaProtocol.
        """
        return self.conns.connectCached(endpoint.Q2QEndpoint(self.svc,
                                                             self.addr,
                                                             peer,
                                                             PROTOCOL_NAME),
                                        self.clientFactory)


    def push(self, fpath, name, peers):
        t = self.seed(fpath, name)
        t.putToPeers(peers)

    def pull(self, incompletePath, finalPath, name, peer):
        t = self.transloads[name] = Transload(peer, self, name,
                                              incompletePath, finalPath,
                                              self.ui.startTransload(name, peer))
        D = self.connectPeer(peer).addCallback(lambda proto: proto.get(name))
        D.addCallback(t.changeSize)
        return D

    def increaseScore(self, participant):
        """
        The participant successfully transferred a chunk to me.
        """
        if participant not in self.scores:
            self.scores[participant] = 0
        self.scores[participant] += 1


    def decreaseScore(self, participant, authorities):
        """
        Much more severe than increaseScore, this implies that the named
        participant has a broken client or is cheating.  Report them to
        authorities if they do this more than once.
        """
        self.scores[participant] -= 10


    def anyAuthority(self, authorities):
        return self.connectPeer(random.choice(authorities))

    def verifyChunk(self, name, who, chunkNumber, digest, authorities):
        return self.anyAuthority(authorities).addCallback(
            lambda authority: authority.verify(name, who, chunkNumber, digest))

