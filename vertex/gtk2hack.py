
import os
import rfc822

from twisted.python.filepath import FilePath

# import gtk ### pyflakes complains about this, due to the next line
import gtk.glade

from vertex.q2qclient import ClientQ2QService
from vertex.q2q import Q2QAddress

class _NullCb:
    def __init__(self, name):
        self.name = name

    def __call__(self, *a, **kw):
        print 'No callback provided for', self.name, a, kw

class _SignalAttacher:
    def __init__(self, original):
        self.original = original

    def __getitem__(self, callbackName):
        return getattr(self.original, callbackName, None) or _NullCb(callbackName)

GLADE_FILE = os.path.splitext(__file__)[0] + '.glade'

class IdentificationDialog:
    def __init__(self, clientService, plug):
        self.xml = gtk.glade.XML(GLADE_FILE, "ident_dialog")
        self.clientService = clientService
        self.xml.signal_autoconnect(_SignalAttacher(self))
        self.addressEntry = self.xml.get_widget('addressEntry')
        self.passwordEntry = self.xml.get_widget('passwordEntry')
        self.progressBar = self.xml.get_widget('identifyProgressBar')
        self.progressLabel = self.xml.get_widget('identifyProgressLabel')
        self.identifyWindow = self.xml.get_widget("ident_dialog")
        self.cancelButton = self.xml.get_widget('cancelbutton1')
        self.okButton = self.xml.get_widget('okbutton1')
        self.plug = plug

    def identifyCancel(self, event):
        self.identifyWindow.destroy()

    def identifyOK(self, event):
        idstr = self.addressEntry.get_text()
        D = self.clientService.authorize(
            Q2QAddress.fromString(idstr),
            self.passwordEntry.get_text())

        sensitiveWidgets = [self.addressEntry,
                            self.passwordEntry,
                            self.okButton,
                            self.cancelButton]
        for widget in sensitiveWidgets:
            widget.set_sensitive(False)
        self.progressLabel.set_text("Authenticating...")
        def itWorked(workedNone):
            self.identifyWindow.destroy()
            self.plug.setCurrentID(idstr)
        def itDidntWork(error):
            self.progressLabel.set_text(error.getErrorMessage())
            for widget in sensitiveWidgets:
                widget.set_sensitive(True)
        D.addCallbacks(itWorked, itDidntWork)

class AddContactDialog:
    def __init__(self, plug):
        self.xml = gtk.glade.XML(GLADE_FILE, "add_contact_dialog")
        self.xml.signal_autoconnect(_SignalAttacher(self))
        self.window = self.xml.get_widget("add_contact_dialog")
        self.window.show_all()
        self.plug = plug

    def doAddContact(self, evt):
        name = self.xml.get_widget("nameentry").get_text()
        addr = self.xml.get_widget("q2qidentry").get_text()
        self.plug.addBuddy(name, addr)
        self.popdownDialog()

    def popdownDialog(self, evt=None):
        self.window.destroy()

class AcceptConnectionDialog:
    def __init__(self, d, From, to, protocol):
        self.d = d
        self.xml = gtk.glade.XML(GLADE_FILE, "accept_connection_dialog")
        self.xml.signal_autoconnect(_SignalAttacher(self))
        self.label = self.xml.get_widget("accept_connection_label")
        self.label.set_text(
            "Accept connection from %s for %s?" % (From, protocol))
        self.window = self.xml.get_widget("accept_connection_dialog")
        self.window.show_all()

    done = False

    def destroyit(self, evt):
        self.window.destroy()

    def acceptConnectionEvt(self, evt):
        self.done = True
        print "YES"
        self.d.callback(1)
        print "WHAT"
        self.window.destroy()

    def rejectConnectionEvt(self, evt):
        print "DSTRY"
        if not self.done:
            print "DIE!"
            from twisted.python import failure
            self.d.errback(failure.Failure(KeyError("Connection rejected by user")))
        else:
            print "OK"

from twisted.internet.protocol import ServerFactory
from twisted.internet.protocol import Protocol

class VertexDemoProtocol(Protocol):

    def connectionMade(self):
        print 'CONN MADE'

    def dataReceived(self, data):
        print 'HOLY SHNIKIES', data

class VertexFactory(ServerFactory):
    protocol = VertexDemoProtocol

    def __init__(self, plug):
        self.plug = plug

    def startFactory(self):
        #self.plug.animator.stop(1)
        pass

    def stopFactory(self):
        #self.plug.animator.stop(0)
        pass


class BuddyItem:
    def __init__(self, plug, alias, q2qaddress):
        mi = self.menuItem = gtk.MenuItem(alias + " <"+q2qaddress+">")
        mi.connect("activate", self.initiateFileTransfer)
        mi.show_all()
        self.plug = plug
        self.alias = alias
        self.q2qaddress = q2qaddress
        self.plug.loadedBuddies[q2qaddress] = self

    def initiateFileTransfer(self, evt):
        print 'Initiate transfer with ' + self.alias + self.q2qaddress

    def addToMenu(self):
        self.plug.section.append(self.menuItem)

    def removeFromMenu(self):
        self.plug.section.remove(self.menuItem)

from twisted.plugin import IPlugin
from prime.iprime import IMenuApplication
from zope.interface import implements

class PlugEntry:
    implements(IMenuApplication, IPlugin)

    def __init__(self):
        self.xml = gtk.glade.XML(GLADE_FILE, "notification_popup")

    def register(self, section):
        print 'REGISTER'
        self.section = section

        workingdir = FilePath(os.path.expanduser("~/.vertex"))
        self.clientService = ClientQ2QService(
            workingdir.child("q2q-certificates").path,
            verifyHook=self.displayVerifyDialog,
            inboundTCPPortnum=8172,
            # q2qPortnum=8173,
            udpEnabled=False)
        self.setCurrentID(self.clientService.getDefaultFrom())
        self.buddiesfile = workingdir.child("q2q-buddies.txt")
        self.loadedBuddies = {}
        self.parseBuddies()

    def parseBuddies(self):
        try:
            self.buddyList = rfc822.AddressList(self.buddiesfile.open().read())
        except IOError:
            return
        self.clearContactMenu()
        for dispn, addr in self.buddyList:
            if addr not in self.loadedBuddies:
                BuddyItem(self, dispn, addr)
        self.buildContactMenu()

    def clearContactMenu(self):
        for bud in self.loadedBuddies.values():
            bud.removeFromMenu()

    def buildContactMenu(self):
        l = self.loadedBuddies.values()
        l.sort(key=lambda x: x.alias)
        l.reverse()
        for bud in l:
            bud.addToMenu()

    def addBuddy(self, alias, q2qaddr):
        temp = self.buddiesfile.temporarySibling()
        try:
            origdata = self.buddiesfile.open().read()
        except IOError:
            origdata = ''
        moredata = '\n%s <%s>' % (alias, q2qaddr)
        ftemp = temp.open('w')
        ftemp.write(origdata)
        ftemp.write(moredata)
        ftemp.close()
        temp.moveTo(self.buddiesfile)
        self.parseBuddies()

    def displayVerifyDialog(self, From, to, protocol):
        from twisted.internet import defer
        d = defer.Deferred()
        AcceptConnectionDialog(d, From, to, protocol)
        return d

    def setCurrentID(self, idName):

        if idName is not None:
            currentID = Q2QAddress.fromString(idName)
            # log in?
            # self.animator.start()
            SL = self.xml.get_widget("identifymenuitem").get_children()[0].set_label
            def loggedIn(result):
                SL(str(currentID))
                self.currentID = currentID
            def notLoggedIn(error):
                SL("Identify")
                # self.animator.stop(0)
            # This following order is INSANE - you should definitely not have
            # to wait until the LISTEN succeeds to start the service; quite the
            # opposite, you should wait until the service has started, then
            # issue the LISTEN!! For some reason, the connection drops
            # immediately if you do that, and I have no idea why.  As soon as I
            # can fix that issue the startService should be moved up previous
            # to listenQ2Q.
            self.clientService.listenQ2Q(currentID,
                                         {'vertex': VertexFactory(self)},
                                         "desktop vertex UI").addCallbacks(
                loggedIn, notLoggedIn).addCallback(
                lambda ign: self.clientService.startService())

    # XXX event handlers

    def toggleAnimate(self, event):
        if self.animator.animating:
            # SL("Animate")
            self.animator.stop()
        else:
            # SL("Stop Animating")
            self.animator.start()

    def identifyDialog(self, event):
        IdentificationDialog(self.clientService, self)

    def addContact(self, event):
        AddContactDialog(self)
