
import os

import pygtk
pygtk.require("2.0")
from twisted.internet import gtk2reactor
gtk2reactor.install()

from twisted.internet import reactor
from twisted.internet.task import LoopingCall

import gtk
import gtk.glade
import egg.trayicon

from vertex.q2qclient import ClientQ2QService
from vertex.q2q import Q2QAddress

class IconAnimator:
    lc = None
    def __init__(self, box, icons):
        self.box = box
        self.icons = icons
        for icon in icons:
            icon.show()
        self.stop()

    def tick(self):
        self.position += 1
        self.position %= len(self.icons)
        c = self.box.get_children()
        if c:
            self.box.remove(c[0])
        self.box.add(self.icons[self.position])

    def start(self):
        self.animating = True
        self.tick()
        self.lc = LoopingCall(self.tick)
        self.lc.start(1.0)

    def stop(self, index=0):
        self.animating = False
        self.position = index - 1
        self.tick()
        if self.lc is not None:
            self.lc.stop()
            self.lc = None


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
    def __init__(self, clientService, notification):
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
        self.notification = notification

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
            self.notification.setCurrentID(idstr)
        def itDidntWork(error):
            self.progressLabel.set_text(error.getErrorMessage())
            for widget in sensitiveWidgets:
                widget.set_sensitive(True)
        D.addCallbacks(itWorked, itDidntWork)

from twisted.internet.protocol import ServerFactory

class VertexFactory(ServerFactory):

    def __init__(self, notification):
        self.notification = notification

    def startFactory(self):
        self.notification.animator.stop(1)

    def stopFactory(self):
        self.notification.animator.stop(0)



class NotificationEntry:
    def __init__(self):
        self.xml = gtk.glade.XML(GLADE_FILE, "notification_popup")
        icon = egg.trayicon.TrayIcon("Vertex")
        eventbox = gtk.EventBox()
        icon.add(eventbox)
        icon.show_all()

        self.animateItem = self.xml.get_widget("animate")

#         [gtk.image_new_from_icon_name(name, gtk.ICON_SIZE_SMALL_TOOLBAR)
#          for name in ['gnome-mime-text-x-python', 'xchat']]

        icons = [
            gtk.image_new_from_stock(name, gtk.ICON_SIZE_SMALL_TOOLBAR)
            for name in gtk.STOCK_NO, gtk.STOCK_YES
            ]

        self.animator = IconAnimator(eventbox, icons)
        self.xml.signal_autoconnect(_SignalAttacher(self))
        self.menu = self.xml.get_widget("notification_popup")

        self.contactsStart = self.menu.get_children().index(
            self.xml.get_widget("contacts_begin"))

        eventbox.connect('button_press_event', self.popupMenu)
        self.clientService = ClientQ2QService(os.path.expanduser(
                "~/.vertex/q2q-certificates"))

        self.setCurrentID(self.clientService.getDefaultFrom())

    def setCurrentID(self, idName):

        if idName is not None:
            currentID = Q2QAddress.fromString(idName)
            # log in?
            self.animator.start()
            SL = self.xml.get_widget("identifymenuitem").get_children()[0].set_label
            def loggedIn(result):
                SL(str(currentID))
                self.currentID = currentID
            def notLoggedIn(error):
                SL("Identify")
                self.animator.stop(0)
            self.clientService.listenQ2Q(currentID,
                                         {'vertex': VertexFactory(self)},
                                         "desktop vertex UI").addCallbacks(
                loggedIn, notLoggedIn)

    # XXX event handlers

    def toggleAnimate(self, event):
        SL = self.animateItem.get_children()[0].set_label
        if self.animator.animating:
            SL("Animate")
            self.animator.stop()
        else:
            SL("Stop Animating")
            self.animator.start()

    def identifyDialog(self, event):
        IdentificationDialog(self.clientService, self)

    def addContact(self, event):
        mi = gtk.MenuItem("Dummy Contact")
        mi.show_all()
        self.menu.insert(mi, self.contactsStart + 1)

    def popupMenu(self, box, event):
        self.menu.popup(None, None, None, event.button, event.get_time())

    def quit(self, event):
        reactor.stop()


def main():
    import gnome
    gnome.program_init("Vertex", "0.1")
    global ne
    ne = NotificationEntry()
    reactor.run()
