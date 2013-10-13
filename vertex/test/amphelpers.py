# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Helpers for testing AMP protocols.
"""

from twisted.protocols import amp

def callResponder(__locator, __command, **args):
    """
    Call an I{AMP} responder on a given locator,

    @param __locator: Locator on which to find responder
    @type __locator: L{amp.IResponderLocator}
    @param __command: Command to run.
    @type __command: L{amp.Command}
    """
    box = __command.makeArguments(args, None)
    d = __locator.locateResponder(__command.commandName)(box)
    d.addCallback(amp._stringsToObjects, __command.response, None)
    return d
