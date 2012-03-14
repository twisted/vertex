# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from twisted.protocols.amp import Command, String

class NotAllowed(Exception):
    pass

class AddUser(Command):
    """
    Add a user to a domain.
    """
    commandName = "add_user"

    arguments = [
        ("name", String()),
        ("password", String())
        ]

    response = []

    errors = {NotAllowed: "NotAllowed"}
