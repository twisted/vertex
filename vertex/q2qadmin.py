# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from epsilon import juice

class NotAllowed(Exception):
    pass

class AddUser(juice.Command):
    """
    Add a user to a domain.
    """
    commandName = "add_user"

    arguments = [
        ("name", juice.String()),
        ("password", juice.String())
        ]

    response = []

    errors = {NotAllowed: "NotAllowed"}
