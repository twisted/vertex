# -*- test-case-name: vertex.test -*-

from vertex._version import __version__
from twisted.python import versions


def asTwistedVersion(packageName, versionString):
    return versions.Version(packageName, *map(int, versionString.split(".")))

version = asTwistedVersion("vertex", __version__)
__all__ = ['version']
