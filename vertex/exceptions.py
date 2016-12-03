# -*- test-case-name: vertex.test.test_q2q -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
All exception types defined for Vertex.
"""

class ConnectionError(Exception):
    """
    An error occurred trying to establish a connection.
    """



class AttemptsFailed(ConnectionError):
    """
    All attempts to establish a connection have failed.
    """



class NoAttemptsMade(ConnectionError):
    """
    No viable connection paths were found so no attempts to connect were made.
    """



class VerifyError(Exception):
    """
    An error occurred while verifying or authenticating a certificate.
    """



class BadCertificateRequest(VerifyError):
    """
    The given certificate request could not be signed because of a problem with
    either it or the party it was sent to.
    """
