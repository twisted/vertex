# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Exceptions and errors for use in L{vertex} modules.
"""

class ConnectionError(Exception):
    pass

class AttemptsFailed(ConnectionError):
    pass

class NoAttemptsMade(ConnectionError):
    pass

class VerifyError(Exception):
    pass

class BadCertificateRequest(VerifyError):
    pass


__all__ = [
        'ConnectionError', 'AttemptsFailed', 'NoAttemptsMade',
        'VerifyError', 'BadCertificateRequest',
        ]
