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