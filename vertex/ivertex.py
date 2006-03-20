# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from zope.interface import Interface

class IQ2QTransport(Interface):
    """
    I am a byte-stream-oriented transport which has Q2Q identifiers associated
    with the endpoints, and possibly some cryptographic verification of the
    authenticity of those endpoints.
    """

    def getQ2QHost():
        """ Returns a Q2QAddress object representing the user on this end of the
        connection.
        """

    def getQ2QPeer():
        """ Returns a Q2QAddress object representing the user on the other end of the
        connection.
        """

class IQ2QUser(Interface):
    """
    A cred interface for Q2Q users.
    """
    def signCertificateRequest(certificateRequest, domainCert, suggestedSerial):
        """
        Return a signed certificate object if the subject fields in the
        certificateRequest are valid.
        """

class IFileTransfer(Interface):

    def getUploadSink(self, path):
        """
        @param path: a PathFragment that the client wishes to upload to.

        @return: a DataSink where we'll save the data to.
        """

    def getDownloadSource(self, path):
        """
        @param path: a PathFragment that the client wishes to download.

        @return: a DataSource to download data from.
        """

    def listChildren(self, path):
        """
        @param path: a PathFragment that the client wishes to get a list of.

        @return: a list of dictionaries mapping::
            {'name': str,
             'size': int,
             'type': vertex.filexfer.MIMEType,
             'modified': epsilon.extime.Time}
        """

class ISessionTokenStorage(Interface):
    def idFromCookie(self, cookie, domain):
        """Look up a user ID from the given cookie in the given domain.
        """

class ICertificateStorage(Interface):
    def getSelfSignedCertificate(self, domainName):
        """
        @return: a Deferred which will fire with the certificate for the given
        domain name.
        """

    def storeSelfSignedCertificate(self, domainName, mainCert):
        """
        @type mainCert: C{str}
        @param mainCert: Serialized, self-signed certificate to associate
        with the given domain.

        @return: a Deferred which will fire when the certificate has been
        stored successfully.
        """

    def getPrivateCertificate(self, domainName):
        """
        @return: a PrivateCertificate instance, e.g. a certificate including a
        private key, for 'domainName'.
        """

    def addPrivateCertificate(self, domainName, existingCertificate=None):
        """
        """

class IOfferUp(Interface):
    """
    Sharing control database storage.
    """

class IPlugin(Interface):
    """
    """

class ITestPlugin(Interface):
    """
    Dummy plug-in interface for unit testing.
    """

class ITestPlugin2(Interface):
    """
    Dummy plug-in interface for unit testing.
    """
