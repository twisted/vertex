# Copyright 2005 Divmod, Inc.  See LICENSE file for details

import sys

from twisted.python import usage

from vertex import sslverify

class Options(usage.Options):
    optParameters = [
        ["country", "C", "US", None],
        ["state", "s", "New York", None],
        ["city", "c", "New York", None],
        ["organization", "o", "Divmod LLC", None],
        ["unit", "u", "Security", None],
        ["hostname", "h", "divmod.com", None],
        ["email", "e", "support@divmod.org", None],

        ["filename", "f", "server.pem", "Name of the file to which to write the PEM."],
        ["serial-number", "S", 1, None],
    ]

def createSSLCertificate(opts):
    sslopt = {}
    for x, y in (('country','C'),
                 ('state', 'ST'),
                 ('city', 'L'),
                 ('organization', 'O'),
                 ('unit', 'OU'),
                 ('hostname', 'CN'),
                 ('email','emailAddress')):
        sslopt[y] = opts[x]
    serialNumber = int(opts['serial-number'])
    ssc = sslverify.KeyPair.generate().selfSignedCert(serialNumber, **sslopt)
    file(opts['filename'], 'w').write(ssc.dumpPEM())
    print 'Wrote SSL certificate:'
    print ssc.inspect()
    return ssc

def main(args=None):
    """
    Create a private key and a certificate and write them to a file.
    """
    if args is None:
        args = sys.argv[1:]

    o = Options()
    try:
        o.parseOptions(args)
    except usage.UsageError, e:
        raise SystemExit(str(e))
    else:
        return createSSLCertificate(o)
