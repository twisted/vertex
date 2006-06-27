
from twisted.trial import unittest
from vertex import q2qclient
from twisted.python.usage import UsageError
import sys
from StringIO import StringIO

class TimeoutTestCase(unittest.TestCase):
    def testNoUsage(self):
        """
        When the vertex Q2QClientProgram is run without any arguments, it
        should print a usage error and exit.
        """
        cp = q2qclient.Q2QClientProgram()

        # smash stdout for the duration of the test.
        sys.stdout, realout = StringIO(), sys.stdout
        try:
            # the act of showing the help will cause a sys.exit(0), catch that
            # exception.
            self.assertRaises(SystemExit, cp.parseOptions, [])

            # check that the usage string was (roughly) output.
            output = sys.stdout.getvalue()
            self.assertIn('Usage:', output)
            self.assertIn('Options:', output)
            self.assertIn('Commands:', output)
        finally:
            # always restore stdout.
            sys.stdout = realout
