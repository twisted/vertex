# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
from twisted.trial import unittest
from vertex import q2qclient
import sys
from StringIO import StringIO

class TimeoutTests(unittest.TestCase):
    def test_NoUsage(self):
        """
        When the vertex Q2QClientProgram is run without any arguments, it
        should print a usage error and exit.
        """
        cp = q2qclient.Q2QClientProgram()

        # Smash stdout for the duration of the test.
        sys.stdout, realout = StringIO(), sys.stdout
        try:
            # The act of showing the help will cause a sys.exit(0), catch that
            # exception.
            self.assertRaises(SystemExit, cp.parseOptions, [])

            # Check that the usage string was (roughly) output.
            output = sys.stdout.getvalue()
            self.assertIn('Usage:', output)
            self.assertIn('Options:', output)
            self.assertIn('Commands:', output)
        finally:
            # Always restore stdout.
            sys.stdout = realout
