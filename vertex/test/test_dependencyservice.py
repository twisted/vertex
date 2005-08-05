# Copyright 2005 Divmod, Inc.  See LICENSE file for details
from twisted.trial import unittest

from vertex import depserv


class Serv(depserv.DependencyService):
    requiredServices = ['one']

    def __init__(self, **kw):
        self.initialized = []
        depserv.DependencyService.__init__(self, **kw)

    def setup_ONE(self):
        self.initialized.append('ONE')

    def setup_TWO(self):
        self.initialized.append('TWO')

    def setup_THREE(self):
        self.initialized.append('THREE')


class TestDependencyService(unittest.TestCase):

    def test_depends(self):
        class One(Serv):
            def depends_TWO(self):
                return ['three']

        class Two(Serv):
            def depends_THREE(self):
                return ['two']

        args = dict(one={}, two={}, three={})

        one = One(**args)
        self.assert_(one.initialized == ['ONE', 'THREE', 'TWO'])

        two = Two(**args)
        self.assert_(two.initialized == ['ONE', 'TWO', 'THREE'])


    def test_circularDepends(self):
        class One(Serv):
            def depends_THREE(self):
                return ['two']
            def depends_TWO(self):
                return ['three']
        try:
            One(one={}, two={}, three={})
        except depserv.StartupError:
            pass
        else:
            raise unittest.FailTest, 'circular dependencies did not raise an error'


    def test_requiredWithDependency(self):
        """A service is required but has dependencies"""

        class One(Serv):
            def depends_ONE(self):
                return ['three']
        try:
            One(one={}, two={}, three={})
        except depserv.StartupError:
            pass
        else:
            raise unittest.FailTest, 'unsatisfied dependencies did not raise an error'
