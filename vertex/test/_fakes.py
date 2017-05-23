# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
Verified fakes used across tests.
"""
from pretend import stub, call, call_recorder
from twisted.internet import defer
from twisted.trial import unittest
import txscrypt



def _makeStubTxscrypt(computeKeyReturns, checkPasswordReturns):
    """
    Construct a stub L{txscrypt} implementation.

    @param computeKeyReturns: What C{computeKey} should return.

    @param checkPasswordReturns: What C{checkPassword} should return.

    @return: A L{stub} implementation of L{txscrypt}
    @rtype: L{stub}
    """

    def computeKey(password):
        return computeKeyReturns


    def checkPassword(key, password):
        return checkPasswordReturns

    return stub(computeKey=call_recorder(computeKey),
                checkPassword=call_recorder(checkPassword))



def _makeStubCredentials(username, password, checkPasswordReturns):
    """
    Construct a stub L{IUsernamePassword} implementer.

    @param username: The username.
    @type username: L{str}

    @param password: The password.
    @type password: L{str}

    @param checkPasswordReturns: What C{checkPassword} should return.

    @return: A L{stub} implementation of
        L{twisted.python.cred.credentials.UsernamePassword}
    @rtype: L{stub}
    """

    def checkPassword(password):
        return checkPasswordReturns

    return stub(username=username,
                password=password,
                checkPassword=call_recorder(checkPassword))



def _makeStubIQ2QUserStore(storeReturns, keyReturns):
    """
    Construct a stub L{vertex.ivertex.IQ2QUserStore} implementer.

    @param storeReturns: What C{store} returns.

    @param keyReturns: What C{key} returns.

    @return: A L{stub} implementation of
        L{vertex.ivertex.IQ2QUserStore}
    @rtype: L{stub}
    """

    def store(domain, username, password):
        return storeReturns


    def key(domain, username):
        return keyReturns

    return stub(store=call_recorder(store), key=call_recorder(key))



class VerifyStubTxscrypt(unittest.TestCase):
    """
    Test that the stub returned by L{_makeStubTxscrypt} behaves the
    same as L{txscrypt}.
    """

    def setUp(self):
        """
        Setup the test.
        """
        self.computeKeyReturns = defer.Deferred()
        self.checkPasswordReturns = defer.Deferred()

        self.fakeTxscrypt = _makeStubTxscrypt(
            computeKeyReturns=self.computeKeyReturns,
            checkPasswordReturns=self.checkPasswordReturns,
        )


    @defer.inlineCallbacks
    def test_computeKey(self):
        """
        The stub key computer accepts the same arguments as the real
        key computer, both return a L{defer.Deferred} that fires with
        the computed key.
        """
        password = "password"
        realKey = yield txscrypt.computeKey(password)

        self.computeKeyReturns.callback(realKey)
        fakeKey = yield self.fakeTxscrypt.computeKey(password)

        self.assertEqual(realKey, fakeKey)
        self.assertEqual(self.fakeTxscrypt.computeKey.calls, [call(password)])


    @defer.inlineCallbacks
    def compareCheckPassword(self, keyPassword, password):
        """
        Assert that L{txscrypt.checkPassword} and the stub
        C{checkPassword} agree that C{password} matches or does not
        match the key derived from C{keyPassword}.

        @param keyPassword: The password from which to derive a key.
        @type keyPassword: L{str}

        @param password: The password to check against the derived
            key.
        @type password: L{str}

        @return: A L{defer.Deferred} that fires when the results have
            been compared.
        @rtype: L{defer.Deferred}
        """
        key = yield txscrypt.computeKey(keyPassword)

        realResult = yield txscrypt.checkPassword(key, password)

        self.checkPasswordReturns.callback(realResult)
        fakeResult = yield self.fakeTxscrypt.checkPassword(key, password)

        self.assertEqual(realResult, fakeResult)
        self.assertEqual(
            self.fakeTxscrypt.checkPassword.calls,
            [call(key, password)],
        )


    def test_checkPasswordMatches(self):
        """
        The stub password checker accepts the same arguments as the
        real password checker, and both return a L{defer.Deferred} that
        fires with L{True} when the the password matches the key.
        """
        return self.compareCheckPassword(keyPassword="password",
                                         password="password")


    def test_checkPassword_doesNotMatch(self):
        """
        The stub password checker accepts the same arguments as the
        real password checker, and both return a L{defer.Deferred} that
        fires with L{False} when the the password does not match the
        key.
        """
        return self.compareCheckPassword(keyPassword="password",
                                         password="wrong password")
