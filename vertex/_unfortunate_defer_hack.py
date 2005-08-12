

from twisted.internet.defer import Deferred
try:
    from twisted.internet.defer import FirstError
except:
    class FirstError(Exception):
        """omgwtf
        """
from twisted.python import failure

class NoFailure(Exception):
    """ This is a placeholder exception used by DeferredList to indicate that there
    is not actually a failure.
    """

class DeferredList(Deferred):
    """I combine a group of deferreds into one callback.

    I track a list of L{Deferred}s for their callbacks, and make a single
    callback when they have all completed, a list of (success, result)
    tuples, 'success' being a boolean.

    Note that you can still use a L{Deferred} after putting it in a
    DeferredList.  For example, you can suppress 'Unhandled error in Deferred'
    messages by adding errbacks to the Deferreds *after* putting them in the
    DeferredList, as a DeferredList won't swallow the errors.  (Although a more
    convenient way to do this is simply to set the consumeErrors flag)
    """

    fireOnOneCallback = 0
    fireOnOneErrback = 0

    def __init__(self, deferredList, fireOnOneCallback=0, fireOnOneErrback=0,
                 consumeErrors=0):
        """Initialize a DeferredList.

        @type deferredList:  C{list} of L{Deferred}s
        @param deferredList: The list of deferreds to track.
        @param fireOnOneCallback: (keyword param) a flag indicating that
                             only one callback needs to be fired for me to call
                             my callback
        @param fireOnOneErrback: (keyword param) a flag indicating that
                            only one errback needs to be fired for me to call
                            my errback
        @param consumeErrors: (keyword param) a flag indicating that any errors
                            raised in the original deferreds should be
                            consumed by this DeferredList.  This is useful to
                            prevent spurious warnings being logged.
        """
        self.resultList = [None] * len(deferredList)
        Deferred.__init__(self)
        if len(deferredList) == 0 and not fireOnOneCallback:
            self.callback(self.resultList)

        # These flags need to be set *before* attaching callbacks to the
        # deferreds, because the callbacks use these flags, and will run
        # synchronously if any of the deferreds are already fired.
        self.fireOnOneCallback = fireOnOneCallback
        self.fireOnOneErrback = fireOnOneErrback
        self.consumeErrors = consumeErrors
        self.finishedCount = 0

        index = 0
        for deferred in deferredList:
            deferred.addCallbacks(self._cbDeferred, self._cbDeferred,
                                  callbackArgs=(index,SUCCESS),
                                  errbackArgs=(index,FAILURE))
            index = index + 1

    def _cbDeferred(self, result, index, succeeded):
        """(internal) Callback for when one of my deferreds fires.
        """
        self.resultList[index] = (succeeded, result)

        self.finishedCount += 1
        if not self.called:
            if succeeded == SUCCESS and self.fireOnOneCallback:
                # build a convincing list:
                for rli in xrange(len(self.resultList)):
                    if self.resultList[rli] is None:
                        self.resultList[rli] = (0, failure.Failure(NoFailure()))
                self.callback(self.resultList)
            elif succeeded == FAILURE and self.fireOnOneErrback:
                self.errback(failure.Failure(FirstError(result, index)))
            elif self.finishedCount == len(self.resultList):
                self.callback(self.resultList)

        if succeeded == FAILURE and self.consumeErrors:
            result = None

        return result

# Constants for use with DeferredList

SUCCESS = True
FAILURE = False




