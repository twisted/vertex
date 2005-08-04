# -*- test-case-name: vertex.test.test_statemachine -*-

NOTHING = 'nothing'             # be quiet (no output)

class StateMachine:

    initialState = None         # a str describing initial state

    states = None     # dict, mapping state to dict of str input: (str output,
                      # str new-state)


    def __init__(self, initialState=None):
        if initialState is None:
            initialState = self.initialState
        self.state = self.initialState

    def transition(self, oldstate, newstate, datum, *a, **kw):
        exitmeth = getattr(self, 'exit_%s' % (oldstate,), None)
        entermeth = getattr(self, 'enter_%s' % (newstate,), None)
        transmeth = getattr(self, 'transition_%s_to_%s' % (
                oldstate.upper(), newstate.upper()), None)
        for meth in exitmeth, entermeth, transmeth:
            if meth is not None:
                meth(*a, **kw)
        self.state = newstate

    def input(self, datum, *a, **kw):
        oldstate = self.state
        if datum == NOTHING:
            return
        output, newstate = self.states[self.state][datum]
        OLDSTATE = self.state
        NEWSTATE = newstate.upper()
        DATUM = datum.upper()
        self.transition(OLDSTATE, NEWSTATE, DATUM, *a, **kw)
        self.output(output, *a, **kw)

    def output(self, datum, *a, **kw):
        foo = getattr(self, 'output_' + datum.upper(), None)
        if foo is not None:
            foo(*a, **kw)
