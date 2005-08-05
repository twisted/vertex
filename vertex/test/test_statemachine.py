
from twisted.trial import unittest

from vertex import statemachine

S_1, S_2 = 'S_1', 'S_2'
I_1, I_2 = 'I_1', 'I_2'
O_1, O_2 = 'O_1', 'O_2'

class TestMachine(statemachine.StateMachine):
    states = {
        S_1: {
            I_1: (O_1, S_1),
            I_2: (O_1, S_2),
            },
        S_2: {
            I_1: (O_2, S_2),
            I_2: (O_1, S_2),
            },
        }

    initialState = S_1

    def _event(self, name):
        def method():
            self.events.append(name)
        return method

    def __getattr__(self, name):
        if (name.startswith('exit_') or name.startswith('enter_') or
            name.startswith('transition_') or name.startswith('output_')):
            return self._event(name)
        raise AttributeError(name)

class Transitions(unittest.TestCase):
    def testOutput(self):
        m = TestMachine()

        self.assertEquals(m.state, S_1)

        m.events = []
        m.input(I_1)
        self.assertEquals(
            m.events,
            ['output_O_1'])
        self.assertEquals(m.state, S_1)

        m.events = []
        m.input(I_2)
        self.assertEquals(
            m.events,
            ['exit_S_1', 'enter_S_2', 'transition_S_1_to_S_2', 'output_O_1'])
        self.assertEquals(m.state, S_2)

        m.events = []
        m.input(I_1)
        self.assertEquals(
            m.events,
            ['output_O_2'])
        self.assertEquals(m.state, S_2)

        m.events = []
        m.input(I_2)
        self.assertEquals(
            m.events,
            ['output_O_1'])
        self.assertEquals(m.state, S_2)
