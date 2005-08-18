# -*- test-case-name: vertex.test.test_ptcp -*-
# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from vertex.statemachine import StateMachine, NOTHING

# States

CLOSED = 'CLOSED'
LISTEN = 'LISTEN'
SYN_RCVD = 'SYN_RCVD'
SYN_SENT = 'SYN_SENT'
ESTABLISHED = 'ESTABLISHED'
CLOSE_WAIT = 'CLOSE_WAIT'
LAST_ACK = 'LAST_ACK'
CLOSING = 'CLOSING'
FIN_WAIT_1 = 'FIN_WAIT_1'
FIN_WAIT_2 = 'FIN_WAIT_2'
TIME_WAIT = 'TIME_WAIT'

# Network vocabulary
SYN = 'SYN'
ACK = 'ACK'
SYN_ACK = 'SYN_ACK'
FIN = 'FIN'
RST = 'RST'

# Application vocabulary
APP_PASSIVE_OPEN = 'PASSIVE_OPEN'
APP_ACTIVE_OPEN = 'ACTIVE_OPEN'
APP_SEND_DATA = 'APP_SEND'
TIMEOUT = 'TIMEOUT'
APP_CLOSE = 'APP_CLOSE'

# This isn't detailed by the spec in the diagram, so we use a different
# identifier, but in various places it does make references to going straight
# to the 'closed' state.
BROKEN = 'CLOSED'


class TCP(StateMachine):
    # dict, mapping state to dict of input: (output, new-state)

    states = {
        CLOSED: {
            APP_PASSIVE_OPEN: (NOTHING, LISTEN),
            APP_ACTIVE_OPEN: (SYN, SYN_SENT),
            },
        SYN_SENT: {
            TIMEOUT: (NOTHING, CLOSED),
            APP_CLOSE: (NOTHING, CLOSED),
            SYN_ACK: (ACK, ESTABLISHED),
            # SYN: (SYN_ACK, SYN_RCVD),
            },
        SYN_RCVD: {
            ACK: (NOTHING, ESTABLISHED),
            APP_CLOSE: (FIN, FIN_WAIT_1),
            TIMEOUT: (RST, CLOSED),
            RST: (NOTHING, LISTEN),
            },
        LISTEN: {
            APP_SEND_DATA: (SYN, SYN_SENT),
            SYN: (SYN_ACK, SYN_RCVD),
            },
        ESTABLISHED: {
            APP_CLOSE: (FIN, FIN_WAIT_1),
            FIN: (ACK, CLOSE_WAIT),
            TIMEOUT: (NOTHING, BROKEN),
            },
        CLOSE_WAIT: {
            APP_CLOSE: (FIN, LAST_ACK),
            TIMEOUT: (NOTHING, BROKEN),
            },
        LAST_ACK:  {
            ACK: (NOTHING, CLOSED),
            TIMEOUT: (NOTHING, BROKEN),
            },
        FIN_WAIT_1: {
            ACK: (NOTHING, FIN_WAIT_2),
            FIN: (ACK, CLOSING),
            # FIN_ACK: (ACK, TIME_WAIT),
            TIMEOUT: (NOTHING, BROKEN),
            },
        FIN_WAIT_2: {
            TIMEOUT: (NOTHING, BROKEN),
            FIN: (ACK, TIME_WAIT),
            },
        CLOSING: {
            TIMEOUT: (NOTHING, BROKEN),
            ACK: (NOTHING, TIME_WAIT),
            },
        TIME_WAIT: {
            TIMEOUT: (NOTHING, CLOSED),
            },
        }

    initialState = CLOSED
