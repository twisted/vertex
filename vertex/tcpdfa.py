# Copyright 2005 Divmod, Inc.  See LICENSE file for details

from vertex.statemachine import StateMachine, NOTHING

# States

CLOSED = 'closed'
LISTEN = 'listen'
SYN_RCVD = 'syn_rcvd'
SYN_SENT = 'syn_sent'
ESTABLISHED = 'established'
CLOSE_WAIT = 'close_wait'
LAST_ACK = 'last_ack'
CLOSING = 'closing'
FIN_WAIT_1 = 'fin_wait_1'
FIN_WAIT_2 = 'fin_wait_2'
TIME_WAIT = 'time_wait'

# Network vocabulary
SYN = 'syn'
ACK = 'ack'
SYN_ACK = 'syn_ack'
FIN = 'fin'
FIN_ACK = 'fin_ack'
RST = 'rst'

# Application vocabulary
APP_PASSIVE_OPEN = 'passive_open'
APP_ACTIVE_OPEN = 'active_open'
APP_SEND_DATA = 'app_send'
TIMEOUT = 'timeout'
APP_CLOSE = 'app_close'

# My own vocabulary:
BROKEN = 'broken'


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
            SYN: (SYN_ACK, SYN_RCVD),
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
            ACK: (NOTHING, ESTABLISHED),
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
            FIN_ACK: (ACK, TIME_WAIT),
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
            TIMEOUT: (NOTHING, CLOSED)
            },
        }

    initialState = CLOSED
