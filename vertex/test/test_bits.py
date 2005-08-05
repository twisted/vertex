# Copyright 2005 Divmod, Inc.  See LICENSE file for details

import array
from vertex.bits import BitArray

from twisted.trial import unittest

bitResult = [
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2,
    3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3,
    3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3,
    4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4,
    3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5,
    6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4,
    4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5,
    6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 3,
    4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6,
    6, 7, 6, 7, 7, 8 ]



class BitArrayTest(unittest.TestCase):

    def testBasicBits(self):
        prev = BitArray(size=3)
        prev[0] = 1
        prev[1] = 1
        prev[2] = 1
        for size in (5, 6, 8, 12, 14, 15):
            ba = BitArray(size=size)
            ba[0] = 1
            ba[2] = 1
            ba[-1] = 1
            assert ba.countbits() == 3, str(ba.countbits())
            xo = (prev ^ ba)
            cb = xo.countbits()
            assert cb == 2, cb
            prev = ba

    def testPositions(self):
        SIZE = 25
        bitz = BitArray(size=SIZE)
        self.assertEquals(list(bitz.positions(0)), range(SIZE))
        self.assertEquals(list(bitz.positions(1)), [])
        rs = range(SIZE)
        rs.remove(7)
        bitz[7] = 1
        self.assertEquals(list(bitz.positions(0)), rs)
        self.assertEquals(list(bitz.positions(1)), [7])

    def testDefaultBit(self):
        a = BitArray(size=100, default=0)
        b = BitArray(size=100, default=1)
        self.assertEquals(list(a), [0] * 100)
        self.assertEquals(list(b), [1] * 100)

    def testCalculateOnBits(self):
        calc = []
        for x in range(256):
            c = 0
            a = array.array('B')
            a.append(x)
            for n in BitArray(a):
                c += n
            calc.append(c)
        self.assertEquals(calc, bitResult)

