# Copyright 2005 Divmod, Inc.  See LICENSE file for details
# -*- test-case-name: vertex.test.test_bits -*-
""" The purpose of this module is to provide the class BitArray, a compact
overlay onto an array of bytes which is instead bit-addressable.  It also
includes several bitwise operators.

It does not include all array operations yet, most notably those related to
slicing, since it is written primarily for use by the swarming implementation
and swarming only requires fixed-size bit masks.

"""

__metaclass__ = type

import array
import operator
import math

BITS_PER_BYTE = 8

def operate(operation):
    # XXX TODO: optimize this and countbits later
    def __x__(self, other):
        if len(self) < len(other):
            return operation(other, self)
        new = BitArray(size=len(self))
        for offt, (mybit, hisbit) in enumerate(zip(self, other)):
            result = new[offt] = operation(mybit, hisbit)

        for j in range(offt+1, len(self)):
            new[j] = operation(self[j], 0)
        return new
    return __x__


class BitArray:
    """
    A large mutable array of bits.
    """

    def __init__(self, bytes=None, size=None, default=0):
        if bytes is None and size is None:
            size = 0
        if bytes is None:
            bytes = array.array("B")
            bytesize = int(math.ceil(float(size) / BITS_PER_BYTE))
            if default:
                padbyte = 255
            else:
                padbyte = 0
            bytes.fromlist([padbyte] * bytesize)
        self.bytes = bytes
        if size is None:
            size = len(self.bytes) * self.bytes.itemsize * BITS_PER_BYTE
        self.size = size

        # initialize 'on' and 'off' lists to optimize various things
        self.on = []
        self.off = []
        blists = self.blists = self.off, self.on

        for index, bit in enumerate(self):
            blists[bit].append(index)

    def append(self, bit):
        offt = self.size
        self.size += 1
        if (len(self.bytes) * self.bytes.itemsize * BITS_PER_BYTE) < self.size:
            self.bytes.append(0)
        self[offt] = bit

    def any(self, req=1):
        return bool(self.blists[req])

    def percent(self):
        """
        debugging method; returns a string indicating percentage completion
        """
        if not len(self):
            return 'Inf%'
        return '%0.2f%%'% ((float(self.countbits()) / len(self)) * 100,)

    def __getitem__(self, bitcount):
        if bitcount < 0:
            bitcount += self.size
        if bitcount >= self.size:
            raise IndexError("%r >= %r" % (bitcount, self.size))
        div, mod = divmod(bitcount, self.bytes.itemsize * BITS_PER_BYTE)
        byte = self.bytes[div]
        return (byte >> mod) & 1

    def __setitem__(self, bitcount, bit):
        if bitcount < 0:
            bitcount += self.size
        if bitcount >= self.size:
            raise IndexError("bitcount too big")
        div, mod = divmod(bitcount, self.bytes.itemsize * BITS_PER_BYTE)
        if bit:
            self.bytes[div] |= 1 << mod
        else:
            self.bytes[div] &= ~(1 << mod)

        # change updating
        notbitlist = self.blists[not bit]
        try:
            notbitlist.remove(bitcount)
        except ValueError:
            pass
        bitlist = self.blists[bit]
        if bitcount not in bitlist:
            bitlist.append(bitcount)

    def __len__(self):
        return self.size

    def __repr__(self):
        l = []
        l.append('[')
        for b in self:
            if b:
                c = 'X'
            else:
                c = ' '
            l.append(c)
        l.append(']')
        return ''.join(l)

    def countbits(self, on=True):
        return len(self.blists[on])

    def positions(self, bit):
        """
        An iterator of all positions that a bit holds in this BitArray.

        @param bit: 1 or 0
        """
        return self.blists[bit][:]

    __xor__ = operate(operator.xor)
    __and__ = operate(operator.and_)
    __or__ = operate(operator.or_)

