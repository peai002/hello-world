#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May  8 10:37:56 2018

@author: PEAI002


"""
from os import urandom

#------------------------------- MT19937 --------------------------------

class MT19937():
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    f = 1812433253

    def __init__(self, seed):
        x = [seed]
        for i in range(1, self.n):
            t = x[i-1]
            t = self.f*(t ^ (t >> (self.w-2))) + i
            x.append(int(self.lower(t, self.w), 2))
        self.vector = x
        self.update()
        self.counter = 0

    def upper(self, x):
        '''takes integer, returns upper w-r bits'''
        w, r = self.w, self.r
        return format(x, '0%sb'%w)[:w-r]

    def lower(self, x, r):
        '''takes integer, returns lower r bits'''
        return format(x, '0%sb'%self.w)[-r:]

    def concatenate(self, x, y):
        '''concatenates two bit-strings, returns int'''
        return int(x + y, 2)

    def twist_transform(self, x):
        if format(x, 'b')[-1:] == '0':
            return x >> 1
        else:
            return (x >> 1) ^ self.a

    def update(self):
        '''regenerates the underlying vector using recurrence relation'''
        x = self.vector
        m, r, n = self.m, self.r, self.n
        for k in range(len(x)):
            temp = x[m+k] ^ self.twist_transform(self.concatenate(
                    self.upper(x[k]), self.lower(x[k+1], r)))
            x.append(temp)
        self.vector = x[-n:]

    def tempering_transform(i, x):
        b, c, d, l, s, t, u = i.b, i.c, i.d, i.l, i.s, i.t, i.u
        y = x ^ ((x >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        return y ^ (y >> l)

    def generate(self):
        if self.counter == self.n:
            self.update()
            self.counter = 0
        else:
            temp = self.vector[self.counter]
            self.counter += 1
            return self.tempering_transform(temp)



def untemper_transform(x):
    u = 11
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18

    def reverse_offset_xor_and(bitstring, offset, mask):
        ''' offset and mask are both integers'''
        ans = bitstring[-offset:]
        bitstring = bitstring[:-offset]
        mask = format(mask, '032b')[:-offset]

        for i in range(1, len(bitstring)+1):
            ans = str((int(ans[-i]) & int(mask[-i])) ^ int(bitstring[-i])) + ans

        return ans

    def reverse_offset_xor(bitstring, offset):
        ans = bitstring[: offset]
        bitstring = bitstring[offset:]
        for i in range(len(bitstring)):
            ans += str(int(bitstring[i]) ^ int(ans[i]))
        return ans

    x = format(x, '032b')
    y = reverse_offset_xor(x, l)
    y = reverse_offset_xor_and(y, t, c)
    y = reverse_offset_xor_and(y, s, b)
    y = reverse_offset_xor(y, u)

    return int(y, 2)

def main():
    rand_seed = int.from_bytes(urandom(5), 'little')
    rng = MT19937(rand_seed)
    internal_state = []
    for i in range(624):
        x = untemper_transform(rng.generate())
        internal_state.append(x)

    cloned_rng = MT19937(0)
    cloned_rng.vector = internal_state
    cloned_rng.counter = 624

    print(cloned_rng.generate() == rng.generate())

if __name__ == '__main__':
    main()
