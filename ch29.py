#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 18 10:16:29 2018

@author: PEAI002
"""
from hashlib import sha1
from os import urandom

class sha_attack:
    def __init__(self):
        self.initialisation = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                               0xC3D2E1F0]

    def pad(self, message, padded=True):
        '''returns padded message. set padded to False to return padding only'''
        #message length in bits
        ml = 8*len(message)

        # Pre-processing:
        k = -(9 + len(message)) % 64
        padding = b'\x80' + b'\x00'*k + int.to_bytes(ml, 8, 'big')
        if padded == True:
            padding = message + padding
        return padding

    def digest(self, message, padding=True):
        '''takes a message (plaintext string, length <= 2**64) and
        applies sha_1.'''
        if padding == True:
            message = self.pad(message)

        # from the pseudocode on wikipedia
        if len(message) > 2**64:
            raise Exception('message length should be 2**64 or less')
        if type(message) != bytes:
            if type(message) == str:
                message = message.encode()
            else:
                raise TypeError('message should be a str or bytes')

        def left_rotate(word, offset):
            n = 32
            left = (word  << offset) & (2**n - 1)
            right = word >> (n - offset)
            return right^left

        #initialising
        h0, h1, h2, h3, h4 = self.initialisation


        # processing:
        while len(message) > 0:
            chunk = message[:64]
            message = message[64:]
            w = []
            while len(chunk) > 0:
                w.append(int.from_bytes(chunk[:4], 'big'))
                chunk = chunk[4:]
            for i in range(16, 80):
                w.append(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16])
                w[i] = left_rotate(w[i], 1)

            a = h0
            b = h1
            c = h2
            d = h3
            e = h4

            for i in range(80):
                if i in range(20):
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                if i in range(20, 40):
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                if i in range(40, 60):
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                if i in range(60, 80):
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = left_rotate(a, 5) + f + e + k + w[i] & (2**32 - 1)
                e = d
                d = c
                c = left_rotate(b, 30)
                b = a
                a = temp

            h0 = h0 + a & (2**32 - 1)
            h1 = h1 + b & (2**32 - 1)
            h2 = h2 + c & (2**32 - 1)
            h3 = h3 + d & (2**32 - 1)
            h4 = h4 + e & (2**32 - 1)

        hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4

        return format(hh, 'x')


class sha1_MAC:
    def __init__(self):
        self.key = urandom(32)

    def tag(self, message):
        s = sha1()
        s.update(self.key+message)
        return s.hexdigest()

    def validate(self, message, tag):
        return False or (self.tag(message) == tag)

def hack():
    target = sha1_MAC()
    original_msg = b'''comment1=cooking%20MCs;userdata=foo;
                    comment2=%20like%20a%20pound%20of%20bacon'''
    new_msg = b';admin=true'
    key_length = 32
    t = target.tag(original_msg)
    s = sha_attack()
    s.initialisation = [int(t[8*i:8*i+8], 16) for i in range(5)]

    glue = s.pad(b'a'*key_length + original_msg, False)
    tagret = s.digest(new_msg + s.pad(b'a'*key_length + original_msg + glue + new_msg, 0), 0)
    return target.validate(original_msg + glue + new_msg, tagret)

if __name__ == '__main__':
    if hack() == True:
        print('hack successful 😎')
