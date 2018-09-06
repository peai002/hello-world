#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#§11. An ECB/CBC detection oracle


from os import urandom
from random import randint
from Crypto.Cipher import AES
from ch09 import pkcs
from base64 import b64decode
unknown_key = urandom(16)

class encryption_oracle():
    def __init__(self):
        self.k = urandom(16)

    def encrypt(self, msg):
        '''sandwiches msg between two random strings and encrypts under
        ECB or CBC'''
        plaintext = urandom(randint(5, 10)) + msg + urandom(randint(5, 10))
        plaintext = pkcs.pad(plaintext, 16)
        rand_mode=randint(1,2)
        obj = AES.new(self.k, rand_mode, urandom(16)) #1 = ECB, 2=CBC
        return obj.encrypt(plaintext)

    def distinguish_mode(self, function):
        '''distinguishes whether the oracle is running ECB or CBC'''
        ciphertext = function(b'0'*256)
        if max([ciphertext.count(ciphertext[i*16:(i+1)*16]) for i in \
                range(len(ciphertext)//16)]) > 1:
            return (1, "ECB")
        else: return (2, "CBC")

    def blocklength(self, function):
        temp = []
        for i in range(30):
            for j in range(300):
                s = (len(encryption_cassandra(b'a'*i)))
                if s not in temp:
                    temp.append(s)
        return abs(temp[1] - temp[0])

def encryption_cassandra(msg):
    k = unknown_key
    string = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXk\
        gaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvI\
        HNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    string = b64decode(string)
    msg = msg + string
    plaintext = pkcs.pad(msg, 16)
    from Crypto.Cipher import AES
    obj = AES.new(k, 1, urandom(16)) #1 = ECB, 2=CBC
    return obj.encrypt(plaintext)

def recover():
    def target(i):
        return encryption_cassandra(b'a'*((16 -i)%16))

    def trial(char, string):
        return encryption_cassandra(b'a'*((15-len(string))%16)+string+chr(char).encode())

    recovered_text = b''
    limit = len(encryption_cassandra(b'a'))//16+1
    for k in range(limit):
        for i in range(1, 17):
            for j in range(256):
                if trial(j, recovered_text)[16*(k):16*(k+1)] == target(i)[16*(k):16*(k+1)]:
                    recovered_text += chr(j).encode()
                    break
    print(recovered_text[:-1].decode())

if __name__ == '__main__':
    recover()
