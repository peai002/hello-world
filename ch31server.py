#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import sha1
import web
from os import urandom
from time import sleep

# this is the server!

key = urandom(32)

# test value:
# key = b'\xd1\xa7\x8fs\x84y\xca\x08\x8c\xa0\xbey2\xfa g"Z\xbf\xed\x93u9\xb9\xdd|;>z\xe4\xc2Y'
# should output signature 9c99c56dfa3c3505de76b198bd5cd9d19797490a
# url = 'http://0.0.0.0:8080/test?file=foo&signature=9c99c56dfa3c3505de76b198bd5cd9d19797490a'

# first to define the functions we need

def sha_1(m, output='bytes'):
    f = sha1()
    f.update(m)
    if output == 'bytes':
        return f.digest()
    if output == 'hex':
        return f.hexdigest()

def HMAC(k, m):
    'message and key both bytes objects. returns output as hex'''
    def xor(b1, b2):
        return bytes([b1[i] ^ b2[i] for i in range(min(len(b1), len(b2)))])

    while len(k) < 64:
        k +=  b'\x00'
    if len(k) > 64:
        k = sha1(k)

    o_key_pad = xor(k, (bytes([0x5c]) * 64))
    i_key_pad = xor(k, (bytes([0x36]) * 64))

    return sha_1(o_key_pad + sha_1(i_key_pad + m), 'hex')

def process(string):
    first_index = string.find('?file=') + 6
    second_index = string.find('&signature=')
    return string[first_index: second_index], string[second_index + 11:]

def compare(file, signature):
    if HMAC(key, file) == signature:
        return 'Everything looks good to me!!'
    else:
        return web.HTTPError('500')

def insecure_compare(file, signature):
    test = HMAC(key, file)

    for i in range(len(test)):
        try:
            if test[i] == signature[i]:
                sleep(0.1)
            else:
                return web.HTTPError('500')
        except IndexError:
            return web.HTTPError('500')
    return 'Everything looks good to me!!'

# now to the actual server functionality

urls = (
    '/verify/(.*)', 'verify',
)

app = web.application(urls, globals())

class verify:
    def GET(self, name):
        file, signature = process(web.ctx['query'])
        file = file.encode() #get file into the correct format (bytes)
        return insecure_compare(file, signature)

if __name__ == "__main__":
    app.run()
