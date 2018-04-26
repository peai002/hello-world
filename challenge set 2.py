#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jan 23 12:20:29 2018

@author: PEAI002
"""

class pkcs: #challenge 9
    ''' PKCS#7 padding '''
    
    def pad(byte_string, blocklen):
        padding_length = blocklen - len(byte_string)%blocklen
        byte_string = byte_string + bytes([padding_length]*padding_length)
        return byte_string

    def test_padding(byte_string, blocklen):
        if len(byte_string)%blocklen != 0:
            return False
        padded_block = byte_string[-blocklen:]
        padding_length = padded_block[blocklen - 1:] #byte string length 1
        l = padding_length[0] # integer
        if l not in range(1, blocklen + 1):
            return False
        if padded_block[-l:] != padding_length*l:
            return False
        return True
    
    class PaddingError(Exception):
        pass
    
    def unpad(byte_string, blocklen):
        if pkcs.test_padding(byte_string, blocklen) == False:
            raise pkcs.PaddingError
        padded_block = byte_string[-blocklen:]
        padding_len = padded_block[blocklen-1]
        return byte_string[:-padding_len]


def AES_cbc_DEC(ciphertext, iv):
    from Crypto.Cipher import AES
    key = "YELLOW SUBMARINE"
    plaintext = b''
    obj = AES.new(key, AES.MODE_ECB)
    for i in range(len(ciphertext)//16):
        block = ciphertext[16*i:16*(i+1)]
        temp = obj.decrypt(block)
        plainblock = [x^y for x, y in zip(bytearray([i for i in temp]), 
                                          bytearray([i for i in iv]))]
        iv = block
        plaintext = plaintext + bytes(plainblock)
    return plaintext
        
#%%
    
'''§11. An ECB/CBC detection oracle
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.
'''

from random import randint

def keygen(n):
    return bytes(bytearray([randint(0, 255) for i in range(n)]))

'''
Write a function that encrypts data under an unknown key --- that is, a 
function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly) 
before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC 
the other half (just use random IVs each time for CBC). Use rand(2) to decide 
which to use.
'''


def encryption_oracle(msg):
    k = keygen(16)
    plaintext = keygen(randint(5, 10)) + msg + keygen(randint(5, 10))
    plaintext = pkcs.pad(plaintext, 16)
    from Crypto.Cipher import AES
    rand_mode=randint(1,2)
    obj = AES.new(k, rand_mode, keygen(16)) #1 = ECB, 2=CBC
   
    return obj.encrypt(plaintext)

'''
Detect the block cipher mode the function is using each time. You should end up 
with a piece of code that, pointed at a block box that might be encrypting ECB 
or CBC, tells you which one is happening.
    
'''

def distinguish_mode(function):
    ciphertext = function(b'0'*256)
    if max([ciphertext.count(ciphertext[i*16:(i+1)*16]) for i in \
            range(len(ciphertext)//16)]) > 1:
        return (1, "ECB")
    else: return (2, "CBC")

#%%
'''§12 Copy your oracle function to a new function that encrypts buffers under
 ECB mode using a consistent but unknown key (for instance, assign a single 
random key, once, to a global variable).'''

unknown_key = keygen(16)

'''Now take that same function and have it append to the plaintext, BEFORE 
ENCRYPTING, the following string:'''

def encryption_cassandra(msg):
    k = unknown_key
    string = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXk\
        gaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvI\
        HNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    string = base64.b64decode(string)
    msg = msg + string
    plaintext = pkcs.pad(msg, 16)
    from Crypto.Cipher import AES
    obj = AES.new(k, 1, keygen(16)) #1 = ECB, 2=CBC
    return obj.encrypt(plaintext)

'''1. discovering block-length'''
def blocklength(function):
    temp = []
    for i in range(30):
        for j in range(300):
            s = (len(encryption_cassandra(b'a'*i)))
            if s not in temp:
                temp.append(s)
    return temp[1] - temp[0]

'''2. detecting the mode'''
distinguish_mode(encryption_cassandra)

'''3. one byte short of a block'''

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

    
    
class ECB_CutAndPaste:
    ''' challenge 13'''
    def __init__(self):
        from os import urandom
        self.master_k = urandom(16)
        
    def parser(self, s):
        'convert user profile encoded as string to dictionary object'
        temp = {}
        for i in s.rsplit('&'):
            temp[i.rsplit('=')[0]]=i.rsplit('=')[1]
        return temp
    
    def d_parser(self, d):
        'convert user profile dictionary object to string'
        string = '';
        for i in [item[0]+'='+item[1] for item in d.items()]: string+='&'+i
        return string[1:]
    
    def profile_for(self, email):
        'given email, creates user profile encoded as string'
        string = email.replace('&', '').replace('=', '')
        temp = {'email':string, 'uid':'10', 'role':'user'}
        return self.d_parser(temp)
    
    def encrypt_profile(self, email):
        'given email, encrypts user profile encoded as string'
        encoded = pkcs.pad(self.profile_for(email).encode(), 16)
        from Crypto.Cipher import AES
        obj = AES.new(self.master_k, 1)
        return obj.encrypt(encoded)
    
    def decrypt_profile(self, ciphertext):
        #AES decrypt encoded profile
        from Crypto.Cipher import AES
        obj = AES.new(self.master_k, 1)
        profile = obj.decrypt(ciphertext)
        return pkcs.unpad(profile, 16).decode()

def ch13():
    ch13 = ECB_CutAndPaste()
    part_1 = ch13.encrypt_profile('HACKER@ABC.DE')[:-16]
    part_2 = ch13.encrypt_profile(10*'a'+'admin'+'\x0b'*11)[16:32]
    return ch13.decrypt_profile((part_1+part_2))
