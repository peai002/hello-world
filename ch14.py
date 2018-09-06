from os import urandom
from random import randint
from base64 import b64decode
from ch09 import pkcs
master_key = urandom(16)

def encryption_cassandra(msg):
    k = master_key
    string = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXk\
        gaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvI\
        HNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    string = b64decode(string)
    prefix = urandom(randint(1, 16))
    msg = prefix + msg + string
    plaintext = pkcs.pad(msg, 16)
    from Crypto.Cipher import AES
    obj = AES.new(k, 1) #1 = ECB, 2=CBC
    return obj.encrypt(plaintext)

def sneaky_encryption(block):
    '''encrypt any block u like'''

    def base_block(char_1, char_2):
        if char_1 != b'a' and char_2 != b'a':
            char = b'a'
        elif char_1 != b'b' and char_2 != b'b':
            char = b'b'
        else: char = b'c'
        ciphertext = encryption_cassandra(char*48)
        for i in range(len(ciphertext)//16):
            if ciphertext[i*16:(i+1)*16] == ciphertext[(i+1)*16:(i+2)*16]:
                return (ciphertext[i*16:(i+1)*16], char)

    baseblock, char = base_block(block[:1], block[-1:])

    while True:
        trial = encryption_cassandra(char*16+block+char*16)
        n = trial.find(baseblock)
        if n >= 0:
            return trial[n+16:n+32]

def target_blocks(i):
    temp = []
    while len(temp) <16:
        c = encryption_cassandra(b'')
        c = c[-16*(i+1):len(c)-16*i]
        if c not in temp:
            temp.append(c)
    return temp

def decode_last_block():
    target = target_blocks(0)
    decoded_text = b''
    for char in range(16):
        for i in range(256):
            if sneaky_encryption(pkcs.pad(chr(i).encode()+decoded_text, 16))\
                    in target:
                decoded_text = (chr(i).encode()) + decoded_text
    return decoded_text

def decode_other_blocks(i, decoded_text):
    target = target_blocks(i)
    for char in range(16):
        for i in range(256):
            if sneaky_encryption((chr(i).encode()+decoded_text)[:16]) in target:
                decoded_text = (chr(i).encode()) + decoded_text
    return decoded_text

def decode_first_block(decoded_text):
    def first_target():
        temp  = []
        for i in range(100):
            c = encryption_cassandra(b'')
            if len(c) == 160:
                if c[16:32] not in temp:
                    temp.append(c[16:32])
        return temp

    target = first_target()
    for char in range(len(target)):
        for i in range(256):
            if sneaky_encryption((chr(i).encode()+decoded_text)[:16]) in target:
                decoded_text = (chr(i).encode()) + decoded_text
    return decoded_text

def main():
    decoded = decode_last_block()
    for i in range(10):
        decoded = decode_other_blocks(i, decoded)
    decoded = decode_first_block(decoded)
    print(decoded.decode())

if __name__ == '__main__':
    main()
