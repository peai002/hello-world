from Crypto.Cipher import AES
from os import urandom
import base64
secret_key = urandom(32)
key = "YELLOW SUBMARINE"

infile = open('ch24file.txt', 'rb')
ciphertext = infile.read()
infile.close()

obj = AES.new(key, AES.MODE_ECB)
ciphertext = base64.b64decode(ciphertext)
plaintext = obj.decrypt(ciphertext).decode()

class counter():
    '''counter function, increments by one when called'''
    def __init__(self, start = 0):
        self.value = start
    def __call__(self):
        self.value += 1
        return format(self.value, '016b').encode()

#require keyword argument counter= *kwarg
# need to get counter to call on something. "'counter' parameter must be a
# callable object"
# CTR function must return bytes of length 16.
# there is a built in way to do this from teh PyCrypto library.

ciphertext = AES.new(secret_key, AES.MODE_CTR, counter = counter()).encrypt(plaintext)

def edit(ciphertext, key, offset, newtext):
    ''' offset gives the block. newtext needs to be a multiple of 16'''
    if len(newtext) + offset*16 != len(ciphertext):
        raise ValueError('Input strings must be a multiple of 16 in length')
    if type(newtext) == bytes:
        pass
    else:
        if type(newtext) == str:
            newtext = newtext.encode()
        else:
            raise TypeError('newtext should be bytes')
    plaintext = AES.new(key, AES.MODE_CTR, counter = counter(0)).decrypt(ciphertext)
    plaintext = plaintext[:offset*16] + newtext
    return AES.new(key, AES.MODE_CTR, counter = counter(0)).encrypt(plaintext)

if __name__ == '__main__':
    print(edit(ciphertext, secret_key, 0, ciphertext).decode())
