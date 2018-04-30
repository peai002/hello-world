from os import urandom
from Crypto.Cipher import AES
from random import randint
from ch9 import pkcs

sample_plaintexts = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

class CBC_padding_oracle:
    def __init__(self):
        self.master_key = urandom(32)

    def encrypt(self, string):
        iv = urandom(16)
        obj = AES.new(self.master_key, 2, iv)
        return obj.encrypt(pkcs.pad(string.encode(), 16)), iv

    def decrypt(self, bit_string, iv):
        obj = AES.new(self.master_key, 2, iv)
        string = obj.decrypt(bit_string)
        string =  pkcs.unpad(string, 16)
        return string

def decrypt_byte(iteration):
    byte, adapted_iv, ct_block_1, decrypted = iteration
    target = 15 - byte

    def test(j):
        temp = [i for i in adapted_iv]
        temp[target] = temp[target] ^ j
        oracle.decrypt(ct_block_1, bytes(temp))
        output = temp
        for i in range(target, 16):
            output[i] = output[i] ^ (byte + 1 ^ (byte + 2))
        d_out = chr(j ^ (byte + 1)) + decrypted
        return byte + 1, bytes(output), ct_block_1, d_out

    for j in range(1, 256):
        try:
            return test(j)
        except pkcs.PaddingError:
            pass
    return test(0)

def decrypt_block(c_A, c_B):
    x = decrypt_byte((0, c_A, c_B, ''))
    for i in range(1, 16):
        x = decrypt_byte(x)
    return x[3]

def decrypt_ciphertext(ciphertext, iv):
    ct = iv + ciphertext
    decryption = ''
    for i in range(len(ct)//16 - 1):
        c_A = ct[16*i:16*(i+1)]
        c_B = ct[16*(i+1):16*(i+2)]
        decryption = decryption + decrypt_block(c_A, c_B)
    return decryption

oracle = CBC_padding_oracle()

def main():
    pt = sample_plaintexts[randint(0, len(sample_plaintexts))]
    pt = oracle.encrypt(pt)
    print(pkcs.unpad(decrypt_ciphertext(pt[0], pt[1]).encode(), 16))

if __name__=='__main__':
    main()
