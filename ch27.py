from os import urandom
from Crypto.Cipher import AES
from ch09 import pkcs

class CBC_oracle:
    def __init__(self):
        self.master_key = urandom(16)
        self.iv = self.master_key

    def encrypt(self, string):
        obj = AES.new(self.master_key, 2, self.iv)
        return obj.encrypt(pkcs.pad(string.encode(), 16))

    def decrypt(self, bit_string):
        obj = AES.new(self.master_key, 2, self.iv)
        string = obj.decrypt(bit_string)
        #string = pkcs.unpad(string, 16)
        return string

    def decrypt_test(self, bit_string):
        string = self.decrypt(bit_string)
        if all([(31<i<128) for i in string]):
            return True
        else:
            raise Exception('non-ascii', string)

def xor(string, key):
    return bytes([string[i] ^ key[i] for i in range(len(string))])

cbc_cassandra = CBC_oracle()

def method1():
    c = b'a'*16+ b'\x00'*16 + b'a'*16
    try:
        cbc_cassandra.decrypt_test(c)
    except Exception as e:
        c = e.args[1]
    return xor(c[:16], c[-16:]) == cbc_cassandra.master_key, cbc_cassandra.master_key

def method2(): 
    c = cbc_cassandra.encrypt('a'*32)
    c = b'\x00'*16 + c[:16]
    try:
        cbc_cassandra.decrypt_test(c)
    except Exception as e:
        c = ( e.args[1][-16:])
    return xor(c, b'a'*16) == cbc_cassandra.master_key, cbc_cassandra.master_key
