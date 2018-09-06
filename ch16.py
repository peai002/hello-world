from os import urandom
from Crypto.Cipher import AES
from ch09 import pkcs

class CBC_padding_oracle:
    def __init__(self):
        self.master_key = urandom(32)
        self.iv = urandom(16)

    def encrypt(self, string):
        string = string.replace(';', '').replace('=', '')
        prefix = "comment1=cooking%20MCs;userdata="
        suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
        m = prefix + string + suffix
        obj = AES.new(self.master_key, 2, self.iv)
        return obj.encrypt(pkcs.pad(m.encode(), 16))

    def decrypt(self, bit_string):
        obj = AES.new(self.master_key, 2, self.iv)
        string = obj.decrypt(bit_string)
        string = pkcs.unpad(string, 16)
        return string

    def decrypt_test(self, bit_string):
        obj = AES.new(self.master_key, 2, self.iv)
        string = obj.decrypt(bit_string)
        string = pkcs.unpad(string, 16)
        if b';admin=true;' in string:
            return True
        else: return False

def main():
    oracle = CBC_padding_oracle()
    a = oracle.encrypt("$$$$:admin<true")
    temp = [j for j in a]
    temp[20] = temp[20] ^ 1
    temp[26] = temp[26] ^ 1
    print(oracle.decrypt_test(bytes(temp)))

if __name__ == '__main__':
    main()
