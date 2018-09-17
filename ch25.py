'''§25: CTR Bitflipping

There are people in the world that believe that CTR resists bit flipping
attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead
of CBC mode. Inject an "admin=true" token.'''

from os import urandom
from Crypto.Cipher import AES
from ch09 import pkcs
from ch24 import counter


class CTR_padding_oracle:
    def __init__(self):
        self.master_key = urandom(32)

    def encrypt(self, string):
        string = string.replace(';', '').replace('=', '')
        prefix = "comment1=cooking%20MCs;userdata="
        suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
        m = prefix + string + suffix
        obj = AES.new(self.master_key, 6, counter=counter(0)) #AES_CTR = 6
        return obj.encrypt(pkcs.pad(m.encode(), 16))

    def decrypt(self, bit_string):
        obj = AES.new(self.master_key, 6, counter=counter(0))
        string = obj.decrypt(bit_string)
        string = pkcs.unpad(string, 16)
        return string

    def decrypt_test(self, bit_string):
        obj = AES.new(self.master_key, 6, counter=counter(0))
        string = obj.decrypt(bit_string)
        string = pkcs.unpad(string, 16)
        if b';admin=true;' in string:
            return True
        else: return False

def main():
    oracle = CTR_padding_oracle()
    a = oracle.encrypt(":admin<true")
    temp = [j for j in a]
    temp[32] ^= 1
    temp[38] ^= 1
    print(oracle.decrypt_test(bytes(temp)))

if __name__ == '__main__':
    main()
