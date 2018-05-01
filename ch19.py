from Crypto.Cipher import AES
from base64 import b64encode, b64decode

ciphertext = b'/\xbe\xe7k\xf9\xeb\x16\xc2\xaf\xcawz\x1f3\xa8\x1b\xb1\x87L\xb5\xecM[\xbd\xaa\xf6?\xda\xcc\x8b_8O\xc1\xec\xb212T.\xef\xfa\xfeE\xd7\xd0\xa4\xaf\xa0\xe2\xd2\x15'

def b64_to_n(ct):
    '''takes b64 encoded string of length 8 bytes and outputs integer val'''
    temp = [x for x in b64decode(ct)]
    counter = 0
    for i in range(8):
        counter += temp[i] * (256**i)
    return counter

def n_to_b64(counter):
    '''takes integer val and outputs b64 encoded string'''
    ct = []
    temp = counter
    for i in range(8):
        n = temp % 256
        ct.append(n)
        temp = (temp - n) // 256
    return b64encode(bytes(ct))

def xor(bstr1, bstr2):
        '''len(bstr1) < len(bstr2)'''
        xor = bytes(bstr1[i]^bstr2[i] for i in range(len(bstr1)))
        return xor

def AES_ctr(key, nonce, counter, text):
    def AES_ctr_block(key, nonce, counter):
        '''nonce has length 8 bytes = 64 bits
        counter has length 8 bytes = 64 bits'''
        nonce = b64decode(nonce)
        counter = b64decode(counter)
        obj = AES.new(key, AES.MODE_ECB)
        return obj.encrypt(nonce+counter)

    outout_text = b''
    ct = b64_to_n(counter)
    for i in range(len(text)//16 + 1):
        block = text[16*i:16*(i+1)]
        mask = AES_ctr_block(key, nonce, n_to_b64(ct))[:len(block)]
        outout_text += (xor(block, mask))
        ct += 1
    return outout_text
