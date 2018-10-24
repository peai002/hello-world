
from os import urandom
from binascii import unhexlify

class md4:
    def __init__(self):
        self.initialisation = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    def pad(self, message, padded = True):
        '''returns padded message. set padded to false to return padding only'''
        ml = 8*len(message)
        k = -(9 + len(message)) % 64
        padding = b'\x80' + b'\x00'*k + int.to_bytes(ml, 8, 'little')
        if padded:
            padding = message + padding
        return padding

    def digest(self, message, padding=True):
        '''takes a message (plaintext string, length <= 2**64 and
        applies md4.'''
        #spec defines md4 for longer messages, could incorporate
        #this from the pseudocode https://tools.ietf.org/html/rfc1186
        if padding:
            message = self.pad(message)

        A, B, C, D = self.initialisation

        while len(message) > 0:
            X = []
            block = message[:64]
            message = message[64:]
            while len(block) > 0:
                X.append(int.from_bytes(block[:4], 'little'))
                block = block[4:]

            AA = A
            BB = B
            CC = C
            DD = D

            def left_rotate(word, offset):
                    n = 32
                    left = (word  << offset) & 0xFFFFFFFF
                    right = word >> (n - offset)
                    return right | left

            def f(x, y, z):
                return ((x & y) | ((~x) & z))
            def g(x, y, z):
                return (x & y) | (x & z) | (y & z)
            def h(x, y, z):
                return x ^ y ^ z

            def round_1(A, B, C, D, i, s):
                return left_rotate((A + f(B, C, D) + X[i]) & 0xFFFFFFFF, s)

            A = round_1(A, B, C, D, 0, 3)
            D = round_1(D, A, B, C, 1, 7)
            C = round_1(C, D, A, B, 2, 11)
            B = round_1(B, C, D, A, 3, 19)
            A = round_1(A, B, C, D, 4, 3)
            D = round_1(D, A, B, C, 5, 7)
            C = round_1(C, D, A, B, 6, 11)
            B = round_1(B, C, D, A, 7, 19)
            A = round_1(A, B, C, D, 8, 3)
            D = round_1(D, A, B, C, 9, 7)
            C = round_1(C, D, A, B, 10, 11)
            B = round_1(B, C, D, A, 11, 19)
            A = round_1(A, B, C, D, 12, 3)
            D = round_1(D, A, B, C, 13, 7)
            C = round_1(C, D, A, B, 14, 11)
            B = round_1(B, C, D, A, 15, 19)

            def round_2(A, B, C, D, i, s):
                return left_rotate((A + g(B, C, D) + X[i] + 0x5a827999) & 0xFFFFFFFF, s)

            A = round_2(A, B, C, D, 0, 3)
            D = round_2(D, A, B, C, 4, 5)
            C = round_2(C, D, A, B, 8, 9)
            B = round_2(B, C, D, A, 12, 13)
            A = round_2(A, B, C, D, 1, 3)
            D = round_2(D, A, B, C, 5, 5)
            C = round_2(C, D, A, B, 9, 9)
            B = round_2(B, C, D, A, 13, 13)
            A = round_2(A, B, C, D, 2, 3)
            D = round_2(D, A, B, C, 6, 5)
            C = round_2(C, D, A, B, 10, 9)
            B = round_2(B, C, D, A, 14, 13)
            A = round_2(A, B, C, D, 3, 3)
            D = round_2(D, A, B, C, 7, 5)
            C = round_2(C, D, A, B, 11, 9)
            B = round_2(B, C, D, A, 15, 13)

            def round_3(A, B, C, D, i, s):
                return left_rotate((A + h(B, C, D) + X[i] + 0x6ed9eba1) & 0xFFFFFFFF, s)

            A = round_3(A, B, C, D, 0, 3)
            D = round_3(D, A, B, C, 8, 9)
            C = round_3(C, D, A, B, 4, 11)
            B = round_3(B, C, D, A, 12, 15)
            A = round_3(A, B, C, D, 2, 3)
            D = round_3(D, A, B, C, 10, 9)
            C = round_3(C, D, A, B, 6, 11)
            B = round_3(B, C, D, A, 14, 15)
            A = round_3(A, B, C, D, 1, 3)
            D = round_3(D, A, B, C, 9, 9)
            C = round_3(C, D, A, B, 5, 11)
            B = round_3(B, C, D, A, 13, 15)
            A = round_3(A, B, C, D, 3, 3)
            D = round_3(D, A, B, C, 11, 9)
            C = round_3(C, D, A, B, 7, 11)
            B = round_3(B, C, D, A, 15, 15)

            A = A + AA & (2**32 - 1)
            B = B + BB & (2**32 - 1)
            C = C + CC & (2**32 - 1)
            D = D + DD & (2**32 - 1)

        def conv(X):
            return b''.join([b'%02x'%i for i in int.to_bytes(X, 4, 'little')])

        return b''.join([conv(i) for i in (A, B, C, D)])

    def test_suite(self):
            assert all((self.digest(b'') == b'31d6cfe0d16ae931b73c59d7e0c089c0',
                        self.digest(b'a') == b'bde52cb31de33e46245e05fbdbd6fb24',
                        self.digest(b'abc') == b'a448017aaf21d8525fc10ae87aa6729d',
                        self.digest(b'message digest') ==
                            b'd9130a8164549fe818874806e1c7014b',
                        self.digest(b'abcdefghijklmnopqrstuvwxyz') ==
                            b'd79e1c308aa5bbcdeea8ed63df412da9',
                        self.digest(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
                            == b'043f8582f241db351ce627e153e7f0e4'))

class md4_mac:
    '''keyed mac. appends randomly generated key to message and applies md4 hash
    function'''
    def __init__(self):
        self.key = urandom(32)

    def tag(self, message):
        s = md4()
        return s.digest(self.key+message)

    def validate(self, message, tag):
        return self.tag(message) == tag

def hack():
    target = md4_mac()
    original_msg = b'''comment1=cooking%20MCs;userdata=foo;
                    comment2=%20like%20a%20pound%20of%20bacon'''
    new_msg = b';admin=true'
    key_length = 32
    t = target.tag(original_msg)

    s = md4()
    s.initialisation = [int.from_bytes(unhexlify(t[8*i:8*i+8]), 'little') for i in range(4)]

    glue = s.pad(b'a'*key_length + original_msg, False)
    tagret = s.digest(new_msg + s.pad(b'a'*key_length + original_msg + glue + new_msg, 0), 0)
    return target.validate(original_msg + glue + new_msg, tagret)

if __name__ == '__main__':
    if hack() == True:
        print('good work boyo')
