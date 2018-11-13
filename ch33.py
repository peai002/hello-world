from random import randint
import socket
from sys import argv
from Crypto.Cipher import AES
from hashlib import sha1
from os import urandom

def modexp(a, b, m):
   """computes s = (a**b) mod p
     using so called 'addition chaining' method (binary representation of power,
     see Bruce Schneier's book, _Applied Cryptography_ p. 244)"""
   s = 1
   while b != 0:
      if b & 1:
         s = (s * a)%m
      b >>= 1
      a = (a * a)%m;
   return s

# modexp(A, b, p) == modexp(B, a, p)

class DHKeyAgreement:
    def __init__(self):
        self.p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
                'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
                '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
                '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
                '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
                'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
                'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
                'fffffffffffff', 16
                )
        self.g = 2

    def hello(self):
        a = randint(0, self.p - 1)
        A = modexp(self.g, a, self.p)
        return self.p, self.g, A, a

    def response(self, p, g):
        b = randint(0, p - 1)
        B = modexp(g, b, p)
        return b, B

    def acknowledgement(self, key, message):
        '''s is the shared secret'''
        iv = urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(message)
        return ciphertext, iv

    def keyagree(self, key, ctext, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        message = cipher.decrypt(ctext)

        iv = urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(message)

        return ciphertext, iv

    def check(self, key, ctext, iv, message):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        testmessage = cipher.decrypt(ctext)
        if testmessage == message:
            print('Connection up and running!')
        else:
            print('Could not validate connection')


def Bob():
    #open port, establish socket.

    host = 'localhost'
    port = 12345
    s = socket.socket()
    s.bind((host, port))
    s.listen(1)
    conn, addr = s.accept()
    print('Connected by', addr)

    data = conn.recv(1024)
    p, g, A = data.decode().split()
    p = int(p); g = int(g); A = int(A)

    obj = DHKeyAgreement()
    b, B = obj.response(p, g)
    conn.sendall(str(B).encode())

    shared_secret = str(modexp(A, b, p)).encode()
    sha = sha1()
    sha.update(shared_secret)
    shared_key = sha.digest()
    shared_key = shared_key[:16]


    data = conn.recv(1024)
    ciphertext, iv = data[:-16], data[-16:]
    ciphertext2, iv2 = obj.keyagree(shared_key, ciphertext, iv)

    conn.sendall(ciphertext2+iv2)



    conn.close()

def Alice():
    #open port, establish socket
    host = 'localhost'
    port = 12345
    s = socket.socket()
    s.connect((host, port))

    #hello message
    obj = DHKeyAgreement()
    p, g, A, a = obj.hello()

    data = b'%i %i %i' % (p, g, A)
    s.sendall(data)

    data = s.recv(1024)
    B = int(data.decode())

    shared_secret = str(modexp(B, a, p)).encode()
    sha = sha1()
    sha.update(shared_secret)
    shared_key = sha.digest()
    shared_key = shared_key[:16]

    message = urandom(32)
    ciphertext, iv = obj.acknowledgement(shared_key, message)
    s.sendall(ciphertext + iv)

    data = s.recv(1024)
    obj.check(shared_key, data[:-16], data[-16:], message)

    s.close()


if __name__ == '__main__':
    if argv[1] == '-Alice':
        Alice()
    if argv[1] == '-Bob':
        Bob()
    
