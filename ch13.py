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

def main():
    ch13 = ECB_CutAndPaste()
    part_1 = ch13.encrypt_profile('HACKER@ABC.DE')[:-16]
    part_2 = ch13.encrypt_profile(10*'a'+'admin'+'\x0b'*11)[16:32]
    print(ch13.decrypt_profile((part_1+part_2)))

if __name__ == '__main__':
    main()
