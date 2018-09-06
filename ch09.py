class pkcs:
    '''pkcs padding'''
    def pad(byte_string, blocklen):
        '''pads a byte_string'''
        padding_length = blocklen - len(byte_string)%blocklen
        byte_string = byte_string + bytes([padding_length]*padding_length)
        return byte_string

    def test_padding(byte_string, blocklen):
        '''tests whether a byte_string has been padded correctly'''
        if len(byte_string)%blocklen != 0:
            return False
        padded_block = byte_string[-blocklen:]
        padding_length = padded_block[blocklen - 1:] #byte string length 1
        l = padding_length[0] # integer
        if l not in range(1, blocklen + 1):
            return False
        if padded_block[-l:] != padding_length*l:
            return False
        return True

    class PaddingError(Exception):
        pass

    def unpad(byte_string, blocklen):
        '''unpads a correctly padded byte_string'''
        if pkcs.test_padding(byte_string, blocklen) == False:
            raise pkcs.PaddingError
        padded_block = byte_string[-blocklen:]
        padding_len = padded_block[blocklen-1]
        return byte_string[:-padding_len]
