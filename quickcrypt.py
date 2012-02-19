'''
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''
import base64
import random

# Gets set to false if your system does not have pyCrypto
can_crypto = True

# Attempt to load pyCrypto
try:
    from Crypto.Cipher import AES
    # Attempt to load the pyCrypt KDF library
    try:
        from Crypto.Protocol import KDF
    except ImportError:    
        # As a backup, try loading the standalone PBKDF2 library
        from pbkdf2 import PBKDF2
except ImportError:
    can_crypto = False

# Must be 16
_BLOCK_SIZE = 16

# This must be a multiple of 16
#   advise >=32 for proper decryption detection
_PAD_SIZE = 32

# Header to ensure the file is valid
_DEFAULTHEADER = "!aes!"

# Will be initialized when init(password) is called
key = None

class InvalidFileException(Exception):
    '''
        Returned from decrypt when a document's header or size is incorrect to be encrypted
    '''
    pass

class InvalidKeyException(Exception):
    '''
        Returned from decrypt when a document failed to decrypt
    '''
    pass

def _pad(s):
    '''
    Pads a string to be a multiple of the padding size
        s: Bytes to be padded
    '''
    # Get the number of bytes needed to pad to a mutlple of the padding size
    numpad = _PAD_SIZE - (len(s) % _PAD_SIZE)
    # If no padding required, pad up to the full padding size anyway
    numpad = _PAD_SIZE if not numpad else numpad
    # Return the original string plus the padding characters
    return s + (numpad * chr(numpad))

def _getcypher(iv):
    '''
    Generated an AES CBC mode cypher with a starting IV and key
    '''
    assert(can_crypto and key)
    return AES.new(key, AES.MODE_CBC, iv)

def encrypt(s, header=_DEFAULTHEADER, b64=True):
    '''
    Pads and encrypts a string using a given cipher, returns base64 with header
            e: Bytes to encrypt
            header: Header to pad at the start of the encrypted file
            b64: Encode encrypted data in base64
    '''
    # Generate a random IV within printable ascii range
    iv = ''.join([chr(random.randint(ord(' '), ord('~'))) for i in range(_BLOCK_SIZE)])
    
    # Generate a cypher with that IV
    c = _getcypher(iv)
    
    # Pad and encrypt the data
    e = c.encrypt(_pad(s))
    
    # Base64 encode the encrypted data to make it within ascii range
    if b64:
        e = base64.b64encode(e)
    
    # Return the encrypted data along witha a header and the IV
    return header + iv + e

def decrypt(e, header=_DEFAULTHEADER, b64=True):
    '''
    Decrypts and then removes padding characters given an encrypted string
        e: Bytes of encrypted data
        header: Header to pad at the start of the encrypted file
        b64: Encrypted data is stored in base64
    Raises InvalidKeyException if the file could not be decrypted using the current key
    Raises InvalidFileException if the file is not believed to be an encrypted file (based on the header)
    '''
    # Ensure the file has the length for an IV and header
    if len(e) <= (_BLOCK_SIZE + len(header)):
        raise InvalidFileException()
    
    # Extract the header and verify it is at the start of the file
    e = e.split(header, 1)
    if e[0] or len(e) < 2:
        raise InvalidFileException()
    e = e[1]
    
    # Extract the IV and strip from the front
    iv = e[:_BLOCK_SIZE]
    e = e[_BLOCK_SIZE:]
    
    # Generated a cypher for the key and decrypt
    c = _getcypher(iv)
    if b64:
        e = base64.b64decode(e)
    s = c.decrypt(e)
    
    # Strip out padding and ensure the padding is valid
    p_char = s[-1]
    p = ord(p_char)
    padding = s[-p:]
    for c in padding:
        # Ensure that the string decrypted correctly
        # If all the padding characters are the same, it did
        if c != p_char:
            raise InvalidKeyException()
    
    # Return the decrypted text with the padding chopped off
    return s[:-p]

def init(password, salt='', keysize=32, count=2000):
    '''
    Generates keys with supported methods of a given size based on a password
        password: Bytes to use for a password
        salt: A known salt, I advise it be random and stored
        keysize: Must be: 16, 24, or 32
        count: Iterations for key derivation, 2000 or more advised
    Returns the final key
    '''
    global key
    assert(can_crypto)
    
    # Add some extra data to the salt
    salt += str(keysize)+str(count)+_DEFAULTHEADER
    
    # Generate a PBKDF2 based key
    try:
        # Try to generate a PBKDF2 based key using the pyCrypto KDF library
        key = KDF.PBKDF2(password, salt, dkLen=keysize, count=count)
    except NameError:
        # If the KDF library was not loaded, try the standalone PBKDF2 one instead
        key = PBKDF2(password, salt, iterations=count).read(keysize)
    return key

def _test():
    '''
    Gets some random bytes, then encrypt and decrypts those bytes
    '''
    s = os.urandom(random.randint(1, 255))
    e = encrypt(s)
    d = decrypt(e)
    assert(s and s == d and e != s and e)

def _randomize_key():
    '''
        Inits keys with a random password
    '''
    return init(os.urandom(random.randint(1,128)))

if __name__ == '__main__':
    import os
    TEST_ITERATIONS = 25
    print "Testing AES encryption with random key %d times..." % (TEST_ITERATIONS)
    for i in range(1, TEST_ITERATIONS+1):
        _randomize_key()
        _test()
        if i and not i % 5:
            print "passed (%d/%d)" % (i, TEST_ITERATIONS)
    exit(1)
    



    
