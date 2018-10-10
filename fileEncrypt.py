import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CONST_BIT_LENGTH = 128
CONST_IV = os.urandom(16)
CONST_BACKEND = default_backend()

def main():



def myEncrypt(message, key):

def myDecrypt(message, key):

def myFileEncrypt(filepath):

def myFileDecrypt(filepath, key):


main()


backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()
decryptor = cipher.decryptor()
decryptor.update(ct) + decryptor.finalize()
b'a secret message'


# (C, IV)= Myencrypt(message, key):

# In this method, you will generate a 16 Bytes IV, and encrypt the message using the key and IV in CBC mode (AES).  
# You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).

# (C, IV, key, ext)= MyfileEncrypt (filepath):

# In this method, you'll generate a 32Byte key. You open and read the file as a string. 
# You then call the above method to encrypt your file using the key you generated. 
# You return the cipher C, IV, key and the extension of the file (as a string).

# You'll have to write the inverse of the above methods. 