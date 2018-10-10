#https://www.reddit.com/r/learnpython/comments/51hxul/how_do_you_split_a_binary_file_into_specific/

import os, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CONST_KEY_BYTES = 32
CONST_IV_BYTES = 16
CONST_FILE_PATH = "picture.jpg"

def main():
	# Creates a random string of 32 bytes
	key = os.urandom(CONST_KEY_BYTES)
	message = b"This is a secret message. ATTACK AT DAWN FROM THE NORTH."
	(cipherText, IV) = myEncrypt(message, key)
	print("Cipher Text: ", cipherText)
	plainText = myDecrypt(cipherText, key, IV)
	print("Plain Text: ", plainText)

	myFileEncrypt(CONST_FILE_PATH)

# Encrypts a message using a random key generated from the OS
def myEncrypt(message, key):

	if(len(key) < CONST_KEY_BYTES):
		print("Error: key length less than 32 bytes")
		return
		
	# Creates a random string of 16 bytes
	iv = os.urandom(CONST_IV_BYTES)

	# Here we set the parameters for the encryptor
	# We use AES and CBC
	encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend()).encryptor()
	# Encode the message to base64
	encoded = base64.b64encode(message)

	encoded = addPadding(encoded)


	# We encrypt the message
	cipherText = encryptor.update(encoded) + encryptor.finalize()

	return (cipherText, iv)

# Decrypts a message using returned parameters from encrypt function 
def myDecrypt(cipherText, key, iv):
	if(len(key) < CONST_KEY_BYTES):
		print("Error: key length less than 32 bytes")
		return

	# Here we set the parameters for the decryptor	
	decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()

	# The cipherText gets decrypted but it is still encoded
	encoded = decryptor.update(cipherText) + decryptor.finalize()

	# Removes padding 
	encoded = removePadding(encoded)

	# We decode from base64
	plainText = base64.b64decode(encoded)

	# Return the plaintext
	return plainText


def myFileEncrypt(filepath):
	key = os.urandom(CONST_KEY_BYTES)
	fileName, fileExt = os.path.splitext(filepath)
	print(fileExt)
	with open(filepath, "rb") as file:
		file_string = file.read()

	cipherFile, iv = myEncrypt(file_string, key)

	return (cipherFile, iv, key, fileExt)


# def myFileDecrypt(filepath, key):


# AES requires plain text and ciphertext to be a multiple of 16
# We pad it so that the message is a multiple of the IV, 16
def addPadding(encoded):
	# TAKEN FROM https://stackoverflow.com/questions/14179784/python-encrypting-with-pycrypto-aes/14205319#14205319
	length = CONST_IV_BYTES - (len(encoded) % CONST_IV_BYTES)
	encoded += bytes([length])*length
	return encoded


# Here we remove the padding
def removePadding(encoded):
	# TAKEN FROM https://stackoverflow.com/questions/14179784/python-encrypting-with-pycrypto-aes/14205319#14205319
	encoded = encoded[:-encoded[-1]]
	
	return encoded

main()




# (C, IV)= Myencrypt(message, key):

# In this method, you will generate a 16 Bytes IV, and encrypt the message using the key and IV in CBC mode (AES).  
# You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).

# (C, IV, key, ext)= MyfileEncrypt (filepath):

# In this method, you'll generate a 32Byte key. You open and read the file as a string. 
# You then call the above method to encrypt your file using the key you generated. 
# You return the cipher C, IV, key and the extension of the file (as a string).

# You'll have to write the inverse of the above methods. 