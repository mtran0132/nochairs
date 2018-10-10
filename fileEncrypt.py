# Group 2 Marco Tran, Fa Fu
# Will implement a module that saves the key and iv
# So that you can encrypt the file, exit the program, then run it again to decrypt it.

import os, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CONST_KEY_BYTES = 32
CONST_IV_BYTES = 16
CONST_FILE_PATH = "picture.jpg"
CWD_PATH = os.getcwd()


def main():
	print(CWD_PATH)
	# Creates a random string of 32 bytes
	key = os.urandom(CONST_KEY_BYTES)
	message = b"This is a secret message. ATTACK AT DAWN FROM THE NORTH."
	print("Original Message: ", message,"\n")
	(cipherText, IV) = myEncrypt(message, key)
	print("Cipher Text: ", cipherText, "\n")
	plainText = myDecrypt(cipherText, key, IV)
	print("Plain Text: ", plainText,"\n")

	fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")
	while(fileChoice != "exit"):
		(fileCipherText, fileIv, fileKey, fileExt) = myFileEncrypt(fileChoice)
		dummy_text = input("Check the file to see if it is encrypted!\nThen press enter\n")
		myFileDecrypt(CONST_FILE_PATH, fileKey, fileIv)
		fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")
		


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



# Given a file within the same working directory it will encrypt it
def myFileEncrypt(fileName):

	# Makes an absolute path to the file
	inFile = os.path.join(CWD_PATH,fileName)

	# Checks if file exists
	if(fileCheck(inFile)):
	
		# Makes a 32 byte key
		key = os.urandom(CONST_KEY_BYTES)
		
		# Splits the file name and file extension
		fileName, fileExt = os.path.splitext(fileName)
		
		# Opens the file to read it as binary
		with open(inFile, "rb") as file:
			file_string = file.read()

			# Encrypts the file_string using the key
			# returns the encrypted file as encoded cipherFile and iv
			cipherFile, iv = myEncrypt(file_string, key)
		
		# Opens the file to overwrite it as binary
		with open(inFile, "wb") as file:

			# Overwrites whatever is inside with the encrypted encoded cipherFile
			file.write(cipherFile)
			file.close()

	# Not sure why we are returning all this
	return (cipherFile, iv, key, fileExt)

# Given the same file you want to decrypt and the same key and IV used to encrypt
def myFileDecrypt(fileName, key, iv):

	# Make an absolute path to the file
	inFile = os.path.join(CWD_PATH,fileName)

	# Checks if file exists
	if(fileCheck(inFile)):

		# Opens the file to read it as binary
		with open(inFile, "rb") as file:

			# Reads the encrypted encoded file
			file_string = file.read()

			# Decrypts it back to its normal state with the key and iv
			plainTextFile = myDecrypt(file_string,key,iv)
		
		# Opens the file to overwrite it as binary
		with open(inFile, "wb") as file:
			file.write(plainTextFile)
			file.close()


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

# FileCheck returns 'True' or 'False' if the file exists 
# This is a safeguard against non-existant files
def fileCheck(file):
	try:
		open(file, "r")
		return True
	except IOError:
		print("Can't find file: \n" + file + "\nMoving on...\n")
		return False


main()




# (C, IV)= Myencrypt(message, key):

# In this method, you will generate a 16 Bytes IV, and encrypt the message using the key and IV in CBC mode (AES).  
# You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).

# (C, IV, key, ext)= MyfileEncrypt (fileName):

# In this method, you'll generate a 32Byte key. You open and read the file as a string. 
# You then call the above method to encrypt your file using the key you generated. 
# You return the cipher C, IV, key and the extension of the file (as a string).

# You'll have to write the inverse of the above methods. 