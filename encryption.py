import os, base64, constants
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac

# Encrypts a message using a random key generated from the OS
def myEncrypt(message, key):

	if(len(key) < constants.CONST_KEY_BYTES):
		print("Error: key length less than 32 bytes")
		return
		
	# Creates a random string of 16 bytes
	iv = os.urandom(constants.CONST_IV_BYTES)

	# Here we set the parameters for the encryptor
	# We use AES and CBC
	encryptor = Cipher(
				algorithms.AES(key),
				modes.CBC(iv),
				backend = default_backend()
				).encryptor()

	# Encode the message to base64
	encoded = base64.b64encode(message)
	encoded = addPadding(encoded)

	# We encrypt the message
	cipherText = encryptor.update(encoded) + encryptor.finalize()

	return (cipherText, iv)

# Do not use the same key twice
# HMAC key should equal length to the digest_size
def myEncryptMAC(message, EncKey, HmacKey):

	if(len(EncKey) < constants.CONST_KEY_BYTES):
		print("Error: key length less than 32 bytes")
		return
	
	if(len(HmacKey) < constants.CONST_HMACKEY_BYTES):
		print("Error: HMAC Key length less than 32 bytes")
		return

	# Creates a random string of 16 bytes
	iv = os.urandom(constants.CONST_IV_BYTES)


	# Here we set the parameters for the encryptor
	# We use AES and CBC
	encryptor = Cipher(
				algorithms.AES(EncKey),
				modes.CBC(iv),
				backend = default_backend()
				).encryptor()
	

	# Encode the message to base64
	encoded = base64.b64encode(message)
	encoded = addPadding(encoded)

	# We encrypt the message
	cipherText = encryptor.update(encoded) + encryptor.finalize()

	# After we encrypt it, we can make hash-based message authenication codes
	h = hmac.HMAC(HmacKey, hashes.SHA256(), backend = default_backend())
	h.update(cipherText)
	tag = h.finalize()

	return (cipherText, iv, tag)


# Given a file within the same working directory it will encrypt it
def myFileEncrypt(fileName):

	# Checks if file exists
	if(os.path.isfile(fileName)):
	
		# Makes a 32 byte key
		key = os.urandom(constants.CONST_KEY_BYTES)
		
		# Splits the file name and file extension
		fileLabel, fileExt = os.path.splitext(fileName)
		
		# Opens the file to read it as binary
		with open(fileName, "rb") as file:
			file_string = file.read()

			# Encrypts the file_string using the key
			# returns the encrypted file as encoded cipherFile and iv
			cipherFile, iv = myEncrypt(file_string, key)
		
		# Opens the file to overwrite it as binary
		with open(fileName, "wb") as file:

			# Overwrites whatever is inside with the encrypted encoded cipherFile
			file.write(cipherFile)
			file.close()

		# Not sure why we are returning all this
		return (cipherFile, iv, key, fileExt)


def myFileEncryptMAC(fileName):

	# Checks if file exists
	if(os.path.isfile(fileName)):
	
		# Makes a 32 byte key
		EncKey = os.urandom(constants.CONST_KEY_BYTES)
		HmacKey = os.urandom(constants.CONST_HMACKEY_BYTES)	
		
		# Splits the file name and file extension
		fileLabel, fileExt = os.path.splitext(fileName)
		
		# Opens the file to read it as binary
		with open(fileName, "rb") as file:
			file_string = file.read()

			# Encrypts the file_string using the key
			# returns the encrypted file as encoded cipherFile and iv
			cipherFile, iv = myEncrypt(file_string, EncKey)
		
		# Opens the file to overwrite it as binary
		with open(fileName, "wb") as file:

			# Overwrites whatever is inside with the encrypted encoded cipherFile
			file.write(cipherFile)
			file.close()

		# After we encrypt it, we can make hash-based message authenication codes
		h = hmac.HMAC(HmacKey, hashes.SHA256(), backend = default_backend())
		h.update(cipherFile)
		tag = h.finalize()

		# Not sure why we are returning all this
		return (cipherFile, iv, tag, EncKey, HmacKey, fileExt)


# AES requires plain text and ciphertext to be a multiple of 16
# We pad it so that the message is a multiple of the IV, 16
def addPadding(encoded):
	
	# We pad it with 128 bits or 16 bytes
	padder = padding.PKCS7(constants.CONST_PADDING_BITS).padder()

	# update() pads the encoded message
	padded_encoded = padder.update(encoded)

	# .finalize () Returns the remainder of the data.
	padded_encoded += padder.finalize()
	return padded_encoded