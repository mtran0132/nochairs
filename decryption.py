import os, base64, constants
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac

# Decrypts a message using returned parameters from encrypt function 
def myDecrypt(cipherText, key, iv):
	if(len(key) < constants.CONST_KEY_BYTES):
		print("Error: key length less than 32 bytes")
		return

	# Here we set the parameters for the decryptor	
	decryptor = Cipher(
				algorithms.AES(key),
				modes.CBC(iv),
				backend=default_backend()
				).decryptor()

	# The cipherText gets decrypted but it is still encoded
	encoded = decryptor.update(cipherText) + decryptor.finalize()

	# Removes padding 
	encoded = removePadding(encoded)

	# We decode from base64
	plainText = base64.b64decode(encoded)

	# Return the plaintext
	return plainText

def myDecryptMAC(cipherText, EncKey, HmacKey, iv, tag):
	if(len(EncKey) < constants.CONST_KEY_BYTES):
		print("Error: key length less than 32 bytes")
		return

	h = hmac.HMAC(HmacKey, hashes.SHA256(), backend = default_backend())
	h.update(cipherText)
	hashTest = h.finalize() 
	# If the hash is the same, meaning ciphertext has not been modified

	if(tag == hashTest):
		
		# Here we set the parameters for the decryptor	
		decryptor = Cipher(
					algorithms.AES(EncKey), 
					modes.CBC(iv), 
					backend=default_backend()
					).decryptor()
		
		# The cipherText gets decrypted but it is still encoded
		encoded = decryptor.update(cipherText) + decryptor.finalize()

		# Removes padding 
		encoded = removePadding(encoded)

		# We decode from base64
		plainText = base64.b64decode(encoded)

		# Return the plaintext
		return plainText
	else:
		print("Hashes don't match")

# Given the same file you want to decrypt and the same key and IV used to encrypt
def myFileDecrypt(fileName, EncKey, iv):

	# Checks if file exists
	if(os.path.isfile(fileName)):

		# Opens the file to read it as binary
		with open(fileName, "rb") as file:

			# Reads the encrypted encoded file
			file_string = file.read()

			# Decrypts it back to its normal state with the key and iv
			plainTextFile = myDecrypt(file_string,EncKey,iv)
		
		# Opens the file to overwrite it as binary
		with open(fileName, "wb") as file:
			file.write(plainTextFile)
			file.close()

# Given the same file you want to decrypt and the same key, IV, and tag used to encrypt
def myFileDecryptMAC(fileName, EncKey, HmacKey, iv, tag):

	# Checks if file exists
	if(os.path.isfile(fileName)):

		# Opens the file to read it as binary
		with open(fileName, "rb") as file:

			# Reads the encrypted encoded file
			file_string = file.read()

			# Decrypts it back to its normal state with the key and iv
			plainTextFile = myDecryptMAC(file_string, EncKey, HmacKey, iv, tag)
		
		# Opens the file to overwrite it as binary
		with open(fileName, "wb") as file:
			file.write(plainTextFile)
			file.close()


# Here we remove the padding
def removePadding(padded_encoded):

	# We unpad it using 128 bits or 16 bytes
	unpadder = padding.PKCS7(constants.CONST_PADDING_BITS).unpadder()

	# update() unpads the padded encoded message
	unpadded_encoded = unpadder.update(padded_encoded)

	# finalize() Returns the remainder of the data.
	unpadded_encoded += unpadder.finalize()
	return unpadded_encoded