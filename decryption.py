import os, base64, constants
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization, asymmetric

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

def myDecryptMAC(cipherText, enc_key, hmac_key, iv, tag):
	if(len(enc_key) < constants.CONST_KEY_BYTES):
		print("Error: key length less than 32 bytes")
		return

	h = hmac.HMAC(hmac_key, hashes.SHA256(), backend = default_backend())
	h.update(cipherText)
	hashTest = h.finalize() 
	# If the hash is the same, meaning ciphertext has not been modified

	if(tag == hashTest):
		
		# Here we set the parameters for the decryptor	
		decryptor = Cipher(
					algorithms.AES(enc_key), 
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
def myFileDecrypt(file_path, enc_key, iv):

	# Checks if file exists
	if(os.path.isfile(file_path)):

		# Opens the file to read it as binary
		with open(file_path, "rb") as file:

			# Reads the encrypted encoded file
			file_string = file.read()

			# Decrypts it back to its normal state with the key and iv
			plainTextFile = myDecrypt(file_string,enc_key,iv)
		
		# Opens the file to overwrite it as binary
		with open(file_path, "wb") as file:
			file.write(plainTextFile)
			file.close()

# Given the same file you want to decrypt and the same key, IV, and tag used to encrypt
def myFileDecryptMAC(file_path, enc_key, hmac_key, iv, tag):

	# Checks if file exists
	if(os.path.isfile(file_path)):

		# Opens the file to read it as binary
		with open(file_path, "rb") as file:

			# Reads the encrypted encoded file
			file_string = file.read()

			# Decrypts it back to its normal state with the key and iv
			plainTextFile = myDecryptMAC(file_string, enc_key, hmac_key, iv, tag)
		
		# Opens the file to overwrite it as binary
		with open(file_path, "wb") as file:
			file.write(plainTextFile)
			file.close()

def myRSADecrypt (RSACipher, C, iv, tag, ext, RSA_Privatekey_filepath):
	hmac_key = ""
	enc_key = ""
	key = ""
	if(os.path.isfile(RSA_Privatekey_filepath)):
		with open(RSA_Privatekey_filepath, "rb") as key_file:
			private_key = serialization.load_pem_private_key(
				key_file.read(),
				password=None,
				backend=default_backend()
				)

			key = private_key.decrypt(
				RSACipher,
				asymmetric.padding.OAEP(
					mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
					algorithm=hashes.SHA256(),
					label=None)
				)
			enc_key_start = 0
			enc_key_end = int((len(key)/2))
			hmac_key_start = enc_key_end
			hmac_key_end = int(len(key))  
			enc_key = key[enc_key_start:enc_key_end]
			hmac_key = key[hmac_key_start:hmac_key_end]
			key_file.close()

		myFileDecryptMAC(C, enc_key, hmac_key, iv, tag)

	else:
		print("Private key not found!\nDecryption failed.")

def endRansom():
	for dirName, subDirList, fileList in os.walk(os.getcwd()):
		for fileName in fileList:
			print(fileName)
			with open(fileName) as json_file:
				data = json.load(json_file)
				print(data)

# Here we remove the padding
def removePadding(padded_encoded):

	# We unpad it using 128 bits or 16 bytes
	unpadder = padding.PKCS7(constants.CONST_PADDING_BITS).unpadder()

	# update() unpads the padded encoded message
	unpadded_encoded = unpadder.update(padded_encoded)

	# finalize() Returns the remainder of the data.
	unpadded_encoded += unpadder.finalize()
	return unpadded_encoded