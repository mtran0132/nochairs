# Group 2 Marco Tran, Fa Fu
# Will implement a module that saves the key and iv
# So that you can encrypt the file, exit the program, then run it again to decrypt it.

import os, base64, constants
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
def main():
	# Creates a random string of 32 bytes
	key = os.urandom(constants.CONST_KEY_BYTES)
	message = b"This is a secret message. ATTACK AT DAWN FROM THE NORTH."
	print("Original Message: ", message,"\n")
	(cipherText, IV) = myEncrypt(message, key)
	print("Cipher Text: ", cipherText, "\n")
	plainText = myDecrypt(cipherText, key, IV)
	print("Plain Text: ", plainText,"\n")
	print("----------------------------------------------")
	print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	print("----------------------------------------------")

	fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")
	while(fileChoice != "exit"):

		if(os.path.isfile(fileChoice)):

			(fileCipherText, fileIv, fileKey, fileExt) = myFileEncrypt(fileChoice)
			dummy_text = input("Check the file to see if it is encrypted!\nThen press enter\n")
			myFileDecrypt(fileChoice, fileKey, fileIv)
			print("File should be decrypted now")
			fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")

		else:
			print("File doesn't exist, try again")
			fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")


# Encrypts a message using a random key generated from the OS
def myEncrypt(message, key):

	if(len(key) < constants.CONST_KEY_BYTES):
		print("Error: key length less than 32 bytes")
		return
		
	# Creates a random string of 16 bytes
	iv = os.urandom(constants.CONST_IV_BYTES)

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
	if(len(key) < constants.CONST_KEY_BYTES):
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


# Given the same file you want to decrypt and the same key and IV used to encrypt
def myFileDecrypt(fileName, key, iv):

	# Checks if file exists
	if(os.path.isfile(fileName)):

		# Opens the file to read it as binary
		with open(fileName, "rb") as file:

			# Reads the encrypted encoded file
			file_string = file.read()

			# Decrypts it back to its normal state with the key and iv
			plainTextFile = myDecrypt(file_string,key,iv)
		
		# Opens the file to overwrite it as binary
		with open(fileName, "wb") as file:
			file.write(plainTextFile)
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


# Here we remove the padding
def removePadding(padded_encoded):

	# We unpad it using 128 bits or 16 bytes
	unpadder = padding.PKCS7(constants.CONST_PADDING_BITS).unpadder()

	# update() unpads the padded encoded message
	unpadded_encoded = unpadder.update(padded_encoded)

	# finalize() Returns the remainder of the data.
	unpadded_encoded += unpadder.finalize()
	return unpadded_encoded

main()

# Step 2:
# Modify your File Encryption to include the policy of Encrypt-then-MAC for every encryption.
# (C, IV, tag)= MyencryptMAC(message, EncKey, HMACKey)
# (C, IV, tag, Enckey, HMACKey, ext)= MyfileEncryptMAC (filepath)
# You will be asked to encrypt a JPEG file and then decrypt it and make sure you still can view the image.
# You can use SHA256 in your HMAC.
# Make sure to use github to commit and push all of your code so the instructor can see your source.