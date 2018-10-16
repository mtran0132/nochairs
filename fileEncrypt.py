# Group 2 Marco Tran, Fa Fu
# Will implement a module that saves the key and iv
# So that you can encrypt the file, exit the program, then run it again to decrypt it.

import os, base64, constants, encryption, decryption

def main():
	# Creates random 32 bytes
	key = os.urandom(constants.CONST_KEY_BYTES)
	hmacKey = os.urandom(constants.CONST_HMACKEY_BYTES)

	message = b"This is a secret message. ATTACK AT DAWN FROM THE NORTH."
	print("Original Message: ", message,"\n")
	
	(cipherText, iv) = encryption.myEncrypt(message, key)
	print("Cipher Text: ", cipherText, "\n")
	
	plainText = decryption.myDecrypt(cipherText, key, iv)
	print("Plain Text: ", plainText,"\n")
		
	######## HMAC SECTION #########
	hmacMessage = b"HMAC HERE WE GO, YAAAAS"
	print("Original message: ", hmacMessage)

	(cipherText, IV, tag) = encryption.myEncryptMAC(hmacMessage, key, hmacKey)
	print("Cipher Text: ", cipherText)

	plainText = decryption.myDecryptMAC(cipherText, key, hmacKey, IV, tag)
	print("Plain Text: ", plainText)
	
	print("----------------------------------------------")
	print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	print("----------------------------------------------")			
	print("File Encryption with HMAC")
	fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")
	while(fileChoice != "exit"):

		if(os.path.isfile(fileChoice)):

			(fileCipherText, fileIv, fileTag, fileEncKey, fileHmacKey, fileExt) = encryption.myFileEncryptMAC(fileChoice)
			dummy_text = input("Check the file to see if it is encrypted!\nThen press enter\n")
			decryption.myFileDecryptMAC(fileChoice, fileEncKey, fileHmacKey, fileIv, fileTag)
			print("File should be decrypted now")
			fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")

		else:
			print("File doesn't exist, try again")
			fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")


	# print("----------------------------------------------")
	# print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	# print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	# print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	# print("----------------------------------------------")


	# print("File Encryption")
	# fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")
	# while(fileChoice != "exit"):

	# 	if(os.path.isfile(fileChoice)):

	# 		(fileCipherText, fileIv, fileKey, fileExt) = encryption.myFileEncrypt(fileChoice)
	# 		dummy_text = input("Check the file to see if it is encrypted!\nThen press enter\n")
	# 		decryption.myFileDecrypt(fileChoice, fileKey, fileIv)
	# 		print("File should be decrypted now")
	# 		fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")

	# 	else:
	# 		print("File doesn't exist, try again")
	# 		fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")

main()