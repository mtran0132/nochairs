# Group 2 Marco Tran, Fa Fu
# Will implement a module that saves the key and iv
# So that you can encrypt the file, exit the program, then run it again to decrypt it.
# TO DO: Add error/exception handling

import os, base64, constants, encryption, decryption, rsakeys

def main():
	# Creates random 32 bytes
	encKey = os.urandom(constants.CONST_KEY_BYTES)
	hmacKey = os.urandom(constants.CONST_HMACKEY_BYTES)

	#rsakeys.createKeyPair(os.getcwd())
	(RSACipher, cipherFile, iv, tag, fileExt) = encryption.myRSAEncrypt("hello.txt","public_key")
	pause = input("Enter when finished")
	decryption.myRSADecrypt(RSACipher,"hello.txt",iv,tag,fileExt,"private_key")
	message = b"This is a secret message. ATTACK AT DAWN FROM THE NORTH."
	print("Original Message: ", message,"\n")
	
	(cipherText, iv) = encryption.myEncrypt(message, encKey)
	print("Cipher Text: ", cipherText, "\n")
	
	plainText = decryption.myDecrypt(cipherText, encKey, iv)
	print("Plain Text: ", plainText,"\n")
		
	######## HMAC SECTION #########
	hmacMessage = b"HMAC HERE WE GO, YAAAAS"
	print("Original message: ", hmacMessage)

	(cipherText, IV, tag) = encryption.myEncryptMAC(hmacMessage, encKey, hmacKey)
	print("Cipher Text: ", cipherText)

	plainText = decryption.myDecryptMAC(cipherText, encKey, hmacKey, IV, tag)
	print("Plain Text: ", plainText)
	
	print("----------------------------------------------")
	print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	print("DO NOT CHOOSE A FILE THAT IS IMPORTANT!!!!!!!")
	print("DO NOT CLOSE THE PROGRAM UNTIL CHOSEN FILE IS DECRYPTED!!!!!!!")
	print("DO NOT CLOSE THE PROGRAM UNTIL CHOSEN FILE IS DECRYPTED!!!!!!!")
	print("DO NOT CLOSE THE PROGRAM UNTIL CHOSEN FILE IS DECRYPTED!!!!!!!")
	print("----------------------------------------------")			
	print("File Encryption with HMAC")
	fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")
	while(fileChoice != "exit"):

		if(os.path.isfile(fileChoice)):

			(fileCipherText, fileIv, fileTag, fileEncKey, fileHmacKey, fileExt) = encryption.myFileEncryptMAC(fileChoice)
			print("You encrypted a ", fileExt, " file.")
			dummy_text = input("Check the file to see if it is encrypted!\nThen press enter\n")
			decryption.myFileDecryptMAC(fileChoice, fileEncKey, fileHmacKey, fileIv, fileTag)
			print(fileChoice, "should be decrypted now")
			fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")

		else:
			print("File doesn't exist, try again")
			fileChoice = input("Which file to encrypt? Otherwise, 'exit' to exit: ")

main()