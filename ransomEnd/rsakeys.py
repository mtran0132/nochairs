import os, constants
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def doesKeyPairExist(file_path):
	private_key_path = os.path.join(file_path, constants.CONST_PRIVATE_KEY)
	public_key_path = os.path.join(file_path, constants.CONST_PUBLIC_KEY)

	if(os.path.isfile(private_key_path) and os.path.isfile(public_key_path)):
		return True
	return False

def createDirectory(directoryName):
	try:
		os.makedirs(directoryName)
		print('Creating directory: "%s"' % directoryName)

	except FileExistsError:
		print('Directory "%s" already exists' % directoryName)

def createRSAKeys(file_path):
	private_key = rsa.generate_private_key(
		public_exponent=constants.CONST_PUBLIC_EXPONENT,
		key_size= constants.CONST_RSA_KEY_SIZE,
		backend=default_backend()
		)

	pem = private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())

	output_path = os.path.join(file_path, constants.CONST_PRIVATE_KEY)
	createFile(output_path, pem)

	public_key = private_key.public_key()
	pem = public_key
	pem = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
    	format=serialization.PublicFormat.SubjectPublicKeyInfo
    	)

	output_path = os.path.join(file_path,constants.CONST_PUBLIC_KEY)
	createFile(output_path,pem)

def createFile(file_path, pem):
	with open(file_path, 'wb') as file:
		for line in pem.splitlines():
			file.write(line)
			file.write(b"\n")
		file.close()

def createKeyPair(file_path):
	if(doesKeyPairExist(file_path)):
		print("Key Pair already exists.\n")
	else:
		print("Key Pair does not exist.\nCreating Key Pair...\n")
		createRSAKeys(file_path)
