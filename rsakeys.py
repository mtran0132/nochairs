import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def doesKeyPairExist(file_path):
	private_key_path = os.path.join(file_path, constants.CONST_PRIVATE_KEY)
	public_key_path = os.path.join(file_path, constants.CONST_PUBLIC_KEY)

	if(os.path.isfile(private_key_path) and os.path.isfile(public_key_path)):
		return True
	return False

def createPrivateKey(file_path):
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
		)

	pem = private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())

	output_path = os.path.join(file_path, constants.CONST_PRIVATE_KEY)
	createFile(output_path, pem)
	return private_key


def createPublicKey(private_key, file_path):
	public_key = private_key.public_key()
	pem = public_key
	pem = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
    	format=serialization.PublicFormat.SubjectPublicKeyInfo
    	)
	output_path = os.path.join(file_path,constants.CONST_PUBLIC_KEY)
	createFile(output_path,pem)


def createFile(fileName, pem):
	with open(fileName, 'wb') as file:
		for line in pem.splitlines():
			file.write(line)
			file.write(b"\n")
		file.close()

def createKeyPair(file_path):
	if(doesKeyPairExist(file_path)):
		print("Key Pair already exists.\n")
	else:
		print("Key Pair does not exist.\nCreating Key Pair...\n")
		private_key = createPrivateKey(file_path)
		createPublicKey(private_key, file_path)
