import decryption, api
def main():
	print("Pay me 100 olives then I'll give you the password")
	password = input("Password: ")
	while(password != "cecs378"):
		password = input("Password: ")
	api.downloadPrivateKey()
	decryption.endRansom()

main()
