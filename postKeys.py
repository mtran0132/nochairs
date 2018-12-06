import os, requests, json, encryption, decryption, rsakeys

def main():
    URL = "https://marcoptran.com/api/v1/login"

    PARAMS = {'name':'admin', 'password':'adminpassword'} 
  
    # sending get request and saving the response as response object 
    r = requests.post(url = URL, data = PARAMS) 
  
    # extracting data in json format 
    
    data = r.json()

    print(data)

main()