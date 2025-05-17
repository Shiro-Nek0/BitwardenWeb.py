from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import requests
import base64
import pyotp
import time
import uuid
import json
import os

class ConnectionHandler:
    def __init__(self, url, email, password, totpSecret):
        self.url = url
        self.email = email
        self.password = password
        self.totp = pyotp.TOTP(totpSecret)
        self.persistentData = self.getPersData()

        self.bwClientData = {
            'userAgent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
            'clientId': self.persistentData['guid'],
            'clientName': "web",
            'clientVersion': "2025.1.1",
            'deviceType': "10",
            'isPrerelease': "1",
            'base64Email': base64.b64encode(self.email.encode()).decode()
        }
 
        self.isKnown = self.knownDevice()
        self.preLoginData = self.preLogin()
        self.tokenData = self.getToken()
        self.vaultData = self.syncData(self.tokenData)
        #self.configData = self.config(self.tokenData)

    def getPersData(self):
        file_path = 'persData.json'
        persData = {}

        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf8') as file:
                persData = json.load(file)
        else:
            persData = {
                'guid': str(uuid.uuid4()),
                'refresh_token': "",
                'tokenUnixCreation': 0
            }
            with open(file_path, 'w', encoding='utf8') as file:
                json.dump(persData, file, ensure_ascii=False, indent=4)
        return persData

    def setPersData(self):
        file_path = 'persData.json'
        with open(file_path, 'w', encoding='utf8') as file:
            json.dump(self.persistentData, file, ensure_ascii=False, indent=4)


    def getMasterPasswordHash(self): 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes(self.email, 'utf-8'),
            iterations=self.preLoginData['kdfIterations'],
            backend=default_backend()
        )
        masterKey = kdf.derive(self.password.encode())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes(self.password.encode()),
            iterations=1,
            backend=default_backend()
        )
        return base64.b64encode(kdf.derive(masterKey)).decode('utf-8')

    def knownDevice(self):
        headers = {
            #'Accept': 'application/json',
            'Bitwarden-Client-Name': self.bwClientData['clientName'],
            'Bitwarden-Client-Version': self.bwClientData['clientVersion'],
            #'device-type': self.bwClientData['deviceType'],
            #'is-prerelease': self.bwClientData['isPrerelease'],
            #'User-Agent': self.bwClientData['userAgent'],
            'x-device-identifier': self.bwClientData["clientId"],
            'x-request-email': self.bwClientData['base64Email']
        }

        response = requests.get(f"{self.url}/api/devices/knowndevice", headers=headers).json()
        return response
        
    def preLogin(self):
        headers = {
            #'Accept': 'application/json',
            'Bitwarden-Client-Name': self.bwClientData['clientName'],
            'Bitwarden-Client-Version': self.bwClientData['clientVersion'],
            #'device-type': self.bwClientData['deviceType'],
            #'DNT': 1,
            #'is-prerelease': self.bwClientData['isPrerelease'],
            #'User-Agent': self.bwClientData['userAgent'],
        }
        
        data = {
            'email': self.email
        }

        response = requests.post(f"{self.url}/identity/accounts/prelogin", headers=headers, data=json.dumps(data)).json()
        return response
    
    def getToken(self, twoFactorToken = ""):
        if(self.persistentData["refresh_token"] == "" and self.persistentData["tokenUnixCreation"] < time.time() + 7200000):
            tfaRemember = "0"
            tfaProvider = "5"
            
            if (len(twoFactorToken) == 6):
                tfaRemember = "1"
                tfaProvider = "0"

            headers = {
                #'Accept': 'application/json',
                'auth-email': self.bwClientData['base64Email'],
                'Bitwarden-Client-Name': self.bwClientData['clientName'],
                'Bitwarden-Client-Version': self.bwClientData['clientVersion'],
                #'device-type': self.bwClientData['deviceType'],
                #'DNT': 1,
                #'User-Agent': self.bwClientData['userAgent'],
            }

            data = {
                'scope': 'api offline_access',
                'client_id': self.bwClientData['clientName'],
                'deviceType': self.bwClientData['deviceType'],
                'deviceIdentifier': self.bwClientData["clientId"],
                'deviceName': 'firefox',
                'grant_type': 'password',
                'username': self.email,
                'password': self.getMasterPasswordHash()
            }
            if twoFactorToken:
                data.update({
                    'twoFactorToken': twoFactorToken,
                    'twoFactorProvider': tfaProvider,
                    'twoFactorRemember': tfaRemember,
                })

            response = requests.post(f'{self.url}/identity/connect/token', headers=headers, data=data).json()
            if("error_description" in response):
                if(response["error_description"] == "Two factor required."):
                    return self.getToken(self.totp.now())
                elif (response["error_description"] == ""):
                    print("Invalid TOTP code!")
                    quit()
            self.persistentData["refresh_token"] = response["refresh_token"]
            self.persistentData["tokenUnixCreation"] = time.time()
            self.setPersData()
        else:
            response = self.refreshToken(self.persistentData["refresh_token"])
        return response

    def refreshToken(self, refreshToken):
        headers = {
            #'Accept': 'application/json',
            'auth-email': self.bwClientData['base64Email'],
            'Bitwarden-Client-Name': self.bwClientData['clientName'],
            'Bitwarden-Client-Version': self.bwClientData['clientVersion'],
            #'device-type': self.bwClientData['deviceType'],
            #'DNT': 1,
            #'User-Agent': self.bwClientData['userAgent'],
        }

        data = {
            'grant_type': 'refresh_token',
            'client_id': self.bwClientData["clientId"],
            'refresh_token': refreshToken
        }

        response = requests.post(f'{self.url}/identity/connect/token', headers=headers, data=data).json()
        self.persistentData["refresh_token"] = response["refresh_token"]
        self.persistentData["tokenUnixCreation"] = time.time()
        self.setPersData()
        return response

    # def config(self, tokenData):
    #     headers = {
    #         #'Accept': 'application/json',
    #         'Authorization': f"Bearer {tokenData['access_token']}",
    #         'Bitwarden-Client-Name': self.bwClientData['clientName'],
    #         'Bitwarden-Client-Version': self.bwClientData['clientVersion'],
    #         #'device-type': self.bwClientData['deviceType'],
    #         #'is-prerelease': self.bwClientData['isPrerelease'],
    #         #'User-Agent': self.bwClientData['userAgent'],
    #     }

    #     response = requests.get(f"{self.url}/api/config", headers=headers).json()
    #     return response

    # def getProfile(self,tokenData):
    #     headers = {
    #         #'Accept': 'application/json',
    #         'auth-email': self.bwClientData['base64Email'],
    #         'Authorization': f"Bearer {tokenData['access_token']}",
    #         'Bitwarden-Client-Name': self.bwClientData['clientName'],
    #         'Bitwarden-Client-Version': self.bwClientData['clientVersion'],
    #         #'device-type': self.bwClientData['deviceType'],
    #         #'is-prerelease': self.bwClientData['isPrerelease'],
    #         #'User-Agent': self.bwClientData['userAgent'],
    #     }

    #     response = requests.get(f"{self.url}/api/config", headers=headers).json()
    #     return response
            
    def syncData(self, tokenData):
        headers = {
            #'Accept': 'application/json',
            'auth-email': self.bwClientData['base64Email'],
            'Authorization': f"Bearer {tokenData['access_token']}",
            'Bitwarden-Client-Name': self.bwClientData['clientName'],
            'Bitwarden-Client-Version': self.bwClientData['clientVersion'],
            #'device-type': self.bwClientData['deviceType'],
            #'is-prerelease': self.bwClientData['isPrerelease'],
            #'User-Agent': self.bwClientData['userAgent'],
        }

        params = {
            'excludeDomains': 'true'
        }

        response = requests.get(f'{self.url}/api/sync', headers=headers, params=params).json()
        return response
