from BWConnect import ConnectionHandler
from collections import OrderedDict
import BitwardenDecrypt as BD
import json
import re

bwc = ConnectionHandler("https://VAULTWARDEN_URL", "EMAIL", "PASSWORD","TWO_FACTOR_AUTH_SECRET")

BD.getBitwardenSecrets(
    bwc.email,
    bwc.password.encode("utf-8"),
    bwc.preLoginData['kdfIterations'],
    bwc.preLoginData['kdfParallelism'],
    bwc.preLoginData['kdfMemory'],
    bwc.preLoginData['kdf'],
    bwc.vaultData["profile"]["key"], #_masterPassword_masterKeyEncryptedUserKey
    bwc.vaultData["profile"]["privateKey"] #_crypto_privateKey
)

regexPattern = re.compile(r"\d\.[^,]+\|[^,]+=+")
decryptedEntries = OrderedDict()

BD.BitwardenSecrets['OrgSecrets'] = {}
organizationKeys = bwc.vaultData['profile']['organizations']

for organization in organizationKeys:
    BD.BitwardenSecrets['OrgSecrets'][organization["id"]] = BD.decryptRSA(organization['key'], BD.BitwardenSecrets['RSAPrivateKey'])

for a in bwc.vaultData:
    supportedGroups = ['folders', 'ciphers', 'collections', 'organizations', 'sends']

    for group in supportedGroups:
        if (any(x in a for x in supportedGroups)):
            group = a
        else:
            group = None
    
    if group:
        groupItemsList = []
        for b in bwc.vaultData[group]:
            groupEntries = list(b)
            for groupItem in groupEntries:
                if type(b[groupItem]) is dict:
                    tempString = json.dumps(b[groupItem])
                    if group == "sends":
                        tempString = BD.decryptSend(b)
                    else:
                        try:
                            if b.get('organizationId') is None:
                                encKey = BD.BitwardenSecrets['GeneratedEncryptionKey']
                                macKey = BD.BitwardenSecrets['GeneratedMACKey']
                            else:
                                encKey = BD.BitwardenSecrets['OrgSecrets'][b['organizationId']][0:32]
                                macKey = BD.BitwardenSecrets['OrgSecrets'][b['organizationId']][32:64]
                            
                            if b[groupItem].get('key', None) is None:
                                cipherEncKey = encKey
                                cipherMacKey = macKey
                            else:
                                cipherKey, cipherEncKey, cipherMacKey = BD.decryptProtectedSymmetricKey(b[groupItem].get('key'), encKey, macKey)

                            for match in regexPattern.findall(tempString):
                                jsonEscapedString = json.JSONEncoder().encode(BD.decryptCipherString(match, cipherEncKey, cipherMacKey))
                                jsonEscapedString = jsonEscapedString[1:(len(jsonEscapedString)-1)]
                                tempString = tempString.replace(match, jsonEscapedString)
                                tempString = tempString.replace('"key": "ERROR: MAC did not match. CipherString not decrypted."', '"key": ""')
                        except Exception as e:
                            print(f"ERROR: Could Not Determine encKey/macKey for: {groupItem.get('id')}")

                    groupItemsList.append(json.loads(tempString))
            decryptedEntries[group] = groupItemsList

with open("vaultData.json", 'w', encoding='utf8') as file:
    json.dump(bwc.vaultData, file, ensure_ascii=False, indent=4)
    
with open("vaultData_decrypted.json", 'w', encoding='utf8') as file:
    json.dump(decryptedEntries, file, ensure_ascii=False, indent=4)