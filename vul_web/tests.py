from vul_web.Encrypt import encrypt
import json
import hashlib
def generate_token(account):
    f = open("../vul_web/Encrypt/config","rb")

    load_config  = json.loads(f.read())
    f.close()
    salt_key = str(load_config["SALT_KEY"])+"_"+account
    salt_key_encrypted = encrypt.ecb_mode(salt_key.encode())
    print(salt_key_encrypted)
    salt_key_string = ""
    for i in salt_key_encrypted:
        salt_key_string+=str(i)
    print(salt_key_string)

    token_hash = hashlib.sha256(account.encode()).hexdigest()
    return token_hash
token = generate_token("admin")