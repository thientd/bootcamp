from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def load_key(file_to_key):
    private_key_file = open(file_to_key, "rb")
    key = RSA.importKey(private_key_file.read())
    private_key_file.close()
    return key


def enc_data(message, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(message)
    return enc_session_key


def dec_data(cipher, key):
    cipher_rsa = PKCS1_OAEP.new(key)
    plain_text = cipher_rsa.decrypt(cipher)
    return plain_text
