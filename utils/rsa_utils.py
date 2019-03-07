from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def encrypt_rsa_f(plaintext, rsa_key_path):
    m_pubk_obj = RSA.importKey(open(rsa_key_path, 'r').read())
    aoep_obj = PKCS1_OAEP.new(m_pubk_obj)
    ciphertext = aoep_obj.encrypt(plaintext)

    return ciphertext


def decrypt_rsa_f(ciphertext, rsa_key_path):
    m_privk_obj = RSA.importKey(open(rsa_key_path, 'r').read())
    aoep_obj = PKCS1_OAEP.new(m_privk_obj)
    plaintext = aoep_obj.decrypt(ciphertext)

    return plaintext


def encrypt_rsa_s(plaintext, rsa_key):
    m_pubk_obj = RSA.importKey(rsa_key)
    aoep_obj = PKCS1_OAEP.new(m_pubk_obj)
    ciphertext = aoep_obj.encrypt(plaintext)

    return ciphertext


def decrypt_rsa_s(ciphertext, rsa_key):
    m_privk_obj = RSA.importKey(rsa_key)
    aoep_obj = PKCS1_OAEP.new(m_privk_obj)
    plaintext = aoep_obj.decrypt(ciphertext)

    return plaintext
