from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA


def get_signature_f(message, rsa_key_path):
    rsa_key_obj = RSA.importKey(open(rsa_key_path).read())
    hash_obj = SHA.new()
    hash_obj.update(message)
    sign_obj = PKCS1_PSS.new(rsa_key_obj)
    signature = sign_obj.sign(hash_obj)

    return signature


def get_signature_s(message, rsa_key):
    rsa_key_obj = RSA.importKey(rsa_key)
    hashed_message = SHA.new(message)
    sign_obj = PKCS1_PSS.new(rsa_key_obj)
    signature = sign_obj.sign(hashed_message)

    return signature


def is_authentic_f(message, signature, rsa_key_path):
    rsa_key_obj = RSA.importKey(open(rsa_key_path).read())
    hashed_message = SHA.new(message)
    verifier = PKCS1_PSS.new(rsa_key_obj)
    result = verifier.verify(hashed_message, signature)

    return result


def is_authentic_s(message, signature, rsa_key):
    rsa_key_obj = RSA.importKey(rsa_key)
    hashed_message = SHA.new(message)
    verifier = PKCS1_PSS.new(rsa_key_obj)
    result = verifier.verify(hashed_message, signature)

    return result
