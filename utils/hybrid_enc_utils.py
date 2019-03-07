from utils import hash_utils
from utils import rsa_utils
from utils import aes_utils


def hybrid_encrypt_rsa_f(message, aes_password, rsa_key_path):
    aes_key = hash_utils.get_sha256_hash(aes_password)

    message_encrypted_with_aes = aes_utils.encrypt_aes_ecb(aes_key, message)
    aes_key_encrypted_with_rsa_key = rsa_utils.encrypt_rsa_f(aes_key, rsa_key_path)

    return message_encrypted_with_aes, aes_key_encrypted_with_rsa_key


def hybrid_decrypt_rsa_f(message_encrypted_with_aes, aes_key_encrypted_with_rsa_key, rsa_key_path):
    aes_key = rsa_utils.decrypt_rsa_f(aes_key_encrypted_with_rsa_key, rsa_key_path)
    decrypted_message = aes_utils.decrypt_aes_ecb(aes_key, message_encrypted_with_aes)

    return decrypted_message


def hybrid_encrypt_rsa_s(message, aes_password, rsa_key):
    aes_key = hash_utils.get_sha256_hash(aes_password)

    message_encrypted_with_aes = aes_utils.encrypt_aes_ecb(aes_key, message)
    aes_key_encrypted_with_rsa_key = rsa_utils.encrypt_rsa_s(aes_key, rsa_key)

    return message_encrypted_with_aes, aes_key_encrypted_with_rsa_key


def hybrid_decrypt_rsa_s(message_encrypted_with_aes, aes_key_encrypted_with_rsa_key, rsa_key):
    aes_key = rsa_utils.decrypt_rsa_s(aes_key_encrypted_with_rsa_key, rsa_key)
    decrypted_message = aes_utils.decrypt_aes_ecb(aes_key, message_encrypted_with_aes)

    return decrypted_message
