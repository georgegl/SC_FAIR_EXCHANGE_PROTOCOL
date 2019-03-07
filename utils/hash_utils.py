import hashlib


def get_sha256_hash(key):
    return hashlib.sha256(key.encode('UTF-8')).digest()
