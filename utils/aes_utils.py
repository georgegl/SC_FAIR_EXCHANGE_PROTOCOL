from Crypto.Cipher import AES


def encrypt_aes_ecb(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(plaintext)
    return cipher.encrypt(padded_text)


def decrypt_aes_ecb(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext)).decode('UTF-8')


def pad(s):
    return s + (32 - len(s) % 32) * chr(32 - len(s) % 32)


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]
