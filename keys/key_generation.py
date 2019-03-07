import os

from Crypto.PublicKey import RSA
from utils import constants

KEYS_DIR = os.path.dirname(os.path.abspath(__file__))


def generate_merchant_keys():
    merchant_rsa_key = RSA.generate(2048)
    f = open(constants.MERCHANT_PRIVATE_KEY_PATH, 'w')
    f.write(merchant_rsa_key.exportKey('PEM').decode('UTF-8'))
    f.close()

    f = open(constants.MERCHANT_PUBLIC_KEY_PATH, 'w')
    f.write(merchant_rsa_key.publickey().exportKey('PEM').decode('UTF-8'))
    f.close()

    print("Merchant public and private RSA keys has been generated.")


def generate_payment_gateway_keys():
    merchant_rsa_key = RSA.generate(2048)
    f = open(constants.PAYMENT_GATEWAY_PRIVATE_KEY, 'w')
    f.write(merchant_rsa_key.exportKey('PEM').decode('UTF-8'))
    f.close()

    f = open(constants.PAYMENT_GATEWAY_PUBLIC_KEY, 'w')
    f.write(merchant_rsa_key.publickey().exportKey('PEM').decode('UTF-8'))
    f.close()

    print("Payment gateway public and private RSA keys has been generated.")


def generate_all_keys():
    generate_payment_gateway_keys()
    generate_merchant_keys()

# generate_merchant_keys()
# generate_payment_gateway_keys()
