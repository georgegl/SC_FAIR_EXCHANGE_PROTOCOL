import pickle
import socket

from Crypto.PublicKey import RSA

from utils import constants
from utils import hybrid_enc_utils
from utils import signature_utils

AES_PASSWORD = "clientpassword"


def client():
    client_rsa_obj = RSA.generate(2048)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", constants.MERCHANT_PORT))

    sid = setup_sub_protocol(s, client_rsa_obj)

    exchange_sub_protocol(s, client_rsa_obj, sid)


def setup_sub_protocol(connection, client_rsa_obj):
    client_pubk_obj = client_rsa_obj.publickey()
    client_pubk = client_pubk_obj.exportKey()

    # STEP 1

    client_pubk_packet = hybrid_enc_utils.hybrid_encrypt_rsa_f(client_pubk.decode('UTF-8'), AES_PASSWORD,
                                                               constants.MERCHANT_PUBLIC_KEY_PATH)
    serialized_client_pubk_packet = pickle.dumps(client_pubk_packet)
    connection.send(serialized_client_pubk_packet)
    print("C: STEP 1:Sent data to merchant!")

    # STEP 2

    serialized_sid_packet = connection.recv(4096)
    print("C: STEP 2:Received data from merchant!")

    sid_message_encrypted_with_aes, aes_key_encrypted_with_rsa_key = pickle.loads(serialized_sid_packet)
    sid, sid_signature_hex = hybrid_enc_utils.hybrid_decrypt_rsa_s(sid_message_encrypted_with_aes,
                                                                   aes_key_encrypted_with_rsa_key,
                                                                   client_rsa_obj.exportKey()).split(",", 1)

    if signature_utils.is_authentic_f(sid.encode('UTF-8'), bytes.fromhex(sid_signature_hex),
                                      constants.MERCHANT_PUBLIC_KEY_PATH):
        print("C: STEP 2:(" + str(sid) + ") Sid is valid!")
    else:
        print("C: STEP 2:(" + str(sid) + ") Sid is NOT valid!")

    return sid


def exchange_sub_protocol(connection, client_rsa_obj, sid):
    client_pubk_obj = client_rsa_obj.publickey()
    client_pubk = client_pubk_obj.exportKey()
    client_nounce = 0

    # STEP 3

    payment_info = constants.CARDNUMBER + "," + constants.CARD_EXP + "," + constants.CCODE + "," + str(
        sid) + "," + constants.AMOUNT + "," + client_pubk.decode("UTF-8") + "," + str(client_nounce)
    payment_info_signature = signature_utils.get_signature_s(payment_info.encode("UTF-8"), client_rsa_obj.exportKey())

    payment_message_encrypted_with_aes, aes_key_encrypted_with_rsa_key = hybrid_enc_utils.hybrid_encrypt_rsa_f(
        payment_info + "," + payment_info_signature.hex(),
        AES_PASSWORD, constants.PAYMENT_GATEWAY_PUBLIC_KEY)

    payment_order_info = constants.ORDER_DESC + "," + str(sid) + "," + constants.AMOUNT
    payment_order_signature = signature_utils.get_signature_s(payment_order_info.encode("UTF-8"),
                                                              client_rsa_obj.exportKey())
    payment_order_packet = payment_order_info + "," + payment_order_signature.hex()

    packet = payment_message_encrypted_with_aes.hex() + ',' + aes_key_encrypted_with_rsa_key.hex() + ',' + payment_order_packet

    encrypted_packet = hybrid_enc_utils.hybrid_encrypt_rsa_f(packet, AES_PASSWORD, constants.MERCHANT_PUBLIC_KEY_PATH)

    serialized_encrypted_packet = pickle.dumps(encrypted_packet)

    connection.send(serialized_encrypted_packet)
    print("C: STEP 3:(" + str(sid) + ") Sent data to merchant!")

    # STEP 6

    response_message = bytearray()
    try:
        connection.settimeout(5)
        response_message = connection.recv(4096)
        print("C: STEP 6:(" + str(sid) + ") Received data from merchant!")

        connection.settimeout(None)
    except:
        resolution_protocol(sid, constants.AMOUNT, client_nounce, client_rsa_obj)
        return

    encrypted_response_message, aes_key = pickle.loads(response_message)

    decrypted_response_message = hybrid_enc_utils.hybrid_decrypt_rsa_s(encrypted_response_message, aes_key,
                                                                       client_rsa_obj.exportKey())

    pg_response_code, pg_sid, pg_amount, pg_nounce, code_sid_amount_nc_signature = tuple(
        decrypted_response_message.split(','))

    is_code_sid_amount_nc_valid = signature_utils.is_authentic_f(
        (pg_response_code + ',' + pg_sid + ',' + pg_amount + ',' + pg_nounce).encode('UTF-8'),
        bytes.fromhex(code_sid_amount_nc_signature), constants.PAYMENT_GATEWAY_PUBLIC_KEY)

    if is_code_sid_amount_nc_valid:
        print("C: STEP 6:(" + str(sid) + ") Response code, sid, amount and nounce are valid!")
    else:
        print("C: STEP 6:(" + str(sid) + ") Response code, sid, amount and nounce are NOT valid!")

    if (pg_sid, pg_nounce) == (sid, str(client_nounce)):
        print("C: STEP 6:(" + str(sid) + ") Sid and nounce are correct!")
    else:
        print("C: STEP 6:(" + str(sid) + ") Sid nounce are NOT correct!")

    if pg_response_code is '3':
        print("C: STEP 6:(" + str(sid) + ") Successfull transaction!")
    elif pg_response_code is '2':
        print("C: STEP 6:(" + str(sid) + ") Insufficient funds!")
    else:
        print("C: STEP 6:(" + str(sid) + ") Invalid data!")


def resolution_protocol(sid, amount, nounce, client_rsa_obj):
    client_pubk_obj = client_rsa_obj.publickey()
    client_pubk = client_pubk_obj.exportKey()

    # STEP 7
    print("C: STEP 7:(" + str(sid) + ") Timeout occured, resolution protocol initiated!")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", constants.PAYMENT_GATEWAY_PORT))

    resolution_message = str(sid) + ',' + str(amount) + ',' + str(nounce) + ',' + client_pubk.hex()

    resolution_message_signature = signature_utils.get_signature_s(resolution_message.encode('UTF-8'),
                                                                   client_rsa_obj.exportKey())
    encrpyted_resolution_message = hybrid_enc_utils.hybrid_encrypt_rsa_f(
        resolution_message + ',' + resolution_message_signature.hex(), AES_PASSWORD,
        constants.PAYMENT_GATEWAY_PUBLIC_KEY)

    serialized_resolution_message = pickle.dumps(encrpyted_resolution_message)

    s.send(serialized_resolution_message)
    print("C: STEP 7:(" + str(sid) + ") Sent message to PG!")


    # STEP 8

    serialized_resolution_response = s.recv(4096)
    print("C: STEP 8:(" + str(sid) + ") Received message from PG!")

    encrypted_resolution_message, aes_key = pickle.loads(serialized_resolution_response)

    decrypted_message = hybrid_enc_utils.hybrid_decrypt_rsa_s(encrypted_resolution_message, aes_key,
                                                              client_rsa_obj.exportKey())

    response_code, recv_sid, code_sig_signature = tuple(decrypted_message.split(','))

    is_code_sid_valid = signature_utils.is_authentic_f((response_code + ',' + recv_sid).encode('UTF-8'),
                                                       bytes.fromhex(code_sig_signature),
                                                       constants.PAYMENT_GATEWAY_PUBLIC_KEY)

    if is_code_sid_valid:
        print("C: STEP 8:(" + str(sid) + ") Response code and Sid are valid!")
    else:
        print("C: STEP 8:(" + str(sid) + ") Response code and Sid are NOT valid!")

    if response_code is '3':
        print("C: STEP 8:(" + str(sid) + ") Successfull transaction!")
    elif response_code is '2':
        print("C: STEP 8:(" + str(sid) + ") Insufficient funds!")
    elif response_code is '1':
        print("C: STEP 8:(" + str(sid) + ") Invalid data!")
    else:
        print("C: STEP 8:(" + str(sid) + ") Transaction have not reached the PG!")


client()
