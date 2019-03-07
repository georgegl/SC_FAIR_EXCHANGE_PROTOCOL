import socket
import pickle
import time
import random

from utils import constants
from utils import signature_utils
from utils import hybrid_enc_utils

AES_PASSWORD = "merchantpassword"


def merchant():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", constants.MERCHANT_PORT))
    s.listen(1)

    while True:
        (connection, address) = s.accept()

        sid, client_pubk = setup_sub_protocol(connection)

        exchange_sub_protocol(connection, client_pubk, sid)

        connection.close()


def setup_sub_protocol(connection):
    # STEP 1

    message = connection.recv(4096)
    print("M: STEP 1:Received data from client!")

    client_pubk_encrypted_with_aes, aes_key_encrypted_with_rsa_key = pickle.loads(message)

    client_pubk = hybrid_enc_utils.hybrid_decrypt_rsa_f(client_pubk_encrypted_with_aes,
                                                        aes_key_encrypted_with_rsa_key,
                                                        constants.MERCHANT_PRIVATE_KEY_PATH)

    # STEP 2

    sid = get_sid()
    sid_signature = signature_utils.get_signature_f(str(sid).encode('UTF-8'), constants.MERCHANT_PRIVATE_KEY_PATH)

    sid_message = hybrid_enc_utils.hybrid_encrypt_rsa_s(str(sid) + "," + str(sid_signature.hex()), AES_PASSWORD,
                                                        client_pubk)

    serialized_sid_message = pickle.dumps(sid_message)

    connection.send(serialized_sid_message)
    print("M: STEP 2:Sending data to client!")

    return sid, client_pubk


def exchange_sub_protocol(client_connection, client_pubk, sid):
    # STEP 3

    message = client_connection.recv(4096)
    print("M: STEP 3:(" + str(sid) + ")Received data from client!")

    payment_packets_encrypted_with_aes, aes_key_encrypted_with_rsa_key = pickle.loads(message)

    packet = hybrid_enc_utils.hybrid_decrypt_rsa_f(payment_packets_encrypted_with_aes, aes_key_encrypted_with_rsa_key,
                                                   constants.MERCHANT_PRIVATE_KEY_PATH)

    payment_message_encrypted_with_aes, aes_key_encrypted_with_rsa_key, order_desc, recv_sid, amount, signature = packet.split(
        ",")

    is_valid_payment_order = signature_utils.is_authentic_s(
        (order_desc + ',' + str(sid) + ',' + amount).encode('UTF-8'),
        bytes.fromhex(signature),
        client_pubk)

    if is_valid_payment_order:
        print("M: STEP 3:(" + str(sid) + ") Payment order is valid!")
    else:
        print("M: STEP 3:(" + str(sid) + ") Payment order is NOT valid!")

    if sid == int(recv_sid):
        print("M: STEP 3:(" + str(sid) + ") Sid is valid!")
    else:
        print("M: STEP 3:(" + str(sid) + ") Sid is NOT valid!")

    # STEP 4
    if constants.SIMULATE_ERROR_STEP_4:
        print("M: STEP 4:(" + str(sid) + ") Error occured!")
        time.sleep(1000)
        return

    gateway_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    gateway_connection.connect(("127.0.0.1", constants.PAYMENT_GATEWAY_PORT))

    sid_clientpubk_amount_signature = signature_utils.get_signature_f(
        (recv_sid + "," + client_pubk + ',' + amount).encode("UTF-8"),
        constants.MERCHANT_PRIVATE_KEY_PATH)

    message_for_gateway = payment_message_encrypted_with_aes + ',' + aes_key_encrypted_with_rsa_key + "," + sid_clientpubk_amount_signature.hex()

    pubkpg_hybrid_encrypted_message = hybrid_enc_utils.hybrid_encrypt_rsa_f(message_for_gateway, AES_PASSWORD,
                                                                            constants.PAYMENT_GATEWAY_PUBLIC_KEY)

    serialized_pubkpg_hybrid_encrypted_message = pickle.dumps(pubkpg_hybrid_encrypted_message)

    gateway_connection.send(serialized_pubkpg_hybrid_encrypted_message)
    print("M: STEP 4:(" + str(sid) + ")Sent data to PG!")

    # STEP 5

    response_message = gateway_connection.recv(4096)
    print("M: STEP 5:(" + str(sid) + ")Received data from PG!")

    encrypted_response_message, aes_key = pickle.loads(response_message)

    decrypted_response_message = hybrid_enc_utils.hybrid_decrypt_rsa_f(encrypted_response_message, aes_key,
                                                                       constants.MERCHANT_PRIVATE_KEY_PATH)

    pg_response_code, pg_sid, pg_amount, pg_nounce, code_sid_amount_nc_signature = tuple(
        decrypted_response_message.split(','))

    is_code_sid_amount_nc_valid = signature_utils.is_authentic_f(
        (pg_response_code + ',' + pg_sid + ',' + pg_amount + ',' + pg_nounce).encode('UTF-8'),
        bytes.fromhex(code_sid_amount_nc_signature), constants.PAYMENT_GATEWAY_PUBLIC_KEY)

    if is_code_sid_amount_nc_valid:
        print("M: STEP 5:(" + str(sid) + ") Response code, sid, amount and nounce are valid!")
    else:
        print("M: STEP 5:(" + str(sid) + ") Response code, sid, amount and nounce are NOT valid!")

    if pg_sid == sid:
        print("M: STEP 5:(" + str(sid) + ") Sid is correct!")
    else:
        print("M: STEP 5:(" + str(sid) + ") Sid is correct!")

    if pg_response_code is '3':
        print("M: STEP 5:(" + str(sid) + ") Successfull transaction!")
    elif pg_response_code is '2':
        print("M: STEP 5:(" + str(sid) + ") Insufficient funds!")
    else:
        print("M: STEP 5:(" + str(sid) + ") Invalid data!")

    # STEP 6

    if constants.SIMULATE_ERROR_STEP_6:
        print("M: STEP 6:(" + str(sid) + ") Error occured!")
        time.sleep(1000)
        return

    encrypted_client_response = hybrid_enc_utils.hybrid_encrypt_rsa_s(decrypted_response_message, AES_PASSWORD,
                                                                      client_pubk)

    serialized_client_response = pickle.dumps(encrypted_client_response)

    client_connection.send(serialized_client_response)
    print("M: STEP 6:(" + str(sid) + ")Sent data to client!")


def get_sid():
    return random.randint(0, 10000)


merchant()
