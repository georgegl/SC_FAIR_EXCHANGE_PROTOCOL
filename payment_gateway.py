import socket
import pickle

from utils import constants
from utils import signature_utils
from utils import hybrid_enc_utils

AES_PASSWORD = "paymentgatewaypassword"


def payment_gateway():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", constants.PAYMENT_GATEWAY_PORT))
    s.listen(1)

    exchange_return_code = ''
    sid = ''
    amount = ''
    nounce = ''

    while True:
        (connection, address) = s.accept()

        data = connection.recv(4096)

        deserialized_message_encrypted_with_aes, aes_key = pickle.loads(data)

        decrypted_message = hybrid_enc_utils.hybrid_decrypt_rsa_f(deserialized_message_encrypted_with_aes, aes_key,
                                                                  constants.PAYMENT_GATEWAY_PRIVATE_KEY)

        # IF IS MERCHANT (MERCHANT HAS 3 INFOS)
        if len(decrypted_message.split(',')) == 3:
            exchange_return_code, sid, amount, nounce = exchange_sub_protocol(connection, decrypted_message)
        else:
            resolution_sub_protocol(connection, decrypted_message, exchange_return_code, sid, amount, nounce)

        connection.close()


def exchange_sub_protocol(connection, decrypted_message):
    # STEP 4

    encrypted_client_payment_message, aes_key, sid_clientpubk_amount_signature = tuple(decrypted_message.split(','))

    decrypted_client_payment_message = hybrid_enc_utils.hybrid_decrypt_rsa_f(
        bytes.fromhex(encrypted_client_payment_message),
        bytes.fromhex(aes_key),
        constants.PAYMENT_GATEWAY_PRIVATE_KEY)

    card_number, expiration_date, ccode, sid, amount, client_pubk, nounce, client_signature = tuple(
        decrypted_client_payment_message.split(","))

    print("PG: STEP 4:(" + str(sid) + ")Received data from merchant!")

    are_sid_clientpubk_amount_valid = signature_utils.is_authentic_f(
        (sid + ',' + client_pubk + ',' + amount).encode('UTF-8'), bytes.fromhex(sid_clientpubk_amount_signature),
        constants.MERCHANT_PUBLIC_KEY_PATH)

    if are_sid_clientpubk_amount_valid:
        print("PG: STEP 4:(" + str(sid) + ") Sid, clientPubK and amount are valid!")
    else:
        print("PG: STEP 4:(" + str(sid) + ") Sid, clientPubK and amount are NOT valid!")

    client_data_to_validate = card_number + "," + expiration_date + "," + ccode + "," + sid + "," + amount + "," + client_pubk + "," + nounce

    are_client_personal_fields_valid = signature_utils.is_authentic_s(client_data_to_validate.encode('UTF-8'),
                                                                      bytes.fromhex(client_signature), client_pubk)

    if are_client_personal_fields_valid:
        print("PG: STEP 4:(" + str(sid) + ") Client personal data is valid!")
    else:
        print("PG: STEP 4:(" + str(sid) + ") Client personal data is NOT valid!")

    # CODE 1: Invalid card data
    # CODE 2: Insufficient funds
    # CODE 3: Successfull transaction
    if (card_number, expiration_date, ccode) != (
            constants.CARDNUMBER_PG, constants.CARD_EXP_PG, constants.CCODE_PG) or int(amount) < 0:
        resp = 1
        print("PG: STEP 6:(" + str(sid) + ") Invalid data!")
    elif int(amount) > int(constants.AMOUNT_PG):
        resp = 2
        print("PG: STEP 6:(" + str(sid) + ") Insufficient funds!")
    else:
        resp = 3
        print("PG: STEP 6:(" + str(sid) + ") Successfull transaction!")

    # STEP 5

    resp_sid_amount_nounce_signature = signature_utils.get_signature_f(
        (str(resp) + "," + sid + "," + amount + ',' + nounce).encode('UTF-8'),
        constants.PAYMENT_GATEWAY_PRIVATE_KEY)

    encrypted_message = hybrid_enc_utils.hybrid_encrypt_rsa_f(
        str(resp) + ',' + sid + ',' + amount + ',' + nounce + ',' + resp_sid_amount_nounce_signature.hex(),
        AES_PASSWORD,
        constants.MERCHANT_PUBLIC_KEY_PATH)

    serialized_encrypted_message = pickle.dumps(encrypted_message)

    connection.send(serialized_encrypted_message)
    print("PG: STEP 5:(" + str(sid) + ")Sent data to merchant!")

    return resp, sid, amount, nounce


def resolution_sub_protocol(connection, decrypted_message, exchange_return_code, sid, amount, nounce):
    # STEP 7

    print("PG: STEP 7: Resolution sub-protocol initiated!")
    print("PG: STEP 7: Received message from client!")

    c_sid, c_amount, c_nounce, client_pubk, signature = tuple(decrypted_message.split(','))

    is_sid_amount_nounce_pubk_valid = signature_utils.is_authentic_s(
        (c_sid + ',' + c_amount + ',' + c_nounce + ',' + client_pubk).encode('UTF-8'), signature,
        bytes.fromhex(client_pubk))

    if is_sid_amount_nounce_pubk_valid:
        print("PG: STEP 7: Sid, Amount, nounce and clientPubK are valid!")
    else:
        print("PG: STEP 7: Sid, Amount, nounce and clientPubK are NOT valid!")

        # CODE 0: Transaction does not exist
        # CODE 1: Invalid card data
        # CODE 2: Insufficient funds
        # CODE 3: Successfull transaction
    resolution_response = 0

    if (c_sid, c_amount, c_nounce) == (sid, amount, nounce):
        print("PG: STEP 7: This transaction exists!")
        resolution_response = exchange_return_code
    else:
        print("PG: STEP 7: This transaction has not reached PG!")

    # STEP 8

    response_message = str(resolution_response) + ',' + sid

    response_message_signature = signature_utils.get_signature_f(response_message.encode("UTF-8"),
                                                                 constants.PAYMENT_GATEWAY_PRIVATE_KEY)

    encrypted_response_message = hybrid_enc_utils.hybrid_encrypt_rsa_s(
        response_message + ',' + response_message_signature.hex(), AES_PASSWORD, bytes.fromhex(client_pubk))

    serialized_response_message = pickle.dumps(encrypted_response_message)

    connection.send(serialized_response_message)
    print("PG: STEP 8: Sent message to client!")


payment_gateway()
