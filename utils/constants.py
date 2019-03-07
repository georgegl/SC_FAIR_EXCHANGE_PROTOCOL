import os

from keys import key_generation

# KEY PATHS
MERCHANT_PUBLIC_KEY_PATH = os.path.join(key_generation.KEYS_DIR, "merchant_public_key.pem")
MERCHANT_PRIVATE_KEY_PATH = os.path.join(key_generation.KEYS_DIR, "merchant_private_key.pem")
PAYMENT_GATEWAY_PUBLIC_KEY = os.path.join(key_generation.KEYS_DIR, "payment_gateway_public_key.pem")
PAYMENT_GATEWAY_PRIVATE_KEY = os.path.join(key_generation.KEYS_DIR, "payment_gateway_private_key.pem")

# CLIENT DATA MOCK-UPS
CARDNUMBER = "1234 5678 9012 1234"
CARD_EXP = "10/21"
CCODE = "321"
AMOUNT = "350"
ORDER_DESC = "1 TV; 2 PHONES; 3 TABLETS"

# PAYMENT DATA GATEWAY MOCK-UPS
CARDNUMBER_PG = "1234 5678 9012 1234"
CARD_EXP_PG = "10/21"
CCODE_PG = "321"
AMOUNT_PG = "500"

# RESOLUTION MOCK-UPS
SIMULATE_ERROR_STEP_4 = False
SIMULATE_ERROR_STEP_6 = False

# PORTS
MERCHANT_PORT = 50024
PAYMENT_GATEWAY_PORT = 50025
