import datetime
import json
from Hashing_algorithm import generate_aes_key
from dycrption import decrypt_tgt_ticket
from encrpt import encrypt_tgt_ticket

TGS_session_key = ""


def get_tgs_session_key():
    return TGS_session_key


def auth_verify(auth_response, password, salt, kvn, username):
    global auth_ticket, tgs_ticket, TGS_session_key
    try:
        response_dict = json.loads(auth_response)
        auth_ticket = response_dict.get("AUTH_ticket")
        tgs_ticket = response_dict.get("TGT_ticket")
        if tgs_ticket and auth_ticket:
            pass
        else:
            print("TGS Ticket not found in the authentication response.")
    except json.JSONDecodeError:
        print("Invalid JSON format in authentication response.")

    aes_key = generate_aes_key(password, salt, kvn)
    aes_key_hex = aes_key.hex()
    key = aes_key_hex.encode('utf-8')
    decrypted_auth_ticket = decrypt_tgt_ticket(key, auth_ticket)

    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    user_authentication = {
        "username": username,
        "timestamp": current_time
    }
    TGS_session_key = decrypted_auth_ticket['TGS_session_key']
    TGS_session_key = TGS_session_key.encode('utf-8')
    encrypt_user_authentication = encrypt_tgt_ticket(user_authentication, TGS_session_key)
    request = {
        "service_name": "genshin impact",
        "timestamp": current_time
    }
    return {'TGT_ticket': tgs_ticket, "User_auth": encrypt_user_authentication, "Request": request}
