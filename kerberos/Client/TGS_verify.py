import datetime
import json
from datetime import datetime

from dycrption import decrypt_tgt_ticket
from encrpt import encrypt_tgt_ticket


def get_service_session_key():
    return service_session_key


def TGS_verify(request, key, username):
    global service_session_key
    response_dict = json.loads(request)
    auth_ticket = response_dict.get("Auth_ticket")
    service_ticket = response_dict.get("Service_ticket")
    data = decrypt_tgt_ticket(key, auth_ticket)

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    user_auth = {
        "username": username,
        "timestamp": timestamp
    }

    service_session_key = data.get("service_session_key")
    service_session_key = service_session_key.encode('utf-8')

    user_auturization = encrypt_tgt_ticket(user_auth, service_session_key)

    response_data = {
        "user_auth": user_auturization,
        "Service": service_ticket
    }

    return response_data
