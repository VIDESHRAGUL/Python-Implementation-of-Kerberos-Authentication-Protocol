import json
import socket
from datetime import datetime, timedelta

from dycrption import decrypt_tgt_ticket
from encrpt import encrypt_tgt_ticket

service_session_key = "189b1a177a909d795321ed017863feb42412676a9f8be4033892e425fc591784"

key = {
    "genshin impact": b'739441c005031f1e41b0e60f52f11aa483d78d3c28fafbadd1b70c10a0fa4b9e'
}


def create_ticket(tgt_data, secret_key):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lifetime = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

    username = tgt_data.get("Username")
    user_ip = tgt_data.get("User_IP_Address")
    TGS_session_key = tgt_data.get("TGS_session_key")
    auth_ticket = {
        "service_name": service_name,
        "timestamp": current_time,
        "lifetime": lifetime,
        "service_session_key": service_session_key
    }
    TGS_session_key = TGS_session_key.encode('utf-8')
    encrypted_auth_ticket = encrypt_tgt_ticket(auth_ticket, TGS_session_key)
    service_ticket = {
        "username": username,
        "service_name": service_name,
        "timestamp": current_time,
        "ip_address": user_ip,
        "lifetime": lifetime,
        "service_session_key": service_session_key
    }

    encrypted_service_ticket = encrypt_tgt_ticket(service_ticket, secret_key)

    return {"Auth_ticket": encrypted_auth_ticket, "Service_ticket": encrypted_service_ticket}


def get_AUTH(tgt_data, data):
    TGS_session_key = tgt_data.get("TGS_session_key")
    TGS_session_key = TGS_session_key.encode('utf-8')
    data_dict = json.loads(data)
    tgt_ticket = data_dict.get("User_auth")

    return decrypt_tgt_ticket(TGS_session_key, tgt_ticket)


def get_TGT(data, secret_key):
    try:
        data_dict = json.loads(data)
        tgt_ticket = data_dict.get("TGT_ticket")
        return decrypt_tgt_ticket(secret_key, tgt_ticket)
    except json.JSONDecodeError:
        return None


def get_service_key(data):
    global service_name
    try:
        data_dict = json.loads(data)
        request_data = data_dict.get("Request", {})
        service_name = request_data.get("service_name")
        if service_name in key:
            service_key = key[service_name]
            return service_key
        return None
    except json.JSONDecodeError:
        return None


def compare_tgt_auth_data(tgt_data, auth_data, addr):
    tgt_username = tgt_data.get("Username")
    tgt_timestamp = tgt_data.get("Timestamp")
    tgt_user_ip = tgt_data.get("User_IP_Address")
    tgt_lifetime = tgt_data.get("Lifetime")
    auth_username = auth_data.get("username")
    auth_timestamp = auth_data.get("timestamp")

    tgt_timestamp = datetime.strptime(tgt_timestamp, "%Y-%m-%d %H:%M:%S")
    auth_timestamp = datetime.strptime(auth_timestamp, "%Y-%m-%d %H:%M:%S")

    client_ip = addr[0]
    time_difference = abs((tgt_timestamp - auth_timestamp).total_seconds())

    if tgt_username == auth_username and time_difference <= 10 and tgt_user_ip == client_ip:
        current_time = datetime.now()
        tgt_lifetime = datetime.strptime(tgt_lifetime, "%Y-%m-%d %H:%M:%S")
        if current_time > tgt_lifetime:
            return False
        else:
            return True
    else:
        return False


def main():
    host = 'localhost'
    port = 12344

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)

        print("Ticker server listening...")
        conn, addr = server_socket.accept()

        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            print(f"\nReceived data : {data}")
            if data:
                secret_key = get_service_key(data)
                tgt_data = get_TGT(data, secret_key)
                auth_data = get_AUTH(tgt_data, data)
                verify = compare_tgt_auth_data(tgt_data, auth_data, addr)
                if verify:
                    Request = create_ticket(tgt_data, secret_key)
                    json_string = json.dumps(Request)
                    conn.sendall(json_string.encode('utf-8'))
                    print(f"Ticket is generated (Reply) : {json_string.encode('utf-8')}")
                else:
                    conn.sendall(b'Authentication failed')


if __name__ == "__main__":
    main()
