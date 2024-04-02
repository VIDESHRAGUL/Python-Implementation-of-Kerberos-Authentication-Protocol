import json
import socket
from encrpt import encrypt_tgt_ticket
from datetime import datetime, timedelta

tgs_secret_key = b'739441c005031f1e41b0e60f52f11aa483d78d3c28fafbadd1b70c10a0fa4b9e'

username = ""
user_ip = ""

tgs_name = "TGS1"
lifetime_minutes = 5
tgs_session_key = "4fe4965433ff79c760ad0e8a50d8e5b3cd698ac2d39b80a98428b32716a08c4f"

Key = {
    "frey": b'688d8c84d4fac20252eed935c2b6aad9e32a8615982cc0ca5f7f4f0050599e9e',
    "robin": b'4898cd3c25683099efd6fc01b4c96d625d6872904d1b09e80912b921ecb18a8c'
}


def create_ticket(tgs_name, lifetime_minutes, tgs_session_key, data_str):
    global tgs_secret_key
    data_dict = json.loads(data_str)
    username = data_dict.get("username")
    user_secret_key = Key[username]

    timestamp = datetime.now()
    expiration_time = timestamp + timedelta(minutes=lifetime_minutes)
    timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")

    auth_ticket = {
        "TGS_name": tgs_name,
        "Timestamp": timestamp,
        "Lifetime": expiration_time.strftime("%Y-%m-%d %H:%M:%S"),
        "TGS_session_key": tgs_session_key
    }
    encrypted_auth_ticket_base64 = encrypt_tgt_ticket(auth_ticket, user_secret_key)

    tgt_ticket = {
        "Username": username,
        "TGS_name": tgs_name,
        "Timestamp": timestamp,
        "User_IP_Address": user_ip,
        "Lifetime": expiration_time.strftime("%Y-%m-%d %H:%M:%S"),
        "TGS_session_key": tgs_session_key
    }
    encrypted_tgt_ticket_base64 = encrypt_tgt_ticket(tgt_ticket, tgs_secret_key)

    return {"AUTH_ticket": encrypted_auth_ticket_base64, "TGT_ticket": encrypted_tgt_ticket_base64}


def Check_username(data_str):
    try:
        global username
        data_dict = json.loads(data_str)
        username = data_dict.get("username")
        if username in Key:
            return True
        else:
            return False
    except json.JSONDecodeError:
        print("Invalid JSON format")
        return False


def Check_user_ip(data_str, addr):
    try:
        global user_ip
        data_dict = json.loads(data_str)
        user_ip = data_dict.get("ip_address")
        client_ip = addr[0]
        if user_ip == client_ip:
            return True
        else:
            return False
    except json.JSONDecodeError:
        print("Invalid JSON format")
        return False


def Check_timestamp(data_str):
    try:
        data_dict = json.loads(data_str)
        timestamp_str = data_dict.get("timestamp")

        if not timestamp_str:
            return False
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        current_time = datetime.now()
        time_difference = abs(current_time - timestamp)
        if time_difference <= timedelta(minutes=3):
            return True
        else:
            return False
    except json.JSONDecodeError:
        print("Invalid JSON format")
        return False


def main():
    host = 'localhost'
    port = 12343

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)

        print("Authentication server listening...")
        conn, addr = server_socket.accept()

        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            data_str = data.decode('utf-8')
            print("\nReceived data:", data_str)

            if Check_username(data_str) and Check_user_ip(data_str, addr) and Check_timestamp(data_str):
                ticket = create_ticket(tgs_name, lifetime_minutes, tgs_session_key, data_str)
                json_string = json.dumps(ticket)
                conn.sendall(json_string.encode('utf-8'))
                print(f"\nAuthorization Ticket sent (Reply): {json_string.encode('utf-8')}")
            else:
                conn.sendall(b"Authentication failed")


if __name__ == "__main__":
    main()
