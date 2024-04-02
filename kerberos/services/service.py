import json
import socket

from dycrption import decrypt_tgt_ticket
from datetime import datetime, timedelta

from encrpt import encrypt_tgt_ticket

service_key = b'739441c005031f1e41b0e60f52f11aa483d78d3c28fafbadd1b70c10a0fa4b9e'


def verify(ST, auth, addr):
    st_timestamp = datetime.strptime(ST['timestamp'], '%Y-%m-%d %H:%M:%S')
    auth_timestamp = datetime.strptime(auth['timestamp'], '%Y-%m-%d %H:%M:%S')
    if ST['username'] != auth['username']:
        print(f"{ST['username']} ==== {auth['username']}")
        print("username is different")
        return False
    time_difference = abs(st_timestamp - auth_timestamp)
    if time_difference > timedelta(seconds=10):
        print("time of creation is different")
        return False
    current_time = datetime.now()
    lifetime = datetime.strptime(ST['lifetime'], '%Y-%m-%d %H:%M:%S')
    if lifetime < current_time:
        print("it is a expired ticket")
        return False
    if ST['ip_address'] != addr[0]:
        return False

    return True


def check(data, addr):
    data_dict = json.loads(data)
    service_value = data_dict.get("Service")
    user_auth = data_dict.get("user_auth")
    service_value = service_value.encode('utf-8')
    ST = decrypt_tgt_ticket(service_key, service_value)
    service_session_key = ST.get("service_session_key")
    service_session_key = service_session_key.encode('utf-8')
    user_auth = user_auth.encode('utf-8')
    auth = decrypt_tgt_ticket(service_session_key, user_auth)
    if verify(ST, auth, addr):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        service_auth = {
            "service_name": "genshin impact",
            "timestamp": timestamp
        }
        return encrypt_tgt_ticket(service_auth, service_session_key)
    return "problem with authentication"



def main():
    host = 'localhost'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)

        print("Services server listening...")
        conn, addr = server_socket.accept()

        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            print(f"\nReceived data {data}")

            Request = check(data, addr)
            if data:
                json_string = json.dumps(Request)
                conn.sendall(json_string.encode('utf-8'))
                print(f"\nUser verified and service provided (reply) : {json_string.encode('utf-8')}")
            else:
                conn.sendall(b'Error no service')


if __name__ == "__main__":
    main()
