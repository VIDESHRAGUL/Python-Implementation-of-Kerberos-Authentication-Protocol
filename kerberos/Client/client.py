import json
import socket
from datetime import datetime

from Auth_verify import auth_verify, get_tgs_session_key
from Client.TGS_verify import TGS_verify, get_service_session_key
from Client.service_verify import Service_verify

salt = "salt"
kvn = "kvn"

username = input("Enter your username: ")
password = input("Enter your password: ")
service_name = input("Enter the service you wanna access:")


def get_ip_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address


def get_current_timestamp():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return timestamp


def user_authentication():
    ip_address = get_ip_address()
    timestamp = get_current_timestamp()
    data_dict = {
        "username": username,
        "service_name": service_name,
        "ip_address": '127.0.0.1', #ip_address,
        "timestamp": timestamp
    }
    json_string = json.dumps(data_dict)
    return json_string.encode('utf-8')


def main():
    host = 'localhost'
    AS_port = 12343
    TGS_port = 12344
    S_port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as auth_socket:
        auth_socket.connect((host, AS_port))
        auth_socket.sendall(user_authentication())
        auth_response = auth_socket.recv(1024)
        Request = auth_verify(auth_response.decode(), password, salt, kvn, username)
        print(f"\nSent to authentication server: {user_authentication()}")
        print(f"Received authentication response: {auth_response.decode()}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tick_socket:
        tick_socket.connect((host, TGS_port))
        Request_json = json.dumps(Request)
        tick_socket.sendall(Request_json.encode())
        print(f"\nSent to TGS: {Request_json.encode()}")
        tick_response = tick_socket.recv(1024)
        Request = TGS_verify(tick_response.decode(), get_tgs_session_key(), username)
        print(f"Received TGS response: {tick_response.decode()}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as services_socket:
        services_socket.connect((host, S_port))
        Request_json = json.dumps(Request)
        services_socket.sendall(Request_json.encode())
        print(f"\nSent to services server: {Request_json.encode()}")
        services_response = services_socket.recv(1024)
        Request = Service_verify(services_response.decode(), get_service_session_key())
        print(f"Received services response: {services_response.decode()}")
        print(f"\nWe are verified {Request}")


if __name__ == "__main__":
    main()
