import base64
import json

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def derive_key(key):
    salt = b'salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(key)


def encrypt_aes(key, data):
    iv = b'\x00' * 16
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


def decrypt_aes(key, ciphertext):
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def encrypt_tgt_ticket(tgt_ticket, tgs_secret_key):
    tgt_ticket_json = json.dumps(tgt_ticket)
    derived_key = derive_key(tgs_secret_key)
    encrypted_tgt_ticket = encrypt_aes(derived_key, tgt_ticket_json.encode())
    encrypted_tgt_ticket_base64 = base64.b64encode(encrypted_tgt_ticket)
    return encrypted_tgt_ticket_base64.decode()
