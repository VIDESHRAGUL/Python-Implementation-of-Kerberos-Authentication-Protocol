from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import json

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

def decrypt_tgt_ticket(tgs_secret_key, encrypted_tgt_ticket_base64):
    encrypted_tgt_ticket = base64.b64decode(encrypted_tgt_ticket_base64)
    derived_key = derive_key(tgs_secret_key)
    decrypted_tgt_ticket = decrypt_aes(derived_key, encrypted_tgt_ticket)
    tgt_ticket_json = decrypted_tgt_ticket.decode()
    tgt_ticket = json.loads(tgt_ticket_json)
    return tgt_ticket

def decrypt_aes(key, ciphertext):
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data