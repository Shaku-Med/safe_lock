import os
import json
import base64
from argon2 import low_level
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from stegano import lsb
from PIL import Image

SALT_SIZE = 32
KEY_SIZE = 32
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
ARGON2_TYPE = low_level.Type.ID
PBKDF2_ITERATIONS = 600000
KEY_FILE_NONCE_SIZE = 12

def derive_key_argon2(password: bytes, salt: bytes) -> bytes:
    hash_output = low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=ARGON2_TYPE
    )
    return hash_output

def derive_key_pbkdf2(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)

def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)

def generate_device_key() -> bytes:
    return os.urandom(KEY_SIZE)

def save_keys_file_json(all_keys_data: list[dict], file_path: str, password: str):
    keys_json = json.dumps(all_keys_data).encode('utf-8')
    
    password_bytes = password.encode('utf-8')
    salt = generate_salt()
    key = derive_key_argon2(password_bytes, salt)
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(KEY_FILE_NONCE_SIZE)
    encrypted_data = aesgcm.encrypt(nonce, keys_json, None)
    
    key_file_data = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'data': base64.b64encode(encrypted_data).decode('utf-8')
    }
    
    with open(file_path, 'w') as f:
        json.dump(key_file_data, f)

def load_keys_file_json(file_path: str, password: str) -> list[dict]:
    with open(file_path, 'r') as f:
        key_file_data = json.load(f)
    
    salt = base64.b64decode(key_file_data['salt'])
    nonce = base64.b64decode(key_file_data['nonce'])
    encrypted_data = base64.b64decode(key_file_data['data'])
    
    password_bytes = password.encode('utf-8')
    key = derive_key_argon2(password_bytes, salt)
    
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
    
    return json.loads(decrypted_data.decode('utf-8'))

def save_keys_file_image(all_keys_data: list[dict], cover_image_path: str, output_image_path: str, password: str):
    keys_json = json.dumps(all_keys_data).encode('utf-8')
    
    password_bytes = password.encode('utf-8')
    salt = generate_salt()
    key = derive_key_argon2(password_bytes, salt)
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(KEY_FILE_NONCE_SIZE)
    encrypted_data = aesgcm.encrypt(nonce, keys_json, None)
    
    key_file_data = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'data': base64.b64encode(encrypted_data).decode('utf-8')
    }
    
    key_file_json = json.dumps(key_file_data)
    key_file_b64 = base64.b64encode(key_file_json.encode('utf-8')).decode('utf-8')
    
    img = Image.open(cover_image_path)
    img_format = img.format
    
    secret = lsb.hide(cover_image_path, key_file_b64)
    secret.save(output_image_path, format=img_format)

def load_keys_file_image(image_path: str, password: str) -> list[dict]:
    hidden_data_b64 = lsb.reveal(image_path)
    if hidden_data_b64 is None:
        raise Exception("No hidden data found in image")
    
    key_file_json = base64.b64decode(hidden_data_b64.encode('utf-8')).decode('utf-8')
    key_file_data = json.loads(key_file_json)
    
    salt = base64.b64decode(key_file_data['salt'])
    nonce = base64.b64decode(key_file_data['nonce'])
    encrypted_data = base64.b64decode(key_file_data['data'])
    
    password_bytes = password.encode('utf-8')
    key = derive_key_argon2(password_bytes, salt)
    
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
    
    return json.loads(decrypted_data.decode('utf-8'))

def derive_keys_from_password(password: str) -> tuple[bytes, bytes]:
    salt1 = generate_salt()
    salt2 = generate_salt()
    password_bytes = password.encode('utf-8')
    key1 = derive_key_argon2(password_bytes, salt1)
    key2 = derive_key_pbkdf2(password_bytes, salt2)
    return (salt1, key1), (salt2, key2)

