import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm

AES_NONCE_SIZE = 12
CHACHA_NONCE_SIZE = 12
CHUNK_SIZE = 1024 * 1024

def encrypt_aes_gcm(data: bytes, key: bytes, desc: str = "Encrypting (AES-256-GCM)") -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(AES_NONCE_SIZE)
    with tqdm(total=len(data), unit='B', unit_scale=True, unit_divisor=1024, desc=desc, leave=False) as pbar:
        ciphertext = aesgcm.encrypt(nonce, data, None)
        pbar.update(len(data))
    return nonce + ciphertext

def decrypt_aes_gcm(encrypted_data: bytes, key: bytes, desc: str = "Decrypting (AES-256-GCM)") -> bytes:
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:AES_NONCE_SIZE]
    ciphertext = encrypted_data[AES_NONCE_SIZE:]
    with tqdm(total=len(ciphertext), unit='B', unit_scale=True, unit_divisor=1024, desc=desc, leave=False) as pbar:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        pbar.update(len(ciphertext))
    return plaintext

def encrypt_chacha20_poly1305(data: bytes, key: bytes, desc: str = "Encrypting (ChaCha20-Poly1305)") -> bytes:
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(CHACHA_NONCE_SIZE)
    with tqdm(total=len(data), unit='B', unit_scale=True, unit_divisor=1024, desc=desc, leave=False) as pbar:
        ciphertext = chacha.encrypt(nonce, data, None)
        pbar.update(len(data))
    return nonce + ciphertext

def decrypt_chacha20_poly1305(encrypted_data: bytes, key: bytes, desc: str = "Decrypting (ChaCha20-Poly1305)") -> bytes:
    chacha = ChaCha20Poly1305(key)
    nonce = encrypted_data[:CHACHA_NONCE_SIZE]
    ciphertext = encrypted_data[CHACHA_NONCE_SIZE:]
    with tqdm(total=len(ciphertext), unit='B', unit_scale=True, unit_divisor=1024, desc=desc, leave=False) as pbar:
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        pbar.update(len(ciphertext))
    return plaintext

def multi_layer_encrypt(file_path: str, keys: list[bytes]) -> bytes:
    file_size = os.path.getsize(file_path)
    with tqdm(total=file_size, unit='B', unit_scale=True, unit_divisor=1024, desc="Reading file") as pbar:
        with open(file_path, 'rb') as f:
            plaintext = f.read()
            pbar.update(file_size)
    
    encrypted_data = plaintext
    for i, key in enumerate(keys):
        if i % 2 == 0:
            encrypted_data = encrypt_aes_gcm(encrypted_data, key, f"Encryption layer {i+1}/{len(keys)} (AES-256-GCM)")
        else:
            encrypted_data = encrypt_chacha20_poly1305(encrypted_data, key, f"Encryption layer {i+1}/{len(keys)} (ChaCha20-Poly1305)")
    
    return encrypted_data

def multi_layer_decrypt(encrypted_data: bytes, keys: list[bytes]) -> bytes:
    decrypted_data = encrypted_data
    for i, key in enumerate(reversed(keys)):
        layer_num = len(keys) - i
        original_index = len(keys) - i - 1
        if original_index % 2 == 0:
            decrypted_data = decrypt_aes_gcm(decrypted_data, key, f"Decryption layer {layer_num}/{len(keys)} (AES-256-GCM)")
        else:
            decrypted_data = decrypt_chacha20_poly1305(decrypted_data, key, f"Decryption layer {layer_num}/{len(keys)} (ChaCha20-Poly1305)")
    
    return decrypted_data

def double_encrypt(file_path: str, key1: bytes, key2: bytes) -> bytes:
    return multi_layer_encrypt(file_path, [key1, key2])

def double_decrypt(encrypted_data: bytes, key1: bytes, key2: bytes) -> bytes:
    return multi_layer_decrypt(encrypted_data, [key1, key2])

