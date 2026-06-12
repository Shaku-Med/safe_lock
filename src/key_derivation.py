import os
import json
import base64
import tempfile
from argon2 import low_level
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from stegano import lsb
from PIL import Image

from src.file_format import MAX_TIME_COST, MAX_MEMORY_COST, MAX_PARALLELISM

SALT_SIZE = 32
KEY_SIZE = 32
# Legacy Argon2id params. DO NOT change these: existing files store no params and rely on them.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
# Strengthened params for new (V2) encryptions. Safe to raise: V2 files store their own params.
ARGON2_TIME_COST_V2 = 4
ARGON2_MEMORY_COST_V2 = 131072
ARGON2_PARALLELISM_V2 = 4
ARGON2_TYPE = low_level.Type.ID
PBKDF2_ITERATIONS = 600000
KEY_FILE_NONCE_SIZE = 12
# V2 key files store derived keys (never the raw passwords) and record their own KDF params.
KEYFILE_VERSION = 2

def derive_key_argon2_with_params(password: bytes, salt: bytes, time_cost: int, memory_cost: int, parallelism: int) -> bytes:
    return low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_SIZE,
        type=ARGON2_TYPE
    )

def derive_key_argon2(password: bytes, salt: bytes) -> bytes:
    # Legacy derivation, kept for backward compatibility with existing files.
    return derive_key_argon2_with_params(password, salt, ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM)

def derive_key_argon2_v2(password: bytes, salt: bytes) -> bytes:
    return derive_key_argon2_with_params(password, salt, ARGON2_TIME_COST_V2, ARGON2_MEMORY_COST_V2, ARGON2_PARALLELISM_V2)

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

def _encrypt_keyfile_payload(all_keys_data: list[dict], password: str) -> dict:
    """Build a versioned, encrypted key-file envelope. Shared by JSON and image storage."""
    keys_json = json.dumps(all_keys_data).encode('utf-8')
    salt = generate_salt()
    key = derive_key_argon2_v2(password.encode('utf-8'), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(KEY_FILE_NONCE_SIZE)
    encrypted_data = aesgcm.encrypt(nonce, keys_json, None)
    return {
        'v': KEYFILE_VERSION,
        'kdf': {'t': ARGON2_TIME_COST_V2, 'm': ARGON2_MEMORY_COST_V2, 'p': ARGON2_PARALLELISM_V2},
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'data': base64.b64encode(encrypted_data).decode('utf-8'),
    }

def _decrypt_keyfile_payload(envelope: dict, password: str) -> list[dict]:
    """Decrypt a key-file envelope. V2 uses stored KDF params; older envelopes use legacy Argon2."""
    salt = base64.b64decode(envelope['salt'])
    nonce = base64.b64decode(envelope['nonce'])
    encrypted_data = base64.b64decode(envelope['data'])
    if envelope.get('v') == KEYFILE_VERSION:
        kdf = envelope.get('kdf', {})
        time_cost = int(kdf.get('t', ARGON2_TIME_COST_V2))
        memory_cost = int(kdf.get('m', ARGON2_MEMORY_COST_V2))
        parallelism = int(kdf.get('p', ARGON2_PARALLELISM_V2))
        # Bound untrusted params so a tampered key file cannot trigger an OOM before any key check.
        if not (1 <= time_cost <= MAX_TIME_COST and 8 <= memory_cost <= MAX_MEMORY_COST and 1 <= parallelism <= MAX_PARALLELISM):
            raise ValueError("Invalid key file KDF parameters")
        key = derive_key_argon2_with_params(password.encode('utf-8'), salt, time_cost, memory_cost, parallelism)
    else:
        key = derive_key_argon2(password.encode('utf-8'), salt)
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
    return json.loads(decrypted_data.decode('utf-8'))

def save_keys_file_json(all_keys_data: list[dict], file_path: str, password: str):
    envelope = _encrypt_keyfile_payload(all_keys_data, password)
    with open(file_path, 'w') as f:
        json.dump(envelope, f)

def load_keys_file_json(file_path: str, password: str) -> list[dict]:
    with open(file_path, 'r') as f:
        envelope = json.load(f)
    return _decrypt_keyfile_payload(envelope, password)

def save_keys_file_image(all_keys_data: list[dict], cover_image_path: str, output_image_path: str, password: str):
    """
    Save encrypted keys to an image using steganography.
    Always saves as PNG to preserve LSB data (lossless format).
    """
    try:
        # Prepare the encrypted key data (same versioned envelope as the JSON path)
        envelope = _encrypt_keyfile_payload(all_keys_data, password)
        key_file_json = json.dumps(envelope)
        key_file_b64 = base64.b64encode(key_file_json.encode('utf-8')).decode('utf-8')
        
        # Open and convert cover image to PNG format first
        # This ensures compatibility with steganography (PNG is lossless)
        img = Image.open(cover_image_path)
        
        # Convert to RGB mode if necessary (LSB steganography works best with RGB)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Check if image is large enough
        width, height = img.size
        pixel_count = width * height
        required_pixels = len(key_file_b64) * 8  # Each character needs 8 bits (1 byte)
        
        if required_pixels > pixel_count:
            raise Exception(
                f"Image is too small to hide the keys.\n"
                f"Image size: {width}x{height} = {pixel_count:,} pixels\n"
                f"Required: {required_pixels:,} pixels\n"
                f"Please use a larger cover image."
            )
        
        # Convert cover image to PNG format (save to temp file if original isn't PNG)
        # This ensures stegano works properly regardless of input format
        temp_cover_png = None
        try:
            if img.format == 'PNG' and cover_image_path.lower().endswith('.png'):
                # Already PNG, use it directly
                cover_png_path = cover_image_path
            else:
                # Convert to PNG format
                temp_cover_png = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
                img.save(temp_cover_png.name, format='PNG')
                cover_png_path = temp_cover_png.name
            
            # Hide the data using LSB steganography (now using PNG format)
            secret = lsb.hide(cover_png_path, key_file_b64)
            
            # Ensure output path has .png extension
            output_path_png = output_image_path
            if not output_path_png.lower().endswith('.png'):
                base_name = os.path.splitext(output_path_png)[0]
                output_path_png = base_name + '.png'
            
            # Save as PNG (lossless format - CRITICAL for preserving steganography data)
            secret.save(output_path_png, format='PNG')
            
        finally:
            # Clean up temporary PNG file if created
            if temp_cover_png is not None:
                try:
                    os.unlink(temp_cover_png.name)
                except:
                    pass
        
    except Exception as e:
        raise Exception(f"Error saving keys to image: {str(e)}")

def load_keys_file_image(image_path: str, password: str) -> list[dict]:
    try:
        hidden_data_b64 = lsb.reveal(image_path)
    except Exception as e:
        error_msg = str(e).lower()
        if "impossible to detect" in error_msg or "no message" in error_msg:
            raise Exception(
                f"Could not find hidden keys in the image.\n"
                f"Possible reasons:\n"
                f"  1. The image file doesn't contain hidden keys\n"
                f"  2. The image was modified/compressed after keys were saved (LSB steganography is fragile)\n"
                f"  3. You're using the wrong image file\n"
                f"  4. The image format doesn't support steganography properly\n\n"
                f"Make sure you're using the exact image file that was created when you saved your keys.\n"
                f"If the image was edited, resaved, or compressed, the hidden data may be lost.\n"
                f"Consider using a JSON key file instead, which is more reliable."
            )
        else:
            raise Exception(f"Error reading hidden data from image: {str(e)}")
    
    if hidden_data_b64 is None:
        raise Exception(
            "No hidden data found in image.\n"
            "Make sure you're using the correct image file that contains your saved keys."
        )
    
    try:
        key_file_json = base64.b64decode(hidden_data_b64.encode('utf-8')).decode('utf-8')
        envelope = json.loads(key_file_json)
    except Exception as e:
        raise Exception(f"Error decoding hidden data from image: {str(e)}")

    try:
        return _decrypt_keyfile_payload(envelope, password)
    except KeyError as e:
        raise Exception(f"Invalid key file format in image: missing {str(e)}")
    except Exception as e:
        raise Exception(f"Error decrypting keys: Wrong password or corrupted key file. {str(e)}")

