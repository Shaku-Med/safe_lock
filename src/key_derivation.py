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
    """
    Save encrypted keys to an image using steganography.
    Always saves as PNG to preserve LSB data (lossless format).
    """
    try:
        # Prepare the encrypted key data
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
        key_file_data = json.loads(key_file_json)
    except Exception as e:
        raise Exception(f"Error decoding hidden data from image: {str(e)}")
    
    try:
        salt = base64.b64decode(key_file_data['salt'])
        nonce = base64.b64decode(key_file_data['nonce'])
        encrypted_data = base64.b64decode(key_file_data['data'])
    except KeyError as e:
        raise Exception(f"Invalid key file format in image: missing {str(e)}")
    except Exception as e:
        raise Exception(f"Error extracting key data from image: {str(e)}")
    
    try:
        password_bytes = password.encode('utf-8')
        key = derive_key_argon2(password_bytes, salt)
        
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        raise Exception(f"Error decrypting keys: Wrong password or corrupted key file. {str(e)}")

def derive_keys_from_password(password: str) -> tuple[bytes, bytes]:
    salt1 = generate_salt()
    salt2 = generate_salt()
    password_bytes = password.encode('utf-8')
    key1 = derive_key_argon2(password_bytes, salt1)
    key2 = derive_key_pbkdf2(password_bytes, salt2)
    return (salt1, key1), (salt2, key2)

