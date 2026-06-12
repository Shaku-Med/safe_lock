import os
import sys
import getpass
from pathlib import Path
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.encryption import multi_layer_encrypt, multi_layer_decrypt
from src.key_derivation import (
    derive_key_argon2, derive_key_argon2_v2, derive_key_argon2_with_params, generate_salt,
    save_keys_file_json, load_keys_file_json,
    save_keys_file_image, load_keys_file_image,
    ARGON2_TIME_COST_V2, ARGON2_MEMORY_COST_V2, ARGON2_PARALLELISM_V2,
)
from src.file_format import is_v2, pack_header_v2, unpack_header_v2
from src.utils import (
    unpack_metadata, get_file_info, ensure_directory,
    get_metadata_size, KEY_TYPE_PASSWORD_ARGON2, SL01_MAGIC,
    pack_steal_locker_metadata, get_steal_locker_metadata_size,
    unpack_steal_locker_metadata, _sanitize_steal_locker_output_filename,
)
from src.secure_open import verify_device_identity, view_file_temp
from steal_locker.key import (
    ensure_keypair, load_public_key, load_private_key,
    wrap_symmetric_key, unwrap_symmetric_key, WRAPPED_BLOB_SIZE,
    _key_dir as _steal_key_dir,
)
from steal_locker import lock as steal_lock

def get_key_count():
    while True:
        try:
            count = int(input("How many encryption keys do you want to use? (2-50): ").strip())
            if 2 <= count <= 50:
                return count
            else:
                print("Please enter a number between 2 and 50.")
        except ValueError:
            print("Please enter a valid number.")

def get_output_directory(default_dir: str = "output") -> str:
    """Get output directory from user, with option to use default"""
    print(f"\nWhere would you like to save the output file(s)?")
    print(f"Press Enter to use default: '{default_dir}'")
    output_dir = input("Enter output directory path: ").strip().strip('"')
    
    if not output_dir:
        output_dir = default_dir
    
    # Create directory if it doesn't exist
    ensure_directory(output_dir)
    
    return output_dir

def collect_keys_without_saving(num_keys: int):
    """Collect keys without prompting to save them"""
    keys = []
    key_types = []
    salts = []

    print("\nEnter your encryption keys:")
    for i in range(num_keys):
        password = getpass.getpass(f"Enter key {i + 1}: ")
        if not password:
            print("Error: Key cannot be empty")
            return None

        salt = generate_salt()
        key = derive_key_argon2_v2(password.encode('utf-8'), salt)
        keys.append(key)
        key_types.append(KEY_TYPE_PASSWORD_ARGON2)
        salts.append(salt)

    return {
        'keys': keys,
        'key_types': key_types,
        'salts': salts,
    }

def build_v2_header(key_types: list[int], salts: list[bytes], filename: bytes, extension: bytes) -> bytes:
    """Build the authenticated V2 header recording the KDF params used for new encryptions."""
    key_params = [
        {
            'key_type': kt,
            'time_cost': ARGON2_TIME_COST_V2,
            'memory_cost': ARGON2_MEMORY_COST_V2,
            'parallelism': ARGON2_PARALLELISM_V2,
            'salt': salt,
        }
        for kt, salt in zip(key_types, salts)
    ]
    return pack_header_v2(key_params, filename, extension)

def derive_keys_from_v2_header(passwords: list[str], header: dict) -> list[bytes]:
    """Re-derive keys using the per-key params stored in a V2 header."""
    keys = []
    for password, kp in zip(passwords, header['keys']):
        keys.append(derive_key_argon2_with_params(
            password.encode('utf-8'), kp['salt'],
            kp['time_cost'], kp['memory_cost'], kp['parallelism'],
        ))
    return keys

def build_keyfile_entries(keys: list[bytes], salts: list[bytes]) -> list[dict]:
    """V2 key files store the derived keys, never the raw passwords (no cross-service password leak)."""
    return [{'index': i, 'key': keys[i].hex(), 'salt': salts[i].hex()} for i in range(len(keys))]

def save_keys_prompt(keys: list, salts: list):
    """Prompt user to save keys and handle the saving process"""
    key_data_list = build_keyfile_entries(keys, salts)
    print("\n" + "="*60)
    print("⚠ WARNING: Saving keys without encryption is risky!")
    print("If someone steals your key file, they can access your encrypted files.")
    print("="*60)

    save_option = input("\nDo you want to save these keys to your device? (y/n): ").strip().lower()
    
    if save_option == 'y':
        print("\n⚠ IMPORTANT: You will encrypt the key file with a password.")
        print("In the future, if you have the key file, you only need to remember")
        print("the password for the key file to unlock all your keys.")
        
        print("\nHow would you like to save the key file?")
        print("1. JSON file")
        print("2. Image (hidden in image using steganography)")
        
        format_choice = input("Select format (1-2): ").strip()
        
        if format_choice not in ['1', '2']:
            print("Error: Invalid format choice")
            return None
        
        key_file_password = getpass.getpass("\nEnter password to encrypt the key file: ")
        if not key_file_password:
            print("Error: Key file password cannot be empty")
            return None
        
        try:
            if format_choice == '1':
                key_file = input("Enter path to save key file: ").strip().strip('"')
                
                if os.path.isdir(key_file):
                    default_filename = os.path.join(key_file, "encryption_keys.json")
                    use_default = input(f"Path is a directory. Save as '{default_filename}'? (y/n): ").strip().lower()
                    if use_default == 'y':
                        key_file = default_filename
                    else:
                        filename = input("Enter filename (will be saved in the directory): ").strip()
                        if not filename:
                            print("Error: Filename cannot be empty")
                            return None
                        if not filename.endswith('.json'):
                            filename += '.json'
                        key_file = os.path.join(key_file, filename)
                
                key_file_dir = os.path.dirname(key_file)
                if key_file_dir:
                    ensure_directory(key_file_dir)
                
                save_keys_file_json(key_data_list, key_file, key_file_password)
                print(f"\n✓ All keys saved to {key_file}")
                print(f"⚠ Remember: You only need to remember the key file password to unlock all keys!")
            
            elif format_choice == '2':
                print("\n⚠ IMPORTANT: The output image will be saved as PNG format")
                print("   (PNG is required to preserve hidden steganography data)")
                print("   JPEG format cannot be used as it destroys hidden data during compression")
                
                cover_image = input("\nEnter path to cover image: ").strip().strip('"')
                if not os.path.exists(cover_image):
                    print(f"Error: Cover image not found: {cover_image}")
                    return None
                
                output_image = input("Enter path to save the image with hidden keys: ").strip().strip('"')
                
                if os.path.isdir(output_image):
                    default_filename = os.path.join(output_image, "encryption_keys.png")
                    use_default = input(f"Path is a directory. Save as '{default_filename}'? (y/n): ").strip().lower()
                    if use_default == 'y':
                        output_image = default_filename
                    else:
                        filename = input("Enter filename (will be saved in the directory): ").strip()
                        if not filename:
                            print("Error: Filename cannot be empty")
                            return None
                        # Always use .png extension
                        if not filename.lower().endswith('.png'):
                            filename += '.png'
                        output_image = os.path.join(output_image, filename)
                else:
                    # Ensure output has .png extension
                    if not output_image.lower().endswith('.png'):
                        base_name = os.path.splitext(output_image)[0]
                        output_image = base_name + '.png'
                        print(f"⚠ Output will be saved as: {output_image} (PNG format required)")
                
                output_dir = os.path.dirname(output_image)
                if output_dir:
                    ensure_directory(output_dir)
                
                try:
                    save_keys_file_image(key_data_list, cover_image, output_image, key_file_password)
                    print(f"\n✓ All keys hidden in image: {output_image}")
                    print(f"✓ The image looks normal but contains your encrypted keys!")
                    print(f"⚠ IMPORTANT: Keep this PNG file safe and DO NOT edit, compress, or convert it!")
                    print(f"   Any modification to the image will destroy the hidden keys.")
                    print(f"⚠ Remember: You only need to remember the key file password to unlock all keys!")
                except Exception as e:
                    print(f"Error saving keys to image: {str(e)}")
                    return None
            
            return True
        
        except Exception as e:
            print(f"Error saving keys: {str(e)}")
            return None
    
    # User chose not to save keys
    return True

def collect_keys(num_keys: int):
    keys = []
    key_types = []
    salts = []

    print("\nEnter your encryption keys:")
    for i in range(num_keys):
        password = getpass.getpass(f"Enter key {i + 1}: ")
        if not password:
            print("Error: Key cannot be empty")
            return None

        salt = generate_salt()
        key = derive_key_argon2_v2(password.encode('utf-8'), salt)
        keys.append(key)
        key_types.append(KEY_TYPE_PASSWORD_ARGON2)
        salts.append(salt)

    save_result = save_keys_prompt(keys, salts)
    if save_result is None:
        return None

    return {
        'keys': keys,
        'key_types': key_types,
        'salts': salts,
    }

def _interpret_key_file(all_keys_data: list, num_keys: int):
    """Turn a loaded key file into a material dict. V2 files carry derived keys; older files carry passwords."""
    if len(all_keys_data) != num_keys:
        print(f"Error: Key file contains {len(all_keys_data)} keys, but files require {num_keys} keys")
        return None
    if all('key' in entry for entry in all_keys_data):
        keys = []
        for entry in all_keys_data:
            key_bytes = bytes.fromhex(entry['key'])
            if len(key_bytes) != 32:
                print("Error: Invalid key in key file")
                return None
            keys.append(key_bytes)
        print(f"✓ All {num_keys} keys loaded from key file")
        return {'mode': 'keys', 'keys': keys}
    passwords = [entry['password'] for entry in all_keys_data]
    print(f"✓ All {num_keys} passwords loaded from key file")
    return {'mode': 'passwords', 'passwords': passwords}

def collect_key_material_for_decrypt(num_keys: int):
    """Collect key material once: ready keys from a V2 key file, or passwords (legacy file / manual entry)."""
    print(f"\nFiles encrypted with {num_keys} keys")
    load_option = input("Do you have a key file saved? (y/n): ").strip().lower()

    if load_option == 'y':
        print("\nWhat format is your key file?")
        print("1. JSON file")
        print("2. Image (with hidden keys)")

        format_choice = input("Select format (1-2): ").strip()

        if format_choice not in ['1', '2']:
            print("Error: Invalid format choice")
            return None

        if format_choice == '1':
            key_file = input("Enter path to key file: ").strip().strip('"')
            if not os.path.exists(key_file):
                print(f"Error: Key file not found: {key_file}")
                return None
            if os.path.isdir(key_file):
                print(f"Error: Path is a directory, not a file: {key_file}")
                return None
        else:
            key_file = input("Enter path to image with hidden keys: ").strip().strip('"')
            if not os.path.exists(key_file):
                print(f"Error: Image file not found: {key_file}")
                return None

        key_file_password = getpass.getpass("Enter password for the key file: ")
        try:
            if format_choice == '1':
                all_keys_data = load_keys_file_json(key_file, key_file_password)
            else:
                all_keys_data = load_keys_file_image(key_file, key_file_password)
            return _interpret_key_file(all_keys_data, num_keys)
        except Exception:
            print("Error loading keys: wrong password or corrupted key file.")
            return None
    else:
        print("\nEnter your encryption passwords:")
        passwords = []
        for i in range(num_keys):
            password = getpass.getpass(f"Enter password {i + 1}: ")
            if not password:
                print("Error: Password cannot be empty")
                return None
            passwords.append(password)
        return {'mode': 'passwords', 'passwords': passwords}

def derive_keys_from_passwords(passwords: list[str], salts: list[bytes]) -> list[bytes]:
    """Derive encryption keys from passwords and salts"""
    keys = []
    for i, password in enumerate(passwords):
        key = derive_key_argon2(password.encode('utf-8'), salts[i])
        keys.append(key)
    return keys

def encrypt_file():
    print("\n=== Quantum-Safe Multi-Layer Encryption ===\n")
    
    file_path = input("Enter path to file to encrypt: ").strip().strip('"')
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return
    
    num_keys = get_key_count()
    
    key_data = collect_keys(num_keys)
    if key_data is None:
        return
    
    output_dir = get_output_directory()
    
    filename, ext = get_file_info(file_path)
    output_file = os.path.join(output_dir, f"{filename}{ext}")
    
    print("\nEncrypting file...")
    
    try:
        file_size = os.path.getsize(file_path)
        print(f"File size: {file_size / (1024*1024):.2f} MB")
        print(f"Using {num_keys} encryption layers")
        
        with tqdm(desc="Generating encryption salts", leave=False) as pbar:
            pbar.update(1)

        original_filename = filename.encode('utf-8')
        file_extension = ext.encode('utf-8')

        with tqdm(desc="Preparing metadata", leave=False) as pbar:
            header = build_v2_header(key_data['key_types'], key_data['salts'], original_filename, file_extension)
            pbar.update(1)

        encrypted_data = multi_layer_encrypt(file_path, key_data['keys'], aad=header)
        full_payload = header + encrypted_data
        
        with tqdm(total=len(full_payload), unit='B', unit_scale=True, unit_divisor=1024, desc="Saving encrypted file") as pbar:
            with open(output_file, 'wb') as f:
                f.write(full_payload)
                pbar.update(len(full_payload))
        
        print(f"\n✓ Encryption complete!")
        print(f"✓ Encrypted file saved to: {output_file}")
        print(f"✓ Original file: {file_path}")
        print(f"\n⚠ IMPORTANT: Remember your keys to decrypt!")
        
    except Exception as e:
        print(f"Error during encryption: {str(e)}")

def decrypt_payload_to_memory(full_payload: bytes):
    """Decrypt a multi-layer payload (V2 or legacy) in memory.

    Returns (data, filename_bytes, ext_bytes), None if the user backed out, or raises on bad input/keys.
    """
    if is_v2(full_payload):
        header, header_size = unpack_header_v2(full_payload)
        material = collect_key_material_for_decrypt(len(header['keys']))
        if material is None:
            return None
        keys = material['keys'] if material['mode'] == 'keys' else derive_keys_from_v2_header(material['passwords'], header)
        data = multi_layer_decrypt(full_payload[header_size:], keys, aad=full_payload[:header_size])
        return data, header['filename'], header['extension']
    metadata_size = get_metadata_size(full_payload)
    key_types, salts, original_filename, file_extension = unpack_metadata(full_payload[:metadata_size])
    material = collect_key_material_for_decrypt(len(key_types))
    if material is None:
        return None
    keys = material['keys'] if material['mode'] == 'keys' else derive_keys_from_passwords(material['passwords'], salts)
    data = multi_layer_decrypt(full_payload[metadata_size:], keys)
    return data, original_filename, file_extension

def decrypt_file():
    print("\n=== Decrypt Quantum-Safe Multi-Layer Encrypted File ===\n")
    print("⚠ This writes an UNPROTECTED copy to disk. To just view a file, use 'Open file securely' instead.\n")

    encrypted_file = input("Enter path to encrypted file: ").strip().strip('"')
    if not os.path.exists(encrypted_file):
        print(f"Error: Encrypted file not found: {encrypted_file}")
        return

    output_dir = get_output_directory()

    print("\nDecrypting file...")

    try:
        file_size = os.path.getsize(encrypted_file)
        with tqdm(total=file_size, unit='B', unit_scale=True, unit_divisor=1024, desc="Reading encrypted file") as pbar:
            with open(encrypted_file, 'rb') as f:
                full_payload = f.read()
                pbar.update(file_size)

        result = decrypt_payload_to_memory(full_payload)
        if result is None:
            return
        decrypted_data, original_filename, file_extension = result

        output_filename = _sanitize_steal_locker_output_filename(original_filename, file_extension)
        output_path = os.path.join(output_dir, output_filename)
        
        with tqdm(total=len(decrypted_data), unit='B', unit_scale=True, unit_divisor=1024, desc="Saving decrypted file") as pbar:
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
                pbar.update(len(decrypted_data))
        
        print(f"\n✓ Decryption complete!")
        print(f"✓ Decrypted file saved to: {output_path}")
        
    except Exception:
        print("Decryption failed (wrong key, tampered data, or invalid file).")

def decrypt_directory():
    print("\n=== Decrypt All Files in Directory ===\n")
    
    dir_path = input("Enter path to directory containing encrypted files: ").strip().strip('"')
    if not os.path.exists(dir_path):
        print(f"Error: Directory not found: {dir_path}")
        return
    
    if not os.path.isdir(dir_path):
        print(f"Error: Path is not a directory: {dir_path}")
        return
    
    # Get all files in the directory (not subdirectories)
    files = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
    
    if not files:
        print(f"Error: No files found in directory: {dir_path}")
        return
    
    print(f"\nFound {len(files)} file(s) in directory:")
    for i, file in enumerate(files, 1):
        file_path = os.path.join(dir_path, file)
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
        print(f"  {i}. {file} ({file_size:.2f} MB)")
    
    # Read first file to get encryption parameters (should be same for all)
    first_file_path = os.path.join(dir_path, files[0])
    try:
        with open(first_file_path, 'rb') as f:
            full_payload = f.read()

        if is_v2(full_payload):
            header, _ = unpack_header_v2(full_payload)
            num_keys = len(header['keys'])
        else:
            metadata_size = get_metadata_size(full_payload)
            key_types, _, _, _ = unpack_metadata(full_payload[:metadata_size])
            num_keys = len(key_types)

        print(f"\n✓ Detected encryption parameters: {num_keys} keys")

    except Exception as e:
        print(f"Error reading first file to detect encryption parameters: {str(e)}")
        print("Make sure the directory contains valid encrypted files.")
        return
    
    # Collect key material once (same for all files): ready keys, or passwords to re-derive per file.
    material = collect_key_material_for_decrypt(num_keys)
    if material is None:
        return
    
    output_dir = get_output_directory()
    
    print(f"\n{'='*60}")
    print(f"Decrypting {len(files)} file(s) with the same passwords...")
    print(f"{'='*60}\n")
    
    successful = 0
    failed = 0
    
    for idx, filename in enumerate(files, 1):
        file_path = os.path.join(dir_path, filename)
        
        try:
            print(f"\n[{idx}/{len(files)}] Decrypting: {filename}")
            
            file_size = os.path.getsize(file_path)
            with tqdm(total=file_size, unit='B', unit_scale=True, unit_divisor=1024, desc="  Reading encrypted file", leave=False) as pbar:
                with open(file_path, 'rb') as f:
                    full_payload = f.read()
                    pbar.update(file_size)
            
            if is_v2(full_payload):
                header, header_size = unpack_header_v2(full_payload)
                keys = material['keys'] if material['mode'] == 'keys' else derive_keys_from_v2_header(material['passwords'], header)
                decrypted_data = multi_layer_decrypt(full_payload[header_size:], keys, aad=full_payload[:header_size])
                original_filename, file_extension = header['filename'], header['extension']
            else:
                metadata_size = get_metadata_size(full_payload)
                key_types, salts, original_filename, file_extension = unpack_metadata(full_payload[:metadata_size])
                keys = material['keys'] if material['mode'] == 'keys' else derive_keys_from_passwords(material['passwords'], salts)
                decrypted_data = multi_layer_decrypt(full_payload[metadata_size:], keys)

            output_filename = _sanitize_steal_locker_output_filename(original_filename, file_extension)
            output_path = os.path.join(output_dir, output_filename)
            
            with tqdm(total=len(decrypted_data), unit='B', unit_scale=True, unit_divisor=1024, desc="  Saving decrypted file", leave=False) as pbar:
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                    pbar.update(len(decrypted_data))
            
            print(f"  ✓ Decrypted: {output_path}")
            successful += 1
            
        except Exception:
            print(f"  ✗ Error decrypting {filename}: Decryption failed (wrong key, tampered data, or invalid file).")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"Decryption Summary:")
    print(f"  ✓ Successful: {successful}")
    print(f"  ✗ Failed: {failed}")
    print(f"{'='*60}")
    
    if successful > 0:
        print(f"\n✓ All decrypted files saved to: {output_dir}")

def encrypt_directory():
    print("\n=== Encrypt All Files in Directory ===\n")
    
    dir_path = input("Enter path to directory containing files to encrypt: ").strip().strip('"')
    if not os.path.exists(dir_path):
        print(f"Error: Directory not found: {dir_path}")
        return
    
    if not os.path.isdir(dir_path):
        print(f"Error: Path is not a directory: {dir_path}")
        return
    
    # Get all files in the directory (not subdirectories)
    files = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
    
    if not files:
        print(f"Error: No files found in directory: {dir_path}")
        return
    
    print(f"\nFound {len(files)} file(s) in directory:")
    for i, file in enumerate(files, 1):
        file_path = os.path.join(dir_path, file)
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
        print(f"  {i}. {file} ({file_size:.2f} MB)")
    
    num_keys = get_key_count()
    
    # Collect keys once for all files
    key_data = collect_keys_without_saving(num_keys)
    if key_data is None:
        return
    
    output_dir = get_output_directory()
    
    print(f"\n{'='*60}")
    print(f"Encrypting {len(files)} file(s) with the same keys...")
    print(f"{'='*60}\n")
    
    successful = 0
    failed = 0
    
    for idx, filename in enumerate(files, 1):
        file_path = os.path.join(dir_path, filename)
        
        try:
            print(f"\n[{idx}/{len(files)}] Encrypting: {filename}")
            
            file_size = os.path.getsize(file_path)
            print(f"  File size: {file_size / (1024*1024):.2f} MB")
            print(f"  Using {num_keys} encryption layers")
            
            name, ext = get_file_info(file_path)
            original_filename = name.encode('utf-8')
            file_extension = ext.encode('utf-8')

            header = build_v2_header(key_data['key_types'], key_data['salts'], original_filename, file_extension)
            encrypted_data = multi_layer_encrypt(file_path, key_data['keys'], aad=header)
            full_payload = header + encrypted_data
            
            output_file = os.path.join(output_dir, filename)
            
            with tqdm(total=len(full_payload), unit='B', unit_scale=True, unit_divisor=1024, desc="  Saving encrypted file", leave=False) as pbar:
                with open(output_file, 'wb') as f:
                    f.write(full_payload)
                    pbar.update(len(full_payload))
            
            print(f"  ✓ Encrypted: {output_file}")
            successful += 1
            
        except Exception as e:
            print(f"  ✗ Error encrypting {filename}: {str(e)}")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"Encryption Summary:")
    print(f"  ✓ Successful: {successful}")
    print(f"  ✗ Failed: {failed}")
    print(f"{'='*60}")
    
    if successful > 0:
        print(f"\n✓ All encrypted files saved to: {output_dir}")
        print(f"⚠ IMPORTANT: Remember your keys to decrypt!")
        
        # Ask if user wants to save keys (one key file for all)
        save_result = save_keys_prompt(key_data['keys'], key_data['salts'])
        if save_result is None:
            print("\n⚠ Keys were not saved. Make sure to remember them!")


def _steal_locker_key_dir() -> Path:
    # Use the OS-specific hidden key directory chosen by steal_locker.key
    return _steal_key_dir()


def encrypt_file_steal_locker():
    """Single file: encrypt with device key only (SL01 + wrapped key + AES-GCM)."""
    print("\n=== Steal Locker: Encrypt file (device key) ===\n")
    file_path = input("Enter path to file to encrypt: ").strip().strip('"')
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return
    key_dir = _steal_locker_key_dir()
    try:
        priv_path, pub_path = ensure_keypair(key_dir)
        pub = load_public_key(pub_path)
    except Exception as e:
        print(f"Error: {e}")
        return
    output_dir = get_output_directory()
    name, ext = get_file_info(file_path)
    fn_bytes, ext_bytes = name.encode("utf-8"), ext.encode("utf-8")
    sym_key = os.urandom(32)
    wrapped = wrap_symmetric_key(sym_key, pub)
    with open(file_path, "rb") as f:
        plaintext = f.read()
    aes = AESGCM(sym_key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    metadata = pack_steal_locker_metadata(WRAPPED_BLOB_SIZE, fn_bytes, ext_bytes)
    out_path = os.path.join(output_dir, f"{name}{ext}")
    with open(out_path, "wb") as f:
        f.write(metadata + wrapped + nonce + ct)
    print(f"\n✓ Encrypted to {out_path}")


def decrypt_steal_locker_payload_to_memory(payload: bytes, key_dir: Path):
    """Decrypt an SL01 payload in memory; returns (data, filename_bytes, ext_bytes). Raises on any failure."""
    meta_size = get_steal_locker_metadata_size(payload)
    metadata = payload[:meta_size]
    rest = payload[meta_size:]
    wlen, fn_bytes, ext_bytes = unpack_steal_locker_metadata(metadata)
    if len(rest) < wlen + 12:
        raise ValueError("invalid payload")
    wrapped = rest[:wlen]
    if len(wrapped) != WRAPPED_BLOB_SIZE:
        raise ValueError("invalid payload")
    priv = load_private_key(ensure_keypair(key_dir)[0])
    sym_key = unwrap_symmetric_key(wrapped, priv)
    nonce = rest[wlen : wlen + 12]
    ct = rest[wlen + 12 :]
    aes = AESGCM(sym_key)
    return aes.decrypt(nonce, ct, None), fn_bytes, ext_bytes


def decrypt_file_steal_locker():
    """Decrypt a Steal Locker file; one generic error to avoid oracle leakage."""
    print("\n=== Steal Locker: Decrypt file ===\n")
    enc_path = input("Enter path to encrypted file: ").strip().strip('"')
    if not os.path.exists(enc_path):
        print(f"Error: File not found: {enc_path}")
        return
    output_dir = get_output_directory()
    key_dir = _steal_locker_key_dir()
    try:
        with open(enc_path, "rb") as f:
            payload = f.read()
        plaintext, fn_bytes, ext_bytes = decrypt_steal_locker_payload_to_memory(payload, key_dir)
        out_name = _sanitize_steal_locker_output_filename(fn_bytes, ext_bytes)
        out_path = os.path.join(output_dir, out_name)
        with open(out_path, "wb") as f:
            f.write(plaintext)
        print(f"\n✓ Decrypted to {out_path}")
    except Exception:
        print("Decryption failed (wrong key, tampered data, or invalid file)")


def steal_locker_lock_folder():
    """Lock folder: (A) encrypt each file with option-3 then finalize, (B) zip then encrypt."""
    print("\n=== Steal Locker: Lock folder ===\n")
    dir_path = input("Enter path to folder to lock: ").strip().strip('"')
    if not os.path.isdir(dir_path):
        print("Error: Not a directory or not found.")
        return
    print("1. Encrypt every file (option-3 style) then finalize with device key")
    print("2. Zip folder then encrypt with device key")
    choice = input("Select (1 or 2): ").strip()
    key_dir = _steal_locker_key_dir()
    output_dir = get_output_directory()
    if choice == "1":
        num_keys = get_key_count()
        key_data = collect_keys_without_saving(num_keys)
        if key_data is None:
            return
        out_path = Path(output_dir) / (Path(dir_path).name + ".locked_dir")
        try:
            steal_lock.lock_folder_per_file(
                Path(dir_path), key_data, key_dir, out_path,
                progress_cb=lambda n: None,
            )
            print(f"\n✓ Locked folder saved to {out_path}")
        except Exception as e:
            print(f"Error: {e}")
    elif choice == "2":
        out_file = Path(output_dir) / (Path(dir_path).name + ".locked")
        try:
            steal_lock.lock_folder_zip(Path(dir_path), key_dir, out_file, progress_cb=lambda n: None)
            print(f"\n✓ Locked zip saved to {out_file}")
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Invalid choice.")


def steal_locker_unlock_folder():
    """Unlock a Steal Locker folder (either .locked_dir or .locked zip)."""
    print("\n=== Steal Locker: Unlock folder ===\n")
    path = input("Enter path to .locked_dir folder or .locked file: ").strip().strip('"')
    if not os.path.exists(path):
        print("Error: Not found.")
        return
    output_dir = get_output_directory()
    key_dir = _steal_locker_key_dir()
    try:
        if os.path.isfile(path) and path.endswith(".locked"):
            steal_lock.unlock_folder_zip(Path(path), key_dir, Path(output_dir))
            print(f"\n✓ Unzipped to {output_dir}")
        elif os.path.isdir(path):
            steal_lock.unlock_folder_per_file(Path(path), key_dir, Path(output_dir), progress_cb=lambda n: None)
            print(f"\n✓ Unlocked to {output_dir}")
        else:
            print("Error: Provide a .locked file or a .locked_dir directory.")
    except Exception:
        print("Decryption failed (wrong key, tampered data, or invalid file)")


def steal_locker_menu():
    while True:
        print("\n--- Steal Locker ---")
        print("1. Lock folder (encrypt each file + device key, or zip+encrypt)")
        print("2. Unlock folder")
        print("3. Encrypt file (device key only)")
        print("4. Decrypt file (device key)")
        print("5. Back to main menu")
        c = input("Select (1-5): ").strip()
        if c == "1":
            steal_locker_lock_folder()
        elif c == "2":
            steal_locker_unlock_folder()
        elif c == "3":
            encrypt_file_steal_locker()
        elif c == "4":
            decrypt_file_steal_locker()
        elif c == "5":
            return
        else:
            print("Invalid option.")


def open_file_securely():
    """Decrypt to a temp file for viewing only: optional device verification, then auto-wipe."""
    print("\n=== Open File Securely (temp view, auto-wipe) ===\n")
    enc_path = input("Enter path to encrypted file: ").strip().strip('"')
    if not os.path.exists(enc_path):
        print(f"Error: File not found: {enc_path}")
        return

    print("\nHow should the file be protected before opening?")
    print("1. Verify my identity with this device (Hello / Touch ID / account password)")
    print("2. Keys only (skip device verification)")
    protect_choice = input("Select (1-2, Enter = 1): ").strip()
    if protect_choice != '2':
        if not verify_device_identity():
            print("Verification failed. File stays locked.")
            return

    print("\nHow do you want to open it?")
    print("1. Open with the default app, wipe when I'm done")
    print("2. Extract to a temp folder (I'll open it myself), wipe when I'm done")
    open_choice = input("Select (1-2, Enter = 1): ").strip()
    launch = open_choice != '2'

    try:
        with open(enc_path, 'rb') as f:
            full_payload = f.read()

        if full_payload[:4] == SL01_MAGIC:
            # Steal Locker file: the device key itself is the gate.
            data, fn_bytes, ext_bytes = decrypt_steal_locker_payload_to_memory(full_payload, _steal_locker_key_dir())
        else:
            result = decrypt_payload_to_memory(full_payload)
            if result is None:
                return
            data, fn_bytes, ext_bytes = result

        filename = _sanitize_steal_locker_output_filename(fn_bytes, ext_bytes)
        view_file_temp(data, filename, launch=launch)
    except Exception:
        print("Decryption failed (wrong key, tampered data, or invalid file).")


def main():
    print("=" * 60)
    print("  Quantum-Safe Multi-Layer Encryption")
    print("=" * 60)

    while True:
        print("\nOptions:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Encrypt all files in a directory")
        print("4. Decrypt all files in a directory")
        print("5. Open file securely (temp view, auto-wipe)")
        print("6. Steal Locker (device keys, no third-party recovery)")
        print("7. Exit")

        choice = input("\nSelect an option (1-7): ").strip()

        if choice == '1':
            encrypt_file()
        elif choice == '2':
            decrypt_file()
        elif choice == '3':
            encrypt_directory()
        elif choice == '4':
            decrypt_directory()
        elif choice == '5':
            open_file_securely()
        elif choice == '6':
            steal_locker_menu()
        elif choice == '7':
            print("\nGoodbye!")
            sys.exit(0)
        else:
            print("Invalid option. Please select 1-7.")

if __name__ == "__main__":
    main()
