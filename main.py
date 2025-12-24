import os
import sys
import getpass
from pathlib import Path
from tqdm import tqdm
from src.encryption import multi_layer_encrypt, multi_layer_decrypt
from src.key_derivation import (
    derive_key_argon2, generate_salt,
    save_keys_file_json, load_keys_file_json,
    save_keys_file_image, load_keys_file_image
)
from src.utils import (
    pack_metadata, unpack_metadata, get_file_info, ensure_directory,
    get_metadata_size, KEY_TYPE_PASSWORD_ARGON2
)

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
    key_data_list = []
    
    print("\nEnter your encryption keys:")
    for i in range(num_keys):
        password = getpass.getpass(f"Enter key {i + 1}: ")
        if not password:
            print("Error: Key cannot be empty")
            return None
        
        salt = generate_salt()
        key = derive_key_argon2(password.encode('utf-8'), salt)
        keys.append(key)
        key_types.append(KEY_TYPE_PASSWORD_ARGON2)
        salts.append(salt)
        key_data_list.append({
            'index': i,
            'password': password,
            'salt': salt.hex()
        })
    
    return {
        'keys': keys,
        'key_types': key_types,
        'salts': salts,
        'key_data_list': key_data_list
    }

def save_keys_prompt(key_data_list: list):
    """Prompt user to save keys and handle the saving process"""
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
    key_data_list = []
    
    print("\nEnter your encryption keys:")
    for i in range(num_keys):
        password = getpass.getpass(f"Enter key {i + 1}: ")
        if not password:
            print("Error: Key cannot be empty")
            return None
        
        salt = generate_salt()
        key = derive_key_argon2(password.encode('utf-8'), salt)
        keys.append(key)
        key_types.append(KEY_TYPE_PASSWORD_ARGON2)
        salts.append(salt)
        key_data_list.append({
            'index': i,
            'password': password,
            'salt': salt.hex()
        })
    
    save_result = save_keys_prompt(key_data_list)
    if save_result is None:
        return None
    
    return {
        'keys': keys,
        'key_types': key_types,
        'salts': salts,
        'key_data_list': key_data_list
    }

def collect_passwords_for_decrypt(num_keys: int):
    """Collect passwords once (from key file or manual input) for directory decryption"""
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
            
            if len(all_keys_data) != num_keys:
                print(f"Error: Key file contains {len(all_keys_data)} keys, but files require {num_keys} keys")
                return None
            
            passwords = []
            for i in range(num_keys):
                key_data = all_keys_data[i]
                passwords.append(key_data['password'])
            
            print(f"✓ All {num_keys} passwords loaded from key file")
            return passwords
        except Exception as e:
            print(f"Error loading keys: {str(e)}")
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
        
        return passwords

def derive_keys_from_passwords(passwords: list[str], salts: list[bytes]) -> list[bytes]:
    """Derive encryption keys from passwords and salts"""
    keys = []
    for i, password in enumerate(passwords):
        key = derive_key_argon2(password.encode('utf-8'), salts[i])
        keys.append(key)
    return keys

def collect_keys_for_decrypt(num_keys: int, key_types: list[int], salts: list[bytes]):
    keys = []
    
    print(f"\nFile encrypted with {num_keys} keys")
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
            
            if len(all_keys_data) != num_keys:
                print(f"Error: Key file contains {len(all_keys_data)} keys, but file requires {num_keys} keys")
                return None
            
            for i in range(num_keys):
                key_data = all_keys_data[i]
                password = key_data['password']
                salt = bytes.fromhex(key_data['salt'])
                key = derive_key_argon2(password.encode('utf-8'), salt)
                keys.append(key)
            
            print(f"✓ All {num_keys} keys loaded from file")
            return keys
        except Exception as e:
            print(f"Error loading keys: {str(e)}")
            return None
    else:
        print("\nEnter your encryption keys:")
        for i in range(num_keys):
            password = getpass.getpass(f"Enter key {i + 1}: ")
            if not password:
                print("Error: Key cannot be empty")
                return None
            
            salt = salts[i]
            key = derive_key_argon2(password.encode('utf-8'), salt)
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
        
        encrypted_data = multi_layer_encrypt(file_path, key_data['keys'])
        
        original_filename = filename.encode('utf-8')
        file_extension = ext.encode('utf-8')
        
        with tqdm(desc="Preparing metadata", leave=False) as pbar:
            metadata = pack_metadata(key_data['key_types'], key_data['salts'], original_filename, file_extension)
            full_payload = metadata + encrypted_data
            pbar.update(1)
        
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

def decrypt_file():
    print("\n=== Decrypt Quantum-Safe Multi-Layer Encrypted File ===\n")
    
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
        
        with tqdm(desc="Extracting metadata", leave=False) as pbar:
            metadata_size = get_metadata_size(full_payload)
            metadata = full_payload[:metadata_size]
            encrypted_data = full_payload[metadata_size:]
            pbar.update(1)
        
        key_types, salts, original_filename, file_extension = unpack_metadata(metadata)
        num_keys = len(key_types)
        
        keys = collect_keys_for_decrypt(num_keys, key_types, salts)
        if keys is None:
            return
        
        decrypted_data = multi_layer_decrypt(encrypted_data, keys)
        
        original_filename_str = original_filename.decode('utf-8')
        file_extension_str = file_extension.decode('utf-8')
        output_filename = f"{original_filename_str}{file_extension_str}"
        output_path = os.path.join(output_dir, output_filename)
        
        with tqdm(total=len(decrypted_data), unit='B', unit_scale=True, unit_divisor=1024, desc="Saving decrypted file") as pbar:
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
                pbar.update(len(decrypted_data))
        
        print(f"\n✓ Decryption complete!")
        print(f"✓ Decrypted file saved to: {output_path}")
        
    except Exception as e:
        print(f"Error during decryption: {str(e)}")
        print("Make sure you entered the correct keys and the file is a valid encrypted file.")

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
        file_size = os.path.getsize(first_file_path)
        with open(first_file_path, 'rb') as f:
            full_payload = f.read()
        
        metadata_size = get_metadata_size(full_payload)
        metadata = full_payload[:metadata_size]
        key_types, _, _, _ = unpack_metadata(metadata)
        num_keys = len(key_types)
        
        print(f"\n✓ Detected encryption parameters: {num_keys} keys")
        
    except Exception as e:
        print(f"Error reading first file to detect encryption parameters: {str(e)}")
        print("Make sure the directory contains valid encrypted files.")
        return
    
    # Collect passwords once (same passwords for all files)
    passwords = collect_passwords_for_decrypt(num_keys)
    if passwords is None:
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
            
            with tqdm(desc="  Extracting metadata", leave=False) as pbar:
                metadata_size = get_metadata_size(full_payload)
                metadata = full_payload[:metadata_size]
                encrypted_data = full_payload[metadata_size:]
                pbar.update(1)
            
            key_types, salts, original_filename, file_extension = unpack_metadata(metadata)
            
            # Derive keys for this file using its salts and the passwords
            keys = derive_keys_from_passwords(passwords, salts)
            
            decrypted_data = multi_layer_decrypt(encrypted_data, keys)
            
            original_filename_str = original_filename.decode('utf-8')
            file_extension_str = file_extension.decode('utf-8')
            output_filename = f"{original_filename_str}{file_extension_str}"
            output_path = os.path.join(output_dir, output_filename)
            
            with tqdm(total=len(decrypted_data), unit='B', unit_scale=True, unit_divisor=1024, desc="  Saving decrypted file", leave=False) as pbar:
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                    pbar.update(len(decrypted_data))
            
            print(f"  ✓ Decrypted: {output_path}")
            successful += 1
            
        except Exception as e:
            print(f"  ✗ Error decrypting {filename}: {str(e)}")
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
            
            encrypted_data = multi_layer_encrypt(file_path, key_data['keys'])
            
            name, ext = get_file_info(file_path)
            original_filename = name.encode('utf-8')
            file_extension = ext.encode('utf-8')
            
            metadata = pack_metadata(key_data['key_types'], key_data['salts'], original_filename, file_extension)
            full_payload = metadata + encrypted_data
            
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
        save_result = save_keys_prompt(key_data['key_data_list'])
        if save_result is None:
            print("\n⚠ Keys were not saved. Make sure to remember them!")

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
        print("5. Exit")
        
        choice = input("\nSelect an option (1-5): ").strip()
        
        if choice == '1':
            encrypt_file()
        elif choice == '2':
            decrypt_file()
        elif choice == '3':
            encrypt_directory()
        elif choice == '4':
            decrypt_directory()
        elif choice == '5':
            print("\nGoodbye!")
            sys.exit(0)
        else:
            print("Invalid option. Please select 1, 2, 3, 4, or 5.")

if __name__ == "__main__":
    main()
