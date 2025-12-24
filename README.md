# Quantum-Safe Multi-Layer Encryption Tool

A secure encryption tool that lets you encrypt your sensitive files with multiple layers of protection. You can use anywhere from 2 to 50 different encryption keys, and all your keys can be saved securely so you don't have to remember them all.

## What Makes This Secure

This tool uses quantum-safe encryption algorithms that are designed to remain secure even as computing power advances. Your files are encrypted multiple times with different keys, making them extremely difficult to crack. Even if someone gets one key, your data remains protected by the other layers.

## Getting Started

### Setting Up Your Environment

First, you'll want to create a virtual environment to keep everything organized and avoid conflicts with other Python projects on your system.

**On Windows:**
```
python -m venv venv
venv\Scripts\activate
```

**On Mac or Linux:**
```
python3 -m venv venv
source venv/bin/activate
```

Once your virtual environment is active, you'll see `(venv)` at the start of your command prompt. This means you're working in an isolated environment.

### Installing Dependencies

With your virtual environment active, install the required packages:

```
pip install -r requirements.txt
```

This will install all the necessary libraries for encryption, key derivation, and steganography.

### Running the Tool

Start the program by running:

```
python main.py
```

You'll see a menu with options to encrypt or decrypt files.

## How to Encrypt a File

When you choose to encrypt a file, the program will guide you through these steps:

1. **Choose your file**: Enter the full path to the file you want to encrypt. You can drag and drop the file into the terminal or type the path manually.

2. **Decide on key count**: You'll be asked how many encryption keys you want to use. The minimum is 2, and you can go up to 50. More keys mean more security, but also more to remember or manage.

3. **Enter your keys**: For each key, you'll be prompted to enter a password. These are your encryption keys, so make them strong and memorable. The program will hide what you type for security.

4. **Save your keys (optional)**: After entering all your keys, you'll be asked if you want to save them to your device. This is helpful because you won't have to remember all those keys later.

   - If you choose to save, you'll need to pick a format:
     - **JSON file**: A regular file that stores your encrypted keys
     - **Image**: Your keys will be hidden inside an image file using steganography, so it just looks like a normal picture
   
   - You'll also need to create a password for the key file itself. This is the only password you'll need to remember if you save your keys. The key file is encrypted, so even if someone finds it, they can't use it without your password.

5. **Wait for encryption**: The program will show you progress as it encrypts your file. This might take a moment for large files.

Your encrypted file will be saved in the output folder with the same name and extension as the original. The original file remains unchanged.

## How to Decrypt a File

To get your file back, you'll need to decrypt it:

1. **Choose your encrypted file**: Enter the path to the encrypted file you want to decrypt.

2. **Provide your keys**: You have two options here:
   - If you saved your keys earlier, you can load them from the file or image. You'll just need to enter the password you used to protect the key file.
   - If you didn't save your keys, you'll need to enter each key manually, just like when you encrypted the file.

3. **Wait for decryption**: The program will decrypt your file and save it in the output folder.

## Understanding Key Files

When you save your keys, they're stored in an encrypted format. This means:

- Your actual keys are never stored in plain text
- The key file itself is protected by a password you choose
- Even if someone steals the key file, they can't use it without your password
- You only need to remember one password (for the key file) instead of remembering all your encryption keys

If you choose to save keys in an image, the image will look completely normal. The keys are hidden using steganography, which embeds the data in a way that's invisible to the naked eye. You can share the image, use it as a wallpaper, or store it anywhere, and it will still look like a regular picture.

## Important Security Notes

- Always remember your key file password if you choose to save your keys. Without it, you won't be able to decrypt your files even if you have the key file.

- If you don't save your keys, make sure you remember all of them. There's no way to recover your files if you forget your encryption keys.

- Keep backups of your encrypted files and key files in safe places. If you lose either, you lose access to your data.

- The encrypted files are saved with the same name as the originals. Be careful not to overwrite important files.

- This tool is designed for personal use. Make sure you understand how encryption works before using it for critical data.

## Frequently Asked Questions

**Can I decrypt my files on another device?**

Yes, absolutely. You can decrypt your files on any device that has this tool installed. Here's what you need:

- The encrypted file itself (you can copy it to the other device)
- Either your original encryption keys, or your saved key file along with the password for that key file

If you saved your keys to a file or image, just copy that file or image to the other device along with the encrypted file. When you run the decryption process on the new device, choose to load from your key file and enter the password you used to protect it. The tool will work exactly the same way on any computer.

If you didn't save your keys, you'll need to remember and enter all your encryption keys manually on the new device. This is why saving your keys to a file is recommended if you plan to use your encrypted files across multiple devices.

## Troubleshooting

**The program says my file wasn't found:**
Make sure you're using the full path to the file, including the drive letter on Windows. You can right-click a file and copy its path to avoid typing mistakes.

**I forgot my key file password:**
Unfortunately, there's no way to recover this. The encryption is designed this way for security. You'll need to decrypt using your original keys if you remember them.

**The encryption is taking a long time:**
Large files and more encryption keys will take longer to process. This is normal. The progress bars will show you how things are going.

**I'm getting permission errors:**
Make sure you have write permissions in the output folder and wherever you're trying to save key files. On Windows, you might need to run the program as administrator if you're saving to certain locations.

## Upcoming Features

**Same Device Decryption Only Option**

We're working on adding an option that lets you restrict decryption to the device where you encrypted the file. When you choose this option during encryption, the tool will generate a private key unique to your device and incorporate it into the encryption process.

This means:
- Your encrypted file can only be decrypted on the same computer where it was encrypted
- Even if someone has your encryption keys and the encrypted file, they won't be able to decrypt it on a different device
- This provides an extra layer of security for files you only want accessible on one specific machine
- You'll still be able to choose between device-locked and portable encryption when you encrypt each file

This feature is useful if you want to ensure your sensitive files never leave your primary device, even if your encryption keys or key files are compromised. The device-specific key is generated from hardware and system characteristics, making it unique to your computer.

## Technical Details

The tool uses AES-256-GCM and ChaCha20-Poly1305 encryption algorithms, which are considered quantum-resistant for symmetric encryption. Keys are derived using Argon2, a memory-hard function that makes brute-force attacks extremely difficult. The alternating use of different encryption algorithms provides additional security layers.

Keys are derived from your passwords using Argon2, which is designed to be resistant to both traditional and quantum computing attacks. Each key gets its own randomly generated salt, ensuring that even identical passwords produce different encryption keys.
