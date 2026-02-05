# Steal Locker — How It Works

Steal Locker is a device-bound encryption path: keys are generated and stored only on your machine. No third party (including Microsoft or any OS vendor) can recover your data; only you, with this machine’s key, can decrypt.

## Why “Steal Locker”

Unlike BitLocker (and similar), recovery keys are not sent or storable by the OS vendor. Keys are created locally and never leave your control. If you lose the key (e.g. lose the machine and have no backup), the data cannot be recovered by anyone—by design.

## Components

- **`steal_locker/`**  
  All Steal Locker code lives here.

- **`steal_locker/key.py`**  
  SSH-style keypair and key wrapping:
  - **Keypair:** X25519 (Curve25519) private/public key, 32 bytes each.
  - **Storage:** `key.private` and `key.public` in the `steal_locker` folder. Private key is restricted to owner-only (e.g. `chmod 0o600`) and must not be a symlink.
  - **Wrapping:** A 32-byte symmetric key is wrapped for “this machine” using ECDH (X25519) + HKDF-SHA256 + AES-256-GCM. Only the holder of `key.private` can unwrap.
  - **Blob:** Fixed 92 bytes: ephemeral public (32) + nonce (12) + ciphertext (32+16). Length and symlink checks prevent misuse and oracle attacks.

- **`steal_locker/lock.py`**  
  Folder locking:
  - **Option A (per-file + finalize):** Encrypt every file with the same multi-layer scheme as “option 3” (AES-GCM + ChaCha20-Poly1305 layers). Then encrypt the key material (passwords/salts) with a random symmetric key and wrap that key with the device key. Only this machine can unwrap and then decrypt the files.
  - **Option B (zip then encrypt):** Zip the folder, encrypt the zip with a random key, wrap that key with the device key. One `.locked` file; unlock restores the tree.

- **`src/utils.py` (SL01)**  
  Steal Locker metadata for single-file format:
  - **Format:** Magic `SL01` + lengths (wlen, fnlen, extlen) + filename + extension. Lengths are capped (wlen ≤ 256, fnlen ≤ 4096, extlen ≤ 256) to avoid overflow/OOM. Total metadata size is validated so parsing never reads past the buffer.
  - **Path traversal:** Output filenames are sanitized (basename only, no `..` or path separators) so decryption cannot write outside the chosen output directory.

- **`main.py`**  
  Menu option **5. Steal Locker**:
  1. **Lock folder** — Choose (A) encrypt each file then finalize with device key, or (B) zip then encrypt.
  2. **Unlock folder** — Unlock a `.locked_dir` or `.locked` bundle.
  3. **Encrypt file** — Single file encrypted with device key only (SL01 + wrapped key + AES-GCM).
  4. **Decrypt file** — Decrypt a Steal Locker file; single generic error message to avoid decryption oracles.

## Single-file format (device key only)

1. **Encrypt:** Generate random 32-byte key → wrap with device public key → encrypt file with AES-256-GCM using that key. Output = SL01 metadata + 92-byte wrapped blob + nonce + ciphertext.
2. **Decrypt:** Read SL01 metadata (with length caps and bounds checks), read wrapped blob (exactly 92 bytes), unwrap with device private key, decrypt with AES-GCM, write using sanitized filename.

## Folder formats

- **Per-file + finalize (option A):** Output is a directory (e.g. `name.locked_dir`) containing:
  - `manifest`: 92-byte wrapped key + encrypted payload (key material + file list). Only this machine can unwrap and recover the multi-layer keys and filenames.
  - `000000.enc`, `000001.enc`, …: each file encrypted with the same multi-layer scheme as option 3.

- **Zip then encrypt (option B):** One `.locked` file = 92-byte wrapped key + nonce + AES-GCM(zip bytes). Unlock: unwrap key, decrypt, unzip to output directory.

## Security properties

- **Device-bound:** Decryption requires the private key on this machine (or a backup you control). No cloud or vendor recovery.
- **No oracle leakage:** Decrypt failures (wrong key, tampered data, bad format) all yield the same generic message; no distinct errors or timing to probe the key or ciphertext.
- **Path traversal:** Decrypted filenames are sanitized so output never escapes the chosen directory.
- **Bounded parsing:** SL01 and key blobs use fixed or capped lengths and strict checks so malformed input cannot cause overflow or out-of-bounds read.

## Where keys live

- **Device keypair:** `safe_lock/steal_locker/key.private` and `key.public`. Created on first use. Back these up securely if you want to unlock on another machine or after reinstall; without them, Steal Locker data cannot be recovered.
