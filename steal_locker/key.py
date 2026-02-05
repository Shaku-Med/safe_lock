"""
SSH-style keypair for Steal Locker. X25519 + HKDF + AES-256-GCM.
Keys stay on this machine; only the holder of the private key can unwrap data.
Optionally, the device private key itself can be encrypted with a passphrase.

First time we create keys we also ask where to store them:
- Default: an OS-specific \"hidden\" app directory under the current user.
- Custom: any folder/drive path the user chooses.
"""
import json
import os
import sys
from getpass import getpass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.key_derivation import derive_key_argon2, generate_salt

KEY_SIZE = 32
NONCE_SIZE = 12
# blob: ephemeral_public(32) + nonce(12) + ciphertext(32+16)
WRAPPED_BLOB_SIZE = 32 + 12 + 32 + 16  # 92

_default_key_dir: Path | None = None
_DEVICE_KEY_NONCE_SIZE = 12


def _default_os_key_dir() -> Path:
    """OS-specific default directory for Steal Locker device keys."""
    home = Path.home()
    if os.name == "nt":
        root = Path(os.environ.get("APPDATA", home))
        return root / "StealLocker" / "keys"
    if sys.platform == "darwin":
        root = home / "Library" / "Application Support"
        return root / "StealLocker" / "keys"
    # Linux / Unix
    return home / ".steal_locker"


def _key_dir() -> Path:
    global _default_key_dir
    if _default_key_dir is None:
        _default_key_dir = _default_os_key_dir()
    return _default_key_dir


def generate_keypair(key_dir: Path | None = None) -> tuple[bytes, bytes]:
    """Generate X25519 keypair; return (private_32, public_32)."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw_priv, raw_pub


def _encrypt_device_private_key(raw_priv: bytes, passphrase: str) -> bytes:
    """Encrypt device private key with a user passphrase using Argon2 + AES-GCM."""
    salt = generate_salt()
    key = derive_key_argon2(passphrase.encode("utf-8"), salt)
    aes = AESGCM(key)
    nonce = os.urandom(_DEVICE_KEY_NONCE_SIZE)
    ct = aes.encrypt(nonce, raw_priv, None)
    data = {
        "v": 1,
        "enc": True,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ct": ct.hex(),
    }
    return json.dumps(data).encode("utf-8")


def _decrypt_device_private_key(blob: bytes, get_passphrase) -> bytes:
    """Decrypt device private key, prompting for passphrase via get_passphrase()."""
    try:
        obj = json.loads(blob.decode("utf-8"))
        if not obj.get("enc"):
            raise ValueError("Not an encrypted key file")
    except Exception as e:
        raise ValueError(f"Invalid encrypted device key format: {e}")

    try:
        salt = bytes.fromhex(obj["salt"])
        nonce = bytes.fromhex(obj["nonce"])
        ct = bytes.fromhex(obj["ct"])
    except Exception as e:
        raise ValueError(f"Corrupted encrypted device key: {e}")

    # Single prompt per call; caller can retry if desired.
    pw = get_passphrase()
    if not pw:
        raise ValueError("Empty passphrase not allowed for encrypted device key")
    key = derive_key_argon2(pw.encode("utf-8"), salt)
    aes = AESGCM(key)
    try:
        raw_priv = aes.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Failed to decrypt device key (wrong passphrase or corrupted file)")
    if len(raw_priv) != KEY_SIZE:
        raise ValueError("Decrypted device key has invalid length")
    return raw_priv


def ensure_keypair(key_dir: Path | None = None) -> tuple[Path, Path]:
    """
    Create key.private and key.public in key_dir if missing; return (priv_path, pub_path).

    On first creation:
    - Ask where to store the keys (default hidden OS dir vs custom folder/drive).
    - Ask once if the user wants to protect the device key with a passphrase.
    """
    base = key_dir or _key_dir()
    priv_path = base / "key.private"
    pub_path = base / "key.public"

    if not priv_path.exists() or not pub_path.exists():
        # Let user choose where to store keys.
        print("\nWhere do you want to store the Steal Locker device keys?")
        print(f"1. Default (hidden) location on this device: {base}")
        print("2. Custom folder or drive (you pick the path)")
        loc_choice = input("Select (1-2, Enter = 1): ").strip()
        if loc_choice == "2":
            custom = input("Enter folder path for device keys: ").strip().strip('"')
            if custom:
                base = Path(custom)
                priv_path = base / "key.private"
                pub_path = base / "key.public"

        base.mkdir(parents=True, exist_ok=True)

        # First-time setup: offer optional passphrase protection.
        print("\nSteal Locker device key will be created for this machine.")
        while True:
            choice = input("Protect device key with a passphrase? (y/n): ").strip().lower()
            if choice in ("y", "n", ""):
                break
            print("Please type 'y' or 'n'.")
        raw_priv, raw_pub = generate_keypair()
        if len(raw_priv) != KEY_SIZE or len(raw_pub) != KEY_SIZE:
            raise ValueError("Key size mismatch")

        if choice == "y":
            print("\nIf you forget this passphrase, your Steal Locker data is PERMANENTLY lost.")
            print("There is no recovery key, no backdoor, and no way to reset it.")
            pw1 = getpass("Enter passphrase to encrypt device key: ")
            pw2 = getpass("Re-enter passphrase: ")
            if not pw1 or pw1 != pw2:
                print("Passphrases did not match or were empty; storing device key WITHOUT passphrase.")
                priv_path.write_bytes(raw_priv)
            else:
                enc_blob = _encrypt_device_private_key(raw_priv, pw1)
                priv_path.write_bytes(enc_blob)
        else:
            priv_path.write_bytes(raw_priv)

        try:
            os.chmod(priv_path, 0o600)
        except OSError:
            pass
        pub_path.write_bytes(raw_pub)
    else:
        # Tighten permissions on existing key file if possible.
        try:
            os.chmod(priv_path, 0o600)
        except OSError:
            pass

    return priv_path, pub_path


def load_private_key(path: Path | str) -> bytes:
    """
    Load 32-byte private key; reject symlinks.

    If the key file is encrypted JSON, prompt once for the passphrase.
    """
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Private key path must not be a symlink")
    raw = path.read_bytes()

    # Try encrypted JSON first.
    try:
        text = raw.decode("utf-8")
        if text.strip().startswith("{"):
            # Encrypted key format.
            return _decrypt_device_private_key(
                raw,
                get_passphrase=lambda: getpass("Enter passphrase for Steal Locker device key: "),
            )
    except UnicodeDecodeError:
        # Not JSON, fall back to raw.
        pass

    if len(raw) != KEY_SIZE:
        raise ValueError("Private key must be exactly 32 bytes")
    return raw


def load_public_key(path: Path | str) -> bytes:
    """Load 32-byte public key."""
    raw = Path(path).read_bytes()
    if len(raw) != KEY_SIZE:
        raise ValueError("Public key must be exactly 32 bytes")
    return raw


def wrap_symmetric_key(sym_key: bytes, recipient_public_key: bytes) -> bytes:
    """Wrap 32-byte sym_key for recipient; returns fixed-size blob (92 bytes)."""
    if len(sym_key) != KEY_SIZE:
        raise ValueError("Symmetric key must be 32 bytes")
    if len(recipient_public_key) != KEY_SIZE:
        raise ValueError("Public key must be 32 bytes")
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    peer_pub = x25519.X25519PublicKey.from_public_bytes(recipient_public_key)
    shared = ephemeral_priv.exchange(peer_pub)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=b"steal_locker_wrap_v1",
    ).derive(shared)
    aes = AESGCM(derived)
    nonce = os.urandom(NONCE_SIZE)
    ct = aes.encrypt(nonce, sym_key, None)
    return ephemeral_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) + nonce + ct


def unwrap_symmetric_key(blob: bytes, private_key: bytes) -> bytes:
    """Unwrap blob with private key; return 32-byte sym_key. Enforces exact blob size."""
    if len(blob) != WRAPPED_BLOB_SIZE:
        raise ValueError("Wrapped blob must be exactly 92 bytes")
    if len(private_key) != KEY_SIZE:
        raise ValueError("Private key must be 32 bytes")
    ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(blob[:32])
    priv_key = x25519.X25519PrivateKey.from_private_bytes(private_key)
    shared = priv_key.exchange(ephemeral_pub)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=b"steal_locker_wrap_v1",
    ).derive(shared)
    aes = AESGCM(derived)
    nonce = blob[32:44]
    ct = blob[44:92]
    return aes.decrypt(nonce, ct, None)
