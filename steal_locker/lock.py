"""
Lock folder: (A) encrypt each file with option-3 multi-layer then finalize with device key,
or (B) zip folder then encrypt with wrapped key.
"""
import json
import os
import zipfile
import io
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from steal_locker.key import (
    ensure_keypair,
    load_public_key,
    load_private_key,
    wrap_symmetric_key,
    unwrap_symmetric_key,
    WRAPPED_BLOB_SIZE,
)
from src.encryption import multi_layer_encrypt, multi_layer_decrypt
from src.key_derivation import derive_key_argon2

NONCE_SIZE = 12
KEY_SIZE = 32
# V2 manifests store the derived keys directly (no raw passwords); V1 stored passwords + salts.
MANIFEST_VERSION = 2


def _encrypt_key_data(sym_key: bytes, keys_hex: list, file_list: list) -> bytes:
    payload = json.dumps({"v": MANIFEST_VERSION, "keys": keys_hex, "files": file_list}).encode("utf-8")
    aes = AESGCM(sym_key)
    nonce = os.urandom(NONCE_SIZE)
    return nonce + aes.encrypt(nonce, payload, None)


def _decrypt_key_data(sym_key: bytes, blob: bytes) -> tuple[str, list, list]:
    """Return (kind, material, files). kind is 'keys' (V2) or 'legacy' (V1 passwords+salts)."""
    if len(blob) < NONCE_SIZE:
        raise ValueError("Decryption failed (wrong key, tampered data, or invalid file)")
    aes = AESGCM(sym_key)
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    raw = aes.decrypt(nonce, ct, None)
    data = json.loads(raw.decode("utf-8"))
    version = data.get("v")
    if version == 2:
        return "keys", data["keys"], data["files"]
    if version == 1:
        return "legacy", data["key_data_list"], data["files"]
    raise ValueError("Decryption failed (wrong key, tampered data, or invalid file)")


def lock_folder_per_file(
    dir_path: Path,
    key_data: dict,
    key_dir: Path,
    output_dir: Path,
    progress_cb=None,
) -> None:
    """Encrypt every file with option-3 multi-layer, then seal key material with device key."""
    dir_path = Path(dir_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    files = [f for f in dir_path.iterdir() if f.is_file()]
    file_list = []
    keys = key_data["keys"]

    for f in files:
        name, ext = f.stem, f.suffix
        file_list.append({"name": name, "ext": ext})
        enc = multi_layer_encrypt(str(f), keys)
        out_name = f"{len(file_list) - 1:06d}.enc"
        (output_dir / out_name).write_bytes(enc)
        if progress_cb:
            progress_cb(f.name)

    sym_key = os.urandom(KEY_SIZE)
    priv_path, pub_path = ensure_keypair(key_dir)
    pub = load_public_key(pub_path)
    wrapped = wrap_symmetric_key(sym_key, pub)
    keys_hex = [k.hex() for k in keys]
    manifest_payload = _encrypt_key_data(sym_key, keys_hex, file_list)
    (output_dir / "manifest").write_bytes(wrapped + manifest_payload)


def unlock_folder_per_file(locked_dir: Path, key_dir: Path, output_dir: Path, progress_cb=None) -> None:
    """Unlock folder locked with lock_folder_per_file."""
    locked_dir = Path(locked_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = locked_dir / "manifest"
    if not manifest_path.exists():
        raise ValueError("Decryption failed (wrong key, tampered data, or invalid file)")
    raw = manifest_path.read_bytes()
    if len(raw) < WRAPPED_BLOB_SIZE + NONCE_SIZE:
        raise ValueError("Decryption failed (wrong key, tampered data, or invalid file)")
    try:
        wrapped = raw[:WRAPPED_BLOB_SIZE]
        payload_enc = raw[WRAPPED_BLOB_SIZE:]
        priv_path, _ = ensure_keypair(key_dir)
        priv = load_private_key(priv_path)
        sym_key = unwrap_symmetric_key(wrapped, priv)
        kind, material, file_list = _decrypt_key_data(sym_key, payload_enc)
    except Exception:
        raise ValueError("Decryption failed (wrong key, tampered data, or invalid file)")

    if kind == "keys":
        keys = [bytes.fromhex(h) for h in material]
    else:
        # Legacy V1 manifest: re-derive from stored passwords with legacy Argon2.
        keys = [derive_key_argon2(item["password"].encode("utf-8"), bytes.fromhex(item["salt"])) for item in material]

    for i, finfo in enumerate(file_list):
        enc_path = locked_dir / f"{i:06d}.enc"
        if not enc_path.exists():
            continue
        enc_data = enc_path.read_bytes()
        dec = multi_layer_decrypt(enc_data, keys)
        safe_name = finfo.get("name", "decrypted").replace("..", "").replace(os.sep, "_").strip() or "decrypted"
        safe_ext = finfo.get("ext", "")
        out_path = output_dir / f"{safe_name}{safe_ext}"
        out_path.write_bytes(dec)
        if progress_cb:
            progress_cb(out_path.name)


def lock_folder_zip(dir_path: Path, key_dir: Path, output_file: Path, progress_cb=None) -> None:
    """Zip folder then encrypt with a key wrapped by device key."""
    dir_path = Path(dir_path)
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, filenames in os.walk(dir_path):
            for name in filenames:
                full = Path(root) / name
                arc = full.relative_to(dir_path)
                zf.write(full, arc)
                if progress_cb:
                    progress_cb(str(arc))
    zip_bytes = buf.getvalue()
    sym_key = os.urandom(KEY_SIZE)
    _, pub_path = ensure_keypair(key_dir)
    pub = load_public_key(pub_path)
    wrapped = wrap_symmetric_key(sym_key, pub)
    aes = AESGCM(sym_key)
    nonce = os.urandom(NONCE_SIZE)
    ct = aes.encrypt(nonce, zip_bytes, None)
    output_file.write_bytes(wrapped + nonce + ct)


def unlock_folder_zip(locked_file: Path, key_dir: Path, output_dir: Path) -> None:
    """Unlock a .locked zip bundle."""
    locked_file = Path(locked_file)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    raw = locked_file.read_bytes()
    if len(raw) < WRAPPED_BLOB_SIZE + NONCE_SIZE:
        raise ValueError("Decryption failed (wrong key, tampered data, or invalid file)")
    try:
        wrapped = raw[:WRAPPED_BLOB_SIZE]
        rest = raw[WRAPPED_BLOB_SIZE:]
        nonce, ct = rest[:NONCE_SIZE], rest[NONCE_SIZE:]
        priv_path, _ = ensure_keypair(key_dir)
        priv = load_private_key(priv_path)
        sym_key = unwrap_symmetric_key(wrapped, priv)
        aes = AESGCM(sym_key)
        zip_bytes = aes.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Decryption failed (wrong key, tampered data, or invalid file)")
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        zf.extractall(output_dir)
