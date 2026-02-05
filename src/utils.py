import os
import struct

KEY_TYPE_PASSWORD_ARGON2 = 1
KEY_TYPE_PASSWORD_PBKDF2 = 2
KEY_TYPE_DEVICE = 3

def pack_metadata(key_types: list[int], salts: list[bytes], original_filename: bytes, file_extension: bytes) -> bytes:
    filename_len = len(original_filename)
    extension_len = len(file_extension)
    num_keys = len(key_types)
    
    metadata = struct.pack('>I', num_keys)
    metadata += struct.pack('>I', filename_len)
    metadata += struct.pack('>I', extension_len)
    
    for key_type in key_types:
        metadata += struct.pack('>I', key_type)
    
    for salt in salts:
        if len(salt) == 0:
            metadata += b'\x00' * 32
        else:
            metadata += salt
    
    metadata += original_filename
    metadata += file_extension
    
    return metadata

def get_metadata_size(metadata: bytes) -> int:
    if len(metadata) < 12:
        raise ValueError("Metadata too short")
    num_keys = struct.unpack('>I', metadata[:4])[0]
    filename_len = struct.unpack('>I', metadata[4:8])[0]
    extension_len = struct.unpack('>I', metadata[8:12])[0]
    
    base_size = 12
    key_types_size = num_keys * 4
    salts_size = num_keys * 32
    filename_size = filename_len
    extension_size = extension_len
    
    return base_size + key_types_size + salts_size + filename_size + extension_size

def unpack_metadata(metadata: bytes) -> tuple[list[int], list[bytes], bytes, bytes]:
    num_keys = struct.unpack('>I', metadata[:4])[0]
    filename_len = struct.unpack('>I', metadata[4:8])[0]
    extension_len = struct.unpack('>I', metadata[8:12])[0]
    
    offset = 12
    key_types = []
    for i in range(num_keys):
        key_type = struct.unpack('>I', metadata[offset:offset+4])[0]
        key_types.append(key_type)
        offset += 4
    
    salts = []
    for i in range(num_keys):
        salt = metadata[offset:offset+32]
        if salt == b'\x00' * 32:
            salts.append(b'')
        else:
            salts.append(salt)
        offset += 32
    
    filename_start = offset
    filename_end = filename_start + filename_len
    extension_start = filename_end
    extension_end = extension_start + extension_len
    
    original_filename = metadata[filename_start:filename_end]
    file_extension = metadata[extension_start:extension_end]
    
    return key_types, salts, original_filename, file_extension

def get_file_info(file_path: str) -> tuple[str, str]:
    base_name = os.path.basename(file_path)
    name, ext = os.path.splitext(base_name)
    return name, ext

def ensure_directory(path: str):
    os.makedirs(path, exist_ok=True)


# --- Steal Locker SL01 metadata (bounded lengths to prevent overflow/OOM) ---
SL01_MAGIC = b"SL01"
MAX_WLEN, MAX_FNLEN, MAX_EXTLEN = 256, 4096, 256


def pack_steal_locker_metadata(wrapped_blob_len: int, filename: bytes, extension: bytes) -> bytes:
    wlen = min(max(0, wrapped_blob_len), MAX_WLEN)
    fnlen = min(len(filename), MAX_FNLEN)
    extlen = min(len(extension), MAX_EXTLEN)
    fn = filename[:fnlen]
    ext = extension[:extlen]
    return SL01_MAGIC + struct.pack(">I", wlen) + struct.pack(">I", fnlen) + struct.pack(">I", extlen) + fn + ext


def get_steal_locker_metadata_size(metadata: bytes) -> int:
    if len(metadata) < 16:
        raise ValueError("SL01 metadata too short")
    if metadata[:4] != SL01_MAGIC:
        raise ValueError("Invalid SL01 magic")
    wlen = min(struct.unpack(">I", metadata[4:8])[0], MAX_WLEN)
    fnlen = min(struct.unpack(">I", metadata[8:12])[0], MAX_FNLEN)
    extlen = min(struct.unpack(">I", metadata[12:16])[0], MAX_EXTLEN)
    total = 16 + fnlen + extlen
    if total > len(metadata):
        raise ValueError("SL01 metadata length exceeds buffer")
    return total


def unpack_steal_locker_metadata(metadata: bytes) -> tuple[int, bytes, bytes]:
    if len(metadata) < 16:
        raise ValueError("SL01 metadata too short")
    if metadata[:4] != SL01_MAGIC:
        raise ValueError("Invalid SL01 magic")
    wlen = min(struct.unpack(">I", metadata[4:8])[0], MAX_WLEN)
    fnlen = min(struct.unpack(">I", metadata[8:12])[0], MAX_FNLEN)
    extlen = min(struct.unpack(">I", metadata[12:16])[0], MAX_EXTLEN)
    if 16 + fnlen + extlen > len(metadata):
        raise ValueError("SL01 metadata overflow")
    fn = metadata[16 : 16 + fnlen]
    ext = metadata[16 + fnlen : 16 + fnlen + extlen]
    return wlen, fn, ext


def _sanitize_steal_locker_output_filename(filename: bytes, extension: bytes) -> str:
    """Path traversal fix: basename only, no .. or path separators."""
    try:
        fn = filename.decode("utf-8", errors="replace")
    except Exception:
        fn = "decrypted"
    try:
        ext = extension.decode("utf-8", errors="replace")
    except Exception:
        ext = ""
    name = os.path.basename(fn)
    if ".." in name or os.sep in name or (os.altsep and os.altsep in name):
        name = "decrypted"
    if not name.strip():
        name = "decrypted"
    return name + ext

