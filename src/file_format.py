"""Versioned container for multi-layer encrypted files.

Legacy files have no magic and start with a big-endian key count (2..50), so they
can never collide with MAGIC_V2. V2 files carry a self-describing header that records
the KDF parameters per key, so Argon2 strength can be raised without breaking old files.
The whole header is bound as AEAD associated data by the caller, making it tamper-evident.
"""
import struct

MAGIC_V2 = b"SLV2"
FORMAT_VERSION = 2

MAX_KEYS = 50
MAX_SALT = 1024
MAX_NAME = 4096
# Caps on KDF params read from an untrusted file, so a crafted header cannot trigger an
# out-of-memory / hang (e.g. a 4 GiB Argon2 cost) before any key check happens.
MIN_SALT = 8
MAX_TIME_COST = 64
MAX_MEMORY_COST = 1048576  # 1 GiB in KiB
MAX_PARALLELISM = 64

# Per-key entry: key_type(1) | time_cost(4) | memory_cost(4) | parallelism(4) | salt_len(2) | salt
_KEY_FIXED = 1 + 4 + 4 + 4 + 2


def is_v2(payload: bytes) -> bool:
    return payload[:4] == MAGIC_V2


def pack_header_v2(key_params: list[dict], filename: bytes, extension: bytes) -> bytes:
    if not (1 <= len(key_params) <= MAX_KEYS):
        raise ValueError("Invalid key count")
    parts = [MAGIC_V2, struct.pack(">B", FORMAT_VERSION), struct.pack(">H", len(key_params))]
    for kp in key_params:
        salt = kp["salt"]
        parts.append(struct.pack(">B", kp["key_type"]))
        parts.append(struct.pack(">III", kp["time_cost"], kp["memory_cost"], kp["parallelism"]))
        parts.append(struct.pack(">H", len(salt)))
        parts.append(salt)
    parts.append(struct.pack(">H", len(filename)))
    parts.append(struct.pack(">H", len(extension)))
    parts.append(filename)
    parts.append(extension)
    return b"".join(parts)


def unpack_header_v2(payload: bytes) -> tuple[dict, int]:
    """Return (header_dict, header_size). Raises ValueError on any malformed input."""
    if len(payload) < 7 or payload[:4] != MAGIC_V2:
        raise ValueError("Not a V2 file")
    version = payload[4]
    num_keys = struct.unpack(">H", payload[5:7])[0]
    if not (1 <= num_keys <= MAX_KEYS):
        raise ValueError("Invalid key count")
    off = 7
    keys = []
    for _ in range(num_keys):
        if off + _KEY_FIXED > len(payload):
            raise ValueError("Truncated header")
        key_type = payload[off]
        off += 1
        time_cost, memory_cost, parallelism = struct.unpack(">III", payload[off:off + 12])
        off += 12
        if not (1 <= time_cost <= MAX_TIME_COST):
            raise ValueError("Invalid time cost")
        if not (8 <= memory_cost <= MAX_MEMORY_COST):
            raise ValueError("Invalid memory cost")
        if not (1 <= parallelism <= MAX_PARALLELISM):
            raise ValueError("Invalid parallelism")
        salt_len = struct.unpack(">H", payload[off:off + 2])[0]
        off += 2
        if not (MIN_SALT <= salt_len <= MAX_SALT) or off + salt_len > len(payload):
            raise ValueError("Invalid salt length")
        salt = payload[off:off + salt_len]
        off += salt_len
        keys.append({
            "key_type": key_type,
            "time_cost": time_cost,
            "memory_cost": memory_cost,
            "parallelism": parallelism,
            "salt": salt,
        })
    if off + 4 > len(payload):
        raise ValueError("Truncated header")
    fn_len = struct.unpack(">H", payload[off:off + 2])[0]
    off += 2
    ext_len = struct.unpack(">H", payload[off:off + 2])[0]
    off += 2
    if fn_len > MAX_NAME or ext_len > MAX_NAME or off + fn_len + ext_len > len(payload):
        raise ValueError("Invalid filename fields")
    filename = payload[off:off + fn_len]
    off += fn_len
    extension = payload[off:off + ext_len]
    off += ext_len
    return {"version": version, "keys": keys, "filename": filename, "extension": extension}, off
