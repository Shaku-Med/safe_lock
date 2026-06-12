"""Tests for the V2 authenticated format, backward compatibility, and KDF params.

Run from the repo root: python -m unittest discover -s tests
"""
import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.encryption import _encrypt_layers, multi_layer_decrypt
from src.file_format import is_v2, pack_header_v2, unpack_header_v2, MAGIC_V2
from src.key_derivation import (
    derive_key_argon2, derive_key_argon2_with_params, generate_salt,
    save_keys_file_json, load_keys_file_json,
    ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM, KEY_FILE_NONCE_SIZE,
)
from src.utils import pack_metadata, get_metadata_size, KEY_TYPE_PASSWORD_ARGON2
from steal_locker.lock import _encrypt_key_data, _decrypt_key_data


def _keys(n):
    return [os.urandom(32) for _ in range(n)]


def _header(key_types, salts, fn=b"secret", ext=b".txt"):
    params = [
        {"key_type": kt, "time_cost": 4, "memory_cost": 131072, "parallelism": 4, "salt": s}
        for kt, s in zip(key_types, salts)
    ]
    return pack_header_v2(params, fn, ext)


class TestMultiLayer(unittest.TestCase):
    def test_round_trip_no_aad(self):
        for n in (2, 3, 5):
            keys = _keys(n)
            pt = os.urandom(5000)
            ct = _encrypt_layers(pt, keys)
            self.assertEqual(multi_layer_decrypt(ct, keys), pt)

    def test_round_trip_with_aad(self):
        keys = _keys(3)
        aad = b"bound-header-bytes"
        pt = b"hello world" * 100
        ct = _encrypt_layers(pt, keys, aad=aad)
        self.assertEqual(multi_layer_decrypt(ct, keys, aad=aad), pt)

    def test_wrong_aad_fails(self):
        keys = _keys(3)
        ct = _encrypt_layers(b"data", keys, aad=b"real-header")
        with self.assertRaises(Exception):
            multi_layer_decrypt(ct, keys, aad=b"forged-header")

    def test_wrong_key_fails(self):
        ct = _encrypt_layers(b"data", _keys(2))
        with self.assertRaises(Exception):
            multi_layer_decrypt(ct, _keys(2))


class TestV2Header(unittest.TestCase):
    def test_pack_unpack_round_trip(self):
        salts = [os.urandom(32), os.urandom(32)]
        header = _header([1, 1], salts, fn=b"my file", ext=b".pdf")
        parsed, size = unpack_header_v2(header)
        self.assertEqual(size, len(header))
        self.assertEqual(parsed["filename"], b"my file")
        self.assertEqual(parsed["extension"], b".pdf")
        self.assertEqual([k["salt"] for k in parsed["keys"]], salts)
        self.assertEqual(parsed["keys"][0]["memory_cost"], 131072)

    def test_is_v2_detection(self):
        header = _header([1], [os.urandom(32)])
        self.assertTrue(is_v2(header))
        legacy = pack_metadata([KEY_TYPE_PASSWORD_ARGON2] * 2, [os.urandom(32)] * 2, b"f", b".x")
        self.assertFalse(is_v2(legacy))

    def test_magic_never_collides_with_legacy(self):
        # Legacy starts with big-endian key count (2..50); can never equal MAGIC_V2.
        for n in range(2, 51):
            legacy = pack_metadata([KEY_TYPE_PASSWORD_ARGON2] * n, [os.urandom(32)] * n, b"f", b".x")
            self.assertNotEqual(legacy[:4], MAGIC_V2)

    def test_malformed_header_rejected(self):
        with self.assertRaises(ValueError):
            unpack_header_v2(b"SLV2\x02\x00\x05")  # claims 5 keys, truncated
        with self.assertRaises(ValueError):
            unpack_header_v2(b"XXXX\x02\x00\x01")  # bad magic

    def test_absurd_kdf_params_rejected(self):
        # A crafted file demanding a 4 GiB Argon2 cost must be refused before derivation.
        evil = [{"key_type": 1, "time_cost": 4, "memory_cost": 4 * 1048576, "parallelism": 4, "salt": os.urandom(32)}]
        header = pack_header_v2(evil, b"f", b".x")
        with self.assertRaises(ValueError):
            unpack_header_v2(header)

    def test_tampered_header_byte_breaks_decrypt(self):
        salts = [os.urandom(32), os.urandom(32)]
        keys = _keys(2)
        header = _header([1, 1], salts)
        ct = _encrypt_layers(b"top secret", keys, aad=header)
        tampered = bytearray(header)
        tampered[-1] ^= 0x01  # flip a byte in the extension
        with self.assertRaises(Exception):
            multi_layer_decrypt(ct, keys, aad=bytes(tampered))


class TestLegacyCompat(unittest.TestCase):
    def test_legacy_metadata_still_parses(self):
        salts = [os.urandom(32), os.urandom(32)]
        meta = pack_metadata([KEY_TYPE_PASSWORD_ARGON2] * 2, salts, b"name", b".bin")
        self.assertEqual(get_metadata_size(meta), len(meta))

    def test_legacy_kdf_unchanged(self):
        # derive_key_argon2 must equal the explicit legacy params, or old files break.
        pw, salt = b"password", os.urandom(32)
        a = derive_key_argon2(pw, salt)
        b = derive_key_argon2_with_params(pw, salt, ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM)
        self.assertEqual(a, b)


class TestKeyFile(unittest.TestCase):
    def test_v2_keyfile_stores_keys_not_passwords(self):
        entries = [{"index": 0, "key": os.urandom(32).hex(), "salt": os.urandom(32).hex()},
                   {"index": 1, "key": os.urandom(32).hex(), "salt": os.urandom(32).hex()}]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "k.json")
            save_keys_file_json(entries, path, "filepw")
            raw = json.load(open(path))
            self.assertEqual(raw["v"], 2)  # versioned envelope
            self.assertNotIn("password", json.dumps(raw))  # no plaintext password field name leaks structure
            loaded = load_keys_file_json(path, "filepw")
            self.assertEqual(loaded, entries)
            self.assertTrue(all("key" in e and "password" not in e for e in loaded))

    def test_wrong_keyfile_password_fails(self):
        entries = [{"index": 0, "key": os.urandom(32).hex(), "salt": os.urandom(32).hex()}]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "k.json")
            save_keys_file_json(entries, path, "right")
            with self.assertRaises(Exception):
                load_keys_file_json(path, "wrong")

    def test_legacy_keyfile_still_loads(self):
        # Build a pre-V2 envelope (no version, legacy Argon2, inner entries carry passwords).
        inner = [{"index": 0, "password": "alpha", "salt": os.urandom(32).hex()}]
        salt = generate_salt()
        key = derive_key_argon2(b"filepw", salt)
        nonce = os.urandom(KEY_FILE_NONCE_SIZE)
        ct = AESGCM(key).encrypt(nonce, json.dumps(inner).encode(), None)
        envelope = {
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "data": base64.b64encode(ct).decode(),
        }
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "legacy.json")
            json.dump(envelope, open(path, "w"))
            loaded = load_keys_file_json(path, "filepw")
            self.assertEqual(loaded, inner)
            self.assertIn("password", loaded[0])

    def test_keyfile_absurd_kdf_rejected(self):
        envelope = {
            "v": 2, "kdf": {"t": 4, "m": 4 * 1048576, "p": 4},
            "salt": base64.b64encode(os.urandom(32)).decode(),
            "nonce": base64.b64encode(os.urandom(12)).decode(),
            "data": base64.b64encode(b"x" * 32).decode(),
        }
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "evil.json")
            json.dump(envelope, open(path, "w"))
            with self.assertRaises(Exception):
                load_keys_file_json(path, "filepw")


class TestStealLockerManifest(unittest.TestCase):
    def test_v2_manifest_round_trip_keys(self):
        sym = os.urandom(32)
        keys_hex = [os.urandom(32).hex(), os.urandom(32).hex()]
        files = [{"name": "a", "ext": ".txt"}]
        blob = _encrypt_key_data(sym, keys_hex, files)
        kind, material, files2 = _decrypt_key_data(sym, blob)
        self.assertEqual(kind, "keys")
        self.assertEqual(material, keys_hex)
        self.assertEqual(files2, files)

    def test_v1_legacy_manifest_still_parses(self):
        sym = os.urandom(32)
        kdl = [{"index": 0, "password": "p", "salt": os.urandom(32).hex()}]
        files = [{"name": "a", "ext": ".txt"}]
        payload = json.dumps({"v": 1, "key_data_list": kdl, "files": files}).encode()
        nonce = os.urandom(12)
        blob = nonce + AESGCM(sym).encrypt(nonce, payload, None)
        kind, material, files2 = _decrypt_key_data(sym, blob)
        self.assertEqual(kind, "legacy")
        self.assertEqual(material, kdl)


if __name__ == "__main__":
    unittest.main()
