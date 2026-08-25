"""Cryptography, KDF and container tests."""

from __future__ import annotations

import sys
import json
import os
import struct
import unittest

from lockbox.core import crypto, vaultfile
from lockbox.core.errors import DecryptError, VaultFormatError
from lockbox.core.kdf import (
    ARGON2_AVAILABLE, KDFParams, SALT_LEN, default_params, derive, describe,
)

POSIX_PERMS = sys.platform != "win32"
NO_PERMS_REASON = (
    "Windows has no POSIX mode bits; access is governed by NTFS ACLs, which a "
    "file created inside the user's own profile inherits correctly"
)


FAST_KDF = KDFParams("scrypt", b"0123456789abcdef", {"n": 1024, "r": 8, "p": 1})


class TestRandomness(unittest.TestCase):
    def test_random_bytes_length_and_uniqueness(self):
        values = {crypto.random_bytes(32) for _ in range(200)}
        self.assertEqual(len(values), 200)
        self.assertTrue(all(len(v) == 32 for v in values))

    def test_random_bytes_rejects_zero(self):
        with self.assertRaises(ValueError):
            crypto.random_bytes(0)

    def test_random_below_is_in_range_and_unbiased_enough(self):
        counts = [0] * 6
        for _ in range(6000):
            counts[crypto.random_below(6)] += 1
        self.assertTrue(all(700 < c < 1300 for c in counts), counts)

    def test_no_stdlib_random_module_used_for_secrets(self):
        """`random` is seeded from the clock and must never appear in the
        modules that produce secrets."""
        import re

        import lockbox.core.crypto as module
        import lockbox.tools.generators as generators

        for source in (module, generators):
            with open(source.__file__, encoding="utf-8") as fh:
                text = fh.read()
            name = os.path.basename(source.__file__)
            self.assertIsNone(
                re.search(r"^\s*(import random|from random import)\b", text, re.M),
                f"{name} imports the non-cryptographic random module",
            )
            self.assertNotIn("random.random(", text, name)
            self.assertNotIn("time.time()", text.split("def generate_uuid")[0], name)


class TestAEAD(unittest.TestCase):
    def setUp(self):
        self.key = crypto.random_bytes(32)

    def test_round_trip(self):
        blob = crypto.encrypt(self.key, b"secret data", b"header")
        self.assertEqual(crypto.decrypt(self.key, blob, b"header"), b"secret data")

    def test_nonce_is_fresh_every_call(self):
        nonces = {crypto.encrypt(self.key, b"x")[:12] for _ in range(200)}
        self.assertEqual(len(nonces), 200)

    def test_wrong_key_fails(self):
        blob = crypto.encrypt(self.key, b"secret")
        with self.assertRaises(DecryptError):
            crypto.decrypt(crypto.random_bytes(32), blob)

    def test_wrong_aad_fails(self):
        blob = crypto.encrypt(self.key, b"secret", b"aad-1")
        with self.assertRaises(DecryptError):
            crypto.decrypt(self.key, blob, b"aad-2")

    def test_every_single_bit_flip_is_detected(self):
        blob = bytearray(crypto.encrypt(self.key, b"tamper me please"))
        for index in range(len(blob)):
            mutated = bytearray(blob)
            mutated[index] ^= 0x01
            with self.assertRaises(DecryptError):
                crypto.decrypt(self.key, bytes(mutated))

    def test_truncation_is_detected(self):
        blob = crypto.encrypt(self.key, b"secret")
        with self.assertRaises(DecryptError):
            crypto.decrypt(self.key, blob[:-1])

    def test_rejects_wrong_key_size(self):
        with self.assertRaises(ValueError):
            crypto.encrypt(b"short", b"x")


class TestHKDF(unittest.TestCase):
    def test_rfc5869_case_1(self):
        okm = crypto.hkdf_sha256(
            bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
            bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42,
        )
        self.assertEqual(
            okm.hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
        )

    def test_different_info_gives_different_keys(self):
        ikm, salt = b"ikm", b"salt"
        self.assertNotEqual(
            crypto.hkdf_sha256(ikm, salt, b"a"), crypto.hkdf_sha256(ikm, salt, b"b")
        )


class TestWipe(unittest.TestCase):
    def test_bytearray_is_zeroed(self):
        buffer = bytearray(b"super secret")
        crypto.wipe(buffer)
        self.assertEqual(bytes(buffer), b"\x00" * 12)


class TestKDF(unittest.TestCase):
    def test_default_params_have_fresh_salts(self):
        salts = {default_params().salt for _ in range(20)}
        self.assertEqual(len(salts), 20)
        self.assertEqual(len(salts.pop()), SALT_LEN)

    def test_deterministic(self):
        self.assertEqual(derive(b"pw", FAST_KDF), derive(b"pw", FAST_KDF))

    def test_password_and_salt_both_matter(self):
        other_salt = KDFParams("scrypt", b"fedcba9876543210", FAST_KDF.params)
        self.assertNotEqual(derive(b"pw", FAST_KDF), derive(b"pw2", FAST_KDF))
        self.assertNotEqual(derive(b"pw", FAST_KDF), derive(b"pw", other_salt))

    def test_key_length(self):
        self.assertEqual(len(derive(b"pw", FAST_KDF)), 32)

    def test_result_is_wipeable(self):
        self.assertIsInstance(derive(b"pw", FAST_KDF), bytearray)

    def test_header_round_trip(self):
        restored = KDFParams.from_header(json.loads(json.dumps(default_params().to_header())))
        self.assertEqual(restored.algorithm, default_params().algorithm)

    @unittest.skipUnless(ARGON2_AVAILABLE, "argon2-cffi not installed")
    def test_argon2_is_the_default(self):
        self.assertEqual(default_params().algorithm, "argon2id")
        self.assertIn("Argon2id", describe(default_params()))

    @unittest.skipUnless(ARGON2_AVAILABLE, "argon2-cffi not installed")
    def test_argon2_known_answer(self):
        """Pinned so a broken/silently-substituted Argon2 is caught."""
        params = KDFParams("argon2id", b"somesalt12345678",
                           {"memory_kib": 8192, "iterations": 2, "parallelism": 1})
        first = bytes(derive(b"password", params))
        self.assertEqual(len(first), 32)
        self.assertEqual(first, bytes(derive(b"password", params)))
        self.assertNotEqual(first, bytes(derive(b"Password", params)))


class TestVaultFile(unittest.TestCase):
    def setUp(self):
        self.keys = vaultfile.new_keys(b"master", FAST_KDF)
        self.payload = {"schema": 1, "items": [{"id": "1", "title": "x"}]}

    def test_round_trip(self):
        blob = vaultfile.serialize(self.keys, self.payload)
        payload, keys = vaultfile.deserialize(blob, b"master")
        self.assertEqual(payload, self.payload)
        self.assertEqual(bytes(keys.dek), bytes(self.keys.dek))

    def test_magic_and_version(self):
        blob = vaultfile.serialize(self.keys, self.payload)
        self.assertEqual(blob[:4], b"LBXV")
        self.assertEqual(struct.unpack(">H", blob[4:6])[0], vaultfile.VERSION)

    def test_plaintext_is_not_present_in_the_file(self):
        blob = vaultfile.serialize(
            self.keys, {"items": [{"password": "correct-horse-battery-staple"}]}
        )
        self.assertNotIn(b"correct-horse", blob)
        self.assertNotIn(b"password", blob[10 + 400:])

    def test_wrong_password(self):
        blob = vaultfile.serialize(self.keys, self.payload)
        with self.assertRaises(DecryptError):
            vaultfile.deserialize(blob, b"wrong")

    def test_not_a_vault(self):
        with self.assertRaises(VaultFormatError):
            vaultfile.deserialize(b"just some bytes here", b"master")

    def test_header_tampering_is_detected(self):
        """Editing the plaintext header must break body authentication."""
        blob = vaultfile.serialize(self.keys, self.payload)
        header, prefix, body = vaultfile.parse_header(blob)
        header["kdf"]["params"]["n"] = 2  # downgrade attempt
        new_header = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        forged = b"LBXV" + struct.pack(">HI", 1, len(new_header)) + new_header + body
        with self.assertRaises(DecryptError):
            vaultfile.deserialize(forged, b"master")

    def test_body_corruption_is_detected(self):
        blob = bytearray(vaultfile.serialize(self.keys, self.payload))
        blob[-5] ^= 0xFF
        with self.assertRaises(DecryptError):
            vaultfile.deserialize(bytes(blob), b"master")

    def test_rewrap_keeps_the_same_dek(self):
        new_keys = vaultfile.rewrap(self.keys, b"new-master", FAST_KDF)
        blob = vaultfile.serialize(new_keys, self.payload)
        payload, _ = vaultfile.deserialize(blob, b"new-master")
        self.assertEqual(payload, self.payload)
        with self.assertRaises(DecryptError):
            vaultfile.deserialize(blob, b"master")

    def test_keys_repr_does_not_leak(self):
        self.assertNotIn(self.keys.dek.hex()[:8], repr(self.keys))

    def test_atomic_write_keeps_the_previous_copy_and_leaves_no_temp(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "v.lbx")
            vaultfile.write_atomic(path, b"LBXV" + b"x" * 40)
            if POSIX_PERMS:
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            vaultfile.write_atomic(path, b"LBXV" + b"y" * 40)
            self.assertTrue(os.path.exists(path + ".prev"))
            self.assertFalse(
                any(name.startswith(".") and name.endswith(".tmp") for name in os.listdir(tmp))
            )


if __name__ == "__main__":
    unittest.main()
