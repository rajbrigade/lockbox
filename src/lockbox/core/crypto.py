"""Thin, auditable wrapper over audited primitives.

No algorithm is implemented here. AES-256-GCM comes from `cryptography`
(OpenSSL); HMAC/SHA-2 come from the Python standard library; randomness comes
from the OS CSPRNG via `os.urandom`/`secrets`.

Nothing in this module performs I/O of any kind.
"""

from __future__ import annotations

import hmac
import os
import secrets
from hashlib import sha256

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptError

KEY_LEN = 32  # AES-256
NONCE_LEN = 12  # GCM standard nonce
TAG_LEN = 16


def random_bytes(n: int) -> bytes:
    """Cryptographically secure random bytes from the OS CSPRNG."""
    if n <= 0:
        raise ValueError("n must be positive")
    return os.urandom(n)


def random_below(n: int) -> int:
    """Uniform integer in [0, n) with no modulo bias."""
    if n <= 0:
        raise ValueError("n must be positive")
    return secrets.randbelow(n)


def random_choice(seq):
    if not seq:
        raise ValueError("empty sequence")
    return seq[secrets.randbelow(len(seq))]


def ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM. Returns nonce || ciphertext || tag.

    A fresh 96-bit nonce is drawn from the OS CSPRNG for every call; keys are
    never reused with a caller-supplied nonce, so GCM nonce reuse cannot be
    triggered from outside this module.
    """
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Inverse of :func:`encrypt`. Raises DecryptError on any failure."""
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise DecryptError("ciphertext too short")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
    except InvalidTag as exc:  # wrong key, wrong AAD, or tampering
        raise DecryptError("authentication failed") from exc


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF over stdlib HMAC-SHA256."""
    if length > 255 * 32:
        raise ValueError("length too large")
    prk = hmac.new(salt, ikm, sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), sha256).digest()
        out += block
        counter += 1
    return out[:length]


def wipe(buf) -> None:
    """Best-effort zeroisation of a mutable buffer.

    CPython cannot guarantee erasure of immutable `bytes`/`str` objects, so
    secrets that matter are held in `bytearray` and wiped through here. This is
    documented as best-effort in docs/THREAT_MODEL.md rather than claimed as a
    guarantee.
    """
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, memoryview) and not buf.readonly:
        buf[:] = b"\x00" * len(buf)
