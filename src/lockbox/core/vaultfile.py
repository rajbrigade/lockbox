"""The on-disk vault container.

Layout (all integers big-endian):

    magic        4 bytes   b"LBXV"
    version      2 bytes   uint16, currently 1
    header_len   4 bytes   uint32
    header       header_len bytes, canonical UTF-8 JSON, PLAINTEXT
    body         nonce(12) || AES-256-GCM ciphertext || tag(16)

The header is plaintext (it must be readable before the key exists) but it is
fed to the body's AES-GCM as additional authenticated data, so any edit to the
KDF parameters, the salt, or the wrapped key makes the body fail to
authenticate. Downgrade attacks on the header are therefore detectable.

Key hierarchy:

    master password + salt --Argon2id--> KEK --AES-GCM unwrap--> DEK --> body

See docs/VAULT_FORMAT.md and docs/CRYPTO.md.
"""

from __future__ import annotations

import json
import os
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple

from . import crypto
from .errors import DecryptError, VaultFormatError
from .kdf import KDFParams, derive

MAGIC = b"LBXV"
VERSION = 1
_HEADER_MAX = 64 * 1024
_BODY_MAX = 256 * 1024 * 1024  # sanity bound; refuse absurd files
_DEK_INFO = b"lockbox/dek-wrap/v1"
_FILE_MODE = 0o600


def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class VaultKeys:
    """In-memory key material for an unlocked vault."""

    kdf: KDFParams
    dek: bytearray = field(repr=False)
    wrapped_dek: bytes = field(repr=False)

    def wipe(self) -> None:
        crypto.wipe(self.dek)

    def __repr__(self) -> str:  # never leak key bytes into logs/tracebacks
        return f"<VaultKeys kdf={self.kdf.algorithm} dek=<redacted>>"


def _kdf_aad(kdf: KDFParams) -> bytes:
    return _DEK_INFO + _canonical(kdf.to_header())


def new_keys(password: bytes, kdf: KDFParams) -> VaultKeys:
    """Create a fresh random DEK and wrap it under a KEK from `password`."""
    kek = derive(password, kdf)
    try:
        dek = bytearray(crypto.random_bytes(crypto.KEY_LEN))
        wrapped = crypto.encrypt(bytes(kek), bytes(dek), _kdf_aad(kdf))
    finally:
        crypto.wipe(kek)
    return VaultKeys(kdf=kdf, dek=dek, wrapped_dek=wrapped)


def rewrap(keys: VaultKeys, new_password: bytes, new_kdf: KDFParams) -> VaultKeys:
    """Re-wrap the same DEK under a new master password (no re-encryption)."""
    kek = derive(new_password, new_kdf)
    try:
        wrapped = crypto.encrypt(bytes(kek), bytes(keys.dek), _kdf_aad(new_kdf))
    finally:
        crypto.wipe(kek)
    return VaultKeys(kdf=new_kdf, dek=keys.dek, wrapped_dek=wrapped)


def _build_header(keys: VaultKeys) -> Dict[str, Any]:
    return {
        "cipher": "AES-256-GCM",
        "compression": "zlib",
        "kdf": keys.kdf.to_header(),
        "wrapped_dek": keys.wrapped_dek.hex(),
    }


def serialize(keys: VaultKeys, payload: Dict[str, Any]) -> bytes:
    header = _canonical(_build_header(keys))
    if len(header) > _HEADER_MAX:
        raise VaultFormatError("header too large")
    prefix = MAGIC + struct.pack(">HI", VERSION, len(header)) + header
    plaintext = zlib.compress(_canonical(payload), 6)
    body = crypto.encrypt(bytes(keys.dek), plaintext, prefix)
    return prefix + body


def parse_header(blob: bytes) -> Tuple[Dict[str, Any], bytes, bytes]:
    """Return (header_dict, aad_prefix, body_bytes). No key needed."""
    if len(blob) < 10 or blob[:4] != MAGIC:
        raise VaultFormatError("not a Lockbox vault file")
    (version, hlen) = struct.unpack(">HI", blob[4:10])
    if version != VERSION:
        raise VaultFormatError(f"unsupported vault version {version}")
    if hlen > _HEADER_MAX or 10 + hlen > len(blob):
        raise VaultFormatError("corrupt vault header")
    raw_header = blob[10 : 10 + hlen]
    try:
        header = json.loads(raw_header.decode("utf-8"))
    except Exception as exc:
        raise VaultFormatError("corrupt vault header") from exc
    if not isinstance(header, dict) or "kdf" not in header or "wrapped_dek" not in header:
        raise VaultFormatError("corrupt vault header")
    return header, blob[: 10 + hlen], blob[10 + hlen :]


def deserialize(blob: bytes, password: bytes) -> Tuple[Dict[str, Any], VaultKeys]:
    header, prefix, body = parse_header(blob)
    kdf = KDFParams.from_header(header["kdf"])
    wrapped = bytes.fromhex(header["wrapped_dek"])

    kek = derive(password, kdf)
    try:
        dek = bytearray(crypto.decrypt(bytes(kek), wrapped, _kdf_aad(kdf)))
    finally:
        crypto.wipe(kek)

    if len(dek) != crypto.KEY_LEN:
        crypto.wipe(dek)
        raise VaultFormatError("bad key length in vault")

    try:
        plaintext = crypto.decrypt(bytes(dek), body, prefix)
    except DecryptError:
        crypto.wipe(dek)
        raise
    try:
        payload = json.loads(zlib.decompress(plaintext).decode("utf-8"))
    except Exception as exc:
        crypto.wipe(dek)
        raise VaultFormatError("vault body is corrupt") from exc
    if not isinstance(payload, dict):
        crypto.wipe(dek)
        raise VaultFormatError("vault body is corrupt")
    return payload, VaultKeys(kdf=kdf, dek=dek, wrapped_dek=wrapped)


def write_atomic(path: str, blob: bytes, keep_previous: bool = True) -> None:
    """Write `blob` to `path` without ever leaving a truncated vault behind.

    Sequence: write a 0600 temp file in the same directory, fsync it, keep the
    old file as `<path>.prev`, then os.replace() and fsync the directory.
    """
    if len(blob) > _BODY_MAX:
        raise VaultFormatError("refusing to write an implausibly large vault")
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, f".{os.path.basename(path)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        _quiet_unlink(tmp)
        raise
    if keep_previous and os.path.exists(path):
        try:
            prev = path + ".prev"
            os.replace(path, prev)
            os.chmod(prev, _FILE_MODE)
        except OSError:
            pass
    os.replace(tmp, path)
    os.chmod(path, _FILE_MODE)
    try:
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:  # not fatal; some filesystems disallow directory fsync
        pass


def _quiet_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()
