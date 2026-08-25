"""Password-based key derivation.

Primary: Argon2id via argon2-cffi (the reference implementation).
Fallback: scrypt via the standard library, used only when argon2-cffi is not
installed. Both are memory-hard. The vault header records exactly which was
used and with which parameters, so a vault created on one machine opens on the
other, and parameters cannot be silently downgraded (the header is
authenticated as AAD).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from typing import Any, Dict

from .errors import KDFUnavailableError

try:  # pragma: no cover - availability depends on the install
    from argon2.low_level import Type as _Argon2Type, hash_secret_raw as _argon2_raw

    ARGON2_AVAILABLE = True
except Exception:  # pragma: no cover
    ARGON2_AVAILABLE = False

SALT_LEN = 16
KEY_LEN = 32

# Defaults: ~64 MiB, ~0.15-0.4 s on a 2020-era laptop core. Interactive-grade,
# per the Argon2 RFC 9106 second recommended option, raised in memory.
ARGON2_DEFAULTS = {"memory_kib": 65536, "iterations": 3, "parallelism": 1}
SCRYPT_DEFAULTS = {"n": 32768, "r": 8, "p": 1}

# scrypt needs maxmem >= 128*N*r*p; give headroom.
_SCRYPT_MAXMEM = 128 * 32768 * 8 * 1 * 2


@dataclass(frozen=True)
class KDFParams:
    algorithm: str  # "argon2id" | "scrypt"
    salt: bytes
    params: Dict[str, int]

    def to_header(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "salt": self.salt.hex(),
            "params": dict(self.params),
        }

    @staticmethod
    def from_header(d: Dict[str, Any]) -> "KDFParams":
        return KDFParams(
            algorithm=str(d["algorithm"]),
            salt=bytes.fromhex(d["salt"]),
            params={str(k): int(v) for k, v in dict(d["params"]).items()},
        )


def default_params() -> KDFParams:
    from .crypto import random_bytes

    if ARGON2_AVAILABLE:
        return KDFParams("argon2id", random_bytes(SALT_LEN), dict(ARGON2_DEFAULTS))
    return KDFParams("scrypt", random_bytes(SALT_LEN), dict(SCRYPT_DEFAULTS))


def derive(password: bytes, kp: KDFParams) -> bytearray:
    """Derive a 32-byte key. Returns a bytearray so it can be wiped."""
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")
    if len(kp.salt) < 8:
        raise ValueError("salt too short")

    if kp.algorithm == "argon2id":
        if not ARGON2_AVAILABLE:
            raise KDFUnavailableError(
                "This vault uses Argon2id; install argon2-cffi to open it."
            )
        raw = _argon2_raw(
            secret=bytes(password),
            salt=kp.salt,
            time_cost=int(kp.params["iterations"]),
            memory_cost=int(kp.params["memory_kib"]),
            parallelism=int(kp.params["parallelism"]),
            hash_len=KEY_LEN,
            type=_Argon2Type.ID,
        )
    elif kp.algorithm == "scrypt":
        raw = hashlib.scrypt(
            bytes(password),
            salt=kp.salt,
            n=int(kp.params["n"]),
            r=int(kp.params["r"]),
            p=int(kp.params["p"]),
            dklen=KEY_LEN,
            maxmem=_SCRYPT_MAXMEM,
        )
    else:
        raise KDFUnavailableError(f"unknown KDF: {kp.algorithm!r}")
    return bytearray(raw)


def describe(kp: KDFParams) -> str:
    if kp.algorithm == "argon2id":
        p = kp.params
        return (
            f"Argon2id  m={p['memory_kib'] // 1024} MiB  t={p['iterations']}  "
            f"p={p['parallelism']}"
        )
    p = kp.params
    return f"scrypt  N={p['n']}  r={p['r']}  p={p['p']}"


def benchmark(kp: KDFParams | None = None) -> float:
    """Seconds to derive one key with the given parameters (local only)."""
    import time

    kp = kp or default_params()
    start = time.perf_counter()
    derive(b"benchmark-password", kp)
    return time.perf_counter() - start
