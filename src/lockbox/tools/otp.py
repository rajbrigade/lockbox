"""RFC 4226 (HOTP) and RFC 6238 (TOTP), computed locally.

TOTP is a keyed hash of a counter derived from the clock. There is no server
involved by design, so this is offline by construction: Lockbox never contacts
an authentication service to produce a code. If codes are rejected, the cause
is clock drift on this machine -- compare `time_remaining()` against your
phone, or fix the system clock.

Only the standard hash families (SHA-1, SHA-256, SHA-512) are supported, all
from the standard library.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import parse_qs, quote, unquote, urlsplit

from ..core.crypto import ct_eq, random_bytes

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


@dataclass(frozen=True)
class OTPConfig:
    secret: str  # base32
    label: str = "Lockbox"
    issuer: str = ""
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30

    def validate(self) -> None:
        if self.algorithm.upper() not in ALGORITHMS:
            raise ValueError(f"unsupported algorithm: {self.algorithm}")
        if not 6 <= self.digits <= 10:
            raise ValueError("digits must be between 6 and 10")
        if not 5 <= self.period <= 300:
            raise ValueError("period must be between 5 and 300 seconds")
        decode_secret(self.secret)


def normalise_secret(secret: str) -> str:
    return "".join(ch for ch in (secret or "").upper() if ch in _B32_ALPHABET)


def decode_secret(secret: str) -> bytes:
    cleaned = normalise_secret(secret)
    if not cleaned:
        raise ValueError("TOTP secret is empty or not valid base32")
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        raw = base64.b32decode(padded, casefold=True)
    except binascii.Error as exc:
        raise ValueError("TOTP secret is not valid base32") from exc
    if not raw:
        raise ValueError("TOTP secret decodes to zero bytes")
    return raw


def generate_secret(nbytes: int = 20) -> str:
    """A new random base32 TOTP secret (default 160 bits, the RFC 4226 size)."""
    if not 10 <= nbytes <= 64:
        raise ValueError("nbytes must be between 10 and 64")
    return base64.b32encode(random_bytes(nbytes)).decode("ascii").rstrip("=")


def hotp(secret: str, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    if counter < 0:
        raise ValueError("counter must be non-negative")
    digest_fn = ALGORITHMS[algorithm.upper()]
    mac = hmac.new(decode_secret(secret), struct.pack(">Q", counter), digest_fn).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(
    secret: str,
    at: Optional[float] = None,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    now = time.time() if at is None else at
    return hotp(secret, int(now // period), digits=digits, algorithm=algorithm)


def time_remaining(period: int = 30, at: Optional[float] = None) -> float:
    now = time.time() if at is None else at
    return period - (now % period)


def verify(
    secret: str,
    code: str,
    at: Optional[float] = None,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
    window: int = 1,
) -> bool:
    """Constant-time check across +/- `window` steps (clock drift tolerance)."""
    now = time.time() if at is None else at
    counter = int(now // period)
    candidate = (code or "").strip().encode()
    ok = False
    for offset in range(-window, window + 1):
        step = counter + offset
        if step < 0:
            continue
        expected = hotp(secret, step, digits=digits, algorithm=algorithm).encode()
        ok |= ct_eq(expected, candidate)  # no early return: keep timing flat
    return ok


def current(config: OTPConfig, at: Optional[float] = None) -> Dict[str, object]:
    config.validate()
    return {
        "code": totp(
            config.secret, at=at, digits=config.digits,
            period=config.period, algorithm=config.algorithm,
        ),
        "seconds_remaining": round(time_remaining(config.period, at), 1),
        "period": config.period,
        "digits": config.digits,
        "algorithm": config.algorithm.upper(),
    }


def build_otpauth(config: OTPConfig) -> str:
    """Build an otpauth:// URI. It is a local string; nothing is contacted."""
    config.validate()
    label = quote(f"{config.issuer}:{config.label}" if config.issuer else config.label, safe="")
    params = [
        f"secret={normalise_secret(config.secret)}",
        f"algorithm={config.algorithm.upper()}",
        f"digits={config.digits}",
        f"period={config.period}",
    ]
    if config.issuer:
        params.append(f"issuer={quote(config.issuer, safe='')}")
    return f"otpauth://totp/{label}?" + "&".join(params)


def parse_otpauth(uri: str) -> OTPConfig:
    """Parse an otpauth:// URI (what a QR code contains) or a bare secret."""
    raw = (uri or "").strip()
    if not raw.lower().startswith("otpauth://"):
        # Validate here too. `normalise_secret` drops every character outside
        # the base32 alphabet, so unvalidated junk became an empty secret and
        # was stored as a TOTP configuration that can never produce a code.
        config = OTPConfig(secret=normalise_secret(raw))
        config.validate()
        return config
    parts = urlsplit(raw)
    if parts.netloc.lower() not in ("totp", ""):
        raise ValueError("only otpauth://totp URIs are supported")
    query = parse_qs(parts.query)
    label = unquote(parts.path.lstrip("/"))
    issuer = query.get("issuer", [""])[0]
    if ":" in label:
        prefix, _, rest = label.partition(":")
        issuer = issuer or prefix
        label = rest.strip()
    config = OTPConfig(
        secret=normalise_secret(query.get("secret", [""])[0]),
        label=label or "Lockbox",
        issuer=issuer,
        algorithm=(query.get("algorithm", ["SHA1"])[0] or "SHA1").upper(),
        digits=int(query.get("digits", ["6"])[0] or 6),
        period=int(query.get("period", ["30"])[0] or 30),
    )
    config.validate()
    return config
