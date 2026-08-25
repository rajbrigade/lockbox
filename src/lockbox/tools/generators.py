"""Offline generators for passwords, passphrases, keys and identifiers.

Every random choice comes from `core.crypto` (os.urandom / secrets), which is
the OS CSPRNG. `random`, `Math.random`-equivalents, timestamps, PIDs and hashes
of the current time are never used as a source of secret material.

Class requirements ("must contain a digit") are satisfied by *rejection
sampling*: draw a full uniform password, and if it lacks a required class, throw
it away and draw again. Patching a character into a fixed position would bias
the distribution and shave real entropy off the result.
"""

from __future__ import annotations

import math
import uuid as _uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from ..core.crypto import random_below, random_bytes, random_choice
from .analysis import DIGITS, LOWER, SYMBOLS, UPPER, entropy_bits
from .wordlist import WORDS, bits_per_word

DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = "Il1O0o|`'\"{}[]()/\\;:.,<>~"

_CONSONANTS = "bcdfghjklmnpqrstvwxz"
_VOWELS = "aeiou"


@dataclass
class GeneratedSecret:
    value: str
    entropy_bits: float
    alphabet_size: int
    note: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "value": self.value,
            "entropy_bits": round(self.entropy_bits, 2),
            "alphabet_size": self.alphabet_size,
            "note": self.note,
        }


def build_alphabet(
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    symbol_set: str = DEFAULT_SYMBOLS,
    exclude: str = "",
    exclude_ambiguous: bool = False,
    custom: str = "",
) -> str:
    if custom:
        pool = custom
    else:
        pool = ""
        if lowercase:
            pool += LOWER
        if uppercase:
            pool += UPPER
        if digits:
            pool += DIGITS
        if symbols:
            pool += symbol_set
    banned = set(exclude)
    if exclude_ambiguous:
        banned |= set(AMBIGUOUS)
    alphabet = "".join(sorted({c for c in pool if c not in banned}))
    if len(alphabet) < 2:
        raise ValueError("character set is empty after exclusions")
    return alphabet


def random_string(length: int, alphabet: str) -> str:
    if length <= 0:
        raise ValueError("length must be positive")
    if len(alphabet) < 2:
        raise ValueError("alphabet must have at least 2 characters")
    return "".join(alphabet[random_below(len(alphabet))] for _ in range(length))


def generate_password(
    length: int = 20,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    symbol_set: str = DEFAULT_SYMBOLS,
    exclude: str = "",
    exclude_ambiguous: bool = False,
    custom_alphabet: str = "",
    require_each_class: bool = True,
) -> GeneratedSecret:
    if not 4 <= length <= 512:
        raise ValueError("length must be between 4 and 512")
    alphabet = build_alphabet(
        lowercase, uppercase, digits, symbols, symbol_set, exclude,
        exclude_ambiguous, custom_alphabet,
    )
    required: List[str] = []
    if require_each_class and not custom_alphabet:
        for enabled, pool in (
            (lowercase, LOWER), (uppercase, UPPER),
            (digits, DIGITS), (symbols, symbol_set),
        ):
            subset = [c for c in pool if c in alphabet]
            if enabled and subset:
                required.append("".join(subset))
    if len(required) > length:
        raise ValueError("length too short to include every required class")

    for _ in range(2000):  # rejection sampling; overwhelmingly succeeds first try
        candidate = random_string(length, alphabet)
        if all(any(c in pool for c in candidate) for pool in required):
            break
    else:  # pragma: no cover - unreachable for sane parameters
        raise RuntimeError("could not satisfy character requirements")

    return GeneratedSecret(
        value=candidate,
        entropy_bits=entropy_bits(len(alphabet), length),
        alphabet_size=len(alphabet),
        note="uniform over the selected alphabet",
    )


def generate_passphrase(
    words: int = 6,
    separator: str = "-",
    capitalize: bool = False,
    add_number: bool = False,
    add_symbol: bool = False,
    wordlist: Optional[Sequence[str]] = None,
    max_word_length: int = 0,
) -> GeneratedSecret:
    if not 2 <= words <= 32:
        raise ValueError("words must be between 2 and 32")
    pool = list(wordlist or WORDS)
    if max_word_length:
        pool = [w for w in pool if len(w) <= max_word_length] or list(WORDS)
    chosen = [random_choice(pool) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    bits = words * bits_per_word(pool)
    if add_number:
        phrase += separator + str(random_below(1000)).zfill(3)
        bits += math.log2(1000)
    if add_symbol:
        symbol = random_choice(DEFAULT_SYMBOLS)
        phrase += symbol
        bits += math.log2(len(DEFAULT_SYMBOLS))
    return GeneratedSecret(
        value=phrase,
        entropy_bits=bits,
        alphabet_size=len(pool),
        note=f"{len(pool)}-word local list, {bits_per_word(pool):.2f} bits/word",
    )


def generate_pronounceable(
    length: int = 16, capitalize: bool = True, add_digits: int = 2
) -> GeneratedSecret:
    """Alternating consonant/vowel syllables. Easier to say, weaker per
    character -- the reported entropy accounts for the restricted alphabet."""
    if not 6 <= length <= 128:
        raise ValueError("length must be between 6 and 128")
    core_len = max(4, length - add_digits)
    out: List[str] = []
    bits = 0.0
    for i in range(core_len):
        pool = _CONSONANTS if i % 2 == 0 else _VOWELS
        out.append(random_choice(pool))
        bits += math.log2(len(pool))
    text = "".join(out)
    if capitalize:
        text = text.capitalize()
    for _ in range(add_digits):
        text += DIGITS[random_below(10)]
        bits += math.log2(10)
    return GeneratedSecret(
        value=text,
        alphabet_size=len(_CONSONANTS) + len(_VOWELS),
        entropy_bits=bits,
        note="pronounceable: lower entropy per character than a random password",
    )


def generate_username(
    style: str = "word", separator: str = ".", number_digits: int = 3
) -> GeneratedSecret:
    """Usernames are identifiers, not secrets; entropy is informational."""
    if style == "word":
        parts = [random_choice(WORDS), random_choice(WORDS)]
        bits = 2 * bits_per_word()
        value = separator.join(parts)
    elif style == "pronounceable":
        gen = generate_pronounceable(10, capitalize=False, add_digits=0)
        value, bits = gen.value, gen.entropy_bits
    elif style == "random":
        value = random_string(12, LOWER + DIGITS)
        bits = entropy_bits(36, 12)
    else:
        raise ValueError("style must be word, pronounceable or random")
    if number_digits:
        value += separator + "".join(DIGITS[random_below(10)] for _ in range(number_digits))
        bits += number_digits * math.log2(10)
    return GeneratedSecret(value=value, entropy_bits=bits, alphabet_size=len(WORDS),
                           note="usernames are identifiers, not secrets")


def generate_api_key(prefix: str = "", nbytes: int = 32, encoding: str = "base62") -> GeneratedSecret:
    if not 8 <= nbytes <= 256:
        raise ValueError("nbytes must be between 8 and 256")
    raw = random_bytes(nbytes)
    if encoding == "hex":
        body = raw.hex()
    elif encoding == "base64url":
        import base64

        body = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    elif encoding == "base62":
        alphabet = LOWER + UPPER + DIGITS
        n = int.from_bytes(raw, "big")
        chars: List[str] = []
        while n:
            n, rem = divmod(n, 62)
            chars.append(alphabet[rem])
        body = "".join(reversed(chars)) or alphabet[0]
    else:
        raise ValueError("encoding must be hex, base64url or base62")
    value = f"{prefix}{body}" if prefix else body
    return GeneratedSecret(value=value, entropy_bits=nbytes * 8, alphabet_size=256,
                           note=f"{nbytes} random bytes from the OS CSPRNG")


def generate_token(nbytes: int = 32) -> GeneratedSecret:
    return generate_api_key(nbytes=nbytes, encoding="base64url")


def generate_recovery_codes(
    count: int = 10, groups: int = 3, group_len: int = 4, alphabet: str = ""
) -> Dict[str, object]:
    alphabet = alphabet or "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1
    codes = [
        "-".join(random_string(group_len, alphabet) for _ in range(groups))
        for _ in range(count)
    ]
    per_code = entropy_bits(len(alphabet), groups * group_len)
    return {
        "codes": codes,
        "entropy_bits_each": round(per_code, 2),
        "note": "Store these offline. Lockbox does not register them anywhere.",
    }


def generate_uuid(version: int = 4) -> GeneratedSecret:
    if version == 4:
        value = str(_uuid.uuid4())
        bits = 122.0
        note = "UUIDv4, 122 random bits (os CSPRNG)"
    elif version == 7:
        # Time-ordered UUIDv7: 48-bit ms timestamp + 74 random bits.
        import time

        ms = int(time.time() * 1000) & ((1 << 48) - 1)
        rand = random_bytes(10)
        raw = bytearray(ms.to_bytes(6, "big") + rand)
        raw[6] = (raw[6] & 0x0F) | 0x70
        raw[8] = (raw[8] & 0x3F) | 0x80
        value = str(_uuid.UUID(bytes=bytes(raw)))
        bits = 74.0
        note = "UUIDv7 embeds a timestamp - never use as a secret"
    else:
        raise ValueError("only UUID versions 4 and 7 are supported")
    return GeneratedSecret(value=value, entropy_bits=bits, alphabet_size=16, note=note)


def secure_random_number(low: int = 1, high: int = 100, count: int = 1) -> List[int]:
    """Uniform integers in [low, high] inclusive, no modulo bias."""
    if high < low:
        raise ValueError("high must be >= low")
    if not 1 <= count <= 10000:
        raise ValueError("count must be between 1 and 10000")
    span = high - low + 1
    return [low + random_below(span) for _ in range(count)]


def generate_password_history(
    count: int = 5, length: int = 20, **kwargs
) -> List[Dict[str, object]]:
    """Generate a batch of candidate passwords (e.g. to pre-stage rotations).

    These are candidates only; nothing is written to the vault until you save an
    item with one.
    """
    if not 1 <= count <= 100:
        raise ValueError("count must be between 1 and 100")
    return [generate_password(length=length, **kwargs).to_dict() for _ in range(count)]
