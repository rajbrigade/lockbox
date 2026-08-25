"""Offline password analysis: entropy, patterns, strength.

Everything here is a pure function of the input string plus the bundled local
word lists. No password ever leaves this process -- there is no network code in
this module and no call path from it to one.

Two entropy numbers are reported because they answer different questions:

* `charset_bits` -- log2(alphabet ** length). This is the correct number for a
  password generated uniformly at random, and a systematic *over*estimate for
  anything a human chose.
* `estimated_bits` -- charset_bits reduced by detected structure (dictionary
  words, repeats, sequences, keyboard runs, dates). A rough guess at guessing
  cost against an attacker who knows the usual tricks. It is an estimate and is
  labelled as one.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List

from .commonlist import is_common
from .wordlist import WORD_SET

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = LOWER.upper()
DIGITS = "0123456789"
SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "

_KEYBOARD_ROWS = (
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "azerty",
    "qwertz",
)

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

STRENGTH_LABELS = (
    (28, "very weak"),
    (40, "weak"),
    (60, "fair"),
    (80, "strong"),
    (float("inf"), "very strong"),
)


@dataclass
class Analysis:
    length: int = 0
    charset_size: int = 0
    charset_bits: float = 0.0
    estimated_bits: float = 0.0
    strength: str = "very weak"
    score: int = 0  # 0-4
    classes: Dict[str, bool] = field(default_factory=dict)
    patterns: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    crack_times: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "length": self.length,
            "charset_size": self.charset_size,
            "charset_bits": round(self.charset_bits, 2),
            "estimated_bits": round(self.estimated_bits, 2),
            "strength": self.strength,
            "score": self.score,
            "classes": dict(self.classes),
            "patterns": list(self.patterns),
            "suggestions": list(self.suggestions),
            "crack_times": dict(self.crack_times),
        }


def charset_size(password: str) -> int:
    size = 0
    if any(c in LOWER for c in password):
        size += 26
    if any(c in UPPER for c in password):
        size += 26
    if any(c in DIGITS for c in password):
        size += 10
    if any(c in SYMBOLS for c in password):
        size += len(SYMBOLS)
    extra = {c for c in password if c not in LOWER + UPPER + DIGITS + SYMBOLS}
    size += len(extra)
    return size


def charset_entropy(password: str) -> float:
    """Entropy of a *uniformly random* password over the observed alphabet."""
    size = charset_size(password)
    if size <= 1 or not password:
        return 0.0
    return len(password) * math.log2(size)


def entropy_bits(alphabet_size: int, length: int) -> float:
    if alphabet_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(alphabet_size)


def _has_repeats(p: str) -> bool:
    return re.search(r"(.)\1{2,}", p) is not None


def _repeated_block(p: str) -> bool:
    return bool(re.fullmatch(r"(.{2,}?)\1+", p))


def _has_sequence(p: str, minimum: int = 4) -> bool:
    low = p.lower()
    run_up = run_down = 1
    for i in range(1, len(low)):
        delta = ord(low[i]) - ord(low[i - 1])
        run_up = run_up + 1 if delta == 1 else 1
        run_down = run_down + 1 if delta == -1 else 1
        if max(run_up, run_down) >= minimum:
            return True
    return False


def _keyboard_run(p: str, minimum: int = 4) -> bool:
    low = p.lower()
    for row in _KEYBOARD_ROWS:
        for i in range(len(row) - minimum + 1):
            chunk = row[i : i + minimum]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def _dictionary_words(p: str) -> List[str]:
    """Longest bundled-wordlist words found in the password (leet-normalised)."""
    low = p.lower().translate(_LEET)
    found: List[str] = []
    i = 0
    while i < len(low):
        best = ""
        for j in range(min(len(low), i + 12), i + 2, -1):
            candidate = low[i:j]
            if candidate in WORD_SET and len(candidate) > len(best):
                best = candidate
                break
        if best:
            found.append(best)
            i += len(best)
        else:
            i += 1
    return found


def _year_or_date(p: str) -> bool:
    return bool(re.search(r"(19|20)\d{2}", p)) or bool(
        re.search(r"\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b", p)
    )


def _crack_times(bits: float) -> Dict[str, str]:
    """Average guesses / rate, for a few plausible offline attack rates."""
    scenarios = {
        "online throttled (100/s)": 1e2,
        "offline slow hash (1e4/s)": 1e4,
        "offline fast hash (1e10/s)": 1e10,
        "nation-state (1e14/s)": 1e14,
    }
    out = {}
    for name, rate in scenarios.items():
        try:
            seconds = (2 ** (bits - 1)) / rate
        except OverflowError:
            seconds = float("inf")
        out[name] = _human_time(seconds)
    return out


def _human_time(seconds: float) -> str:
    if seconds == float("inf") or seconds > 3.15e16:
        return "longer than a billion years"
    units = (
        ("second", 60),
        ("minute", 60),
        ("hour", 24),
        ("day", 365.25),
        ("year", 1000),
        ("millennium", 1000),
    )
    value = seconds
    for name, factor in units:
        if value < factor:
            return f"{value:.1f} {name}{'' if 0.95 <= value <= 1.05 else 's'}"
        value /= factor
    return f"{value:.1f} million millennia"


def analyze(password: str) -> Analysis:
    a = Analysis()
    password = password or ""
    a.length = len(password)
    if not password:
        a.suggestions.append("Password is empty.")
        a.crack_times = _crack_times(0)
        return a

    a.charset_size = charset_size(password)
    a.charset_bits = charset_entropy(password)
    a.classes = {
        "lowercase": any(c in LOWER for c in password),
        "uppercase": any(c in UPPER for c in password),
        "digits": any(c in DIGITS for c in password),
        "symbols": any(c in SYMBOLS for c in password),
    }

    penalty = 0.0
    if is_common(password):
        a.patterns.append("appears in the bundled common-password list")
        penalty += max(a.charset_bits - 8, 0)
    words = _dictionary_words(password)
    if words:
        a.patterns.append("contains dictionary word(s): " + ", ".join(words[:4]))
        covered = sum(len(w) for w in words)
        # Each dictionary word costs roughly log2(list size) bits instead of
        # len(word) * log2(alphabet).
        per_char = math.log2(max(a.charset_size, 2))
        penalty += max(covered * per_char - len(words) * math.log2(len(WORD_SET) or 2), 0)
    if _has_repeats(password):
        a.patterns.append("three or more identical characters in a row")
        penalty += 6
    if _repeated_block(password):
        a.patterns.append("the whole password is a repeated block")
        penalty += a.charset_bits * 0.4
    if _has_sequence(password):
        a.patterns.append("contains a character sequence (abcd / 4321)")
        penalty += 8
    if _keyboard_run(password):
        a.patterns.append("contains a keyboard run (qwerty / asdf)")
        penalty += 8
    if _year_or_date(password):
        a.patterns.append("contains a year or date")
        penalty += 6
    if re.fullmatch(r"\d+", password):
        a.patterns.append("digits only")
    if len(set(password)) <= max(2, len(password) // 4):
        a.patterns.append("very few distinct characters")
        penalty += 6

    a.estimated_bits = max(0.0, a.charset_bits - penalty)

    for threshold, label in STRENGTH_LABELS:
        if a.estimated_bits < threshold:
            a.strength = label
            break
    a.score = min(4, int(a.estimated_bits // 20))

    if a.length < 12:
        a.suggestions.append("Use at least 12 characters; 16+ is better.")
    if not a.classes["uppercase"] or not a.classes["lowercase"]:
        a.suggestions.append("Mix upper and lower case.")
    if not a.classes["digits"]:
        a.suggestions.append("Add digits.")
    if not a.classes["symbols"]:
        a.suggestions.append("Add symbols.")
    if a.patterns:
        a.suggestions.append("Prefer a generated password or a random passphrase.")
    a.crack_times = _crack_times(a.estimated_bits)
    return a


def strength_label(bits: float) -> str:
    for threshold, label in STRENGTH_LABELS:
        if bits < threshold:
            return label
    return "very strong"


def analyze_characters(text: str) -> Dict[str, object]:
    """Character analyzer micro-tool: composition of an arbitrary string."""
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    categories = {
        "lowercase": sum(1 for c in text if c in LOWER),
        "uppercase": sum(1 for c in text if c in UPPER),
        "digits": sum(1 for c in text if c in DIGITS),
        "symbols": sum(1 for c in text if c in SYMBOLS and c != " "),
        "spaces": text.count(" "),
        "other": sum(
            1 for c in text if c not in LOWER + UPPER + DIGITS + SYMBOLS
        ),
    }
    non_ascii = sorted({c for c in text if ord(c) > 127})
    invisible = sorted(
        {c for c in text if ord(c) < 32 or ord(c) in (0x7F, 0x200B, 0x200C, 0x200D, 0xFEFF)}
    )
    return {
        "length": len(text),
        "unique": len(counts),
        "categories": categories,
        "most_common": sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10],
        "non_ascii": [f"U+{ord(c):04X}" for c in non_ascii][:20],
        "invisible_or_control": [f"U+{ord(c):04X}" for c in invisible][:20],
        "charset_size": charset_size(text),
        "charset_bits": round(charset_entropy(text), 2),
    }
