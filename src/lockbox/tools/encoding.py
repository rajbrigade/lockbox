"""Encoding, hashing and text utilities. Pure functions, stdlib only."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import unicodedata
import uuid
from typing import Any, Dict, List

HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b")
_INSECURE_HASHES = {"md5", "sha1"}


# ------------------------------------------------------------- base64/url --
def base64_encode(text: str, urlsafe: bool = False, strip_padding: bool = False) -> str:
    raw = text.encode("utf-8")
    out = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw).decode("ascii")
    return out.rstrip("=") if strip_padding else out


def base64_decode(text: str, urlsafe: bool = False) -> str:
    cleaned = "".join((text or "").split())
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        raw = (base64.urlsafe_b64decode if urlsafe else base64.b64decode)(cleaned)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not valid base64") from exc
    return raw.decode("utf-8", errors="replace")


def base32_encode(text: str) -> str:
    return base64.b32encode(text.encode("utf-8")).decode("ascii")


def base32_decode(text: str) -> str:
    cleaned = "".join((text or "").split()).upper()
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not valid base32") from exc


def hex_encode(text: str) -> str:
    return text.encode("utf-8").hex()


def hex_decode(text: str) -> str:
    cleaned = "".join((text or "").split()).replace("0x", "")
    try:
        return bytes.fromhex(cleaned).decode("utf-8", errors="replace")
    except ValueError as exc:
        raise ValueError("not valid hex") from exc


def url_encode(text: str, component: bool = True) -> str:
    from urllib.parse import quote

    return quote(text, safe="" if component else "/:?#[]@!$&'()*+,;=")


def url_decode(text: str) -> str:
    from urllib.parse import unquote

    return unquote(text)


def parse_url(url: str) -> Dict[str, Any]:
    """Safe local URL inspection - parsing only, never a request."""
    from urllib.parse import parse_qsl, urlsplit

    parts = urlsplit(url.strip())
    return {
        "scheme": parts.scheme,
        "host": parts.hostname or "",
        "port": parts.port,
        "path": parts.path,
        "query": dict(parse_qsl(parts.query)),
        "fragment": parts.fragment,
        "has_userinfo": bool(parts.username or parts.password),
        "is_https": parts.scheme == "https",
        "punycode_host": (parts.hostname or "").startswith("xn--")
        or ".xn--" in (parts.hostname or ""),
    }


# -------------------------------------------------------------- json/regex --
def json_format(text: str, indent: int = 2, sort_keys: bool = False) -> str:
    return json.dumps(json.loads(text), indent=indent, sort_keys=sort_keys, ensure_ascii=False)


def json_minify(text: str) -> str:
    return json.dumps(json.loads(text), separators=(",", ":"), ensure_ascii=False)


def json_validate(text: str) -> Dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"valid": False, "error": exc.msg, "line": exc.lineno, "column": exc.colno}
    return {
        "valid": True,
        "type": type(value).__name__,
        "keys": list(value)[:50] if isinstance(value, dict) else None,
        "length": len(value) if isinstance(value, (list, dict, str)) else None,
    }


def regex_test(pattern: str, text: str, flags: str = "", limit: int = 200) -> Dict[str, Any]:
    """Test a regex locally.

    `re` can backtrack catastrophically on hostile patterns; that would hang the
    UI rather than leak anything, so the UI runs this on a short input and the
    result reports how many matches were truncated.
    """
    flag_value = 0
    for ch in flags.lower():
        flag_value |= {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A}.get(ch, 0)
    try:
        compiled = re.compile(pattern, flag_value)
    except re.error as exc:
        return {"valid": False, "error": str(exc), "matches": []}
    matches: List[Dict[str, Any]] = []
    for match in compiled.finditer(text):
        matches.append(
            {
                "match": match.group(0),
                "start": match.start(),
                "end": match.end(),
                "groups": list(match.groups()),
                "named": dict(match.groupdict()),
            }
        )
        if len(matches) >= limit:
            break
    return {
        "valid": True,
        "count": len(matches),
        "truncated": len(matches) >= limit,
        "groups": compiled.groups,
        "matches": matches,
    }


# ------------------------------------------------------------ hash / hmac --
def hash_text(text: str, algorithm: str = "sha256", encoding: str = "hex") -> Dict[str, Any]:
    algorithm = algorithm.lower()
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    digest = hashlib.new(algorithm, text.encode("utf-8")).digest()
    return {
        "algorithm": algorithm,
        "value": digest.hex() if encoding == "hex" else base64.b64encode(digest).decode(),
        "bits": len(digest) * 8,
        "warning": (
            "MD5 and SHA-1 are broken for security use; fine for checksums only."
            if algorithm in _INSECURE_HASHES
            else ""
        ),
    }


def hash_file(path: str, algorithm: str = "sha256", chunk: int = 1 << 20) -> Dict[str, Any]:
    algorithm = algorithm.lower()
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    digest = hashlib.new(algorithm)
    size = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            size += len(block)
            digest.update(block)
    return {"algorithm": algorithm, "value": digest.hexdigest(), "bytes": size, "path": path}


def hmac_text(
    key: str, text: str, algorithm: str = "sha256", encoding: str = "hex"
) -> Dict[str, Any]:
    algorithm = algorithm.lower()
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    digest = hmac.new(key.encode("utf-8"), text.encode("utf-8"), algorithm).digest()
    return {
        "algorithm": f"hmac-{algorithm}",
        "value": digest.hex() if encoding == "hex" else base64.b64encode(digest).decode(),
        "bits": len(digest) * 8,
    }


def compare_digests(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").strip().lower(), (b or "").strip().lower())


# ------------------------------------------------------------------- text --
def transform(text: str, operation: str) -> str:
    ops = {
        "upper": lambda t: t.upper(),
        "lower": lambda t: t.lower(),
        "title": lambda t: t.title(),
        "reverse": lambda t: t[::-1],
        "strip": lambda t: t.strip(),
        "collapse_whitespace": lambda t: re.sub(r"\s+", " ", t).strip(),
        "remove_whitespace": lambda t: re.sub(r"\s+", "", t),
        "snake_case": lambda t: re.sub(r"[\s\-]+", "_", t.strip()).lower(),
        "kebab_case": lambda t: re.sub(r"[\s_]+", "-", t.strip()).lower(),
        "camel_case": lambda t: (
            lambda parts: parts[0].lower() + "".join(p.capitalize() for p in parts[1:])
        )(re.split(r"[\s_\-]+", t.strip()) or [""]),
        "sort_lines": lambda t: "\n".join(sorted(t.splitlines())),
        "unique_lines": lambda t: "\n".join(dict.fromkeys(t.splitlines())),
        "count_lines": lambda t: str(len(t.splitlines())),
        "nfc": lambda t: unicodedata.normalize("NFC", t),
        "nfkc": lambda t: unicodedata.normalize("NFKC", t),
        "strip_invisible": lambda t: "".join(
            c for c in t if unicodedata.category(c) not in ("Cf", "Cc") or c in "\n\t"
        ),
        "escape_json": lambda t: json.dumps(t),
        "uuid5_of": lambda t: str(uuid.uuid5(uuid.NAMESPACE_URL, t)),
    }
    if operation not in ops:
        raise ValueError(f"unknown operation: {operation}")
    return ops[operation](text)


TRANSFORMS = (
    "upper", "lower", "title", "reverse", "strip", "collapse_whitespace",
    "remove_whitespace", "snake_case", "kebab_case", "camel_case", "sort_lines",
    "unique_lines", "count_lines", "nfc", "nfkc", "strip_invisible",
    "escape_json", "uuid5_of",
)
