"""Micro-tool registry.

Tools are declared as data and imported only when first used, so starting
Lockbox does not pay for tools you never open. Every entry is a pure local
function; `network: False` on every tool is asserted by the test suite, which
also statically scans these modules for networking imports.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

CATEGORIES = ("Generate", "Analyze", "One-time codes", "Encode", "Hash", "Text", "Vault")


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    category: str
    target: str  # "module:function"
    summary: str
    network: bool = False  # invariant: always False; enforced by tests

    def load(self) -> Callable[..., Any]:
        module_name, _, attr = self.target.partition(":")
        module = importlib.import_module(f"lockbox.tools.{module_name}")
        return getattr(module, attr)

    def __call__(self, *args, **kwargs):
        return self.load()(*args, **kwargs)


_TOOLS: Tuple[Tool, ...] = (
    # -- Generate ------------------------------------------------------
    Tool("password", "Password generator", "Generate", "generators:generate_password",
         "Random password with configurable length, classes and exclusions."),
    Tool("passphrase", "Passphrase generator", "Generate", "generators:generate_passphrase",
         "Word-based passphrase from the bundled local word list."),
    Tool("pronounceable", "Pronounceable password", "Generate", "generators:generate_pronounceable",
         "Syllable-based password that is easier to read aloud."),
    Tool("random_string", "Random string", "Generate", "generators:random_string",
         "Raw random characters over any alphabet you supply."),
    Tool("username", "Username generator", "Generate", "generators:generate_username",
         "Throwaway usernames. Identifiers, not secrets."),
    Tool("api_key", "API key generator", "Generate", "generators:generate_api_key",
         "Prefixed high-entropy key in hex, base62 or base64url."),
    Tool("token", "Secret / token generator", "Generate", "generators:generate_token",
         "URL-safe random token of N bytes."),
    Tool("recovery_codes", "Recovery code generator", "Generate", "generators:generate_recovery_codes",
         "Grouped one-time recovery codes with unambiguous characters."),
    Tool("uuid", "UUID generator", "Generate", "generators:generate_uuid",
         "UUID v4 (random) or v7 (time-ordered)."),
    Tool("random_number", "Secure random number", "Generate", "generators:secure_random_number",
         "Uniform integers from the OS CSPRNG, no modulo bias."),
    Tool("password_batch", "Password history generator", "Generate",
         "generators:generate_password_history",
         "A batch of candidate passwords for staged rotations."),
    Tool("totp_secret", "TOTP secret generator", "Generate", "otp:generate_secret",
         "New base32 TOTP secret (160-bit by default)."),
    # -- Analyze -------------------------------------------------------
    Tool("strength", "Password strength analyzer", "Analyze", "analysis:analyze",
         "Entropy, detected patterns and offline crack-time estimates."),
    Tool("entropy", "Entropy calculator", "Analyze", "misc:entropy_calculator",
         "Bits of entropy for a character or word scheme."),
    Tool("characters", "Character analyzer", "Analyze", "analysis:analyze_characters",
         "Composition, unusual code points and hidden characters."),
    Tool("password_age", "Password age calculator", "Analyze", "misc:password_age",
         "Age of a credential and whether rotation is worth it."),
    Tool("url_inspect", "URL inspector", "Analyze", "encoding:parse_url",
         "Parse a URL locally; flags punycode and embedded credentials."),
    Tool("checklist", "Local security checklist", "Analyze", "misc:security_checklist",
         "Self-audit checklist; auto-checks what Lockbox can verify."),
    Tool("environment", "Environment report", "Analyze", "misc:environment_report",
         "Local diagnostics: Python, Argon2 availability, clipboard backends."),
    # -- One-time codes -------------------------------------------------
    Tool("totp", "TOTP generator", "One-time codes", "otp:current",
         "Current TOTP code with a countdown, computed locally."),
    Tool("hotp", "HOTP generator", "One-time codes", "otp:hotp",
         "Counter-based one-time password."),
    Tool("otpauth_parse", "otpauth URI parser", "One-time codes", "otp:parse_otpauth",
         "Turn an otpauth:// URI or bare secret into TOTP settings."),
    Tool("qr_svg", "QR code generator (SVG)", "One-time codes", "qr:to_svg",
         "Self-contained SVG QR code; no external resources."),
    Tool("qr_text", "QR code generator (text)", "One-time codes", "qr:to_text",
         "QR code drawn with block characters in the terminal."),
    # -- Encode --------------------------------------------------------
    Tool("base64_encode", "Base64 encode", "Encode", "encoding:base64_encode", "Text to base64."),
    Tool("base64_decode", "Base64 decode", "Encode", "encoding:base64_decode", "Base64 to text."),
    Tool("base32_encode", "Base32 encode", "Encode", "encoding:base32_encode", "Text to base32."),
    Tool("base32_decode", "Base32 decode", "Encode", "encoding:base32_decode", "Base32 to text."),
    Tool("hex_encode", "Hex encode", "Encode", "encoding:hex_encode", "Text to hex."),
    Tool("hex_decode", "Hex decode", "Encode", "encoding:hex_decode", "Hex to text."),
    Tool("url_encode", "URL encode", "Encode", "encoding:url_encode", "Percent-encode text."),
    Tool("url_decode", "URL decode", "Encode", "encoding:url_decode", "Decode percent-encoding."),
    Tool("json_format", "JSON formatter", "Encode", "encoding:json_format", "Pretty-print JSON."),
    Tool("json_minify", "JSON minifier", "Encode", "encoding:json_minify", "Compact JSON."),
    Tool("json_validate", "JSON validator", "Encode", "encoding:json_validate",
         "Validate JSON and report the error position."),
    Tool("regex", "Regex tester", "Encode", "encoding:regex_test",
         "Test a pattern against sample text with capture groups."),
    # -- Hash ----------------------------------------------------------
    Tool("hash", "Hash calculator", "Hash", "encoding:hash_text",
         "SHA-2/SHA-3/BLAKE2 digests of text."),
    Tool("hash_file", "File hash calculator", "Hash", "encoding:hash_file",
         "Streaming digest of a local file."),
    Tool("hmac", "HMAC calculator", "Hash", "encoding:hmac_text", "Keyed HMAC of text."),
    Tool("digest_compare", "Digest comparison", "Hash", "encoding:compare_digests",
         "Constant-time comparison of two digests."),
    # -- Text ----------------------------------------------------------
    Tool("transform", "Text transformation", "Text", "encoding:transform",
         "Case, whitespace, Unicode normalisation and slug transforms."),
)

TOOLS: Dict[str, Tool] = {t.id: t for t in _TOOLS}


def by_category() -> Dict[str, List[Tool]]:
    out: Dict[str, List[Tool]] = {}
    for tool in _TOOLS:
        out.setdefault(tool.category, []).append(tool)
    return out


def get(tool_id: str) -> Tool:
    try:
        return TOOLS[tool_id]
    except KeyError:
        raise KeyError(f"unknown tool: {tool_id}") from None


def run(tool_id: str, *args, **kwargs):
    return get(tool_id)(*args, **kwargs)


def search(text: str) -> List[Tool]:
    needle = (text or "").lower().strip()
    if not needle:
        return list(_TOOLS)
    return [
        t
        for t in _TOOLS
        if needle in t.name.lower() or needle in t.id or needle in t.summary.lower()
    ]
