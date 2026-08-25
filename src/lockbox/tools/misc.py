"""Small local utilities that do not fit the other tool modules."""

from __future__ import annotations

import math
import os
import platform
import shutil
import sys
import time
from typing import Any, Dict, List, Optional

from .analysis import strength_label


def password_age(changed_at: int, warn_days: int = 365, now: Optional[int] = None) -> Dict[str, Any]:
    """How old a password is, and whether it is worth rotating.

    Rotation on a fixed schedule is no longer recommended practice (NIST
    SP 800-63B advises changing on evidence of compromise instead), so this
    reports age and flags outliers rather than nagging.
    """
    current = int(time.time() if now is None else now)
    age_seconds = max(0, current - int(changed_at))
    days = age_seconds / 86400
    return {
        "days": round(days, 1),
        "years": round(days / 365.25, 2),
        "stale": days > warn_days,
        "changed_at": int(changed_at),
        "human": _human_age(days),
        "advice": (
            "Rotate if this credential is high value or you suspect exposure. "
            "Age alone is not a compromise."
            if days > warn_days
            else "No action needed on age alone."
        ),
    }


def _human_age(days: float) -> str:
    if days < 1:
        return "today"
    if days < 30:
        return f"{int(days)} day{'s' if int(days) != 1 else ''}"
    if days < 365:
        return f"{int(days / 30)} month{'s' if int(days / 30) != 1 else ''}"
    return f"{days / 365.25:.1f} years"


def entropy_calculator(
    alphabet_size: int = 0,
    length: int = 0,
    alphabet: str = "",
    words: int = 0,
    wordlist_size: int = 0,
) -> Dict[str, Any]:
    """Entropy for either a character password or a passphrase scheme."""
    bits = 0.0
    detail = ""
    if alphabet:
        alphabet_size = len(set(alphabet))
    if alphabet_size > 1 and length > 0:
        bits += length * math.log2(alphabet_size)
        detail += f"{length} chars from {alphabet_size} symbols"
    if words > 0 and wordlist_size > 1:
        bits += words * math.log2(wordlist_size)
        detail += (" + " if detail else "") + f"{words} words from {wordlist_size}"
    if bits <= 0:
        raise ValueError("provide alphabet_size+length, or words+wordlist_size")
    return {
        "bits": round(bits, 2),
        "combinations": f"2^{bits:.1f}",
        "strength": strength_label(bits),
        "detail": detail,
        "note": "Assumes every choice was uniformly random. Human-chosen "
        "secrets have far less entropy than this formula suggests.",
    }


def security_checklist(vault_summary: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """A local, static checklist. Items that Lockbox can verify are checked
    automatically; the rest are for you to confirm. Nothing is reported anywhere.
    """
    summary = vault_summary or {}
    items: List[Dict[str, Any]] = [
        {
            "id": "master_password",
            "text": "Master password is long (16+ chars) and used nowhere else",
            "auto": False,
        },
        {
            "id": "master_written_down",
            "text": "Master password is recorded somewhere offline you can reach "
            "(paper in a safe). There is no reset.",
            "auto": False,
        },
        {
            "id": "backup_exists",
            "text": "A recent encrypted backup exists on separate media",
            "auto": True,
            "ok": bool(summary.get("has_recent_backup")),
        },
        {
            "id": "backup_tested",
            "text": "You have actually restored a backup at least once",
            "auto": False,
        },
        {
            "id": "auto_lock",
            "text": "Auto-lock is enabled",
            "auto": True,
            "ok": bool(summary.get("auto_lock_seconds")),
        },
        {
            # On Windows this cannot be checked automatically -- there are no
            # mode bits to read -- so it becomes a manual item rather than a
            # false pass or a false failure.
            "id": "vault_permissions",
            "text": (
                "Vault file is readable only by your user account"
                + (" (NTFS permissions)" if sys.platform == "win32" else " (0600)")
            ),
            "auto": sys.platform != "win32",
            "ok": (
                None if sys.platform == "win32"
                else summary.get("permissions") in ("0o600", "0o400")
            ),
        },
        {
            "id": "full_disk_encryption",
            "text": "Full-disk encryption is on (FileVault / BitLocker / LUKS)",
            "auto": False,
        },
        {
            "id": "os_updates",
            "text": "Operating system and Python are receiving security updates",
            "auto": False,
        },
        {
            "id": "screen_lock",
            "text": "Screen locks automatically when you walk away",
            "auto": False,
        },
        {
            "id": "no_plaintext_exports",
            "text": "No plaintext export files are left on disk or in Downloads",
            "auto": True,
            "ok": not summary.get("plaintext_exports_found"),
        },
        {
            "id": "totp_separate",
            "text": "For your highest-value accounts, 2FA lives on a separate "
            "device (a vault holding both factors is one factor)",
            "auto": False,
        },
        {
            "id": "audit_clean",
            "text": "Security audit shows no weak or reused passwords",
            "auto": True,
            "ok": summary.get("audit_findings") == 0,
        },
    ]
    for item in items:
        item.setdefault("ok", None)
    return items


def environment_report() -> Dict[str, Any]:
    """Local diagnostics. Contains no vault data and is never transmitted."""
    from ..core.kdf import ARGON2_AVAILABLE

    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "argon2_available": ARGON2_AVAILABLE,
        "clipboard_backends": [
            name
            for name in ("wl-copy", "xclip", "xsel", "pbcopy", "clip")
            if shutil.which(name)
        ],
        "tk_available": _tk_available(),
        "pid": os.getpid(),
    }


def _tk_available() -> bool:
    try:
        import tkinter  # noqa: F401

        return True
    except Exception:
        return False
