"""Local encrypted backups.

A backup is a byte-for-byte copy of the encrypted vault file. That means:

* it is encrypted with the same key hierarchy -- there is no weaker backup format;
* verifying it needs only the master password;
* restoring it is a file copy, and works even if Lockbox itself is gone
  (any build that can read the format can read the backup).

Backups are written where you point them and nowhere else. Nothing is uploaded,
and no cloud folder is chosen for you -- if you put the backup directory inside
a sync folder, that is your decision and your threat model.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from . import vaultfile
from .errors import DecryptError, VaultFormatError

BACKUP_SUFFIX = ".lbx"
_STAMP = "%Y%m%d-%H%M%S"


@dataclass(frozen=True)
class BackupInfo:
    path: str
    size: int
    created: float
    sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "created": int(self.created),
            "created_human": time.strftime("%Y-%m-%d %H:%M", time.localtime(self.created)),
            "sha256": self.sha256,
        }


def default_backup_dir(vault_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(vault_path)), "backups")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def create_backup(
    vault_path: str, backup_dir: Optional[str] = None, keep: int = 10, label: str = ""
) -> BackupInfo:
    """Copy the encrypted vault into `backup_dir`, pruning old copies."""
    if not os.path.isfile(vault_path):
        raise FileNotFoundError(vault_path)
    directory = os.path.abspath(os.path.expanduser(backup_dir or default_backup_dir(vault_path)))
    os.makedirs(directory, exist_ok=True)
    os.chmod(directory, 0o700)

    stamp = time.strftime(_STAMP)
    suffix = f"-{_safe_label(label)}" if label else ""
    target = os.path.join(directory, f"vault-{stamp}{suffix}{BACKUP_SUFFIX}")
    counter = 1
    while os.path.exists(target):
        target = os.path.join(directory, f"vault-{stamp}{suffix}-{counter}{BACKUP_SUFFIX}")
        counter += 1

    blob = vaultfile.read_file(vault_path)
    vaultfile.parse_header(blob)  # refuse to back up something that is not a vault
    vaultfile.write_atomic(target, blob, keep_previous=False)

    if keep > 0:
        prune(directory, keep)
    return BackupInfo(target, len(blob), time.time(), hashlib.sha256(blob).hexdigest())


def _safe_label(label: str) -> str:
    return "".join(c for c in label if c.isalnum() or c in "-_")[:24]


def list_backups(backup_dir: str) -> List[BackupInfo]:
    directory = os.path.abspath(os.path.expanduser(backup_dir))
    if not os.path.isdir(directory):
        return []
    out: List[BackupInfo] = []
    for entry in os.scandir(directory):
        if not entry.is_file() or not entry.name.endswith(BACKUP_SUFFIX):
            continue
        try:
            out.append(
                BackupInfo(entry.path, entry.stat().st_size, entry.stat().st_mtime,
                           _sha256_file(entry.path))
            )
        except OSError:
            continue
    out.sort(key=lambda b: b.created, reverse=True)
    return out


def prune(backup_dir: str, keep: int) -> List[str]:
    removed = []
    for info in list_backups(backup_dir)[keep:]:
        try:
            os.unlink(info.path)
            removed.append(info.path)
        except OSError:
            pass
    return removed


def verify_backup(path: str, password: Optional[bytes] = None) -> Dict[str, Any]:
    """Check a backup.

    Without a password: confirms the container parses (structure only).
    With a password: fully decrypts and counts items -- the only check that
    proves the backup is actually restorable.
    """
    result: Dict[str, Any] = {"path": path, "structure_ok": False, "decrypt_ok": None,
                              "items": None, "error": ""}
    try:
        blob = vaultfile.read_file(path)
        header, _, _ = vaultfile.parse_header(blob)
        result["structure_ok"] = True
        result["cipher"] = header.get("cipher")
        result["kdf"] = header.get("kdf", {}).get("algorithm")
        result["size"] = len(blob)
        result["sha256"] = hashlib.sha256(blob).hexdigest()
    except (OSError, VaultFormatError) as exc:
        result["error"] = str(exc)
        return result

    if password is not None:
        try:
            payload, keys = vaultfile.deserialize(blob, password)
            keys.wipe()
            result["decrypt_ok"] = True
            result["items"] = len(payload.get("items") or [])
        except (DecryptError, VaultFormatError) as exc:
            result["decrypt_ok"] = False
            result["error"] = str(exc)
    return result


def restore_backup(backup_path: str, vault_path: str, password: bytes) -> Dict[str, Any]:
    """Restore a backup over the live vault.

    The backup is decrypted *before* anything is overwritten, so a wrong
    password or a damaged file cannot destroy the working vault. The vault it
    replaces is kept as `<vault>.prev`.
    """
    blob = vaultfile.read_file(backup_path)
    payload, keys = vaultfile.deserialize(blob, password)  # raises before any write
    keys.wipe()
    vaultfile.write_atomic(vault_path, blob, keep_previous=True)
    return {
        "restored_from": backup_path,
        "vault": vault_path,
        "items": len(payload.get("items") or []),
        "previous_kept_at": vault_path + ".prev",
    }


def needs_backup(last_backup: int, reminder_days: int, now: Optional[int] = None) -> bool:
    if reminder_days <= 0:
        return False
    current = int(time.time() if now is None else now)
    return (current - int(last_backup or 0)) > reminder_days * 86400
