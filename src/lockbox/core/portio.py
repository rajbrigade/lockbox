"""Import and export. Entirely local file I/O.

Import understands the CSV/JSON shapes the common managers emit (Bitwarden,
KeePass, Chrome/Edge/Firefox, 1Password's CSV) by mapping column names rather
than by guessing at column order.

Export comes in two flavours:

* **encrypted** -- a copy of the vault container. Safe to store anywhere.
* **plaintext** -- CSV or JSON with every secret readable. Guarded by an
  explicit confirmation token, written 0600, and the caller is handed a warning
  string it is expected to show. Lockbox will not write one silently and will
  not put one in a temp directory.
"""

from __future__ import annotations

import csv
import io
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from . import vaultfile
from .model import Item, now

PLAINTEXT_WARNING = (
    "This file will contain every password, note and TOTP secret in your vault "
    "in readable form. Anyone with the file has your accounts. Store it on "
    "encrypted media, delete it when done, and never place it in a synced or "
    "shared folder."
)
CONFIRM_TOKEN = "I UNDERSTAND"

# Column aliases -> canonical field. Lower-cased, punctuation-stripped.
_ALIASES = {
    "name": "title", "title": "title", "account": "title", "accountname": "title",
    "item": "title", "displayname": "title",
    "username": "username", "user": "username", "login": "username",
    "loginname": "username", "userid": "username", "uid": "username",
    "signon": "username", "usernameoremail": "username",
    "loginusername": "username", "email": "username", "emailaddress": "username",
    "password": "password", "pass": "password", "loginpassword": "password",
    "url": "url", "urls": "url", "website": "url", "site": "url", "loginuri": "url",
    "loginurl": "url", "weburl": "url",
    "notes": "notes", "note": "notes", "comment": "notes", "comments": "notes",
    "extra": "notes",
    "folder": "folder", "group": "folder", "grouping": "folder", "category": "folder",
    "collection": "folder",
    "tags": "tags", "tag": "tags", "labels": "tags",
    "favorite": "favorite", "favourite": "favorite", "fav": "favorite", "starred": "favorite",
    "totp": "totp_secret", "totpsecret": "totp_secret", "otpauth": "totp_secret",
    "logintotp": "totp_secret", "twofactorsecret": "totp_secret", "otp": "totp_secret",
    "type": "type",
}

_EXPORT_FIELDS = (
    "type", "title", "username", "password", "url", "totp_secret", "notes",
    "folder", "tags", "favorite", "created", "updated", "password_updated",
)


@dataclass
class ImportResult:
    items: List[Item] = field(default_factory=list)
    skipped: int = 0
    warnings: List[str] = field(default_factory=list)
    source_format: str = ""

    def summary(self) -> str:
        text = f"{len(self.items)} item(s) parsed from {self.source_format}"
        if self.skipped:
            text += f", {self.skipped} row(s) skipped"
        return text


def _canon(name: str) -> str:
    return "".join(ch for ch in (name or "").lower() if ch.isalnum())


def _map_row(row: Dict[str, Any]) -> Dict[str, Any]:
    mapped: Dict[str, Any] = {}
    custom: Dict[str, str] = {}
    for key, value in row.items():
        if value in (None, ""):
            continue
        field_name = _ALIASES.get(_canon(key))
        if field_name and field_name not in mapped:
            mapped[field_name] = value
        elif not field_name and key:
            custom[str(key)[:64]] = str(value)[:2048]
    if custom:
        mapped["fields"] = custom
    return mapped


def _to_item(mapped: Dict[str, Any]) -> Optional[Item]:
    title = str(mapped.get("title") or "").strip()
    username = str(mapped.get("username") or "").strip()
    password = str(mapped.get("password") or "")
    notes = str(mapped.get("notes") or "")
    if not any((title, username, password, notes)):
        return None

    tags_raw = mapped.get("tags") or []
    if isinstance(tags_raw, str):
        tags = [t.strip() for t in tags_raw.replace(";", ",").split(",") if t.strip()]
    else:
        tags = [str(t).strip() for t in tags_raw if str(t).strip()]

    fav = mapped.get("favorite")
    favorite = str(fav).strip().lower() in ("1", "true", "yes", "y") if fav is not None else False

    totp_raw = str(mapped.get("totp_secret") or "").strip()
    totp_secret = ""
    if totp_raw:
        from ..tools.otp import parse_otpauth

        try:
            config = parse_otpauth(totp_raw)
        except ValueError:
            totp_secret = ""
        else:
            # Keep the whole otpauth:// URI: it carries algorithm, digits and
            # period, and reducing it to the bare secret silently forces the
            # SHA1/6/30 defaults and produces codes the site rejects.
            totp_secret = totp_raw if totp_raw.lower().startswith("otpauth://") \
                else config.secret

    item_type = str(mapped.get("type") or "").strip().lower()
    if item_type not in ("login", "note", "card", "identity", "api_key"):
        item_type = "login" if (password or username) else "note"

    item = Item(
        type=item_type,
        title=title or username or "(untitled)",
        username=username,
        password=password,
        url=str(mapped.get("url") or "").strip(),
        notes=notes,
        tags=tags,
        folder=str(mapped.get("folder") or "").strip(),
        favorite=favorite,
        totp_secret=totp_secret,
        fields={k: str(v) for k, v in (mapped.get("fields") or {}).items()},
    )
    for stamp in ("created", "updated", "password_updated"):
        value = mapped.get(stamp)
        if isinstance(value, (int, float)) and value > 0:
            setattr(item, stamp, int(value))
    return item


def import_csv(text: str) -> ImportResult:
    result = ImportResult(source_format="CSV")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        result.warnings.append("CSV has no header row; nothing imported.")
        return result
    known = [f for f in reader.fieldnames if _ALIASES.get(_canon(f or ""))]
    if not known:
        result.warnings.append(
            "No recognisable columns (title/username/password/url). "
            f"Saw: {', '.join(str(f) for f in reader.fieldnames[:8])}"
        )
        return result
    for row in reader:
        item = _to_item(_map_row({k: v for k, v in row.items() if k}))
        if item is None:
            result.skipped += 1
        else:
            result.items.append(item)
    return result


def import_json(text: str) -> ImportResult:
    result = ImportResult(source_format="JSON")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.warnings.append(f"Invalid JSON: {exc.msg} (line {exc.lineno})")
        return result

    rows: List[Dict[str, Any]] = []
    if isinstance(data, list):
        rows = [r for r in data if isinstance(r, dict)]
        result.source_format = "JSON (array)"
    elif isinstance(data, dict):
        if isinstance(data.get("items"), list):  # native Lockbox export
            rows = [r for r in data["items"] if isinstance(r, dict)]
            result.source_format = f"Lockbox JSON (schema {data.get('schema', '?')})"
        elif isinstance(data.get("logins"), list):
            rows = [r for r in data["logins"] if isinstance(r, dict)]
            result.source_format = "JSON (object)"
        else:
            for key in ("accounts", "entries", "passwords", "data"):
                if isinstance(data.get(key), list):
                    rows = [r for r in data[key] if isinstance(r, dict)]
                    result.source_format = f"JSON ({key})"
                    break
    if not rows:
        result.warnings.append("No item array found in the JSON.")
        return result

    for row in rows:
        flat = dict(row)
        # Bitwarden nests the interesting parts under "login".
        nested = row.get("login")
        if isinstance(nested, dict):
            flat.pop("login", None)
            for key, value in nested.items():
                if key == "uris" and isinstance(value, list) and value:
                    first = value[0]
                    flat["url"] = first.get("uri") if isinstance(first, dict) else first
                else:
                    flat[key] = value
        item = _to_item(_map_row(flat))
        if item is None:
            result.skipped += 1
        else:
            result.items.append(item)
    return result


def import_auto(text: str, filename: str = "") -> ImportResult:
    stripped = text.lstrip()
    if filename.lower().endswith(".json") or stripped[:1] in ("{", "["):
        return import_json(text)
    return import_csv(text)


def import_vault_file(path: str, password: bytes) -> ImportResult:
    """Import from another encrypted Lockbox vault (merge source)."""
    payload, keys = vaultfile.deserialize(vaultfile.read_file(path), password)
    keys.wipe()
    result = ImportResult(source_format="Lockbox vault")
    for raw in payload.get("items") or []:
        try:
            result.items.append(Item.from_dict(raw))
        except Exception:
            result.skipped += 1
    return result


def merge(existing: Sequence[Item], incoming: Iterable[Item], strategy: str = "skip_duplicates"):
    """Merge imported items into a vault's items.

    `skip_duplicates` matches on (title, username, password) so re-importing the
    same file twice is a no-op. `keep_all` imports everything. Nothing is ever
    overwritten in place: an import can only add.
    """
    if strategy not in ("skip_duplicates", "keep_all"):
        raise ValueError("strategy must be skip_duplicates or keep_all")
    if strategy == "keep_all":
        return list(incoming), 0
    seen = {
        (i.title.strip().lower(), i.username.strip().lower(), i.password)
        for i in existing
    }
    added: List[Item] = []
    duplicates = 0
    for item in incoming:
        key = (item.title.strip().lower(), item.username.strip().lower(), item.password)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        added.append(item)
    return added, duplicates


# ------------------------------------------------------------------ export --
def export_json(items: Iterable[Item], include_history: bool = False) -> str:
    payload = {
        "format": "lockbox-plaintext-export",
        "schema": 1,
        "exported_at": now(),
        "warning": PLAINTEXT_WARNING,
        "items": [],
    }
    for item in items:
        data = item.to_dict()
        if not include_history:
            data.pop("history", None)
        payload["items"].append(data)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def export_csv(items: Iterable[Item]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(_EXPORT_FIELDS), extrasaction="ignore")
    writer.writeheader()
    for item in items:
        row = item.to_dict()
        row["tags"] = ",".join(item.tags)
        row["favorite"] = "true" if item.favorite else "false"
        writer.writerow({k: row.get(k, "") for k in _EXPORT_FIELDS})
    return buffer.getvalue()


def write_plaintext_export(
    path: str, items: Iterable[Item], fmt: str = "csv", confirm: str = "",
    include_history: bool = False,
) -> Dict[str, Any]:
    """Write a readable export. Refuses without the exact confirmation token."""
    if confirm != CONFIRM_TOKEN:
        raise PermissionError(
            f"Plaintext export requires confirm={CONFIRM_TOKEN!r}. {PLAINTEXT_WARNING}"
        )
    items = list(items)
    if fmt == "csv":
        text = export_csv(items)
    elif fmt == "json":
        text = export_json(items, include_history)
    else:
        raise ValueError("fmt must be csv or json")

    target = os.path.abspath(os.path.expanduser(path))
    if _looks_like_sync_dir(target):
        raise PermissionError(
            f"{target} looks like a cloud-sync folder. Lockbox will not write a "
            "plaintext export there. Choose a local path."
        )
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return {
        "path": target,
        "format": fmt,
        "items": len(items),
        "bytes": len(text.encode("utf-8")),
        "permissions": "0o600",
        "warning": PLAINTEXT_WARNING,
        "written_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


_SYNC_MARKERS = (
    "dropbox", "onedrive", "google drive", "googledrive", "icloud", "box sync",
    "mega", "pcloud", "sync.com", "yandex.disk", "nextcloud",
)


def _looks_like_sync_dir(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in _SYNC_MARKERS)


def export_encrypted(vault_path: str, target_path: str) -> Dict[str, Any]:
    """Export the encrypted container itself. Same crypto, no downgrade."""
    blob = vaultfile.read_file(vault_path)
    header, _, _ = vaultfile.parse_header(blob)
    target = os.path.abspath(os.path.expanduser(target_path))
    vaultfile.write_atomic(target, blob, keep_previous=False)
    return {
        "path": target,
        "bytes": len(blob),
        "cipher": header.get("cipher"),
        "kdf": header.get("kdf", {}).get("algorithm"),
        "note": "Encrypted with your master password. Useless to anyone without it.",
    }


def shred(path: str, passes: int = 1) -> bool:
    """Best-effort removal of a plaintext export.

    Overwrites, flushes, then unlinks. On SSDs, journalling and copy-on-write
    filesystems this does **not** guarantee the old bytes are gone -- it is a
    tidy-up, not a forensic wipe, and is documented as such.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            for _ in range(max(1, passes)):
                fh.seek(0)
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
        os.unlink(path)
        return True
    except OSError:
        return False
