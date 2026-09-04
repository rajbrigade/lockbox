"""Vault lifecycle and item CRUD.

The vault holds decrypted items in memory only while unlocked. Locking drops
the item objects and wipes the data-encryption key. There is no background
thread: auto-lock is evaluated by `check_autolock()`, which the UI polls from
its own event loop (see docs/ARCHITECTURE.md, "No daemons").
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, Iterable, List, Optional

from . import crypto, vaultfile
from .errors import VaultLockedError
from .kdf import KDFParams, default_params
from .model import Item, empty_payload, normalise_payload, now

APP_DIR_NAME = "lockbox"
VAULT_FILENAME = "vault.lbx"


def default_data_dir() -> str:
    """Per-user local data directory. No roaming, no sync directories."""
    env = os.environ.get("LOCKBOX_HOME")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "share"
        )
    return os.path.join(base, APP_DIR_NAME)


def default_vault_path() -> str:
    """The vault to use when no path was given.

    `LOCKBOX_VAULT` is honoured here rather than only in the CLI argument
    parser, so the GUI entry point -- which takes no arguments -- respects it
    too. `LOCKBOX_VAULT` names a file; `LOCKBOX_HOME` names the directory.
    """
    env = os.environ.get("LOCKBOX_VAULT")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    return os.path.join(default_data_dir(), VAULT_FILENAME)


class Vault:
    def __init__(self, path: Optional[str] = None):
        self.path = os.path.abspath(path or default_vault_path())
        self._keys: Optional[vaultfile.VaultKeys] = None
        self._payload: Optional[Dict[str, Any]] = None
        self._items: Dict[str, Item] = {}
        self._dirty = False
        self._last_activity = 0.0

    # -- state ----------------------------------------------------------
    @property
    def exists(self) -> bool:
        return os.path.exists(self.path)

    @property
    def unlocked(self) -> bool:
        return self._keys is not None

    @property
    def dirty(self) -> bool:
        return self._dirty

    def _require(self) -> None:
        if not self.unlocked:
            raise VaultLockedError("vault is locked")

    def __repr__(self) -> str:
        return f"<Vault path={self.path!r} unlocked={self.unlocked}>"

    # -- lifecycle ------------------------------------------------------
    def create(self, password: bytes, kdf: Optional[KDFParams] = None) -> None:
        if self.exists:
            raise FileExistsError(f"vault already exists: {self.path}")
        self._keys = vaultfile.new_keys(password, kdf or default_params())
        self._payload = empty_payload()
        self._items = {}
        self._dirty = True
        self.save()
        self.touch_activity()

    def unlock(self, password: bytes) -> None:
        blob = vaultfile.read_file(self.path)
        payload, keys = vaultfile.deserialize(blob, password)
        payload = normalise_payload(payload)
        self._keys = keys
        self._payload = payload
        self._items = {}
        for raw in payload.get("items", []):
            item = Item.from_dict(raw)
            self._items[item.id] = item
        self._payload["items"] = []  # single source of truth is self._items
        self._dirty = False
        self.touch_activity()

    def lock(self) -> None:
        if self._keys is not None:
            self._keys.wipe()
        self._keys = None
        self._payload = None
        self._items = {}
        self._dirty = False

    def save(self) -> None:
        self._require()
        assert self._payload is not None and self._keys is not None
        payload = dict(self._payload)
        payload["items"] = [i.to_dict() for i in self._items.values()]
        payload["meta"] = dict(payload.get("meta") or {})
        payload["meta"]["updated"] = now()
        blob = vaultfile.serialize(self._keys, payload)
        vaultfile.write_atomic(self.path, blob)
        self._payload["meta"] = payload["meta"]
        self._dirty = False

    def change_master_password(self, new_password: bytes) -> None:
        self._require()
        assert self._keys is not None
        self._keys = vaultfile.rewrap(self._keys, new_password, default_params())
        self.save()

    def kdf_description(self) -> str:
        from .kdf import describe

        self._require()
        assert self._keys is not None
        return describe(self._keys.kdf)

    # -- auto-lock ------------------------------------------------------
    def touch_activity(self) -> None:
        self._last_activity = time.monotonic()

    def idle_seconds(self) -> float:
        return time.monotonic() - self._last_activity

    def check_autolock(self) -> bool:
        """Lock if idle past the configured timeout. Returns True if locked."""
        if not self.unlocked:
            return False
        timeout = int(self.settings.get("auto_lock_seconds") or 0)
        if timeout > 0 and self.idle_seconds() >= timeout:
            if self._dirty:
                try:
                    self.save()
                except OSError:
                    pass
            self.lock()
            return True
        return False

    # -- settings / folders ---------------------------------------------
    @property
    def settings(self) -> Dict[str, Any]:
        self._require()
        assert self._payload is not None
        return self._payload["settings"]

    def set_setting(self, key: str, value: Any) -> None:
        self._require()
        if key not in self.settings:
            raise KeyError(f"unknown setting: {key}")
        self.settings[key] = value
        self._dirty = True

    @property
    def meta(self) -> Dict[str, Any]:
        self._require()
        assert self._payload is not None
        return self._payload["meta"]

    def folders(self) -> List[str]:
        self._require()
        names = {i.folder for i in self._items.values() if i.folder}
        assert self._payload is not None
        names.update(self._payload.get("folders") or [])
        return sorted(names)

    def tags(self) -> List[str]:
        self._require()
        out = set()
        for item in self._items.values():
            out.update(item.tags)
        return sorted(out)

    # -- CRUD -----------------------------------------------------------
    def items(self) -> List[Item]:
        self._require()
        return list(self._items.values())

    def get(self, item_id: str) -> Item:
        self._require()
        return self._items[item_id]

    def add(self, item: Item) -> Item:
        self._require()
        self._items[item.id] = item
        self._dirty = True
        self.touch_activity()
        return item

    def add_many(self, items: Iterable[Item]) -> int:
        count = 0
        for item in items:
            self.add(item)
            count += 1
        return count

    def update(self, item: Item) -> Item:
        self._require()
        if item.id not in self._items:
            raise KeyError(item.id)
        item.touch()
        self._items[item.id] = item
        self._dirty = True
        self.touch_activity()
        return item

    def delete(self, item_id: str) -> None:
        self._require()
        item = self._items.pop(item_id, None)
        if item is not None:
            _scrub_item(item)
            self._dirty = True
            self.touch_activity()

    # -- integrity ------------------------------------------------------
    def integrity_check(self) -> Dict[str, Any]:
        """Re-read the file from disk and validate it end to end.

        Confirms the header parses, the DEK unwraps, the AEAD tag verifies, the
        payload decompresses, and every item round-trips through the model.
        """
        self._require()
        assert self._keys is not None
        report: Dict[str, Any] = {"ok": False, "checks": [], "errors": []}

        def check(name: str, fn):
            try:
                fn()
                report["checks"].append({"name": name, "ok": True})
                return True
            except Exception as exc:
                report["checks"].append({"name": name, "ok": False, "detail": str(exc)})
                report["errors"].append(f"{name}: {exc}")
                return False

        blob = vaultfile.read_file(self.path)
        state: Dict[str, Any] = {}
        payload_state: Dict[str, Any] = {}

        check("file readable", lambda: state.update(size=len(blob)))
        ok = check("header parses", lambda: state.update(hdr=vaultfile.parse_header(blob)))
        if ok:
            header, prefix, body = state["hdr"]
            check(
                "cipher is AES-256-GCM",
                lambda: _assert(header.get("cipher") == "AES-256-GCM", "unexpected cipher"),
            )
            body_state: Dict[str, Any] = {}
            check(
                "body authenticates",
                lambda: body_state.update(
                    pt=crypto.decrypt(bytes(self._keys.dek), body, prefix)
                ),
            )
            if "pt" in body_state:
                check(
                    "payload decodes",
                    lambda: payload_state.update(
                        p=normalise_payload(_decode_payload(body_state["pt"]))
                    ),
                )
        if "p" in payload_state:
            items = payload_state["p"].get("items", [])
            check(
                "items round-trip",
                lambda: [Item.from_dict(d).to_dict() for d in items],
            )
            report["item_count"] = len(items)
        report["file_size"] = len(blob)
        report["permissions"] = _permissions(self.path)
        report["ok"] = not report["errors"]
        return report


def _assert(cond: bool, message: str) -> None:
    if not cond:
        raise ValueError(message)


def _decode_payload(plaintext: bytes) -> Dict[str, Any]:
    import json
    import zlib

    return json.loads(zlib.decompress(plaintext).decode("utf-8"))


def _permissions(path: str) -> str:
    """POSIX mode as a string, or a note on Windows.

    Windows has no POSIX mode bits: `os.chmod` there only toggles the read-only
    flag, and `st_mode` reports a fabricated 0o666. Access is governed by NTFS
    ACLs, which a file created in the user's own profile inherits correctly.
    Reporting "0o666" would be a lie, so we say what is actually true.
    """
    if sys.platform == "win32":
        return "n/a (Windows: NTFS ACL, inherited from the parent folder)"
    try:
        return oct(os.stat(path).st_mode & 0o777)
    except OSError:
        return "unknown"


def _scrub_item(item: Item) -> None:
    """Best-effort removal of plaintext references from a deleted item."""
    item.password = ""
    item.totp_secret = ""
    item.notes = ""
    item.history.clear()
    item.fields.clear()
