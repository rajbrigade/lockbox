"""Vault data model. Pure data — no crypto, no I/O."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List

SCHEMA_VERSION = 1

ITEM_TYPES = ("login", "note", "card", "identity", "api_key")

TYPE_LABELS = {
    "login": "Login",
    "note": "Secure Note",
    "card": "Card",
    "identity": "Identity",
    "api_key": "API Key",
}

DEFAULT_SETTINGS: Dict[str, Any] = {
    "auto_lock_seconds": 300,
    "clipboard_clear_seconds": 20,
    "clear_clipboard_on_lock": True,
    "password_age_warning_days": 365,
    "min_password_length": 12,
    "backup_reminder_days": 14,
    "backup_keep": 10,
    "history_limit": 10,
    "breach_dataset_path": "",
}


def now() -> int:
    return int(time.time())


def new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Item:
    id: str = field(default_factory=new_id)
    type: str = "login"
    title: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    folder: str = ""
    favorite: bool = False
    totp_secret: str = ""
    fields: Dict[str, str] = field(default_factory=dict)
    created: int = field(default_factory=now)
    updated: int = field(default_factory=now)
    password_updated: int = field(default_factory=now)
    history: List[Dict[str, Any]] = field(default_factory=list)

    # -- mutation -------------------------------------------------------
    def touch(self) -> None:
        self.updated = now()
        self._search_cache = None

    def set_password(self, new_password: str, history_limit: int = 10) -> None:
        """Change the password, recording the old one in local history."""
        if self.password and new_password != self.password:
            self.history.insert(
                0, {"password": self.password, "changed": self.password_updated}
            )
            del self.history[history_limit:]
        if new_password != self.password:
            self.password_updated = now()
        self.password = new_password
        self.touch()

    # -- serialisation --------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "tags": list(self.tags),
            "folder": self.folder,
            "favorite": bool(self.favorite),
            "totp_secret": self.totp_secret,
            "fields": dict(self.fields),
            "created": int(self.created),
            "updated": int(self.updated),
            "password_updated": int(self.password_updated),
            "history": [dict(h) for h in self.history],
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Item":
        it = Item(
            id=str(d.get("id") or new_id()),
            type=str(d.get("type") or "login"),
            title=str(d.get("title") or ""),
            username=str(d.get("username") or ""),
            password=str(d.get("password") or ""),
            url=str(d.get("url") or ""),
            notes=str(d.get("notes") or ""),
            tags=[str(t) for t in (d.get("tags") or [])],
            folder=str(d.get("folder") or ""),
            favorite=bool(d.get("favorite")),
            totp_secret=str(d.get("totp_secret") or ""),
            fields={str(k): str(v) for k, v in (d.get("fields") or {}).items()},
            created=int(d.get("created") or now()),
            updated=int(d.get("updated") or now()),
            password_updated=int(d.get("password_updated") or d.get("updated") or now()),
            history=[dict(h) for h in (d.get("history") or [])],
        )
        if it.type not in ITEM_TYPES:
            it.type = "note"
        return it

    def searchable(self) -> str:
        """Lower-cased haystack of the non-secret fields.

        Cached because search recomputes it for every item on every keystroke;
        `touch()` invalidates it. Secrets are deliberately excluded (see
        core/search.py).
        """
        cached = getattr(self, "_search_cache", None)
        if cached is not None:
            return cached
        parts = [self.title, self.username, self.url, self.folder, " ".join(self.tags)]
        parts.extend(self.fields.keys())
        parts.extend(self.fields.values())
        value = " ".join(p for p in parts if p).lower()
        object.__setattr__(self, "_search_cache", value)
        return value


def empty_payload() -> Dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "items": [],
        "folders": [],
        "settings": dict(DEFAULT_SETTINGS),
        "meta": {"created": now(), "updated": now(), "last_backup": 0},
    }


def normalise_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Accept older/partial payloads and fill in defaults."""
    out = empty_payload()
    schema = int(payload.get("schema") or SCHEMA_VERSION)
    if schema > SCHEMA_VERSION:
        raise ValueError(
            f"vault schema {schema} is newer than this build supports "
            f"({SCHEMA_VERSION}); upgrade Lockbox"
        )
    out["schema"] = SCHEMA_VERSION
    out["items"] = list(payload.get("items") or [])
    out["folders"] = [str(f) for f in (payload.get("folders") or [])]
    settings = dict(DEFAULT_SETTINGS)
    for key, value in (payload.get("settings") or {}).items():
        if key in settings:
            settings[key] = value
    out["settings"] = settings
    meta = dict(out["meta"])
    meta.update(payload.get("meta") or {})
    out["meta"] = meta
    return out
