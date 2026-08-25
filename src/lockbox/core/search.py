"""In-memory vault search.

Operates only on the already-decrypted item list held by an unlocked vault.
Passwords, notes and TOTP secrets are never indexed: matching a query against
secret material would leak it through result ordering and would make shoulder
surfing the search box productive.

Query syntax:  free text plus optional `key:value` filters --
    type: user: url: tag: folder: fav: has:totp
e.g.  ``github user:octo tag:work``
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .model import Item

_FILTER_KEYS = {"type", "user", "username", "url", "domain", "tag", "folder", "fav", "has"}


@dataclass
class Query:
    text: str = ""
    filters: Dict[str, List[str]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.filters is None:
            self.filters = {}


def parse_query(raw: str) -> Query:
    words: List[str] = []
    filters: Dict[str, List[str]] = {}
    for token in (raw or "").split():
        if ":" in token:
            key, _, value = token.partition(":")
            key = key.lower()
            if key in _FILTER_KEYS and value:
                filters.setdefault(key, []).append(value.lower())
                continue
        words.append(token.lower())
    return Query(text=" ".join(words), filters=filters)


def _domain(url: str) -> str:
    """Extract a host from a URL without importing a URL library at import
    time; tolerant of the bare `example.com` forms people actually store."""
    from urllib.parse import urlsplit  # stdlib, no network

    candidate = url.strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = "//" + candidate
    try:
        host = urlsplit(candidate).hostname or ""
    except ValueError:
        return ""
    return host.lower()


def _matches_filters(item: Item, q: Query) -> bool:
    for key, values in q.filters.items():
        if key == "type":
            if item.type.lower() not in values:
                return False
        elif key in ("user", "username"):
            if not any(v in item.username.lower() for v in values):
                return False
        elif key in ("url", "domain"):
            host = _domain(item.url) or item.url.lower()
            if not any(v in host for v in values):
                return False
        elif key == "tag":
            tags = {t.lower() for t in item.tags}
            if not any(any(v in t for t in tags) for v in values):
                return False
        elif key == "folder":
            if not any(v in item.folder.lower() for v in values):
                return False
        elif key == "fav":
            want = values[-1] in ("1", "true", "yes")
            if bool(item.favorite) != want:
                return False
        elif key == "has":
            for v in values:
                if v == "totp" and not item.totp_secret:
                    return False
                if v == "url" and not item.url:
                    return False
                if v == "password" and not item.password:
                    return False
    return True


def _fuzzy_score(needle: str, haystack: str) -> Optional[int]:
    """Subsequence match with a small score. None when it does not match.

    Substring hits score highest (prefix > word-start > anywhere); otherwise an
    ordered-subsequence walk keeps typo-ish queries like `gthb` working. Both
    are O(len(haystack)), so a full scan of a few thousand items stays well
    under a millisecond.
    """
    if not needle:
        return 0
    pos = haystack.find(needle)
    if pos == 0:
        return 1000
    if pos > 0:
        return 800 if haystack[pos - 1] == " " else 600
    i = 0
    gaps = 0
    last = -1
    for idx, ch in enumerate(haystack):
        if ch == needle[i]:
            if last >= 0:
                gaps += idx - last - 1
            last = idx
            i += 1
            if i == len(needle):
                return max(1, 300 - gaps)
    return None


def score_item(item: Item, q: Query) -> Optional[int]:
    if not _matches_filters(item, q):
        return None
    if not q.text:
        return 100
    best = _fuzzy_score(q.text, item.title.lower())
    if best is not None:
        best += 200  # title hits outrank other fields
        if best >= 800:  # a substring hit on the title; nothing can beat it
            return best + (50 if item.favorite else 0)
    # Only fall through to the wider (more expensive) haystack when the title
    # did not already give a strong match.
    for extra in (item.username.lower(), item.searchable()):
        s = _fuzzy_score(q.text, extra)
        if s is not None and (best is None or s > best):
            best = s
    if best is None:
        return None
    if item.favorite:
        best += 50
    return best


def search(items: Iterable[Item], raw_query: str, limit: int = 0) -> List[Item]:
    q = parse_query(raw_query)
    scored: List[Tuple[int, str, Item]] = []
    for item in items:
        s = score_item(item, q)
        if s is not None:
            scored.append((-s, item.title.lower(), item))
    scored.sort(key=lambda t: (t[0], t[1]))
    out = [t[2] for t in scored]
    return out[:limit] if limit else out
