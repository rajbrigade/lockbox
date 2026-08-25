"""Optional breach checking against a dataset **you** put on this machine.

Lockbox never sends a password, a hash, or a hash prefix anywhere. There is no
k-anonymity API call here, because that is still a network request. If you want
breach checking, you download a dataset yourself (out of band, with whatever
tool you like) and point Lockbox at the file.

Supported local formats, auto-detected:

* ``sha1-text``    -- sorted text file, one uppercase SHA-1 hex digest per line,
                      optionally followed by ``:count``. This is the shape of the
                      published "SHA-1 ordered by hash" pwned-password dumps.
* ``sha1-binary``  -- sorted file of raw 20-byte SHA-1 digests, no separators.
* ``prefix-dir``   -- a directory of files named by the first five hex characters
                      of the digest, each holding ``SUFFIX:count`` lines.

Lookups use binary search directly on the file, so a 40 GB dataset costs a
handful of seeks and no RAM. Nothing is loaded, cached to disk, or logged.

**If no dataset is configured, Lockbox reports "not checked".** It never
implies that a password is clean because it has nothing to check against.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Optional

_LINE_MAX = 128


@dataclass(frozen=True)
class BreachStatus:
    available: bool
    kind: str = ""
    path: str = ""
    detail: str = ""

    def describe(self) -> str:
        if not self.available:
            return (
                "No local breach dataset configured. Lockbox will not check "
                "passwords online, so breach status is unknown -- not clean."
            )
        return f"Local dataset: {self.kind} at {self.path} ({self.detail})"


class BreachDataset:
    """A local, read-only breach dataset. Opened lazily, never written to."""

    def __init__(self, path: str):
        self.path = os.path.abspath(os.path.expanduser(path))
        self.kind = self._detect()

    # -- detection ------------------------------------------------------
    def _detect(self) -> str:
        if os.path.isdir(self.path):
            return "prefix-dir"
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"no breach dataset at {self.path}")
        size = os.path.getsize(self.path)
        with open(self.path, "rb") as fh:
            head = fh.read(64)
        if not head:
            raise ValueError("breach dataset is empty")
        printable = all(
            chr(b) in "0123456789ABCDEFabcdef:\r\n" or 32 <= b < 127 for b in head[:40]
        )
        if printable and (b"\n" in head or b":" in head):
            return "sha1-text"
        if size % 20 == 0:
            return "sha1-binary"
        raise ValueError(
            "unrecognised breach dataset format; expected sorted SHA-1 text, "
            "raw 20-byte digests, or a directory of prefix files"
        )

    def status(self) -> BreachStatus:
        if self.kind == "prefix-dir":
            try:
                count = sum(1 for _ in os.scandir(self.path))
            except OSError:
                count = 0
            detail = f"{count} prefix files"
        else:
            detail = f"{os.path.getsize(self.path) / 1e9:.2f} GB"
        return BreachStatus(True, self.kind, self.path, detail)

    # -- lookup ---------------------------------------------------------
    def lookup(self, password: str) -> Optional[int]:
        """Occurrence count for `password`, 0 if absent, None if unusable.

        The SHA-1 here is a dataset index, not a security mechanism: the
        published corpora are keyed by SHA-1, so matching them requires it. It
        is computed in this process and never leaves it.
        """
        if not password:
            return 0
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        try:
            if self.kind == "prefix-dir":
                return self._lookup_prefix_dir(digest)
            if self.kind == "sha1-binary":
                return self._lookup_binary(digest)
            return self._lookup_text(digest)
        except OSError:
            return None

    def _lookup_prefix_dir(self, digest: str) -> int:
        prefix, suffix = digest[:5], digest[5:]
        for name in (prefix, prefix.lower(), f"{prefix}.txt", f"{prefix.lower()}.txt"):
            candidate = os.path.join(self.path, name)
            if os.path.isfile(candidate):
                with open(candidate, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        head, _, count = line.strip().partition(":")
                        if head.upper() == suffix:
                            return int(count) if count.strip().isdigit() else 1
                return 0
        return 0

    def _lookup_binary(self, digest: str) -> int:
        target = bytes.fromhex(digest)
        size = os.path.getsize(self.path)
        low, high = 0, size // 20 - 1
        with open(self.path, "rb") as fh:
            while low <= high:
                mid = (low + high) // 2
                fh.seek(mid * 20)
                value = fh.read(20)
                if value == target:
                    return 1
                if value < target:
                    low = mid + 1
                else:
                    high = mid - 1
        return 0

    def _lookup_text(self, digest: str) -> int:
        """Binary search by byte offset, then a short linear scan.

        Offsets do not land on line boundaries, so the search narrows to a small
        window and then walks it line by line. That avoids the classic
        off-by-one where the first or last record in the file is never compared.
        """
        size = os.path.getsize(self.path)
        low, high = 0, size
        window = 4096
        with open(self.path, "rb") as fh:
            while high - low > window:
                mid = (low + high) // 2
                fh.seek(mid)
                fh.readline()  # discard the partial line
                start = fh.tell()
                if start >= high:
                    break
                line = fh.readline(_LINE_MAX)
                if not line:
                    break
                key = _key_of(line)
                if key == digest:
                    return _count_of(line)
                if key < digest:
                    low = fh.tell()  # always a line boundary
                else:
                    high = start

            fh.seek(low)
            limit = high + _LINE_MAX
            while fh.tell() <= limit:
                line = fh.readline(_LINE_MAX)
                if not line:
                    break
                key = _key_of(line)
                if key == digest:
                    return _count_of(line)
                if key > digest:
                    break
        return 0


def open_dataset(path: str) -> Optional[BreachDataset]:
    """Open a dataset, or return None when the path is empty/missing."""
    if not path:
        return None
    try:
        return BreachDataset(path)
    except (OSError, ValueError):
        return None


def status_for(path: str) -> BreachStatus:
    dataset = open_dataset(path)
    return dataset.status() if dataset else BreachStatus(False)


def _key_of(line: bytes) -> str:
    return line.split(b":")[0].strip().upper().decode("ascii", "ignore")


def _count_of(line: bytes) -> int:
    _, _, count = line.decode("ascii", "ignore").strip().partition(":")
    return int(count) if count.strip().isdigit() else 1
