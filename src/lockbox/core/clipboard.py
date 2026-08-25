"""Clipboard access and timed clearing.

The clipboard is the weakest link in any password manager: it is a global,
unauthenticated buffer that every process on the machine can read. Lockbox
therefore (a) clears it after a configurable delay, (b) only clears it if the
contents are still what Lockbox put there, so it never destroys something you
copied afterwards, and (c) never writes secrets to a temporary file to get them
there.

Backends, in order of preference:
  1. Tk (already loaded by the GUI, no extra process)
  2. the platform clipboard command (pbcopy / wl-copy / xclip / xsel / clip)

All of these are local IPC. None of them is a network operation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from typing import Callable, List, Optional


class ClipboardUnavailable(RuntimeError):
    pass


def _hidden() -> dict:
    """subprocess kwargs that stop Windows flashing a console window.

    A GUI process on Windows has no console, so launching a console program
    (clip.exe, powershell.exe) makes Windows create one and show it. It appears
    for a fraction of a second and looks alarming in a password manager.
    CREATE_NO_WINDOW plus a hidden STARTUPINFO suppresses it. On other
    platforms this is an empty dict.
    """
    if sys.platform != "win32":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {
        "startupinfo": startupinfo,
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
    }


def _commands() -> List[List[str]]:
    if sys.platform == "darwin":
        return [["pbcopy"]]
    if sys.platform == "win32":
        return [["clip"]]
    out = []
    if os.environ.get("WAYLAND_DISPLAY"):
        out.append(["wl-copy"])
    out.extend([["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]])
    return out


def _paste_commands() -> List[List[str]]:
    if sys.platform == "darwin":
        return [["pbpaste"]]
    if sys.platform == "win32":
        # Launching PowerShell costs the better part of a second, so this is a
        # last resort only: the Tk backend is tried first and normally wins.
        return [["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-Clipboard"]]
    out = []
    if os.environ.get("WAYLAND_DISPLAY"):
        out.append(["wl-paste", "--no-newline"])
    out.extend([["xclip", "-selection", "clipboard", "-o"], ["xsel", "--clipboard", "--output"]])
    return out


class Clipboard:
    """A clipboard with an owner-checked, scheduled clear.

    `schedule` is injected by the UI (Tk's `after`) so that no background thread
    is created. In headless use the caller may pass None and clear manually.
    """

    def __init__(self, tk_widget=None, schedule: Optional[Callable] = None):
        self._tk = tk_widget
        self._schedule = schedule
        self._last_copied: Optional[str] = None
        self._last_copy_time: float = 0.0

    # -- backends -------------------------------------------------------
    def _copy_tk(self, text: str) -> bool:
        if self._tk is None:
            return False
        try:
            self._tk.clipboard_clear()
            self._tk.clipboard_append(text)
            self._tk.update_idletasks()
            return True
        except Exception:
            return False

    def _copy_command(self, text: str) -> bool:
        for cmd in _commands():
            if not shutil.which(cmd[0]):
                continue
            try:
                proc = subprocess.run(
                    cmd, input=text.encode("utf-8"), check=True, timeout=5,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    **_hidden(),
                )
                return proc.returncode == 0
            except (OSError, subprocess.SubprocessError):
                continue
        return False

    def paste(self) -> Optional[str]:
        if self._tk is not None:
            try:
                return self._tk.clipboard_get()
            except Exception:
                pass
        for cmd in _paste_commands():
            if not shutil.which(cmd[0]):
                continue
            try:
                out = subprocess.run(
                    cmd, capture_output=True, timeout=5, check=False, **_hidden()
                )
                if out.returncode == 0:
                    return out.stdout.decode("utf-8", errors="replace")
            except (OSError, subprocess.SubprocessError):
                continue
        return None

    # -- api ------------------------------------------------------------
    def copy(self, text: str, clear_after: int = 20) -> bool:
        """Copy `text`, scheduling a clear in `clear_after` seconds (0 = never)."""
        if not (self._copy_tk(text) or self._copy_command(text)):
            raise ClipboardUnavailable(
                "No clipboard backend found. On Linux install wl-clipboard, "
                "xclip or xsel."
            )
        self._last_copied = text
        self._last_copy_time = time.monotonic()
        if clear_after and self._schedule:
            self._schedule(clear_after * 1000, self.clear_if_ours)
        return True

    def clear_if_ours(self) -> bool:
        """Clear only if the clipboard still holds what we put there."""
        if self._last_copied is None:
            return False
        current = self.paste()
        if current is not None and current.strip() != self._last_copied.strip():
            self._last_copied = None
            return False  # the user copied something else; leave it alone
        return self.clear()

    def clear(self) -> bool:
        self._last_copied = None
        # Overwrite with a space first: some clipboard managers keep the last
        # non-empty entry, and an empty write can be a no-op on X11.
        ok = self._copy_tk(" ") or self._copy_command(" ")
        ok = (self._copy_tk("") or self._copy_command("")) or ok
        return ok

    def seconds_since_copy(self) -> Optional[float]:
        if self._last_copied is None:
            return None
        return time.monotonic() - self._last_copy_time
