"""Ctrl/Cmd+K command palette.

A single modal Toplevel with a filter box and a list. Commands are supplied by
the main window as (id, label, hint, callback) tuples; the palette knows nothing
about the vault. Everything it runs is a local function call.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, NamedTuple, Sequence

from . import theme


class Command(NamedTuple):
    id: str
    label: str
    hint: str
    callback: Callable[[], None]


def _score(needle: str, command: Command) -> int:
    """Cheap ranking: prefix > word start > substring > subsequence."""
    if not needle:
        return 1
    label = command.label.lower()
    hint = f"{command.id} {command.hint}".lower()
    if label.startswith(needle):
        return 1000
    position = label.find(needle)
    if position > 0:
        return 800 if label[position - 1] == " " else 600
    if needle in hint:
        return 400
    index = 0
    for char in label:
        if char == needle[index]:
            index += 1
            if index == len(needle):
                return 200
    return 0


class CommandPalette(tk.Toplevel):
    def __init__(self, parent, commands: Sequence[Command]):
        super().__init__(parent)
        self.commands = list(commands)
        self.filtered: List[Command] = list(self.commands)

        self.withdraw()
        self.transient(parent)
        self.title("Commands")
        self.configure(bg=theme.BG_ALT)
        try:
            self.overrideredirect(True)  # frameless; Esc closes
        except Exception:
            pass

        fonts = theme.fonts()
        container = ttk.Frame(self, style="Alt.TFrame", padding=theme.PAD)
        container.pack(fill="both", expand=True)

        self.query = tk.StringVar()
        entry = ttk.Entry(container, textvariable=self.query, font=fonts["base"])
        entry.pack(fill="x")
        entry.focus_set()

        self.listbox = tk.Listbox(
            container, height=10, activestyle="none", borderwidth=0,
            background=theme.BG_ALT, foreground=theme.FG,
            selectbackground=theme.ACCENT, selectforeground="#ffffff", font=fonts["base"],
        )
        self.listbox.pack(fill="both", expand=True, pady=(theme.PAD, 0))
        ttk.Label(container, text="Enter run   Esc close   arrows move",
                  style="Dim.TLabel").pack(anchor="w", pady=(4, 0))

        self.query.trace_add("write", lambda *_: self._refresh())
        for sequence in ("<Return>", "<KP_Enter>"):
            self.bind(sequence, self._run)
        self.bind("<Escape>", lambda _event: self.destroy())
        self.bind("<Down>", lambda _event: self._move(1))
        self.bind("<Up>", lambda _event: self._move(-1))
        self.listbox.bind("<Double-Button-1>", self._run)
        self.bind("<FocusOut>", self._maybe_close)

        self._refresh()
        self._place(parent)
        self.deiconify()
        self.grab_set()

    def _place(self, parent) -> None:
        self.update_idletasks()
        width = max(520, int(parent.winfo_width() * 0.5))
        height = self.winfo_reqheight()
        x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
        y = parent.winfo_rooty() + 80
        self.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")

    def _maybe_close(self, _event=None) -> None:
        if self.focus_get() is None:
            self.destroy()

    def _refresh(self) -> None:
        needle = self.query.get().strip().lower()
        ranked = sorted(
            ((_score(needle, c), c) for c in self.commands),
            key=lambda pair: (-pair[0], pair[1].label),
        )
        self.filtered = [c for score, c in ranked if score > 0]
        self.listbox.delete(0, tk.END)
        for command in self.filtered:
            suffix = f"   {command.hint}" if command.hint else ""
            self.listbox.insert(tk.END, f"{command.label}{suffix}")
        if self.filtered:
            self.listbox.selection_set(0)

    def _move(self, delta: int) -> None:
        if not self.filtered:
            return
        current = self.listbox.curselection()
        index = (current[0] if current else 0) + delta
        index = max(0, min(len(self.filtered) - 1, index))
        self.listbox.selection_clear(0, tk.END)
        self.listbox.selection_set(index)
        self.listbox.see(index)

    def _run(self, _event=None) -> None:
        selection = self.listbox.curselection()
        if not selection or not self.filtered:
            return
        command = self.filtered[selection[0]]
        self.destroy()
        command.callback()
