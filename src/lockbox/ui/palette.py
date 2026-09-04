"""Ctrl/Cmd+K command palette.

A single modal Toplevel with a filter box and a list. Commands are supplied by
the main window as (id, label, hint, callback) tuples; the palette knows nothing
about the vault. Everything it runs is a local function call.

Focus is the fiddly part. A frameless window (`overrideredirect`) is never
given the keyboard by the window manager, so combining it with `grab_set()`
produced a palette that blocked the main window *and* received nothing itself:
the user could not type until they alt-tabbed away and back. The window is
therefore kept frameless but takes the keyboard explicitly, and the grab is
only ever set once the window is actually viewable -- and released on every
exit path, including an exception during setup.
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
        self.parent = parent
        self.commands = list(commands)
        self.filtered: List[Command] = list(self.commands)
        self._closing = False

        self.withdraw()
        self.transient(parent)
        self.title("Commands")
        self.configure(bg=theme.RULE)
        self._frameless = False
        self._set_frameless(True)

        fonts = theme.fonts()
        # 1px of the toplevel's own background shows through as a hairline
        # border, which a frameless window has no other way to get.
        container = ttk.Frame(self, style="Alt.TFrame", padding=theme.PAD_MD)
        container.pack(fill="both", expand=True, padx=1, pady=1)

        prompt = ttk.Frame(container, style="Alt.TFrame")
        prompt.pack(fill="x")
        ttk.Label(prompt, text="\u203a", style="Brand.TLabel").pack(
            side="left", padx=(0, theme.PAD_SM))
        self.query = tk.StringVar()
        self.entry = ttk.Entry(prompt, textvariable=self.query, font=fonts["mono"])
        self.entry.pack(side="left", fill="x", expand=True)

        self.listbox = tk.Listbox(
            container, height=10, activestyle="none", borderwidth=0,
            highlightthickness=0, background=theme.BG_ALT, foreground=theme.FG_DIM,
            selectbackground=theme.ACCENT, selectforeground="#ffffff",
            font=fonts["mono"],
        )
        self.listbox.pack(fill="both", expand=True, pady=(theme.PAD_MD, 0))
        ttk.Label(container, text="enter run   esc close   arrows move",
                  style="CaptionAlt.TLabel").pack(anchor="w", pady=(theme.PAD_SM, 0))

        self.query.trace_add("write", lambda *_: self._refresh())
        for sequence in ("<Return>", "<KP_Enter>"):
            self.bind(sequence, self._run)
        self.bind("<Escape>", lambda _event: self.close())
        self.bind("<Down>", lambda _event: self._move(1))
        self.bind("<Up>", lambda _event: self._move(-1))
        self.listbox.bind("<Double-Button-1>", self._run)
        # Clicking the window underneath dismisses, the way a menu would.
        self.bind("<FocusOut>", self._maybe_close)
        # Keep the funcid: `unbind(sequence)` with no id drops *every* handler
        # on that sequence, including ones the main window installed itself.
        self._click_binding = parent.bind("<Button-1>", self._click_outside, add="+")

        self._refresh()
        self._place(parent)
        self.deiconify()
        self.lift()
        self._take_focus()

    # -- focus / grab ---------------------------------------------------
    def _set_frameless(self, frameless: bool) -> None:
        try:
            self.overrideredirect(frameless)
            self._frameless = frameless
        except Exception:
            self._frameless = False

    def _has_focus(self) -> bool:
        try:
            focused = self.focus_displayof()
        except tk.TclError:
            return False
        return focused is not None and str(focused).startswith(str(self))

    def _focus_watchdog(self) -> None:
        """Fall back to a decorated window if the frameless one never focuses.

        On Windows an override-redirect toplevel is not eligible for the
        keyboard at all, so the palette would sit there holding a grab while
        every keystroke went nowhere -- the user could not type until they
        alt-tabbed away and back. If the window still does not own the focus a
        beat after mapping, drop the frameless flag and re-map it: a titlebar
        is a far smaller cost than an unusable window.
        """
        if self._closing or not self.winfo_exists() or self._has_focus():
            return
        if self._frameless:
            try:
                self.grab_release()
                self._set_frameless(False)
                self.deiconify()
                self.lift()
                self.focus_force()
                self.entry.focus_set()
                self.grab_set()
            except tk.TclError:
                self.close()
                return
            self.after(250, self._focus_watchdog)
            return
        # Already decorated and still not focused: the grab is the only thing
        # that can now block input, so give it up rather than trap the user.
        try:
            self.grab_release()
            self.focus_force()
            self.entry.focus_set()
        except tk.TclError:
            self.close()

    def _take_focus(self) -> None:
        """Claim the keyboard, then grab -- in that order, and never blindly.

        `grab_set` on a window that is not yet viewable raises TclError, and a
        grab held by a window that cannot receive keystrokes locks the whole
        application out of input. If anything here fails, the palette closes
        rather than leaving the main window unusable.
        """
        try:
            self.wait_visibility()
        except tk.TclError:
            self.close()
            return
        try:
            self.focus_force()
            self.entry.focus_set()
            self.grab_set()
        except tk.TclError:
            self.close()
            return
        # Some window managers hand focus back to the parent immediately after
        # an override-redirect window maps; re-assert once the queue drains,
        # then check that it actually stuck.
        self.after_idle(self._reassert_focus)
        self.after(250, self._focus_watchdog)

    def _reassert_focus(self) -> None:
        if self._closing or not self.winfo_exists():
            return
        try:
            self.focus_force()
            self.entry.focus_set()
        except tk.TclError:
            pass

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        try:
            self.grab_release()
        except tk.TclError:
            pass
        if getattr(self, "_click_binding", None):
            try:
                self.parent.unbind("<Button-1>", self._click_binding)
            except tk.TclError:
                pass
            self._click_binding = None
        try:
            self.parent.focus_force()
        except tk.TclError:
            pass
        self.destroy()

    def destroy(self) -> None:  # closing by any other route must free the grab
        self._closing = True
        try:
            self.grab_release()
        except tk.TclError:
            pass
        super().destroy()

    def _click_outside(self, event) -> None:
        if not self.winfo_exists():
            return
        widget = getattr(event, "widget", None)
        if widget is not None and str(widget).startswith(str(self)):
            return
        self.close()

    def _maybe_close(self, _event=None) -> None:
        if self._closing:
            return
        if self.focus_get() is None:
            self.close()

    # -- layout ---------------------------------------------------------
    def _place(self, parent) -> None:
        self.update_idletasks()
        width = max(520, int(parent.winfo_width() * 0.5))
        height = self.winfo_reqheight()
        x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
        y = parent.winfo_rooty() + 80
        self.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")

    # -- contents -------------------------------------------------------
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
            self.listbox.insert(tk.END, f" {command.label}{suffix}")
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
        self.close()
        command.callback()
