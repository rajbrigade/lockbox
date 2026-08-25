"""The Lockbox desktop window (Tk, standard library only).

One window, three panes: categories, item list, detail. A modal unlock screen
in front of it. No web view, no browser engine, no bundled runtime, no images.

Timers use Tk's own `after()` rather than threads, so the process has exactly
one thread and sits at zero CPU when idle: the auto-lock tick runs once a
second and does nothing but compare two numbers.
"""

from __future__ import annotations

import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional

from .. import __version__
from ..core import backup as backup_mod
from ..core import breach as breach_mod
from ..core import portio
from ..core.audit import audit as run_audit
from ..core.clipboard import Clipboard, ClipboardUnavailable
from ..core.errors import DecryptError, LockboxError, VaultFormatError
from ..core.model import ITEM_TYPES, TYPE_LABELS, Item
from ..core.search import search as vault_search
from ..core.vault import Vault, default_vault_path
from ..tools.otp import OTPConfig, current as totp_current, parse_otpauth
from . import theme
from .palette import Command, CommandPalette
from .tools_view import ToolsWindow

CATEGORIES = [
    ("all", "All Items", ""),
    ("favorites", "Favorites", "fav:true"),
    ("login", "Logins", "type:login"),
    ("note", "Secure Notes", "type:note"),
    ("card", "Cards", "type:card"),
    ("identity", "Identities", "type:identity"),
    ("api_key", "API Keys", "type:api_key"),
    ("totp", "TOTP", "has:totp"),
]


class LockboxApp(tk.Tk):
    def __init__(self, vault_path: Optional[str] = None):
        super().__init__()
        self.title(f"Lockbox {__version__}")
        self.geometry("1080x680")
        self.minsize(880, 560)
        theme.apply_styles(self)
        self.fonts = theme.fonts()

        self.vault = Vault(vault_path or default_vault_path())
        self.clipboard_helper = Clipboard(tk_widget=self, schedule=self._schedule)
        self.category = tk.StringVar(value="all")
        self.query = tk.StringVar()
        self.status = tk.StringVar(value="Locked")
        self.visible: List[Item] = []
        self.selected: Optional[Item] = None
        self._totp_job = None
        self._unlocking = False
        self._unlock_result = None
        self._progress_step = 0
        self._search_job = None
        self._strength_job = None

        self.unlock_frame = self._build_unlock()
        self.main_frame = self._build_main()
        self._show_unlock()
        self._bind_keys()
        self.protocol("WM_DELETE_WINDOW", self._quit)
        self.after(1000, self._tick)

    # ------------------------------------------------------------- unlock --
    def _build_unlock(self) -> ttk.Frame:
        frame = ttk.Frame(self, padding=40)
        inner = ttk.Frame(frame)
        inner.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Label(inner, text="Lockbox", style="Title.TLabel").pack()
        ttk.Label(inner, text="Offline password manager. No network, ever.",
                  style="Dim.TLabel").pack(pady=(2, 16))

        self.path_var = tk.StringVar(value=self.vault.path)
        path_row = ttk.Frame(inner)
        path_row.pack(fill="x")
        ttk.Entry(path_row, textvariable=self.path_var, width=46).pack(side="left")
        ttk.Button(path_row, text="...", width=3, command=self._choose_vault).pack(
            side="left", padx=(4, 0))

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(inner, textvariable=self.password_var, show="\u2022",
                                        width=52)
        self.password_entry.pack(pady=theme.PAD)
        self.password_entry.bind("<Return>", lambda _e: self._unlock())

        self.unlock_button = ttk.Button(inner, text="Unlock", command=self._unlock)
        self.unlock_button.pack(fill="x")
        self.unlock_message = ttk.Label(inner, text="", style="Dim.TLabel", wraplength=380)
        self.unlock_message.pack(pady=(theme.PAD, 0))
        return frame

    def _choose_vault(self) -> None:
        path = filedialog.askopenfilename(title="Open vault",
                                          filetypes=[("Lockbox vault", "*.lbx"), ("All", "*")])
        if path:
            self.path_var.set(path)

    def _show_unlock(self) -> None:
        self.main_frame.pack_forget()
        self.unlock_frame.pack(fill="both", expand=True)
        self.password_var.set("")
        self.path_var.set(self.vault.path)
        exists = os.path.exists(self.path_var.get())
        self.unlock_button.configure(text="Unlock" if exists else "Create vault")
        self.unlock_message.configure(
            text="" if exists else "No vault at this path. Entering a password creates one. "
                                   "There is no recovery if you forget it."
        )
        self.password_entry.focus_set()

    def _unlock(self) -> None:
        """Start unlocking. The KDF runs on a worker thread.

        Argon2id at 64 MiB takes a noticeable fraction of a second -- longer on
        a slow disk or a frozen build -- and doing it on the UI thread freezes
        the window, which looks like a hang. This is the only thread Lockbox
        ever starts: it lives for one key derivation and then ends. No secret
        crosses a queue; the worker owns the password bytes and hands back the
        unlocked Vault object.
        """
        if self._unlocking:
            return
        password = self.password_var.get().encode("utf-8")
        if not password:
            self.unlock_message.configure(text="Enter a master password.")
            return
        vault = Vault(self.path_var.get())
        if not vault.exists and len(password) < 8:
            self.unlock_message.configure(text="Use at least 8 characters.")
            return

        self._unlocking = True
        self.password_var.set("")
        self.unlock_button.configure(state="disabled")
        self.password_entry.configure(state="disabled")
        self._unlock_result = None
        self._progress_step = 0
        self._animate_unlock()

        def work() -> None:
            try:
                if vault.exists:
                    vault.unlock(password)
                else:
                    vault.create(password)
                self._unlock_result = ("ok", vault)
            except DecryptError:
                self._unlock_result = ("error", "Wrong password, or the vault was modified.")
            except (VaultFormatError, LockboxError, OSError, ValueError) as exc:
                self._unlock_result = ("error", str(exc))
            finally:
                del password

        threading.Thread(target=work, daemon=True, name="lockbox-kdf").start()
        self.after(50, self._poll_unlock)

    def _animate_unlock(self) -> None:
        """A moving ellipsis, so a slow KDF reads as work rather than a hang."""
        if not self._unlocking:
            return
        self._progress_step = (self._progress_step + 1) % 4
        dots = "." * self._progress_step
        self.unlock_message.configure(text=f"Deriving key (deliberately slow){dots}")
        self.after(300, self._animate_unlock)

    def _poll_unlock(self) -> None:
        if self._unlock_result is None:
            self.after(50, self._poll_unlock)
            return
        self._unlocking = False
        self.unlock_button.configure(state="normal")
        self.password_entry.configure(state="normal")
        status, payload = self._unlock_result
        self._unlock_result = None
        if status == "error":
            self.unlock_message.configure(text=payload)
            self.password_entry.focus_set()
            return
        self.vault = payload
        self.clipboard_helper = Clipboard(tk_widget=self, schedule=self._schedule)
        self.unlock_message.configure(text="")
        self._finish_unlock()

    def _finish_unlock(self) -> None:
        self.unlock_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)
        self.refresh()
        self.search_entry.focus_set()
        self._check_backup_reminder()

    # --------------------------------------------------------------- main --
    def _build_main(self) -> ttk.Frame:
        frame = ttk.Frame(self)

        sidebar = ttk.Frame(frame, style="Alt.TFrame", padding=theme.PAD)
        sidebar.pack(side="left", fill="y")
        self.sidebar_list = tk.Listbox(
            sidebar, width=18, height=16, activestyle="none", borderwidth=0,
            background=theme.BG_ALT, foreground=theme.FG,
            selectbackground=theme.ACCENT, selectforeground="#ffffff", font=self.fonts["base"],
        )
        for _key, label, _q in CATEGORIES:
            self.sidebar_list.insert(tk.END, f" {label}")
        self.sidebar_list.selection_set(0)
        self.sidebar_list.pack(fill="y")
        self.sidebar_list.bind("<<ListboxSelect>>", self._category_changed)

        for label, command in (
            ("Security Audit", self.show_audit),
            ("Micro Tools", self.show_tools),
            ("Settings", self.show_settings),
            ("Lock  (Ctrl+L)", self.lock),
        ):
            ttk.Button(sidebar, text=label, command=command).pack(fill="x", pady=(theme.PAD, 0))

        middle = ttk.Frame(frame, padding=theme.PAD)
        middle.pack(side="left", fill="both", expand=True)
        search_row = ttk.Frame(middle)
        search_row.pack(fill="x")
        self.search_entry = ttk.Entry(search_row, textvariable=self.query)
        self.search_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(search_row, text="+ New", command=self.new_item).pack(side="left",
                                                                        padx=(theme.PAD, 0))
        # Debounced: rebuilding the list on every keystroke makes typing feel
        # sticky once the vault is more than a few dozen items.
        self.query.trace_add("write", lambda *_: self._debounce_search())

        columns = ("title", "username", "type")
        self.tree = ttk.Treeview(middle, columns=columns, show="headings", selectmode="browse")
        for column, heading, width in (("title", "Title", 220), ("username", "Username", 180),
                                       ("type", "Type", 90)):
            self.tree.heading(column, text=heading)
            self.tree.column(column, width=width, stretch=(column == "title"))
        self.tree.pack(fill="both", expand=True, pady=(theme.PAD, 0))
        self.tree.bind("<<TreeviewSelect>>", self._selection_changed)
        self.tree.bind("<Delete>", lambda _e: self.delete_item())

        detail = ttk.Frame(frame, padding=theme.PAD, width=380)
        detail.pack(side="left", fill="both")
        detail.pack_propagate(False)
        self.detail = detail
        self._build_detail(detail)

        status_bar = ttk.Frame(self)
        ttk.Label(status_bar, textvariable=self.status, style="Dim.TLabel").pack(side="left")
        ttk.Label(status_bar, text="Ctrl+K commands   Offline: no network calls",
                  style="Dim.TLabel").pack(side="right")
        status_bar.pack(side="bottom", fill="x", padx=theme.PAD, pady=(0, 4))
        return frame

    def _build_detail(self, parent) -> None:
        self.fields: Dict[str, tk.StringVar] = {
            name: tk.StringVar() for name in
            ("title", "username", "password", "url", "folder", "tags", "totp_secret")
        }
        self.type_var = tk.StringVar(value="login")
        self.favorite_var = tk.BooleanVar(value=False)

        ttk.Label(parent, text="Details", style="Title.TLabel").pack(anchor="w")
        form = ttk.Frame(parent)
        form.pack(fill="x", pady=theme.PAD)

        def row(label: str, key: str, secret: bool = False):
            container = ttk.Frame(form)
            container.pack(fill="x", pady=2)
            ttk.Label(container, text=label, width=10, style="Dim.TLabel").pack(side="left")
            entry = ttk.Entry(container, textvariable=self.fields[key],
                              show="\u2022" if secret else "")
            entry.pack(side="left", fill="x", expand=True)
            return entry

        row("Title", "title")
        row("Username", "username")
        self.password_field = row("Password", "password", secret=True)
        password_buttons = ttk.Frame(form)
        password_buttons.pack(fill="x", pady=(2, 6))
        self.reveal_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(password_buttons, text="Show", variable=self.reveal_var,
                        command=self._toggle_reveal).pack(side="left")
        ttk.Button(password_buttons, text="Copy", command=self.copy_password).pack(
            side="left", padx=4)
        ttk.Button(password_buttons, text="Generate", command=self.fill_generated).pack(side="left")
        self.strength_label = ttk.Label(form, text="", style="Dim.TLabel", wraplength=340)
        self.strength_label.pack(anchor="w")
        self.fields["password"].trace_add("write", lambda *_: self._debounce_strength())

        row("URL", "url")
        row("Folder", "folder")
        row("Tags", "tags")
        row("TOTP", "totp_secret", secret=True)

        type_row = ttk.Frame(form)
        type_row.pack(fill="x", pady=4)
        ttk.Label(type_row, text="Type", width=10, style="Dim.TLabel").pack(side="left")
        ttk.Combobox(type_row, textvariable=self.type_var, values=list(ITEM_TYPES),
                     state="readonly", width=12).pack(side="left")
        ttk.Checkbutton(type_row, text="Favorite", variable=self.favorite_var).pack(
            side="left", padx=theme.PAD)

        self.totp_label = ttk.Label(parent, text="", style="Code.TLabel")
        self.totp_label.pack(anchor="w")
        self.totp_progress = ttk.Progressbar(parent, maximum=30, length=200)
        self.totp_progress.pack(anchor="w", pady=(0, theme.PAD))

        ttk.Label(parent, text="Notes", style="Dim.TLabel").pack(anchor="w")
        self.notes = tk.Text(parent, height=6, wrap="word", background=theme.BG_INPUT,
                             foreground=theme.FG, insertbackground=theme.FG, borderwidth=0,
                             font=self.fonts["base"], padx=6, pady=6)
        self.notes.pack(fill="both", expand=True)

        buttons = ttk.Frame(parent)
        buttons.pack(fill="x", pady=theme.PAD)
        ttk.Button(buttons, text="Save  (Ctrl+S)", command=self.save_item).pack(side="left")
        ttk.Button(buttons, text="Delete", command=self.delete_item).pack(side="left",
                                                                          padx=theme.PAD)
        ttk.Button(buttons, text="Copy TOTP", command=self.copy_totp).pack(side="left")

    # ----------------------------------------------------------- bindings --
    def _bind_keys(self) -> None:
        binds = {
            "<Control-k>": lambda _e: self.show_palette(),
            "<Command-k>": lambda _e: self.show_palette(),
            "<Control-l>": lambda _e: self.lock(),
            "<Control-f>": lambda _e: self.search_entry.focus_set(),
            "<Control-n>": lambda _e: self.new_item(),
            "<Control-s>": lambda _e: self.save_item(),
            "<Control-Shift-C>": lambda _e: self.copy_password(),
            "<Control-b>": lambda _e: self.make_backup(),
            "<Control-t>": lambda _e: self.show_tools(),
        }
        for sequence, handler in binds.items():
            self.bind_all(sequence, handler)
        # Escape clears the search box only while the search box has focus,
        # rather than globally stealing the key from every other widget.
        self.search_entry.bind("<Escape>", lambda _e: self.query.set(""))

    def _schedule(self, milliseconds: int, callback) -> None:
        self.after(milliseconds, callback)

    # ------------------------------------------------------------ refresh --
    def refresh(self) -> None:
        self.refresh_list()
        self.status.set(
            f"{len(self.vault.items())} items - {os.path.basename(self.vault.path)} - "
            f"{self.vault.kdf_description()}"
        )

    def _debounce_search(self, delay: int = 120) -> None:
        if self._search_job is not None:
            self.after_cancel(self._search_job)
        self._search_job = self.after(delay, self._run_search)

    def _run_search(self) -> None:
        self._search_job = None
        self.refresh_list()

    def _debounce_strength(self, delay: int = 200) -> None:
        if self._strength_job is not None:
            self.after_cancel(self._strength_job)
        self._strength_job = self.after(delay, self._run_strength)

    def _run_strength(self) -> None:
        self._strength_job = None
        self._update_strength()

    def refresh_list(self) -> None:
        if not self.vault.unlocked:
            return
        index = self.sidebar_list.curselection()
        _key, _label, filter_query = CATEGORIES[index[0] if index else 0]
        query = " ".join(part for part in (filter_query, self.query.get()) if part)
        self.visible = vault_search(self.vault.items(), query)
        self.tree.delete(*self.tree.get_children())
        for item in self.visible:
            marker = "* " if item.favorite else ""
            self.tree.insert("", "end", iid=item.id,
                             values=(marker + item.title, item.username,
                                     TYPE_LABELS.get(item.type, item.type)))
        self.vault.touch_activity()

    def _category_changed(self, _event=None) -> None:
        self.refresh_list()

    def _selection_changed(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        try:
            item = self.vault.get(selection[0])
        except KeyError:
            return
        self.selected = item
        self.fields["title"].set(item.title)
        self.fields["username"].set(item.username)
        self.fields["password"].set(item.password)
        self.fields["url"].set(item.url)
        self.fields["folder"].set(item.folder)
        self.fields["tags"].set(", ".join(item.tags))
        self.fields["totp_secret"].set(item.totp_secret)
        self.type_var.set(item.type)
        self.favorite_var.set(item.favorite)
        self.notes.delete("1.0", tk.END)
        self.notes.insert("1.0", item.notes)
        self.reveal_var.set(False)
        self.password_field.configure(show="\u2022")
        self._update_totp()
        self.vault.touch_activity()

    def _toggle_reveal(self) -> None:
        self.password_field.configure(show="" if self.reveal_var.get() else "\u2022")

    def _update_strength(self) -> None:
        from ..tools.analysis import analyze

        password = self.fields["password"].get()
        if not password:
            self.strength_label.configure(text="")
            return
        result = analyze(password)
        note = f"{result.estimated_bits:.0f} bits - {result.strength}"
        if result.patterns:
            note += f" - {result.patterns[0]}"
        self.strength_label.configure(text=note)

    def _update_totp(self) -> None:
        secret = self.fields["totp_secret"].get().strip()
        if not secret:
            self.totp_label.configure(text="")
            self.totp_progress.configure(value=0)
            return
        try:
            config = OTPConfig(secret=secret, label=self.fields["title"].get() or "Lockbox")
            result = totp_current(config)
        except ValueError as exc:
            self.totp_label.configure(text=f"TOTP: {exc}")
            return
        code = result["code"]
        self.totp_label.configure(text=f"{code[:3]} {code[3:]}")
        self.totp_progress.configure(maximum=result["period"],
                                     value=result["seconds_remaining"])

    # ------------------------------------------------------------ actions --
    def new_item(self) -> None:
        if not self.vault.unlocked:
            return
        item = Item(title="New item", type="login")
        self.vault.add(item)
        self.refresh_list()
        self.tree.selection_set(item.id)
        self.tree.see(item.id)
        self.fields["title"].set("")
        self.detail.focus_set()

    def save_item(self) -> None:
        if not (self.vault.unlocked and self.selected):
            return
        item = self.selected
        item.title = self.fields["title"].get().strip() or "(untitled)"
        item.username = self.fields["username"].get().strip()
        item.url = self.fields["url"].get().strip()
        item.folder = self.fields["folder"].get().strip()
        item.tags = [t.strip() for t in self.fields["tags"].get().split(",") if t.strip()]
        item.type = self.type_var.get()
        item.favorite = bool(self.favorite_var.get())
        item.notes = self.notes.get("1.0", tk.END).rstrip("\n")

        secret = self.fields["totp_secret"].get().strip()
        if secret:
            try:
                item.totp_secret = parse_otpauth(secret).secret
            except ValueError as exc:
                messagebox.showerror("TOTP", f"Not a usable TOTP secret: {exc}")
                return
        else:
            item.totp_secret = ""

        new_password = self.fields["password"].get()
        if new_password != item.password:
            item.set_password(new_password, int(self.vault.settings["history_limit"]))

        try:
            self.vault.update(item)
            self.vault.save()
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        self.refresh()
        self.tree.selection_set(item.id)
        self.status.set(f"Saved {item.title} at {time.strftime('%H:%M:%S')}")

    def delete_item(self) -> None:
        if not (self.vault.unlocked and self.selected):
            return
        if not messagebox.askyesno("Delete", f"Delete {self.selected.title!r}?"):
            return
        self.vault.delete(self.selected.id)
        self.vault.save()
        self.selected = None
        for var in self.fields.values():
            var.set("")
        self.notes.delete("1.0", tk.END)
        self.refresh()

    def fill_generated(self) -> None:
        from ..tools.generators import generate_password

        self.fields["password"].set(generate_password(length=20).value)
        self.reveal_var.set(True)
        self._toggle_reveal()

    def _copy(self, text: str, label: str) -> None:
        if not text:
            return
        seconds = int(self.vault.settings.get("clipboard_clear_seconds", 20)) \
            if self.vault.unlocked else 20
        try:
            self.clipboard_helper.copy(text, clear_after=seconds)
        except ClipboardUnavailable as exc:
            messagebox.showerror("Clipboard", str(exc))
            return
        self.status.set(f"{label} copied - clipboard clears in {seconds}s")

    def copy_password(self) -> None:
        self._copy(self.fields["password"].get(), "Password")

    def copy_totp(self) -> None:
        secret = self.fields["totp_secret"].get().strip()
        if not secret:
            return
        try:
            self._copy(totp_current(OTPConfig(secret=secret))["code"], "TOTP code")
        except ValueError as exc:
            messagebox.showerror("TOTP", str(exc))

    def lock(self) -> None:
        if self.vault.unlocked:
            if self.vault.dirty:
                try:
                    self.vault.save()
                except OSError:
                    pass
            if self.vault.settings.get("clear_clipboard_on_lock", True):
                self.clipboard_helper.clear_if_ours()
            self.vault.lock()
        self.selected = None
        self.visible = []
        for var in self.fields.values():
            var.set("")
        self.notes.delete("1.0", tk.END)
        self.tree.delete(*self.tree.get_children())
        self.status.set("Locked")
        self._show_unlock()

    def make_backup(self) -> None:
        try:
            info = backup_mod.create_backup(
                self.vault.path, keep=int(self.vault.settings.get("backup_keep", 10))
            )
        except (OSError, LockboxError) as exc:
            messagebox.showerror("Backup", str(exc))
            return
        self.vault.meta["last_backup"] = int(time.time())
        try:
            self.vault.save()
        except OSError:
            pass
        messagebox.showinfo("Backup", f"Encrypted backup written to:\n{info.path}")

    def _check_backup_reminder(self) -> None:
        settings = self.vault.settings
        if backup_mod.needs_backup(self.vault.meta.get("last_backup", 0),
                                   int(settings.get("backup_reminder_days", 14))):
            self.status.set("No recent backup - Ctrl+B makes one (stays on this machine)")

    # -------------------------------------------------------------- views --
    def show_tools(self) -> None:
        ToolsWindow(self, lambda text: self._copy(text, "Value"))

    def show_audit(self) -> None:
        if not self.vault.unlocked:
            return
        dataset = breach_mod.open_dataset(self.vault.settings.get("breach_dataset_path", ""))
        report = run_audit(self.vault.items(), self.vault.settings,
                           breach_lookup=dataset.lookup if dataset else None)

        window = tk.Toplevel(self)
        window.title("Security Audit - local only")
        window.geometry("760x560")
        window.configure(bg=theme.BG)
        header = ttk.Frame(window, padding=theme.PAD)
        header.pack(fill="x")
        ttk.Label(header, text=f"Vault health {report.score()}/100",
                  style="Title.TLabel").pack(anchor="w")
        stats = report.stats
        ttk.Label(header, style="Dim.TLabel",
                  text=f"{stats['items']} items - {stats['reused_passwords']} reused "
                       f"password(s) - {stats['with_totp']} with TOTP").pack(anchor="w")
        ttk.Label(header, text=f"Breach: {report.breach_status}", style="Dim.TLabel",
                  wraplength=700).pack(anchor="w", pady=(4, 0))

        tree = ttk.Treeview(window, columns=("severity", "item", "issue"), show="headings")
        for column, heading, width in (("severity", "Severity", 90), ("item", "Item", 190),
                                       ("issue", "Finding", 420)):
            tree.heading(column, text=heading)
            tree.column(column, width=width)
        tree.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)
        for finding in report.findings:
            tree.insert("", "end", values=(finding.severity, finding.title, finding.message),
                        tags=(finding.severity,))
        for severity, color in theme.SEVERITY_COLORS.items():
            tree.tag_configure(severity, foreground=color)
        if not report.findings:
            ttk.Label(window, text="No findings.", style="Dim.TLabel").pack(pady=theme.PAD)
        window.bind("<Escape>", lambda _e: window.destroy())

    def show_settings(self) -> None:
        if not self.vault.unlocked:
            return
        window = tk.Toplevel(self)
        window.title("Settings")
        window.geometry("560x460")
        window.configure(bg=theme.BG)
        frame = ttk.Frame(window, padding=theme.PAD)
        frame.pack(fill="both", expand=True)

        variables: Dict[str, tk.Variable] = {}
        labels = {
            "auto_lock_seconds": "Auto-lock after (seconds, 0 = never)",
            "clipboard_clear_seconds": "Clear clipboard after (seconds)",
            "clear_clipboard_on_lock": "Clear clipboard when locking",
            "password_age_warning_days": "Flag passwords older than (days)",
            "min_password_length": "Minimum password length",
            "backup_reminder_days": "Remind to back up after (days)",
            "backup_keep": "Backups to keep",
            "history_limit": "Password history entries per item",
            "breach_dataset_path": "Local breach dataset (file or directory)",
        }
        for key, label in labels.items():
            value = self.vault.settings.get(key)
            row = ttk.Frame(frame)
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=label, width=34, style="Dim.TLabel").pack(side="left")
            if isinstance(value, bool):
                var: tk.Variable = tk.BooleanVar(value=value)
                ttk.Checkbutton(row, variable=var).pack(side="left")
            else:
                var = tk.StringVar(value=str(value))
                ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True)
            variables[key] = var

        status = breach_mod.status_for(str(self.vault.settings.get("breach_dataset_path", "")))
        ttk.Label(frame, text=status.describe(), style="Dim.TLabel", wraplength=520).pack(
            anchor="w", pady=theme.PAD)

        def save() -> None:
            for key, var in variables.items():
                raw = var.get()
                default = self.vault.settings.get(key)
                try:
                    value = bool(raw) if isinstance(default, bool) else (
                        int(raw) if isinstance(default, int) else str(raw)
                    )
                except (TypeError, ValueError):
                    messagebox.showerror("Settings", f"{key}: {raw!r} is not valid")
                    return
                self.vault.set_setting(key, value)
            self.vault.save()
            window.destroy()

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=theme.PAD)
        ttk.Button(buttons, text="Save", command=save).pack(side="left")
        ttk.Button(buttons, text="Change master password",
                   command=self._change_master_password).pack(side="left", padx=theme.PAD)
        window.bind("<Escape>", lambda _e: window.destroy())

    def _change_master_password(self) -> None:
        from tkinter import simpledialog

        first = simpledialog.askstring("New master password", "New master password:", show="\u2022",
                                       parent=self)
        if not first:
            return
        second = simpledialog.askstring("Confirm", "Repeat it:", show="\u2022", parent=self)
        if first != second:
            messagebox.showerror("Master password", "The two entries did not match.")
            return
        if len(first) < 8:
            messagebox.showerror("Master password", "Use at least 8 characters.")
            return
        self.vault.change_master_password(first.encode("utf-8"))
        messagebox.showinfo("Master password",
                            "Changed. Existing backups still open with the old password.")

    # ------------------------------------------------------- import/export --
    def do_import(self) -> None:
        path = filedialog.askopenfilename(
            title="Import CSV or JSON",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json"), ("All", "*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                result = portio.import_auto(fh.read(), path)
        except OSError as exc:
            messagebox.showerror("Import", str(exc))
            return
        added, duplicates = portio.merge(self.vault.items(), result.items)
        if not added:
            messagebox.showinfo("Import", f"{result.summary()}. Nothing new to add.")
            return
        if not messagebox.askyesno("Import", f"{result.summary()}.\nAdd {len(added)} item(s)?"):
            return
        self.vault.add_many(added)
        self.vault.save()
        self.refresh()
        messagebox.showinfo("Import", f"Added {len(added)}, skipped {duplicates} duplicate(s).")

    def do_export_encrypted(self) -> None:
        path = filedialog.asksaveasfilename(title="Export encrypted vault",
                                            defaultextension=".lbx")
        if not path:
            return
        try:
            if self.vault.dirty:
                self.vault.save()
            result = portio.export_encrypted(self.vault.path, path)
        except (OSError, LockboxError) as exc:
            messagebox.showerror("Export", str(exc))
            return
        messagebox.showinfo("Export", f"Encrypted copy written to:\n{result['path']}")

    def do_export_plaintext(self) -> None:
        if not messagebox.askyesno("Plaintext export", portio.PLAINTEXT_WARNING +
                                   "\n\nContinue?", icon="warning"):
            return
        path = filedialog.asksaveasfilename(title="Export PLAINTEXT CSV", defaultextension=".csv")
        if not path:
            return
        from tkinter import simpledialog

        typed = simpledialog.askstring(
            "Confirm", f"Type {portio.CONFIRM_TOKEN} to write readable secrets to disk:",
            parent=self,
        )
        try:
            result = portio.write_plaintext_export(path, self.vault.items(), "csv",
                                                   confirm=typed or "")
        except (PermissionError, OSError, ValueError) as exc:
            messagebox.showerror("Export", str(exc))
            return
        messagebox.showwarning(
            "Plaintext export",
            f"{result['items']} item(s) written in the clear to:\n{result['path']}\n\n"
            "Delete it as soon as you are done.",
        )

    def do_restore(self) -> None:
        path = filedialog.askopenfilename(title="Restore backup",
                                          filetypes=[("Lockbox vault", "*.lbx")])
        if not path:
            return
        from tkinter import simpledialog

        password = simpledialog.askstring("Restore", "Master password for that backup:",
                                          show="\u2022", parent=self)
        if not password:
            return
        try:
            result = backup_mod.restore_backup(path, self.vault.path, password.encode("utf-8"))
        except (DecryptError, VaultFormatError, OSError) as exc:
            messagebox.showerror("Restore", f"Nothing was changed.\n\n{exc}")
            return
        messagebox.showinfo("Restore", f"Restored {result['items']} item(s). Unlock again.")
        self.lock()

    def run_integrity_check(self) -> None:
        report = self.vault.integrity_check()
        lines = [f"[{'ok' if c['ok'] else 'FAIL'}] {c['name']}" for c in report["checks"]]
        lines.append(f"\nFile: {report['file_size']} bytes, mode {report['permissions']}")
        (messagebox.showinfo if report["ok"] else messagebox.showerror)(
            "Vault integrity", "\n".join(lines)
        )

    # ------------------------------------------------------------- palette --
    def show_palette(self) -> None:
        commands = [
            Command("search", "Search vault", "Ctrl+F", lambda: self.search_entry.focus_set()),
            Command("new_login", "Create login", "Ctrl+N", lambda: self._new_typed("login")),
            Command("new_note", "Create secure note", "", lambda: self._new_typed("note")),
            Command("new_key", "Create API key", "", lambda: self._new_typed("api_key")),
            Command("new_card", "Create card", "", lambda: self._new_typed("card")),
            Command("gen_password", "Generate password", "", self.fill_generated),
            Command("gen_passphrase", "Generate passphrase", "", self._fill_passphrase),
            Command("totp", "Copy TOTP code", "", self.copy_totp),
            Command("tools", "Open Micro Tools", "Ctrl+T", self.show_tools),
            Command("audit", "Run security audit", "", self.show_audit),
            Command("integrity", "Check vault integrity", "", self.run_integrity_check),
            Command("backup", "Create encrypted backup", "Ctrl+B", self.make_backup),
            Command("restore", "Restore from backup", "", self.do_restore),
            Command("import", "Import CSV or JSON", "", self.do_import),
            Command("export_enc", "Export encrypted vault", "", self.do_export_encrypted),
            Command("export_plain", "Export plaintext (dangerous)", "",
                    self.do_export_plaintext),
            Command("settings", "Open settings", "", self.show_settings),
            Command("clipboard", "Clear clipboard now", "",
                    lambda: self.clipboard_helper.clear()),
            Command("lock", "Lock vault", "Ctrl+L", self.lock),
        ]
        CommandPalette(self, commands)

    def _new_typed(self, item_type: str) -> None:
        self.new_item()
        self.type_var.set(item_type)

    def _fill_passphrase(self) -> None:
        from ..tools.generators import generate_passphrase

        self.fields["password"].set(generate_passphrase(words=6, capitalize=True).value)

    # ---------------------------------------------------------------- tick --
    def _tick(self) -> None:
        """Once a second: auto-lock check and TOTP countdown. Nothing else."""
        try:
            if self.vault.unlocked:
                if self.vault.check_autolock():
                    self.clipboard_helper.clear_if_ours()
                    self.lock()
                    self.unlock_message.configure(text="Vault locked automatically after idle.")
                elif self.fields["totp_secret"].get().strip():
                    self._update_totp()
        finally:
            self.after(1000, self._tick)

    def _quit(self) -> None:
        if self.vault.unlocked:
            if self.vault.dirty:
                try:
                    self.vault.save()
                except OSError:
                    pass
            self.clipboard_helper.clear_if_ours()
            self.vault.lock()
        self.destroy()


def main(vault_path: Optional[str] = None) -> int:
    app = LockboxApp(vault_path)
    app.mainloop()
    return 0
