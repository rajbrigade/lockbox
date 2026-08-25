"""The Micro Tools window.

Two tiers, on purpose:

* the generators people use constantly (password, passphrase, TOTP) get real
  controls;
* everything else gets a generic runner -- a keyword argument box and an output
  pane -- so that adding a tool to the registry makes it usable immediately
  without hand-writing a form for it.

Tools are imported on first use by the registry, so opening this window does not
load code for tools you never touch.
"""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Dict, Optional

from .. import tools as tool_registry
from . import theme


class ToolsWindow(tk.Toplevel):
    def __init__(self, parent, copy_fn: Callable[[str], None]):
        super().__init__(parent)
        self.copy_fn = copy_fn
        self.title("Micro Tools - all local")
        self.geometry("880x560")
        self.configure(bg=theme.BG)
        self.fonts = theme.fonts()

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)
        notebook.add(self._password_tab(notebook), text="Password")
        notebook.add(self._passphrase_tab(notebook), text="Passphrase")
        notebook.add(self._analyzer_tab(notebook), text="Analyzer")
        notebook.add(self._generic_tab(notebook), text="All tools")

        ttk.Label(
            self,
            text="Every tool here runs on this machine. No tool makes a network request.",
            style="Dim.TLabel",
        ).pack(anchor="w", padx=theme.PAD, pady=(0, theme.PAD))
        self.bind("<Escape>", lambda _e: self.destroy())

    # ------------------------------------------------------------ helpers --
    def _output_box(self, parent, height: int = 12) -> tk.Text:
        box = tk.Text(
            parent, height=height, wrap="word", background=theme.BG_ALT,
            foreground=theme.FG, insertbackground=theme.FG, borderwidth=0,
            font=self.fonts["mono"], padx=8, pady=8,
        )
        box.pack(fill="both", expand=True, pady=(theme.PAD, 0))
        return box

    @staticmethod
    def _set(box: tk.Text, text: str) -> None:
        box.configure(state="normal")
        box.delete("1.0", tk.END)
        box.insert("1.0", text)

    # ----------------------------------------------------------- password --
    def _password_tab(self, parent) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=theme.PAD)
        state = {
            "length": tk.IntVar(value=20),
            "upper": tk.BooleanVar(value=True),
            "digits": tk.BooleanVar(value=True),
            "symbols": tk.BooleanVar(value=True),
            "ambiguous": tk.BooleanVar(value=False),
            "exclude": tk.StringVar(value=""),
        }
        row = ttk.Frame(frame)
        row.pack(fill="x")
        ttk.Label(row, text="Length").pack(side="left")
        ttk.Scale(row, from_=8, to=64, variable=state["length"], orient="horizontal",
                  length=200, command=lambda _v: length_label.configure(
                      text=str(state["length"].get()))).pack(side="left", padx=theme.PAD)
        length_label = ttk.Label(row, text="20", style="Mono.TLabel")
        length_label.pack(side="left")

        options = ttk.Frame(frame)
        options.pack(fill="x", pady=theme.PAD)
        for text, key in (("A-Z", "upper"), ("0-9", "digits"), ("symbols", "symbols"),
                          ("exclude look-alikes", "ambiguous")):
            ttk.Checkbutton(options, text=text, variable=state[key]).pack(side="left", padx=4)

        exclude_row = ttk.Frame(frame)
        exclude_row.pack(fill="x")
        ttk.Label(exclude_row, text="Exclude characters").pack(side="left")
        ttk.Entry(exclude_row, textvariable=state["exclude"], width=24).pack(side="left",
                                                                            padx=theme.PAD)
        value = tk.StringVar(value="")
        display = ttk.Label(frame, textvariable=value, style="Code.TLabel", wraplength=780)
        display.pack(anchor="w", pady=theme.PAD)
        detail = ttk.Label(frame, text="", style="Dim.TLabel")
        detail.pack(anchor="w")

        def generate() -> None:
            try:
                result = tool_registry.run(
                    "password",
                    length=int(state["length"].get()),
                    uppercase=state["upper"].get(),
                    digits=state["digits"].get(),
                    symbols=state["symbols"].get(),
                    exclude=state["exclude"].get(),
                    exclude_ambiguous=state["ambiguous"].get(),
                )
            except Exception as exc:
                value.set("")
                detail.configure(text=f"{exc}")
                return
            value.set(result.value)
            from ..tools.analysis import strength_label

            detail.configure(
                text=f"{result.entropy_bits:.1f} bits "
                     f"({strength_label(result.entropy_bits)}), "
                     f"alphabet of {result.alphabet_size}"
            )

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=theme.PAD)
        ttk.Button(buttons, text="Generate  (Ctrl+R)", command=generate).pack(side="left")
        ttk.Button(buttons, text="Copy", command=lambda: self.copy_fn(value.get())).pack(
            side="left", padx=theme.PAD)
        # bind on this window, not bind_all: a tools window must not
        # capture a shortcut from the main window behind it.
        self.bind("<Control-r>", lambda _e: generate())
        generate()
        return frame

    # --------------------------------------------------------- passphrase --
    def _passphrase_tab(self, parent) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=theme.PAD)
        words = tk.IntVar(value=6)
        separator = tk.StringVar(value="-")
        capitalize = tk.BooleanVar(value=True)
        number = tk.BooleanVar(value=False)

        row = ttk.Frame(frame)
        row.pack(fill="x")
        ttk.Label(row, text="Words").pack(side="left")
        ttk.Spinbox(row, from_=3, to=16, textvariable=words, width=5).pack(side="left",
                                                                          padx=theme.PAD)
        ttk.Label(row, text="Separator").pack(side="left")
        ttk.Entry(row, textvariable=separator, width=4).pack(side="left", padx=theme.PAD)
        ttk.Checkbutton(row, text="Capitalise", variable=capitalize).pack(side="left")
        ttk.Checkbutton(row, text="Add number", variable=number).pack(side="left", padx=theme.PAD)

        value = tk.StringVar()
        ttk.Label(frame, textvariable=value, style="Code.TLabel", wraplength=780).pack(
            anchor="w", pady=theme.PAD)
        detail = ttk.Label(frame, text="", style="Dim.TLabel")
        detail.pack(anchor="w")

        def generate() -> None:
            result = tool_registry.run(
                "passphrase", words=int(words.get()), separator=separator.get() or "-",
                capitalize=capitalize.get(), add_number=number.get(),
            )
            value.set(result.value)
            detail.configure(text=f"{result.entropy_bits:.1f} bits - {result.note}")

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=theme.PAD)
        ttk.Button(buttons, text="Generate", command=generate).pack(side="left")
        ttk.Button(buttons, text="Copy", command=lambda: self.copy_fn(value.get())).pack(
            side="left", padx=theme.PAD)
        generate()
        return frame

    # ----------------------------------------------------------- analyzer --
    def _analyzer_tab(self, parent) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=theme.PAD)
        entry_var = tk.StringVar()
        row = ttk.Frame(frame)
        row.pack(fill="x")
        ttk.Label(row, text="Password").pack(side="left")
        entry = ttk.Entry(row, textvariable=entry_var, width=48, show="\u2022")
        entry.pack(side="left", padx=theme.PAD)
        show = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            row, text="Show", variable=show,
            command=lambda: entry.configure(show="" if show.get() else "\u2022"),
        ).pack(side="left")

        output = self._output_box(frame)

        def analyse(*_args) -> None:
            text = entry_var.get()
            if not text:
                self._set(output, "Type a password. It is analysed in this process only.")
                return
            result = tool_registry.run("strength", text).to_dict()
            lines = [
                f"length            {result['length']}",
                f"alphabet          {result['charset_size']} symbols",
                f"entropy (random)  {result['charset_bits']} bits",
                f"entropy (est.)    {result['estimated_bits']} bits  -> {result['strength']}",
                "",
                "patterns found:",
            ]
            lines += [f"  - {p}" for p in result["patterns"]] or ["  (none)"]
            lines += ["", "time to guess:"]
            lines += [f"  {k:<28} {v}" for k, v in result["crack_times"].items()]
            if result["suggestions"]:
                lines += ["", "suggestions:"] + [f"  - {s}" for s in result["suggestions"]]
            self._set(output, "\n".join(lines))

        entry_var.trace_add("write", analyse)
        analyse()
        return frame

    # ------------------------------------------------------------ generic --
    def _generic_tab(self, parent) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=theme.PAD)
        left = ttk.Frame(frame)
        left.pack(side="left", fill="y")
        right = ttk.Frame(frame)
        right.pack(side="left", fill="both", expand=True, padx=(theme.PAD, 0))

        listbox = tk.Listbox(
            left, width=26, height=22, activestyle="none", borderwidth=0,
            background=theme.BG_ALT, foreground=theme.FG,
            selectbackground=theme.ACCENT, selectforeground="#ffffff",
            font=self.fonts["base"],
        )
        listbox.pack(fill="y", expand=True)
        ids: list[str] = []
        for category, tools in tool_registry.by_category().items():
            listbox.insert(tk.END, f"-- {category} --")
            ids.append("")
            for tool in tools:
                listbox.insert(tk.END, f"  {tool.name}")
                ids.append(tool.id)

        summary = ttk.Label(right, text="Pick a tool", style="Dim.TLabel", wraplength=520)
        summary.pack(anchor="w")
        args_var = tk.StringVar()
        args_row = ttk.Frame(right)
        args_row.pack(fill="x", pady=theme.PAD)
        ttk.Label(args_row, text="Arguments").pack(side="left")
        ttk.Entry(args_row, textvariable=args_var).pack(side="left", fill="x", expand=True,
                                                        padx=theme.PAD)
        output = self._output_box(right, height=16)
        current: Dict[str, Optional[str]] = {"id": None}

        def select(_event=None) -> None:
            selection = listbox.curselection()
            if not selection:
                return
            tool_id = ids[selection[0]]
            if not tool_id:
                return
            tool = tool_registry.get(tool_id)
            current["id"] = tool_id
            summary.configure(text=f"{tool.name} - {tool.summary}")
            args_var.set(_example_args(tool_id))

        def run() -> None:
            if not current["id"]:
                return
            try:
                kwargs = _parse_args(args_var.get())
                result = tool_registry.run(current["id"], **kwargs)
            except Exception as exc:
                self._set(output, f"{type(exc).__name__}: {exc}")
                return
            self._set(output, _render(result))

        listbox.bind("<<ListboxSelect>>", select)
        buttons = ttk.Frame(right)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Run", command=run).pack(side="left")
        ttk.Button(buttons, text="Copy output",
                   command=lambda: self.copy_fn(output.get("1.0", tk.END).strip())).pack(
                       side="left", padx=theme.PAD)
        return frame


def _parse_args(text: str) -> Dict[str, Any]:
    """Parse `key=value key2=value2`, or a single positional value."""
    text = (text or "").strip()
    if not text:
        return {}
    if "=" not in text:
        return {"text": text}
    out: Dict[str, Any] = {}
    for token in text.split():
        key, _, value = token.partition("=")
        lowered = value.lower()
        if lowered in ("true", "false"):
            out[key] = lowered == "true"
        else:
            try:
                out[key] = int(value)
            except ValueError:
                out[key] = value
    return out


def _example_args(tool_id: str) -> str:
    examples = {
        "hash": "text=hello algorithm=sha256",
        "hmac": "key=k text=hello",
        "base64_encode": "text=hello",
        "base64_decode": "text=aGVsbG8=",
        "regex": "pattern=\\d+ text=abc123",
        "json_format": "text={\"a\":1}",
        "totp": "",
        "uuid": "version=4",
        "random_number": "low=1 high=100 count=5",
        "entropy": "alphabet_size=95 length=16",
        "api_key": "prefix=lk_ nbytes=32",
        "recovery_codes": "count=10",
        "url_inspect": "url=https://example.com/a?b=1",
        "transform": "text=Hello World operation=snake_case",
        "characters": "text=hello",
        "qr_text": "",
    }
    return examples.get(tool_id, "")


def _render(result: Any) -> str:
    if hasattr(result, "to_dict"):
        result = result.to_dict()
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, indent=2, default=str, ensure_ascii=False)
    except TypeError:
        return str(result)
