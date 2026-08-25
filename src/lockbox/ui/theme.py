"""Visual constants for the Tk interface.

Deliberately plain: system fonts, flat colours, no images, no animation. Nothing
here loads a font, an icon or a stylesheet from disk or from anywhere else, so
the UI cannot become a network dependency by accident.
"""

from __future__ import annotations

import sys

BG = "#1c1f24"
BG_ALT = "#23272e"
BG_INPUT = "#2b3038"
FG = "#e6e8eb"
FG_DIM = "#9aa3ad"
ACCENT = "#4c8dff"
OK = "#3fb950"
WARN = "#d29922"
CRIT = "#f85149"

SEVERITY_COLORS = {
    "critical": CRIT,
    "high": "#ff7b72",
    "medium": WARN,
    "low": FG_DIM,
    "info": FG_DIM,
}

PAD = 8


def fonts():
    """Pick a readable system font per platform; no bundled font files."""
    if sys.platform == "darwin":
        family, mono = "SF Pro Text", "SF Mono"
    elif sys.platform == "win32":
        family, mono = "Segoe UI", "Consolas"
    else:
        family, mono = "DejaVu Sans", "DejaVu Sans Mono"
    return {
        "base": (family, 10),
        "bold": (family, 10, "bold"),
        "title": (family, 13, "bold"),
        "small": (family, 9),
        "mono": (mono, 10),
        "mono_big": (mono, 16),
    }


def apply_styles(root) -> None:
    from tkinter import ttk

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    f = fonts()
    root.configure(bg=BG)
    style.configure(".", background=BG, foreground=FG, font=f["base"])
    style.configure("TFrame", background=BG)
    style.configure("Alt.TFrame", background=BG_ALT)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Dim.TLabel", background=BG, foreground=FG_DIM, font=f["small"])
    style.configure("Title.TLabel", background=BG, foreground=FG, font=f["title"])
    style.configure("Mono.TLabel", background=BG, foreground=FG, font=f["mono"])
    style.configure("Code.TLabel", background=BG, foreground=ACCENT, font=f["mono_big"])
    style.configure("TButton", background=BG_INPUT, foreground=FG, borderwidth=0, padding=6)
    style.map("TButton", background=[("active", ACCENT)], foreground=[("active", "#ffffff")])
    style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG, insertcolor=FG,
                    borderwidth=0, padding=4)
    style.configure("TCombobox", fieldbackground=BG_INPUT, foreground=FG, borderwidth=0)
    style.configure("Treeview", background=BG_ALT, fieldbackground=BG_ALT, foreground=FG,
                    borderwidth=0, rowheight=24)
    style.configure("Treeview.Heading", background=BG, foreground=FG_DIM, borderwidth=0,
                    font=f["small"])
    style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#ffffff")])
    style.configure("TCheckbutton", background=BG, foreground=FG)
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=BG_ALT, foreground=FG_DIM, padding=(12, 6))
    style.map("TNotebook.Tab", background=[("selected", BG)], foreground=[("selected", FG)])
    style.configure("TProgressbar", background=ACCENT, troughcolor=BG_INPUT, borderwidth=0)
