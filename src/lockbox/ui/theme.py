"""Visual constants for the Tk interface.

A dark, sharp, terminal-flavoured palette: near-black panels separated by hard
1px rules rather than boxes, a monospace-first type scale, and a single green
accent. Still deliberately plain -- system fonts only, flat colours, no images,
no animation. Nothing here loads a font, an icon or a stylesheet from disk or
from anywhere else, so the UI cannot become a network dependency by accident.
"""

from __future__ import annotations

import sys

# -- surfaces ---------------------------------------------------------------
# Three depths only. Anything that needs to read as "separate" gets a RULE, not
# another background: stacked panels of slightly different greys are what made
# the detail pane read as a wall of boxes.
BG = "#0b0d10"        # window / deepest
BG_ALT = "#12151a"    # sidebar, list, raised panels
BG_INPUT = "#171b21"  # entries, text areas
BG_HOVER = "#1d222a"

# -- lines ------------------------------------------------------------------
RULE = "#232830"       # hairline separators between regions
RULE_STRONG = "#333b46"  # focus rings, active borders

# -- text -------------------------------------------------------------------
FG = "#dfe4ea"
FG_DIM = "#828d9b"
FG_FAINT = "#5b646f"   # captions, column headings, keyboard hints

# -- accent -----------------------------------------------------------------
# Dark enough that white sits on it legibly (selection bars use white text),
# with a brighter sibling for accent *text* on a dark background.
ACCENT = "#1f8f5f"
ACCENT_BRIGHT = "#57e39b"
ACCENT_MUTED = "#16513a"

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

# Strength meter, weakest to strongest. Indexed by Analysis.score (0-4).
STRENGTH_COLORS = (CRIT, "#ff7b72", WARN, ACCENT_BRIGHT, OK)

# -- spacing ----------------------------------------------------------------
# PAD stays the module's base unit (other views import it); the scale exists so
# panes can breathe without every caller inventing its own number.
PAD = 8
PAD_XS = 2
PAD_SM = 6
PAD_MD = 12
PAD_LG = 18
PAD_XL = 28

ROW_HEIGHT = 30


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
        "mono_bold": (mono, 10, "bold"),
        "mono_small": (mono, 9),
        "mono_big": (mono, 16),
        # Small, letter-spaced-by-hand section captions ("IDENTITY", "SECRET").
        "caption": (mono, 8, "bold"),
        "brand": (mono, 15, "bold"),
    }


def caption(text: str) -> str:
    """Render a section caption the way the UI wants it: upper, spaced out."""
    return " ".join(text.upper())


def apply_styles(root) -> None:
    from tkinter import ttk

    style = ttk.Style(root)
    try:
        style.theme_use("clam")  # the only built-in theme that honours colours
    except Exception:
        pass
    f = fonts()
    root.configure(bg=BG)

    style.configure(".", background=BG, foreground=FG, font=f["base"],
                    borderwidth=0, focuscolor=ACCENT)

    # -- frames -------------------------------------------------------------
    style.configure("TFrame", background=BG)
    style.configure("Alt.TFrame", background=BG_ALT)
    style.configure("Input.TFrame", background=BG_INPUT)
    # A 1px horizontal rule: a frame with a background and a height of one.
    style.configure("Rule.TFrame", background=RULE)
    style.configure("Accent.TFrame", background=ACCENT)

    # -- labels -------------------------------------------------------------
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Alt.TLabel", background=BG_ALT, foreground=FG)
    style.configure("Dim.TLabel", background=BG, foreground=FG_DIM, font=f["small"])
    style.configure("Faint.TLabel", background=BG, foreground=FG_FAINT, font=f["mono_small"])
    style.configure("Title.TLabel", background=BG, foreground=FG, font=f["title"])
    style.configure("Brand.TLabel", background=BG_ALT, foreground=ACCENT_BRIGHT,
                    font=f["brand"])
    style.configure("Caption.TLabel", background=BG, foreground=FG_FAINT, font=f["caption"])
    style.configure("CaptionAlt.TLabel", background=BG_ALT, foreground=FG_FAINT,
                    font=f["caption"])
    style.configure("Field.TLabel", background=BG, foreground=FG_DIM, font=f["mono_small"])
    style.configure("Mono.TLabel", background=BG, foreground=FG, font=f["mono"])
    style.configure("Code.TLabel", background=BG, foreground=ACCENT_BRIGHT, font=f["mono_big"])
    style.configure("Count.TLabel", background=BG, foreground=FG_FAINT, font=f["mono_small"])

    # -- buttons ------------------------------------------------------------
    # Flat by default; the accent arrives on hover as a left-edge fill rather
    # than a full colour swap, so the sidebar does not strobe under the mouse.
    style.configure("TButton", background=BG_INPUT, foreground=FG, borderwidth=0,
                    padding=(PAD_MD, PAD_SM), font=f["mono"], anchor="center")
    style.map("TButton",
              background=[("pressed", ACCENT_MUTED), ("active", BG_HOVER)],
              foreground=[("active", ACCENT_BRIGHT)])

    style.configure("Ghost.TButton", background=BG_ALT, foreground=FG_DIM,
                    borderwidth=0, padding=(PAD_SM, PAD_SM), font=f["mono_small"],
                    anchor="w")
    style.map("Ghost.TButton",
              background=[("pressed", ACCENT_MUTED), ("active", BG_HOVER)],
              foreground=[("active", ACCENT_BRIGHT)])

    style.configure("Primary.TButton", background=ACCENT, foreground="#ffffff",
                    borderwidth=0, padding=(PAD_MD, PAD_SM), font=f["mono_bold"])
    style.map("Primary.TButton", background=[("pressed", ACCENT_MUTED),
                                             ("active", "#27a771")],
              foreground=[("active", "#ffffff")])

    style.configure("Danger.TButton", background=BG_INPUT, foreground=FG_DIM,
                    borderwidth=0, padding=(PAD_MD, PAD_SM), font=f["mono"])
    style.map("Danger.TButton", background=[("active", "#3a1c1c")],
              foreground=[("active", CRIT)])

    # -- inputs -------------------------------------------------------------
    # No etched border. Focus is shown by the border colour turning accent,
    # which is why bordercolor/lightcolor/darkcolor are all set explicitly:
    # clam draws all three and leaving any of them default reintroduces the
    # grey bevel this theme is trying to get rid of.
    for name in ("TEntry", "TCombobox", "TSpinbox"):
        style.configure(name, fieldbackground=BG_INPUT, background=BG_INPUT,
                        foreground=FG, insertcolor=ACCENT_BRIGHT,
                        bordercolor=BG_INPUT, lightcolor=BG_INPUT, darkcolor=BG_INPUT,
                        borderwidth=1, padding=(PAD_SM, PAD_SM), font=f["mono"],
                        arrowcolor=FG_DIM, selectbackground=ACCENT,
                        selectforeground="#ffffff")
        style.map(name,
                  bordercolor=[("focus", ACCENT)],
                  lightcolor=[("focus", ACCENT)],
                  darkcolor=[("focus", ACCENT)],
                  fieldbackground=[("readonly", BG_INPUT), ("disabled", BG)],
                  foreground=[("disabled", FG_FAINT)])
    style.configure("Search.TEntry", padding=(PAD_SM, PAD_SM + 1))

    # -- item list ----------------------------------------------------------
    # fieldbackground matches the window so the empty space under the last row
    # is not a second panel; the rows themselves alternate BG / BG_ALT via tags.
    style.configure("Treeview", background=BG, fieldbackground=BG,
                    foreground=FG, borderwidth=0, relief="flat",
                    bordercolor=BG, lightcolor=BG, darkcolor=BG,
                    rowheight=ROW_HEIGHT, font=f["mono"])
    style.configure("Treeview.Heading", background=BG, foreground=FG_FAINT,
                    borderwidth=0, relief="flat", padding=(PAD_SM, PAD_SM),
                    font=f["caption"])
    style.map("Treeview.Heading", background=[("active", BG)],
              foreground=[("active", FG_DIM)])
    style.map("Treeview",
              background=[("selected", ACCENT)],
              foreground=[("selected", "#ffffff")])

    # -- misc ---------------------------------------------------------------
    style.configure("TCheckbutton", background=BG, foreground=FG_DIM,
                    font=f["mono_small"], indicatorcolor=BG_INPUT,
                    bordercolor=RULE, focuscolor=BG)
    style.map("TCheckbutton", foreground=[("active", FG)],
              background=[("active", BG)],
              indicatorcolor=[("selected", ACCENT)])
    # clam draws a light bevel around notebook pages and scales unless every
    # border colour is pinned to the surface behind them.
    style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0),
                    bordercolor=BG, lightcolor=BG, darkcolor=BG)
    style.configure("TScale", background=BG, troughcolor=BG_INPUT, borderwidth=0,
                    bordercolor=BG_INPUT, lightcolor=ACCENT, darkcolor=ACCENT)
    style.map("TScale", background=[("active", BG)])
    style.configure("TNotebook.Tab", background=BG, foreground=FG_FAINT,
                    padding=(PAD_MD, PAD_SM), borderwidth=0, font=f["mono_small"])
    style.map("TNotebook.Tab", background=[("selected", BG_ALT)],
              foreground=[("selected", ACCENT_BRIGHT), ("active", FG_DIM)])
    for bar in ("TProgressbar", "Horizontal.TProgressbar"):
        style.configure(bar, background=ACCENT, troughcolor=BG_INPUT, borderwidth=0,
                        thickness=4, bordercolor=BG_INPUT, lightcolor=ACCENT,
                        darkcolor=ACCENT)
    for bar in ("TScrollbar", "Vertical.TScrollbar", "Horizontal.TScrollbar"):
        style.configure(bar, background=RULE, troughcolor=BG, borderwidth=0,
                        relief="flat", arrowsize=10, arrowcolor=BG,
                        bordercolor=BG, lightcolor=RULE, darkcolor=RULE)
        style.map(bar, background=[("active", RULE_STRONG), ("pressed", ACCENT)],
                  arrowcolor=[("active", BG)])
    style.configure("TPanedwindow", background=RULE)
    style.configure("TSeparator", background=RULE)
