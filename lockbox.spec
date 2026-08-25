# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Lockbox.

Builds two one-file executables from the same source tree:

  lockbox      console  -- the CLI, works everywhere, no Tk required
  lockbox-gui  windowed -- the desktop window (needs Tk at build time)

Run it through `build.py`, which checks the environment first:

    python3 build.py            # both, if Tk is available
    python3 build.py --cli-only # console binary only

**PyInstaller does not cross-compile.** A Windows `.exe` must be built on
Windows, a macOS binary on macOS, a Linux binary on Linux. There is no flag for
this and never has been; anyone offering one is describing Wine.

Exclusions below are deliberate. They keep the binary small and, more usefully,
they make it impossible for a networking module to be bundled by accident: if
some future import pulls in `urllib.request`, the build fails rather than
quietly shipping it. `verify_binary.py` re-checks the produced executable.
"""

import sys
from pathlib import Path

APP_NAME = "lockbox"
GUI_NAME = "lockbox-gui"
ROOT = Path(SPECPATH).resolve()
SRC = ROOT / "src"
ASSETS = ROOT / "assets"

# Executable icon. Windows wants .ico, macOS wants .icns, Linux ignores it
# entirely (the desktop file supplies the icon there). Missing file means
# icon=None rather than a build error, so a fresh checkout still builds.
ICON_ICO = ASSETS / "lockbox.ico"
ICON_ICNS = ASSETS / "lockbox.icns"
if sys.platform == "win32" and ICON_ICO.exists():
    APP_ICON = str(ICON_ICO)
elif sys.platform == "darwin" and ICON_ICNS.exists():
    APP_ICON = str(ICON_ICNS)
else:
    APP_ICON = None

# The window icon is loaded at runtime by lockbox.ui.app, so the files have to
# travel inside the binary as data. Tk reads PNG natively (8.6+); .ico is used
# via iconbitmap on Windows. Both are tiny.
ICON_DATAS = [
    (str(path), "assets")
    for path in (ICON_ICO, ASSETS / "lockbox.png")
    if path.exists()
]

BUILD_GUI = "--cli-only" not in sys.argv

# One-file vs one-directory. One-file is a single portable executable, but the
# bootloader unpacks it to a temp directory on every launch, which costs about
# 230 ms here. One-directory starts in about a third of that because there is
# nothing to unpack. Default to one-directory for the GUI (launch latency is
# felt) and offer one-file for the CLI (portability is felt).
ONEFILE = "--onedir" not in sys.argv

# Modules that must never end up inside the binary. Networking first, then the
# heavy scientific/packaging machinery PyInstaller sometimes drags in.
EXCLUDES = [
    # networking -- the whole point
    "urllib.request", "urllib.error", "urllib.robotparser",
    "http", "http.client", "http.server", "http.cookiejar", "http.cookies",
    "ftplib", "smtplib", "poplib", "imaplib", "nntplib", "telnetlib",
    "socketserver", "xmlrpc", "xmlrpc.client", "xmlrpc.server",
    "requests", "httpx", "aiohttp", "urllib3", "websockets",
    "asyncio", "ssl", "email", "mailbox", "cgi", "cgitb", "wsgiref",
    "webbrowser",
    # NOTE: urllib.parse, ipaddress and uuid stay. urllib.parse is a pure
    # string parser (used for URL inspection and otpauth URIs) and it imports
    # ipaddress; excluding it breaks the binary at startup. Only the *fetching*
    # halves of urllib are excluded above.
    # bulk we never touch
    "numpy", "scipy", "pandas", "matplotlib", "PIL", "pytest", "setuptools",
    "pip", "distutils", "pydoc", "doctest", "unittest", "lib2to3",
    "sqlite3", "dbm", "curses", "multiprocessing", "concurrent",
    "test", "tests", "idlelib", "turtle", "turtledemo",
]

# The CLI must not pull Tk in; the GUI must.
CLI_EXCLUDES = EXCLUDES + ["tkinter", "tkinter.ttk", "tkinter.filedialog",
                           "tkinter.messagebox", "tkinter.simpledialog"]

# The micro-tool registry imports tool modules by name at call time, so the
# static analyser cannot see them. List them explicitly or they are silently
# left out of the binary and every tool fails at runtime.
HIDDEN = [
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.bindings._rust",
    "argon2.low_level",
    "lockbox.tools",
    "lockbox.tools.analysis",
    "lockbox.tools.commonlist",
    "lockbox.tools.encoding",
    "lockbox.tools.generators",
    "lockbox.tools.misc",
    "lockbox.tools.otp",
    "lockbox.tools.qr",
    "lockbox.tools.wordlist",
]

cli_analysis = Analysis(
    [str(ROOT / "cli_entry.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=ICON_DATAS,
    hiddenimports=HIDDEN,
    hookspath=[],
    runtime_hooks=[],
    excludes=CLI_EXCLUDES,
    noarchive=False,
    optimize=0,          # keep docstrings/asserts: asserts guard crypto invariants
)

cli_pyz = PYZ(cli_analysis.pure)

cli_exe = EXE(
    cli_pyz,
    cli_analysis.scripts,
    *((cli_analysis.binaries, cli_analysis.datas) if ONEFILE else ((), ())),
    [],
    exclude_binaries=not ONEFILE,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,           # UPX-packed binaries look like malware to AV scanners
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=APP_ICON,
)

if not ONEFILE:
    cli_collect = COLLECT(
        cli_exe,
        cli_analysis.binaries,
        cli_analysis.datas,
        strip=False,
        upx=False,
        name=APP_NAME,
    )

if BUILD_GUI:
    gui_analysis = Analysis(
        [str(ROOT / "gui_entry.py")],
        pathex=[str(SRC)],
        binaries=[],
        datas=ICON_DATAS,
        hiddenimports=HIDDEN + ["tkinter", "tkinter.ttk", "tkinter.filedialog",
                                "tkinter.messagebox", "tkinter.simpledialog"],
        hookspath=[],
        runtime_hooks=[],
        excludes=EXCLUDES,
        noarchive=False,
        optimize=0,
    )

    gui_pyz = PYZ(gui_analysis.pure)

    gui_exe = EXE(
        gui_pyz,
        gui_analysis.scripts,
        *((gui_analysis.binaries, gui_analysis.datas) if ONEFILE else ((), ())),
        [],
        exclude_binaries=not ONEFILE,
        name=GUI_NAME,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,   # no console window behind the app on Windows
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        icon=APP_ICON,
    )

    if not ONEFILE:
        gui_collect = COLLECT(
            gui_exe,
            gui_analysis.binaries,
            gui_analysis.datas,
            strip=False,
            upx=False,
            name=GUI_NAME,
        )
