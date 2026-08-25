#!/usr/bin/env python3
"""Rebuild the Lockbox directory tree from files downloaded into one flat folder.

If you saved the files one at a time out of a chat, they all landed in a single
directory and the folder structure is gone. `pip install -e .` then fails with:

    error in 'egg_base' option: 'src' does not exist or is not a directory

because `pyproject.toml` says the package lives in `src/`, and there is no
`src/`. This script puts every file back where it belongs.

    python3 repair_layout.py              # show what it would do
    python3 repair_layout.py --apply      # actually move the files

Run it from inside the flat folder, or point it at one:

    python3 repair_layout.py --apply --dir "M:\\files"

It only moves files it recognises by name. Anything it does not know about is
left alone and listed at the end.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import re
from pathlib import Path

# filename -> destination directory, relative to the project root
LAYOUT = {
    # root
    "README.md": "", "SECURITY.md": "", "LICENSE": "", "Makefile": "",
    "pyproject.toml": "", "requirements.txt": "", "requirements-dev.txt": "",
    "run_tests.py": "", "build.py": "", "verify_binary.py": "",
    "lockbox.spec": "", "cli_entry.py": "", "gui_entry.py": "",
    ".gitignore": "", "repair_layout.py": "", "lockbox-linux-x64": "",
    # package
    "__init__.py": None,   # ambiguous - handled separately below
    "__main__.py": "src/lockbox",
    "py.typed": "src/lockbox",
    "cli.py": "src/lockbox",
    # core
    "crypto.py": "src/lockbox/core", "kdf.py": "src/lockbox/core",
    "vaultfile.py": "src/lockbox/core", "vault.py": "src/lockbox/core",
    "model.py": "src/lockbox/core", "search.py": "src/lockbox/core",
    "audit.py": "src/lockbox/core", "backup.py": "src/lockbox/core",
    "portio.py": "src/lockbox/core", "breach.py": "src/lockbox/core",
    "clipboard.py": "src/lockbox/core", "errors.py": "src/lockbox/core",
    # tools
    "generators.py": "src/lockbox/tools", "analysis.py": "src/lockbox/tools",
    "otp.py": "src/lockbox/tools", "qr.py": "src/lockbox/tools",
    "encoding.py": "src/lockbox/tools", "misc.py": "src/lockbox/tools",
    "wordlist.py": "src/lockbox/tools", "commonlist.py": "src/lockbox/tools",
    # ui
    "app.py": "src/lockbox/ui", "palette.py": "src/lockbox/ui",
    "tools_view.py": "src/lockbox/ui", "theme.py": "src/lockbox/ui",
    # tests
    "test_crypto.py": "tests", "test_vault.py": "tests", "test_tools.py": "tests",
    "test_portio.py": "tests", "test_offline.py": "tests", "test_cli.py": "tests",
    # tools/ (scripts, not the package)
    "benchmark.py": "tools",
    # docs
    "ARCHITECTURE.md": "docs", "THREAT_MODEL.md": "docs", "CRYPTO.md": "docs",
    "VAULT_FORMAT.md": "docs", "OFFLINE.md": "docs", "BACKUP.md": "docs",
    "BUILDING.md": "docs", "TESTING.md": "docs", "DEVELOPMENT.md": "docs",
    # CI
    "build.yml": ".github/workflows",
}

# Empty marker files that must exist. Recreated rather than hunted for, since a
# zero-byte __init__.py cannot be told apart from any other zero-byte one.
MARKERS = [
    "src/lockbox/core/__init__.py",
]

# Files whose content identifies which package they belong to.
INIT_MARKERS = {
    "src/lockbox/__init__.py": "APP_NAME",
    "src/lockbox/tools/__init__.py": "_TOOLS",
    "src/lockbox/ui/__init__.py": "Tk user interface",
}


def classify_init(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for destination, needle in INIT_MARKERS.items():
        if needle in text:
            return destination
    if not text.strip():
        return "src/lockbox/core/__init__.py"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dir", default=".", help="the flat folder (default: here)")
    parser.add_argument("--apply", action="store_true",
                        help="actually move files (default is a dry run)")
    args = parser.parse_args()

    root = Path(args.dir).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    print(f"{'MOVING' if args.apply else 'DRY RUN'} in {root}\n")

    moves: list[tuple[Path, Path]] = []
    unknown: list[Path] = []

    for entry in sorted(root.iterdir()):
        if entry.is_dir():
            continue
        name = entry.name

        # Browsers rename collisions: "__init__ (1).py", "vault(2).py".
        # Strip the counter so the file can still be identified.
        stem = re.sub(r"\s*\((\d+)\)(?=\.|$)", "", name)

        if stem.endswith("__init__.py") or stem == "init.py":
            destination = classify_init(entry)
            if destination is None:
                unknown.append(entry)
                continue
            moves.append((entry, root / destination))
            continue

        if stem not in LAYOUT:
            unknown.append(entry)
            continue

        subdir = LAYOUT[stem]
        if subdir is None:
            unknown.append(entry)
            continue
        target = root / subdir / stem if subdir else root / stem
        if target != entry:
            moves.append((entry, target))

    for source, target in moves:
        relative = target.relative_to(root)
        print(f"  {source.name:<24} ->  {relative}")
        if args.apply:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(target))

    if args.apply:
        for marker in MARKERS:
            path = root / marker
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
                print(f"  (created)                ->  {marker}")
        # py.typed may also have arrived empty and been skipped
        typed = root / "src/lockbox/py.typed"
        if not typed.exists():
            typed.parent.mkdir(parents=True, exist_ok=True)
            typed.touch()
            print("  (created)                ->  src/lockbox/py.typed")

    if unknown:
        print("\nleft alone (not part of Lockbox, or a duplicate download):")
        for path in unknown:
            print(f"  {path.name}")

    if not args.apply:
        print(f"\n{len(moves)} file(s) would move. Re-run with --apply to do it.")
        return 0

    missing = [f for f in (
        "src/lockbox/__init__.py", "src/lockbox/core/__init__.py",
        "src/lockbox/tools/__init__.py", "src/lockbox/ui/__init__.py",
        "src/lockbox/cli.py", "pyproject.toml",
    ) if not (root / f).exists()]
    if missing:
        print("\nSTILL MISSING -- the package will not import:")
        for name in missing:
            print(f"  {name}")
        print("\nThis is the usual outcome of downloading files one by one: all")
        print("four __init__.py files share a name, so they overwrite each other.")
        print("Only src/lockbox/tools/__init__.py has content worth recovering")
        print("(it is the micro-tool registry). Get the ZIP instead -- it keeps")
        print("the folder structure and cannot collide.")
        return 1

    print("\nDone. Now check the layout:")
    print("  python -c \"import pathlib;print(sorted(p.name for p in pathlib.Path('src/lockbox').iterdir()))\"")
    print("\nThen:")
    print("  pip install -r requirements.txt")
    print("  pip install -e .")
    print("  python run_tests.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
