#!/usr/bin/env python3
"""Build standalone Lockbox executables.

    python3 build.py              # console binary, plus the GUI one if Tk exists
    python3 build.py --cli-only   # console binary only
    python3 build.py --clean      # remove build artefacts and exit

What you get:

    dist/lockbox        (lockbox.exe on Windows)     -- CLI, no Python needed
    dist/lockbox-gui    (lockbox-gui.exe on Windows) -- desktop window

**PyInstaller does not cross-compile.** Run this on the platform you want a
binary for: Windows for `.exe`, macOS for a macOS binary, Linux for Linux.
That is a hard limitation of how freezing works, not a missing flag.

The build runs the test suite first and verifies the finished binary afterwards
(see verify_binary.py). A binary that fails either is not worth shipping.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
SPEC = ROOT / "lockbox.spec"

IS_WINDOWS = sys.platform == "win32"
EXE = ".exe" if IS_WINDOWS else ""


def info(message: str) -> None:
    print(f"  {message}")


def heading(message: str) -> None:
    print(f"\n== {message}")


def fail(message: str) -> int:
    print(f"\nBUILD FAILED: {message}", file=sys.stderr)
    return 1


def have_tk() -> bool:
    try:
        import tkinter  # noqa: F401

        return True
    except Exception:
        return False


def check_environment(cli_only: bool) -> list[str]:
    """Return a list of problems. Empty means good to go."""
    problems = []

    if sys.version_info < (3, 10):
        problems.append(f"Python 3.10+ required, found {platform.python_version()}")

    for module, package in (("cryptography", "cryptography"), ("argon2", "argon2-cffi")):
        try:
            __import__(module)
            info(f"found {package}")
        except ImportError:
            problems.append(f"missing dependency: pip install {package}")

    try:
        import PyInstaller  # noqa: F401

        info(f"found PyInstaller {PyInstaller.__version__}")
    except ImportError:
        problems.append("missing PyInstaller: pip install pyinstaller")

    if cli_only:
        info("Tk not required (--cli-only)")
    elif have_tk():
        import tkinter

        info(f"found Tk {tkinter.TkVersion}")
    else:
        problems.append(
            "Tk is missing, so the GUI binary cannot be built.\n"
            "        Debian/Ubuntu: sudo apt install python3-tk\n"
            "        Fedora:        sudo dnf install python3-tkinter\n"
            "        macOS/Windows: reinstall Python with the Tcl/Tk option\n"
            "        Or build the CLI alone: python3 build.py --cli-only"
        )
    return problems


def run_tests() -> bool:
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    result = subprocess.run(
        [sys.executable, str(ROOT / "run_tests.py")],
        env=env, capture_output=True, text=True,
    )
    tail = (result.stderr or result.stdout).strip().splitlines()[-3:]
    for line in tail:
        info(line)
    return result.returncode == 0


def clean(dist: Path = DIST, work: Path = BUILD) -> None:
    for path in (work, dist):
        if path.exists():
            shutil.rmtree(path)
            info(f"removed {path.name}/")
    for spec_cache in ROOT.glob("*.spec.bak"):
        spec_cache.unlink()


def build(cli_only: bool, dist: Path, work: Path, onedir: bool) -> bool:
    command = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--log-level", "WARN",
        "--distpath", str(dist), "--workpath", str(work),
        str(SPEC),
    ]
    flags = ([] if not cli_only else ["--cli-only"]) + (["--onedir"] if onedir else [])
    if flags:
        command.append("--")
        command.extend(flags)
    start = time.perf_counter()
    result = subprocess.run(command, cwd=ROOT)
    info(f"finished in {time.perf_counter() - start:.1f}s")
    return result.returncode == 0


def report(cli_only: bool, dist: Path, onedir: bool = False) -> None:
    heading("Artefacts")
    targets = [f"lockbox{EXE}"] + ([] if cli_only else [f"lockbox-gui{EXE}"])
    for name in targets:
        path = dist / name if not onedir else dist / name.replace(EXE, "") / name
        if path.exists():
            size = path.stat().st_size / (1024 * 1024)
            info(f"{path}  {size:.1f} MB")
        else:
            info(f"{name}: NOT PRODUCED")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Lockbox executables")
    parser.add_argument("--cli-only", action="store_true",
                        help="build only the console binary (no Tk needed)")
    parser.add_argument("--onedir", action="store_true",
                        help="build a directory instead of a single file. "
                             "Starts roughly 3x faster because nothing is "
                             "unpacked at launch; ship the whole folder.")
    parser.add_argument("--clean", action="store_true", help="remove artefacts and exit")
    parser.add_argument("--skip-tests", action="store_true",
                        help="do not run the suite first (not recommended)")
    parser.add_argument("--skip-verify", action="store_true",
                        help="do not verify the produced binary (not recommended)")
    parser.add_argument("--dist", default=None,
                        help="output directory (default: ./dist). Some network "
                             "and container mounts break objcopy during "
                             "freezing; point this at a local disk if so.")
    parser.add_argument("--work", default=None,
                        help="scratch build directory (default: ./build)")
    args = parser.parse_args()

    print(f"Lockbox build -- {platform.system()} {platform.machine()}, "
          f"Python {platform.python_version()}")

    dist = Path(args.dist).resolve() if args.dist else DIST
    work = Path(args.work).resolve() if args.work else BUILD

    if args.clean:
        heading("Cleaning")
        clean(dist, work)
        return 0

    heading("Checking the build environment")
    problems = check_environment(args.cli_only)
    if problems:
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return fail("environment is not ready")

    if not args.skip_tests:
        heading("Running the test suite")
        if not run_tests():
            return fail("tests did not pass; refusing to build")
    else:
        heading("Skipping tests (--skip-tests)")

    heading("Freezing")
    clean(dist, work)
    if not build(args.cli_only, dist, work, args.onedir):
        return fail(
            "PyInstaller reported an error. If it mentions objcopy and 'Bad "
            "file descriptor', the output directory is on a mount that cannot "
            "handle it -- retry with --dist ~/lockbox-dist"
        )

    report(args.cli_only, dist, args.onedir)

    if not args.skip_verify:
        heading("Verifying the binary")
        result = subprocess.run(
            [sys.executable, str(ROOT / "verify_binary.py"),
             str(dist / "lockbox" / f"lockbox{EXE}" if args.onedir
                 else dist / f"lockbox{EXE}")],
        )
        if result.returncode != 0:
            return fail("the produced binary failed verification")

    print("\nBuild complete.")
    print(f"  {dist / ('lockbox' + EXE)}")
    if not args.cli_only:
        print(f"  {dist / ('lockbox-gui' + EXE)}")
    print("\nThese run on a machine with no Python installed. They are not signed;")
    print("Windows SmartScreen and macOS Gatekeeper will warn until you sign them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
