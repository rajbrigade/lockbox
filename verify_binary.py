#!/usr/bin/env python3
"""Verify a frozen Lockbox executable.

    python3 verify_binary.py dist/lockbox

The source tree is proven offline by the test suite. A *binary* is a different
artefact: PyInstaller could have bundled a networking module through a hidden
import, or the crypto could have failed to bundle at all. This script exercises
the finished executable as a black box:

  1. it runs, and reports the expected version
  2. it creates a real vault, stores an item, and reads it back
  3. it rejects a wrong master password
  4. its own offline self-test passes
  5. no networking module is embedded in the archive
  6. no plaintext of the test secret appears in the binary
  7. the vault it writes is mode 0600 and has the right magic bytes

Exit code 0 means every check passed.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PASSWORD = "verify-binary-master-password"
SECRET = "canary-secret-value-9f3a2b"

FORBIDDEN_IN_ARCHIVE = (
    b"urllib.request", b"http.client", b"smtplib", b"ftplib",
    b"requests", b"aiohttp", b"httpx", b"telnetlib", b"xmlrpc",
)


class Checker:
    def __init__(self, binary: Path):
        self.binary = binary
        self.failures: list[str] = []
        self.passes = 0

    def check(self, name: str, condition: bool, detail: str = "") -> bool:
        if condition:
            self.passes += 1
            print(f"  [ok]   {name}")
        else:
            self.failures.append(f"{name}: {detail}" if detail else name)
            print(f"  [FAIL] {name}" + (f" -- {detail}" if detail else ""))
        return condition

    def run(self, *args, password_file: str | None = None, env_extra=None):
        command = [str(self.binary)]
        if password_file:
            command += ["--password-file", password_file]
        command += list(args)
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(command, capture_output=True, text=True, timeout=180, env=env)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    binary = Path(sys.argv[1]).resolve()
    if not binary.exists():
        print(f"no such file: {binary}", file=sys.stderr)
        return 2

    print(f"Verifying {binary}  ({binary.stat().st_size / 1048576:.1f} MB)")
    checker = Checker(binary)

    if not os.access(binary, os.X_OK) and sys.platform != "win32":
        os.chmod(binary, 0o755)

    # 1. it runs
    result = checker.run("--version")
    checker.check("executable runs", result.returncode == 0, result.stderr.strip()[:200])
    checker.check("reports a version",
                  bool(re.search(r"lockbox \d+\.\d+\.\d+", result.stdout)),
                  result.stdout.strip()[:120])

    with tempfile.TemporaryDirectory() as tmp:
        vault = os.path.join(tmp, "verify.lbx")
        password_file = os.path.join(tmp, "pw")
        wrong_file = os.path.join(tmp, "wrong")
        with open(password_file, "w", encoding="utf-8") as fh:
            fh.write(PASSWORD + "\n")
        with open(wrong_file, "w", encoding="utf-8") as fh:
            fh.write("not the password\n")

        def cli(*args, pw=password_file):
            return checker.run("--vault", vault, *args, password_file=pw)

        # 2. real vault lifecycle -- this also proves Argon2 and OpenSSL bundled
        result = cli("init")
        checker.check("creates a vault", result.returncode == 0,
                      (result.stderr or result.stdout).strip()[:200])
        checker.check("Argon2id is bundled and used", "Argon2id" in result.stdout,
                      result.stdout.strip()[:120])

        result = cli("add", "Verify Co", "-u", "tester", "-p", SECRET)
        checker.check("stores an item", result.returncode == 0, result.stderr.strip()[:200])

        result = cli("show", "verify", "--reveal", "--json")
        ok = result.returncode == 0 and SECRET in result.stdout
        checker.check("reads the item back", ok, result.stderr.strip()[:200])
        if ok:
            data = json.loads(result.stdout)
            checker.check("round-trips the exact value", data["password"] == SECRET)

        # 3. wrong password
        result = cli("list", pw=wrong_file)
        checker.check("rejects a wrong master password",
                      result.returncode != 0 and "wrong master password" in result.stderr,
                      result.stderr.strip()[:160])

        # 4. the binary's own offline self-test
        result = cli("check", "--offline")
        checker.check("offline self-test passes",
                      result.returncode == 0 and "Offline self-test: PASSED" in result.stdout,
                      (result.stderr or result.stdout).strip()[-300:])
        checker.check("integrity check passes", "Vault integrity: OK" in result.stdout)

        # 5. TOTP and QR survived freezing
        result = checker.run("tool", "totp_secret")
        checker.check("TOTP tool works", result.returncode == 0, result.stderr.strip()[:160])
        result = checker.run("tool", "qr_text", "-a", "matrix=x")
        checker.check("QR tool is present (arg error, not import error)",
                      "unknown tool" not in (result.stderr + result.stdout))

        # 6. generation works without a vault
        result = checker.run("gen", "--length", "32", "--quiet")
        checker.check("generates a password", len(result.stdout.strip()) == 32,
                      result.stdout.strip()[:80])

        # 7. file permissions and magic
        if not os.path.exists(vault):
            checker.check("vault file exists on disk", False, "no vault was written")
            return _finish(checker, binary)
        if sys.platform != "win32":
            checker.check("vault written mode 0600",
                          oct(os.stat(vault).st_mode & 0o777) == "0o600",
                          oct(os.stat(vault).st_mode & 0o777))
        with open(vault, "rb") as fh:
            head = fh.read(4)
        checker.check("vault has the right magic", head == b"LBXV", repr(head))

        with open(vault, "rb") as fh:
            blob = fh.read()
        checker.check("secret is not readable in the vault file",
                      SECRET.encode() not in blob)

    return _finish(checker, binary)


def _finish(checker: "Checker", binary: Path) -> int:
    # 8. no networking modules embedded, no secrets baked in
    payload = binary.read_bytes()
    embedded = [name.decode() for name in FORBIDDEN_IN_ARCHIVE if name in payload]
    checker.check("no networking modules embedded", not embedded, ", ".join(embedded))
    checker.check("no test secret baked into the binary", SECRET.encode() not in payload)

    print(f"\n{checker.passes} passed, {len(checker.failures)} failed")
    if checker.failures:
        print("\nfailures:")
        for failure in checker.failures:
            print(f"  - {failure}")
        return 1
    print("Binary verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
