"""Offline-operation tests.

Two complementary approaches, because either one alone is weak:

* **Dynamic** -- every socket constructor and every DNS/connect entry point in
  the standard library is replaced with something that raises, then the full
  application workflow is exercised. Anything that tries to reach the network
  fails the test instead of quietly succeeding on a developer machine that
  happens to be online.
* **Static** -- the whole shipped package is parsed with `ast` and every import
  is inspected. A networking module appearing anywhere in `src/lockbox` fails
  the test, even on a code path no test happens to run.
"""

from __future__ import annotations

import ast
import os
import pathlib
import socket
import tempfile
import unittest

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "lockbox"

# Modules that can reach the network. urllib.parse is explicitly allowed: it is
# a pure string parser and lives in the same package as urllib.request.
FORBIDDEN_MODULES = {
    "urllib.request", "urllib.error", "http", "http.client", "https", "ftplib",
    "smtplib", "poplib", "imaplib", "telnetlib", "nntplib", "socketserver",
    "xmlrpc", "requests", "httpx", "aiohttp", "urllib3", "websocket", "websockets",
    "boto3", "botocore", "google", "azure", "paramiko", "pycurl", "grpc", "curl_cffi",
    "asyncio",
}
FORBIDDEN_PREFIXES = tuple(m + "." for m in FORBIDDEN_MODULES)

# `socket` is permitted in exactly one place: the offline self-test, which
# imports it in order to *disable* it.
SOCKET_ALLOWED = {"cli.py"}


def python_files():
    for path in SRC.rglob("*.py"):
        if "__pycache__" not in path.parts:
            yield path


class NetworkBlocked:
    """Context manager that makes any outbound network call raise."""

    ATTRIBUTES = (
        "socket", "create_connection", "create_server", "socketpair",
        "getaddrinfo", "gethostbyname", "gethostbyname_ex", "getfqdn",
    )

    def __enter__(self):
        self.saved = {name: getattr(socket, name, None) for name in self.ATTRIBUTES}

        def blocked(*_args, **_kwargs):
            raise OSError("network access is blocked by the offline test")

        class BlockedSocket:
            def __init__(self, *_args, **_kwargs):
                raise OSError("network access is blocked by the offline test")

        socket.socket = BlockedSocket  # type: ignore[assignment]
        for name in self.ATTRIBUTES[1:]:
            if self.saved[name] is not None:
                setattr(socket, name, blocked)
        return self

    def __exit__(self, *_exc):
        for name, value in self.saved.items():
            if value is not None:
                setattr(socket, name, value)
        return False


class TestTheBlockerItself(unittest.TestCase):
    """If the blocker does not block, every other test here is worthless."""

    def test_socket_creation_raises(self):
        with NetworkBlocked():
            with self.assertRaises(OSError):
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def test_dns_raises(self):
        with NetworkBlocked():
            with self.assertRaises(OSError):
                socket.gethostbyname("example.com")

    def test_connection_raises(self):
        with NetworkBlocked():
            with self.assertRaises(OSError):
                socket.create_connection(("example.com", 80), timeout=1)

    def test_urllib_cannot_escape_the_block(self):
        import urllib.request

        with NetworkBlocked():
            with self.assertRaises(Exception):
                urllib.request.urlopen("http://example.com", timeout=1)

    def test_normal_sockets_work_again_afterwards(self):
        with NetworkBlocked():
            pass
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.close()


class TestFullWorkflowOffline(unittest.TestCase):
    """The complete application workflow, with the network disabled."""

    def test_everything_works_with_no_network(self):
        from lockbox.core import backup as backup_mod
        from lockbox.core import portio
        from lockbox.core.audit import audit
        from lockbox.core.kdf import KDFParams
        from lockbox.core.model import Item
        from lockbox.core.search import search
        from lockbox.core.vault import Vault
        from lockbox.tools import TOOLS, run
        from lockbox.tools.otp import OTPConfig, build_otpauth, current, generate_secret
        from lockbox.tools.qr import encode as qr_encode, to_svg

        fast = KDFParams("scrypt", b"0123456789abcdef", {"n": 1024, "r": 8, "p": 1})
        password = b"offline master password"

        with NetworkBlocked(), tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "vault.lbx")

            vault = Vault(path)
            vault.create(password, fast)

            generated = run("password", length=24)
            self.assertEqual(len(generated.value), 24)
            phrase = run("passphrase", words=5)
            self.assertEqual(len(phrase.value.split("-")), 5)

            secret = generate_secret()
            item = Item(title="Offline Co", username="me", password=generated.value,
                        url="https://offline.example", totp_secret=secret, tags=["test"])
            vault.add(item)
            vault.add(Item(title="Weak", username="w", password="password"))
            vault.save()

            vault.lock()
            vault.unlock(password)
            self.assertEqual(len(vault.items()), 2)

            self.assertTrue(search(vault.items(), "offline"))
            self.assertTrue(search(vault.items(), "has:totp"))

            code = current(OTPConfig(secret=secret))["code"]
            self.assertEqual(len(code), 6)
            self.assertTrue(qr_encode(build_otpauth(OTPConfig(secret=secret))))
            self.assertTrue(to_svg(qr_encode("offline")).startswith("<svg"))

            report = audit(vault.items(), vault.settings)
            self.assertTrue(report.findings)
            self.assertIn("no local breach dataset", report.breach_status)

            self.assertTrue(vault.integrity_check()["ok"])

            info = backup_mod.create_backup(path, os.path.join(tmp, "backups"))
            self.assertTrue(backup_mod.verify_backup(info.path, password)["decrypt_ok"])
            backup_mod.restore_backup(info.path, path, password)

            export_path = os.path.join(tmp, "export.csv")
            portio.write_plaintext_export(export_path, vault.items(), "csv",
                                          confirm=portio.CONFIRM_TOKEN)
            with open(export_path, encoding="utf-8") as fh:
                self.assertEqual(len(portio.import_csv(fh.read()).items), 2)

            # Every registered micro-tool must at least import with no network.
            for tool in TOOLS.values():
                self.assertTrue(callable(tool.load()), tool.id)

            vault.lock()

    def test_cli_offline_selftest_passes(self):
        from lockbox.cli import _offline_selftest

        result = _offline_selftest()
        self.assertTrue(result["passed"], result["steps"])
        names = {step["name"] for step in result["steps"]}
        self.assertIn("create encrypted vault", names)
        self.assertIn("wrong password rejected", names)


class TestNoNetworkCodeAnywhere(unittest.TestCase):
    def test_no_networking_imports(self):
        offences = []
        for path in python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for name in names:
                    if name == "socket":
                        if path.name not in SOCKET_ALLOWED:
                            offences.append(f"{path.name}:{node.lineno} imports socket")
                        continue
                    if name in FORBIDDEN_MODULES or name.startswith(FORBIDDEN_PREFIXES):
                        offences.append(f"{path.name}:{node.lineno} imports {name}")
        self.assertEqual(offences, [], "networking code found in the package")

    def test_no_urls_are_contacted(self):
        """No http(s) literal may appear outside comments, docstrings and the
        two schema URIs that are never fetched."""
        allowed = {
            "http://www.w3.org/2000/svg",  # SVG namespace: an identifier, not a fetch
        }
        offences = []
        for path in python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            docstrings = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
                    doc = ast.get_docstring(node, clean=False)
                    if doc:
                        docstrings.add(doc)
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    text = node.value
                    if text in docstrings:
                        continue
                    for scheme in ("http://", "https://"):
                        index = text.find(scheme)
                        while index != -1:
                            url = text[index:].split()[0].strip("\"'),.")
                            bare_scheme = url in ("http://", "https://")
                            if (url not in allowed and "example" not in url
                                    and not bare_scheme):
                                offences.append(f"{path.name}:{node.lineno}: {url}")
                            index = text.find(scheme, index + 1)
        self.assertEqual(offences, [], "network URLs found in the package")

    def test_no_subprocess_calls_to_network_tools(self):
        banned = ("curl", "wget", "nc ", "netcat", "ssh ", "scp ", "rsync")
        for path in python_files():
            text = path.read_text(encoding="utf-8")
            for tool in banned:
                self.assertNotIn(f'"{tool.strip()}"', text, f"{path.name} references {tool}")

    def test_dependencies_are_the_two_declared_ones(self):
        """Third-party imports must be exactly the audited crypto libraries."""
        stdlib = set(getattr(__import__("sys"), "stdlib_module_names", ()))
        allowed_third_party = {"cryptography", "argon2"}
        found = set()
        for path in python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for name in names:
                    root = name.split(".")[0]
                    if root not in stdlib and root not in ("lockbox", "_frozen_importlib"):
                        found.add(root)
        self.assertTrue(
            found <= allowed_third_party,
            f"unexpected third-party dependencies: {sorted(found - allowed_third_party)}",
        )

    def test_no_telemetry_or_analytics_identifiers(self):
        banned = ("telemetry", "analytics", "sentry", "mixpanel", "amplitude",
                  "segment.io", "posthog", "google-analytics", "phone_home")
        for path in python_files():
            text = path.read_text(encoding="utf-8").lower()
            for term in banned:
                if term in text:
                    # Allowed only in prose that says we do not do it.
                    for line in text.splitlines():
                        if term in line:
                            self.assertTrue(
                                line.strip().startswith(("#", '"', "*", "no ")) or
                                "no " in line or "never" in line or "not " in line,
                                f"{path.name}: {line.strip()[:80]}",
                            )


class TestNoSecretsLeak(unittest.TestCase):
    def test_no_logging_of_secrets(self):
        """The package must not configure logging at all: the simplest way to
        guarantee a password is never written to a log file."""
        for path in python_files():
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("import logging", text, path.name)
            self.assertNotIn("logging.getLogger", text, path.name)

    def test_no_hardcoded_keys_or_passwords(self):
        suspicious = ("api_key =", "apikey =", "secret_key =", "AWS_", "BEGIN PRIVATE KEY")
        for path in python_files():
            text = path.read_text(encoding="utf-8")
            for term in suspicious:
                self.assertNotIn(term, text, f"{path.name} contains {term!r}")

    def test_vault_repr_is_safe(self):
        from lockbox.core.kdf import KDFParams
        from lockbox.core.vaultfile import new_keys

        keys = new_keys(b"pw", KDFParams("scrypt", b"0123456789abcdef",
                                         {"n": 1024, "r": 8, "p": 1}))
        self.assertIn("redacted", repr(keys))
        self.assertNotIn(keys.dek.hex()[:8], repr(keys))


if __name__ == "__main__":
    unittest.main()
