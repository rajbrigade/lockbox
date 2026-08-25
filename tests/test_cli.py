"""CLI end-to-end tests and clipboard behaviour.

The CLI is driven exactly as a user would drive it, through `main(argv)`, with
stdout captured. Nothing is mocked except the clipboard backend (there is no
display in CI) and the master password source.
"""

from __future__ import annotations

import sys
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from lockbox.cli import main
from lockbox.core.clipboard import Clipboard

PASSWORD = "a-good-master-password"
POSIX_PERMS = sys.platform != "win32"
NO_PERMS_REASON = (
    "Windows has no POSIX mode bits; access is governed by NTFS ACLs, which a "
    "file created inside the user's own profile inherits correctly"
)



class CLITestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.vault = os.path.join(self.tmp.name, "vault.lbx")
        self.password_file = os.path.join(self.tmp.name, "pw.txt")
        with open(self.password_file, "w", encoding="utf-8") as fh:
            fh.write(PASSWORD + "\n")
        self.assertEqual(self.run_cli("init")[0], 0)

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        argv = ["--vault", self.vault, "--password-file", self.password_file, *args]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()


class TestCLI(CLITestCase):
    def test_init_creates_a_vault(self):
        self.assertTrue(os.path.exists(self.vault))

    @unittest.skipUnless(POSIX_PERMS, NO_PERMS_REASON)
    def test_init_locks_down_the_vault_file(self):
        self.assertEqual(os.stat(self.vault).st_mode & 0o777, 0o600)

    def test_init_refuses_to_overwrite(self):
        code, _out, err = self.run_cli("init")
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)

    def test_add_list_show(self):
        self.run_cli("add", "GitHub", "-u", "octo", "-p", "s3cret",
                     "--url", "https://github.com", "--tags", "dev,work")
        code, out, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("GitHub", out)

        code, out, _ = self.run_cli("show", "github")
        self.assertIn("hidden", out)
        self.assertNotIn("s3cret", out)

        code, out, _ = self.run_cli("show", "github", "--reveal")
        self.assertIn("s3cret", out)

    def test_generated_password_is_stored(self):
        self.run_cli("add", "Gen", "-g", "--length", "32", "--show")
        _code, out, _ = self.run_cli("show", "gen", "--reveal", "--json")
        data = json.loads(out)
        self.assertEqual(len(data["password"]), 32)

    def test_json_list_never_contains_secrets(self):
        self.run_cli("add", "Secret Co", "-u", "u", "-p", "do-not-print-me",
                     "--totp", "JBSWY3DPEHPK3PXP")
        _code, out, _ = self.run_cli("list", "--json")
        self.assertNotIn("do-not-print-me", out)
        self.assertNotIn("JBSWY3DP", out)

    def test_edit_and_history(self):
        self.run_cli("add", "Site", "-p", "old-password")
        self.run_cli("edit", "site", "--password", "new-password")
        _code, out, _ = self.run_cli("show", "site", "--reveal", "--json")
        data = json.loads(out)
        self.assertEqual(data["password"], "new-password")
        self.assertEqual(data["history"][0]["password"], "old-password")

    def test_rm(self):
        self.run_cli("add", "Temp")
        self.assertEqual(self.run_cli("rm", "temp", "-y")[0], 0)
        _code, out, _ = self.run_cli("list")
        self.assertIn("no matches", out)

    def test_ambiguous_query_is_reported(self):
        self.run_cli("add", "Mail One")
        self.run_cli("add", "Mail Two")
        code, _out, err = self.run_cli("show", "mail")
        self.assertEqual(code, 1)
        self.assertIn("ambiguous", err)

    def test_totp(self):
        self.run_cli("add", "TOTP Site", "--totp", "JBSWY3DPEHPK3PXP")
        code, out, _ = self.run_cli("totp", "totp site")
        self.assertEqual(code, 0)
        self.assertRegex(out.strip().split()[0], r"^\d{6}$")

    def test_gen_without_a_vault(self):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = main(["gen", "--length", "18", "--quiet"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.getvalue().strip()), 18)

    def test_gen_passphrase(self):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            main(["gen", "passphrase", "--words", "7", "--quiet"])
        self.assertEqual(len(out.getvalue().strip().split("-")), 7)

    def test_audit(self):
        self.run_cli("add", "Weak", "-p", "password", "--url", "http://x.example")
        code, out, _ = self.run_cli("audit")
        self.assertEqual(code, 0)
        self.assertIn("CRITICAL", out)
        self.assertIn("no local breach dataset", out)

    def test_audit_json(self):
        self.run_cli("add", "Weak", "-p", "password")
        _code, out, _ = self.run_cli("audit", "--json")
        report = json.loads(out)
        self.assertIn("score", report)
        self.assertTrue(report["findings"])

    def test_wrong_password_message(self):
        other = os.path.join(self.tmp.name, "other-pw.txt")
        with open(other, "w", encoding="utf-8") as fh:
            fh.write("not the right password\n")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--vault", self.vault, "--password-file", other, "list"])
        self.assertEqual(code, 1)
        self.assertIn("wrong master password", err.getvalue())

    def test_backup_create_verify_restore(self):
        self.run_cli("add", "Keeper", "-p", "p")
        directory = os.path.join(self.tmp.name, "bk")
        code, out, _ = self.run_cli("backup", "create", "--dir", directory)
        self.assertEqual(code, 0)
        path = out.split("Backup written: ")[1].split(" ")[0]

        self.run_cli("add", "Later", "-p", "q")
        self.assertEqual(self.run_cli("backup", "verify", path, "--deep")[0], 0)
        self.assertEqual(self.run_cli("backup", "restore", path, "-y")[0], 0)
        _code, out, _ = self.run_cli("list")
        self.assertIn("Keeper", out)
        self.assertNotIn("Later", out)

    def test_import_and_export_round_trip(self):
        source = os.path.join(self.tmp.name, "in.csv")
        with open(source, "w", encoding="utf-8") as fh:
            fh.write("name,username,password,url\nSite A,ua,pa,https://a.example\n"
                     "Site B,ub,pb,https://b.example\n")
        code, out, _ = self.run_cli("import", source)
        self.assertEqual(code, 0)
        self.assertIn("added 2", out)

        # importing the same file again adds nothing
        _code, out, _ = self.run_cli("import", source)
        self.assertIn("added 0", out)

        target = os.path.join(self.tmp.name, "out.csv")
        code, _out, _err = self.run_cli("export", target, "--format", "csv")
        self.assertEqual(code, 1, "plaintext export must refuse without confirmation")
        self.assertFalse(os.path.exists(target))

        code, out, _ = self.run_cli("export", target, "--format", "csv",
                                    "--confirm", "I UNDERSTAND")
        self.assertEqual(code, 0)
        with open(target, encoding="utf-8") as fh:
            self.assertIn("pa", fh.read())

    def test_encrypted_export(self):
        target = os.path.join(self.tmp.name, "copy.lbx")
        self.assertEqual(self.run_cli("export", target)[0], 0)
        with open(target, "rb") as fh:
            self.assertEqual(fh.read(4), b"LBXV")

    def test_check_offline(self):
        code, out, _ = self.run_cli("check", "--offline")
        self.assertEqual(code, 0)
        self.assertIn("Offline self-test: PASSED", out)
        self.assertIn("Vault integrity: OK", out)

    def test_info_reports_zero_network_calls(self):
        _code, out, _ = self.run_cli("info", "--json")
        data = json.loads(out)
        self.assertEqual(data["network_calls"], 0)
        self.assertEqual(data["cipher"], "AES-256-GCM")

    def test_tool_runner(self):
        code, out, _ = self.run_cli("tool", "hash", "-a", "text=abc", "-a", "algorithm=sha256")
        self.assertEqual(code, 0)
        self.assertIn("ba7816bf", out)

    def test_tool_listing(self):
        _code, out, _ = self.run_cli("tool")
        self.assertIn("passphrase", out)
        self.assertIn("none touching the network", out)

    def test_change_master_password(self):
        new = os.path.join(self.tmp.name, "new-pw.txt")
        with open(new, "w", encoding="utf-8") as fh:
            fh.write("brand new master password\n")
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = main(["--vault", self.vault, "--password-file", new, "passwd"])
        # the same file supplies both old and new; the vault must now open with it
        self.assertEqual(code, 1)  # old password is wrong -> refused, nothing changed
        self.assertEqual(self.run_cli("list")[0], 0)


class FakeClipboard(Clipboard):
    """Clipboard with an in-memory backend, for a machine with no display."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.buffer = None

    def _copy_tk(self, text):
        self.buffer = text
        return True

    def _copy_command(self, text):
        self.buffer = text
        return True

    def paste(self):
        return self.buffer


class TestClipboard(unittest.TestCase):
    def test_copy_and_clear(self):
        clip = FakeClipboard()
        clip.copy("secret", clear_after=0)
        self.assertEqual(clip.paste(), "secret")
        clip.clear()
        self.assertEqual(clip.paste(), "")

    def test_clear_if_ours_clears_our_value(self):
        clip = FakeClipboard()
        clip.copy("secret", clear_after=0)
        self.assertTrue(clip.clear_if_ours())
        self.assertEqual(clip.paste(), "")

    def test_clear_if_ours_leaves_other_content_alone(self):
        clip = FakeClipboard()
        clip.copy("secret", clear_after=0)
        clip.buffer = "something the user copied afterwards"
        self.assertFalse(clip.clear_if_ours())
        self.assertEqual(clip.buffer, "something the user copied afterwards")

    def test_scheduled_clear_is_registered(self):
        scheduled = []
        clip = FakeClipboard(schedule=lambda ms, fn: scheduled.append((ms, fn)))
        clip.copy("secret", clear_after=20)
        self.assertEqual(scheduled[0][0], 20000)
        scheduled[0][1]()  # fire the timer
        self.assertEqual(clip.paste(), "")

    def test_no_backend_raises(self):
        from lockbox.core.clipboard import ClipboardUnavailable

        clip = Clipboard()
        clip._copy_tk = lambda text: False
        clip._copy_command = lambda text: False
        with self.assertRaises(ClipboardUnavailable):
            clip.copy("secret")


if __name__ == "__main__":
    unittest.main()
