"""Import/export, backup/restore, security audit and breach-dataset tests."""

from __future__ import annotations

import sys
import hashlib
import json
import os
import tempfile
import time
import unittest

from lockbox.core import backup as backup_mod
from lockbox.core import breach as breach_mod
from lockbox.core import portio
from lockbox.core.audit import audit
from lockbox.core.errors import DecryptError
from lockbox.core.kdf import KDFParams
from lockbox.core.model import Item
from lockbox.core.vault import Vault

POSIX_PERMS = sys.platform != "win32"
NO_PERMS_REASON = (
    "Windows has no POSIX mode bits; access is governed by NTFS ACLs, which a "
    "file created inside the user's own profile inherits correctly"
)


FAST = KDFParams("scrypt", b"0123456789abcdef", {"n": 1024, "r": 8, "p": 1})
PASSWORD = b"a decent master password"

SAMPLE_CSV = """name,username,password,url,notes,folder,tags
GitHub,octocat,gh-pass-123,https://github.com,dev account,Dev,"work,code"
Bank,me@example.com,bank-pass-456,https://bank.example.com,,Money,money
,,,,,,
"""

BITWARDEN_JSON = json.dumps({
    "items": [
        {
            "type": 1, "name": "Reddit", "notes": "note text",
            "login": {"username": "u1", "password": "p1",
                      "uris": [{"uri": "https://reddit.com"}],
                      "totp": "JBSWY3DPEHPK3PXP"},
        },
        {"type": 2, "name": "Wifi code", "notes": "hunter2"},
    ]
})


class TestImport(unittest.TestCase):
    def test_csv(self):
        result = portio.import_csv(SAMPLE_CSV)
        self.assertEqual(len(result.items), 2)
        self.assertEqual(result.skipped, 1)
        github = result.items[0]
        self.assertEqual(github.title, "GitHub")
        self.assertEqual(github.username, "octocat")
        self.assertEqual(github.password, "gh-pass-123")
        self.assertEqual(github.tags, ["work", "code"])
        self.assertEqual(github.folder, "Dev")

    def test_csv_with_semicolons_and_odd_headers(self):
        text = "Title;Login Name;Password;Web Site\nX;u;p;https://x.example\n"
        result = portio.import_csv(text)
        self.assertEqual(len(result.items), 1)
        self.assertEqual(result.items[0].username, "u")
        self.assertEqual(result.items[0].url, "https://x.example")

    def test_csv_unknown_columns_become_custom_fields(self):
        text = "name,password,Security Question\nX,p,mother\n"
        item = portio.import_csv(text).items[0]
        self.assertEqual(item.fields["Security Question"], "mother")

    def test_csv_without_useful_columns_warns(self):
        result = portio.import_csv("a,b\n1,2\n")
        self.assertEqual(result.items, [])
        self.assertTrue(result.warnings)

    def test_bitwarden_style_json(self):
        result = portio.import_json(BITWARDEN_JSON)
        self.assertEqual(len(result.items), 2)
        reddit = result.items[0]
        self.assertEqual(reddit.username, "u1")
        self.assertEqual(reddit.url, "https://reddit.com")
        self.assertEqual(reddit.totp_secret, "JBSWY3DPEHPK3PXP")

    def test_bare_totp_secret_is_normalised(self):
        text = "name,password,totp\nX,p,jbsw y3dp ehpk 3pxp\n"
        self.assertEqual(portio.import_csv(text).items[0].totp_secret, "JBSWY3DPEHPK3PXP")

    def test_otpauth_uri_keeps_its_parameters(self):
        """A URI must survive import intact: digits/period/algorithm change the code."""
        from lockbox.tools.otp import parse_otpauth

        uri = ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&issuer=X"
               "&algorithm=SHA256&digits=8&period=60")
        text = f"name,password,totp\nX,p,{uri}\n"
        stored = portio.import_csv(text).items[0].totp_secret
        self.assertEqual(stored, uri)
        config = parse_otpauth(stored)
        self.assertEqual((config.algorithm, config.digits, config.period),
                         ("SHA256", 8, 60))

    def test_non_dict_rows_do_not_crash_import(self):
        result = portio.import_json('{"logins": ["junk", {"name": "X", "password": "p"}]}')
        self.assertEqual(len(result.items), 1)

    def test_invalid_json_warns(self):
        result = portio.import_json("{not json")
        self.assertEqual(result.items, [])
        self.assertTrue(result.warnings)

    def test_auto_detect(self):
        self.assertIn("JSON", portio.import_auto(BITWARDEN_JSON).source_format)
        self.assertIn("CSV", portio.import_auto(SAMPLE_CSV).source_format)

    def test_merge_skips_duplicates(self):
        existing = [Item(title="GitHub", username="octocat", password="gh-pass-123")]
        incoming = portio.import_csv(SAMPLE_CSV).items
        added, duplicates = portio.merge(existing, incoming)
        self.assertEqual(len(added), 1)
        self.assertEqual(duplicates, 1)

    def test_merge_keep_all(self):
        existing = [Item(title="GitHub", username="octocat", password="gh-pass-123")]
        added, duplicates = portio.merge(existing, portio.import_csv(SAMPLE_CSV).items,
                                         "keep_all")
        self.assertEqual(len(added), 2)
        self.assertEqual(duplicates, 0)


class TestExport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.items = [
            Item(title="A", username="u", password="p1", tags=["x"]),
            Item(title="B", username="v", password="p2", totp_secret="JBSWY3DPEHPK3PXP"),
        ]

    def tearDown(self):
        self.tmp.cleanup()

    def test_csv_round_trip(self):
        text = portio.export_csv(self.items)
        reimported = portio.import_csv(text).items
        self.assertEqual([i.title for i in reimported], ["A", "B"])
        self.assertEqual(reimported[0].password, "p1")

    def test_json_round_trip(self):
        reimported = portio.import_json(portio.export_json(self.items)).items
        self.assertEqual(len(reimported), 2)
        self.assertEqual(reimported[1].totp_secret, "JBSWY3DPEHPK3PXP")

    def test_plaintext_export_requires_the_exact_token(self):
        path = os.path.join(self.tmp.name, "out.csv")
        for bad in ("", "yes", "i understand", "I UNDERSTAND "):
            with self.assertRaises(PermissionError):
                portio.write_plaintext_export(path, self.items, "csv", confirm=bad)
        self.assertFalse(os.path.exists(path))

    def test_plaintext_export_writes_the_file(self):
        path = os.path.join(self.tmp.name, "out.csv")
        result = portio.write_plaintext_export(path, self.items, "csv",
                                               confirm=portio.CONFIRM_TOKEN)
        if POSIX_PERMS:
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(result["items"], 2)
        with open(path, encoding="utf-8") as fh:
            self.assertIn("p1", fh.read())

    def test_plaintext_export_refuses_sync_folders(self):
        directory = os.path.join(self.tmp.name, "Dropbox")
        os.makedirs(directory)
        with self.assertRaises(PermissionError):
            portio.write_plaintext_export(os.path.join(directory, "x.csv"), self.items,
                                          "csv", confirm=portio.CONFIRM_TOKEN)

    def test_shred_removes_the_file(self):
        path = os.path.join(self.tmp.name, "out.csv")
        portio.write_plaintext_export(path, self.items, "csv", confirm=portio.CONFIRM_TOKEN)
        self.assertTrue(portio.shred(path))
        self.assertFalse(os.path.exists(path))


class BackupTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "vault.lbx")
        self.backups = os.path.join(self.tmp.name, "backups")
        self.vault = Vault(self.path)
        self.vault.create(PASSWORD, FAST)
        self.vault.add(Item(title="One", username="u", password="p"))
        self.vault.save()

    def tearDown(self):
        self.vault.lock()
        self.tmp.cleanup()


class TestBackup(BackupTestCase):
    def test_create_and_list(self):
        info = backup_mod.create_backup(self.path, self.backups)
        self.assertTrue(os.path.exists(info.path))
        with open(self.path, "rb") as fh:
            self.assertEqual(info.sha256, hashlib.sha256(fh.read()).hexdigest())
        self.assertEqual(len(backup_mod.list_backups(self.backups)), 1)

    def test_backup_is_encrypted(self):
        info = backup_mod.create_backup(self.path, self.backups)
        with open(info.path, "rb") as fh:
            blob = fh.read()
        self.assertEqual(blob[:4], b"LBXV")
        self.assertNotIn(b"One", blob[200:])

    def test_verify_structure_and_decrypt(self):
        info = backup_mod.create_backup(self.path, self.backups)
        self.assertTrue(backup_mod.verify_backup(info.path)["structure_ok"])
        deep = backup_mod.verify_backup(info.path, PASSWORD)
        self.assertTrue(deep["decrypt_ok"])
        self.assertEqual(deep["items"], 1)

    def test_verify_detects_a_wrong_password(self):
        info = backup_mod.create_backup(self.path, self.backups)
        self.assertFalse(backup_mod.verify_backup(info.path, b"wrong")["decrypt_ok"])

    def test_verify_detects_damage(self):
        info = backup_mod.create_backup(self.path, self.backups)
        with open(info.path, "r+b") as fh:
            fh.seek(-1, os.SEEK_END)
            fh.write(b"\x00")
        self.assertFalse(backup_mod.verify_backup(info.path, PASSWORD)["decrypt_ok"])

    def test_pruning_keeps_the_newest(self):
        for i in range(5):
            backup_mod.create_backup(self.path, self.backups, keep=3, label=f"n{i}")
            time.sleep(0.01)
        self.assertEqual(len(backup_mod.list_backups(self.backups)), 3)

    def test_restore(self):
        info = backup_mod.create_backup(self.path, self.backups)
        self.vault.add(Item(title="Two", password="q"))
        self.vault.save()
        self.vault.lock()

        result = backup_mod.restore_backup(info.path, self.path, PASSWORD)
        self.assertEqual(result["items"], 1)
        reopened = Vault(self.path)
        reopened.unlock(PASSWORD)
        self.assertEqual([i.title for i in reopened.items()], ["One"])
        reopened.lock()
        self.assertTrue(os.path.exists(self.path + ".prev"))

    def test_restore_with_a_wrong_password_changes_nothing(self):
        info = backup_mod.create_backup(self.path, self.backups)
        self.vault.add(Item(title="Two", password="q"))
        self.vault.save()
        with open(self.path, "rb") as fh:
            before = fh.read()
        with self.assertRaises(DecryptError):
            backup_mod.restore_backup(info.path, self.path, b"wrong")
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), before)

    def test_reminder(self):
        now = int(time.time())
        self.assertTrue(backup_mod.needs_backup(now - 20 * 86400, 14, now))
        self.assertFalse(backup_mod.needs_backup(now - 3 * 86400, 14, now))
        self.assertFalse(backup_mod.needs_backup(0, 0, now))

    def test_encrypted_export_matches_the_vault(self):
        target = os.path.join(self.tmp.name, "copy.lbx")
        portio.export_encrypted(self.path, target)
        with open(target, "rb") as a, open(self.path, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_import_from_another_vault(self):
        other_path = os.path.join(self.tmp.name, "other.lbx")
        other = Vault(other_path)
        other.create(b"other master password", FAST)
        other.add(Item(title="Imported", username="x", password="y"))
        other.save()
        other.lock()
        result = portio.import_vault_file(other_path, b"other master password")
        self.assertEqual(len(result.items), 1)
        self.assertEqual(result.items[0].title, "Imported")


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.items = [
            Item(title="Weak", username="a", password="password", url="http://x.example"),
            Item(title="Reused 1", username="b", password="Shared-Pass-99!"),
            Item(title="Reused 2", username="c", password="Shared-Pass-99!"),
            Item(title="Short", username="d", password="abc"),
            Item(title="Empty login", username="e", password="", type="login"),
            Item(title="Old", username="f", password="Str0ng!Passw0rd#2024x",
                 password_updated=int(time.time()) - 86400 * 900),
            Item(title="Punycode", username="g", password="Str0ng!Passw0rd#77x",
                 url="https://xn--pple-43d.com"),
            Item(title="Good", username="h", password="9x!Kq2#vLm4$Zr7@Tb1&",
                 url="https://good.example", totp_secret="JBSWY3DPEHPK3PXP"),
        ]

    def kinds(self, report):
        return {f.kind for f in report.findings}

    def test_detects_every_category(self):
        report = audit(self.items, {"min_password_length": 12})
        found = self.kinds(report)
        for expected in ("common", "reused", "short", "empty", "old", "suspicious_url"):
            self.assertIn(expected, found)

    def test_reuse_is_reported_for_both_items(self):
        report = audit(self.items)
        reused = [f for f in report.findings if f.kind == "reused"]
        self.assertEqual(len(reused), 2)

    def test_clean_item_has_no_high_findings(self):
        report = audit(self.items)
        good_id = self.items[-1].id
        severe = [f for f in report.findings
                  if f.item_id == good_id and f.severity in ("critical", "high")]
        self.assertEqual(severe, [])

    def test_no_breach_claim_without_a_dataset(self):
        report = audit(self.items)
        self.assertNotIn("breached", self.kinds(report))
        self.assertIn("no local breach dataset", report.breach_status)

    def test_breach_claims_only_come_from_the_dataset(self):
        def lookup(password):
            return 42 if password == "password" else 0

        report = audit(self.items, breach_lookup=lookup)
        breached = [f for f in report.findings if f.kind == "breached"]
        self.assertEqual(len(breached), 1)
        self.assertIn("LOCAL", breached[0].message)

    def test_score_reflects_severity(self):
        clean = audit([self.items[-1]])
        messy = audit(self.items)
        self.assertGreater(clean.score(), messy.score())
        self.assertTrue(0 <= messy.score() <= 100)

    def test_stats(self):
        stats = audit(self.items).stats
        self.assertEqual(stats["items"], len(self.items))
        self.assertEqual(stats["reused_passwords"], 1)
        self.assertEqual(stats["with_totp"], 1)

    def test_empty_vault(self):
        report = audit([])
        self.assertEqual(report.findings, [])
        self.assertEqual(report.stats["items"], 0)


class TestBreachDataset(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.passwords = ["password", "hunter2", "letmein", "qwerty", "dragon123"]
        self.digests = sorted(
            hashlib.sha1(p.encode()).hexdigest().upper() for p in self.passwords
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _write_text(self, with_counts=True):
        path = os.path.join(self.tmp.name, "pwned.txt")
        with open(path, "w", encoding="ascii") as fh:
            for digest in self.digests:
                fh.write(f"{digest}:{7 if with_counts else ''}\n" if with_counts
                         else f"{digest}\n")
        return path

    def test_missing_dataset_reports_unavailable(self):
        self.assertIsNone(breach_mod.open_dataset(""))
        self.assertIsNone(breach_mod.open_dataset("/nonexistent/path"))
        status = breach_mod.status_for("")
        self.assertFalse(status.available)
        self.assertIn("not clean", status.describe())

    def test_text_dataset_lookup(self):
        dataset = breach_mod.open_dataset(self._write_text())
        self.assertEqual(dataset.kind, "sha1-text")
        for password in self.passwords:
            self.assertEqual(dataset.lookup(password), 7, password)
        self.assertEqual(dataset.lookup("a-password-that-is-not-in-the-set"), 0)

    def test_text_dataset_without_counts(self):
        dataset = breach_mod.open_dataset(self._write_text(with_counts=False))
        self.assertEqual(dataset.lookup("hunter2"), 1)
        self.assertEqual(dataset.lookup("nope"), 0)

    def test_binary_dataset(self):
        path = os.path.join(self.tmp.name, "pwned.bin")
        with open(path, "wb") as fh:
            for digest in self.digests:
                fh.write(bytes.fromhex(digest))
        dataset = breach_mod.open_dataset(path)
        self.assertEqual(dataset.kind, "sha1-binary")
        for password in self.passwords:
            self.assertEqual(dataset.lookup(password), 1, password)
        self.assertEqual(dataset.lookup("nope"), 0)

    def test_prefix_directory(self):
        directory = os.path.join(self.tmp.name, "prefixes")
        os.makedirs(directory)
        for digest in self.digests:
            with open(os.path.join(directory, digest[:5]), "a", encoding="ascii") as fh:
                fh.write(f"{digest[5:]}:3\n")
        dataset = breach_mod.open_dataset(directory)
        self.assertEqual(dataset.kind, "prefix-dir")
        self.assertEqual(dataset.lookup("qwerty"), 3)
        self.assertEqual(dataset.lookup("nope"), 0)

    def test_large_dataset_binary_search(self):
        """A dataset far bigger than the vault must still answer instantly."""
        path = os.path.join(self.tmp.name, "big.txt")
        digests = sorted(hashlib.sha1(f"pw{i}".encode()).hexdigest().upper()
                         for i in range(50000))
        with open(path, "w", encoding="ascii") as fh:
            for digest in digests:
                fh.write(f"{digest}:1\n")
        dataset = breach_mod.open_dataset(path)
        start = time.perf_counter()
        for i in (0, 1, 25000, 49999):
            self.assertEqual(dataset.lookup(f"pw{i}"), 1, i)
        self.assertEqual(dataset.lookup("definitely-not-present"), 0)
        self.assertLess(time.perf_counter() - start, 0.5)


if __name__ == "__main__":
    unittest.main()
