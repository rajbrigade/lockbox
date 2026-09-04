"""Vault lifecycle, auto-lock, integrity and search tests."""

from __future__ import annotations

import sys
import os
import tempfile
import time
import unittest

from lockbox.core.errors import DecryptError, VaultFormatError, VaultLockedError
from lockbox.core.kdf import KDFParams
from lockbox.core.model import Item, normalise_payload
from lockbox.core.search import parse_query, search
from lockbox.core.vault import Vault, default_vault_path

POSIX_PERMS = sys.platform != "win32"
NO_PERMS_REASON = (
    "Windows has no POSIX mode bits; access is governed by NTFS ACLs, which a "
    "file created inside the user's own profile inherits correctly"
)


FAST = KDFParams("scrypt", b"0123456789abcdef", {"n": 1024, "r": 8, "p": 1})
PASSWORD = b"correct horse battery staple"


class VaultTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "vault.lbx")
        self.vault = Vault(self.path)
        self.vault.create(PASSWORD, FAST)

    def tearDown(self):
        self.vault.lock()
        self.tmp.cleanup()

    def add(self, **kwargs) -> Item:
        return self.vault.add(Item(**kwargs))


class TestLifecycle(VaultTestCase):
    def test_create_writes_a_file(self):
        self.assertTrue(os.path.exists(self.path))

    @unittest.skipUnless(POSIX_PERMS, NO_PERMS_REASON)
    def test_create_locks_down_the_file(self):
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_create_refuses_to_overwrite(self):
        with self.assertRaises(FileExistsError):
            Vault(self.path).create(PASSWORD, FAST)

    def test_round_trip_persists_every_field(self):
        original = self.add(
            title="GitHub", username="octo", password="s3cret", url="https://github.com",
            notes="line1\nline2", tags=["work", "dev"], folder="Dev", favorite=True,
            totp_secret="JBSWY3DPEHPK3PXP", fields={"recovery": "abc"},
        )
        self.vault.save()
        self.vault.lock()

        reopened = Vault(self.path)
        reopened.unlock(PASSWORD)
        restored = reopened.get(original.id)
        self.assertEqual(restored.to_dict(), original.to_dict())
        reopened.lock()

    def test_wrong_password_rejected(self):
        self.vault.save()
        self.vault.lock()
        with self.assertRaises(DecryptError):
            Vault(self.path).unlock(b"nope")

    def test_corrupt_vault_rejected(self):
        self.vault.save()
        self.vault.lock()
        with open(self.path, "r+b") as fh:
            fh.seek(-3, os.SEEK_END)
            fh.write(b"\x00\x00\x00")
        with self.assertRaises(DecryptError):
            Vault(self.path).unlock(PASSWORD)

    def test_truncated_vault_rejected(self):
        self.vault.save()
        self.vault.lock()
        with open(self.path, "rb") as fh:
            data = fh.read()
        with open(self.path, "wb") as fh:
            fh.write(data[: len(data) // 2])
        with self.assertRaises((DecryptError, VaultFormatError)):
            Vault(self.path).unlock(PASSWORD)

    def test_lock_drops_everything(self):
        self.add(title="x", password="y")
        self.vault.save()
        key_copy = bytes(self.vault._keys.dek)
        self.vault.lock()
        self.assertFalse(self.vault.unlocked)
        self.assertNotEqual(key_copy, b"\x00" * 32)
        with self.assertRaises(VaultLockedError):
            self.vault.items()
        with self.assertRaises(VaultLockedError):
            self.vault.save()

    def test_key_material_is_wiped_on_lock(self):
        keys = self.vault._keys
        self.vault.lock()
        self.assertEqual(bytes(keys.dek), b"\x00" * 32)

    def test_change_master_password(self):
        self.add(title="Item", password="p")
        self.vault.save()
        self.vault.change_master_password(b"a whole new password")
        self.vault.lock()
        with self.assertRaises(DecryptError):
            Vault(self.path).unlock(PASSWORD)
        reopened = Vault(self.path)
        reopened.unlock(b"a whole new password")
        self.assertEqual(len(reopened.items()), 1)
        reopened.lock()

    def test_previous_copy_kept_on_save(self):
        self.add(title="one")
        self.vault.save()
        self.add(title="two")
        self.vault.save()
        self.assertTrue(os.path.exists(self.path + ".prev"))

    def test_delete_scrubs_the_item(self):
        item = self.add(title="temp", password="secret-value")
        self.vault.delete(item.id)
        self.assertEqual(item.password, "")
        self.assertEqual(self.vault.items(), [])


class TestAutoLock(VaultTestCase):
    def test_locks_after_timeout(self):
        self.vault.set_setting("auto_lock_seconds", 1)
        self.vault._last_activity = time.monotonic() - 5
        self.assertTrue(self.vault.check_autolock())
        self.assertFalse(self.vault.unlocked)

    def test_does_not_lock_while_active(self):
        self.vault.set_setting("auto_lock_seconds", 60)
        self.vault.touch_activity()
        self.assertFalse(self.vault.check_autolock())
        self.assertTrue(self.vault.unlocked)

    def test_zero_disables_auto_lock(self):
        self.vault.set_setting("auto_lock_seconds", 0)
        self.vault._last_activity = time.monotonic() - 10_000
        self.assertFalse(self.vault.check_autolock())

    def test_unsaved_changes_are_flushed_before_locking(self):
        self.vault.set_setting("auto_lock_seconds", 1)
        self.add(title="unsaved work", password="p")
        self.vault._last_activity = time.monotonic() - 5
        self.vault.check_autolock()
        reopened = Vault(self.path)
        reopened.unlock(PASSWORD)
        self.assertEqual(len(reopened.items()), 1)
        reopened.lock()


class TestIntegrity(VaultTestCase):
    def test_healthy_vault_passes(self):
        self.add(title="a", password="b")
        self.vault.save()
        report = self.vault.integrity_check()
        self.assertTrue(report["ok"], report["errors"])
        self.assertEqual(report["item_count"], 1)
        if POSIX_PERMS:
            self.assertEqual(report["permissions"], "0o600")
        else:
            self.assertIn("Windows", report["permissions"])

    def test_damaged_vault_fails(self):
        self.vault.save()
        with open(self.path, "r+b") as fh:
            fh.seek(-1, os.SEEK_END)
            fh.write(b"\xff")
        report = self.vault.integrity_check()
        self.assertFalse(report["ok"])
        self.assertTrue(any("authenticates" in e for e in report["errors"]))


class TestDefaultPath(unittest.TestCase):
    """LOCKBOX_VAULT must be honoured in core, not only by the CLI parser --
    the GUI entry point takes no arguments and would otherwise ignore it."""

    def setUp(self):
        self._saved = os.environ.get("LOCKBOX_VAULT")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("LOCKBOX_VAULT", None)
        else:
            os.environ["LOCKBOX_VAULT"] = self._saved

    def test_env_override_is_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "elsewhere.lbx")
            os.environ["LOCKBOX_VAULT"] = target
            self.assertEqual(default_vault_path(), os.path.abspath(target))

    def test_without_the_env_var_the_data_dir_is_used(self):
        os.environ.pop("LOCKBOX_VAULT", None)
        self.assertTrue(default_vault_path().endswith("vault.lbx"))


class TestModel(unittest.TestCase):
    def test_password_history_records_the_old_value(self):
        item = Item(title="x", password="old")
        item.set_password("new", history_limit=3)
        self.assertEqual(item.password, "new")
        self.assertEqual(item.history[0]["password"], "old")

    def test_history_is_capped(self):
        item = Item(title="x", password="p0")
        for i in range(10):
            item.set_password(f"p{i + 1}", history_limit=3)
        self.assertEqual(len(item.history), 3)

    def test_setting_the_same_password_is_not_recorded(self):
        item = Item(title="x", password="same")
        item.set_password("same")
        self.assertEqual(item.history, [])

    def test_unknown_type_falls_back(self):
        self.assertEqual(Item.from_dict({"type": "wat"}).type, "note")

    def test_newer_schema_is_refused(self):
        with self.assertRaises(ValueError):
            normalise_payload({"schema": 999})

    def test_unknown_settings_are_dropped(self):
        payload = normalise_payload({"settings": {"auto_lock_seconds": 42, "evil": True}})
        self.assertEqual(payload["settings"]["auto_lock_seconds"], 42)
        self.assertNotIn("evil", payload["settings"])


class TestSearch(unittest.TestCase):
    def setUp(self):
        self.items = [
            Item(title="GitHub", username="octocat", url="https://github.com",
                 tags=["dev", "work"], folder="Dev", favorite=True,
                 totp_secret="JBSWY3DPEHPK3PXP", password="x"),
            Item(title="GitLab", username="fox", url="https://gitlab.com", tags=["dev"],
                 folder="Dev", password="y"),
            Item(title="Bank of Example", username="me@example.com",
                 url="https://bank.example.com", tags=["money"], type="login", password="z"),
            Item(title="Passport", type="identity", notes="private", folder="Personal"),
        ]

    def test_empty_query_returns_everything(self):
        self.assertEqual(len(search(self.items, "")), 4)

    def test_prefix_beats_substring(self):
        self.assertEqual(search(self.items, "git")[0].title, "GitHub")

    def test_fuzzy_subsequence(self):
        self.assertIn("GitHub", [i.title for i in search(self.items, "gthb")])

    def test_search_by_username_and_domain(self):
        self.assertEqual(search(self.items, "octocat")[0].title, "GitHub")
        self.assertEqual(search(self.items, "bank.example")[0].title, "Bank of Example")

    def test_filters(self):
        self.assertEqual(len(search(self.items, "type:identity")), 1)
        self.assertEqual(len(search(self.items, "tag:dev")), 2)
        self.assertEqual(len(search(self.items, "folder:dev")), 2)
        self.assertEqual(len(search(self.items, "fav:true")), 1)
        self.assertEqual(len(search(self.items, "has:totp")), 1)
        self.assertEqual(len(search(self.items, "user:fox")), 1)

    def test_filters_combine_with_text(self):
        self.assertEqual(len(search(self.items, "git tag:dev")), 2)
        self.assertEqual(len(search(self.items, "hub tag:dev")), 1)

    def test_no_match(self):
        self.assertEqual(search(self.items, "zzzzzz"), [])

    def test_secrets_are_not_searchable(self):
        """Matching on password text would leak it through the result list."""
        self.assertEqual(search(self.items, "JBSWY3DP"), [])
        secret_item = Item(title="Thing", password="unmistakable-secret-9")
        self.assertEqual(search([secret_item], "unmistakable"), [])

    def test_query_parsing(self):
        query = parse_query("hello type:login tag:a tag:b junk:x")
        self.assertEqual(query.filters["type"], ["login"])
        self.assertEqual(query.filters["tag"], ["a", "b"])
        self.assertIn("junk:x", query.text)

    def test_large_vault_search_is_fast(self):
        items = [Item(title=f"Item {i}", username=f"user{i}") for i in range(5000)]
        start = time.perf_counter()
        results = search(items, "item 4999")
        elapsed = time.perf_counter() - start
        self.assertTrue(results)
        self.assertLess(elapsed, 0.5, f"search took {elapsed:.3f}s over 5000 items")


if __name__ == "__main__":
    unittest.main()
