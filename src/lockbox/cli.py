"""Lockbox command line.

The CLI is a first-class interface, not a debug hatch: it exists so the whole
application can be scripted, audited and tested without a display server. The
GUI and the CLI call exactly the same core modules.

Master password input, in order:
  1. --password-file <path>  (read once, first line)
  2. LOCKBOX_PASSWORD        (testing/automation only; it is visible to other
                              processes in the environment -- avoid interactively)
  3. an interactive prompt via getpass (no echo)
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

from . import __version__
from .core import backup as backup_mod
from .core import breach as breach_mod
from .core import portio
from .core.audit import audit as run_audit
from .core.clipboard import Clipboard, ClipboardUnavailable
from .core.errors import DecryptError, LockboxError, VaultFormatError
from .core.model import ITEM_TYPES, Item
from .core.search import search as vault_search
from .core.vault import Vault, default_vault_path
from .tools import TOOLS, by_category, get as get_tool


# ------------------------------------------------------------------ helpers --
def _err(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def _read_password(args, prompt: str = "Master password: ", confirm: bool = False) -> bytes:
    path = getattr(args, "password_file", None)
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.readline().rstrip("\n").encode("utf-8")
    env = os.environ.get("LOCKBOX_PASSWORD")
    if env is not None:
        return env.encode("utf-8")
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n").encode("utf-8")
    while True:
        first = getpass.getpass(prompt)
        if not confirm:
            return first.encode("utf-8")
        second = getpass.getpass("Confirm master password: ")
        if first == second:
            return first.encode("utf-8")
        print("Passwords did not match. Try again.", file=sys.stderr)


def _open_vault(args) -> Vault:
    vault = Vault(args.vault)
    if not vault.exists:
        raise LockboxError(f"no vault at {vault.path}; run 'lockbox init' first")
    vault.unlock(_read_password(args))
    return vault


def _emit(data: Any, as_json: bool, text_fn=None) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str, ensure_ascii=False))
    elif text_fn:
        text_fn(data)
    else:
        print(data)


def _resolve(vault: Vault, needle: str) -> Item:
    if needle in {i.id for i in vault.items()}:
        return vault.get(needle)
    matches = vault_search(vault.items(), needle)
    if not matches:
        raise LockboxError(f"no item matches {needle!r}")
    if len(matches) > 1 and matches[0].title.lower() != needle.lower():
        listing = ", ".join(f"{m.title} [{m.id[:8]}]" for m in matches[:5])
        raise LockboxError(f"{needle!r} is ambiguous: {listing}")
    return matches[0]


def _row(item: Item) -> str:
    flags = "".join(("*" if item.favorite else " ", "T" if item.totp_secret else " "))
    return f"{item.id[:8]}  {flags}  {item.type:<8}  {item.title[:34]:<34}  {item.username[:26]}"


# ----------------------------------------------------------------- commands --
def cmd_init(args) -> int:
    vault = Vault(args.vault)
    if vault.exists:
        return _err(f"vault already exists at {vault.path}")
    password = _read_password(args, "Choose a master password: ", confirm=True)
    if len(password) < 8:
        return _err("master password must be at least 8 characters")
    start = time.perf_counter()
    vault.create(password)
    elapsed = time.perf_counter() - start
    print(f"Created {vault.path}")
    print(f"Key derivation: {vault.kdf_description()}  ({elapsed:.2f}s)")
    print("There is no recovery. If you forget this password the data is gone.")
    vault.lock()
    return 0


def cmd_add(args) -> int:
    vault = _open_vault(args)
    try:
        password = args.password or ""
        if args.generate:
            from .tools.generators import generate_password

            password = generate_password(length=args.length).value
        item = Item(
            type=args.type,
            title=args.title,
            username=args.username or "",
            password=password,
            url=args.url or "",
            notes=args.notes or "",
            folder=args.folder or "",
            tags=[t.strip() for t in (args.tags or "").split(",") if t.strip()],
            favorite=bool(args.favorite),
            totp_secret=args.totp or "",
        )
        if item.totp_secret:
            from .tools.otp import parse_otpauth

            item.totp_secret = parse_otpauth(item.totp_secret).secret
        vault.add(item)
        vault.save()
        print(f"Added {item.title} [{item.id[:8]}]")
        if args.generate and args.show:
            print(password)
        return 0
    finally:
        vault.lock()


def cmd_list(args) -> int:
    vault = _open_vault(args)
    try:
        items = vault_search(vault.items(), args.query or "", limit=args.limit)
        if args.json:
            payload = [
                {k: v for k, v in i.to_dict().items()
                 if k not in ("password", "totp_secret", "history", "notes")}
                for i in items
            ]
            print(json.dumps(payload, indent=2))
        else:
            if not items:
                print("(no matches)")
            for item in items:
                print(_row(item))
            print(f"\n{len(items)} item(s) of {len(vault.items())}")
        return 0
    finally:
        vault.lock()


def cmd_show(args) -> int:
    vault = _open_vault(args)
    try:
        item = _resolve(vault, args.query)
        data = item.to_dict()
        if not args.reveal:
            for key in ("password", "totp_secret"):
                if data.get(key):
                    data[key] = "<hidden - use --reveal>"
            data["history"] = f"{len(item.history)} previous password(s)"
        if args.json:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        else:
            for key, value in data.items():
                if value in ("", [], {}, None):
                    continue
                print(f"{key:<18} {value}")
            if item.totp_secret and args.reveal:
                from .tools.otp import OTPConfig, current

                code = current(OTPConfig(secret=item.totp_secret, label=item.title))
                print(f"{'totp_now':<18} {code['code']}  ({code['seconds_remaining']}s left)")
        if args.copy:
            clip = Clipboard()
            try:
                clip.copy(item.password, clear_after=0)
                print("Password copied. Run 'lockbox clip --clear' when done.")
            except ClipboardUnavailable as exc:
                return _err(str(exc))
        return 0
    finally:
        vault.lock()


def cmd_edit(args) -> int:
    vault = _open_vault(args)
    try:
        item = _resolve(vault, args.query)
        changed = []
        for field_name in ("title", "username", "url", "notes", "folder"):
            value = getattr(args, field_name, None)
            if value is not None:
                setattr(item, field_name, value)
                changed.append(field_name)
        if args.tags is not None:
            item.tags = [t.strip() for t in args.tags.split(",") if t.strip()]
            changed.append("tags")
        if args.favorite is not None:
            item.favorite = args.favorite
            changed.append("favorite")
        if args.generate or args.password is not None:
            from .tools.generators import generate_password

            new_password = (
                generate_password(length=args.length).value if args.generate else args.password
            )
            item.set_password(new_password, int(vault.settings["history_limit"]))
            changed.append("password")
        if not changed:
            return _err("nothing to change")
        vault.update(item)
        vault.save()
        print(f"Updated {item.title} [{item.id[:8]}]: {', '.join(changed)}")
        return 0
    finally:
        vault.lock()


def cmd_rm(args) -> int:
    vault = _open_vault(args)
    try:
        item = _resolve(vault, args.query)
        if not args.yes:
            answer = input(f"Delete {item.title!r}? [y/N] ").strip().lower()
            if answer != "y":
                print("Cancelled.")
                return 0
        vault.delete(item.id)
        vault.save()
        print(f"Deleted {item.title}")
        return 0
    finally:
        vault.lock()


def cmd_totp(args) -> int:
    from .tools.otp import OTPConfig, current

    vault = _open_vault(args)
    try:
        item = _resolve(vault, args.query)
        if not item.totp_secret:
            return _err(f"{item.title} has no TOTP secret")
        config = OTPConfig(secret=item.totp_secret, label=item.title)
        if not args.watch:
            result = current(config)
            print(f"{result['code']}   ({result['seconds_remaining']}s remaining)")
            return 0
        try:
            while True:
                result = current(config)
                remaining = result["seconds_remaining"]
                bar = "#" * int(remaining) + "." * (config.period - int(remaining))
                print(f"\r{result['code']}  [{bar}] {remaining:>4}s ", end="", flush=True)
                time.sleep(0.5)
        except KeyboardInterrupt:
            print()
            return 0
    finally:
        vault.lock()


def cmd_gen(args) -> int:
    from .tools.generators import (
        generate_api_key, generate_passphrase, generate_password, generate_pronounceable,
    )

    if args.kind == "passphrase":
        result = generate_passphrase(words=args.words, separator=args.separator,
                                     capitalize=args.capitalize, add_number=args.number)
    elif args.kind == "pronounceable":
        result = generate_pronounceable(length=args.length)
    elif args.kind == "apikey":
        result = generate_api_key(prefix=args.prefix, nbytes=max(16, args.length))
    else:
        result = generate_password(
            length=args.length, uppercase=not args.no_upper, digits=not args.no_digits,
            symbols=not args.no_symbols, exclude=args.exclude,
            exclude_ambiguous=args.no_ambiguous,
        )
    for _ in range(max(1, args.count) - 1):
        print(result.value)
        result = generate_password(length=args.length) if args.kind == "password" else result
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.value)
        if not args.quiet:
            from .tools.analysis import strength_label

            print(
                f"  {result.entropy_bits:.1f} bits ({strength_label(result.entropy_bits)})"
                f"  alphabet={result.alphabet_size}",
                file=sys.stderr,
            )
    return 0


def cmd_audit(args) -> int:
    vault = _open_vault(args)
    try:
        dataset = breach_mod.open_dataset(vault.settings.get("breach_dataset_path", ""))
        lookup = dataset.lookup if dataset else None
        report = run_audit(vault.items(), vault.settings, breach_lookup=lookup)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
            return 0
        stats = report.stats
        print(f"Vault health: {report.score()}/100")
        print(f"  items {stats['items']}, with passwords {stats['items_with_passwords']}, "
              f"reused {stats['reused_passwords']}, with TOTP {stats['with_totp']}")
        print(f"  breach: {report.breach_status}")
        if not report.findings:
            print("\nNo findings. Clean vault.")
            return 0
        grouped = report.by_severity()
        for severity in ("critical", "high", "medium", "low", "info"):
            findings = grouped.get(severity) or []
            if not findings or (args.severity and severity != args.severity):
                continue
            print(f"\n{severity.upper()} ({len(findings)})")
            for finding in findings[: args.limit or None]:
                print(f"  {finding.title[:32]:<32} {finding.message}")
                if finding.detail and args.verbose:
                    print(f"    {finding.detail}")
        return 0
    finally:
        vault.lock()


def cmd_backup(args) -> int:
    vault = Vault(args.vault)
    if args.action == "create":
        info = backup_mod.create_backup(vault.path, args.dir, keep=args.keep, label=args.label)
        _emit(info.to_dict(), args.json, lambda d: print(f"Backup written: {d['path']} "
                                                         f"({d['size']} bytes)"))
        return 0
    directory = args.dir or backup_mod.default_backup_dir(vault.path)
    if args.action == "list":
        backups = [b.to_dict() for b in backup_mod.list_backups(directory)]
        if args.json:
            print(json.dumps(backups, indent=2))
        elif not backups:
            print(f"No backups in {directory}")
        else:
            for entry in backups:
                print(f"{entry['created_human']}  {entry['size']:>8}B  {entry['path']}")
        return 0
    if args.action == "verify":
        password = _read_password(args) if args.deep else None
        result = backup_mod.verify_backup(args.path, password)
        _emit(result, args.json, lambda d: print(
            f"structure_ok={d['structure_ok']} decrypt_ok={d['decrypt_ok']} "
            f"items={d['items']} {d['error']}"))
        return 0 if result["structure_ok"] and result["decrypt_ok"] is not False else 1
    if args.action == "restore":
        password = _read_password(args)
        if not args.yes:
            answer = input(f"Replace {vault.path} with {args.path}? [y/N] ").strip().lower()
            if answer != "y":
                print("Cancelled.")
                return 0
        result = backup_mod.restore_backup(args.path, vault.path, password)
        _emit(result, args.json, lambda d: print(
            f"Restored {d['items']} item(s). Previous vault kept at {d['previous_kept_at']}"))
        return 0
    return _err("unknown backup action")


def cmd_export(args) -> int:
    vault = Vault(args.vault)
    if args.format == "encrypted":
        result = portio.export_encrypted(vault.path, args.path)
        _emit(result, args.json, lambda d: print(f"Encrypted export: {d['path']}"))
        return 0
    unlocked = _open_vault(args)
    try:
        print(portio.PLAINTEXT_WARNING, file=sys.stderr)
        if args.confirm != portio.CONFIRM_TOKEN:
            return _err(f"refusing plaintext export without --confirm '{portio.CONFIRM_TOKEN}'")
        result = portio.write_plaintext_export(
            args.path, unlocked.items(), fmt=args.format, confirm=args.confirm
        )
        _emit(result, args.json, lambda d: print(
            f"Wrote {d['items']} item(s) in the clear to {d['path']} (mode {d['permissions']})"))
        return 0
    finally:
        unlocked.lock()


def cmd_import(args) -> int:
    vault = _open_vault(args)
    try:
        if args.format == "vault":
            source_password = _read_password(args, "Password for the source vault: ")
            result = portio.import_vault_file(args.path, source_password)
        else:
            with open(args.path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            result = portio.import_auto(text, args.path)
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        added, duplicates = portio.merge(
            vault.items(), result.items,
            "keep_all" if args.keep_duplicates else "skip_duplicates",
        )
        if args.dry_run:
            print(f"{result.summary()}; would add {len(added)}, skip {duplicates} duplicate(s)")
            return 0
        vault.add_many(added)
        vault.save()
        print(f"{result.summary()}; added {len(added)}, skipped {duplicates} duplicate(s)")
        return 0
    finally:
        vault.lock()


def cmd_tools(args) -> int:
    if args.tool_id:
        tool = get_tool(args.tool_id)
        kwargs: Dict[str, Any] = {}
        for pair in args.arg or []:
            key, _, value = pair.partition("=")
            kwargs[key] = _coerce(value)
        result = tool(**kwargs)
        if hasattr(result, "to_dict"):
            result = result.to_dict()
        if args.json or isinstance(result, (dict, list)):
            print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        else:
            print(result)
        return 0
    for category, tools in by_category().items():
        print(f"\n{category}")
        for tool in tools:
            print(f"  {tool.id:<18} {tool.summary}")
    print(f"\n{len(TOOLS)} tools, all local, none touching the network.")
    return 0


def _coerce(value: str) -> Any:
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered == "none":
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def cmd_check(args) -> int:
    """Integrity + offline self-check."""
    from .tools.misc import environment_report

    report: Dict[str, Any] = {"environment": environment_report()}
    vault = Vault(args.vault)
    if vault.exists:
        vault.unlock(_read_password(args))
        try:
            report["integrity"] = vault.integrity_check()
        finally:
            vault.lock()
    if args.offline:
        report["offline_selftest"] = _offline_selftest()
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0
    env = report["environment"]
    print(f"Python {env['python']}  Argon2={env['argon2_available']}  Tk={env['tk_available']}")
    print(f"Clipboard backends: {', '.join(env['clipboard_backends']) or 'none found'}")
    if "integrity" in report:
        integrity = report["integrity"]
        print(f"\nVault integrity: {'OK' if integrity['ok'] else 'FAILED'}  "
              f"({integrity.get('item_count', '?')} items, {integrity['file_size']} bytes, "
              f"mode {integrity['permissions']})")
        for check in integrity["checks"]:
            print(f"  [{'ok' if check['ok'] else 'FAIL'}] {check['name']}"
                  + (f" - {check.get('detail')}" if not check["ok"] else ""))
    if "offline_selftest" in report:
        result = report["offline_selftest"]
        print(f"\nOffline self-test: {'PASSED' if result['passed'] else 'FAILED'}")
        for line in result["steps"]:
            print(f"  [{'ok' if line['ok'] else 'FAIL'}] {line['name']}")
    ok = report.get("integrity", {}).get("ok", True) and report.get(
        "offline_selftest", {}).get("passed", True)
    return 0 if ok else 1


def _offline_selftest() -> Dict[str, Any]:
    """Exercise the core with all sockets disabled.

    Any attempt to open a socket raises, so a network dependency that crept in
    anywhere on these paths fails the test loudly instead of silently working
    on a developer machine that happens to be online.
    """
    import socket
    import tempfile

    steps: List[Dict[str, Any]] = []
    original = socket.socket

    class _Blocked(socket.socket):
        def __init__(self, *a, **k):
            raise OSError("network access is blocked during the offline self-test")

    def step(name: str, fn) -> None:
        try:
            fn()
            steps.append({"name": name, "ok": True})
        except Exception as exc:
            steps.append({"name": name, "ok": False, "detail": f"{type(exc).__name__}: {exc}"})

    socket.socket = _Blocked  # type: ignore[misc]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "selftest.lbx")
            state: Dict[str, Any] = {}

            def create():
                from .core.kdf import KDFParams, SCRYPT_DEFAULTS
                from .core.crypto import random_bytes

                vault = Vault(path)
                # scrypt keeps the self-test fast; the real vault uses Argon2id.
                vault.create(b"offline-selftest", KDFParams("scrypt", random_bytes(16),
                                                            {"n": 4096, "r": 8, "p": 1}))
                state["vault"] = vault

            step("create encrypted vault", create)
            step("add and save item", lambda: (
                state["vault"].add(Item(title="Offline", username="a", password="Correct-Horse-9")),
                state["vault"].save(),
            ))
            step("lock and reopen", lambda: (
                state["vault"].lock(), state["vault"].unlock(b"offline-selftest")
            ))
            step("search", lambda: _assert(vault_search(state["vault"].items(), "offl")))
            step("generate password", lambda: __import__(
                "lockbox.tools.generators", fromlist=["x"]).generate_password(length=24))
            step("generate TOTP code", lambda: __import__(
                "lockbox.tools.otp", fromlist=["x"]).totp("JBSWY3DPEHPK3PXP"))
            step("generate QR code", lambda: __import__(
                "lockbox.tools.qr", fromlist=["x"]).encode("otpauth://totp/x?secret=JBSWY3DP"))
            step("security audit", lambda: run_audit(state["vault"].items(),
                                                     state["vault"].settings))
            step("integrity check", lambda: _assert(state["vault"].integrity_check()["ok"]))
            step("backup and verify", lambda: _assert(
                backup_mod.verify_backup(
                    backup_mod.create_backup(path, os.path.join(tmp, "b")).path,
                    b"offline-selftest")["decrypt_ok"]))
            step("wrong password rejected", lambda: _expect_error(
                lambda: Vault(path).unlock(b"wrong"), DecryptError))
            state["vault"].lock()
    finally:
        socket.socket = original  # type: ignore[misc]
    return {"passed": all(s["ok"] for s in steps), "steps": steps}


def _assert(value) -> None:
    if not value:
        raise AssertionError("check returned a falsy value")


def _expect_error(fn, exc_type) -> None:
    try:
        fn()
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__}")


def cmd_passwd(args) -> int:
    vault = _open_vault(args)
    try:
        new_password = _read_password(args, "New master password: ", confirm=True)
        if len(new_password) < 8:
            return _err("master password must be at least 8 characters")
        vault.change_master_password(new_password)
        print("Master password changed. Existing backups still use the old one.")
        return 0
    finally:
        vault.lock()


def cmd_clip(args) -> int:
    clip = Clipboard()
    if args.clear:
        print("Clipboard cleared." if clip.clear() else "No clipboard backend available.")
        return 0
    return _err("use 'lockbox clip --clear'")


def cmd_info(args) -> int:
    vault = Vault(args.vault)
    info: Dict[str, Any] = {
        "version": __version__,
        "vault_path": vault.path,
        "vault_exists": vault.exists,
        "network_calls": 0,
    }
    if vault.exists:
        blob = open(vault.path, "rb").read()
        header, _, _ = __import__("lockbox.core.vaultfile", fromlist=["x"]).parse_header(blob)
        info["size_bytes"] = len(blob)
        info["cipher"] = header.get("cipher")
        info["kdf"] = header.get("kdf", {}).get("algorithm")
        info["kdf_params"] = header.get("kdf", {}).get("params")
    _emit(info, args.json, lambda d: [print(f"{k:<16} {v}") for k, v in d.items()])
    return 0


# ------------------------------------------------------------------- parser --
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lockbox",
        description="Offline, local-only password manager. Makes no network requests.",
    )
    parser.add_argument("--version", action="version", version=f"lockbox {__version__}")
    parser.add_argument("--vault", default=os.environ.get("LOCKBOX_VAULT") or default_vault_path(),
                        help="path to the vault file")
    parser.add_argument("--password-file", help="read the master password from this file")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    # --json is accepted both before and after the subcommand. SUPPRESS keeps
    # the subparser from resetting a value already given globally.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="machine-readable output")

    class Sub:
        """Small wrapper so every subparser inherits the common options."""

        def __init__(self, subparsers):
            self._subparsers = subparsers

        def add_parser(self, name, **kwargs):
            kwargs.setdefault("parents", [common])
            return self._subparsers.add_parser(name, **kwargs)

    sub = Sub(parser.add_subparsers(dest="command", required=True))

    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)

    add = sub.add_parser("add", help="add an item")
    add.add_argument("title")
    add.add_argument("--type", choices=ITEM_TYPES, default="login")
    add.add_argument("--username", "-u")
    add.add_argument("--password", "-p")
    add.add_argument("--generate", "-g", action="store_true", help="generate the password")
    add.add_argument("--length", type=int, default=20)
    add.add_argument("--show", action="store_true", help="print the generated password")
    add.add_argument("--url")
    add.add_argument("--notes")
    add.add_argument("--folder")
    add.add_argument("--tags")
    add.add_argument("--totp", help="base32 secret or otpauth:// URI")
    add.add_argument("--favorite", action="store_true")
    add.set_defaults(func=cmd_add)

    ls = sub.add_parser("list", help="list or search items")
    ls.add_argument("query", nargs="?", default="")
    ls.add_argument("--limit", type=int, default=0)
    ls.set_defaults(func=cmd_list)

    show = sub.add_parser("show", help="show one item")
    show.add_argument("query")
    show.add_argument("--reveal", action="store_true", help="print secrets")
    show.add_argument("--copy", action="store_true", help="copy the password instead")
    show.set_defaults(func=cmd_show)

    edit = sub.add_parser("edit", help="edit an item")
    edit.add_argument("query")
    edit.add_argument("--title")
    edit.add_argument("--username")
    edit.add_argument("--password")
    edit.add_argument("--generate", "-g", action="store_true")
    edit.add_argument("--length", type=int, default=20)
    edit.add_argument("--url")
    edit.add_argument("--notes")
    edit.add_argument("--folder")
    edit.add_argument("--tags")
    edit.add_argument("--favorite", type=lambda v: v.lower() in ("1", "true", "yes"), default=None)
    edit.set_defaults(func=cmd_edit)

    rm = sub.add_parser("rm", help="delete an item")
    rm.add_argument("query")
    rm.add_argument("--yes", "-y", action="store_true")
    rm.set_defaults(func=cmd_rm)

    totp = sub.add_parser("totp", help="show a TOTP code")
    totp.add_argument("query")
    totp.add_argument("--watch", "-w", action="store_true")
    totp.set_defaults(func=cmd_totp)

    gen = sub.add_parser("gen", help="generate a secret (no vault needed)")
    gen.add_argument("kind", nargs="?", default="password",
                     choices=["password", "passphrase", "pronounceable", "apikey"])
    gen.add_argument("--length", "-l", type=int, default=20)
    gen.add_argument("--count", "-n", type=int, default=1)
    gen.add_argument("--words", type=int, default=6)
    gen.add_argument("--separator", default="-")
    gen.add_argument("--capitalize", action="store_true")
    gen.add_argument("--number", action="store_true")
    gen.add_argument("--prefix", default="")
    gen.add_argument("--no-upper", action="store_true")
    gen.add_argument("--no-digits", action="store_true")
    gen.add_argument("--no-symbols", action="store_true")
    gen.add_argument("--no-ambiguous", action="store_true")
    gen.add_argument("--exclude", default="")
    gen.add_argument("--quiet", "-q", action="store_true")
    gen.set_defaults(func=cmd_gen)

    audit_p = sub.add_parser("audit", help="run the local security audit")
    audit_p.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"])
    audit_p.add_argument("--limit", type=int, default=0)
    audit_p.add_argument("--verbose", "-v", action="store_true")
    audit_p.set_defaults(func=cmd_audit)

    backup_p = sub.add_parser("backup", help="local encrypted backups")
    backup_p.add_argument("action", choices=["create", "list", "verify", "restore"])
    backup_p.add_argument("path", nargs="?", help="backup file (verify/restore)")
    backup_p.add_argument("--dir", help="backup directory")
    backup_p.add_argument("--keep", type=int, default=10)
    backup_p.add_argument("--label", default="")
    backup_p.add_argument("--deep", action="store_true", help="decrypt while verifying")
    backup_p.add_argument("--yes", "-y", action="store_true")
    backup_p.set_defaults(func=cmd_backup)

    export = sub.add_parser("export", help="export the vault")
    export.add_argument("path")
    export.add_argument("--format", choices=["encrypted", "csv", "json"], default="encrypted")
    export.add_argument("--confirm", default="", help=f"required for plaintext: {portio.CONFIRM_TOKEN!r}")
    export.set_defaults(func=cmd_export)

    imp = sub.add_parser("import", help="import items")
    imp.add_argument("path")
    imp.add_argument("--format", choices=["auto", "csv", "json", "vault"], default="auto")
    imp.add_argument("--keep-duplicates", action="store_true")
    imp.add_argument("--dry-run", action="store_true")
    imp.set_defaults(func=cmd_import)

    tools_p = sub.add_parser("tool", help="run a micro-tool")
    tools_p.add_argument("tool_id", nargs="?")
    tools_p.add_argument("--arg", "-a", action="append", metavar="KEY=VALUE")
    tools_p.set_defaults(func=cmd_tools)

    check = sub.add_parser("check", help="integrity and offline self-test")
    check.add_argument("--offline", action="store_true", help="run with sockets blocked")
    check.set_defaults(func=cmd_check)

    sub.add_parser("passwd", help="change the master password").set_defaults(func=cmd_passwd)

    clip = sub.add_parser("clip", help="clipboard utilities")
    clip.add_argument("--clear", action="store_true")
    clip.set_defaults(func=cmd_clip)

    sub.add_parser("info", help="vault and build information").set_defaults(func=cmd_info)

    gui = sub.add_parser("gui", help="launch the desktop interface")
    gui.set_defaults(func=cmd_gui)
    return parser


def cmd_gui(args) -> int:
    try:
        from .ui.app import main as gui_main
    except ImportError as exc:
        return _err(f"the GUI needs Tk: {exc}. On Debian/Ubuntu: apt install python3-tk")
    return gui_main(args.vault)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except DecryptError:
        return _err("wrong master password, or the vault has been tampered with")
    except VaultFormatError as exc:
        return _err(f"vault problem: {exc}")
    except LockboxError as exc:
        return _err(str(exc))
    except FileNotFoundError as exc:
        return _err(f"file not found: {exc}")
    except PermissionError as exc:
        return _err(str(exc))
    except KeyboardInterrupt:
        print()
        return 130
    except BrokenPipeError:
        # `lockbox tool | head` closes the pipe early; exit quietly.
        try:
            sys.stdout.close()
        finally:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    sys.exit(main())
