# Lockbox

An offline password manager. One window, one encrypted file, no network code.

Lockbox is built to be small enough to read. The whole application is about
6,500 lines of Python across 30 files, with two third-party dependencies —
both of them audited cryptography libraries that exist because you should never
hand-write AES or Argon2. The GUI is Tk, which ships with Python, so there is no
browser engine, no bundled runtime, no node_modules.

**This application is designed to operate without network connectivity.** It
makes zero network requests during normal operation, and that claim is enforced
by tests rather than asserted in prose — see [docs/OFFLINE.md](docs/OFFLINE.md).

---

## Install

**Get the ZIP, not the individual files.** Four files in this project are named
`__init__.py`; saving them one at a time into a single folder makes them
overwrite each other, and `pip install -e .` then fails with
`error in 'egg_base' option: 'src' does not exist`. If that already happened,
run `python repair_layout.py --apply` in the flat folder — it puts everything
back, including browser-renamed duplicates like `__init__ (1).py`.


```bash
pip install -r requirements.txt
pip install -e .
```

Tk usually comes with Python. On Debian/Ubuntu it is a separate package:

```bash
sudo apt install python3-tk       # only needed for the GUI
```

Lockbox runs without Tk — the CLI is complete on its own.

## Or build a standalone executable

No Python on the target machine? Freeze it:

```bash
pip install -r requirements-dev.txt
python3 build.py              # dist/lockbox and dist/lockbox-gui
python3 build.py --onedir     # ~3x faster startup, ships as a folder
python3 verify_binary.py dist/lockbox
```

`build.py` runs the test suite first and refuses to build if it fails, then puts
the finished binary through 18 black-box checks — including its own offline
self-test and a scan of the artefact for embedded networking modules.

**PyInstaller cannot cross-compile: a Windows `.exe` must be built on Windows.**
Tag a release and the included GitHub Actions workflow builds and verifies all
three platforms. Details, signing, and troubleshooting:
[docs/BUILDING.md](docs/BUILDING.md).

| Frozen CLI (measured, Linux x64) | One file | One directory |
| --- | --- | --- |
| Size | 11.6 MB | 31.3 MB folder |
| Startup | 288 ms | 115 ms |
| Peak RSS during unlock | 92 MB | 92 MB |
| Verification checks passed | 18/18 | 18/18 |

A built-and-verified Linux x64 one-file binary is included as
`lockbox-linux-x64` (the output mount strips the execute bit, so
`chmod +x lockbox-linux-x64` first). There is no `.exe` in this tree because it
cannot be produced on Linux — build it on Windows or via the workflow.

## Use

```bash
lockbox init                      # create the vault (asks for a master password)
lockbox gui                       # desktop window
lockbox add GitHub -u octocat -g  # add an item with a generated password
lockbox list                      # list / search
lockbox show github --reveal      # print secrets
lockbox totp github --watch       # live TOTP with a countdown
lockbox audit                     # local security audit
lockbox backup create             # encrypted backup
lockbox check --offline           # integrity + prove it works with sockets blocked
lockbox gen passphrase --words 6  # generate without touching the vault
lockbox tool                      # list all 41 micro-tools
```

The vault lives at `~/.local/share/lockbox/vault.lbx` (`%LOCALAPPDATA%` on
Windows, `~/Library/Application Support` on macOS). Override with `--vault` or
`LOCKBOX_VAULT`.

### Keyboard

| Key | Action |
| --- | --- |
| `Ctrl/Cmd+K` | Command palette |
| `Ctrl+F` | Search |
| `Ctrl+N` | New item |
| `Ctrl+S` | Save |
| `Ctrl+Shift+C` | Copy password (auto-clears) |
| `Ctrl+T` | Micro Tools |
| `Ctrl+B` | Backup |
| `Ctrl+L` | Lock |

## What is inside

- **Vault** — single encrypted file. Argon2id → key-encryption key → AES-256-GCM
  wrapped data key → AES-256-GCM over the zlib-compressed payload. The plaintext
  header is authenticated, so KDF parameters cannot be downgraded.
- **Items** — logins, secure notes, cards, identities, API keys; folders, tags,
  favourites, custom fields, per-item password history, TOTP secrets.
- **Search** — instant, fuzzy, with `type:`, `tag:`, `folder:`, `user:`, `url:`,
  `fav:`, `has:totp` filters. Secrets are deliberately *not* searchable.
- **Security audit** — weak, reused, duplicate, empty, short, stale, missing
  TOTP, plain-HTTP and punycode URLs. It never says "breached" unless a local
  breach dataset actually matched.
- **41 micro-tools** — generators (password, passphrase, pronounceable, API key,
  token, recovery codes, UUID, username, TOTP secret), analysis (strength,
  entropy, character inspector, password age, URL inspector), one-time codes
  (TOTP, HOTP, otpauth parsing, QR generation), encoders (base64/32/hex/URL,
  JSON format/validate, regex tester), hashes (SHA-2/SHA-3/BLAKE2, HMAC,
  constant-time compare) and text transforms.
- **Backups** — byte-for-byte encrypted copies, verified by decryption, restored
  only after the backup has been proven to open.

## Measured, not claimed

Run `make bench` to reproduce on your hardware. These are from one run on a
single-core Linux VM (Python 3.12.3, x86-64) — not a fast machine:

| | |
| --- | --- |
| Source size | 241 KiB, 30 files, 6,475 lines |
| Direct dependencies | 2 (`cryptography`, `argon2-cffi`) |
| Core import time | 55 ms |
| CLI end-to-end (`lockbox gen`) | 114 ms including interpreter start |
| Resident memory, 100-item vault open | 28.8 MB |
| Resident memory, 1,000-item vault open | 32.3 MB |
| Peak memory during unlock | 93 MB (Argon2's 64 MiB buffer, released immediately) |
| Unlock, 1,000 items | 0.22 s (deliberately slow: that is the KDF) |
| Save, 1,000 items | 15 ms |
| Vault file, 1,000 items | 52 KiB (53 bytes/item) |
| Search, 1,000 items | 6.8 ms exact, 4.3 ms fuzzy, 1.7 ms filtered |
| Security audit, 1,000 items | 98 ms |
| Generate a password | 0.05 ms |
| Generate a TOTP code | 0.008 ms |
| Generate a QR code | 6 ms |
| Idle CPU | 0% — one `after()` tick per second that compares two numbers |
| Network requests | 0 |

The KDF is the only slow thing, on purpose: 64 MiB and three passes is what
makes a stolen vault expensive to attack.

## Testing

```bash
python3 run_tests.py            # 218 tests, ~15 s
python3 run_tests.py offline -v # just the offline/no-network proofs
```

The suite uses RFC test vectors where standards define them (RFC 4226 HOTP,
RFC 6238 TOTP for SHA-1/256/512, RFC 4648 base encodings, RFC 4231 HMAC,
RFC 5869 HKDF), flips every single bit of a ciphertext to prove tampering is
caught, and cross-checks the hand-written QR encoder against a reference
implementation. See [docs/TESTING.md](docs/TESTING.md).

## Honest limitations

- **A forgotten master password means the data is gone.** There is no recovery,
  no backdoor, no reset link. That is the design.
- **Memory hygiene is best-effort.** CPython cannot reliably erase immutable
  `str`/`bytes`. Keys are held in `bytearray` and wiped; decrypted item strings
  are not, and cannot be. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Lockbox cannot protect you from your own machine.** Malware running as your
  user, a keylogger, or a compromised Python install defeat it.
- **Breach checking only works with a dataset you already have locally.** With
  no dataset, Lockbox reports "not checked" and never implies "clean".
- **No QR *reading*.** That needs a camera or an image-decoding library; adding
  one for a rare convenience was not worth the dependency. Paste the
  `otpauth://` URI instead — it is parsed locally.
- **No browser extension, no autofill, no sync.** Each of those is a network or
  IPC attack surface that this project deliberately does not have.
- **The frozen GUI binary has not been launched.** The CLI binary was built and
  passed all 18 verification checks on Linux; the GUI executable could not be
  built here at all, because this environment has no Tk. The spec for it is
  written but unproven.
- **The GUI was written against the Tk API but could not be launched in the
  environment this was built in** (no display, no Tk). Every module compiles and
  the entire core is covered by tests through the CLI; the widget layer itself
  has not been exercised on-screen. Treat the GUI as the least-tested part.

## Documentation

| Document | Contents |
| --- | --- |
| [SECURITY.md](SECURITY.md) | What is protected, what is not, reporting |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Adversaries, assumptions, accepted risks |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module layout and data flow |
| [docs/CRYPTO.md](docs/CRYPTO.md) | Key hierarchy and algorithm choices |
| [docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md) | Byte-level file format |
| [docs/OFFLINE.md](docs/OFFLINE.md) | The no-network policy and how to verify it |
| [docs/BACKUP.md](docs/BACKUP.md) | Backup, restore, disaster recovery |
| [docs/BUILDING.md](docs/BUILDING.md) | Freezing to an .exe, signing, CI |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Contributing, adding tools, style |
| [docs/TESTING.md](docs/TESTING.md) | What is tested and why |

## Licence

MIT.
