# Lockbox

Offline password manager using a single encrypted vault file.

**Features**

- No network requests during normal operation
- CLI and desktop GUI
- Encrypted vault using Argon2id and AES-256-GCM
- Local encrypted backups
- TOTP support
- Password and passphrase generation

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Vault Location](#vault-location)
- [Offline Operation](#offline-operation)
- [Security](#security)
- [Backups](#backups)
- [Standalone Executable](#standalone-executable)
- [Testing](#testing)
- [Limitations](#limitations)
- [Licence](#licence)

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.x | Required |
| `pip` | Required |
| `cryptography` | Required |
| `argon2-cffi` | Required |
| Tk | GUI only; CLI works without it |

### Debian / Ubuntu

Tk is usually included with Python. If it is not installed:

```bash
sudo apt install python3-tk
```

---

## Installation

> **Download or clone the complete project. Do not copy individual files.**
>
> The project contains multiple files named `__init__.py`. Copying files individually into one directory can overwrite them and break the project layout.

Install the dependencies:

```bash
pip install -r requirements.txt
pip install -e .
```

### Repairing a flattened layout

If the project was accidentally flattened:

```bash
python repair_layout.py --apply
```

---

## Usage

### Vault setup

```bash
lockbox init
```

### GUI

```bash
lockbox gui
```

### Items

Add an item:

```bash
lockbox add GitHub -u octocat -g
```

List and search items:

```bash
lockbox list
```

Show a secret:

```bash
lockbox show github --reveal
```

### TOTP

```bash
lockbox totp github --watch
```

### Maintenance

Run a security audit:

```bash
lockbox audit
```

Create an encrypted backup:

```bash
lockbox backup create
```

Check vault integrity and offline operation:

```bash
lockbox check --offline
```

### Standalone tools

Generate a passphrase without opening the vault:

```bash
lockbox gen passphrase --words 6
```

List available tools:

```bash
lockbox tool
```

---

## Vault Location

| Platform | Location |
|---|---|
| Linux | `~/.local/share/lockbox/vault.lbx` |
| Windows | `%LOCALAPPDATA%\lockbox\vault.lbx` |
| macOS | `~/Library/Application Support/lockbox/vault.lbx` |

Override the vault location with `--vault` or `LOCKBOX_VAULT`.

---

## Offline Operation

Lockbox is designed to operate without network connectivity. Normal operation makes zero network requests.

Verify offline operation with:

```bash
lockbox check --offline
```

See [`docs/OFFLINE.md`](docs/OFFLINE.md) for offline verification details.

---

## Security

### Key hierarchy

```text
Master Password
      |
      v
   Argon2id
      |
      v
Key Encryption Key
      |
      v
 AES-256-GCM
      |
      v
Encrypted Data Key
      |
      v
 AES-256-GCM
      |
      v
Encrypted Vault
```

### Properties

- The vault payload is compressed before encryption.
- The plaintext header is authenticated to prevent modification or downgrade of KDF parameters.

---

## Backups

- Backups are encrypted copies of the vault.
- A backup is verified by decryption before it can be restored.
- Keep backups in a secure location.

---

## Standalone Executable

Install build dependencies:

```bash
pip install -r requirements-dev.txt
```

Build:

```bash
python3 build.py
```

Build a directory-based version:

```bash
python3 build.py --onedir
```

Verify the CLI binary:

```bash
python3 verify_binary.py dist/lockbox
```

### Platform limitation

PyInstaller cannot cross-compile.

- Windows `.exe` files must be built on Windows.
- Linux binaries must be built on Linux.
- macOS binaries must be built on macOS.

The included CI workflow can build and verify the supported platforms.

---

## Testing

Run the complete test suite:

```bash
python3 run_tests.py
```

Run the offline/no-network tests:

```bash
python3 run_tests.py offline -v
```

---

## Limitations

### Forgotten master password

There is no master-password recovery. If the master password is forgotten:

- The vault cannot be unlocked.
- There is no reset link.
- There is no backdoor.
- The encrypted data is unrecoverable.

### Memory protection

Memory wiping is best-effort. Keys stored in mutable `bytearray` objects are wiped, but CPython cannot reliably erase immutable `str` and `bytes` objects. Decrypted item strings may therefore remain in memory temporarily.

### Compromised machine

Lockbox cannot protect secrets from a compromised machine. Malware running as the current user, a keylogger, or a compromised Python installation can defeat the application's protections.

### Breach checking

Breach checking is local. It only works when a breach dataset is already available on the machine. Without a dataset, Lockbox reports `not checked` and does not claim that a password is safe.

### QR codes

Lockbox can generate QR codes but does not read QR codes. For TOTP setup, provide the `otpauth://` URI instead.

### GUI testing

The CLI/core functionality is more thoroughly tested than the GUI. The GUI could not be launched in the original build environment because Tk/display support was unavailable. The GUI should therefore be considered the least-tested part of the application.

### Features not included

Lockbox intentionally does not provide:

- Browser extension
- Browser autofill
- Cloud synchronization
- Network synchronization
- QR-code scanning

These features are excluded to preserve the offline design and reduce attack surface.

---

## Licence

MIT