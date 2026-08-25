# Security

## What Lockbox actually protects

Lockbox protects **a vault file at rest** against someone who has the file but
not your master password. That is the whole security claim, and it is the one
that matters for a stolen laptop, a backup drive, a rifled-through Dropbox
folder, or a discarded disk.

Concretely:

- The vault is encrypted with AES-256-GCM. Every byte of the payload is
  authenticated; a single flipped bit anywhere makes decryption fail loudly
  rather than yielding garbage. This is verified by a test that flips every bit
  of a ciphertext in turn.
- The master password is never stored, in any form, anywhere. It is not hashed
  into the file for verification. "Wrong password" and "corrupt file" are the
  same event to Lockbox: the AEAD tag failed.
- The key comes from Argon2id (64 MiB, 3 passes) so guessing is expensive in
  memory as well as time. GPU and ASIC attacks are what memory-hardness exists
  to blunt.
- The plaintext header — which must be readable before a key exists — is fed to
  AES-GCM as additional authenticated data. Editing the salt or lowering the
  Argon2 cost parameters produces a file that will not open, so a downgrade
  attack is detected rather than silently accepted.
- On Unix the vault file is created with mode 0600. **Windows has no POSIX mode
  bits** — `os.chmod` there only toggles the read-only flag — so access is
  governed by NTFS ACLs instead. A vault inside your own user profile
  (`%LOCALAPPDATA%`, the default) inherits an ACL that excludes other standard
  users. Lockbox reports this honestly rather than printing a fabricated
  "0o600", and the built-in checklist turns that item into a manual check on
  Windows. If you move the vault to a shared drive, the protection is whatever
  that drive's ACL says.
- The vault file is created with mode 0600 and written atomically, so a crash
  mid-save cannot leave a truncated vault, and the previous version is retained
  as `.prev`.

## What Lockbox does not protect against

Stated plainly, because a security document that only lists strengths is
marketing.

| Threat | Status |
| --- | --- |
| Malware running as your user | **Not protected.** It can read the decrypted vault out of memory, log your keystrokes, or read the clipboard. |
| A keylogger | **Not protected.** It captures the master password. |
| Someone at your unlocked, logged-in machine | **Partially.** Auto-lock helps; if the vault is open, the data is open. |
| Cold-boot / RAM forensics while unlocked | **Not protected.** See memory hygiene below. |
| A malicious or backdoored Python, OpenSSL, or OS | **Not protected.** Nothing at this layer can fix that. |
| Rubber-hose / legal compulsion | **Not protected.** There is no deniability feature and none is claimed. |
| Shoulder surfing | **Partially.** Secrets are masked by default and search never matches on secret fields. |
| A forgotten master password | **Not recoverable, by design.** |

## Memory hygiene: what is real, what is not

- Key material (the KEK and the DEK) is held in `bytearray` and zeroed on lock,
  on error paths, and after use. This is real and tested.
- Decrypted item fields (passwords, notes, TOTP secrets) are Python `str`
  objects. CPython interns, copies and garbage-collects them at will, and does
  not guarantee erasure. **Lockbox cannot wipe them and does not claim to.** A
  language with manual memory control would do better here; that trade was made
  knowingly in exchange for auditability and a tiny dependency tree.
- There is no swap-locking (`mlock`). On a system that swaps, decrypted content
  may reach disk. Use full-disk encryption; that advice is in the built-in
  checklist for exactly this reason.

## Clipboard

The clipboard is the weakest link in every password manager: it is a global
buffer readable by every process on the machine. Lockbox:

- clears it after a configurable delay (default 20 s);
- clears it only if the contents are still what Lockbox put there, so it never
  destroys something you copied afterwards;
- clears it on lock, if enabled;
- never routes a secret through a temporary file to reach it.

It cannot stop another process reading the clipboard during that window. If you
have a clipboard-history manager installed, it will capture your passwords —
that is a property of your system, not of Lockbox.

## Cryptographic decisions

| Decision | Reason |
| --- | --- |
| Argon2id, 64 MiB, t=3, p=1 | RFC 9106 recommended profile, memory-hard. Falls back to stdlib scrypt only if `argon2-cffi` is absent; the header records which was used. |
| AES-256-GCM | Authenticated encryption from OpenSSL via `cryptography`. Hardware-accelerated on any modern CPU. |
| 96-bit random nonce per encryption | Standard GCM nonce size. Nonces are generated inside the crypto wrapper and cannot be supplied by callers, so nonce reuse cannot be triggered from outside it. |
| Random DEK wrapped by the KEK | Changing the master password re-wraps a 32-byte key instead of re-encrypting everything, and backups made under an old password remain valid under it. |
| `os.urandom` / `secrets` for all randomness | The OS CSPRNG. `random`, timestamps and PIDs are never used for secrets; a test enforces this by scanning the source. |
| SHA-1 in breach lookups only | The published breach corpora are indexed by SHA-1. It is used as a *database index*, never as a security primitive, and never leaves the process. |
| No custom cryptography | Nothing in this codebase implements a cipher, a hash or a KDF. The QR encoder is hand-written, but QR is an error-correcting code, not a security primitive. |

## Reporting a vulnerability

Open an issue describing the problem, or contact the maintainer privately if it
is exploitable. Please include the version (`lockbox --version`), the platform,
and steps to reproduce. Do not include your vault file or your master password —
they are never needed to describe a bug.

## Verifying the build yourself

```bash
python3 run_tests.py offline -v     # network-blocked workflow + static scan
python3 -m lockbox check --offline  # integrity + self-test on your real vault
pip list | grep -Ei 'cryptography|argon2'
```

The static scan parses every shipped file with `ast` and fails if any networking
module is imported anywhere, if an unexpected third-party package appears, if
`logging` is configured (so that a secret can never be written to a log file),
or if a fetchable URL literal exists in the code.
