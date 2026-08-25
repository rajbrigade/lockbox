# Threat model

A threat model is only useful if it names what is *not* covered. This one does.

## Assets

| Asset | Where it lives | Value to an attacker |
| --- | --- | --- |
| Master password | Only in your head, and transiently in process memory | Total compromise |
| Key-encryption key (KEK) | Derived on unlock, wiped immediately after unwrapping the DEK | Total compromise |
| Data-encryption key (DEK) | `bytearray` in memory while unlocked; wrapped in the file | Total compromise |
| Decrypted items | Python objects while unlocked | Total compromise |
| Vault file | Disk, mode 0600 | Useless without the password; worth offline cracking |
| Backups | Disk, wherever you put them | Same as the vault |
| Plaintext export | Only if you make one | Immediate, total compromise |

## Adversaries

### 1. Someone who has the file but not the password — **primary threat, defended**

A stolen laptop, a lifted backup drive, a synced folder someone else can read, a
recovered disk. They get an AES-256-GCM ciphertext whose key needs Argon2id at
64 MiB and three passes per guess. Their cost scales with your master password's
entropy, which is why Lockbox nags about that one password and nothing else.

The header is plaintext but authenticated, so they cannot rewrite it to say
"Argon2 with 8 KiB and one pass" and cheapen the attack: the body will not
authenticate afterwards.

### 2. Someone who tampers with the file — **defended**

Any modification — header, wrapped key, ciphertext, a single bit — makes the
AEAD tag fail. Lockbox refuses to open the vault rather than presenting
attacker-chosen content. A test flips every bit of a ciphertext in turn and
requires a failure each time. The previous version is kept as `.prev`, and
restore decrypts a backup fully *before* overwriting anything.

### 3. A passive network observer — **not applicable**

There is nothing to observe. Lockbox never opens a socket.

### 4. Malware or another user process on your machine — **not defended**

Code running as your user can read the decrypted vault out of memory, hook the
GUI, log keystrokes, read the clipboard, or replace the Lockbox source. No
user-space password manager solves this; anyone claiming otherwise is selling
something. Auto-lock, clipboard clearing and masked fields raise the effort
slightly — they do not stop it.

### 5. Physical access to an unlocked machine — **partially defended**

Auto-lock (default 5 minutes idle) and manual lock (`Ctrl+L`) limit the window.
While unlocked, everything is readable.

### 6. Cold-boot / memory forensics — **not defended**

Key material is wiped on lock, but decrypted `str` objects cannot be. See
"Accepted limitations".

### 7. Supply chain — **partially defended**

Two dependencies, both widely audited, pinned in `requirements.txt`, both from
PyPI's most-scrutinised tier. A test fails if a third dependency ever appears.
That does not protect against a compromised release of `cryptography` itself,
nor against a compromised Python or OpenSSL. Install from a trusted index and
verify signatures if that is in your model.

### 8. Malicious import file — **defended against the obvious**

Imports are parsed with `csv`/`json` (no `eval`, no `pickle`, no YAML), field
lengths are bounded, unknown columns become inert custom fields, and item types
are validated against a fixed set. An import can only *add* items; it never
overwrites or executes anything.

### 9. You, exporting plaintext — **defended by friction, not by force**

A plaintext export requires typing `I UNDERSTAND` exactly, prints a warning,
writes mode 0600, refuses paths that look like cloud-sync folders, and offers a
best-effort shred afterwards. If you insist, it is your file and your risk.

## Trust assumptions

Lockbox assumes all of the following are honest. If any is not, it fails:

- The operating system and its CSPRNG (`os.urandom`).
- The CPython interpreter you run it with.
- OpenSSL, via `cryptography`, for AES-256-GCM.
- The Argon2 reference implementation, via `argon2-cffi`.
- The filesystem: that `os.replace` is atomic and `fsync` means what it says.
- The display server and clipboard, for anything shown or copied.

## Accepted limitations

These are deliberate trades, not oversights.

1. **Decrypted strings cannot be wiped.** CPython gives no control over `str`
   lifetime. Keys use `bytearray` and are zeroed; item content cannot be. The
   alternative was a language with manual memory management, at the cost of a
   large dependency tree and a codebase far harder to audit. That trade was
   made knowingly.
2. **No `mlock`.** Decrypted data may be swapped to disk. Mitigation is
   full-disk encryption, which the built-in checklist asks about.
3. **No key file / hardware-token second factor.** A YubiKey or key file would
   genuinely help against threat #1. It is the most defensible thing missing.
4. **TOTP secrets live in the same vault as the passwords.** Convenient, and a
   real weakening: one compromise yields both factors. The audit says so in
   plain words rather than treating stored TOTP as an unqualified win.
5. **No deniability / hidden volumes.** The file is obviously a Lockbox vault.
6. **No autofill or browser integration.** Both need IPC or a network listener.
   The manual-copy workflow is worse UX and a much smaller attack surface.
7. **Timing.** Vault operations are not constant-time with respect to item count
   or search terms. The attacker who could measure that is already inside
   threat #4, where the game is over anyway. HMAC and digest comparisons *are*
   constant-time.
8. **The GUI layer is the least-tested code.** It could not be launched in the
   environment where it was written (no display, no Tk). The core is exercised
   end-to-end through the CLI by 218 tests; the widget code is compile-checked
   only.

## Residual risk, in one sentence

If your master password is strong and your machine is not compromised, an
attacker with your vault file has a very expensive problem; if your machine is
compromised, Lockbox will not save you, and nothing at this layer would.
