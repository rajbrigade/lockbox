# Testing guide

```bash
python3 run_tests.py            # 218 tests, about 15 s
python3 run_tests.py offline -v # only the offline / no-network proofs
python3 run_tests.py -v         # verbose
```

`unittest` from the standard library. No pytest, no plugins, no fixtures
framework — the same "two dependencies" rule applies to the test suite, with one
exception: `qrcode` is installed for development so the hand-written QR encoder
can be cross-checked against a reference implementation. That test skips
cleanly if it is absent.

## Files

| File | Tests | Covers |
| --- | --- | --- |
| `test_crypto.py` | 32 | CSPRNG, AEAD, HKDF, wiping, KDF, container format |
| `test_vault.py` | 33 | Lifecycle, locking, auto-lock, integrity, model, search |
| `test_tools.py` | 70 | Generators, analysis, TOTP/HOTP, QR, encoders, hashes, registry |
| `test_portio.py` | 41 | Import, export, backup, restore, audit, breach datasets |
| `test_offline.py` | 15 | Network-blocked workflow, static scans, secret-leak checks |
| `test_cli.py` | 27 | Every CLI command end to end, clipboard behaviour |

## Principles

**Use the standard's vectors where one exists.** A self-consistent
implementation proves nothing; an implementation that reproduces published
vectors is interoperable. The suite pins:

- RFC 4226 — all ten HOTP vectors
- RFC 6238 — TOTP vectors for SHA-1, SHA-256 and SHA-512
- RFC 4648 — base64 vectors including padding edge cases
- RFC 4231-style HMAC and known SHA-2 digests
- RFC 5869 — HKDF test case 1

**Prove the negative, not just the positive.** Round-tripping a ciphertext shows
encryption works. Flipping *every single bit* of the ciphertext and requiring a
failure each time shows authentication works. That test exists.

**Test the test.** `test_offline.py` first asserts that the socket blocker
actually blocks — a real `socket()` must raise, DNS must raise, and `urllib`
must fail through it — because a blocker that silently does nothing would make
every offline assertion worthless.

**Test what could quietly rot.** Static scans catch a networking import, a new
dependency, a `logging` call, a hard-coded key, or a fetchable URL appearing on
a code path nobody happens to exercise.

## The offline proof, in detail

Dynamic: `socket.socket`, `create_connection`, `create_server`, `socketpair`,
`getaddrinfo`, `gethostbyname`, `gethostbyname_ex` and `getfqdn` are replaced
with functions that raise. The full workflow then runs — create, add, save,
lock, unlock, search, generate, TOTP, QR, audit, integrity check, backup,
verify, restore, plaintext export, re-import, and loading all 41 tools.

Static: every shipped `.py` is parsed with `ast`; imports are checked against a
forbidden list; third-party roots must be exactly `{cryptography, argon2}`;
`socket` is permitted only in `cli.py`, where it is imported in order to be
disabled.

`lockbox check --offline` runs the same idea against your real vault and prints
a per-step pass/fail table.

## Notable specific cases

- **Wrong password vs corrupt file** — both raise, and the messages do not
  distinguish them, because the AEAD cannot.
- **Header downgrade** — rewriting the Argon2 parameters in the plaintext header
  must break body authentication.
- **Restore safety** — a wrong password during restore must leave the live vault
  byte-identical.
- **Plaintext export** — refused for `""`, `"yes"`, `"i understand"` and
  `"I UNDERSTAND "` (trailing space); the file must not exist afterwards.
- **Sync-folder refusal** — a path containing `Dropbox` is rejected.
- **Secrets are not searchable** — searching for a password or TOTP secret must
  return nothing.
- **JSON list output** — must not contain passwords or TOTP secrets.
- **Breach honesty** — with no dataset there must be no `breached` finding and
  the status must say "not checked".
- **Clipboard ownership** — if the user copied something else afterwards,
  `clear_if_ours()` must leave it alone.
- **Search performance** — 5,000 items must search in under 0.5 s.
- **Large breach dataset** — 50,000 records, first/middle/last must all be found
  (this test caught a real off-by-one in the binary search).

## What is not covered

- **The Tk widget layer.** It needs a display; the environment this was built in
  had neither Tk nor an X server. Every UI module compiles, and all the logic it
  calls is tested through the CLI, but the widgets themselves have not been
  clicked by a test. This is the weakest spot in the suite and is stated in the
  README as well.
- **File permissions on Windows.** The five tests that assert mode 0600 are
  skipped there, because the bits do not exist. What replaces them is a
  documented statement of what NTFS actually provides — not a test.
- **Cross-platform paths.** Only Linux was exercised end to end. The macOS and Windows
  branches in `default_data_dir()` and the clipboard backends are written from
  documented behaviour, not observed behaviour.
- **Concurrency.** Two Lockbox processes writing the same vault will have one
  overwrite the other. Single-writer is assumed.
- **Fuzzing.** The import parsers are the obvious target (`csv`/`json` with
  hostile input). Structured fuzzing has not been done; the parsers use no
  `eval`, `pickle` or YAML, and bound field lengths.

## Adding tests

Put them in the module that matches the subject, name them after the behaviour
(`test_restore_with_a_wrong_password_changes_nothing`, not `test_restore_2`),
and use the fast scrypt parameters — `KDFParams("scrypt", …, {"n": 1024, …})` —
so the suite stays fast. If you are testing something a standard defines, find
the vectors first.
