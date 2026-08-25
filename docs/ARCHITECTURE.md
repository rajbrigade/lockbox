# Architecture

## Shape

```
                 ui/ (Tk)            cli.py
                     \                 /
                      \               /
                       +-- core/ ----+
                       |             |
      vault.py  vaultfile.py  crypto.py  kdf.py  model.py
      search.py  audit.py  backup.py  portio.py  breach.py  clipboard.py
                       |
                    tools/  (41 lazily-imported micro-tools)
```

Two front ends, one core. The CLI is not a debug hatch: it is a complete
interface, which is why the whole application can be tested without a display.
The GUI adds widgets and nothing else — no logic lives only in `ui/`.

Dependencies point one way: `ui` and `cli` depend on `core`; `core` depends on
`tools` for analysis and OTP; `tools` depends on `core.crypto` for randomness
and nothing else. There are no cycles.

## Modules

| Module | Lines | Responsibility |
| --- | --- | --- |
| `core/crypto.py` | 103 | Thin wrapper over OpenSSL AEAD, HKDF, CSPRNG, wipe. Implements no algorithm. |
| `core/kdf.py` | 122 | Argon2id (scrypt fallback), parameters serialised into the header. |
| `core/vaultfile.py` | 205 | Byte format, DEK wrap/unwrap, atomic writes. |
| `core/vault.py` | 312 | Lifecycle, CRUD, auto-lock, integrity check. |
| `core/model.py` | 172 | `Item`, settings, payload normalisation and migration. |
| `core/search.py` | 159 | Filters plus fuzzy scoring over non-secret fields. |
| `core/audit.py` | 238 | Local findings, severity, health score. |
| `core/backup.py` | 176 | Create, list, prune, verify, restore. |
| `core/portio.py` | 382 | CSV/JSON import mapping, exports, plaintext guardrails. |
| `core/breach.py` | 205 | Optional local dataset, binary search on disk. |
| `core/clipboard.py` | 148 | Backends, owner-checked timed clearing. |
| `tools/*` | 2,045 | The micro-tools, each a pure function. |
| `ui/*` | 1,344 | Tk window, command palette, tools window, theme. |
| `cli.py` | 824 | Every command, plus the offline self-test. |

## Data flow

**Unlock.** password + salt → Argon2id → KEK → AES-GCM unwrap → DEK → AES-GCM
decrypt body → zlib inflate → JSON → `Item` objects in a dict. The KEK is wiped
the moment the DEK is out.

**Save.** items → JSON → zlib → AES-GCM (AAD = magic + version + header) →
temp file → fsync → keep previous as `.prev` → `os.replace` → fsync directory.
Interrupt it anywhere and you still have a complete old vault or a complete new
one, never half of either.

**Lock.** wipe the DEK, drop the payload, drop the item dict, clear the
clipboard if we put something there.

## No daemons, no threads

The process has one thread almost all of the time. There is no background
service, no scheduler and no watcher. The single exception is unlocking: the
Argon2 derivation runs on a short-lived worker thread so the window keeps
repainting instead of appearing to hang, and that thread ends the moment the
key is derived. Nothing else is concurrent. Auto-lock is `check_autolock()`, called once a second from Tk's
`after()` loop; it compares `time.monotonic()` against the last activity stamp
and does nothing else. That is the entire reason idle CPU sits at zero.

The CLI never polls at all — it unlocks, does one thing, and locks in a
`finally` block.

## Lazy loading

`tools/__init__.py` declares tools as data (`id`, `category`, `"module:function"`,
summary) and imports the module on first call. Starting Lockbox does not import
the QR encoder, the regex tester or the hash tools. `import lockbox.core.vault`
costs 55 ms, most of which is `cryptography` pulling in OpenSSL.

## Design rules the code follows

- **No algorithm is implemented that a library already provides.** The single
  exception is the QR encoder, and QR is an error-correcting code, not a
  security primitive; it is cross-checked against a reference implementation in
  the tests.
- **Secrets never reach a log.** The package does not import `logging` at all,
  which a test enforces. `VaultKeys.__repr__` returns `<redacted>` so a stray
  traceback cannot print a key.
- **Errors say what happened without saying what the data is.** "Wrong master
  password, or the vault has been tampered with" is one message because those
  two cases are genuinely indistinguishable to the AEAD.
- **Anything destructive is verified before it destroys.** Restore decrypts the
  backup fully before touching the live vault; save keeps `.prev`.
- **The UI holds no state the core does not.** Locking clears the widgets, but
  the widgets were never the source of truth.

## Extending it

Adding a micro-tool is one function and one registry line — see
[DEVELOPMENT.md](DEVELOPMENT.md). Adding a *vault field* means touching
`model.py` (the dataclass, `to_dict`, `from_dict`), bumping `SCHEMA_VERSION` if
the change is not backward-compatible, and handling the old shape in
`normalise_payload`. Payloads with a newer schema than the running build are
refused rather than silently mangled.
