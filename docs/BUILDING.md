# Building a standalone executable

Lockbox freezes into a self-contained binary with PyInstaller: one file that
runs on a machine with no Python, no pip and no dependencies installed.

```bash
pip install -r requirements-dev.txt
python3 build.py
```

Output:

```
dist/lockbox      (lockbox.exe on Windows)      -- CLI
dist/lockbox-gui  (lockbox-gui.exe on Windows)  -- desktop window
```

`build.py` runs the test suite first, refuses to build if anything fails, then
verifies the finished binary with `verify_binary.py`.

## PyInstaller does not cross-compile

**A Windows `.exe` must be built on Windows.** Same for macOS and Linux. This is
not a missing flag; the freezer embeds a platform-specific bootloader and the
platform's own compiled extension modules. Options:

| You have | You want | Do this |
| --- | --- | --- |
| Windows | `.exe` | `python build.py` on that machine |
| macOS / Linux | `.exe` | GitHub Actions (`.github/workflows/build.yml`, included) or a Windows VM |
| Any | all three | Push a `v*` tag; the workflow builds and uploads all three |
| Linux only, willing to hold your nose | `.exe` | Wine + Windows Python + PyInstaller. It usually works and is untested here; the CI runner is the honest route. |

The included workflow builds on `windows-latest`, `macos-latest` and
`ubuntu-latest`, runs `verify_binary.py` on each result, and uploads the
artefacts.

## On Windows, specifically

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
python build.py
dist\lockbox.exe --version
dist\lockbox.exe check --offline
```

Tk comes with the python.org installer as long as "tcl/tk and IDLE" is ticked
(it is by default). If it is missing, `build.py` says so and tells you to use
`--cli-only`.

The GUI executable is built with `console=False`, so double-clicking it opens
the window with no black console box behind it. The CLI one is `console=True`
so it works properly in PowerShell and `cmd`.

## One file or one directory

```bash
python3 build.py            # one file: a single portable executable
python3 build.py --onedir   # one directory: starts about 3x faster
```

Measured on the same (slow, single-core) Linux VM as the rest of the numbers:

| | One file | One directory |
| --- | --- | --- |
| Size | 11.6 MB | 31.3 MB (folder) |
| Startup, `lockbox gen` | 288 ms | 115 ms |
| Ship as | one file | the whole folder |

The one-file difference is the bootloader unpacking the archive to a temp
directory on **every** launch. For the CLI that is invisible; for the GUI, use
`--onedir` if launch latency bothers you, or accept a quarter-second.

For comparison, running from source on the same machine is 114 ms — the
one-directory build costs essentially nothing over plain Python.

## Windows GUI notes

- **Run `lockbox-gui.exe`, not `lockbox.exe gui`.** The second one is the
  console binary, so a console window stays open behind the app for as long as
  it runs. Only `lockbox-gui.exe` is built with `console=False`.
- **Use `--onedir` for the GUI.** A one-file GUI binary unpacks itself to a temp
  directory on every launch, which on Windows also means Defender scans the
  extracted tree each time. The window can take several seconds to appear.
  `python build.py --onedir` removes that entirely.
- **Console flashes** during clipboard operations were a bug, fixed by passing
  `CREATE_NO_WINDOW` to every subprocess. If you still see one, say which
  action triggered it -- something is spawning a process that should not be.
- **First-launch slowness** that never recurs is usually Defender scanning the
  freshly extracted files. Excluding the install folder from real-time scanning
  fixes it; that is a decision for you, not something the app should ask for.

## What is excluded from the binary, and why

`lockbox.spec` excludes every networking module by name: `urllib.request`,
`http`, `ftplib`, `smtplib`, `telnetlib`, `xmlrpc`, `asyncio`, `ssl`,
`requests`, `httpx`, `aiohttp`, and the rest. This is not just size trimming —
it means a future accidental import cannot be silently shipped, because the
build breaks instead.

`urllib.parse` and `ipaddress` **stay**. `urllib.parse` is a pure string parser
used for URL inspection and `otpauth://` URIs, and it imports `ipaddress`.
Excluding them was tried, and produced a binary that died at startup — which is
exactly what the verification step is for.

`verify_binary.py` then greps the finished artefact for `urllib.request`,
`http.client`, `smtplib`, `ftplib`, `requests`, `aiohttp`, `httpx`, `telnetlib`
and `xmlrpc`. If any is embedded, verification fails.

## Hidden imports

The micro-tool registry imports tool modules by name at call time, so
PyInstaller's static analyser cannot see them. Every `lockbox.tools.*` module is
therefore listed in `HIDDEN` in the spec. **If you add a tool module, add it
there**, or the binary will ship without it and the tool will fail at runtime
with `ModuleNotFoundError`. The offline self-test inside `verify_binary.py`
catches exactly this — it is how the missing QR module was found during
development.

## What the verification actually checks

```bash
python3 verify_binary.py dist/lockbox
```

18 black-box checks against the finished executable: it runs and reports its
version; it creates a real vault (proving Argon2 and OpenSSL were bundled);
stores an item and reads back the exact value; rejects a wrong master password;
passes its own offline self-test with sockets blocked; passes an integrity
check; runs the TOTP, QR and generator tools; writes the vault mode 0600 with
the right magic bytes; leaves no plaintext of the test secret in the vault; and
has no networking module or test secret embedded in the binary itself.

## Signing and antivirus

The binaries are **not signed**. Consequences:

- **Windows**: SmartScreen shows "Windows protected your PC" until the binary
  builds reputation or you sign it with an Authenticode certificate
  (`signtool sign /fd sha256 /tr <timestamp-url> /td sha256 dist\lockbox.exe`).
- **macOS**: Gatekeeper blocks it. Sign and notarise
  (`codesign --deep --force --options runtime --sign "Developer ID..."`, then
  `xcrun notarytool submit`), or right-click → Open the first time.
- **Antivirus false positives**: PyInstaller one-file binaries are flagged by
  some scanners because malware authors use the same packer. This is why the
  spec sets `upx=False` — UPX compression makes it much worse. If a scanner
  complains, build from source yourself; that is the whole point of a 6,500-line
  auditable codebase.

Nothing in Lockbox contacts a signing or notarisation service on its own. Those
are commands **you** run.

## Reproducibility

Frozen binaries are not bit-reproducible: they embed absolute paths, timestamps
and the bootloader compiled for the host. Two builds of the same commit will
differ. If you need to verify a binary, verify what it *does*
(`verify_binary.py`, `lockbox check --offline`) rather than its hash, or build
it yourself.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `objcopy Failure ... Bad file descriptor` | Output directory is on a mount that cannot handle it (container mounts, some network shares). `python3 build.py --dist ~/lockbox-dist` |
| `attempted relative import with no known parent package` | Something is entering through `src/lockbox/__main__.py` instead of `cli_entry.py`. The spec points at the shims for this reason. |
| `ModuleNotFoundError: lockbox.tools.<x>` at runtime | New tool module missing from `HIDDEN` in `lockbox.spec`. |
| `No module named 'ipaddress'` at startup | Something re-added `ipaddress` or `urllib.parse` to the exclude list. Remove it. |
| Tk missing at build | `sudo apt install python3-tk` (Debian/Ubuntu), `sudo dnf install python3-tkinter` (Fedora), or reinstall Python with Tcl/Tk. Or `--cli-only`. |
| Binary is enormous | Check that the excludes list survived your edits; `numpy`/`PIL` creeping in is the usual cause. |
