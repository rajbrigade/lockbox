# Offline and privacy

**This application is designed to operate without network connectivity.**

Lockbox works with Wi-Fi off, Ethernet unplugged, DNS dead and every port
firewalled. Not "degrades gracefully" — every feature works, because no feature
was built on a remote service in the first place.

## The policy

1. Lockbox makes **zero** network requests. Not at startup, not on unlock, not
   on a timer, not for updates, not for telemetry, not for crash reports.
2. There is no analytics, tracking, advertising or usage reporting of any kind.
3. There is no account, no login, no licence check, no activation.
4. There is no cloud storage and no sync. The vault is a file on your disk.
5. No remote fonts, stylesheets, scripts, images or CDN resources. The GUI uses
   system fonts and flat colours; the QR SVG output has no external references.
6. Dependencies are two audited cryptography libraries. Neither phones home.

## Why the design contains no network code at all

The strongest guarantee is not "we promise not to call the network" — it is
"there is no code here that could." Lockbox has no HTTP client, no socket usage
outside the test that disables sockets, and no async event loop. A leak would
require someone to add networking, and the test suite fails the moment they do.

## Features that were deliberately removed rather than made online

| Feature | Decision |
| --- | --- |
| Breach checking (HIBP API) | Removed the API. Even a k-anonymity hash-prefix lookup is a network request that leaks which passwords you hold and when you checked. Replaced with an **optional local dataset** you supply yourself. |
| Cloud sync | Removed. Copy the encrypted file yourself if you want it elsewhere. |
| Update checks | Removed. Check for updates the same way you do for anything else. |
| Website favicons | Removed. Fetching a favicon tells a server which sites you have accounts on. |
| Password-strength APIs | Never considered. Strength analysis is local and bundled. |
| Online password generators | Never considered. A password someone else generated is not your password. |
| Crash reporting | Removed. A stack trace from a password manager is a description of your data. |

## Breach checking without a network

`core/breach.py` reads a dataset **you** put on disk. Supported shapes:

- `sha1-text` — sorted text, one uppercase SHA-1 hex digest per line, optionally
  `:count`. This is the format of the published "ordered by hash" corpora.
- `sha1-binary` — sorted raw 20-byte digests.
- `prefix-dir` — a directory of files named by the first five hex characters.

Lookups binary-search the file by byte offset, so a 40 GB dataset costs a
handful of seeks and no RAM. Point Lockbox at it in Settings, or:

```bash
lockbox tool url_inspect       # (any tool; settings live in the vault)
# Settings -> "Local breach dataset" -> /path/to/pwned-passwords.txt
```

**With no dataset configured, Lockbox reports "not checked".** It never reports
"clean", because it has not checked. This distinction is enforced by a test.

## How to verify the claim yourself

**Run the tests.** Two independent approaches:

```bash
python3 run_tests.py offline -v
```

*Dynamic:* `socket.socket`, `create_connection`, `getaddrinfo`,
`gethostbyname` and friends are replaced with functions that raise, and then the
entire workflow runs — vault creation, save, lock, unlock, search, generation,
TOTP, QR, audit, integrity check, backup, verify, restore, plaintext export,
re-import, and loading every registered micro-tool. The test suite first proves
the blocker itself works (a real `socket()` call must raise, and `urllib` must
fail through it), because a blocker that does not block would make every other
assertion worthless.

*Static:* every shipped `.py` file is parsed with `ast` and every import
inspected. Any of `urllib.request`, `http`, `requests`, `httpx`, `aiohttp`,
`socket` (outside the self-test), `asyncio`, cloud SDKs and so on fails the
build. A separate check asserts that the only third-party roots imported
anywhere are `cryptography` and `argon2`.

**Run the built-in self-test** against your own vault:

```bash
python3 -m lockbox check --offline
```

**Watch it from outside.** Nothing should appear:

```bash
sudo tcpdump -i any -n host not 127.0.0.1 &
python3 -m lockbox gui

# or Linux namespaces:
sudo unshare --net --user --map-root-user python3 -m lockbox check --offline

# or macOS/BSD:
sudo lsof -i -a -p $(pgrep -f lockbox)
```

**Firewall it.** Deny the process all outbound access and use it normally. You
will not notice a difference; there is nothing to block.

## What leaves your machine

Nothing, unless you explicitly export a file and move it yourself.

Local-only side effects worth knowing about:

- The vault, `.prev` and backups are files on your disk. Your own OS backup
  software may copy them — they are encrypted, so that is safe, but it is your
  system doing it, not Lockbox.
- Copying a password puts it on the system clipboard, readable by other local
  processes until it is cleared.
- A plaintext export writes readable secrets to a path you choose. It requires
  typing `I UNDERSTAND`, is written mode 0600, and is refused outright if the
  path looks like a cloud-sync folder.
