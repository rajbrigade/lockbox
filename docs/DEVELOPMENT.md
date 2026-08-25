# Development guide

```bash
git clone <repo> && cd lockbox
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
python3 run_tests.py
```

No build step, no bundler, no code generation. `PYTHONPATH=src` is enough to run
everything (`make` sets it for you).

## Layout

```
src/lockbox/
  core/     vault, crypto, storage, search, audit, backup, import/export, breach
  tools/    micro-tools, one module per family, imported lazily
  ui/       Tk window, command palette, tools window, theme
  cli.py    every command plus the offline self-test
tests/      218 tests, stdlib unittest only
tools/      benchmark.py
docs/
```

## Adding a micro-tool

1. Write a **pure function** in the right `tools/` module. It takes plain
   arguments, returns a plain value (or a dataclass with `to_dict()`), touches
   no global state, writes no files unless that is the point of the tool, and
   never logs its input.
2. Register it in `tools/__init__.py`:

```python
Tool("mytool", "My tool", "Analyze", "analysis:my_function",
     "One line saying what it does."),
```

3. Add tests. If a standard defines vectors, use the vectors.

It now appears in `lockbox tool`, in the GUI's generic tool runner, and in the
tool search. No UI code is required.

Rules the registry enforces by test: `network` is always `False`, every target
imports, every summary is non-empty.

## Adding a vault field

`model.py` only: add it to the `Item` dataclass, to `to_dict()`, and to
`from_dict()` with a default so older vaults still load. Add it to
`Item.searchable()` **only if it is not a secret**. Bump `SCHEMA_VERSION` if the
change would confuse an older build, and handle the old shape in
`normalise_payload`.

Never add a secret field to `searchable()`. Search results are visible; matching
on a secret leaks it.

## Style

- Standard library first. A new dependency needs a real argument, and the
  dependency test will fail until someone updates the allow-list deliberately.
- No `logging`, ever. A test enforces this; it is the cheapest way to guarantee
  a password never lands in a log file.
- Docstrings explain *why*, not *what*. The code says what.
- Type hints on public functions.
- Errors raise `LockboxError` subclasses; `cli.py` turns them into messages.
- Never widen an error message to include secret material.
- Lines under 100 characters.

## The non-negotiables

A change that does any of these will fail the suite, and should:

1. Imports a networking module anywhere in `src/lockbox`.
2. Adds a third-party dependency beyond `cryptography` and `argon2-cffi`.
3. Imports `logging`.
4. Uses `random` (rather than `secrets`/`os.urandom`) anywhere near a secret.
5. Claims a password is breached without a local dataset having matched.
6. Writes a plaintext export without the explicit confirmation token.
7. Weakens the KDF defaults or the cipher.

## Testing while developing

```bash
python3 run_tests.py               # everything, ~15 s
python3 run_tests.py offline -v    # the no-network proofs
python3 run_tests.py crypto        # one module
python3 -m unittest tests.test_vault.TestAutoLock -v
```

Vault tests use scrypt with `n=1024` so the suite is not spent on key
derivation. Never copy those parameters into anything that ships; the real
defaults live in `kdf.py`.

## Benchmarking

```bash
make bench                          # human-readable
python3 tools/benchmark.py --json   # machine-readable
```

If you change anything on a hot path (search, save, unlock), run it before and
after and put the numbers in the pull request. The README's table is one run on
one machine and says so; replace it only with output you actually produced.

## Working on the GUI

`ui/` is the least-tested layer — it needs a display, and the environment this
was written in had none. If you touch it, actually launch it:

```bash
make gui
```

and exercise: unlock, create, edit, save, delete, search, category switching,
the palette (`Ctrl+K`), the tools window, the audit window, settings, backup,
clipboard clearing, and auto-lock (set it to 5 seconds and wait).

Keep logic out of `ui/`. If a widget needs to compute something, the computation
belongs in `core/` or `tools/`, where it can be tested.

## Release checklist

- [ ] `python3 run_tests.py` — all green
- [ ] `python3 -m lockbox check --offline` — passes
- [ ] `make bench` — no regressions; README numbers refreshed if they moved
- [ ] GUI launched and exercised by hand
- [ ] Version bumped in `pyproject.toml` and `__init__.py`
- [ ] Docs updated if behaviour changed
- [ ] `git grep -nE '\b(TODO|FIXME|XXX)\b' src/` reviewed
