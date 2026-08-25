# Cryptographic design

Nothing here is novel. That is the point: every primitive is a standard one from
an audited implementation, arranged in the least surprising way.

## Key hierarchy

```
  master password (never stored)
        |
        |  Argon2id( salt=16B random, m=64 MiB, t=3, p=1 )
        v
  KEK  (32 bytes, in a bytearray, wiped immediately after use)
        |
        |  AES-256-GCM decrypt( wrapped_dek, aad = "lockbox/dek-wrap/v1" || canonical(kdf header) )
        v
  DEK  (32 bytes, random at vault creation, lives only while unlocked)
        |
        |  AES-256-GCM decrypt( body, aad = magic || version || header_len || header )
        v
  payload  ->  zlib inflate  ->  JSON  ->  items
```

### Why two keys instead of one

A single password-derived key would mean re-encrypting the entire vault on every
password change, and would tie every backup to the password in force when it was
made. With a wrapped DEK:

- changing the master password rewrites 60 bytes, not the whole file;
- a backup taken under the old password still opens with the old password,
  which is the behaviour people actually expect;
- the DEK never depends on password strength for its own randomness.

## Algorithms

| Purpose | Choice | Source |
| --- | --- | --- |
| Password hashing | Argon2id, m=65536 KiB, t=3, p=1 | `argon2-cffi` (reference implementation) |
| Fallback KDF | scrypt, N=32768, r=8, p=1 | stdlib `hashlib.scrypt` |
| Encryption | AES-256-GCM, 96-bit nonce, 128-bit tag | `cryptography` → OpenSSL |
| Key derivation from a key | HKDF-SHA256 (RFC 5869) | stdlib `hmac` + `hashlib` |
| Randomness | `os.urandom` / `secrets` | OS CSPRNG |
| TOTP/HOTP | HMAC-SHA1/256/512 | stdlib `hmac` |
| Digests | SHA-2, SHA-3, BLAKE2 | stdlib `hashlib` |
| Breach index | SHA-1 | stdlib — an index, not a security primitive |
| Constant-time compare | `hmac.compare_digest` | stdlib |

### Argon2 parameters

64 MiB and three passes is the RFC 9106 second recommended profile, with memory
raised. On the (slow, single-core) machine used for the benchmarks it costs
0.21 s per guess. Higher memory would be better against GPUs; 64 MiB is the
point where the interactive cost is still acceptable on old hardware. The
parameters live in the header, are authenticated, and can be raised later
without breaking existing vaults.

### The scrypt fallback

If `argon2-cffi` is not installed, Lockbox uses stdlib scrypt so it still runs
on a bare Python. This is a genuine downgrade in GPU resistance and is recorded
explicitly in the header (`"algorithm": "scrypt"`), shown in `lockbox info`, and
in the GUI status bar. It is a fallback, not a default.

### Nonces

Every `encrypt()` call draws a fresh 96-bit nonce from `os.urandom` inside the
crypto wrapper. Callers cannot supply one, so GCM nonce reuse — the one way to
catastrophically break this construction — cannot be triggered from anywhere
else in the codebase. With random 96-bit nonces the birthday bound is far beyond
any realistic number of saves.

### Additional authenticated data

The body's AAD is the entire file prefix: magic, version, header length and the
full plaintext header JSON. So the KDF algorithm, salt, cost parameters, cipher
name, compression name and the wrapped DEK are all covered. An attacker can edit
the header, but the result will not decrypt. This is what makes a parameter
downgrade detectable instead of silent.

The DEK wrap uses a separate AAD (a domain-separation string plus the canonical
KDF section), so a wrapped key cannot be transplanted between vaults with
different KDF parameters.

## What is deliberately absent

- **No password verifier.** Nothing in the file confirms the password before
  decryption. The AEAD tag is the check. This means no offline oracle that is
  cheaper than the real work.
- **No integrity hash beside the tag.** GCM already authenticates. A second
  checksum would add nothing and could disagree with the tag.
- **No encrypted search index.** An index over secrets is a side channel.
  Searching happens over already-decrypted, non-secret fields in memory.
- **No key stretching of the DEK.** It is 32 random bytes; stretching random
  bytes accomplishes nothing.
- **No custom cipher, hash, KDF or CSPRNG.** Not one line.

## Randomness in the generators

Every generated secret draws from `secrets.randbelow`, which is rejection-based
and free of modulo bias. Character-class requirements ("must contain a digit")
are satisfied by rejection sampling — draw a full uniform password, discard and
redraw if a class is missing — rather than by patching a character into a fixed
position, which would bias the distribution and quietly reduce entropy.

Reported entropy is computed from the alphabet actually used, and passphrase
entropy from `log2(len(wordlist))` at runtime, so the numbers match the list in
use rather than a hard-coded ideal.

## Verification

`tests/test_crypto.py` checks HKDF against RFC 5869 vector 1, requires that
flipping any single bit of any ciphertext raises, that a modified header breaks
authentication, that nonces never repeat across 200 encryptions, that key
material is zeroed on lock, and that no plaintext appears anywhere in a written
vault. `tests/test_tools.py` checks HOTP against all ten RFC 4226 vectors and
TOTP against the RFC 6238 vectors for SHA-1, SHA-256 and SHA-512.
