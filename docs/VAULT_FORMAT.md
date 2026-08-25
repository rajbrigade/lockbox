# Vault format (v1)

A vault is one file. The format is small enough to reimplement from this page,
which is the point: your data should not depend on this program surviving.

## Layout

All integers big-endian.

```
offset  size        contents
------  ----------  --------------------------------------------------------
0       4           magic  b"LBXV"
4       2           uint16 format version (currently 1)
6       4           uint32 header length H
10      H           header: canonical UTF-8 JSON, PLAINTEXT
10+H    12          AES-GCM nonce
22+H    N           AES-GCM ciphertext
22+H+N  16          AES-GCM tag
```

The header is plaintext because it must be read before a key exists. It is fed
to the body's AES-GCM as additional authenticated data, so editing it breaks
decryption.

## Header

Canonical JSON: keys sorted, no whitespace (`separators=(",", ":")`). Byte
stability matters because these exact bytes are the AAD.

```json
{
  "cipher": "AES-256-GCM",
  "compression": "zlib",
  "kdf": {
    "algorithm": "argon2id",
    "params": {"iterations": 3, "memory_kib": 65536, "parallelism": 1},
    "salt": "1f8b3c...32 hex chars..."
  },
  "wrapped_dek": "…hex: 12-byte nonce ‖ 32-byte ciphertext ‖ 16-byte tag…"
}
```

| Field | Meaning |
| --- | --- |
| `cipher` | Always `AES-256-GCM` in v1. Present so a future format can change it explicitly. |
| `compression` | `zlib`, level 6, applied to the JSON payload before encryption. |
| `kdf.algorithm` | `argon2id` or `scrypt`. |
| `kdf.params` | Argon2: `memory_kib`, `iterations`, `parallelism`. scrypt: `n`, `r`, `p`. |
| `kdf.salt` | 16 random bytes, hex. Fresh per vault and per password change. |
| `wrapped_dek` | The data key under the KEK, AAD = `b"lockbox/dek-wrap/v1"` + canonical `kdf` JSON. |

## Payload

zlib-compressed canonical JSON:

```json
{
  "schema": 1,
  "items": [ … ],
  "folders": ["Work", "Personal"],
  "settings": {
    "auto_lock_seconds": 300,
    "clipboard_clear_seconds": 20,
    "clear_clipboard_on_lock": true,
    "password_age_warning_days": 365,
    "min_password_length": 12,
    "backup_reminder_days": 14,
    "backup_keep": 10,
    "history_limit": 10,
    "breach_dataset_path": ""
  },
  "meta": {"created": 1750000000, "updated": 1750000600, "last_backup": 0}
}
```

### Item

```json
{
  "id": "32 hex chars (uuid4)",
  "type": "login | note | card | identity | api_key",
  "title": "GitHub",
  "username": "octocat",
  "password": "…",
  "url": "https://github.com",
  "notes": "free text",
  "tags": ["work", "dev"],
  "folder": "Dev",
  "favorite": false,
  "totp_secret": "base32, no padding",
  "fields": {"Recovery code": "…"},
  "created": 1750000000,
  "updated": 1750000600,
  "password_updated": 1750000000,
  "history": [{"password": "previous", "changed": 1740000000}]
}
```

Timestamps are Unix seconds. `fields` holds arbitrary custom key/value pairs,
including anything an import did not recognise, so importing never loses data.
`history` is capped by `settings.history_limit` (oldest dropped first).

Cards and identities use `fields` rather than dedicated columns — a card is a
note with a well-known set of field names — which keeps the schema from growing
a column per document type.

## Writing

1. Serialise and compress the payload.
2. Encrypt with the DEK, AAD = the whole file prefix.
3. Write to `.<name>.tmp` in the same directory, mode 0600.
4. `flush()` + `fsync()`.
5. Rename the current vault to `<name>.prev`.
6. `os.replace(tmp, path)` — atomic on POSIX and on Windows.
7. `fsync` the directory (best effort; some filesystems refuse).

At no point does a partially written file occupy the vault's path.

## Reading

1. Check the magic and version. Unknown version → refuse; do not guess.
2. Parse the header; reject if `kdf` or `wrapped_dek` is missing.
3. Derive the KEK from the password and `kdf.salt`.
4. Unwrap the DEK. Failure here means wrong password (or tampering).
5. Decrypt the body with AAD = prefix. Failure means tampering.
6. Inflate, parse JSON, normalise the payload.
7. Refuse a `schema` higher than this build supports.

## Compatibility

`version` covers the container; `schema` covers the payload. New optional item
fields do not need a schema bump — `Item.from_dict` fills defaults for anything
absent. A change that would make an old build misread data does need one, and a
newer schema is refused rather than silently mangled.

## Recovering without Lockbox

Roughly forty lines, given the password:

```python
import json, struct, zlib
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

blob = open("vault.lbx", "rb").read()
assert blob[:4] == b"LBXV"
version, hlen = struct.unpack(">HI", blob[4:10])
prefix, header = blob[:10 + hlen], json.loads(blob[10:10 + hlen])
body = blob[10 + hlen:]

kdf = header["kdf"]
kek = hash_secret_raw(
    secret=b"YOUR MASTER PASSWORD",
    salt=bytes.fromhex(kdf["salt"]),
    time_cost=kdf["params"]["iterations"],
    memory_cost=kdf["params"]["memory_kib"],
    parallelism=kdf["params"]["parallelism"],
    hash_len=32, type=Type.ID,
)

wrap_aad = b"lockbox/dek-wrap/v1" + json.dumps(
    kdf, sort_keys=True, separators=(",", ":")).encode()
wrapped = bytes.fromhex(header["wrapped_dek"])
dek = AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], wrap_aad)

payload = json.loads(zlib.decompress(AESGCM(dek).decrypt(body[:12], body[12:], prefix)))
print(len(payload["items"]), "items")
```

If that script ever stops working against a file this program wrote, the bug is
in the program.
