# Backup and recovery

A password manager that loses your data is worse than no password manager. Read
this section once, now, rather than after something has gone wrong.

## The one thing to understand

**There is no recovery for a forgotten master password.** No reset, no backdoor,
no support address that can help. The password is not stored anywhere, in any
form. If you forget it, the vault is random bytes forever.

So: write the master password on paper and put it somewhere safe. This is not
old-fashioned advice; it is the only recovery mechanism that exists.

## What a backup is

A byte-for-byte copy of the encrypted vault file. Same crypto, same password,
no weaker "backup format". Consequences worth knowing:

- A backup is safe to store anywhere an attacker might see it, exactly as safe
  as the vault itself.
- A backup opens with the password in force **when it was taken**. Change your
  master password and old backups keep the old one. Keep track.
- Any build that can read the format can read a backup, including the forty-line
  script in [VAULT_FORMAT.md](VAULT_FORMAT.md).

## Making backups

```bash
lockbox backup create                     # default: <vault dir>/backups/
lockbox backup create --dir /mnt/usb/lb   # anywhere you like
lockbox backup create --label pre-cleanup # tag it
lockbox backup list
```

In the GUI: `Ctrl+B`, or the command palette.

Files are named `vault-YYYYMMDD-HHMMSS[-label].lbx`, in a directory created
mode 0700. Old ones are pruned to `settings.backup_keep` (default 10, newest
kept). Lockbox reminds you in the status bar after `backup_reminder_days`
(default 14) without one. It never backs up on a schedule of its own, and it
never uploads anything.

## Verifying backups

An unverified backup is a hope, not a backup.

```bash
lockbox backup verify path/to/vault-20260824-120000.lbx          # structure only
lockbox backup verify path/to/vault-20260824-120000.lbx --deep   # actually decrypt
```

`--deep` derives the key, decrypts the whole payload, and reports the item
count. That is the only check that proves the file is restorable. Structure-only
verification catches truncation and corruption but not a wrong password.

Do a `--deep` verify whenever you change your master password, and periodically
on your archive copies.

## Restoring

```bash
lockbox backup restore path/to/backup.lbx
```

The backup is fully decrypted **before** anything is overwritten, so a wrong
password or a damaged file cannot destroy your working vault — the operation
fails and nothing changes. This is covered by a test. The vault being replaced
is kept as `vault.lbx.prev`.

In the GUI: command palette → "Restore from backup".

## The `.prev` file

Every save renames the previous vault to `<vault>.prev` before writing the new
one. It is a one-deep undo for "I just deleted the wrong item and saved". To use
it, close Lockbox and move the file back:

```bash
mv ~/.local/share/lockbox/vault.lbx.prev ~/.local/share/lockbox/vault.lbx
```

It is overwritten on the next save, so it is a safety net, not an archive.

## A backup routine worth actually following

1. **Weekly**, or after any batch of changes: `lockbox backup create`.
2. **Monthly**: copy the newest backup to removable media that lives somewhere
   else. Encrypted, so a drawer at another address is fine.
3. **Quarterly**: `lockbox backup verify <newest> --deep`, and once a year
   actually restore one into a scratch path to prove you know how:
   ```bash
   lockbox --vault /tmp/drill.lbx backup restore /mnt/usb/lb/vault-....lbx -y
   lockbox --vault /tmp/drill.lbx list
   rm /tmp/drill.lbx
   ```
4. **After every master-password change**: make a fresh backup and label it, so
   you know where the password boundary falls.

## Cloud storage

Lockbox will never upload anything. If *you* put a backup in a synced folder,
that is a decision you are entitled to make: the file is encrypted with
AES-256-GCM under an Argon2id key, which is the case a strong master password
exists for. Two cautions:

- Sync clients keep version history you cannot easily purge.
- A plaintext export in a synced folder is a catastrophe, which is why Lockbox
  refuses to write one to a path that looks like Dropbox, OneDrive, Google
  Drive, iCloud and friends.

## Migrating to another manager

```bash
lockbox export out.csv --format csv --confirm 'I UNDERSTAND'
# import into the other program, verify it worked, then:
shred -u out.csv     # or: python3 -c "from lockbox.core.portio import shred; shred('out.csv')"
```

Understand that `shred` is best-effort on modern storage: SSD wear-levelling,
copy-on-write filesystems and journals can retain the old blocks. The safest
plaintext export is one that lived on an encrypted volume and existed for two
minutes.

## Disaster scenarios

| Situation | What to do |
| --- | --- |
| Deleted an item, saved, noticed immediately | Restore `vault.lbx.prev` |
| Vault will not open, password is right | Restore the newest backup; `--deep` verify first |
| Disk died | Restore from removable media |
| Machine stolen | The vault is encrypted. Change the important passwords anyway, in priority order — the thief has an offline cracking target. |
| Forgot the master password | Nothing can be done. Start a new vault and reset accounts. |
| Lockbox itself is gone/broken | Use the recovery script in [VAULT_FORMAT.md](VAULT_FORMAT.md) — it is tested and needs only `argon2-cffi` and `cryptography`. |
