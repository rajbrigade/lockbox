"""Exception hierarchy. Error messages never contain secret material."""


class LockboxError(Exception):
    """Base class for all Lockbox errors."""


class DecryptError(LockboxError):
    """Authenticated decryption failed (wrong password, or tampering)."""


class VaultFormatError(LockboxError):
    """The vault file is not a Lockbox vault, or is corrupt."""


class VaultLockedError(LockboxError):
    """An operation needing plaintext was attempted on a locked vault."""


class KDFUnavailableError(LockboxError):
    """The KDF named in the vault header is not available on this machine."""


class ImportError_(LockboxError):
    """Import parsing failed."""
