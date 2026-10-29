"""Client-side cryptography.

encoding  canonical bytes for everything hashed, signed or used as AAD; secp256k1 keys
aead      AES-256-GCM file encryption
signing   ECDSA-secp256k1-SHA256 signatures and the signed file manifest
ecies     DEK wrapping for one recipient
keystore  password-protected storage of a user's three private keys

Exceptions below are shared by all modules; their messages are safe to show to users.
"""

from __future__ import annotations


class CryptoError(Exception):
    """Base class for every crypto failure; catch this one type."""


class EncodingError(CryptoError, ValueError):
    """Data does not have the expected format."""


class InvalidKeyError(CryptoError, ValueError):
    """A key is malformed, out of range or not a point on secp256k1."""


class DecryptionError(CryptoError):
    """A ciphertext object cannot be decrypted or its content is malformed."""


class KeyUnwrapError(CryptoError):
    """A wrapped DEK cannot be recovered with this key and context."""


class ManifestError(CryptoError):
    """A signed manifest file is malformed."""


class KeystoreError(CryptoError):
    """A keystore cannot be created, read or unlocked."""
