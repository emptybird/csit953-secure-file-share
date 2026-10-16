"""ECIES wrapping of a file's DEK for one recipient (DESIGN.md 6.1).

    E          = e*G for a fresh ephemeral scalar e                   (33-byte compressed)
    Z          = x-coordinate of e*encPub_R                            (ECDH, 32 bytes)
    KEK        = HKDF-SHA256(IKM = Z, salt = E | encPub_R,
                             info = "SFS-keywrap-v1" | chainId | contract | fileId | recipient,
                             length = 32)
    C          = AES-256-GCM(KEK, n, DEK, AAD = fileId | recipient)   # 32 + 16 bytes
    wrappedKey = E | n | C                                             # 33 + 12 + 48 = 93 bytes

Only the holder of the recipient's encryption key can compute Z. The file and
the recipient are bound into both the KEK and the AAD, so a wrapped key copied
to another file or handed to another person does not open.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.crypto import InvalidKeyError, KeyUnwrapError
from app.crypto.aead import DEK_LEN, NONCE_LEN, TAG_LEN, check_dek
from app.crypto.encoding import (
    PUBLIC_KEY_LEN,
    FileContext,
    PrivateKey,
    address_bytes,
    generate_private_key,
    load_public_key,
    public_key_bytes,
)

INFO_TAG = b"SFS-keywrap-v1"
KEK_LEN = 32
WRAPPED_KEY_LEN = PUBLIC_KEY_LEN + NONCE_LEN + DEK_LEN + TAG_LEN  # 93, SecureFileShare.WRAPPED_KEY_LEN


def wrap_key(dek: bytes, recipient_enc_key: bytes, ctx: FileContext, recipient: str) -> bytes:
    """Encrypt `dek` so that only the owner of `recipient_enc_key` (the encPubKey
    registered on-chain for `recipient`) can recover it.
    Raises InvalidKeyError if that public key is not a valid point."""
    check_dek(dek)
    recipient_key = load_public_key(recipient_enc_key)
    ephemeral = generate_private_key()
    ephemeral_pub = public_key_bytes(ephemeral)
    shared = ephemeral.exchange(ec.ECDH(), recipient_key)
    kek = _derive_kek(shared, ephemeral_pub, recipient_enc_key, ctx, recipient)
    nonce = os.urandom(NONCE_LEN)
    return ephemeral_pub + nonce + AESGCM(kek).encrypt(nonce, dek, _aad(ctx, recipient))


def unwrap_key(wrapped_key: bytes, enc_key: PrivateKey, ctx: FileContext, recipient: str) -> bytes:
    """Recover the DEK with the recipient's own encryption private key."""
    if not isinstance(wrapped_key, bytes) or len(wrapped_key) != WRAPPED_KEY_LEN:
        raise KeyUnwrapError(f"Wrapped key must be {WRAPPED_KEY_LEN} bytes")
    ephemeral_pub = wrapped_key[:PUBLIC_KEY_LEN]
    nonce = wrapped_key[PUBLIC_KEY_LEN : PUBLIC_KEY_LEN + NONCE_LEN]
    ciphertext = wrapped_key[PUBLIC_KEY_LEN + NONCE_LEN :]
    try:
        ephemeral = load_public_key(ephemeral_pub)
    except InvalidKeyError:
        raise KeyUnwrapError("Wrapped key contains an invalid ephemeral public key") from None

    shared = enc_key.exchange(ec.ECDH(), ephemeral)
    kek = _derive_kek(shared, ephemeral_pub, public_key_bytes(enc_key), ctx, recipient)
    try:
        return AESGCM(kek).decrypt(nonce, ciphertext, _aad(ctx, recipient))
    except InvalidTag:
        raise KeyUnwrapError("Wrapped key does not open with this key for this file and recipient") from None


def _derive_kek(shared: bytes, ephemeral_pub: bytes, recipient_pub: bytes, ctx: FileContext, recipient: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEK_LEN,
        salt=ephemeral_pub + recipient_pub,
        info=INFO_TAG + ctx.location_bytes() + address_bytes(recipient),
    )
    return hkdf.derive(shared)


def _aad(ctx: FileContext, recipient: str) -> bytes:
    return ctx.file_id + address_bytes(recipient)
