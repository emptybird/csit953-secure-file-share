"""File encryption with AES-256-GCM.

    P      = len(header) (4, big-endian) | header | file bytes
    AAD    = "SFS-v1" | chainId (32) | contract (20) | fileId (32) | owner (20)
    object = "SFS1" | nonce (12) | AES-256-GCM(DEK, nonce, P, AAD)    # last 16 bytes are the tag

The file name lives in the encrypted header, so storage never sees it. The random
header salt stops a guessed file from being confirmed against SHA-256(P).
One DEK per object, so a random 96-bit nonce is never reused under a key.
"""

from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto import DecryptionError, EncodingError
from app.crypto.encoding import (
    FileContext,
    address_bytes,
    canonical_json,
    from_hex,
    require_fields,
    require_int,
    require_str,
    sha256,
    strict_json_loads,
    to_hex,
)

ALGORITHM = "AES-256-GCM"
OBJECT_MAGIC = b"SFS1"
AAD_TAG = b"SFS-v1"
DEK_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN_BYTES = 4
HEADER_SALT_LEN = 16
MAX_HEADER_BYTES = 4096
MAX_NAME_CHARS = 255
MAX_MIME_CHARS = 127
DEFAULT_MIME = "application/octet-stream"
MIN_OBJECT_LEN = len(OBJECT_MAGIC) + NONCE_LEN + TAG_LEN

_HEADER_FIELDS = frozenset({"name", "mime", "size", "salt"})
_FORBIDDEN_NAMES = frozenset({".", ".."})
# Unicode categories banned in file names: controls (Cc), invisible format chars (Cf;
# U+202E RIGHT-TO-LEFT OVERRIDE renders "invoice<U+202E>fdp.exe" as "invoiceexe.pdf"),
# lone surrogates (Cs), line and paragraph separators (Zl, Zp).
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


@dataclass(frozen=True)
class FileHeader:
    """Metadata encrypted together with the content."""

    name: str
    mime: str
    size: int
    salt: bytes

    def __post_init__(self) -> None:
        _check_file_name(self.name)
        _check_mime(self.mime)
        require_int(self.size, "File size")
        if len(self.salt) != HEADER_SALT_LEN:
            raise EncodingError("Header salt must be 16 bytes")

    def to_bytes(self) -> bytes:
        return canonical_json({"name": self.name, "mime": self.mime, "size": self.size, "salt": to_hex(self.salt)})

    @classmethod
    def from_bytes(cls, data: bytes) -> FileHeader:
        value = require_fields(
            strict_json_loads(data, max_bytes=MAX_HEADER_BYTES, what="File header"), _HEADER_FIELDS, "File header"
        )
        return cls(
            name=require_str(value["name"], "File name", max_chars=MAX_NAME_CHARS),
            mime=require_str(value["mime"], "MIME type", max_chars=MAX_MIME_CHARS),
            size=require_int(value["size"], "File size"),
            salt=from_hex(value["salt"], HEADER_SALT_LEN, "Header salt"),
        )


@dataclass(frozen=True)
class EncryptedFile:
    object_bytes: bytes = field(repr=False)
    ct_hash: bytes  # SHA-256(object): storage address and on-chain ctHash
    pt_digest: bytes  # SHA-256(P): signed in the manifest, checked after decryption (V6)

    @property
    def ct_size(self) -> int:
        return len(self.object_bytes)


@dataclass(frozen=True)
class DecryptedFile:
    header: FileHeader
    content: bytes = field(repr=False)
    pt_digest: bytes


def generate_dek() -> bytes:
    """A new 256-bit data encryption key for exactly one file."""
    return os.urandom(DEK_LEN)


def file_aad(ctx: FileContext) -> bytes:
    """Binds the object to its on-chain record: chain, contract, fileId, owner."""
    return AAD_TAG + ctx.location_bytes() + address_bytes(ctx.owner)


def encrypt_file(dek: bytes, ctx: FileContext, *, name: str, content: bytes, mime: str = DEFAULT_MIME) -> EncryptedFile:
    """Seal header + content under `dek`, bound to `ctx` through the AAD."""
    check_dek(dek)
    header = FileHeader(name=name, mime=mime, size=len(content), salt=os.urandom(HEADER_SALT_LEN)).to_bytes()
    plaintext = len(header).to_bytes(HEADER_LEN_BYTES, "big") + header + content
    nonce = os.urandom(NONCE_LEN)
    object_bytes = OBJECT_MAGIC + nonce + AESGCM(dek).encrypt(nonce, plaintext, file_aad(ctx))
    return EncryptedFile(object_bytes=object_bytes, ct_hash=sha256(object_bytes), pt_digest=sha256(plaintext))


def decrypt_file(dek: bytes, ctx: FileContext, object_bytes: bytes) -> DecryptedFile:
    """Open an SFS1 object. Raises DecryptionError if the tag does not verify:
    wrong DEK, different file context (AAD) or any modified byte."""
    check_dek(dek)
    if len(object_bytes) < MIN_OBJECT_LEN or not object_bytes.startswith(OBJECT_MAGIC):
        raise DecryptionError("Not an SFS1 ciphertext object")
    nonce_end = len(OBJECT_MAGIC) + NONCE_LEN
    nonce = object_bytes[len(OBJECT_MAGIC) : nonce_end]
    try:
        plaintext = AESGCM(dek).decrypt(nonce, object_bytes[nonce_end:], file_aad(ctx))
    except InvalidTag:
        raise DecryptionError(
            "AES-GCM authentication failed: wrong key, wrong file record or modified ciphertext"
        ) from None
    header, content = _split_plaintext(plaintext)
    return DecryptedFile(header=header, content=content, pt_digest=sha256(plaintext))


def _split_plaintext(plaintext: bytes) -> tuple[FileHeader, bytes]:
    """Split P into header and content. A valid tag does not make P well-formed (the
    owner may be malicious), so every length is checked."""
    if len(plaintext) < HEADER_LEN_BYTES:
        raise DecryptionError("Decrypted data is too short")
    header_len = int.from_bytes(plaintext[:HEADER_LEN_BYTES], "big")
    header_end = HEADER_LEN_BYTES + header_len
    if header_len > MAX_HEADER_BYTES or header_end > len(plaintext):
        raise DecryptionError("Decrypted header length is invalid")
    try:
        header = FileHeader.from_bytes(plaintext[HEADER_LEN_BYTES:header_end])
    except EncodingError as exc:
        raise DecryptionError(f"Decrypted header is invalid: {exc}") from exc
    content = plaintext[header_end:]
    if header.size != len(content):
        raise DecryptionError("Decrypted size does not match the header")
    return header, content


def check_dek(dek: bytes) -> None:
    if not isinstance(dek, bytes) or len(dek) != DEK_LEN:
        raise EncodingError("DEK must be 32 bytes")


def _check_file_name(name: str) -> None:
    """Bare file name only: no separators, so saving cannot escape the target folder;
    no invisible characters, so the name shown is the name saved. Re-checked on
    decryption, since a malicious owner need not use this client."""
    require_str(name, "File name", max_chars=MAX_NAME_CHARS)
    unsafe = any(ch in "/\\" or unicodedata.category(ch) in _FORBIDDEN_CATEGORIES for ch in name)
    if name in _FORBIDDEN_NAMES or unsafe:
        raise EncodingError("File name must not contain path separators, control or formatting characters")


def _check_mime(mime: str) -> None:
    require_str(mime, "MIME type", max_chars=MAX_MIME_CHARS)
    if not mime.isascii() or not mime.isprintable() or " " in mime:
        raise EncodingError("MIME type must be printable ASCII without spaces")
