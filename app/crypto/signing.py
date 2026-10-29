"""ECDSA signatures and the signed file manifest.

    manifest      = canonical JSON {schema, chainId, contract, fileId, owner,
                                    ctHash, ctSize, ptDigest, enc, createdAt}
    manifestHash  = SHA-256(manifest)                         -> on-chain
    signature     = ECDSA(K_sig, manifest)                    -> off-chain, next to the manifest
    stored file   = canonical JSON {manifest, signature: {r, s}}

ECDSA over secp256k1 with SHA-256. Nonces are deterministic (RFC 6979), so a weak
or repeated RNG output cannot leak the signing key. s is normalised to the low
half of the group order and verify() accepts only that form: one valid encoding
per signature.

The signing public key is deliberately not stored with the manifest. Verifiers
must use the owner's sigPubKey registered on-chain (V4); otherwise an attacker
could re-sign a forged manifest with their own key.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from app.crypto import EncodingError, ManifestError, aead
from app.crypto.encoding import (
    HASH_LEN,
    N,
    FileContext,
    PrivateKey,
    canonical_json,
    from_hex,
    from_hex32,
    load_public_key,
    require_fields,
    require_int,
    sha256,
    strict_json_loads,
    to_hex,
    to_hex32,
)

SIGNATURE_ALGORITHM = "ECDSA-secp256k1-SHA256"
HALF_N = N // 2
SCALAR_LEN = 32

_SIGNATURE_FIELDS = frozenset({"r", "s"})


@dataclass(frozen=True)
class Signature:
    """ECDSA (r, s), range-checked; serialised as 32-byte hex each."""

    r: int
    s: int

    def __post_init__(self) -> None:
        for name, value in (("r", self.r), ("s", self.s)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value < N:
                raise EncodingError(f"Signature {name} must be in [1, N-1]")

    @property
    def is_low_s(self) -> bool:
        return self.s <= HALF_N

    def to_dict(self) -> dict[str, str]:
        return {"r": to_hex(self.r.to_bytes(SCALAR_LEN, "big")), "s": to_hex(self.s.to_bytes(SCALAR_LEN, "big"))}

    @classmethod
    def from_dict(cls, value: Any) -> Signature:
        fields = require_fields(value, _SIGNATURE_FIELDS, "Signature")
        r = int.from_bytes(from_hex(fields["r"], SCALAR_LEN, "Signature r"), "big")
        s = int.from_bytes(from_hex(fields["s"], SCALAR_LEN, "Signature s"), "big")
        return cls(r=r, s=s)


def sign(key: PrivateKey, message: bytes) -> Signature:
    """Sign SHA-256(message); the result always has low s."""
    der = key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return Signature(r=r, s=N - s if s > HALF_N else s)


def verify(public_key: bytes, message: bytes, signature: Signature) -> bool:
    """True only for a low-s signature by `public_key` over SHA-256(message).
    Raises InvalidKeyError if `public_key` itself is not a valid point."""
    key = load_public_key(public_key)
    if not signature.is_low_s:
        return False
    try:
        key.verify(encode_dss_signature(signature.r, signature.s), message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


# ------------------------------------------------------------------ manifest

SCHEMA = "sfs-manifest/1"
MAX_SIGNED_MANIFEST_BYTES = 16 * 1024

_MANIFEST_FIELDS = frozenset(
    {"schema", "chainId", "contract", "fileId", "owner", "ctHash", "ctSize", "ptDigest", "enc", "createdAt"}
)
_SIGNED_FIELDS = frozenset({"manifest", "signature"})


@dataclass(frozen=True)
class Manifest:
    """What the owner signs; its SHA-256 is anchored on-chain."""

    context: FileContext
    ct_hash: bytes
    ct_size: int
    pt_digest: bytes
    created_at: int

    def __post_init__(self) -> None:
        if len(self.ct_hash) != HASH_LEN or len(self.pt_digest) != HASH_LEN:
            raise EncodingError("ctHash and ptDigest must be 32 bytes")
        require_int(self.ct_size, "ctSize", minimum=aead.MIN_OBJECT_LEN)
        require_int(self.created_at, "createdAt")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "chainId": self.context.chain_id,
            "contract": self.context.contract,
            "fileId": to_hex32(self.context.file_id),
            "owner": self.context.owner,
            "ctHash": to_hex(self.ct_hash),
            "ctSize": self.ct_size,
            "ptDigest": to_hex(self.pt_digest),
            "enc": aead.ALGORITHM,
            "createdAt": self.created_at,
        }

    def to_bytes(self) -> bytes:
        """The exact bytes that are signed and hashed."""
        return canonical_json(self.to_dict())

    def digest(self) -> bytes:
        """manifestHash as registered on-chain."""
        return sha256(self.to_bytes())

    @classmethod
    def from_dict(cls, value: Any) -> Manifest:
        fields = require_fields(value, _MANIFEST_FIELDS, "Manifest")
        if fields["schema"] != SCHEMA:
            raise EncodingError(f"Unsupported manifest schema {fields['schema']!r}")
        if fields["enc"] != aead.ALGORITHM:
            raise EncodingError(f"Unsupported encryption {fields['enc']!r}")
        context = FileContext(
            chain_id=require_int(fields["chainId"], "chainId", minimum=1),
            contract=fields["contract"],
            file_id=from_hex32(fields["fileId"], "fileId"),
            owner=fields["owner"],
        )
        manifest = cls(
            context=context,
            ct_hash=from_hex(fields["ctHash"], HASH_LEN, "ctHash"),
            ct_size=require_int(fields["ctSize"], "ctSize"),
            pt_digest=from_hex(fields["ptDigest"], HASH_LEN, "ptDigest"),
            created_at=require_int(fields["createdAt"], "createdAt"),
        )
        # Rejects equivalent but non-canonical spellings, e.g. lowercase addresses.
        if manifest.to_dict() != fields:
            raise EncodingError("Manifest is not in canonical form")
        return manifest


@dataclass(frozen=True)
class SignedManifest:
    manifest: Manifest
    signature: Signature

    def to_bytes(self) -> bytes:
        """Content of manifests/<fileId>.json in storage."""
        return canonical_json({"manifest": self.manifest.to_dict(), "signature": self.signature.to_dict()})

    @classmethod
    def from_bytes(cls, data: bytes) -> SignedManifest:
        try:
            value = strict_json_loads(data, max_bytes=MAX_SIGNED_MANIFEST_BYTES, what="Signed manifest")
            fields = require_fields(value, _SIGNED_FIELDS, "Signed manifest")
            return cls(manifest=Manifest.from_dict(fields["manifest"]), signature=Signature.from_dict(fields["signature"]))
        except EncodingError as exc:
            raise ManifestError(f"Invalid signed manifest: {exc}") from exc


def build_manifest(ctx: FileContext, encrypted: aead.EncryptedFile, *, created_at: int | None = None) -> Manifest:
    """Manifest for a freshly encrypted file; createdAt defaults to now."""
    return Manifest(
        context=ctx,
        ct_hash=encrypted.ct_hash,
        ct_size=encrypted.ct_size,
        pt_digest=encrypted.pt_digest,
        created_at=int(time.time()) if created_at is None else created_at,
    )


def sign_manifest(sig_key: PrivateKey, manifest: Manifest) -> SignedManifest:
    return SignedManifest(manifest=manifest, signature=sign(sig_key, manifest.to_bytes()))


def verify_manifest(sig_public_key: bytes, signed: SignedManifest) -> bool:
    """V4: `sig_public_key` must be the owner's key as registered on-chain."""
    return verify(sig_public_key, signed.manifest.to_bytes(), signed.signature)
