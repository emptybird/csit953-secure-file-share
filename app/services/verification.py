"""The requester's V1–V6 checks (DESIGN.md 4.3), as pure functions.

    V1   SHA-256(downloaded object) == on-chain ctHash        storage changed or rolled back the ciphertext
    V2   SHA-256(manifest) == on-chain manifestHash           storage changed the manifest
    V3   manifest fields == on-chain record                   manifest moved from another file, owner or chain
    V4   ECDSA verify with the owner's ON-CHAIN sigPubKey     forged or re-signed manifest
    Key  ECIES unwrap of the DEK                              wrapped key for someone or something else
    V5   AES-256-GCM decrypt, tag verifies                    modified ciphertext, wrong AAD
    V6   SHA-256(P) == manifest.ptDigest                      content differs from what the owner signed

The trusted side (Anchor) comes from the chain; the untrusted side (Fetched)
from storage. V1–V4 always all run, so the report shows every independent
problem at once. The key is unwrapped and the object decrypted only when V1–V4
passed, unless `force_decrypt` is set: the tamper demo uses that to show GCM
catching a modified object as well. Plaintext is returned only if all seven pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.crypto import CryptoError, DecryptionError, KeyUnwrapError, ManifestError, aead, ecies, signing
from app.crypto.encoding import FileContext, PrivateKey, fingerprint, sha256
from app.services.models import Check, CheckResult, Outcome, RetrievedFile, VerificationReport

_PREFIX = 16


@dataclass(frozen=True)
class Anchor:
    """What the chain says about the file. Trusted (DESIGN.md 3)."""

    context: FileContext
    ct_hash: bytes
    manifest_hash: bytes
    owner_sig_key: bytes


@dataclass(frozen=True)
class Fetched:
    """One download from storage: the bytes, or why there are none. Untrusted."""

    data: bytes | None = field(default=None, repr=False)
    error: str = ""


def verify_and_decrypt(
    anchor: Anchor,
    obj: Fetched,
    manifest: Fetched,
    *,
    wrapped_key: bytes,
    enc_key: PrivateKey,
    recipient: str,
    force_decrypt: bool = False,
) -> RetrievedFile:
    v1 = _check_ct_hash(anchor, obj)
    signed, v2 = _check_manifest_hash(anchor, manifest)
    v3 = _check_context(anchor, signed)
    v4 = _check_signature(anchor, signed)
    before_key = (v1, v2, v3, v4)

    if not force_decrypt and not all(r.passed for r in before_key):
        reason = "Skipped because an earlier check failed"
        rest = tuple(_skipped(check, reason) for check in (Check.UNWRAP, Check.V5_DECRYPT, Check.V6_PT_DIGEST))
        return RetrievedFile(report=VerificationReport(anchor.context.file_id, before_key + rest))

    dek, unwrap = _unwrap(anchor, wrapped_key, enc_key, recipient)
    decrypted, v5 = _decrypt(anchor, dek, obj)
    v6 = _check_pt_digest(signed, decrypted)
    report = VerificationReport(anchor.context.file_id, (*before_key, unwrap, v5, v6))
    return RetrievedFile(report=report, plaintext=decrypted if report.ok else None)


# ------------------------------------------------------------------ checks


def _check_ct_hash(anchor: Anchor, obj: Fetched) -> CheckResult:
    if obj.data is None:
        return _failed(Check.V1_CT_HASH, obj.error or "The encrypted object could not be downloaded")
    actual = sha256(obj.data)
    if actual != anchor.ct_hash:
        return _failed(
            Check.V1_CT_HASH,
            f"Stored object hashes to {_short(actual)}; the chain records {_short(anchor.ct_hash)}",
        )
    return _passed(Check.V1_CT_HASH, f"SHA-256 {_short(actual)} ({len(obj.data):,} bytes)")


def _check_manifest_hash(anchor: Anchor, manifest: Fetched) -> tuple[signing.SignedManifest | None, CheckResult]:
    if manifest.data is None:
        return None, _failed(Check.V2_MANIFEST_HASH, manifest.error or "The manifest could not be downloaded")
    try:
        signed = signing.SignedManifest.from_bytes(manifest.data)
    except ManifestError as exc:
        return None, _failed(Check.V2_MANIFEST_HASH, str(exc))
    actual = signed.manifest.digest()
    if actual != anchor.manifest_hash:
        detail = f"Manifest hashes to {_short(actual)}; the chain records {_short(anchor.manifest_hash)}"
        return signed, _failed(Check.V2_MANIFEST_HASH, detail)
    return signed, _passed(Check.V2_MANIFEST_HASH, f"SHA-256 {_short(actual)}")


def _check_context(anchor: Anchor, signed: signing.SignedManifest | None) -> CheckResult:
    if signed is None:
        return _skipped(Check.V3_CONTEXT, "No readable manifest")
    manifest, expected = signed.manifest, anchor.context
    fields = (
        ("chainId", manifest.context.chain_id == expected.chain_id),
        ("contract", manifest.context.contract == expected.contract),
        ("fileId", manifest.context.file_id == expected.file_id),
        ("owner", manifest.context.owner == expected.owner),
        ("ctHash", manifest.ct_hash == anchor.ct_hash),
    )
    wrong = [name for name, same in fields if not same]
    if wrong:
        return _failed(Check.V3_CONTEXT, f"Manifest fields differ from the on-chain record: {', '.join(wrong)}")
    return _passed(Check.V3_CONTEXT, f"chainId {expected.chain_id}, owner {expected.owner}")


def _check_signature(anchor: Anchor, signed: signing.SignedManifest | None) -> CheckResult:
    if signed is None:
        return _skipped(Check.V4_SIGNATURE, "No readable manifest")
    if not anchor.owner_sig_key:
        return _failed(Check.V4_SIGNATURE, "The owner has no signing key registered on-chain")
    key_fp = fingerprint(anchor.owner_sig_key)
    try:
        valid = signing.verify_manifest(anchor.owner_sig_key, signed)
    except CryptoError as exc:
        return _failed(Check.V4_SIGNATURE, f"The owner's on-chain signing key is unusable: {exc}")
    if not valid:
        return _failed(Check.V4_SIGNATURE, f"Signature does not verify with the owner's on-chain key {key_fp}")
    return _passed(Check.V4_SIGNATURE, f"Signed with the owner's on-chain key {key_fp}")


def _unwrap(
    anchor: Anchor, wrapped_key: bytes, enc_key: PrivateKey, recipient: str
) -> tuple[bytes | None, CheckResult]:
    try:
        dek = ecies.unwrap_key(wrapped_key, enc_key, anchor.context, recipient)
    except KeyUnwrapError as exc:
        return None, _failed(Check.UNWRAP, str(exc))
    return dek, _passed(Check.UNWRAP, f"Wrapped for {recipient}")


def _decrypt(anchor: Anchor, dek: bytes | None, obj: Fetched) -> tuple[aead.DecryptedFile | None, CheckResult]:
    if dek is None:
        return None, _skipped(Check.V5_DECRYPT, "No file key")
    if obj.data is None:
        return None, _skipped(Check.V5_DECRYPT, "No encrypted object")
    try:
        decrypted = aead.decrypt_file(dek, anchor.context, obj.data)
    except DecryptionError as exc:
        return None, _failed(Check.V5_DECRYPT, str(exc))
    header = decrypted.header
    return decrypted, _passed(Check.V5_DECRYPT, f"Tag verified: {header.name}, {header.size:,} bytes")


def _check_pt_digest(signed: signing.SignedManifest | None, decrypted: aead.DecryptedFile | None) -> CheckResult:
    if decrypted is None:
        return _skipped(Check.V6_PT_DIGEST, "Nothing was decrypted")
    if signed is None:
        return _skipped(Check.V6_PT_DIGEST, "No readable manifest for comparison")
    if decrypted.pt_digest != signed.manifest.pt_digest:
        return _failed(
            Check.V6_PT_DIGEST,
            f"Plaintext digest {_short(decrypted.pt_digest)} differs from the signed digest "
            f"{_short(signed.manifest.pt_digest)}",
        )
    return _passed(Check.V6_PT_DIGEST, f"SHA-256(P) {_short(decrypted.pt_digest)}")


# ----------------------------------------------------------------- helpers


def _passed(check: Check, detail: str) -> CheckResult:
    return CheckResult(check, Outcome.PASSED, detail)


def _failed(check: Check, detail: str) -> CheckResult:
    return CheckResult(check, Outcome.FAILED, detail)


def _skipped(check: Check, detail: str) -> CheckResult:
    return CheckResult(check, Outcome.SKIPPED, detail)


def _short(digest: bytes) -> str:
    return digest.hex()[:_PREFIX] + "…"
