from __future__ import annotations

import dataclasses
import json
from typing import Any, Callable

import pytest

from app.crypto import EncodingError, InvalidKeyError, ManifestError, aead
from app.crypto.encoding import N, FileContext, generate_private_key, public_key_bytes, sha256
from app.crypto.keystore import UserKeys
from app.crypto.signing import (
    HALF_N,
    MAX_SIGNED_MANIFEST_BYTES,
    Manifest,
    Signature,
    SignedManifest,
    build_manifest,
    sign,
    sign_manifest,
    verify,
    verify_manifest,
)

from .conftest import CONTRACT
from .test_encoding import VECTOR_FILE_ID, VECTOR_OWNER

MESSAGE = b'{"schema":"sfs-manifest/1"}'

GOLDEN_MANIFEST = Manifest(
    context=FileContext(31337, CONTRACT, VECTOR_FILE_ID, VECTOR_OWNER),
    ct_hash=b"\x11" * 32,
    ct_size=1234,
    pt_digest=b"\x22" * 32,
    created_at=1_760_000_000,
)
GOLDEN_BYTES = (
    '{"chainId":31337,"contract":"0x5FbDB2315678afecb367f032d93F642f64180aa3","createdAt":1760000000,'
    f'"ctHash":"{"11" * 32}","ctSize":1234,"enc":"AES-256-GCM",'
    f'"fileId":"0x{VECTOR_FILE_ID.hex()}","owner":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",'
    f'"ptDigest":"{"22" * 32}","schema":"sfs-manifest/1"}}'
).encode()


@pytest.fixture(scope="module")
def key_pair() -> tuple:
    key = generate_private_key()
    return key, public_key_bytes(key)


def test_sign_and_verify(key_pair: tuple) -> None:
    key, public = key_pair
    assert verify(public, MESSAGE, sign(key, MESSAGE))


def test_signing_is_deterministic(key_pair: tuple) -> None:
    """RFC 6979: no fresh random nonce, so a bad RNG cannot leak the key."""
    key, _ = key_pair
    assert sign(key, MESSAGE) == sign(key, MESSAGE)
    assert sign(key, MESSAGE).r != sign(key, MESSAGE + b" ").r


def test_signatures_are_low_s(key_pair: tuple) -> None:
    key, _ = key_pair
    assert all(sign(key, MESSAGE + bytes([i])).s <= HALF_N for i in range(64))


def test_high_s_twin_is_rejected(key_pair: tuple) -> None:
    """(r, N - s) is mathematically valid too; accepting one form keeps signatures unique."""
    key, public = key_pair
    signature = sign(key, MESSAGE)
    assert not verify(public, MESSAGE, Signature(r=signature.r, s=N - signature.s))


def test_modified_message_fails(key_pair: tuple) -> None:
    key, public = key_pair
    assert not verify(public, MESSAGE + b"x", sign(key, MESSAGE))


def test_other_public_key_fails(key_pair: tuple) -> None:
    key, _ = key_pair
    other = public_key_bytes(generate_private_key())
    assert not verify(other, MESSAGE, sign(key, MESSAGE))


def test_invalid_public_key_raises(key_pair: tuple) -> None:
    key, public = key_pair
    with pytest.raises(InvalidKeyError):
        verify(b"\x04" + public[1:], MESSAGE, sign(key, MESSAGE))


class TestSignatureEncoding:
    def test_dict_round_trip(self, key_pair: tuple) -> None:
        key, _ = key_pair
        signature = sign(key, MESSAGE)
        encoded = signature.to_dict()
        assert set(encoded) == {"r", "s"}
        assert all(len(part) == 64 for part in encoded.values())
        assert Signature.from_dict(encoded) == signature

    @pytest.mark.parametrize(("r", "s"), [(0, 1), (1, 0), (N, 1), (1, N), (True, 1)])
    def test_rejects_out_of_range_values(self, r: int, s: int) -> None:
        with pytest.raises(EncodingError):
            Signature(r=r, s=s)

    @pytest.mark.parametrize(
        "value",
        [
            {"r": "AB" * 32, "s": "01" * 32},
            {"r": "01" * 31, "s": "01" * 32},
            {"r": "01" * 32, "s": "01" * 32, "v": 27},
            {"r": "01" * 32},
            ["01" * 32, "01" * 32],
        ],
        ids=["uppercase", "short", "extra-field", "missing-s", "list"],
    )
    def test_from_dict_is_strict(self, value: object) -> None:
        with pytest.raises(EncodingError):
            Signature.from_dict(value)


# ------------------------------------------------------------------ manifest


@pytest.fixture
def signed(alice: UserKeys, ctx: FileContext, dek: bytes) -> SignedManifest:
    encrypted = aead.encrypt_file(dek, ctx, name="notes.txt", content=b"lecture notes")
    return sign_manifest(alice.sig_key, build_manifest(ctx, encrypted))


def _stored(signed: SignedManifest) -> dict[str, Any]:
    return json.loads(signed.to_bytes())


def _dump(value: Any) -> bytes:
    return json.dumps(value).encode()


class TestFormat:
    def test_golden_canonical_bytes(self) -> None:
        """Pins the exact bytes that are signed; any format change must update DESIGN.md 4.3."""
        assert GOLDEN_MANIFEST.to_bytes() == GOLDEN_BYTES
        assert GOLDEN_MANIFEST.digest() == sha256(GOLDEN_BYTES)

    def test_build_copies_encryption_results(self, ctx: FileContext, dek: bytes) -> None:
        encrypted = aead.encrypt_file(dek, ctx, name="a.txt", content=b"abc")
        manifest = build_manifest(ctx, encrypted, created_at=42)
        assert manifest.context == ctx
        assert (manifest.ct_hash, manifest.ct_size, manifest.pt_digest) == (
            encrypted.ct_hash,
            encrypted.ct_size,
            encrypted.pt_digest,
        )
        assert manifest.created_at == 42

    def test_stored_file_round_trip(self, signed: SignedManifest) -> None:
        assert SignedManifest.from_bytes(signed.to_bytes()) == signed

    def test_whitespace_does_not_change_the_manifest(self, signed: SignedManifest) -> None:
        reformatted = json.dumps(_stored(signed), indent=2).encode()
        assert SignedManifest.from_bytes(reformatted).manifest.digest() == signed.manifest.digest()

    def test_signing_key_is_not_stored(self, signed: SignedManifest) -> None:
        assert set(_stored(signed)) == {"manifest", "signature"}


class TestVerification:
    def test_owner_signature_verifies(self, alice: UserKeys, signed: SignedManifest) -> None:
        assert verify_manifest(alice.sig_public_key, SignedManifest.from_bytes(signed.to_bytes()))

    def test_S7_modified_pt_digest_is_detected(self, alice: UserKeys, signed: SignedManifest) -> None:
        stored = _stored(signed)
        stored["manifest"]["ptDigest"] = "00" * 32
        tampered = SignedManifest.from_bytes(_dump(stored))
        assert tampered.manifest.digest() != signed.manifest.digest()  # V2
        assert not verify_manifest(alice.sig_public_key, tampered)  # V4

    def test_S8_attacker_resigning_fails_with_onchain_key(
        self, alice: UserKeys, mallory: UserKeys, signed: SignedManifest
    ) -> None:
        forged = dataclasses.replace(signed.manifest, ct_hash=b"\xee" * 32)
        resigned = sign_manifest(mallory.sig_key, forged)
        assert verify_manifest(mallory.sig_public_key, resigned)  # valid, but under the wrong key
        assert not verify_manifest(alice.sig_public_key, resigned)  # V4 uses Alice's registered key

    def test_signature_from_other_file_fails(self, alice: UserKeys, signed: SignedManifest) -> None:
        other = dataclasses.replace(signed.manifest, created_at=signed.manifest.created_at + 1)
        assert not verify_manifest(alice.sig_public_key, SignedManifest(other, signed.signature))


def _set(section: str, key: str, value: Any) -> Callable[[dict], None]:
    def mutate(stored: dict) -> None:
        target = stored if section == "" else stored[section]
        target[key] = value

    return mutate


def _delete(key: str) -> Callable[[dict], None]:
    return lambda stored: stored["manifest"].pop(key)


class TestStrictParsing:
    @pytest.mark.parametrize(
        "mutate",
        [
            _set("manifest", "extra", 1),
            _delete("ctSize"),
            _set("manifest", "schema", "sfs-manifest/2"),
            _set("manifest", "enc", "AES-128-CTR"),
            _set("manifest", "chainId", 0),
            _set("manifest", "ctSize", True),
            _set("manifest", "ctSize", 1.5),
            _set("manifest", "createdAt", -1),
            _set("manifest", "fileId", "11" * 32),
            _set("manifest", "ctHash", "AB" * 32),
            _set("manifest", "owner", VECTOR_OWNER.lower()),
            _set("", "sigPubKey", "02" + "11" * 32),
        ],
        ids=[
            "extra-field",
            "missing-field",
            "schema",
            "cipher",
            "chain-zero",
            "bool-size",
            "float-size",
            "negative-time",
            "file-id-no-prefix",
            "uppercase-hash",
            "lowercase-address",
            "key-supplied-by-storage",
        ],
    )
    def test_rejects_invalid_fields(self, signed: SignedManifest, mutate: Callable[[dict], None]) -> None:
        stored = _stored(signed)
        mutate(stored)
        with pytest.raises(ManifestError):
            SignedManifest.from_bytes(_dump(stored))

    @pytest.mark.parametrize(
        "data",
        [b"[]", b"not json", b'{"manifest":{},"manifest":{},"signature":{}}', b" " * (MAX_SIGNED_MANIFEST_BYTES + 1)],
        ids=["list", "not-json", "duplicate-key", "oversized"],
    )
    def test_rejects_malformed_files(self, data: bytes) -> None:
        with pytest.raises(ManifestError):
            SignedManifest.from_bytes(data)

    def test_rejects_impossible_ciphertext_size(self) -> None:
        with pytest.raises(EncodingError):
            dataclasses.replace(GOLDEN_MANIFEST, ct_size=aead.MIN_OBJECT_LEN - 1)
