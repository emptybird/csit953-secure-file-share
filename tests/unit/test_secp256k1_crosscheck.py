"""Cross-check app.crypto (OpenSSL) against the textbook formulas in secp256k1_reference (py_ecc).

Two independent implementations must agree on public keys, signatures in both
directions and the ECDH shared secret used by the key wrap.
"""

from __future__ import annotations

import dataclasses

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto import aead
from app.crypto.ecies import wrap_key
from app.crypto.encoding import (
    N,
    FileContext,
    generate_private_key,
    load_public_key,
    private_key_to_bytes,
    public_key_bytes,
)
from app.crypto.keystore import UserKeys
from app.crypto.signing import Manifest, Signature, build_manifest, sign, sign_manifest, verify

from . import secp256k1_reference as ref


def _scalar(key: ec.EllipticCurvePrivateKey) -> int:
    """The private key as an integer, for py_ecc."""
    return int.from_bytes(private_key_to_bytes(key), "big")


@pytest.fixture
def manifest(ctx: FileContext, dek: bytes) -> Manifest:
    encrypted = aead.encrypt_file(dek, ctx, name="crosscheck.txt", content=b"cross-check me")
    return build_manifest(ctx, encrypted, created_at=1_760_000_000)


def test_public_key_matches_reference(alice: UserKeys) -> None:
    q = ref.public_key(_scalar(alice.sig_key))
    assert ref.compress(q) == alice.sig_public_key
    assert ref.decompress(alice.sig_public_key) == q


def test_our_manifest_signature_passes_reference_verification(alice: UserKeys, manifest: Manifest) -> None:
    signed = sign_manifest(alice.sig_key, manifest)
    z = ref.hash_message(manifest.to_bytes())
    q = ref.decompress(alice.sig_public_key)  # the key as registered on-chain
    trace = ref.verify_signature(q, signed.signature.r, signed.signature.s, z)
    assert trace.valid
    assert trace.w * signed.signature.s % N == 1
    assert trace.x[0] % N == signed.signature.r


def test_tampered_manifest_fails_reference_verification(alice: UserKeys, manifest: Manifest) -> None:
    signed = sign_manifest(alice.sig_key, manifest)
    tampered = dataclasses.replace(manifest, pt_digest=b"\x00" * 32)
    z = ref.hash_message(tampered.to_bytes())
    q = ref.decompress(alice.sig_public_key)
    assert not ref.verify_signature(q, signed.signature.r, signed.signature.s, z).valid


@pytest.mark.parametrize("message", [b"", b"reference", b"\x00" * 1000])
def test_reference_signature_passes_our_verification(message: bytes) -> None:
    key = generate_private_key()
    r, s = ref.sign_message(_scalar(key), ref.hash_message(message))
    low_s = min(s, N - s)
    # The reference accepts both (r, s) and (r, N - s); app.crypto accepts only low s.
    assert verify(public_key_bytes(key), message, Signature(r=r, s=low_s))
    assert not verify(public_key_bytes(key), message, Signature(r=r, s=N - low_s))


def test_rfc6979_signature_uses_sha256_of_message() -> None:
    """z in equation (2) is exactly what OpenSSL signs: SHA-256 of the bytes, no prefix."""
    key = generate_private_key()
    message = b"which digest is signed?"
    signature = sign(key, message)
    q = ref.decompress(public_key_bytes(key))
    assert ref.verify_signature(q, signature.r, signature.s, ref.hash_message(message)).valid
    assert not ref.verify_signature(q, signature.r, signature.s, ref.hash_message(message + b"!")).valid


def test_ecdh_secret_matches_point_multiplication(bob: UserKeys) -> None:
    """The key wrap's ECDH: Z is the x-coordinate of e * encPub_B, computed from either side."""
    ephemeral = generate_private_key()
    openssl_z = ephemeral.exchange(ec.ECDH(), load_public_key(bob.enc_public_key))
    sender_side = ref.multiply(ref.decompress(bob.enc_public_key), _scalar(ephemeral))
    receiver_side = ref.multiply(ref.decompress(public_key_bytes(ephemeral)), _scalar(bob.enc_key))
    assert openssl_z == sender_side[0].to_bytes(32, "big") == receiver_side[0].to_bytes(32, "big")


def test_wrapped_key_carries_a_valid_ephemeral_point(dek: bytes, bob: UserKeys, ctx: FileContext) -> None:
    wrapped = wrap_key(dek, bob.enc_public_key, ctx, bob.address)
    assert ref.is_on_curve(ref.decompress(wrapped[:33]))
