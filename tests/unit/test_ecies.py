"""ECIES DEK wrapping: round trip, recipient and file binding, tamper resistance."""

from __future__ import annotations

import dataclasses

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.crypto import EncodingError, InvalidKeyError, KeyUnwrapError
from app.crypto.ecies import WRAPPED_KEY_LEN, unwrap_key, wrap_key
from app.crypto.encoding import PUBLIC_KEY_LEN, FileContext
from app.crypto.keystore import UserKeys


@pytest.fixture
def wrapped(dek: bytes, bob: UserKeys, ctx: FileContext) -> bytes:
    return wrap_key(dek, bob.enc_public_key, ctx, bob.address)


def _flip(data: bytes, index: int) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


class TestRoundTrip:
    def test_recipient_recovers_dek(self, dek: bytes, bob: UserKeys, ctx: FileContext, wrapped: bytes) -> None:
        assert len(wrapped) == WRAPPED_KEY_LEN == 93
        assert unwrap_key(wrapped, bob.enc_key, ctx, bob.address) == dek

    def test_owner_copy(self, dek: bytes, alice: UserKeys, ctx: FileContext) -> None:
        """ownerWrappedKey: the owner wraps the DEK for themselves at registration."""
        own = wrap_key(dek, alice.enc_public_key, ctx, alice.address)
        assert unwrap_key(own, alice.enc_key, ctx, alice.address) == dek

    def test_fresh_ephemeral_key_every_time(self, dek: bytes, bob: UserKeys, ctx: FileContext) -> None:
        first = wrap_key(dek, bob.enc_public_key, ctx, bob.address)
        second = wrap_key(dek, bob.enc_public_key, ctx, bob.address)
        assert first[:PUBLIC_KEY_LEN] != second[:PUBLIC_KEY_LEN]
        assert first != second
        assert unwrap_key(second, bob.enc_key, ctx, bob.address) == dek

    def test_dek_does_not_appear_in_wrapped_key(self, dek: bytes, wrapped: bytes) -> None:
        assert dek not in wrapped


class TestWireFormat:
    def test_unwraps_with_raw_primitives(
        self, dek: bytes, bob: UserKeys, ctx: FileContext, wrapped: bytes
    ) -> None:
        """Rebuild the KEK by hand from the layout in app.crypto.ecies. The recipient is
        bound twice (HKDF info and AAD), so dropping one copy still passes every behaviour
        test; only an independent rebuild catches it."""
        ephemeral_pub, nonce, sealed = wrapped[:33], wrapped[33:45], wrapped[45:]
        ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), ephemeral_pub)
        shared = bob.enc_key.exchange(ec.ECDH(), ephemeral)
        recipient = bytes.fromhex(bob.address[2:])
        info = (
            b"SFS-keywrap-v1"
            + ctx.chain_id.to_bytes(32, "big")
            + bytes.fromhex(ctx.contract[2:])
            + ctx.file_id
            + recipient
        )
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=ephemeral_pub + bob.enc_public_key, info=info).derive(shared)
        assert AESGCM(kek).decrypt(nonce, sealed, ctx.file_id + recipient) == dek


class TestOnlyTheRecipient:
    def test_other_users_key_fails(
        self, mallory: UserKeys, bob: UserKeys, ctx: FileContext, wrapped: bytes
    ) -> None:
        """Mallory reads Bob's wrappedKey from the chain; her own key cannot open it."""
        with pytest.raises(KeyUnwrapError):
            unwrap_key(wrapped, mallory.enc_key, ctx, bob.address)
        with pytest.raises(KeyUnwrapError):
            unwrap_key(wrapped, mallory.enc_key, ctx, mallory.address)

    def test_signing_key_cannot_unwrap(self, bob: UserKeys, ctx: FileContext, wrapped: bytes) -> None:
        with pytest.raises(KeyUnwrapError):
            unwrap_key(wrapped, bob.sig_key, ctx, bob.address)


class TestBinding:
    @pytest.mark.parametrize(
        "change",
        [{"file_id": b"\x44" * 32}, {"chain_id": 11155111}, {"contract": "0x" + "55" * 20}],
        ids=["other-file", "other-chain", "other-contract"],
    )
    def test_wrapped_key_cannot_move_to_another_file(
        self, bob: UserKeys, ctx: FileContext, wrapped: bytes, change: dict
    ) -> None:
        with pytest.raises(KeyUnwrapError):
            unwrap_key(wrapped, bob.enc_key, dataclasses.replace(ctx, **change), bob.address)

    def test_wrapped_key_is_bound_to_recipient_address(
        self, bob: UserKeys, mallory: UserKeys, ctx: FileContext, wrapped: bytes
    ) -> None:
        with pytest.raises(KeyUnwrapError):
            unwrap_key(wrapped, bob.enc_key, ctx, mallory.address)


class TestTampering:
    @pytest.mark.parametrize(
        "index", [0, 1, 32, PUBLIC_KEY_LEN, PUBLIC_KEY_LEN + 11, 50, 76, 92], ids=lambda i: f"byte{i}"
    )
    def test_any_flipped_byte_fails(self, bob: UserKeys, ctx: FileContext, wrapped: bytes, index: int) -> None:
        """Byte 0 turns E into -E, whose ECDH result has the same x-coordinate; it still
        fails because E itself is part of the HKDF salt."""
        with pytest.raises(KeyUnwrapError):
            unwrap_key(_flip(wrapped, index), bob.enc_key, ctx, bob.address)

    def test_invalid_ephemeral_point(self, bob: UserKeys, ctx: FileContext, wrapped: bytes) -> None:
        with pytest.raises(KeyUnwrapError, match="ephemeral"):
            unwrap_key(b"\x04" + wrapped[1:], bob.enc_key, ctx, bob.address)

    @pytest.mark.parametrize("length", [0, 92, 94])
    def test_wrong_length(self, bob: UserKeys, ctx: FileContext, wrapped: bytes, length: int) -> None:
        data = (wrapped + b"\x00")[:length]
        with pytest.raises(KeyUnwrapError):
            unwrap_key(data, bob.enc_key, ctx, bob.address)


class TestWrapInputs:
    def test_rejects_invalid_recipient_key(self, dek: bytes, bob: UserKeys, ctx: FileContext) -> None:
        with pytest.raises(InvalidKeyError):
            wrap_key(dek, b"\x02" + b"\xff" * 32, ctx, bob.address)

    def test_rejects_wrong_dek_length(self, bob: UserKeys, ctx: FileContext) -> None:
        with pytest.raises(EncodingError):
            wrap_key(b"\x00" * 16, bob.enc_public_key, ctx, bob.address)
