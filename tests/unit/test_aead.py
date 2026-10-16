from __future__ import annotations

import dataclasses
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto import DecryptionError, EncodingError, aead
from app.crypto.encoding import FileContext, canonical_json, sha256

SECRET = b"TOP-SECRET-MARKER " * 64
NAME = "exam-answers-报告.pdf"


def _encrypt(dek: bytes, ctx: FileContext, content: bytes = SECRET, name: str = NAME) -> aead.EncryptedFile:
    return aead.encrypt_file(dek, ctx, name=name, content=content, mime="application/pdf")


def _flip(data: bytes, index: int) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


def _seal_raw(dek: bytes, ctx: FileContext, plaintext: bytes) -> bytes:
    """Encrypt an arbitrary P with the correct AAD, as a buggy or malicious owner could."""
    nonce = os.urandom(aead.NONCE_LEN)
    return aead.OBJECT_MAGIC + nonce + AESGCM(dek).encrypt(nonce, plaintext, aead.file_aad(ctx))


class TestRoundTrip:
    def test_decrypts_content_and_header(self, dek: bytes, ctx: FileContext) -> None:
        encrypted = _encrypt(dek, ctx)
        decrypted = aead.decrypt_file(dek, ctx, encrypted.object_bytes)
        assert decrypted.content == SECRET
        assert (decrypted.header.name, decrypted.header.mime, decrypted.header.size) == (
            NAME,
            "application/pdf",
            len(SECRET),
        )
        assert decrypted.pt_digest == encrypted.pt_digest

    def test_empty_file(self, dek: bytes, ctx: FileContext) -> None:
        encrypted = _encrypt(dek, ctx, content=b"")
        assert aead.decrypt_file(dek, ctx, encrypted.object_bytes).content == b""

    def test_object_layout_and_hashes(self, dek: bytes, ctx: FileContext) -> None:
        encrypted = _encrypt(dek, ctx)
        obj = encrypted.object_bytes
        assert obj.startswith(b"SFS1")
        assert encrypted.ct_hash == sha256(obj)
        assert encrypted.ct_size == len(obj)
        header_len = len(obj) - len(aead.OBJECT_MAGIC) - aead.NONCE_LEN - aead.TAG_LEN - 4 - len(SECRET)
        assert 0 < header_len <= aead.MAX_HEADER_BYTES

    def test_dek_is_random_256_bit(self) -> None:
        keys = {aead.generate_dek() for _ in range(8)}
        assert len(keys) == 8
        assert all(len(key) == 32 for key in keys)


class TestConfidentiality:
    def test_object_hides_content_and_name(self, dek: bytes, ctx: FileContext) -> None:
        obj = _encrypt(dek, ctx).object_bytes
        assert b"TOP-SECRET" not in obj
        assert b"exam-answers" not in obj

    def test_same_file_encrypts_differently(self, dek: bytes, ctx: FileContext) -> None:
        first, second = _encrypt(dek, ctx), _encrypt(dek, ctx)
        assert first.object_bytes[4:16] != second.object_bytes[4:16]  # nonce
        assert first.ct_hash != second.ct_hash
        # The random header salt keeps ptDigest from confirming a guessed file.
        assert first.pt_digest != second.pt_digest


class TestIntegrity:
    @pytest.mark.parametrize("index", [0, 4, 15, 16, 200, -16, -1], ids=lambda i: f"byte{i}")
    def test_S6_any_flipped_byte_is_detected(self, dek: bytes, ctx: FileContext, index: int) -> None:
        obj = _encrypt(dek, ctx).object_bytes
        with pytest.raises(DecryptionError):
            aead.decrypt_file(dek, ctx, _flip(obj, index % len(obj)))

    @pytest.mark.parametrize("length", [0, 4, 31, -1], ids=["empty", "magic-only", "no-body", "minus-one"])
    def test_truncated_object(self, dek: bytes, ctx: FileContext, length: int) -> None:
        obj = _encrypt(dek, ctx).object_bytes
        with pytest.raises(DecryptionError):
            aead.decrypt_file(dek, ctx, obj[:length])

    def test_wrong_dek(self, dek: bytes, ctx: FileContext) -> None:
        obj = _encrypt(dek, ctx).object_bytes
        with pytest.raises(DecryptionError, match="authentication failed"):
            aead.decrypt_file(aead.generate_dek(), ctx, obj)

    @pytest.mark.parametrize(
        "change",
        [
            {"chain_id": 11155111},
            {"contract": "0x" + "11" * 20},
            {"file_id": b"\x22" * 32},
            {"owner": "0x" + "33" * 20},
        ],
        ids=["other-chain", "other-contract", "other-file", "other-owner"],
    )
    def test_aad_binds_object_to_its_record(self, dek: bytes, ctx: FileContext, change: dict) -> None:
        """Storage swapping in another file's object (or moving it to another chain) fails."""
        obj = _encrypt(dek, ctx).object_bytes
        with pytest.raises(DecryptionError):
            aead.decrypt_file(dek, dataclasses.replace(ctx, **change), obj)


class TestMaliciousPlaintext:
    def test_header_length_beyond_data(self, dek: bytes, ctx: FileContext) -> None:
        obj = _seal_raw(dek, ctx, (10_000).to_bytes(4, "big") + b"{}")
        with pytest.raises(DecryptionError, match="length"):
            aead.decrypt_file(dek, ctx, obj)

    def test_size_mismatch(self, dek: bytes, ctx: FileContext) -> None:
        header = canonical_json({"name": "a.txt", "mime": "text/plain", "size": 99, "salt": "00" * 16})
        obj = _seal_raw(dek, ctx, len(header).to_bytes(4, "big") + header + b"short")
        with pytest.raises(DecryptionError, match="size"):
            aead.decrypt_file(dek, ctx, obj)

    def test_path_in_header_name(self, dek: bytes, ctx: FileContext) -> None:
        header = canonical_json({"name": "../../.zshrc", "mime": "text/plain", "size": 1, "salt": "00" * 16})
        obj = _seal_raw(dek, ctx, len(header).to_bytes(4, "big") + header + b"x")
        with pytest.raises(DecryptionError, match="header"):
            aead.decrypt_file(dek, ctx, obj)


class TestInputValidation:
    @pytest.mark.parametrize(
        "name",
        ["", ".", "..", "../x", "dir/file", "dir\\file", "a\x00b", "line\nbreak", "x" * 256],
        ids=["empty", "dot", "dotdot", "parent", "slash", "backslash", "nul", "newline", "too-long"],
    )
    def test_rejects_unsafe_file_names(self, dek: bytes, ctx: FileContext, name: str) -> None:
        with pytest.raises(EncodingError):
            _encrypt(dek, ctx, name=name)

    @pytest.mark.parametrize("mime", ["", "text/plain; charset=utf-8", "tëxt/plain"])
    def test_rejects_bad_mime(self, dek: bytes, ctx: FileContext, mime: str) -> None:
        with pytest.raises(EncodingError):
            aead.encrypt_file(dek, ctx, name="a.txt", content=b"x", mime=mime)

    @pytest.mark.parametrize("bad_dek", [b"", b"\x00" * 16, b"\x00" * 33])
    def test_rejects_wrong_dek_length(self, ctx: FileContext, bad_dek: bytes) -> None:
        with pytest.raises(EncodingError):
            _encrypt(bad_dek, ctx)
        with pytest.raises(EncodingError):
            aead.decrypt_file(bad_dek, ctx, b"SFS1" + b"\x00" * 40)
