"""Canonical encodings, addresses, fileId derivation and secp256k1 key handling."""

from __future__ import annotations

import re

import pytest
from cryptography.hazmat.primitives import serialization

from app.crypto import EncodingError, InvalidKeyError
from app.crypto.encoding import (
    N,
    P,
    FileContext,
    canonical_json,
    compute_file_id,
    fingerprint,
    from_hex,
    from_hex32,
    generate_private_key,
    load_public_key,
    normalize_address,
    private_key_from_bytes,
    private_key_to_bytes,
    public_key_bytes,
    strict_json_loads,
)

from .conftest import CONTRACT

# Computed with Foundry, the same derivation as SecureFileShare.computeFileId:
#   cast keccak $(cast abi-encode "f(address,bytes32)" <owner> <salt>)
VECTOR_OWNER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
VECTOR_SALT = (1).to_bytes(32, "big")
VECTOR_FILE_ID = bytes.fromhex("3c8e904cdb19937d60d41c8d984b1a8803ad6e0891b4f9e032dcec2a22c2c7f5")


class TestCanonicalJson:
    def test_sorts_keys_without_whitespace(self) -> None:
        assert canonical_json({"b": 1, "a": [1, {"d": 2, "c": 3}]}) == b'{"a":[1,{"c":3,"d":2}],"b":1}'

    def test_escapes_non_ascii(self) -> None:
        assert canonical_json({"name": "报告"}) == b'{"name":"\\u62a5\\u544a"}'

    def test_same_object_same_bytes(self) -> None:
        assert canonical_json({"x": 1, "y": 2}) == canonical_json({"y": 2, "x": 1})

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), {"k": b"bytes"}])
    def test_rejects_unencodable_values(self, value: object) -> None:
        with pytest.raises(EncodingError):
            canonical_json(value)


class TestStrictJsonLoads:
    def test_parses_valid_json(self) -> None:
        assert strict_json_loads(b'{"a":1}', max_bytes=100, what="x") == {"a": 1}

    @pytest.mark.parametrize(
        "data",
        [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b"\xff\xfe", b"{not json"],
        ids=["duplicate-key", "nan", "infinity", "bad-utf8", "syntax"],
    )
    def test_rejects_malformed_input(self, data: bytes) -> None:
        with pytest.raises(EncodingError):
            strict_json_loads(data, max_bytes=100, what="x")

    def test_rejects_oversized_input(self) -> None:
        with pytest.raises(EncodingError, match="larger than"):
            strict_json_loads(b"[" + b"1," * 100 + b"1]", max_bytes=100, what="x")


class TestHex:
    def test_round_trip(self) -> None:
        assert from_hex("00ff", 2, "x") == b"\x00\xff"
        assert from_hex32("0x" + "ab" * 32, "x") == b"\xab" * 32

    @pytest.mark.parametrize("text", ["00FF", "0x00ff", "00f", "00ff00", 255])
    def test_rejects_non_canonical_hex(self, text: object) -> None:
        with pytest.raises(EncodingError):
            from_hex(text, 2, "x")

    def test_hex32_requires_prefix(self) -> None:
        with pytest.raises(EncodingError):
            from_hex32("ab" * 32, "x")


class TestAddresses:
    def test_lowercase_becomes_checksum(self) -> None:
        assert normalize_address(CONTRACT.lower()) == CONTRACT

    def test_valid_checksum_kept(self) -> None:
        assert normalize_address(CONTRACT) == CONTRACT

    @pytest.mark.parametrize(
        "address",
        [CONTRACT.replace("F", "f", 1), CONTRACT[:-1], "5FbDB2315678afecb367f032d93F642f64180aa3", None],
        ids=["bad-checksum", "too-short", "no-prefix", "not-a-string"],
    )
    def test_rejects_invalid_addresses(self, address: object) -> None:
        with pytest.raises(EncodingError):
            normalize_address(address)


class TestFileId:
    def test_matches_solidity_abi_encode(self) -> None:
        assert compute_file_id(VECTOR_OWNER, VECTOR_SALT) == VECTOR_FILE_ID

    def test_depends_on_owner(self) -> None:
        assert compute_file_id(CONTRACT, VECTOR_SALT) != VECTOR_FILE_ID

    def test_rejects_short_salt(self) -> None:
        with pytest.raises(EncodingError):
            compute_file_id(VECTOR_OWNER, b"\x01")


class TestFileContext:
    def test_normalizes_addresses(self) -> None:
        ctx = FileContext(1, CONTRACT.lower(), VECTOR_FILE_ID, VECTOR_OWNER.lower())
        assert ctx.contract == CONTRACT
        assert ctx.owner == VECTOR_OWNER

    def test_location_bytes_layout(self) -> None:
        ctx = FileContext(31337, CONTRACT, VECTOR_FILE_ID, VECTOR_OWNER)
        packed = ctx.location_bytes()
        assert len(packed) == 32 + 20 + 32
        assert packed[:32] == (31337).to_bytes(32, "big")
        assert packed[32:52] == bytes.fromhex(CONTRACT[2:])
        assert packed[52:] == VECTOR_FILE_ID

    @pytest.mark.parametrize(
        ("chain_id", "file_id"),
        [(0, VECTOR_FILE_ID), (True, VECTOR_FILE_ID), (1, b"\x00" * 31)],
        ids=["zero-chain", "bool-chain", "short-file-id"],
    )
    def test_rejects_invalid_fields(self, chain_id: int, file_id: bytes) -> None:
        with pytest.raises(EncodingError):
            FileContext(chain_id, CONTRACT, file_id, VECTOR_OWNER)


def test_fingerprint_is_short_and_stable() -> None:
    value = fingerprint(b"public key bytes")
    assert re.fullmatch(r"[0-9a-f]{4}( [0-9a-f]{4}){3}", value)
    assert value == fingerprint(b"public key bytes")
    assert value != fingerprint(b"public key bytez")


# ------------------------------------------------------------ secp256k1 keys


def _x_without_point() -> int:
    """Smallest x for which x^3 + 7 has no square root mod P, i.e. no point exists."""
    return next(x for x in range(1, 1000) if pow(x**3 + 7, (P - 1) // 2, P) != 1)


def test_private_key_round_trip() -> None:
    key = generate_private_key()
    restored = private_key_from_bytes(private_key_to_bytes(key))
    assert restored.private_numbers() == key.private_numbers()


def test_generated_keys_differ() -> None:
    assert private_key_to_bytes(generate_private_key()) != private_key_to_bytes(generate_private_key())


def test_public_key_is_compressed_point() -> None:
    encoded = public_key_bytes(generate_private_key())
    assert len(encoded) == 33
    assert encoded[0] in (2, 3)
    assert public_key_bytes(load_public_key(encoded)) == encoded


@pytest.mark.parametrize("value", [0, N, N + 1], ids=["zero", "order", "above-order"])
def test_private_key_out_of_range(value: int) -> None:
    with pytest.raises(InvalidKeyError):
        private_key_from_bytes(value.to_bytes(32, "big"))


def test_private_key_wrong_length() -> None:
    with pytest.raises(InvalidKeyError):
        private_key_from_bytes(b"\x01" * 31)


class TestLoadPublicKey:
    """Malformed keys are rejected before they are ever used for ECDH."""

    def test_rejects_uncompressed_encoding(self) -> None:
        uncompressed = (
            generate_private_key()
            .public_key()
            .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        )
        with pytest.raises(InvalidKeyError):
            load_public_key(uncompressed)

    @pytest.mark.parametrize("prefix", [0x00, 0x04, 0x05])
    def test_rejects_bad_prefix(self, prefix: int) -> None:
        valid = public_key_bytes(generate_private_key())
        with pytest.raises(InvalidKeyError):
            load_public_key(bytes([prefix]) + valid[1:])

    def test_rejects_point_not_on_curve(self) -> None:
        with pytest.raises(InvalidKeyError, match="not a point"):
            load_public_key(b"\x02" + _x_without_point().to_bytes(32, "big"))

    def test_rejects_x_not_below_field_prime(self) -> None:
        """OpenSSL also rejects this, so match our own message to show our check ran first."""
        with pytest.raises(InvalidKeyError, match="field prime"):
            load_public_key(b"\x02" + (P + 1).to_bytes(32, "big"))

    @pytest.mark.parametrize("data", [b"", b"\x02" * 32, "02" * 33], ids=["empty", "short", "str"])
    def test_rejects_wrong_type_or_length(self, data: object) -> None:
        with pytest.raises(InvalidKeyError):
            load_public_key(data)
