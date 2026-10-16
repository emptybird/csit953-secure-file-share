"""Canonical encodings and secp256k1 keys shared by the crypto modules.

Everything that is hashed, signed or used as AAD is built here, so the owner and
the requester always produce the same bytes. Parsers are strict: anything that
is not in canonical form is rejected rather than repaired.

Public keys travel as 33-byte compressed points, the format the contract stores.
Private keys travel as 32-byte big-endian scalars, only inside the keystore.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from eth_utils import is_checksum_address, keccak, to_checksum_address

from app.crypto import EncodingError, InvalidKeyError

HASH_LEN = 32
ADDRESS_LEN = 20
UINT256_LEN = 32
FINGERPRINT_BYTES = 8

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_LOWER_HEX = re.compile(r"[0-9a-f]*")


# ---------------------------------------------------------------------- JSON


def canonical_json(value: Any) -> bytes:
    """Sorted keys, no whitespace, ASCII only, no NaN: one object, one byte string."""
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EncodingError(f"Value cannot be encoded as canonical JSON: {exc}") from exc
    return text.encode("ascii")


def strict_json_loads(data: bytes, *, max_bytes: int, what: str) -> Any:
    """Parse UTF-8 JSON, rejecting oversized input, duplicate keys and NaN/Infinity."""
    if len(data) > max_bytes:
        raise EncodingError(f"{what} is larger than {max_bytes} bytes")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ValueError as exc:
        raise EncodingError(f"{what} is not valid JSON: {exc}") from exc


def require_fields(value: Any, fields: frozenset[str], what: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise EncodingError(f"{what} must have exactly the fields {', '.join(sorted(fields))}")
    return value


def require_int(value: Any, what: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EncodingError(f"{what} must be an integer >= {minimum}")
    return value


def require_str(value: Any, what: str, *, max_chars: int) -> str:
    if not isinstance(value, str) or not value or len(value) > max_chars:
        raise EncodingError(f"{what} must be a non-empty string of at most {max_chars} characters")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise EncodingError("duplicate key in JSON object")
    return dict(pairs)


def _reject_constant(name: str) -> None:
    raise EncodingError(f"{name} is not allowed")


# ----------------------------------------------------------------------- hex


def to_hex(data: bytes) -> str:
    """Lowercase hex without a prefix (ctHash, ptDigest, salts, signature parts)."""
    return data.hex()


def from_hex(text: Any, length: int, what: str) -> bytes:
    """Inverse of to_hex: exactly `length` bytes of lowercase hex, no prefix."""
    if not isinstance(text, str) or len(text) != 2 * length or not _LOWER_HEX.fullmatch(text):
        raise EncodingError(f"{what} must be {2 * length} lowercase hex characters")
    return bytes.fromhex(text)


def to_hex32(data: bytes) -> str:
    """0x-prefixed hex, the form web3 and Solidity use for bytes32 (fileId)."""
    if len(data) != HASH_LEN:
        raise EncodingError("bytes32 value must be 32 bytes")
    return "0x" + data.hex()


def from_hex32(text: Any, what: str) -> bytes:
    if not isinstance(text, str) or not text.startswith("0x"):
        raise EncodingError(f"{what} must be 0x followed by 64 lowercase hex characters")
    return from_hex(text[2:], HASH_LEN, what)


# ------------------------------------------------------------------ hashing


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def fingerprint(data: bytes) -> str:
    """First 8 bytes of SHA-256 in groups of four, short enough to compare by eye."""
    digest = sha256(data)[:FINGERPRINT_BYTES].hex()
    return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))


# ----------------------------------------------------------- Ethereum values


def normalize_address(address: Any) -> str:
    """Return the EIP-55 checksum form. All-lower or all-upper hex is accepted;
    mixed case must carry a valid checksum, which catches typing mistakes."""
    if not isinstance(address, str) or not _ADDRESS.fullmatch(address):
        raise EncodingError("Address must be 0x followed by 40 hex characters")
    body = address[2:]
    if body not in (body.lower(), body.upper()) and not is_checksum_address(address):
        raise EncodingError("Address has an invalid EIP-55 checksum")
    return to_checksum_address(address)


def address_bytes(address: str) -> bytes:
    return bytes.fromhex(normalize_address(address)[2:])


def uint256_bytes(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**256:
        raise EncodingError("Value does not fit in uint256")
    return value.to_bytes(UINT256_LEN, "big")


def compute_file_id(owner: str, salt: bytes) -> bytes:
    """keccak256(abi.encode(owner, salt)), the same as SecureFileShare.computeFileId."""
    if len(salt) != HASH_LEN:
        raise EncodingError("File salt must be 32 bytes")
    return keccak(bytes(UINT256_LEN - ADDRESS_LEN) + address_bytes(owner) + salt)


@dataclass(frozen=True)
class FileContext:
    """The on-chain record a file belongs to. Ciphertexts (AAD), manifests and
    wrapped keys (HKDF info) are all bound to it, so none can be moved to another
    file, owner, contract or chain. Addresses are stored in checksum form."""

    chain_id: int
    contract: str
    file_id: bytes
    owner: str

    def __post_init__(self) -> None:
        require_int(self.chain_id, "chainId", minimum=1)
        if not isinstance(self.file_id, bytes) or len(self.file_id) != HASH_LEN:
            raise EncodingError("fileId must be 32 bytes")
        object.__setattr__(self, "contract", normalize_address(self.contract))
        object.__setattr__(self, "owner", normalize_address(self.owner))

    def location_bytes(self) -> bytes:
        """chainId (32) | contract (20) | fileId (32): the prefix shared by AAD and HKDF info."""
        return uint256_bytes(self.chain_id) + address_bytes(self.contract) + self.file_id


# ------------------------------------------------------------ secp256k1 keys

CURVE = ec.SECP256K1()
# Field prime and group order of secp256k1 (SEC 2, section 2.4.1).
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PUBLIC_KEY_LEN = 33
PRIVATE_KEY_LEN = 32

PrivateKey = ec.EllipticCurvePrivateKey
PublicKey = ec.EllipticCurvePublicKey


def generate_private_key() -> PrivateKey:
    """A fresh key from OpenSSL's CSPRNG (never Python's `random` module)."""
    return ec.generate_private_key(CURVE)


def private_key_to_bytes(key: PrivateKey) -> bytes:
    return key.private_numbers().private_value.to_bytes(PRIVATE_KEY_LEN, "big")


def private_key_from_bytes(data: bytes) -> PrivateKey:
    if not isinstance(data, bytes) or len(data) != PRIVATE_KEY_LEN:
        raise InvalidKeyError("Private key must be 32 bytes")
    value = int.from_bytes(data, "big")
    if not 1 <= value < N:
        raise InvalidKeyError("Private key must be in [1, N-1]")
    return ec.derive_private_key(value, CURVE)


def public_key_bytes(key: PrivateKey | PublicKey) -> bytes:
    """33-byte compressed point: 0x02/0x03 (parity of y) followed by x."""
    public = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def load_public_key(data: bytes) -> PublicKey:
    """Parse a compressed point and reject anything that is not on the curve.
    Accepting an off-curve point would allow invalid-curve attacks on ECDH."""
    if not isinstance(data, bytes) or len(data) != PUBLIC_KEY_LEN or data[0] not in (2, 3):
        raise InvalidKeyError("Public key must be a 33-byte compressed point (prefix 0x02 or 0x03)")
    if int.from_bytes(data[1:], "big") >= P:
        raise InvalidKeyError("Public key x-coordinate is not below the field prime")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)
    except ValueError as exc:
        raise InvalidKeyError("Public key is not a point on secp256k1") from exc
