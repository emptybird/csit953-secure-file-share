"""Password-protected keystore for a user's three private keys.

    key        = scrypt(NFKC(password), salt, n = 2^17, r = 8, p = 1, length = 32)
    ciphertext = AES-256-GCM(key, nonce, {eth, sig, enc}, AAD = canonical header)

The header (version, address, KDF and cipher parameters) is the AAD: editing any
field fails exactly like a wrong password, with the same message, so the error
does not reveal which one happened.
"""

from __future__ import annotations

import os
import re
import tempfile
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from eth_account import Account
from eth_account.signers.local import LocalAccount

from app.crypto import CryptoError, EncodingError, KeystoreError
from app.crypto.aead import ALGORITHM, NONCE_LEN
from app.crypto.encoding import (
    PRIVATE_KEY_LEN,
    PrivateKey,
    canonical_json,
    from_hex,
    generate_private_key,
    normalize_address,
    private_key_from_bytes,
    private_key_to_bytes,
    public_key_bytes,
    require_fields,
    require_int,
    strict_json_loads,
    to_hex,
)

VERSION = 1
KDF_NAME = "scrypt"
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
# Accepted n when reading a file: the floor allows fast test keystores, the cap
# stops a crafted file from making scrypt allocate gigabytes.
MIN_SCRYPT_N = 2**14
MAX_SCRYPT_N = 2**18
SALT_LEN = 16
KEY_LEN = 32
MIN_PASSWORD_CHARS = 8
MAX_KEYSTORE_BYTES = 16 * 1024
MAX_CIPHERTEXT_BYTES = 1024
UNLOCK_FAILED = "Wrong password or corrupted keystore"

_ALIAS = re.compile(r"[A-Za-z0-9_-]{1,32}")
_LOWER_HEX = re.compile(r"(?:[0-9a-f]{2})+")
_FILE_FIELDS = frozenset({"version", "address", "kdf", "cipher", "ciphertext"})
_KDF_FIELDS = frozenset({"name", "n", "r", "p", "salt"})
_CIPHER_FIELDS = frozenset({"name", "nonce"})
_SECRET_FIELDS = frozenset({"eth", "sig", "enc"})


@dataclass(frozen=True, eq=False)
class UserKeys:
    """K_eth signs transactions, K_sig signs manifests, K_enc receives wrapped DEKs."""

    address: str
    eth_key: bytes = field(repr=False)
    sig_key: PrivateKey = field(repr=False)
    enc_key: PrivateKey = field(repr=False)

    @property
    def sig_public_key(self) -> bytes:
        return public_key_bytes(self.sig_key)

    @property
    def enc_public_key(self) -> bytes:
        return public_key_bytes(self.enc_key)

    def account(self) -> LocalAccount:
        """eth-account signer for transactions; used only by the chain client."""
        return Account.from_key(self.eth_key)


@dataclass(frozen=True)
class _KdfParams:
    salt: bytes
    n: int
    r: int = SCRYPT_R
    p: int = SCRYPT_P


# ----------------------------------------------------------------- keys


def generate_user_keys(eth_private_key: bytes | None = None) -> UserKeys:
    """New K_sig and K_enc; K_eth is new too unless an existing account key is imported."""
    eth_key = private_key_to_bytes(generate_private_key()) if eth_private_key is None else eth_private_key
    return _make_keys(eth_key, generate_private_key(), generate_private_key())


def _make_keys(eth_key: bytes, sig_key: PrivateKey, enc_key: PrivateKey) -> UserKeys:
    private_key_from_bytes(eth_key)  # range check
    if public_key_bytes(sig_key) == public_key_bytes(enc_key):
        raise KeystoreError("Signing and encryption keys must differ")
    address = Account.from_key(eth_key).address
    return UserKeys(address=address, eth_key=eth_key, sig_key=sig_key, enc_key=enc_key)


# ------------------------------------------------------------ encryption


def encrypt_keystore(keys: UserKeys, password: str, *, scrypt_n: int = SCRYPT_N) -> dict[str, Any]:
    """Encrypt all three keys under a password-derived key; returns the keystore dict."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_CHARS:
        raise KeystoreError(f"Password must be at least {MIN_PASSWORD_CHARS} characters")
    params = _KdfParams(salt=os.urandom(SALT_LEN), n=_check_n(scrypt_n))
    nonce = os.urandom(NONCE_LEN)
    header = _header(keys.address, params, nonce)
    secret = canonical_json(
        {
            "eth": to_hex(keys.eth_key),
            "sig": to_hex(private_key_to_bytes(keys.sig_key)),
            "enc": to_hex(private_key_to_bytes(keys.enc_key)),
        }
    )
    ciphertext = AESGCM(_derive_key(password, params)).encrypt(nonce, secret, canonical_json(header))
    return {**header, "ciphertext": to_hex(ciphertext)}


def decrypt_keystore(data: Any, password: str) -> UserKeys:
    """Unlock a parsed keystore. A wrong password and a tampered file raise the same error."""
    address, params, nonce, ciphertext = _parse(data)
    header = _header(address, params, nonce)
    try:
        secret = AESGCM(_derive_key(password, params)).decrypt(nonce, ciphertext, canonical_json(header))
    except InvalidTag:
        raise KeystoreError(UNLOCK_FAILED) from None
    keys = _keys_from_secret(secret)
    # The header address must belong to the decrypted K_eth.
    if keys.address != address:
        raise KeystoreError(UNLOCK_FAILED)
    return keys


def _header(address: str, params: _KdfParams, nonce: bytes) -> dict[str, Any]:
    """Everything except the ciphertext; doubles as the AAD."""
    return {
        "version": VERSION,
        "address": address,
        "kdf": {"name": KDF_NAME, "n": params.n, "r": params.r, "p": params.p, "salt": to_hex(params.salt)},
        "cipher": {"name": ALGORITHM, "nonce": to_hex(nonce)},
    }


def _derive_key(password: str, params: _KdfParams) -> bytes:
    """scrypt over the NFKC form, so equivalent Unicode input yields the same key."""
    normalized = unicodedata.normalize("NFKC", password).encode("utf-8")
    return Scrypt(salt=params.salt, length=KEY_LEN, n=params.n, r=params.r, p=params.p).derive(normalized)


def _parse(data: Any) -> tuple[str, _KdfParams, bytes, bytes]:
    """Validate layout and parameters before any KDF work; failures raise KeystoreError."""
    try:
        fields = require_fields(data, _FILE_FIELDS, "Keystore")
        if fields["version"] != VERSION:
            raise EncodingError(f"unsupported version {fields['version']!r}")
        address = normalize_address(fields["address"])
        kdf = require_fields(fields["kdf"], _KDF_FIELDS, "Keystore kdf")
        cipher = require_fields(fields["cipher"], _CIPHER_FIELDS, "Keystore cipher")
        if kdf["name"] != KDF_NAME or kdf["r"] != SCRYPT_R or kdf["p"] != SCRYPT_P or cipher["name"] != ALGORITHM:
            raise EncodingError("unsupported KDF or cipher parameters")
        params = _KdfParams(salt=from_hex(kdf["salt"], SALT_LEN, "kdf salt"), n=_check_n(kdf["n"]))
        nonce = from_hex(cipher["nonce"], NONCE_LEN, "cipher nonce")
        ciphertext = _ciphertext(fields["ciphertext"])
    except EncodingError as exc:
        raise KeystoreError(f"Not a valid keystore file: {exc}") from exc
    return address, params, nonce, ciphertext


def _check_n(n: Any) -> int:
    value = require_int(n, "scrypt n", minimum=MIN_SCRYPT_N)
    if value > MAX_SCRYPT_N or value & (value - 1):
        raise EncodingError(f"scrypt n must be a power of two between {MIN_SCRYPT_N} and {MAX_SCRYPT_N}")
    return value


def _ciphertext(text: Any) -> bytes:
    if not isinstance(text, str) or len(text) > 2 * MAX_CIPHERTEXT_BYTES or not _LOWER_HEX.fullmatch(text):
        raise EncodingError("ciphertext must be lowercase hex")
    return bytes.fromhex(text)


def _keys_from_secret(secret: bytes) -> UserKeys:
    try:
        fields = require_fields(
            strict_json_loads(secret, max_bytes=MAX_CIPHERTEXT_BYTES, what="Keystore secret"),
            _SECRET_FIELDS,
            "Keystore secret",
        )
        return _make_keys(
            from_hex(fields["eth"], PRIVATE_KEY_LEN, "eth key"),
            private_key_from_bytes(from_hex(fields["sig"], PRIVATE_KEY_LEN, "sig key")),
            private_key_from_bytes(from_hex(fields["enc"], PRIVATE_KEY_LEN, "enc key")),
        )
    except CryptoError:
        raise KeystoreError("Keystore content is corrupted") from None


# ------------------------------------------------------------------ files


def keystore_path(directory: Path, alias: str) -> Path:
    """keystore/<alias>.json; the alias is restricted so it cannot name another path."""
    if not _ALIAS.fullmatch(alias):
        raise KeystoreError("Alias may only use letters, digits, '-' and '_' (at most 32)")
    return directory / f"{alias}.json"


def save_keystore(path: Path, data: dict[str, Any], *, overwrite: bool = False) -> None:
    """Write atomically with owner-only permissions (0600 on Unix)."""
    if path.exists() and not overwrite:
        raise KeystoreError(f"{path.name} already exists")
    payload = canonical_json(data)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise KeystoreError(f"Could not save {path.name}: {exc.strerror or exc}") from exc


def load_keystore(path: Path) -> dict[str, Any]:
    """Read and parse the JSON, size-capped. Unlocking is decrypt_keystore's job."""
    try:
        if path.stat().st_size > MAX_KEYSTORE_BYTES:
            raise KeystoreError(f"{path.name} is too large to be a keystore")
        data = path.read_bytes()
    except OSError as exc:
        raise KeystoreError(f"Could not read {path.name}: {exc.strerror or exc}") from exc
    try:
        return strict_json_loads(data, max_bytes=MAX_KEYSTORE_BYTES, what=path.name)
    except EncodingError as exc:
        raise KeystoreError(f"Not a valid keystore file: {exc}") from exc
