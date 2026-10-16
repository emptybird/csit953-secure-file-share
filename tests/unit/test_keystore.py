from __future__ import annotations

import copy
import os
import secrets
import stat
import unicodedata
from pathlib import Path
from typing import Any

import pytest
from eth_account import Account

from app.crypto import KeystoreError
from app.crypto.encoding import private_key_to_bytes
from app.crypto.keystore import (
    MIN_SCRYPT_N,
    SCRYPT_N,
    UNLOCK_FAILED,
    UserKeys,
    decrypt_keystore,
    encrypt_keystore,
    generate_user_keys,
    keystore_path,
    load_keystore,
    save_keystore,
)

PASSWORD = "correct horse battery"


@pytest.fixture(scope="module")
def keys() -> UserKeys:
    return generate_user_keys()


@pytest.fixture(scope="module")
def keyfile(keys: UserKeys) -> dict[str, Any]:
    return encrypt_keystore(keys, PASSWORD, scrypt_n=MIN_SCRYPT_N)


def _private_hex(keys: UserKeys) -> list[str]:
    return [keys.eth_key.hex(), private_key_to_bytes(keys.sig_key).hex(), private_key_to_bytes(keys.enc_key).hex()]


def _same_keys(a: UserKeys, b: UserKeys) -> bool:
    return a.address == b.address and _private_hex(a) == _private_hex(b)


class TestKeys:
    def test_three_independent_keys(self, keys: UserKeys) -> None:
        assert len(set(_private_hex(keys))) == 3
        assert keys.sig_public_key != keys.enc_public_key

    def test_address_belongs_to_eth_key(self, keys: UserKeys) -> None:
        assert keys.account().address == keys.address == Account.from_key(keys.eth_key).address

    def test_import_existing_account_key(self) -> None:
        eth_key = secrets.token_bytes(32)
        imported = generate_user_keys(eth_private_key=eth_key)
        assert imported.address == Account.from_key(eth_key).address

    def test_repr_hides_private_keys(self, keys: UserKeys) -> None:
        text = repr(keys)
        assert keys.address in text
        assert not any(part in text for part in _private_hex(keys))


class TestRoundTrip:
    def test_unlock_restores_all_keys(self, keys: UserKeys, keyfile: dict[str, Any]) -> None:
        assert _same_keys(decrypt_keystore(keyfile, PASSWORD), keys)

    def test_default_parameters(self, keys: UserKeys) -> None:
        keyfile = encrypt_keystore(keys, PASSWORD)
        kdf = keyfile["kdf"]
        assert (kdf["name"], kdf["n"], kdf["r"], kdf["p"], len(kdf["salt"])) == ("scrypt", SCRYPT_N, 8, 1, 32)
        assert keyfile["cipher"]["name"] == "AES-256-GCM"
        assert _same_keys(decrypt_keystore(keyfile, PASSWORD), keys)

    def test_file_contains_no_private_key(self, keys: UserKeys, keyfile: dict[str, Any]) -> None:
        text = str(keyfile)
        assert not any(part in text for part in _private_hex(keys))

    def test_password_is_unicode_normalized(self, keys: UserKeys) -> None:
        composed = unicodedata.normalize("NFC", "pässwörd-123")
        decomposed = unicodedata.normalize("NFD", composed)
        assert composed != decomposed
        keyfile = encrypt_keystore(keys, composed, scrypt_n=MIN_SCRYPT_N)
        assert _same_keys(decrypt_keystore(keyfile, decomposed), keys)

    def test_short_password_rejected(self, keys: UserKeys) -> None:
        with pytest.raises(KeystoreError, match="at least"):
            encrypt_keystore(keys, "short", scrypt_n=MIN_SCRYPT_N)


def _edit(keyfile: dict[str, Any], *path: str, value: Any) -> dict[str, Any]:
    edited = copy.deepcopy(keyfile)
    target = edited
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return edited


def _flip_hex(text: str) -> str:
    return ("1" if text[0] == "0" else "0") + text[1:]


class TestUnlockFailures:
    def test_S13_wrong_password(self, keyfile: dict[str, Any]) -> None:
        with pytest.raises(KeystoreError) as info:
            decrypt_keystore(keyfile, PASSWORD + "!")
        assert str(info.value) == UNLOCK_FAILED

    @pytest.mark.parametrize(
        "path",
        [("address",), ("kdf", "salt"), ("cipher", "nonce"), ("ciphertext",)],
        ids=["address", "salt", "nonce", "ciphertext"],
    )
    def test_tampering_looks_like_a_wrong_password(self, keyfile: dict[str, Any], path: tuple[str, ...]) -> None:
        """The header is the AAD, so editing it fails the same way and gives the same message."""
        original = keyfile
        for key in path:
            original = original[key]
        value = Account.create().address if path == ("address",) else _flip_hex(original)
        with pytest.raises(KeystoreError) as info:
            decrypt_keystore(_edit(keyfile, *path, value=value), PASSWORD)
        assert str(info.value) == UNLOCK_FAILED

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            (("kdf", "n"), 2**30),
            (("kdf", "n"), 3 * 2**14),
            (("kdf", "n"), 2**10),
            (("kdf", "r"), 1),
            (("kdf", "name"), "pbkdf2"),
            (("cipher", "name"), "AES-256-CTR"),
            (("version",), 2),
            (("ciphertext",), "XYZ"),
        ],
        ids=["n-huge", "n-not-power-of-two", "n-too-small", "r", "kdf-name", "cipher-name", "version", "hex"],
    )
    def test_rejects_unsupported_parameters(
        self, keyfile: dict[str, Any], path: tuple[str, ...], value: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Checked before scrypt runs, so a crafted file cannot exhaust memory."""

        def scrypt_must_not_run(*_: Any) -> bytes:
            pytest.fail("scrypt ran before the parameters were checked")

        # Without the stub, a missing check would run scrypt with n = 2**30 (1 TiB) instead of failing.
        monkeypatch.setattr("app.crypto.keystore._derive_key", scrypt_must_not_run)
        with pytest.raises(KeystoreError, match="Not a valid keystore"):
            decrypt_keystore(_edit(keyfile, *path, value=value), PASSWORD)

    @pytest.mark.parametrize("data", [[], {}, "keystore", None])
    def test_rejects_non_keystore_data(self, data: Any) -> None:
        with pytest.raises(KeystoreError, match="Not a valid keystore"):
            decrypt_keystore(data, PASSWORD)


class TestFiles:
    def test_save_and_load(self, tmp_path: Path, keys: UserKeys, keyfile: dict[str, Any]) -> None:
        path = keystore_path(tmp_path / "keystore", "alice")
        save_keystore(path, keyfile)
        assert _same_keys(decrypt_keystore(load_keystore(path), PASSWORD), keys)
        assert [p.name for p in path.parent.iterdir()] == ["alice.json"]  # no temp files left

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
    def test_file_is_owner_only(self, tmp_path: Path, keyfile: dict[str, Any]) -> None:
        path = tmp_path / "alice.json"
        save_keystore(path, keyfile)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_refuses_to_overwrite(self, tmp_path: Path, keyfile: dict[str, Any]) -> None:
        path = tmp_path / "alice.json"
        save_keystore(path, keyfile)
        with pytest.raises(KeystoreError, match="already exists"):
            save_keystore(path, keyfile)
        save_keystore(path, keyfile, overwrite=True)

    def test_load_rejects_bad_files(self, tmp_path: Path) -> None:
        missing, garbage, huge = tmp_path / "missing.json", tmp_path / "garbage.json", tmp_path / "huge.json"
        garbage.write_bytes(b"{not json")
        huge.write_bytes(b" " * (64 * 1024))
        for path in (missing, garbage, huge):
            with pytest.raises(KeystoreError):
                load_keystore(path)

    @pytest.mark.parametrize("alias", ["", "../alice", "a/b", "alice bob", "x" * 33])
    def test_alias_cannot_escape_directory(self, tmp_path: Path, alias: str) -> None:
        with pytest.raises(KeystoreError):
            keystore_path(tmp_path, alias)
