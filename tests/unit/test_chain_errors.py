from __future__ import annotations

from pathlib import Path

import pytest
import requests
from eth_abi import encode
from eth_utils import keccak
from web3.exceptions import ContractCustomError, ContractLogicError, ContractPanicError, Web3RPCError

from app.chain import (
    ChainConnectionError,
    ChainError,
    ContractRevertError,
    RequestStatus,
    TransactionError,
)
from app.chain.client import load_abi
from app.chain.errors import decode_revert, describe, error_table, short_hex, translate

ABI = load_abi()
TABLE = error_table(ABI)
FILE_ID = bytes.fromhex("7c" * 31 + "41")
MALLORY = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
SAMPLE_ARGS = {"bytes32": FILE_ID, "address": MALLORY, "uint8": 2}


def _revert_data(signature: str, types: list[str], values: list[object]) -> str:
    return "0x" + (keccak(text=signature)[:4] + encode(types, values)).hex()


class TestTable:
    def test_every_abi_error_is_known(self) -> None:
        names = {entry["name"] for entry in ABI if entry["type"] == "error"}
        assert {entry.name for entry in TABLE.values()} == names
        assert len(names) == 11

    def test_selector_uses_the_canonical_signature(self) -> None:
        selector = keccak(text="NotFileOwner(bytes32,address)")[:4]
        assert TABLE[selector].types == ("bytes32", "address")

    def test_enum_argument_is_uint8(self) -> None:
        assert TABLE[keccak(text="InvalidStatus(uint8)")[:4]].name == "InvalidStatus"

    @pytest.mark.parametrize("entry", list(TABLE.values()), ids=lambda e: e.name)
    def test_every_error_has_a_specific_message(self, entry) -> None:
        message = describe(entry.name, tuple(SAMPLE_ARGS[t] for t in entry.types))
        assert "rejected the call" not in message


class TestDecode:
    def test_not_file_owner(self) -> None:
        data = _revert_data("NotFileOwner(bytes32,address)", ["bytes32", "address"], [FILE_ID, MALLORY])
        error = decode_revert(data, TABLE)
        assert error.error_name == "NotFileOwner"
        assert error.error_args == (FILE_ID, MALLORY.lower())
        assert "Only the owner" in str(error)
        assert MALLORY in str(error)
        assert short_hex(FILE_ID) in str(error)

    @pytest.mark.parametrize("status", list(RequestStatus))
    def test_invalid_status_names_the_state(self, status: RequestStatus) -> None:
        error = decode_revert(_revert_data("InvalidStatus(uint8)", ["uint8"], [status]), TABLE)
        assert str(error) == f"Not allowed while the request is {status.label}"

    def test_out_of_range_status(self) -> None:
        error = decode_revert(_revert_data("InvalidStatus(uint8)", ["uint8"], [9]), TABLE)
        assert "status 9" in str(error)

    def test_error_without_arguments(self) -> None:
        error = decode_revert("0x" + keccak(text="OwnerCannotRequest()")[:4].hex(), TABLE)
        assert error.error_name == "OwnerCannotRequest"
        assert error.error_args == ()

    def test_bytes_input(self) -> None:
        data = bytes.fromhex(_revert_data("FileNotFound(bytes32)", ["bytes32"], [FILE_ID])[2:])
        assert decode_revert(data, TABLE).error_name == "FileNotFound"

    @pytest.mark.parametrize("data", ["0xdeadbeef", "0x", "0x12", "nothex", "0xzz112233", None, {"x": 1}])
    def test_unknown_or_malformed(self, data: object) -> None:
        error = decode_revert(data, TABLE)
        assert error.error_name == "Unknown"
        assert "unrecognised" in str(error)

    def test_truncated_arguments_keep_the_name(self) -> None:
        data = _revert_data("FileNotFound(bytes32)", ["bytes32"], [FILE_ID])[:-10]
        error = decode_revert(data, TABLE)
        assert error.error_name == "FileNotFound"
        assert error.error_args == ()
        assert "FileNotFound" in str(error)


class TestTranslate:
    def test_custom_error(self) -> None:
        exc = ContractCustomError("0x...", data=_revert_data("FileInactive(bytes32)", ["bytes32"], [FILE_ID]))
        translated = translate(exc, TABLE, "127.0.0.1")
        assert isinstance(translated, ContractRevertError)
        assert translated.error_name == "FileInactive"

    def test_panic_and_plain_revert(self) -> None:
        assert translate(ContractPanicError("Panic", data="0x4e487b71"), TABLE, "h").error_name == "Panic"
        plain = translate(ContractLogicError("execution reverted: nope"), TABLE, "h")
        assert plain.error_name == "Revert"
        assert "nope" in str(plain)

    def test_connection_error_names_only_the_host(self) -> None:
        exc = requests.exceptions.ConnectionError(
            "HTTPSConnectionPool(host='eth-sepolia.g.alchemy.com'): Max retries exceeded with url: /v2/SECRETKEY"
        )
        translated = translate(exc, TABLE, "eth-sepolia.g.alchemy.com")
        assert isinstance(translated, ChainConnectionError)
        assert "SECRETKEY" not in str(translated)
        assert "eth-sepolia.g.alchemy.com" in str(translated)

    def test_timeout_is_a_connection_error(self) -> None:
        assert isinstance(translate(requests.exceptions.ReadTimeout("slow"), TABLE, "h"), ChainConnectionError)

    def test_insufficient_funds(self) -> None:
        exc = Web3RPCError(
            "x", rpc_response={"error": {"code": -32003, "message": "Insufficient funds for gas * price + value"}}
        )
        translated = translate(exc, TABLE, "h")
        assert isinstance(translated, TransactionError)
        assert str(translated) == "Not enough ETH in this account to pay for gas"

    def test_nonce_problem(self) -> None:
        exc = Web3RPCError("x", rpc_response={"error": {"code": -32000, "message": "nonce too low"}})
        assert "nonce" in str(translate(exc, TABLE, "h"))

    def test_other_rpc_error(self) -> None:
        exc = Web3RPCError("method not found")
        assert "method not found" in str(translate(exc, TABLE, "h"))

    def test_chain_error_passes_through(self) -> None:
        original = ChainError("already translated")
        assert translate(original, TABLE, "h") is original

    def test_unexpected_exception_hides_details(self) -> None:
        translated = translate(RuntimeError("internal /secret/path"), TABLE, "h")
        assert type(translated) is ChainError
        assert "/secret/path" not in str(translated)


def test_missing_abi_file(tmp_path: Path) -> None:
    with pytest.raises(ChainConnectionError, match="ABI"):
        load_abi(tmp_path / "missing.json")
