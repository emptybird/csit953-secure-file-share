"""Readable messages for contract reverts and RPC failures.

web3.py reports a revert as ContractCustomError whose `data` is the 4-byte error
selector followed by the ABI-encoded arguments. The selector table is built from
the ABI, so a new custom error only needs a message in `_MESSAGES`.

Connection errors from `requests` quote the full RPC URL, which may embed an API
key, so they are replaced by a message that names only the host.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import requests
from eth_abi import decode
from eth_abi.exceptions import DecodingError
from eth_utils import keccak, to_checksum_address
from web3.exceptions import (
    ContractCustomError,
    ContractLogicError,
    ContractPanicError,
    ProviderConnectionError,
    Web3RPCError,
)

from app.chain import (
    ChainConnectionError,
    ChainError,
    ContractRevertError,
    RequestStatus,
    TransactionError,
)

SELECTOR_LEN = 4


@dataclass(frozen=True)
class ErrorAbi:
    name: str
    types: tuple[str, ...]


ErrorTable = Mapping[bytes, ErrorAbi]


def error_table(abi: list[dict[str, Any]]) -> dict[bytes, ErrorAbi]:
    """selector -> custom error, for every `error` entry of the ABI."""
    table = {}
    for entry in abi:
        if entry.get("type") != "error":
            continue
        types = tuple(item["type"] for item in entry.get("inputs", []))
        selector = keccak(text=f"{entry['name']}({','.join(types)})")[:SELECTOR_LEN]
        table[selector] = ErrorAbi(name=entry["name"], types=types)
    return table


def decode_revert(data: Any, table: ErrorTable) -> ContractRevertError:
    """Revert data (selector + ABI-encoded args) -> ContractRevertError with a readable message."""
    raw = _revert_bytes(data)
    entry = table.get(raw[:SELECTOR_LEN]) if raw is not None else None
    if entry is None:
        return ContractRevertError("The contract rejected the call (unrecognised error)", "Unknown")
    try:
        values = tuple(decode(list(entry.types), raw[SELECTOR_LEN:]))
    except (DecodingError, ValueError, OverflowError):
        values = ()
    return ContractRevertError(describe(entry.name, values), entry.name, values)


def describe(name: str, values: tuple[Any, ...]) -> str:
    """The message shown to the user for a custom error."""
    message = _MESSAGES.get(name)
    if message is None:
        return f"The contract rejected the call ({name})"
    try:
        return message(*values)
    except (TypeError, ValueError, IndexError):
        return f"The contract rejected the call ({name})"


def translate(exc: Exception, table: ErrorTable, rpc_host: str) -> ChainError:
    """Map an exception raised by web3.py or requests to a ChainError."""
    if isinstance(exc, ChainError):
        return exc
    if isinstance(exc, ContractCustomError):
        return decode_revert(exc.data, table)
    if isinstance(exc, ContractPanicError):
        return ContractRevertError("The contract hit an internal error (panic)", "Panic")
    if isinstance(exc, ContractLogicError):
        return ContractRevertError(f"The contract rejected the call: {exc.message or 'no reason given'}", "Revert")
    if isinstance(exc, (requests.RequestException, ProviderConnectionError, ConnectionError, TimeoutError)):
        return ChainConnectionError(
            f"Cannot reach {rpc_host}; check the network connection and that the node is running"
        )
    if isinstance(exc, Web3RPCError):
        return _rpc_error(exc)
    return ChainError(f"Blockchain request failed ({type(exc).__name__})")


def short_hex(value: bytes) -> str:
    """0x1234…abcd: enough of a fileId to recognise it in a message."""
    text = value.hex()
    return f"0x{text[:4]}…{text[-4:]}"


def _rpc_error(exc: Web3RPCError) -> TransactionError:
    """Explain the common node rejections; otherwise pass the node's message through."""
    response = exc.rpc_response if isinstance(exc.rpc_response, dict) else {}
    error = response.get("error") if isinstance(response.get("error"), dict) else {}
    message = str(error.get("message") or exc.message or "").strip()
    lowered = message.lower()
    if "insufficient funds" in lowered:
        return TransactionError("Not enough ETH in this account to pay for gas")
    if "nonce too low" in lowered or "already known" in lowered or "replacement transaction" in lowered:
        return TransactionError(
            f"The node rejected the transaction nonce ({message}); wait for pending transactions and retry"
        )
    return TransactionError(f"The node rejected the request: {message or 'no reason given'}")


def _revert_bytes(data: Any) -> bytes | None:
    """Revert payload as bytes; None if it is not hex or too short for a selector."""
    if isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
    elif isinstance(data, str) and data.startswith("0x"):
        try:
            raw = bytes.fromhex(data[2:])
        except ValueError:
            return None
    else:
        return None
    return raw if len(raw) >= SELECTOR_LEN else None


def _status(value: int) -> str:
    try:
        return RequestStatus(value).label
    except ValueError:
        return f"status {value}"


# Custom error name -> message builder, called with the decoded arguments.
_MESSAGES: dict[str, Callable[..., str]] = {
    "InvalidPublicKey": lambda: "The public keys must be two different 33-byte compressed secp256k1 keys",
    "KeysNotRegistered": lambda user: f"{to_checksum_address(user)} has not registered public keys yet",
    "InvalidHash": lambda: "ctHash and manifestHash must not be zero",
    "InvalidWrappedKey": lambda: "A wrapped key must be exactly 93 bytes",
    "LabelTooLong": lambda: "The public label is longer than 128 bytes",
    "FileAlreadyExists": lambda file_id: f"File {short_hex(file_id)} is already registered",
    "FileNotFound": lambda file_id: f"No file {short_hex(file_id)} is registered on this contract",
    "FileInactive": lambda file_id: f"File {short_hex(file_id)} has been deactivated by its owner",
    "NotFileOwner": lambda file_id, caller: (
        f"Only the owner of file {short_hex(file_id)} can do this; {to_checksum_address(caller)} is not the owner"
    ),
    "OwnerCannotRequest": lambda: "You own this file, so you cannot request access to it",
    "InvalidStatus": lambda current: f"Not allowed while the request is {_status(current)}",
}
