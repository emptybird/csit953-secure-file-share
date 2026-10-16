"""Client for the SecureFileShare contract (DESIGN.md 5).

client  web3.py wrapper: typed view calls and signed transactions
errors  custom-error decoding and readable messages for reverts and RPC failures
events  event decoding, incremental log scanning and CSV export for the Activity Log

The exceptions below are shared by all modules. Messages are safe to show to the
user; in particular they never contain the RPC URL, which may embed an API key.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any


class RequestStatus(IntEnum):
    """SecureFileShare.Status; the numbers must match the Solidity enum."""

    NONE = 0
    PENDING = 1
    APPROVED = 2
    REJECTED = 3
    REVOKED = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


class ChainError(Exception):
    """Base class; the GUI can catch this one type."""


class ChainConnectionError(ChainError):
    """The node cannot be reached, is on another chain, or has no compatible contract."""


class ContractRevertError(ChainError):
    """The contract rejected a call. `error_name` is the Solidity custom error
    (e.g. "NotFileOwner") and `error_args` its decoded arguments."""

    def __init__(self, message: str, error_name: str, error_args: tuple[Any, ...] = ()) -> None:
        super().__init__(message)
        self.error_name = error_name
        self.error_args = error_args


class TransactionError(ChainError):
    """The node refused a transaction, e.g. not enough ETH for gas or a stale nonce."""


class TransactionFailedError(ChainError):
    """A transaction was mined but reverted. Only possible when gas estimation was
    skipped or the state changed between estimation and mining."""

    def __init__(self, message: str, tx_hash: str, revert: ContractRevertError | None) -> None:
        super().__init__(message)
        self.tx_hash = tx_hash
        self.revert = revert


class TransactionTimeoutError(ChainError):
    """No receipt arrived in time. The transaction may still be mined later."""

    def __init__(self, message: str, tx_hash: str) -> None:
        super().__init__(message)
        self.tx_hash = tx_hash
