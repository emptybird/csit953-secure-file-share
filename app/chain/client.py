"""web3.py client for SecureFileShare.

Views return frozen dataclasses instead of web3's positional tuples.
Transactions are built, signed locally with the user's K_eth and sent raw, so
the node never holds a user key. Gas estimation runs first: a call that would
revert fails there with a decoded ContractRevertError and costs nothing.
`transact(gas_limit=...)` skips the estimate so a reverting call still gets
mined; the security demo relies on this.

Sends are serialised (one lock around nonce, send and receipt), so worker
threads cannot race each other into a nonce clash.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.exceptions import ContractLogicError, TransactionNotFound, Web3Exception

from app.chain import (
    ChainConnectionError,
    ChainError,
    ContractRevertError,
    RequestStatus,
    TransactionFailedError,
    TransactionTimeoutError,
    errors,
)
from app.chain.events import ChainEvent, EventDecoder
from app.config import NetworkConfig
from app.crypto import ecies
from app.crypto.encoding import HASH_LEN, normalize_address

ABI_PATH = Path(__file__).resolve().parent / "abi" / "SecureFileShare.json"
RPC_TIMEOUT_SECONDS = 30
RECEIPT_TIMEOUT_SECONDS = 300
# Poll quickly first (Anvil mines within milliseconds), then back off so a 12 s
# Sepolia block does not cost dozens of requests against a rate-limited RPC.
RECEIPT_FIRST_POLL_SECONDS = 0.05
RECEIPT_MAX_POLL_SECONDS = 2.0
GAS_MARGIN_PERCENT = 20

SubmittedCallback = Callable[[str], None]


@dataclass(frozen=True)
class RegisteredKeys:
    """A user's on-chain public keys; both empty if never registered."""

    sig_public_key: bytes
    enc_public_key: bytes

    @property
    def is_registered(self) -> bool:
        return bool(self.sig_public_key)


@dataclass(frozen=True)
class FileRecord:
    """getFile() result."""

    file_id: bytes
    owner: str
    registered_at: int
    active: bool
    ct_hash: bytes
    manifest_hash: bytes
    owner_wrapped_key: bytes = field(repr=False)


@dataclass(frozen=True)
class RequestRecord:
    """getRequest() result; `wrapped_key` is set only while approved."""

    status: RequestStatus
    updated_at: int
    wrapped_key: bytes = field(repr=False)


@dataclass(frozen=True)
class TxReceipt:
    """A mined, successful transaction and the contract events it emitted."""

    tx_hash: str
    block_number: int
    gas_used: int
    events: tuple[ChainEvent, ...]

    def event(self, name: str) -> ChainEvent | None:
        return next((event for event in self.events if event.name == name), None)


def load_abi(path: Path = ABI_PATH) -> list[dict[str, Any]]:
    """The ABI exported by scripts/deploy.py ({contractName, compiler, abi, bytecode})."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))["abi"]
    except (OSError, ValueError, KeyError) as exc:
        raise ChainConnectionError(f"Cannot read the contract ABI {path.name}: {exc}") from exc


class ChainClient:
    """Typed access to one SecureFileShare deployment."""

    def __init__(self, w3: Web3, config: NetworkConfig, abi: list[dict[str, Any]] | None = None) -> None:
        abi = load_abi() if abi is None else abi
        self._w3 = w3
        self._config = config
        self._contract = w3.eth.contract(address=config.contract_address, abi=abi)
        self._errors = errors.error_table(abi)
        self._decoder = EventDecoder(self._contract)
        self._send_lock = threading.Lock()

    @classmethod
    def connect(cls, config: NetworkConfig, *, timeout: float = RPC_TIMEOUT_SECONDS) -> ChainClient:
        """Connect and check that the node and contract are the ones the config names."""
        w3 = Web3(Web3.HTTPProvider(config.rpc_url, request_kwargs={"timeout": timeout}))
        client = cls(w3, config)
        client.check_deployment()
        return client

    def check_deployment(self) -> None:
        """Fail fast on a wrong chain, a missing contract or an incompatible one."""
        host, address = self._config.rpc_host, self._config.contract_address
        with self._rpc():
            chain_id = self._w3.eth.chain_id
            if chain_id != self._config.chain_id:
                raise ChainConnectionError(
                    f"{host} is chain {chain_id}, but the {self._config.name} settings expect {self._config.chain_id}"
                )
            if not self._w3.eth.get_code(address):
                raise ChainConnectionError(f"No contract at {address} on {self._config.name}; deploy it first")
            wrapped_len = self._contract.functions.WRAPPED_KEY_LEN().call()
        if wrapped_len != ecies.WRAPPED_KEY_LEN:
            raise ChainConnectionError(f"The contract at {address} is not a compatible SecureFileShare")

    # ----------------------------------------------------------- properties

    @property
    def config(self) -> NetworkConfig:
        return self._config

    @property
    def chain_id(self) -> int:
        return self._config.chain_id

    @property
    def contract_address(self) -> str:
        return self._config.contract_address

    @property
    def deploy_block(self) -> int:
        return self._config.deploy_block

    @property
    def web3(self) -> Web3:
        """The underlying connection, for scripts and tests that need raw RPC calls."""
        return self._w3

    # ---------------------------------------------------------------- views

    def latest_block(self) -> int:
        with self._rpc():
            return self._w3.eth.block_number

    def balance(self, address: str) -> int:
        with self._rpc():
            return self._w3.eth.get_balance(normalize_address(address))

    def get_user_keys(self, user: str) -> RegisteredKeys:
        with self._rpc():
            sig, enc = self._contract.functions.getUserKeys(normalize_address(user)).call()
        return RegisteredKeys(sig_public_key=bytes(sig), enc_public_key=bytes(enc))

    def get_file(self, file_id: bytes) -> FileRecord:
        """Raises ContractRevertError("FileNotFound") for an unknown fileId."""
        with self._rpc():
            owner, registered_at, active, ct_hash, manifest_hash, wrapped = self._contract.functions.getFile(
                _bytes32(file_id, "fileId")
            ).call()
        return FileRecord(
            file_id=file_id,
            owner=owner,
            registered_at=registered_at,
            active=active,
            ct_hash=bytes(ct_hash),
            manifest_hash=bytes(manifest_hash),
            owner_wrapped_key=bytes(wrapped),
        )

    def get_request(self, file_id: bytes, requester: str) -> RequestRecord:
        with self._rpc():
            status, updated_at, wrapped = self._contract.functions.getRequest(
                _bytes32(file_id, "fileId"), normalize_address(requester)
            ).call()
        return RequestRecord(status=RequestStatus(status), updated_at=updated_at, wrapped_key=bytes(wrapped))

    def compute_file_id(self, owner: str, salt: bytes) -> bytes:
        with self._rpc():
            return bytes(
                self._contract.functions.computeFileId(normalize_address(owner), _bytes32(salt, "salt")).call()
            )

    def get_events(self, from_block: int, to_block: int) -> tuple[ChainEvent, ...]:
        """Decoded contract events in [from_block, to_block]."""
        with self._rpc():
            logs = self._w3.eth.get_logs(
                {"address": self.contract_address, "fromBlock": from_block, "toBlock": to_block}
            )
        return self._decoder.decode_all(logs)

    # --------------------------------------------------------- transactions
    # Thin wrappers: check argument shapes, then transact().

    def register_keys(
        self,
        account: LocalAccount,
        sig_public_key: bytes,
        enc_public_key: bytes,
        *,
        on_submitted: SubmittedCallback | None = None,
    ) -> TxReceipt:
        return self.transact(account, "registerKeys", sig_public_key, enc_public_key, on_submitted=on_submitted)

    def register_file(
        self,
        account: LocalAccount,
        salt: bytes,
        ct_hash: bytes,
        manifest_hash: bytes,
        owner_wrapped_key: bytes,
        public_label: str = "",
        *,
        on_submitted: SubmittedCallback | None = None,
    ) -> TxReceipt:
        args = (_bytes32(salt, "salt"), _bytes32(ct_hash, "ctHash"), _bytes32(manifest_hash, "manifestHash"))
        return self.transact(account, "registerFile", *args, owner_wrapped_key, public_label, on_submitted=on_submitted)

    def request_access(
        self, account: LocalAccount, file_id: bytes, *, on_submitted: SubmittedCallback | None = None
    ) -> TxReceipt:
        return self.transact(account, "requestAccess", _bytes32(file_id, "fileId"), on_submitted=on_submitted)

    def approve_access(
        self,
        account: LocalAccount,
        file_id: bytes,
        requester: str,
        wrapped_key: bytes,
        *,
        on_submitted: SubmittedCallback | None = None,
    ) -> TxReceipt:
        args = (_bytes32(file_id, "fileId"), normalize_address(requester), wrapped_key)
        return self.transact(account, "approveAccess", *args, on_submitted=on_submitted)

    def reject_access(
        self, account: LocalAccount, file_id: bytes, requester: str, *, on_submitted: SubmittedCallback | None = None
    ) -> TxReceipt:
        args = (_bytes32(file_id, "fileId"), normalize_address(requester))
        return self.transact(account, "rejectAccess", *args, on_submitted=on_submitted)

    def revoke_access(
        self, account: LocalAccount, file_id: bytes, requester: str, *, on_submitted: SubmittedCallback | None = None
    ) -> TxReceipt:
        args = (_bytes32(file_id, "fileId"), normalize_address(requester))
        return self.transact(account, "revokeAccess", *args, on_submitted=on_submitted)

    def deactivate_file(
        self, account: LocalAccount, file_id: bytes, *, on_submitted: SubmittedCallback | None = None
    ) -> TxReceipt:
        return self.transact(account, "deactivateFile", _bytes32(file_id, "fileId"), on_submitted=on_submitted)

    def transact(
        self,
        account: LocalAccount,
        function: str,
        *args: Any,
        gas_limit: int | None = None,
        on_submitted: SubmittedCallback | None = None,
    ) -> TxReceipt:
        """Sign and send one contract call and wait for its receipt.

        `on_submitted(tx_hash)` runs as soon as the node accepts the transaction,
        so the GUI can show the hash while it waits for a block.
        Raises ContractRevertError if gas estimation shows the call would revert,
        TransactionFailedError if it reverted on-chain, TransactionTimeoutError if
        no receipt arrived in time."""
        call = self._contract.functions[function](*args)
        with self._send_lock:
            with self._rpc():
                params = {
                    "from": account.address,
                    "chainId": self.chain_id,
                    "nonce": self._w3.eth.get_transaction_count(account.address, "pending"),
                }
                if gas_limit is None:
                    # Estimation dry-runs the call: a revert surfaces here, before any gas is spent.
                    estimate = call.estimate_gas({"from": account.address})
                    params["gas"] = estimate + estimate * GAS_MARGIN_PERCENT // 100
                else:
                    params["gas"] = gas_limit
                tx = call.build_transaction(params)
                tx_hash = self._w3.eth.send_raw_transaction(account.sign_transaction(tx).raw_transaction).to_0x_hex()
            if on_submitted is not None:
                on_submitted(tx_hash)
            receipt = self._wait_for_receipt(tx_hash)

        if receipt["status"] != 1:
            # The receipt carries no reason; replay the call to recover it.
            revert = self._replay_revert(tx, receipt["blockNumber"])
            reason = f": {revert}" if revert is not None else ""
            raise TransactionFailedError(f"Transaction {tx_hash} reverted on-chain{reason}", tx_hash, revert)
        return TxReceipt(
            tx_hash=tx_hash,
            block_number=receipt["blockNumber"],
            gas_used=receipt["gasUsed"],
            events=self._decoder.decode_all(receipt["logs"]),
        )

    # ------------------------------------------------------------- internal

    def _wait_for_receipt(self, tx_hash: str) -> Any:
        """Poll with exponential backoff until mined or RECEIPT_TIMEOUT_SECONDS passes."""
        deadline = time.monotonic() + RECEIPT_TIMEOUT_SECONDS
        delay = RECEIPT_FIRST_POLL_SECONDS
        while True:
            with self._rpc():
                try:
                    return self._w3.eth.get_transaction_receipt(tx_hash)
                except TransactionNotFound:
                    pass
            if time.monotonic() >= deadline:
                raise TransactionTimeoutError(
                    f"No receipt for {tx_hash} after {RECEIPT_TIMEOUT_SECONDS} s; it may still be mined later", tx_hash
                )
            time.sleep(delay)
            delay = min(delay * 2, RECEIPT_MAX_POLL_SECONDS)

    def _replay_revert(self, tx: dict[str, Any], block_number: int) -> ContractRevertError | None:
        """Best effort: re-run the failed call on the state before its block to learn why."""
        call = {key: tx[key] for key in ("from", "to", "data", "gas")}
        try:
            self._w3.eth.call(call, block_identifier=max(block_number - 1, 0))
        except ContractLogicError as exc:
            translated = errors.translate(exc, self._errors, self._config.rpc_host)
            return translated if isinstance(translated, ContractRevertError) else None
        except (Web3Exception, OSError, ValueError):
            return None
        return None

    @contextmanager
    def _rpc(self) -> Iterator[None]:
        """Translate web3/requests exceptions into ChainError. Connection errors drop
        the original exception, whose text contains the full RPC URL."""
        try:
            yield
        except ChainError:
            raise
        except (Web3Exception, OSError) as exc:
            translated = errors.translate(exc, self._errors, self._config.rpc_host)
            if isinstance(translated, ChainConnectionError):
                raise translated from None
            raise translated from exc


def _bytes32(value: bytes, what: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != HASH_LEN:
        raise ValueError(f"{what} must be 32 bytes")
    return value
