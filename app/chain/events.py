"""Contract events: decoding, incremental scanning and CSV export (DESIGN.md 5.5).

Solidity mappings cannot be enumerated, so events are how clients discover files
(FileRegistered, which also carries the public label) and requesters
(AccessRequested). Events serve only discovery and the audit trail; the current
state of a file or request is always read from the view functions.

eth_getLogs is called in block ranges of DEFAULT_CHUNK_BLOCKS because public
Sepolia endpoints limit the range of a single query, and EventLog remembers how
far it has scanned so that polling only asks for new blocks.
"""

from __future__ import annotations

import csv
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from web3.contract import Contract
from web3.exceptions import Web3Exception

from app.crypto.encoding import fingerprint, normalize_address

if TYPE_CHECKING:
    from app.chain.client import ChainClient

EVENT_NAMES = (
    "KeysRegistered",
    "FileRegistered",
    "AccessRequested",
    "AccessApproved",
    "AccessRejected",
    "AccessRevoked",
    "FileDeactivated",
)
DEFAULT_CHUNK_BLOCKS = 5000
CSV_COLUMNS = ("block", "tx_hash", "log_index", "event", "file_id", "account", "label", "details")

_ACCOUNT_ARGS = ("requester", "owner", "user")
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


@dataclass(frozen=True)
class ChainEvent:
    name: str
    block_number: int
    tx_hash: str
    log_index: int
    args: Mapping[str, Any]

    @property
    def file_id(self) -> bytes | None:
        return self.args.get("fileId")

    @property
    def account(self) -> str | None:
        """The user the event is about: requester, owner or key holder."""
        return next((self.args[name] for name in _ACCOUNT_ARGS if name in self.args), None)

    @property
    def label(self) -> str:
        return self.args.get("publicLabel", "")

    def details(self) -> str:
        if self.name == "KeysRegistered":
            return f"sigKey {fingerprint(self.args['sigPubKey'])}; encKey {fingerprint(self.args['encPubKey'])}"
        if self.name == "FileRegistered":
            return f"ctHash {self.args['ctHash'].hex()[:16]}…"
        return ""


class EventDecoder:
    """Turns raw logs of one contract into ChainEvents; logs of other contracts are skipped."""

    def __init__(self, contract: Contract) -> None:
        self._address = contract.address
        self._events = {bytes.fromhex(contract.events[name].topic[2:]): contract.events[name] for name in EVENT_NAMES}

    def decode(self, log: Mapping[str, Any]) -> ChainEvent | None:
        topics = log.get("topics") or ()
        if log.get("address") != self._address or not topics:
            return None
        event = self._events.get(bytes(topics[0]))
        if event is None:
            return None
        try:
            data = event().process_log(log)
        except (Web3Exception, ValueError):
            return None
        return ChainEvent(
            name=data["event"],
            block_number=data["blockNumber"],
            tx_hash=data["transactionHash"].to_0x_hex(),
            log_index=data["logIndex"],
            args=MappingProxyType({key: _plain(value) for key, value in data["args"].items()}),
        )

    def decode_all(self, logs: Iterable[Mapping[str, Any]]) -> tuple[ChainEvent, ...]:
        decoded = (self.decode(log) for log in logs)
        return tuple(event for event in decoded if event is not None)


class EventLog:
    """All events of the contract from its deploy block on. Thread-safe, so a GUI
    worker can refresh it while another thread reads `events`."""

    def __init__(self, client: ChainClient, *, chunk_blocks: int = DEFAULT_CHUNK_BLOCKS) -> None:
        if chunk_blocks < 1:
            raise ValueError("chunk_blocks must be at least 1")
        self._client = client
        self._chunk_blocks = chunk_blocks
        self._next_block = client.deploy_block
        self._events: tuple[ChainEvent, ...] = ()
        self._lock = threading.Lock()

    @property
    def events(self) -> tuple[ChainEvent, ...]:
        return self._events

    def refresh(self) -> tuple[ChainEvent, ...]:
        """Fetch events up to the latest block and return the new ones. Progress is
        kept per chunk, so a failed request does not lose what was already read."""
        with self._lock:
            latest = self._client.latest_block()
            found: tuple[ChainEvent, ...] = ()
            while self._next_block <= latest:
                end = min(self._next_block + self._chunk_blocks - 1, latest)
                chunk = self._client.get_events(self._next_block, end)
                self._events = (*self._events, *chunk)
                found = (*found, *chunk)
                self._next_block = end + 1
            return found

    def file_registrations(self, owner: str | None = None) -> tuple[ChainEvent, ...]:
        wanted = None if owner is None else normalize_address(owner)
        return tuple(
            event
            for event in self._events
            if event.name == "FileRegistered" and (wanted is None or event.args["owner"] == wanted)
        )

    def requesters(self, file_id: bytes) -> tuple[str, ...]:
        """Everyone who ever requested `file_id`, in order of their first request."""
        found = (e.account for e in self._events if e.name == "AccessRequested" and e.file_id == file_id)
        return tuple(dict.fromkeys(found))

    def requested_files(self, requester: str) -> tuple[bytes, ...]:
        """Every file `requester` ever asked for, in order of the first request."""
        wanted = normalize_address(requester)
        found = (e.file_id for e in self._events if e.name == "AccessRequested" and e.account == wanted)
        return tuple(dict.fromkeys(found))


def write_csv(events: Iterable[ChainEvent], path: Path) -> None:
    """Export for the report's evidence appendix. Cells that a spreadsheet would
    run as a formula (public labels are attacker-chosen) are prefixed with a quote."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for event in events:
            writer.writerow(
                _csv_safe(str(cell))
                for cell in (
                    event.block_number,
                    event.tx_hash,
                    event.log_index,
                    event.name,
                    "0x" + event.file_id.hex() if event.file_id else "",
                    event.account or "",
                    event.label,
                    event.details(),
                )
            )


def _plain(value: Any) -> Any:
    """HexBytes -> bytes, so events compare equal to values computed locally."""
    return bytes(value) if isinstance(value, (bytes, bytearray)) else value


def _csv_safe(cell: str) -> str:
    return "'" + cell if cell.startswith(_CSV_FORMULA_PREFIXES) else cell
