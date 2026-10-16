from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from app.chain.events import CSV_COLUMNS, ChainEvent, EventLog, write_csv

ALICE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
FILE_A = bytes([0xA]) * 32
FILE_B = bytes([0xB]) * 32


def _event(name: str, block: int, **args: Any) -> ChainEvent:
    return ChainEvent(
        name=name, block_number=block, tx_hash=f"0x{block:064x}", log_index=0, args=MappingProxyType(args)
    )


def _registered(block: int, file_id: bytes, owner: str = ALICE, label: str = "") -> ChainEvent:
    args = {"fileId": file_id, "owner": owner, "ctHash": b"\x01" * 32, "manifestHash": b"\x02" * 32}
    return _event("FileRegistered", block, **args, publicLabel=label)


def _requested(block: int, file_id: bytes, requester: str) -> ChainEvent:
    return _event("AccessRequested", block, fileId=file_id, requester=requester)


@dataclass
class FakeClient:
    """Stands in for ChainClient: a list of events and a latest block number."""

    deploy_block: int
    latest: int
    all_events: list[ChainEvent]
    calls: list[tuple[int, int]] = field(default_factory=list)
    fail_from: int | None = None

    def latest_block(self) -> int:
        return self.latest

    def get_events(self, from_block: int, to_block: int) -> tuple[ChainEvent, ...]:
        if self.fail_from is not None and from_block >= self.fail_from:
            raise ConnectionError("node went away")
        self.calls.append((from_block, to_block))
        return tuple(e for e in self.all_events if from_block <= e.block_number <= to_block)


class TestChainEvent:
    def test_properties(self) -> None:
        event = _registered(5, FILE_A, label="Q3 report")
        assert event.file_id == FILE_A
        assert event.account == ALICE
        assert event.label == "Q3 report"
        assert event.details() == "ctHash " + "01" * 8 + "…"

    def test_requester_is_the_account(self) -> None:
        assert _requested(5, FILE_A, BOB).account == BOB

    def test_keys_registered_shows_fingerprints_only(self) -> None:
        sig, enc = b"\x02" + b"\x11" * 32, b"\x03" + b"\x22" * 32
        details = _event("KeysRegistered", 1, user=ALICE, sigPubKey=sig, encPubKey=enc).details()
        assert details.startswith("sigKey ")
        assert sig.hex() not in details

    def test_deactivated_has_no_account(self) -> None:
        assert _event("FileDeactivated", 1, fileId=FILE_A).account is None


class TestEventLog:
    def test_scans_in_chunks_from_the_deploy_block(self) -> None:
        client = FakeClient(deploy_block=10, latest=17, all_events=[_registered(9, FILE_B), _registered(12, FILE_A)])
        log = EventLog(client, chunk_blocks=3)  # type: ignore[arg-type]
        new = log.refresh()
        assert client.calls == [(10, 12), (13, 15), (16, 17)]
        assert [e.file_id for e in new] == [FILE_A]
        assert log.events == new

    def test_refresh_only_reads_new_blocks(self) -> None:
        client = FakeClient(deploy_block=0, latest=5, all_events=[_registered(3, FILE_A)])
        log = EventLog(client, chunk_blocks=100)  # type: ignore[arg-type]
        log.refresh()
        assert log.refresh() == ()
        client.latest = 8
        client.all_events.append(_requested(7, FILE_A, BOB))
        assert [e.name for e in log.refresh()] == ["AccessRequested"]
        assert client.calls == [(0, 5), (6, 8)]
        assert len(log.events) == 2

    def test_failure_keeps_finished_chunks(self) -> None:
        client = FakeClient(deploy_block=0, latest=9, all_events=[_registered(1, FILE_A), _registered(8, FILE_B)])
        log = EventLog(client, chunk_blocks=5)  # type: ignore[arg-type]
        client.fail_from = 5
        with pytest.raises(ConnectionError):
            log.refresh()
        assert [e.file_id for e in log.events] == [FILE_A]
        client.fail_from = None
        assert [e.file_id for e in log.refresh()] == [FILE_B]
        assert client.calls == [(0, 4), (5, 9)]

    def test_chunk_size_must_be_positive(self) -> None:
        with pytest.raises(ValueError):
            EventLog(FakeClient(0, 0, []), chunk_blocks=0)  # type: ignore[arg-type]

    def test_queries(self) -> None:
        events = [
            _registered(1, FILE_A, ALICE),
            _registered(2, FILE_B, BOB),
            _requested(3, FILE_A, BOB),
            _requested(4, FILE_B, ALICE),
            _event("AccessRejected", 5, fileId=FILE_A, requester=BOB),
            _requested(6, FILE_A, BOB),
        ]
        log = EventLog(FakeClient(0, 6, events))  # type: ignore[arg-type]
        log.refresh()
        assert [e.file_id for e in log.file_registrations()] == [FILE_A, FILE_B]
        assert [e.file_id for e in log.file_registrations(owner=ALICE.lower())] == [FILE_A]
        assert log.requesters(FILE_A) == (BOB,)
        assert log.requesters(FILE_B) == (ALICE,)
        assert log.requested_files(BOB) == (FILE_A,)


class TestCsv:
    def test_columns_and_rows(self, tmp_path: Path) -> None:
        path = tmp_path / "activity.csv"
        write_csv([_registered(1, FILE_A, label="ok"), _event("FileDeactivated", 2, fileId=FILE_A)], path)
        rows = list(csv.reader(path.open(encoding="utf-8")))
        assert tuple(rows[0]) == CSV_COLUMNS
        assert rows[1][3:7] == ["FileRegistered", "0x" + FILE_A.hex(), ALICE, "ok"]
        assert rows[2][5:7] == ["", ""]

    @pytest.mark.parametrize("label", ['=HYPERLINK("http://evil")', "+1", "-1", "@SUM(A1)"])
    def test_formula_labels_are_neutralised(self, tmp_path: Path, label: str) -> None:
        """Public labels are attacker-chosen; a spreadsheet must not run them as formulas."""
        path = tmp_path / "activity.csv"
        write_csv([_registered(1, FILE_A, label=label)], path)
        assert list(csv.reader(path.open(encoding="utf-8")))[1][6] == "'" + label
