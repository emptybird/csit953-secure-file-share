"""GUI text formatting and error messages; no display needed."""

from __future__ import annotations

import time

import pytest

from app.chain import ContractRevertError, RequestStatus
from app.chain.events import EVENT_NAMES
from app.config import ConfigError
from app.crypto import KeystoreError
from app.gui.format import (
    NO_LABEL,
    event_title,
    event_tone,
    file_id_text,
    file_title,
    format_eth,
    format_size,
    format_time,
    is_low_balance,
    parse_file_id,
    pending_count,
    plural,
    short_hex,
    status_badge,
)
from app.gui.worker import describe_error
from app.services import ServiceError
from app.storage import ObjectNotFoundError

FILE_ID = bytes.fromhex("7c" * 31 + "41")
TONES = {"accent", "success", "amber", "red", "slate"}


def test_short_hex_of_bytes_address_and_short_values() -> None:
    assert short_hex(FILE_ID) == "0x7c7c7c…7c41"
    assert short_hex("0x9187aDD5a0dC3F07eB45687218ED611b551cF6E3") == "0x9187aD…F6E3"
    assert short_hex("0x1234") == "0x1234"
    assert short_hex(FILE_ID, 10, 6) == "0x" + "7c" * 5 + "…" + "7c7c41"


def test_file_id_round_trip() -> None:
    text = file_id_text(FILE_ID)
    assert text == "0x" + FILE_ID.hex()
    assert parse_file_id(text) == FILE_ID
    assert parse_file_id("  " + FILE_ID.hex().upper() + " ") == FILE_ID


@pytest.mark.parametrize("text", ["", "0x1234", "0x" + "g" * 64, "0x" + "ab" * 33, "../../keystore"])
def test_parse_file_id_rejects_anything_else(text: str) -> None:
    assert parse_file_id(text) is None


def test_file_title_prefers_the_original_name() -> None:
    assert file_title("quarterly report.pdf", "Q3 report") == "quarterly report.pdf"
    assert file_title("", "Q3 report") == "Q3 report"
    assert file_title("", "") == NO_LABEL == "Unlabelled file"


def test_format_eth_is_exact() -> None:
    assert format_eth(0) == "0.0000 ETH"
    assert format_eth(10**18) == "1.0000 ETH"
    assert format_eth(1_234_567 * 10**18 + 5 * 10**13) == "1,234,567.0000 ETH"
    assert format_eth(123_456_789_000_000_000) == "0.1235 ETH"


def test_low_balance_threshold() -> None:
    assert is_low_balance(0)
    assert is_low_balance(10**16 - 1)
    assert not is_low_balance(10**16)


def test_format_time() -> None:
    assert format_time(0) == "–"
    stamp = 1_760_000_000
    assert format_time(stamp) == time.strftime("%d %b %Y, %H:%M", time.localtime(stamp))


@pytest.mark.parametrize(
    ("size", "text"),
    [(0, "0 bytes"), (1023, "1,023 bytes"), (1024, "1.0 KB"), (180_000, "175.8 KB"), (50 * 1024**2, "50.0 MB")],
)
def test_format_size(size: int, text: str) -> None:
    assert format_size(size) == text


def test_every_status_has_a_badge() -> None:
    badges = {status: status_badge(status) for status in RequestStatus}
    assert badges[RequestStatus.PENDING] == ("Pending", "amber")
    assert badges[RequestStatus.APPROVED] == ("Approved", "success")
    assert badges[RequestStatus.REJECTED] == ("Rejected", "red")
    assert {tone for _, tone in badges.values()} <= TONES


def test_pending_count() -> None:
    assert pending_count([]) == 0
    assert pending_count([RequestStatus.PENDING, RequestStatus.APPROVED, RequestStatus.PENDING]) == 2


def test_every_contract_event_has_a_title_and_tone() -> None:
    for name in EVENT_NAMES:
        assert event_title(name) != name
        assert event_tone(name) in TONES
    assert event_title("AccessApproved") == "Access approved"
    assert event_title("SomethingNew") == "SomethingNew"


def test_plural() -> None:
    assert plural(1, "check") == "1 check"
    assert plural(2, "check") == "2 checks"


@pytest.mark.parametrize(
    "exc",
    [
        ServiceError("Register your public keys first"),
        ContractRevertError("Only the owner of file 0x7c7c…7c41 can do this", "NotFileOwner"),
        ObjectNotFoundError("Encrypted object ab12… is missing from storage"),
        KeystoreError("Wrong password or corrupted keystore"),
        ConfigError("CONTRACT_ADDRESS is empty in .env.local"),
    ],
)
def test_user_errors_are_shown_as_written(exc: Exception) -> None:
    assert describe_error(exc) == str(exc)


def test_unexpected_errors_hide_their_message(caplog: pytest.LogCaptureFixture) -> None:
    message = describe_error(KeyError("internal detail"))
    assert "internal detail" not in message
    assert "KeyError" in message
    assert "internal detail" in caplog.text  # the traceback goes to the log instead
