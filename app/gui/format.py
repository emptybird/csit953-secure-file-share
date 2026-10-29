"""Text shown in the GUI: short ids, balances, times and status names.

Pure functions without Tk, so they are unit-tested directly. Nothing here ever
formats a private key or a DEK; the most the GUI shows of a key is its
fingerprint (first 8 bytes of SHA-256).
"""

from __future__ import annotations

import re
import time
from decimal import Decimal

from app.chain import RequestStatus
from app.crypto.encoding import to_hex32

WEI_PER_ETH = Decimal(10) ** 18
LOW_BALANCE_WEI = 10**16  # 0.01 ETH: a handful of transactions on Sepolia
NO_LABEL = "Unlabelled file"  # no public label, and the name is encrypted

_FILE_ID = re.compile(r"(?:0x)?([0-9a-fA-F]{64})")
_UNITS = ("bytes", "KB", "MB", "GB")

# status: badge text, badge tone (see widgets.TONES)
_STATUS_BADGE = {
    RequestStatus.NONE: ("Not requested", "slate"),
    RequestStatus.PENDING: ("Pending", "amber"),
    RequestStatus.APPROVED: ("Approved", "success"),
    RequestStatus.REJECTED: ("Rejected", "red"),
    RequestStatus.REVOKED: ("Revoked", "slate"),
}

# contract event: title in the activity list, dot tone
_EVENTS = {
    "KeysRegistered": ("Keys registered", "slate"),
    "FileRegistered": ("File registered", "accent"),
    "AccessRequested": ("Access requested", "amber"),
    "AccessApproved": ("Access approved", "success"),
    "AccessRejected": ("Access rejected", "red"),
    "AccessRevoked": ("Access revoked", "slate"),
    "FileDeactivated": ("File deactivated", "slate"),
}


def short_hex(text_or_bytes: str | bytes, head: int = 6, tail: int = 4) -> str:
    """0x7c41a2…9e41: enough to recognise an address, fileId or hash in a list."""
    text = "0x" + text_or_bytes.hex() if isinstance(text_or_bytes, bytes) else text_or_bytes
    digits = text.removeprefix("0x")
    if len(digits) <= head + tail:
        return text
    return f"0x{digits[:head]}…{digits[-tail:]}"


def file_id_text(file_id: bytes) -> str:
    return to_hex32(file_id)


def parse_file_id(text: str) -> bytes | None:
    """A fileId typed or pasted by the user, with or without 0x; None if it is not one."""
    match = _FILE_ID.fullmatch(text.strip())
    return bytes.fromhex(match.group(1)) if match else None


def file_title(name: str, label: str) -> str:
    """Display name of a file: the original name when this session knows it (own or
    decrypted files), else the public label."""
    return name or label or NO_LABEL


def format_eth(wei: int, places: int = 4) -> str:
    amount = (Decimal(wei) / WEI_PER_ETH).quantize(Decimal(1).scaleb(-places))
    return f"{amount:,} ETH"


def is_low_balance(wei: int) -> bool:
    return wei < LOW_BALANCE_WEI


def format_time(timestamp: int) -> str:
    """Block timestamps in the viewer's local time; 0 means 'never'."""
    if timestamp <= 0:
        return "–"
    return time.strftime("%d %b %Y, %H:%M", time.localtime(timestamp))


def format_size(size: int) -> str:
    value = float(size)
    for unit in _UNITS:
        if value < 1024 or unit == _UNITS[-1]:
            return f"{size:,} bytes" if unit == "bytes" else f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def status_badge(status: RequestStatus) -> tuple[str, str]:
    """Badge text and tone for a request status."""
    return _STATUS_BADGE[status]


def pending_count(statuses: list[RequestStatus]) -> int:
    return statuses.count(RequestStatus.PENDING)


def event_title(name: str) -> str:
    return _EVENTS.get(name, (name, "slate"))[0]


def event_tone(name: str) -> str:
    return _EVENTS.get(name, (name, "slate"))[1]


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"
