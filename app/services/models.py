"""Result types returned by the services.

Frozen dataclasses the GUI renders as is, without calling crypto or chain code
itself. None holds a DEK or a private key; wrapped keys and plaintext stay out
of repr() so they never reach a log line.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from app.chain import RequestStatus
from app.chain.client import FileRecord, TxReceipt
from app.crypto.aead import DecryptedFile
from app.crypto.encoding import PUBLIC_KEY_LEN, fingerprint

# ------------------------------------------------------------------ account


class KeyStatus(Enum):
    """On-chain keys versus this keystore; values are display text."""

    NOT_REGISTERED = "Not registered"
    MATCHES = "Registered"
    MISMATCH = "Different keys registered on-chain"


@dataclass(frozen=True)
class AccountInfo:
    """Address, network, balance and key status of the logged-in user."""

    address: str
    network: str
    balance_wei: int
    key_status: KeyStatus
    sig_fingerprint: str
    enc_fingerprint: str


# -------------------------------------------------------------------- owner


class ProtectStage(Enum):
    """Steps of the Protect & Register wizard, reported as they finish."""

    ENCRYPTED = "Encrypted"
    SIGNED = "Signed"
    UPLOADED = "Uploaded"
    SUBMITTED = "Transaction sent"
    CONFIRMED = "Registered on-chain"


ProgressCallback = Callable[[ProtectStage, str], None]


@dataclass(frozen=True)
class ProtectedFile:
    """Result of a successful protect_file()."""

    file_id: bytes
    name: str
    size: int
    ct_hash: bytes
    ct_size: int
    manifest_hash: bytes
    label: str
    receipt: TxReceipt


@dataclass(frozen=True)
class AccessRequest:
    """One row of the owner's request table."""

    file_id: bytes
    requester: str
    status: RequestStatus
    updated_at: int
    enc_fingerprint: str


@dataclass(frozen=True)
class ApprovalPreview:
    """Shown before approveAccess, so the owner sees exactly which key the DEK
    will be wrapped to."""

    file_id: bytes
    label: str
    requester: str
    enc_public_key: bytes
    name: str = ""

    @property
    def enc_fingerprint(self) -> str:
        return fingerprint(self.enc_public_key)


# ---------------------------------------------------------------- catalogue


@dataclass(frozen=True)
class FileSummary:
    """One catalogue row. `label` is the public on-chain label; `name` is the original
    file name when this session knows it (own or decrypted files), else empty.
    `my_status` is NONE for the user's own files."""

    file_id: bytes
    owner: str
    label: str
    registered_at: int
    active: bool
    is_mine: bool
    my_status: RequestStatus
    name: str = ""

    @classmethod
    def from_chain(
        cls, label: str, record: FileRecord, my_status: RequestStatus, *, is_mine: bool, name: str = ""
    ) -> FileSummary:
        return cls(
            file_id=record.file_id,
            owner=record.owner,
            label=label,
            registered_at=record.registered_at,
            active=record.active,
            is_mine=is_mine,
            my_status=my_status,
            name=name,
        )

    @property
    def can_retrieve(self) -> bool:
        return self.is_mine or self.my_status is RequestStatus.APPROVED


# ------------------------------------------------------------ key grant


@dataclass(frozen=True)
class KeyGrant:
    """The wrapped DEK the contract holds for this user: the 93-byte ECIES
    wrappedKey from approveAccess, or the owner's own copy. Public on-chain;
    only the recipient's K_enc opens it."""

    file_id: bytes
    recipient: str
    status: RequestStatus
    updated_at: int
    is_owner_copy: bool
    wrapped_key: bytes = field(repr=False)

    @property
    def size(self) -> int:
        return len(self.wrapped_key)

    @property
    def ephemeral_fingerprint(self) -> str:
        """Fingerprint of E, the one-time public key the owner wrapped the DEK with."""
        return fingerprint(self.wrapped_key[:PUBLIC_KEY_LEN])


# ------------------------------------------------------------- verification


class Check(Enum):
    """Requester-side checks, in run order."""

    V1_CT_HASH = ("V1", "Ciphertext hash matches the on-chain ctHash")
    V2_MANIFEST_HASH = ("V2", "Manifest hash matches the on-chain manifestHash")
    V3_CONTEXT = ("V3", "Manifest names this chain, contract, file, owner and ciphertext")
    V4_SIGNATURE = ("V4", "Manifest signature verifies with the owner's on-chain key")
    UNWRAP = ("Key", "File key unwrapped with your encryption key")
    V5_DECRYPT = ("V5", "AES-256-GCM decryption and tag check")
    V6_PT_DIGEST = ("V6", "Decrypted content matches the signed plaintext digest")

    def __init__(self, code: str, description: str) -> None:
        self.code = code
        self.description = description


class Outcome(Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class CheckResult:
    check: Check
    outcome: Outcome
    detail: str

    @property
    def passed(self) -> bool:
        return self.outcome is Outcome.PASSED


@dataclass(frozen=True)
class VerificationReport:
    """Check results of one retrieval, in Check order."""

    file_id: bytes
    results: tuple[CheckResult, ...]

    @property
    def ok(self) -> bool:
        """True only if every check ran and passed."""
        return tuple(r.check for r in self.results) == tuple(Check) and all(r.passed for r in self.results)

    def result(self, check: Check) -> CheckResult:
        return next(r for r in self.results if r.check is check)

    @property
    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(r for r in self.results if r.outcome is Outcome.FAILED)


@dataclass(frozen=True)
class RetrievedFile:
    """`plaintext` is set only when the report is ok; nothing unverified is handed out."""

    report: VerificationReport
    plaintext: DecryptedFile | None = field(default=None, repr=False)

    @property
    def ok(self) -> bool:
        return self.report.ok and self.plaintext is not None
