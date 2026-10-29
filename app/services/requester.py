"""Requester workflow.

Browse files (discovered through FileRegistered events, state read from views),
request access and, once approved, retrieve and verify. Every check compares what
storage returned with what the chain says; nothing storage says about itself is
trusted. Owners retrieve their own files the same way, with ownerWrappedKey.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from app.chain import RequestStatus
from app.chain.client import FileRecord, SubmittedCallback, TxReceipt
from app.chain.errors import short_hex
from app.crypto.encoding import to_hex32
from app.services import AccessDeniedError, ServiceError
from app.services.account import AccountService, Session
from app.services.models import FileSummary, KeyGrant, RetrievedFile
from app.services.owner import original_name
from app.services.verification import Anchor, Fetched, verify_and_decrypt
from app.storage import StorageError

MAX_NAME_ATTEMPTS = 100
# Not allowed in Windows file names; ':' would even open an NTFS alternate data stream.
_UNSAFE_NAME_CHARS = str.maketrans({ch: "_" for ch in '<>:"|?*'})


class RequesterService:
    """Browse files, request access, retrieve and verify."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # -------------------------------------------------------------- browse

    def catalogue(self) -> tuple[FileSummary, ...]:
        """Every registered file with the caller's request status, oldest first."""
        session = self._session
        session.events.refresh()
        return tuple(self._summary(e.file_id, e.label) for e in session.events.file_registrations())

    def my_requests(self) -> tuple[FileSummary, ...]:
        """Files the caller has requested, with each request's current status."""
        session = self._session
        session.events.refresh()
        labels = {e.file_id: e.label for e in session.events.file_registrations()}
        return tuple(
            self._summary(file_id, labels.get(file_id, ""))
            for file_id in session.events.requested_files(session.address)
        )

    def file(self, file_id: bytes) -> FileSummary:
        """Look up one file by id, e.g. from the search box."""
        session = self._session
        session.events.refresh()
        label = next((e.label for e in session.events.file_registrations() if e.file_id == file_id), "")
        return self._summary(file_id, label)

    def _summary(self, file_id: bytes, label: str) -> FileSummary:
        chain, me = self._session.chain, self._session.address
        record = chain.get_file(file_id)
        mine = record.owner == me
        status = RequestStatus.NONE if mine else chain.get_request(file_id, me).status
        return FileSummary.from_chain(label, record, status, is_mine=mine, name=original_name(self._session, record))

    # ------------------------------------------------------------- request

    def request_access(self, file_id: bytes, *, on_submitted: SubmittedCallback | None = None) -> TxReceipt:
        """The owner wraps the DEK to the caller's on-chain encPubKey, so that key must
        match this keystore. The contract checks the rest (owner, active, status)."""
        session = self._session
        AccountService(session).require_registered()
        return session.chain.request_access(session.account(), file_id, on_submitted=on_submitted)

    # ----------------------------------------------------------- key grant

    def key_grant(self, file_id: bytes) -> KeyGrant:
        """The wrapped DEK the contract stores for the caller, and since when. Owners
        get their own copy; anyone else gets AccessDeniedError unless Approved."""
        session = self._session
        record = session.chain.get_file(file_id)
        if record.owner == session.address:
            return KeyGrant(
                file_id=file_id,
                recipient=session.address,
                status=RequestStatus.NONE,
                updated_at=record.registered_at,
                is_owner_copy=True,
                wrapped_key=record.owner_wrapped_key,
            )
        request = session.chain.get_request(file_id, session.address)
        if request.status is not RequestStatus.APPROVED or not request.wrapped_key:
            raise _access_denied(file_id, request.status)
        return KeyGrant(
            file_id=file_id,
            recipient=session.address,
            status=request.status,
            updated_at=request.updated_at,
            is_owner_copy=False,
            wrapped_key=request.wrapped_key,
        )

    # ------------------------------------------------------------ retrieve

    def retrieve(self, file_id: bytes, *, force_decrypt: bool = False) -> RetrievedFile:
        """Download, run V1-V6 and decrypt. Raises AccessDeniedError unless Approved
        (or the caller owns the file); check failures are reported, not raised."""
        session = self._session
        record = session.chain.get_file(file_id)
        wrapped_key = self._my_wrapped_key(record)
        # Everything the checks compare against comes from the chain.
        owner_keys = session.chain.get_user_keys(record.owner)
        anchor = Anchor(
            context=session.file_context(file_id, record.owner),
            ct_hash=record.ct_hash,
            manifest_hash=record.manifest_hash,
            owner_sig_key=owner_keys.sig_public_key,
        )
        retrieved = verify_and_decrypt(
            anchor,
            _fetch(lambda: session.store.get_object(record.ct_hash.hex())),
            _fetch(lambda: session.store.get_manifest(to_hex32(file_id))),
            wrapped_key=wrapped_key,
            enc_key=session.keys.enc_key,
            recipient=session.address,
            force_decrypt=force_decrypt,
        )
        if retrieved.plaintext is not None:  # set only when every check passed
            session.names[file_id] = retrieved.plaintext.header.name
        return retrieved

    def _my_wrapped_key(self, record: FileRecord) -> bytes:
        """The owner's copy for own files, otherwise the approved request's key."""
        me = self._session.address
        if record.owner == me:
            return record.owner_wrapped_key
        request = self._session.chain.get_request(record.file_id, me)
        if request.status is not RequestStatus.APPROVED or not request.wrapped_key:
            raise _access_denied(record.file_id, request.status)
        return request.wrapped_key


def save_plaintext(retrieved: RetrievedFile, directory: Path) -> Path:
    """Write a verified file under its original name in `directory`. Never overwrites:
    "report.pdf" becomes "report (1).pdf" if the name is taken."""
    if not retrieved.ok or retrieved.plaintext is None:
        raise ServiceError("Only a file that passed every check can be saved")
    name = Path(retrieved.plaintext.header.name.translate(_UNSAFE_NAME_CHARS))
    for attempt in range(MAX_NAME_ATTEMPTS):
        candidate = directory / (name.name if attempt == 0 else f"{name.stem} ({attempt}){name.suffix}")
        try:
            handle = candidate.open("xb")  # exclusive create: no check-then-write race
        except FileExistsError:
            continue
        except OSError as exc:
            raise ServiceError(f"Cannot save to {directory}: {exc.strerror or exc}") from exc
        try:
            with handle:
                handle.write(retrieved.plaintext.content)
        except OSError as exc:
            candidate.unlink(missing_ok=True)
            raise ServiceError(f"Cannot save {candidate.name}: {exc.strerror or exc}") from exc
        return candidate
    raise ServiceError(f"Too many files named {name.name} in {directory}")


def _access_denied(file_id: bytes, status: RequestStatus) -> AccessDeniedError:
    return AccessDeniedError(
        f"Your access to file {short_hex(file_id)} is {status.label}; only an approved request carries a file key"
    )


def _fetch(read: Callable[[], bytes]) -> Fetched:
    """Storage failures become failed checks, not exceptions: a deleted object is a
    finding to report, not a crash."""
    try:
        return Fetched(data=read())
    except StorageError as exc:
        return Fetched(error=str(exc))
