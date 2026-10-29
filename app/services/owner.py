"""Owner workflow.

Protect & Register:
    salt, fileId = keccak256(owner, salt)  ->  DEK  ->  AES-256-GCM encrypt
    ->  sign manifest with K_sig  ->  wrap DEK for the owner (ownerWrappedKey)
    ->  upload object + signed manifest  ->  registerFile(salt, ctHash, manifestHash, ownerWrappedKey, label)

Approve:
    the requester's encPubKey is read from the chain, never from the requester,
    and shown as a fingerprint for confirmation. The DEK is recovered from the
    owner's own wrapped copy on-chain, so no DEK is ever stored locally.

File names:
    the original name exists only inside the encrypted object. The owner's
    client recovers it with its own wrapped copy of the DEK and caches it in
    memory for the session.
"""

from __future__ import annotations

import mimetypes
import os
from dataclasses import dataclass
from pathlib import Path

from app.chain import RequestStatus
from app.chain.client import FileRecord, SubmittedCallback, TxReceipt
from app.chain.errors import short_hex
from app.crypto import CryptoError, EncodingError, KeyUnwrapError, aead, ecies, signing
from app.crypto.encoding import (
    HASH_LEN,
    FileContext,
    compute_file_id,
    fingerprint,
    load_public_key,
    sha256,
    to_hex32,
)
from app.services import KeysNotRegisteredError, NotFileOwnerError, ServiceError, StaleApprovalError
from app.services.account import AccountService, Session
from app.services.models import (
    AccessRequest,
    ApprovalPreview,
    FileSummary,
    ProgressCallback,
    ProtectedFile,
    ProtectStage,
)
from app.storage import StorageError
from app.storage.object_store import MAX_OBJECT_BYTES

MAX_LABEL_BYTES = 128  # must match SecureFileShare.MAX_LABEL_LEN
MAX_FILE_BYTES = MAX_OBJECT_BYTES - 8 * 1024  # room for magic, nonce, header and tag


@dataclass(frozen=True)
class _Sealed:
    """A file encrypted and signed locally, ready to upload and register."""

    salt: bytes
    ctx: FileContext
    encrypted: aead.EncryptedFile
    signed: signing.SignedManifest
    own_wrapped_key: bytes


class OwnerService:
    """Protect files, list them, decide on access requests."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------ protect

    def protect_file(
        self, path: Path, label: str = "", *, on_progress: ProgressCallback | None = None
    ) -> ProtectedFile:
        """Encrypt, sign, upload and register one file; the caller becomes its owner.
        `label` is public (it goes into an event), so it defaults to empty."""
        _check_label(label)
        AccountService(self._session).require_registered()
        content = _read_file(path)
        report = on_progress or _ignore_progress

        sealed = self._seal(path, content, report)
        # Upload before registering: an on-chain record must never point at a missing object.
        store = self._session.store
        store.put_object(sealed.encrypted.object_bytes)
        store.put_manifest(to_hex32(sealed.ctx.file_id), sealed.signed.to_bytes())
        report(ProtectStage.UPLOADED, f"ctHash {sealed.encrypted.ct_hash.hex()[:16]}…")

        receipt = self._register(sealed, label, report)
        self._session.names[sealed.ctx.file_id] = path.name
        return ProtectedFile(
            file_id=sealed.ctx.file_id,
            name=path.name,
            size=len(content),
            ct_hash=sealed.encrypted.ct_hash,
            ct_size=sealed.encrypted.ct_size,
            manifest_hash=sealed.signed.manifest.digest(),
            label=label,
            receipt=receipt,
        )

    def _seal(self, path: Path, content: bytes, report: ProgressCallback) -> _Sealed:
        """All local work, before anything leaves this machine. The DEK lives only
        inside this function and in ownerWrappedKey."""
        keys = self._session.keys
        salt = os.urandom(HASH_LEN)
        ctx = self._session.file_context(compute_file_id(keys.address, salt), keys.address)
        dek = aead.generate_dek()
        try:
            encrypted = aead.encrypt_file(dek, ctx, name=path.name, content=content, mime=_guess_mime(path))
        except EncodingError as exc:
            raise ServiceError(f"Cannot protect {path.name}: {exc}") from exc
        report(ProtectStage.ENCRYPTED, f"AES-256-GCM, {encrypted.ct_size:,} bytes")

        signed = signing.sign_manifest(keys.sig_key, signing.build_manifest(ctx, encrypted))
        report(ProtectStage.SIGNED, f"manifest {signed.manifest.digest().hex()[:16]}…")
        own_wrapped_key = ecies.wrap_key(dek, keys.enc_public_key, ctx, keys.address)
        return _Sealed(salt=salt, ctx=ctx, encrypted=encrypted, signed=signed, own_wrapped_key=own_wrapped_key)

    def _register(self, sealed: _Sealed, label: str, report: ProgressCallback) -> TxReceipt:
        """registerFile, then confirm the contract derived the same fileId."""
        session = self._session
        receipt = session.chain.register_file(
            session.account(),
            sealed.salt,
            sealed.encrypted.ct_hash,
            sealed.signed.manifest.digest(),
            sealed.own_wrapped_key,
            label,
            on_submitted=lambda tx_hash: report(ProtectStage.SUBMITTED, tx_hash),
        )
        registered = receipt.event("FileRegistered")
        if registered is None or registered.file_id != sealed.ctx.file_id:
            raise ServiceError("The contract derived a different fileId than this client; the ciphertext is unusable")
        report(ProtectStage.CONFIRMED, f"block {receipt.block_number}, gas {receipt.gas_used:,}")
        return receipt

    # -------------------------------------------------------------- lists

    def my_files(self) -> tuple[FileSummary, ...]:
        """Files the current user registered, with their current on-chain state."""
        session = self._session
        session.events.refresh()
        summaries = []
        for event in session.events.file_registrations(owner=session.address):
            record = session.chain.get_file(event.file_id)
            name = original_name(session, record)
            summaries.append(FileSummary.from_chain(event.label, record, RequestStatus.NONE, is_mine=True, name=name))
        return tuple(summaries)

    def requests_for(self, file_id: bytes) -> tuple[AccessRequest, ...]:
        """Everyone who ever asked for `file_id`, with the current on-chain status."""
        session = self._session
        session.events.refresh()
        return tuple(self._access_request(file_id, requester) for requester in session.events.requesters(file_id))

    def _access_request(self, file_id: bytes, requester: str) -> AccessRequest:
        chain = self._session.chain
        request = chain.get_request(file_id, requester)
        keys = chain.get_user_keys(requester)
        return AccessRequest(
            file_id=file_id,
            requester=requester,
            status=request.status,
            updated_at=request.updated_at,
            enc_fingerprint=fingerprint(keys.enc_public_key) if keys.is_registered else "",
        )

    # ----------------------------------------------------------- decisions

    def prepare_approval(self, file_id: bytes, requester: str) -> ApprovalPreview:
        """Everything the owner must confirm before approving. Fails early, before any
        key material is touched, if the request is not Pending."""
        session = self._session
        record = self._owned_file(file_id)
        if not record.active:
            raise ServiceError(f"File {short_hex(file_id)} is deactivated; new approvals are not possible")
        status = session.chain.get_request(file_id, requester).status
        if status is not RequestStatus.PENDING:
            raise StaleApprovalError(f"The request is {status.label}, not Pending")
        enc_public_key = self._requester_enc_key(requester)
        session.events.refresh()
        label = next((e.label for e in session.events.file_registrations(session.address) if e.file_id == file_id), "")
        return ApprovalPreview(
            file_id=file_id,
            label=label,
            requester=requester,
            enc_public_key=enc_public_key,
            name=original_name(session, record),
        )

    def approve(self, preview: ApprovalPreview, *, on_submitted: SubmittedCallback | None = None) -> TxReceipt:
        """Wrap the DEK for the key the owner confirmed and call approveAccess."""
        session, keys = self._session, self._session.keys
        record = self._owned_file(preview.file_id)
        # The key on-chain must still be the one the owner confirmed.
        if self._requester_enc_key(preview.requester) != preview.enc_public_key:
            raise StaleApprovalError("The requester's encryption key changed after you reviewed it; review it again")

        # Recover the DEK from the owner's on-chain copy, then rewrap it for the requester.
        ctx = session.file_context(preview.file_id, keys.address)
        try:
            dek = ecies.unwrap_key(record.owner_wrapped_key, keys.enc_key, ctx, keys.address)
        except KeyUnwrapError as exc:
            raise ServiceError(f"Cannot recover the file key with this keystore: {exc}") from exc
        wrapped_key = ecies.wrap_key(dek, preview.enc_public_key, ctx, preview.requester)
        return session.chain.approve_access(
            session.account(), preview.file_id, preview.requester, wrapped_key, on_submitted=on_submitted
        )

    def reject(self, file_id: bytes, requester: str, *, on_submitted: SubmittedCallback | None = None) -> TxReceipt:
        session = self._session
        return session.chain.reject_access(session.account(), file_id, requester, on_submitted=on_submitted)

    def revoke(self, file_id: bytes, requester: str, *, on_submitted: SubmittedCallback | None = None) -> TxReceipt:
        """Delete the stored wrapped key. Not retroactive: a DEK the requester already
        recovered stays valid, and the approve calldata stays on-chain."""
        session = self._session
        return session.chain.revoke_access(session.account(), file_id, requester, on_submitted=on_submitted)

    def deactivate(self, file_id: bytes, *, on_submitted: SubmittedCallback | None = None) -> TxReceipt:
        session = self._session
        return session.chain.deactivate_file(session.account(), file_id, on_submitted=on_submitted)

    # ------------------------------------------------------------ helpers

    def _owned_file(self, file_id: bytes) -> FileRecord:
        record = self._session.chain.get_file(file_id)
        if record.owner != self._session.address:
            raise NotFileOwnerError(f"You are not the owner of file {short_hex(file_id)}")
        return record

    def _requester_enc_key(self, requester: str) -> bytes:
        registered = self._session.chain.get_user_keys(requester)
        if not registered.is_registered:
            raise KeysNotRegisteredError(f"{requester} has no public keys on-chain")
        try:
            # The contract checks only the encoding; an off-curve point is rejected here.
            load_public_key(registered.enc_public_key)
        except CryptoError as exc:
            raise ServiceError(f"The encryption key registered by {requester} is invalid: {exc}") from exc
        return registered.enc_public_key


def original_name(session: Session, record: FileRecord) -> str:
    """Original file name if this session can know it, else "".

    Own files: decrypted from storage with the owner's wrapped DEK, once per
    session; unknown while the stored object is missing or modified. Other files:
    known only after a fully verified retrieve in this session."""
    if record.file_id in session.names:
        return session.names[record.file_id]
    if record.owner != session.address:
        return ""
    name = _read_own_name(session, record)
    if name:
        session.names[record.file_id] = name
    return name


def _read_own_name(session: Session, record: FileRecord) -> str:
    keys = session.keys
    ctx = session.file_context(record.file_id, record.owner)
    try:
        data = session.store.get_object(record.ct_hash.hex())
        if sha256(data) != record.ct_hash:  # same as V1: never decrypt a changed object
            return ""
        dek = ecies.unwrap_key(record.owner_wrapped_key, keys.enc_key, ctx, keys.address)
        return aead.decrypt_file(dek, ctx, data).header.name
    except (CryptoError, StorageError):
        return ""


def _read_file(path: Path) -> bytes:
    """Read at most MAX_FILE_BYTES; anything larger is refused."""
    try:
        with path.open("rb") as handle:
            content = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ServiceError(f"Cannot read {path.name}: {exc.strerror or exc}") from exc
    if len(content) > MAX_FILE_BYTES:
        raise ServiceError(f"{path.name} is larger than {MAX_FILE_BYTES:,} bytes, the supported maximum")
    return content


def _check_label(label: str) -> None:
    if not isinstance(label, str) or len(label.encode("utf-8")) > MAX_LABEL_BYTES:
        raise ServiceError(f"The public label must be at most {MAX_LABEL_BYTES} bytes")


def _guess_mime(path: Path) -> str:
    guessed, _ = mimetypes.guess_type(path.name)
    return guessed or aead.DEFAULT_MIME


def _ignore_progress(stage: ProtectStage, detail: str) -> None:
    del stage, detail
