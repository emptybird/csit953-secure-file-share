"""Security demo, shown only with SFS_DEMO=1 or --demo (DESIGN.md 8, 10.2).

Two attacks for the live demonstration:

    A1 storage   flip a ciphertext byte, edit the signed manifest or delete the
                 object, then Retrieve and verify shows which check catches it
                 (S6, S7, S9). The originals are kept as *.orig and put back by
                 "Restore originals".
    A2 user      call approveAccess on a file this account does not own (S1, S2).
                 By default gas estimation stops it before sending; "broadcast"
                 skips the estimate so the failed transaction is mined and can be
                 shown in the explorer (DESIGN.md 10.4, E6).
"""

from __future__ import annotations

import json
import os
import shutil
import tkinter as tk
from collections.abc import Callable, Sequence
from pathlib import Path

from app.chain import ContractRevertError, TransactionFailedError
from app.chain.client import SubmittedCallback, TxReceipt
from app.chain.events import ChainEvent
from app.crypto import EncodingError
from app.crypto.ecies import WRAPPED_KEY_LEN
from app.crypto.encoding import canonical_json, normalize_address, to_hex32
from app.gui.format import file_title, short_hex
from app.gui.host import Host
from app.gui.layout import ScrollArea
from app.gui.page import Page
from app.gui.theme import INK_2, INK_3, PAGE_PAD, RED, SUCCESS, SURFACE, px
from app.gui.widgets import Button, Checkbox, Field, Link, Select, hline, label, vline
from app.gui.worker import describe_error
from app.services import ServiceError
from app.services.models import FileSummary
from app.services.requester import RequesterService
from app.storage.object_store import LocalObjectStore

BROADCAST_GAS = 300_000
BACKUP_SUFFIX = ".orig"
COLUMN_WRAP = 400


class DemoPage(Page):
    key = "demo"

    def __init__(self, parent: tk.Misc, host: Host) -> None:
        super().__init__(
            parent,
            host,
            "Security demo",
            "Simulated attacks that show which control stops each one. For demonstration only.",
        )
        self._files: list[FileSummary] = []
        self._loading = False
        hline(self.content).pack(fill="x")
        scroll = ScrollArea(self.content, background=SURFACE)
        scroll.pack(fill="both", expand=True)
        body = scroll.body
        body.columnconfigure(0, weight=1, uniform="demo")
        body.columnconfigure(2, weight=1, uniform="demo")
        left = tk.Frame(body, background=SURFACE)
        left.grid(row=0, column=0, sticky="nsew", padx=(px(PAGE_PAD), px(28)), pady=px(26))
        vline(body).grid(row=0, column=1, sticky="ns", pady=px(26))
        right = tk.Frame(body, background=SURFACE)
        right.grid(row=0, column=2, sticky="nsew", padx=(px(28), px(PAGE_PAD)), pady=px(26))
        self._build_tamper(left)
        self._build_attack(right)
        self.reload()

    # ----------------------------------------------------------------- layout

    def _build_tamper(self, column: tk.Frame) -> None:
        label(column, "Tamper with storage", style="heading").pack(anchor="w")
        text = (
            "Storage is untrusted. Modify a stored object, then run Retrieve and verify on the file "
            "to see which check detects the change."
        )
        label(column, text, style="small", colour=INK_2, wrap=COLUMN_WRAP).pack(anchor="w", pady=(px(4), px(18)))
        label(column, "File", style="small_strong").pack(anchor="w", pady=(0, px(6)))
        self._tamper_file = Select(column, [], width=COLUMN_WRAP)
        self._tamper_file.pack(fill="x")
        actions = (
            ("Flip one bit of the ciphertext", "flip", "Expected: V1 fails; with forced decryption, V5 also fails."),
            ("Change the digest in the manifest", "manifest", "Expected: V2 and V4 fail."),
            ("Delete the ciphertext", "delete", "Expected: V1 fails because the object is missing."),
            ("Restore the originals", "restore", "Expected: all checks pass."),
        )
        for text, action, expect in actions:
            row = tk.Frame(column, background=SURFACE)
            row.pack(fill="x", pady=(px(12), 0))
            Button(row, text, lambda a=action: self._tamper(a), size="sm").pack(anchor="w")
            label(row, expect, style="small", colour=INK_3).pack(anchor="w", padx=(px(4), 0), pady=(px(3), 0))
        self._tamper_result = label(column, "", style="small", colour=INK_2, wrap=COLUMN_WRAP)
        self._tamper_result.pack(anchor="w", pady=(px(18), 0))
        self._verify_link = Link(column, "Open Retrieve and verify", self._open_verify)

    def _build_attack(self, column: tk.Frame) -> None:
        label(column, "Approve another owner's file", style="heading").pack(anchor="w")
        text = (
            "Approval rights are enforced by the contract, not by this client. "
            "Call approveAccess on a file owned by another account."
        )
        label(column, text, style="small", colour=INK_2, wrap=COLUMN_WRAP).pack(anchor="w", pady=(px(4), px(18)))
        label(column, "File owned by another account", style="small_strong").pack(anchor="w", pady=(0, px(6)))
        self._attack_file = Select(column, [], width=COLUMN_WRAP, on_change=lambda _v: self._fill_requesters())
        self._attack_file.pack(fill="x")
        label(column, "Requester to approve", style="small_strong").pack(anchor="w", pady=(px(16), px(6)))
        self._requester = Field(column, width=COLUMN_WRAP, mono=True)
        self._requester.pack(fill="x")
        hint = "Your own address tests self-approval (S2); any other address tests S1."
        label(column, hint, style="small", colour=INK_3, wrap=COLUMN_WRAP).pack(anchor="w", pady=(px(6), 0))
        self._broadcast = Checkbox(column, "Broadcast anyway so the reverted transaction is mined (uses gas)")
        self._broadcast.pack(anchor="w", pady=(px(16), 0))
        self._attack_button = Button(column, "Call approveAccess", self._attack, kind="danger")
        self._attack_button.pack(anchor="w", pady=(px(18), 0))
        self._attack_result = label(column, "", style="small", colour=INK_2, wrap=COLUMN_WRAP)
        self._attack_result.pack(anchor="w", pady=(px(16), 0))

    # -------------------------------------------------------------- loading

    def reload(self) -> None:
        if self._loading:
            return
        self._loading = True
        service = RequesterService(self.host.session)
        self.host.worker.submit(service.catalogue, self._loaded, self._load_failed, owner=self, name="demo-files")

    def wants(self, events: Sequence[ChainEvent]) -> bool:
        return any(e.name in ("FileRegistered", "AccessRequested") for e in events)

    def on_busy_changed(self) -> None:
        self._attack_button.set_enabled(not self.host.tx_in_flight)

    def _loaded(self, files: tuple[FileSummary, ...]) -> None:
        self._loading = False
        self._files = list(reversed(files))
        self._tamper_file.set_options([(to_hex32(f.file_id), _describe(f)) for f in self._files])
        others = [f for f in self._files if not f.is_mine]
        self._attack_file.set_options([(to_hex32(f.file_id), _describe(f)) for f in others])
        self._fill_requesters()

    def _load_failed(self, exc: BaseException) -> None:
        self._loading = False
        self._tamper_result.configure(text=describe_error(exc), foreground=RED)

    def _fill_requesters(self) -> None:
        if not self._requester.get():
            self._requester.set(self.host.session.address)

    def _file(self, select: Select) -> FileSummary | None:
        return next((f for f in self._files if to_hex32(f.file_id) == select.get()), None)

    # --------------------------------------------------------------- tamper

    def _tamper(self, action: str) -> None:
        summary = self._file(self._tamper_file)
        if summary is None:
            self._tamper_result.configure(text="Select a file first.", foreground=INK_2)
            return
        session = self.host.session

        def job() -> str:
            store = session.store
            if not isinstance(store, LocalObjectStore):
                raise ServiceError("Tampering requires the local directory store.")
            record = session.chain.get_file(summary.file_id)
            obj = store.object_path(record.ct_hash.hex())
            manifest = store.manifest_path(to_hex32(summary.file_id))
            return _TAMPER[action](store.root, obj, manifest)

        def done(text: str) -> None:
            self._tamper_result.configure(text=text, foreground=INK_2)
            self._verify_link.pack(anchor="w", pady=(px(8), 0))

        self.host.worker.submit(
            job, done, lambda exc: self._tamper_result.configure(text=_error_text(exc), foreground=RED), owner=self
        )

    def _open_verify(self) -> None:
        summary = self._file(self._tamper_file)
        if summary is not None:
            self.host.navigate("verify", file_id=summary.file_id)

    # --------------------------------------------------------------- attack

    def _attack(self) -> None:
        summary = self._file(self._attack_file)
        if summary is None:
            self._attack_result.configure(text="Register a file from another account first.", foreground=INK_2)
            return
        try:
            requester = normalize_address(self._requester.get().strip())
        except EncodingError as exc:
            self._attack_result.configure(text=f"Requester: {exc}", foreground=RED)
            return
        session, broadcast = self.host.session, self._broadcast.get()
        wrapped_key = os.urandom(WRAPPED_KEY_LEN)  # any 93 bytes: the caller is rejected first

        def job(on_submitted: SubmittedCallback) -> TxReceipt:
            if broadcast:
                return session.chain.transact(
                    session.account(),
                    "approveAccess",
                    summary.file_id,
                    requester,
                    wrapped_key,
                    gas_limit=BROADCAST_GAS,
                    on_submitted=on_submitted,
                )
            return session.chain.approve_access(
                session.account(), summary.file_id, requester, wrapped_key, on_submitted=on_submitted
            )

        self._attack_result.configure(text="Calling approveAccess…", foreground=INK_2)
        self.host.run_transaction("Unauthorized approveAccess", job, self._accepted, self._blocked)

    def _accepted(self, receipt: TxReceipt) -> None:
        self._attack_result.configure(
            text=f"The contract accepted the call ({receipt.tx_hash}). Access control has failed.", foreground=RED
        )

    def _blocked(self, exc: BaseException) -> None:
        if isinstance(exc, TransactionFailedError):
            reason = f" {exc.revert}." if exc.revert else ""
            text = (
                f"Blocked. The transaction was mined and reverted.{reason} "
                f"Transaction {short_hex(exc.tx_hash, 8, 6)}."
            )
            self._attack_result.configure(text=text, foreground=SUCCESS)
        elif isinstance(exc, ContractRevertError):
            text = f"Blocked before broadcast: {exc.error_name}. {exc}."
            self._attack_result.configure(text=text, foreground=SUCCESS)
        else:
            self._attack_result.configure(text=describe_error(exc), foreground=RED)


# ------------------------------------------------------------ tamper actions


def _flip_byte(root: Path, obj: Path, _manifest: Path) -> str:
    _backup(obj)
    data = bytearray(obj.read_bytes())
    index = len(data) // 2
    before = data[index]
    data[index] ^= 0x01
    obj.write_bytes(bytes(data))
    return (
        f"Flipped one bit of byte {index:,} in {obj.relative_to(root)} (0x{before:02x} to 0x{data[index]:02x}). "
        "Expected: V1 fails; with forced decryption, V5 (GCM tag) also fails."
    )


def _edit_manifest(root: Path, _obj: Path, manifest: Path) -> str:
    _backup(manifest)
    value = json.loads(manifest.read_bytes())
    digest = value["manifest"]["ptDigest"]
    value["manifest"]["ptDigest"] = ("1" if digest[0] == "0" else "0") + digest[1:]
    manifest.write_bytes(canonical_json(value))
    return (
        f"Changed the first digit of ptDigest in {manifest.relative_to(root)} without re-signing. "
        "Expected: V2 (hash differs from the chain) and V4 (signature mismatch) fail; "
        "with forced decryption, V6 also fails."
    )


def _delete_object(root: Path, obj: Path, _manifest: Path) -> str:
    _backup(obj)
    obj.unlink(missing_ok=True)
    return (
        f"Deleted {obj.relative_to(root)}. Expected: V1 fails because the object is missing. "
        "Storage can delete data; the client detects the loss but cannot prevent it."
    )


def _restore(root: Path, obj: Path, manifest: Path) -> str:
    restored = []
    for path in (obj, manifest):
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        if backup.exists():
            os.replace(backup, path)
            restored.append(str(path.relative_to(root)))
    if not restored:
        return "Nothing to restore. This file is unchanged."
    return "Restored " + " and ".join(restored) + ". All checks should pass."


def _backup(path: Path) -> None:
    """Keep the first original next to the file, so several edits still restore cleanly."""
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    if path.exists() and not backup.exists():
        shutil.copy2(path, backup)


_TAMPER: dict[str, Callable[[Path, Path, Path], str]] = {
    "flip": _flip_byte,
    "manifest": _edit_manifest,
    "delete": _delete_object,
    "restore": _restore,
}


def _describe(summary: FileSummary) -> str:
    owner = "you" if summary.is_mine else short_hex(summary.owner)
    return f"{file_title(summary.name, summary.label)} ({short_hex(summary.file_id)}, owner {owner})"


def _error_text(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or str(exc)
    return describe_error(exc)
