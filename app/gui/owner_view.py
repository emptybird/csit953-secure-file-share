"""My files (DESIGN.md 8, owner): every file I registered and who asked for it.

Selecting a file shows its requests. Approve first opens a dialog with the
requester's encryption-key fingerprint as read from the chain, because that is
the key the file key will be encrypted to; reject, revoke and deactivate also
ask before sending a transaction.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Sequence

from app.chain import RequestStatus
from app.chain.client import TxReceipt
from app.chain.events import ChainEvent
from app.gui.dialogs import DialogField, confirm
from app.gui.format import file_id_text, format_time, label_text, pending_count, short_hex, status_badge
from app.gui.host import Host, Level
from app.gui.layout import ListRow, ListView, field_row, section_title
from app.gui.page import Page, clear, split
from app.gui.theme import INK, INK_2, INK_3, LINE, SURFACE, px
from app.gui.widgets import Badge, Button, Link, hline, label
from app.gui.worker import describe_error
from app.services.models import AccessRequest, ApprovalPreview, FileSummary
from app.services.owner import OwnerService

DETAIL_WRAP = 330
_HINTS = {
    RequestStatus.PENDING: "Approving encrypts the file key to this key.",
    RequestStatus.APPROVED: "Can download and decrypt the file.",
    RequestStatus.REJECTED: "Rejected. They can ask again.",
    RequestStatus.REVOKED: "Revoked. They can ask again.",
}

FileItem = tuple[FileSummary, tuple[AccessRequest, ...]]


class FilesPage(Page):
    key = "files"

    def __init__(self, parent: tk.Misc, host: Host) -> None:
        super().__init__(parent, host, "My files", "Files you encrypted and registered, and who has asked for them.")
        self._owner = OwnerService(host.session)
        self._items: dict[str, FileItem] = {}
        self._loading = self._reload_again = False
        self._wanted: str | None = None
        Button(self.actions, "Protect a file", lambda: host.navigate("protect"), kind="primary", icon="plus").pack(
            side="right"
        )
        Button(self.actions, "", self.reload, kind="quiet", icon="refresh").pack(side="right", padx=(0, px(6)))
        left, self._detail = split(self)
        self._list: ListView[FileItem] = ListView(
            left,
            build=_build_row,
            fill=_fill_row,
            on_select=lambda _key: self._show_detail(),
            empty=("files", "No files yet", "Protect a file to encrypt it, sign it and register it on-chain."),
        )
        self._list.empty.add_action("Protect a file", lambda: host.navigate("protect"), icon="plus")
        self._list.pack(fill="both", expand=True)
        self._show_detail()
        self.reload()

    # -------------------------------------------------------------- loading

    def reload(self) -> None:
        if self._loading:
            self._reload_again = True
            return
        self._loading = True

        def job() -> list[FileItem]:
            files = self._owner.my_files()
            return [(f, self._owner.requests_for(f.file_id)) for f in files]

        self.host.worker.submit(job, self._loaded, self._load_failed, owner=self, name="my-files")

    def wants(self, events: Sequence[ChainEvent]) -> bool:
        me = self.host.session.address
        mine = {summary.file_id for summary, _ in self._items.values()}
        return any((e.name == "FileRegistered" and e.args.get("owner") == me) or e.file_id in mine for e in events)

    def on_show(self, **options: object) -> None:
        file_id = options.get("file_id")
        if isinstance(file_id, bytes):
            self._wanted = file_id_text(file_id)
            if self._wanted in self._items:
                self._list.select(self._wanted)
                self._wanted = None
            else:
                self.reload()

    def _loaded(self, items: list[FileItem]) -> None:
        self._items = {file_id_text(summary.file_id): (summary, requests) for summary, requests in items}
        self._list.set_items([(key, self._items[key]) for key in reversed(list(self._items))])
        pending = sum(pending_count([r.status for r in requests]) for summary, requests in items if summary.active)
        self.host.set_badge(self.key, pending)
        if self._wanted in self._items:
            self._list.select(self._wanted)
            self._wanted = None
        elif self._list.selected is None and self._list.row_keys:
            self._list.select(self._list.row_keys[0])
        self._show_detail()
        self._loading = False
        if self._reload_again:
            self._reload_again = False
            self.reload()

    def _load_failed(self, exc: BaseException) -> None:
        self._loading = False
        self.host.notify(describe_error(exc), Level.ERROR, title="Could not load your files")

    def on_busy_changed(self) -> None:
        self._show_detail()

    # --------------------------------------------------------------- detail

    def _selected(self) -> FileItem | None:
        key = self._list.selected
        return self._items.get(key) if key else None

    def _show_detail(self) -> None:
        body = self._detail.body
        clear(body)
        item = self._selected()
        if item is None:
            text = "Select a file to see who asked for it." if self._items else ""
            label(body, text, style="small", colour=INK_3, wrap=DETAIL_WRAP).pack(anchor="w", padx=px(24), pady=px(28))
            return
        summary, requests = item
        idle = not self.host.tx_in_flight
        pane = tk.Frame(body, background=SURFACE)
        pane.pack(fill="both", expand=True, padx=px(24), pady=(px(22), px(24)))

        heading = tk.Frame(pane, background=SURFACE)
        heading.pack(fill="x")
        label(heading, label_text(summary.label), style="heading", wrap=DETAIL_WRAP - 90).pack(side="left")
        if not summary.active:
            Badge(heading, "Deactivated", "slate").pack(side="right")

        fields = tk.Frame(pane, background=SURFACE)
        fields.pack(fill="x", pady=(px(14), 0))
        file_id = file_id_text(summary.file_id)
        field_row(fields, 0, "File ID", mono=True, wrap=230).configure(text=file_id)
        Link(fields, "Copy file ID", lambda: self.host.copy_to_clipboard(file_id, "File ID")).grid(
            row=1, column=1, sticky="w", pady=(0, px(4))
        )
        field_row(fields, 2, "Registered").configure(text=format_time(summary.registered_at))

        hline(pane).pack(fill="x", pady=(px(18), px(16)))
        section_title(pane, "Access requests", count=str(len(requests)) if requests else "").pack(anchor="w")
        if not requests:
            text = "Nobody has asked yet. Share the file ID with the person who needs the file."
            label(pane, text, style="small", colour=INK_2, wrap=DETAIL_WRAP).pack(anchor="w", pady=(px(8), 0))
        for request in requests:
            self._request_block(pane, summary, request, idle)

        if summary.active:
            hline(pane).pack(fill="x", pady=(px(22), px(14)))
            danger = Button(
                pane, "Deactivate file", lambda: self._deactivate(summary), kind="danger_outline", size="sm"
            )
            danger.set_enabled(idle)
            danger.pack(anchor="w")
            note = "Stops new requests. People you already approved keep their access."
            label(pane, note, style="small", colour=INK_3, wrap=DETAIL_WRAP).pack(anchor="w", pady=(px(4), 0))

    def _request_block(self, pane: tk.Frame, summary: FileSummary, request: AccessRequest, idle: bool) -> None:
        block = tk.Frame(pane, background=SURFACE, highlightthickness=1, highlightbackground=LINE)
        block.pack(fill="x", pady=(px(10), 0))
        inner = tk.Frame(block, background=SURFACE)
        inner.pack(fill="x", padx=px(14), pady=px(12))
        top = tk.Frame(inner, background=SURFACE)
        top.pack(fill="x")
        label(top, short_hex(request.requester), style="mono", colour=INK).pack(side="left")
        Badge(top, *status_badge(request.status)).pack(side="right")
        key_row = tk.Frame(inner, background=SURFACE)
        key_row.pack(fill="x", pady=(px(8), 0))
        label(key_row, "Key", style="small", colour=INK_2).pack(side="left")
        fingerprint = request.enc_fingerprint or "no keys registered"
        label(key_row, fingerprint, style="mono_small", colour=INK).pack(side="left", padx=(px(8), 0))
        hint = f"{_HINTS.get(request.status, '')} Updated {format_time(request.updated_at)}."
        label(inner, hint, style="small", colour=INK_3, wrap=DETAIL_WRAP - 30).pack(anchor="w", pady=(px(6), 0))
        if not summary.active and request.status is not RequestStatus.APPROVED:
            return
        actions = tk.Frame(inner, background=SURFACE)
        if request.status is RequestStatus.PENDING:
            approve = Button(actions, "Approve", lambda: self._approve(summary, request), kind="primary", size="sm")
            approve.set_enabled(idle and summary.active)
            approve.pack(side="left")
            reject = Button(actions, "Reject", lambda: self._reject(summary, request), size="sm")
            reject.set_enabled(idle)
            reject.pack(side="left", padx=(px(8), 0))
        elif request.status is RequestStatus.APPROVED:
            revoke = Button(
                actions, "Revoke access", lambda: self._revoke(summary, request), kind="danger_outline", size="sm"
            )
            revoke.set_enabled(idle)
            revoke.pack(side="left")
        else:
            return
        actions.pack(anchor="w", pady=(px(10), 0))

    # ------------------------------------------------------------ decisions

    def _approve(self, summary: FileSummary, request: AccessRequest) -> None:
        self.host.worker.submit(
            lambda: self._owner.prepare_approval(summary.file_id, request.requester),
            self._confirm_approval,
            self._failed,
            owner=self,
            name="prepare-approval",
        )

    def _confirm_approval(self, preview: ApprovalPreview) -> None:
        if not confirm(
            self,
            "Approve access",
            "Share this file?",
            [
                DialogField("File", label_text(preview.label), emphasis=True),
                DialogField("File ID", file_id_text(preview.file_id), mono=True),
                DialogField("Requester", preview.requester, mono=True),
                DialogField("Their encryption key", preview.enc_fingerprint, mono=True, emphasis=True),
            ],
            "The file key will be encrypted (ECIES) to the key this address registered on-chain. "
            "Check the fingerprint with the requester in person or over another channel first.",
            "Approve",
        ):
            return
        self.host.run_transaction(
            "Approve access",
            lambda on_submitted: self._owner.approve(preview, on_submitted=on_submitted),
            self._decided,
            done="Access approved",
        )

    def _reject(self, summary: FileSummary, request: AccessRequest) -> None:
        if not confirm(
            self,
            "Reject request",
            "Reject this request?",
            [
                DialogField("File", label_text(summary.label), emphasis=True),
                DialogField("Requester", request.requester, mono=True),
            ],
            "No key is shared. The rejection is recorded on-chain, and the requester can ask again.",
            "Reject",
            danger=True,
        ):
            return
        self.host.run_transaction(
            "Reject request",
            lambda on_submitted: self._owner.reject(summary.file_id, request.requester, on_submitted=on_submitted),
            self._decided,
            done="Request rejected",
        )

    def _revoke(self, summary: FileSummary, request: AccessRequest) -> None:
        if not confirm(
            self,
            "Revoke access",
            "Revoke this person's access?",
            [
                DialogField("File", label_text(summary.label), emphasis=True),
                DialogField("Requester", request.requester, mono=True),
            ],
            "The wrapped key is deleted from contract storage. It stays in the history of the approve "
            "transaction, and anything the requester already decrypted stays with them.",
            "Revoke access",
            danger=True,
        ):
            return
        self.host.run_transaction(
            "Revoke access",
            lambda on_submitted: self._owner.revoke(summary.file_id, request.requester, on_submitted=on_submitted),
            self._decided,
            done="Access revoked",
        )

    def _deactivate(self, summary: FileSummary) -> None:
        if not confirm(
            self,
            "Deactivate file",
            "Stop accepting requests for this file?",
            [
                DialogField("File", label_text(summary.label), emphasis=True),
                DialogField("File ID", file_id_text(summary.file_id), mono=True),
            ],
            "Nobody can request or be approved for this file any more. Existing approvals stay valid. "
            "This cannot be undone.",
            "Deactivate file",
            danger=True,
        ):
            return
        self.host.run_transaction(
            "Deactivate file",
            lambda on_submitted: self._owner.deactivate(summary.file_id, on_submitted=on_submitted),
            self._decided,
            done="File deactivated",
        )

    def _decided(self, _receipt: TxReceipt) -> None:
        self.reload()

    def _failed(self, exc: BaseException) -> None:
        self.host.notify(describe_error(exc), Level.ERROR, title="Cannot approve")
        self.reload()


# ------------------------------------------------------------------- rows


def _build_row(row: ListRow) -> None:
    body = row.body
    body.columnconfigure(0, weight=1)
    row.parts["label"] = label(body, "", style="strong")
    row.parts["label"].grid(row=0, column=0, sticky="w")
    row.parts["badge"] = Badge(body)
    row.parts["badge"].grid(row=0, column=1, sticky="e")
    row.parts["id"] = label(body, "", style="mono_small", colour=INK_2)
    row.parts["id"].grid(row=1, column=0, sticky="w", pady=(px(5), 0))
    row.parts["time"] = label(body, "", style="small", colour=INK_3)
    row.parts["time"].grid(row=1, column=1, sticky="e", pady=(px(5), 0))


def _fill_row(row: ListRow, item: FileItem) -> None:
    summary, requests = item
    statuses = [r.status for r in requests]
    pending, approved = pending_count(statuses), statuses.count(RequestStatus.APPROVED)
    row.parts["label"].configure(text=label_text(summary.label), foreground=INK if summary.label else INK_2)
    badge = row.parts["badge"]
    assert isinstance(badge, Badge)
    if not summary.active:
        badge.set("Deactivated", "slate")
    elif pending:
        badge.set(f"{pending} pending", "amber")
    elif approved:
        badge.set("Shared with 1 person" if approved == 1 else f"Shared with {approved} people", "accent")
    else:
        badge.set("")
    row.parts["id"].configure(text=short_hex(summary.file_id, 10, 8))
    row.parts["time"].configure(text=format_time(summary.registered_at))
