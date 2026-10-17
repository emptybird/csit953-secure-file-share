"""Browse files (DESIGN.md 8, requester): every registered file and my access to it.

The list shows my status for each file and refreshes when the owner decides.
From the detail pane I request access, and once approved open Retrieve and
verify. My own encryption-key fingerprint is shown next to the request, so I
can read it to the owner when they check it in the approval dialog.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Sequence

from app.chain import RequestStatus
from app.chain.client import TxReceipt
from app.chain.events import ChainEvent
from app.crypto.encoding import fingerprint
from app.gui.format import file_id_text, file_title, format_time, short_hex, status_badge
from app.gui.host import Host, Level
from app.gui.layout import ListRow, ListView, field_row
from app.gui.page import Page, clear, split
from app.gui.theme import INK, INK_2, INK_3, PAGE_PAD, SURFACE, px
from app.gui.widgets import Badge, Button, Field, Link, Segmented, hline, label
from app.gui.worker import describe_error
from app.services.models import FileSummary
from app.services.requester import RequesterService

DETAIL_WRAP = 330
_REQUESTABLE = (RequestStatus.NONE, RequestStatus.REJECTED, RequestStatus.REVOKED)
_EXPLAIN = {
    RequestStatus.NONE: "Not requested. The owner reviews each request before sharing the file key.",
    RequestStatus.PENDING: "Awaiting the owner's decision. This page updates automatically.",
    RequestStatus.APPROVED: "The file key is encrypted to your encryption key. The file is ready to "
    "retrieve, verify and decrypt.",
    RequestStatus.REJECTED: "The owner rejected your request. You may request access again.",
    RequestStatus.REVOKED: "The owner revoked your access and deleted the wrapped key. You may request access again.",
}


class BrowsePage(Page):
    key = "browse"

    def __init__(self, parent: tk.Misc, host: Host) -> None:
        super().__init__(
            parent,
            host,
            "Browse files",
            "All files registered on this contract. Request access, then retrieve and verify a file.",
        )
        self._requester = RequesterService(host.session)
        self._files: dict[str, FileSummary] = {}
        self._order: list[str] = []
        self._query = ""
        self._loading = self._reload_again = False
        self._wanted: str | None = None
        self._search = Field(
            self.actions, placeholder="Search by name, file ID or owner", width=280, on_change=self._searched
        )
        self._search.pack(side="right")

        toolbar = tk.Frame(self.content, background=SURFACE)
        toolbar.pack(fill="x", padx=px(PAGE_PAD), pady=(0, px(14)))
        self._scope = Segmented(
            toolbar, [("all", "All files"), ("mine", "My requests")], value="all", on_change=lambda _v: self._render()
        )
        self._scope.pack(side="left")
        self._count = label(toolbar, "", style="small", colour=INK_3)
        self._count.pack(side="left", padx=(px(14), 0))
        left, self._detail = split(self)
        self._list: ListView[FileSummary] = ListView(
            left,
            build=_build_row,
            fill=_fill_row,
            on_select=lambda _key: self._show_detail(),
            empty=("search", "No files", "Files appear here once registered on the contract."),
        )
        self._list.pack(fill="both", expand=True)
        self._show_detail()
        self.reload()

    # -------------------------------------------------------------- loading

    def reload(self) -> None:
        if self._loading:
            self._reload_again = True
            return
        self._loading = True
        self.host.worker.submit(
            self._requester.catalogue, self._loaded, self._load_failed, owner=self, name="catalogue"
        )

    def wants(self, events: Sequence[ChainEvent]) -> bool:
        me = self.host.session.address
        return any(e.name in ("FileRegistered", "FileDeactivated") or e.account == me for e in events)

    def on_show(self, **options: object) -> None:
        file_id = options.get("file_id")
        if isinstance(file_id, bytes):
            self._wanted = file_id_text(file_id)
            self._scope.set("all", notify=False)
            self._render()

    def _loaded(self, files: tuple[FileSummary, ...]) -> None:
        self._files = {file_id_text(f.file_id): f for f in files}
        self._order = list(reversed(self._files))
        self._render()
        self._loading = False
        if self._reload_again:
            self._reload_again = False
            self.reload()

    def _load_failed(self, exc: BaseException) -> None:
        self._loading = False
        self.host.notify(describe_error(exc), Level.ERROR, title="Could not load the file list")

    def _searched(self, text: str) -> None:
        self._query = text.strip().lower()
        self._render()

    def _render(self) -> None:
        mine_only = self._scope.get() == "mine"
        shown = []
        for key in self._order:
            summary = self._files[key]
            if mine_only and (summary.is_mine or summary.my_status is RequestStatus.NONE):
                continue
            if self._query and self._query not in f"{key} {summary.name} {summary.label} {summary.owner}".lower():
                continue
            shown.append((key, summary))
        if self._query:
            self._list.empty.set("No matching files", "Search by name, file ID or owner address.")
        elif mine_only:
            self._list.empty.set("No requests", "Select a file under All files to request access.")
        else:
            self._list.empty.set("No files", "Files appear here once registered on the contract.")
        self._list.set_items(shown)
        self._count.configure(text=f"{len(shown)} shown" if self._files else "")
        if self._wanted is not None and self._wanted in self._files:
            self._list.select(self._wanted)
            self._wanted = None
        elif self._list.selected is None and self._list.row_keys:
            self._list.select(self._list.row_keys[0])
        self._show_detail()

    # --------------------------------------------------------------- detail

    def _selected(self) -> FileSummary | None:
        key = self._list.selected
        return self._files.get(key) if key else None

    def on_busy_changed(self) -> None:
        self._show_detail()

    def _show_detail(self) -> None:
        body = self._detail.body
        clear(body)
        summary = self._selected()
        if summary is None:
            text = "Select a file to view your access." if self._files else ""
            label(body, text, style="small", colour=INK_3, wrap=DETAIL_WRAP).pack(anchor="w", padx=px(24), pady=px(28))
            return
        pane = tk.Frame(body, background=SURFACE)
        pane.pack(fill="both", expand=True, padx=px(24), pady=(px(22), px(24)))
        label(pane, file_title(summary.name, summary.label), style="heading", wrap=DETAIL_WRAP).pack(anchor="w")

        fields = tk.Frame(pane, background=SURFACE)
        fields.pack(fill="x", pady=(px(14), 0))
        owner = "You" if summary.is_mine else summary.owner
        field_row(fields, 0, "Owner", mono=not summary.is_mine, wrap=230).configure(text=owner)
        file_id = file_id_text(summary.file_id)
        field_row(fields, 1, "File ID", mono=True, wrap=230).configure(text=file_id)
        Link(fields, "Copy file ID", lambda: self.host.copy_to_clipboard(file_id, "File ID")).grid(
            row=2, column=1, sticky="w", pady=(0, px(4))
        )
        field_row(fields, 3, "Registered").configure(text=format_time(summary.registered_at))
        if summary.name:  # the heading shows the private name, so also show what everyone sees
            public = field_row(fields, 4, "Public label", wrap=230)
            public.configure(text=summary.label or "None", foreground=INK if summary.label else INK_3)

        hline(pane).pack(fill="x", pady=(px(18), px(16)))
        heading = tk.Frame(pane, background=SURFACE)
        heading.pack(fill="x")
        label(heading, "Your access", style="strong").pack(side="left")
        if summary.is_mine:
            Badge(heading, "Owner", "accent").pack(side="right")
        else:
            Badge(heading, *status_badge(summary.my_status)).pack(side="right")
        label(pane, _explain(summary), style="small", colour=INK_2, wrap=DETAIL_WRAP).pack(anchor="w", pady=(px(8), 0))
        if not summary.is_mine and summary.my_status in (
            RequestStatus.NONE,
            RequestStatus.PENDING,
            RequestStatus.APPROVED,
        ):
            keys = tk.Frame(pane, background=SURFACE)
            keys.pack(fill="x", pady=(px(12), 0))
            label(keys, "Your encryption key", style="small", colour=INK_2).pack(side="left")
            mine = fingerprint(self.host.session.keys.enc_public_key)
            label(keys, mine, style="mono_small", colour=INK).pack(side="left", padx=(px(8), 0))
        self._action_button(pane, summary)

    def _action_button(self, pane: tk.Frame, summary: FileSummary) -> None:
        idle = not self.host.tx_in_flight
        if summary.can_retrieve:
            button = Button(
                pane, "Retrieve and verify", lambda: self.host.navigate("verify", file_id=summary.file_id),
                kind="primary", fill=True, icon="shield",
            )  # fmt: skip
        elif not summary.active:
            button = Button(pane, "Deactivated by the owner", None, fill=True)
            button.set_enabled(False)
        elif summary.my_status is RequestStatus.PENDING:
            button = Button(pane, "Awaiting approval", None, fill=True)
            button.set_enabled(False)
        else:
            text = "Request access" if summary.my_status is RequestStatus.NONE else "Request again"
            button = Button(pane, text, lambda: self._request(summary), kind="primary", fill=True)
            button.set_enabled(idle and summary.my_status in _REQUESTABLE)
        button.pack(fill="x", pady=(px(20), 0))

    def _request(self, summary: FileSummary) -> None:
        self.host.run_transaction(
            "Request access",
            lambda on_submitted: self._requester.request_access(summary.file_id, on_submitted=on_submitted),
            self._requested,
            done="Access requested",
        )

    def _requested(self, _receipt: TxReceipt) -> None:
        self.reload()


def _explain(summary: FileSummary) -> str:
    if summary.is_mine:
        return "You own this file. Retrieve and verify uses your copy of the file key."
    if not summary.active and summary.my_status is not RequestStatus.APPROVED:
        return "The owner deactivated this file. New requests are not accepted."
    return _EXPLAIN[summary.my_status]


# ------------------------------------------------------------------- rows


def _build_row(row: ListRow) -> None:
    body = row.body
    body.columnconfigure(0, weight=1)
    row.parts["label"] = label(body, "", style="strong")
    row.parts["label"].grid(row=0, column=0, sticky="w")
    row.parts["badge"] = Badge(body)
    row.parts["badge"].grid(row=0, column=1, sticky="e")
    owner = tk.Frame(body, background=SURFACE)
    owner.grid(row=1, column=0, sticky="w", pady=(px(5), 0))
    row.parts["by"] = label(owner, "Owner", style="small", colour=INK_3)
    row.parts["by"].pack(side="left")
    row.parts["owner"] = label(owner, "", style="mono_small", colour=INK_2)
    row.parts["owner"].pack(side="left", padx=(px(6), 0))
    row.parts["time"] = label(body, "", style="small", colour=INK_3)
    row.parts["time"].grid(row=1, column=1, sticky="e", pady=(px(5), 0))


def _fill_row(row: ListRow, summary: FileSummary) -> None:
    known = summary.name or summary.label
    row.parts["label"].configure(text=file_title(summary.name, summary.label), foreground=INK if known else INK_2)
    badge = row.parts["badge"]
    assert isinstance(badge, Badge)
    if summary.is_mine:
        badge.set("Yours", "slate")
    elif not summary.active and summary.my_status is not RequestStatus.APPROVED:
        badge.set("Deactivated", "slate")
    elif summary.my_status is RequestStatus.NONE:
        badge.set("")
    else:
        badge.set(*status_badge(summary.my_status))
    row.parts["by"].configure(text="Owned by you" if summary.is_mine else "Owner")
    row.parts["owner"].configure(text="" if summary.is_mine else short_hex(summary.owner))
    row.parts["time"].configure(text=format_time(summary.registered_at))
