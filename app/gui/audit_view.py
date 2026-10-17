"""Activity (DESIGN.md 5.5, 8): the contract's events as an audit trail.

Rows come from the session's EventLog, which the main window refreshes in the
background, so this page makes no RPC calls of its own. Clicking a row opens
the transaction in the block explorer, or copies its hash on a local chain.
Export CSV writes the shown events for the report's evidence appendix.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Sequence
from pathlib import Path
from tkinter import filedialog

from app.chain.events import ChainEvent, write_csv
from app.gui.format import event_title, event_tone, label_text, plural, short_hex
from app.gui.host import Host, Level
from app.gui.layout import ListRow, ListView
from app.gui.page import Page
from app.gui.theme import INK_2, INK_3, PAGE_PAD, SURFACE, px
from app.gui.widgets import TONES, Button, Checkbox, hline, label
from app.gui.worker import describe_error

MAX_ROWS = 300

ActivityItem = tuple[ChainEvent, str]  # the event and its one-line description


class ActivityPage(Page):
    key = "activity"

    def __init__(self, parent: tk.Misc, host: Host) -> None:
        super().__init__(
            parent,
            host,
            "Activity",
            "Every row is a transaction the contract recorded. Nobody can edit or delete them.",
        )
        self._shown: tuple[ChainEvent, ...] = ()
        Button(self.actions, "Export CSV", self._export, icon="download", size="sm").pack(side="right")
        self._mine = Checkbox(self.actions, "Only events about me", command=lambda _v: self.reload())
        self._mine.pack(side="right", padx=(0, px(18)))
        hline(self.content).pack(fill="x")
        self._list: ListView[ActivityItem] = ListView(
            self.content,
            build=_build_row,
            fill=_fill_row,
            on_activate=self._open,
            selectable=False,
            empty=("activity", "No activity yet", "Registrations, requests and decisions appear here as they happen."),
        )
        self._list.pack(fill="both", expand=True)
        self._count = label(self.content, "", style="small", colour=INK_3)
        self._count.pack(anchor="w", padx=px(PAGE_PAD), pady=px(10))
        host.worker.submit(
            host.session.events.refresh,
            lambda _new: self.reload(),
            lambda exc: host.notify(describe_error(exc), Level.ERROR, title="Could not read the activity"),
            owner=self,
            name="events",
        )

    def wants(self, events: Sequence[ChainEvent]) -> bool:
        return bool(events)

    def reload(self) -> None:
        session = self.host.session
        me = session.address
        everything = session.events.events
        labels = {e.file_id: e.label for e in everything if e.name == "FileRegistered"}
        owners = {e.file_id: e.args.get("owner") for e in everything if e.name == "FileRegistered"}
        if self._mine.get():
            shown = tuple(e for e in everything if e.account == me or owners.get(e.file_id) == me)
        else:
            shown = everything
        self._shown = shown
        latest = list(reversed(shown))[:MAX_ROWS]
        self._list.set_items([(f"{e.tx_hash}/{e.log_index}", (e, _describe(e, labels, me))) for e in latest])
        more = f" Showing the latest {MAX_ROWS}; Export CSV has all of them." if len(shown) > MAX_ROWS else ""
        self._count.configure(text=f"{plural(len(shown), 'event')} since block {session.chain.deploy_block}.{more}")

    def _open(self, key: str) -> None:
        self.host.tx_action(key.split("/")[0])[1]()

    def _export(self) -> None:
        events = self._shown
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export the activity",
            initialfile=f"sfs-activity-{self.host.app_config.network.name}.csv",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not path:
            return
        self.host.worker.submit(
            lambda: write_csv(events, Path(path)),
            lambda _none: self.host.notify(path, Level.SUCCESS, title=f"Exported {plural(len(events), 'event')}"),
            lambda exc: self.host.notify(_os_error(exc), Level.ERROR, title="Export failed"),
            owner=self,
            name="export",
        )


def _describe(event: ChainEvent, labels: dict[bytes | None, str], me: str) -> str:
    who = "you" if event.account == me else short_hex(event.account or "")
    name = label_text(labels.get(event.file_id, "")) if event.file_id else ""
    if event.name == "KeysRegistered":
        return f"By {who}"
    if event.name == "FileRegistered":
        return f"{name}, owned by {who}"
    if event.name == "AccessRequested":
        return f"{name}, requested by {who}"
    if event.name == "FileDeactivated":
        return name
    return f"{name}, for {who}"


def _build_row(row: ListRow) -> None:
    body = row.body
    body.columnconfigure(1, weight=1)
    dot = tk.Canvas(body, width=px(10), height=px(10), background=SURFACE, highlightthickness=0)
    dot.grid(row=0, column=0, rowspan=2, sticky="n", padx=(0, px(14)), pady=(px(5), 0))
    row.parts["dot"] = dot
    row.parts["title"] = label(body, "", style="strong")
    row.parts["title"].grid(row=0, column=1, sticky="w")
    row.parts["text"] = label(body, "", style="small", colour=INK_2)
    row.parts["text"].grid(row=1, column=1, sticky="w", pady=(px(3), 0))
    row.parts["block"] = label(body, "", style="small", colour=INK_3)
    row.parts["block"].grid(row=0, column=2, sticky="e")
    row.parts["tx"] = label(body, "", style="mono_small", colour=INK_2)
    row.parts["tx"].grid(row=1, column=2, sticky="e", pady=(px(3), 0))


def _fill_row(row: ListRow, item: ActivityItem) -> None:
    event, text = item
    dot = row.parts["dot"]
    assert isinstance(dot, tk.Canvas)
    dot.delete("all")
    colour = TONES[event_tone(event.name)][1]
    size = int(dot.cget("width"))
    dot.create_oval(1, 1, size - 1, size - 1, fill=colour, outline=colour)
    row.parts["title"].configure(text=event_title(event.name))
    row.parts["text"].configure(text=text)
    row.parts["block"].configure(text=f"Block {event.block_number}")
    row.parts["tx"].configure(text=short_hex(event.tx_hash, 8, 6))


def _os_error(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or str(exc)
    return describe_error(exc)
