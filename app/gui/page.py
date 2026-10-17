"""Base class for the pages behind the sidebar, and the list | detail split.

Every page has a title, one line saying what it is for, and an actions area on
the right of the title. The main window calls the hooks: `wants(events)` when
new contract events arrive, `reload()` if it returns True, `on_busy_changed()`
when a transaction starts or ends, and `on_show(**options)` on navigation.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Sequence

from app.chain.events import ChainEvent
from app.gui.host import Host
from app.gui.layout import ScrollArea
from app.gui.theme import DETAIL_WIDTH, INK_2, PAGE_PAD, SURFACE, px
from app.gui.widgets import hline, label, vline


class Page(tk.Frame):
    key = ""

    def __init__(self, parent: tk.Misc, host: Host, title: str, subtitle: str) -> None:
        super().__init__(parent, background=SURFACE)
        self.host = host
        self.header = tk.Frame(self, background=SURFACE)
        self.header.pack(fill="x", padx=px(PAGE_PAD), pady=(px(26), px(18)))
        self.header.columnconfigure(0, weight=1)
        heading = tk.Frame(self.header, background=SURFACE)
        heading.grid(row=0, column=0, sticky="w")
        self._title = label(heading, title, style="title")
        self._title.pack(anchor="w")
        self._subtitle = label(heading, subtitle, style="body", colour=INK_2)
        self._subtitle.pack(anchor="w", pady=(px(4), 0))
        self.actions = tk.Frame(self.header, background=SURFACE)
        self.actions.grid(row=0, column=1, sticky="e")
        self.content = tk.Frame(self, background=SURFACE)
        self.content.pack(fill="both", expand=True)

    def set_heading(self, title: str, subtitle: str | None = None) -> None:
        self._title.configure(text=title)
        if subtitle is not None:
            self._subtitle.configure(text=subtitle)

    # hooks called by the main window
    def wants(self, events: Sequence[ChainEvent]) -> bool:
        del events
        return False

    def reload(self) -> None:
        """Fetch fresh data in the background."""

    def on_busy_changed(self) -> None:
        """A transaction started or finished; enable or disable buttons."""

    def on_show(self, **options: object) -> None:
        """The page became visible, possibly with a file to select."""


def split(page: Page) -> tuple[tk.Frame, ScrollArea]:
    """A hairline under the header, then a flexible list area and a fixed-width
    detail pane separated by a vertical hairline."""
    hline(page.content).pack(fill="x")
    body = tk.Frame(page.content, background=SURFACE)
    body.pack(fill="both", expand=True)
    body.columnconfigure(0, weight=1)
    body.rowconfigure(0, weight=1)
    left = tk.Frame(body, background=SURFACE)
    left.grid(row=0, column=0, sticky="nsew")
    vline(body).grid(row=0, column=1, sticky="ns")
    holder = tk.Frame(body, background=SURFACE, width=px(DETAIL_WIDTH))
    holder.grid(row=0, column=2, sticky="ns")
    holder.grid_propagate(False)
    holder.rowconfigure(0, weight=1)
    holder.columnconfigure(0, weight=1)
    detail = ScrollArea(holder, background=SURFACE)
    detail.grid(row=0, column=0, sticky="nsew")
    return left, detail


def clear(frame: tk.Misc) -> None:
    for child in frame.winfo_children():
        child.destroy()
