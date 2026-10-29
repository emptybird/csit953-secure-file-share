"""Containers: rounded panels, scroll areas and selectable lists.

ListView keeps one row widget per key and updates rows in place when the data
refreshes, so a poll every few seconds does not flicker or lose the selection.
Mouse-wheel scrolling is dispatched once for the whole window to whichever
scroll area is under the pointer (`install_mousewheel`).
"""

from __future__ import annotations

import sys
import tkinter as tk
from collections.abc import Callable, Sequence
from typing import Generic, TypeVar

from app.gui.theme import (
    ACCENT,
    HOVER,
    INK,
    INK_2,
    INK_3,
    LINE,
    LINE_STRONG,
    PANEL_RADIUS,
    SELECTED,
    SURFACE,
    px,
)
from app.gui.widgets import Button, IconCanvas, label, rounded_rect, surface_of

T = TypeVar("T")

# ------------------------------------------------------------------ panel


class Panel(tk.Frame):
    """A surface with rounded corners and a hairline border; children go in `body`.

    The corners are drawn on a canvas placed behind `body`, which is inset by the
    padding, so the panel sizes itself like any frame (to its content, or to the
    space its parent gives it)."""

    def __init__(self, parent: tk.Misc, *, padding: int = 20, background: str = SURFACE, border: str = LINE) -> None:
        surface = surface_of(parent)
        super().__init__(parent, background=surface)
        self._fill, self._border = background, border
        self._shape = tk.Canvas(self, width=1, height=1, background=surface, highlightthickness=0, borderwidth=0)
        self._shape.place(x=0, y=0, relwidth=1, relheight=1)
        self._shape.bind("<Configure>", lambda _e: self._redraw())
        self.body = tk.Frame(self, background=background)
        self.body.pack(fill="both", expand=True, padx=px(padding), pady=px(padding))

    def _redraw(self) -> None:
        shape = self._shape
        shape.delete("all")
        width, height = shape.winfo_width(), shape.winfo_height()
        rounded_rect(shape, 0, 0, width - 1, height - 1, px(PANEL_RADIUS), fill=self._fill, outline=self._border)

    def set_colours(self, background: str, border: str) -> None:
        self._fill, self._border = background, border
        self.body.configure(background=background)
        self._redraw()


# ------------------------------------------------------------ scroll area


class _ScrollBar(tk.Canvas):
    """A slim scrollbar that only shows its thumb when there is something to scroll."""

    def __init__(self, parent: tk.Misc, target: tk.Canvas, background: str) -> None:
        super().__init__(parent, width=px(10), height=1, background=background, highlightthickness=0, borderwidth=0)
        self._target = target
        self._first, self._last = 0.0, 1.0
        self._drag: tuple[int, float] | None = None
        self._hover = False
        self.bind("<Configure>", lambda _e: self._draw())
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))
        self.bind("<ButtonPress-1>", self._press)
        self.bind("<B1-Motion>", self._move)
        self.bind("<ButtonRelease-1>", lambda _e: setattr(self, "_drag", None))

    def set(self, first: str, last: str) -> None:
        self._first, self._last = float(first), float(last)
        self._draw()

    def _set_hover(self, hover: bool) -> None:
        self._hover = hover
        self._draw()

    def _press(self, event: tk.Event) -> None:
        # On the thumb: start a drag. Elsewhere: jump so the thumb centres on the click.
        height = max(1, self.winfo_height())
        if self._first * height <= event.y <= self._last * height:
            self._drag = (event.y, self._first)
        else:
            self._target.yview_moveto(event.y / height - (self._last - self._first) / 2)

    def _move(self, event: tk.Event) -> None:
        if self._drag is not None:
            start_y, start_first = self._drag
            self._target.yview_moveto(start_first + (event.y - start_y) / max(1, self.winfo_height()))

    def _draw(self) -> None:
        self.delete("all")
        if self._last - self._first >= 0.999:
            return
        height = self.winfo_height()
        top, bottom = self._first * height, self._last * height
        x1, x2 = px(2), self.winfo_width() - px(2)
        colour = INK_3 if self._hover or self._drag else LINE_STRONG
        rounded_rect(
            self, x1, top + px(2), x2, max(top + px(24), bottom - px(2)), (x2 - x1) / 2, fill=colour, outline=colour
        )


class ScrollArea(tk.Frame):
    """A vertically scrolling area; put children in `body`."""

    def __init__(self, parent: tk.Misc, *, background: str = SURFACE) -> None:
        super().__init__(parent, background=background)
        self.canvas = tk.Canvas(
            self, width=1, height=1, background=background, highlightthickness=0, borderwidth=0, yscrollincrement=px(4)
        )
        self.body = tk.Frame(self.canvas, background=background)
        self._window = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        self._bar = _ScrollBar(self, self.canvas, background)
        self.canvas.configure(yscrollcommand=self._bar.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self._bar.grid(row=0, column=1, sticky="ns")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.body.bind("<Configure>", lambda _e: self._content_changed())
        self.canvas.bind("<Configure>", self._view_changed)
        self.canvas.sfs_scroll_area = self  # found by the mouse-wheel dispatcher

    def _content_changed(self) -> None:
        """The scroll region follows the body's requested size."""
        self.canvas.configure(scrollregion=(0, 0, self.body.winfo_reqwidth(), self.body.winfo_reqheight()))

    def _view_changed(self, event: tk.Event) -> None:
        """Keep the body exactly as wide as the viewport."""
        self.canvas.itemconfigure(self._window, width=event.width)

    def scroll(self, units: int) -> None:
        # Content that fits must not scroll.
        if self.body.winfo_reqheight() > self.canvas.winfo_height():
            self.canvas.yview_scroll(units, "units")

    def to_top(self) -> None:
        self.canvas.yview_moveto(0)


def install_mousewheel(root: tk.Misc) -> None:
    """Route wheel and trackpad scrolling to the scroll area under the pointer."""

    def area_under(event: tk.Event) -> ScrollArea | None:
        widget = root.winfo_containing(event.x_root, event.y_root)
        while widget is not None:
            area = getattr(widget, "sfs_scroll_area", None)
            if area is not None:
                return area
            widget = widget.master
        return None

    def wheel(event: tk.Event) -> None:
        area = area_under(event)
        if area is None:
            return
        if event.num == 4:
            units = -8
        elif event.num == 5:
            units = 8
        elif abs(event.delta) >= 120:  # Windows, and Tk 8.7+ everywhere
            units = -round(event.delta / 120 * 8)
        else:  # macOS on Tk 8.6 reports small deltas, many per gesture
            units = -event.delta * 2
        area.scroll(units)

    root.bind_all("<MouseWheel>", wheel, add="+")
    if sys.platform.startswith("linux"):  # X11 reports the wheel as buttons 4 and 5
        root.bind_all("<Button-4>", wheel, add="+")
        root.bind_all("<Button-5>", wheel, add="+")


# ------------------------------------------------------------ empty state


class EmptyState(tk.Frame):
    """What to show where a list has nothing yet: what is missing and what to do."""

    def __init__(self, parent: tk.Misc, icon: str, title: str, text: str) -> None:
        super().__init__(parent, background=surface_of(parent))
        self._icon = IconCanvas(self, icon, size=20, colour=ACCENT, disc=SELECTED)
        self._icon.pack(pady=(0, px(14)))
        self._title = label(self, title, style="strong")
        self._title.pack()
        self._text = label(self, text, style="small", colour=INK_2, wrap=320)
        self._text.configure(justify="center", anchor="center")
        self._text.pack(pady=(px(4), 0))
        self._action: Button | None = None

    def set(self, title: str, text: str) -> None:
        self._title.configure(text=title)
        self._text.configure(text=text)

    def add_action(self, text: str, command: Callable[[], None], *, icon: str | None = None) -> None:
        self._action = Button(self, text, command, kind="primary", icon=icon)
        self._action.pack(pady=(px(16), 0))


# ------------------------------------------------------------------- list


class ListRow(tk.Frame):
    """One selectable row: an accent bar on the left when selected, content in `body`."""

    def __init__(self, view: ListView, key: str) -> None:
        super().__init__(view.body, background=SURFACE)
        self.key = key
        self.parts: dict[str, tk.Widget] = {}
        self._selected = False
        self._hover = False
        self._bar = tk.Frame(self, width=px(3), background=SURFACE)
        self._bar.pack(side="left", fill="y")
        self.body = tk.Frame(self, background=SURFACE)
        self.body.pack(side="left", fill="both", expand=True, padx=(px(17), px(20)), pady=px(13))
        separator = tk.Frame(view.body, height=1, background=LINE)
        separator.sfs_keep_colour = True  # skipped by _paint
        self.separator = separator

    def finish(self, on_click: Callable[[str], None]) -> None:
        """Call after the content is built: binds clicks and hover on every descendant."""
        for widget in _descendants(self):
            if isinstance(widget, Button):  # buttons keep their own click handling
                continue
            widget.bind("<Button-1>", lambda _e: on_click(self.key), add="+")
            widget.bind("<Enter>", lambda _e: self._set_hover(True), add="+")
            widget.bind("<Leave>", lambda _e: self.after_idle(self._check_hover), add="+")

    def _check_hover(self) -> None:
        """<Leave> also fires when the pointer moves onto a child; ask where it really is."""
        if not self.winfo_exists():
            return
        x, y = self.winfo_pointerxy()
        under = self.winfo_containing(x, y)
        path = str(under) if under is not None else ""
        self._set_hover(path == str(self) or path.startswith(str(self) + "."))

    def _set_hover(self, hover: bool) -> None:
        if hover != self._hover:
            self._hover = hover
            self._paint()

    def set_selected(self, selected: bool) -> None:
        if selected != self._selected:
            self._selected = selected
            self._paint()

    def _paint(self) -> None:
        colour = SELECTED if self._selected else HOVER if self._hover else SURFACE
        self._bar.configure(background=ACCENT if self._selected else colour)
        for widget in (self, self.body, *_descendants(self.body)):
            if getattr(widget, "sfs_keep_colour", False):
                continue
            if hasattr(widget, "set_surface"):
                widget.set_surface(colour)
            elif isinstance(widget, (tk.Frame, tk.Label, tk.Canvas)):
                widget.configure(background=colour)


def _descendants(widget: tk.Misc) -> list[tk.Misc]:
    found = []
    for child in widget.winfo_children():
        found.append(child)
        found.extend(_descendants(child))
    return found


class ListView(ScrollArea, Generic[T]):
    """Rows keyed by id. `build(row)` creates a row's widgets once; `fill(row, item)`
    updates them on every refresh. Up and Down move the selection."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        build: Callable[[ListRow], None],
        fill: Callable[[ListRow, T], None],
        on_select: Callable[[str | None], None] | None = None,
        on_activate: Callable[[str], None] | None = None,
        selectable: bool = True,
        empty: tuple[str, str, str] = ("files", "Nothing to show", ""),
    ) -> None:
        super().__init__(parent, background=SURFACE)
        self._build, self._fill = build, fill
        self._on_select = on_select
        self._on_activate = on_activate
        self._selectable = selectable
        self._rows: dict[str, ListRow] = {}
        self._order: list[str] = []
        self._selected: str | None = None
        self.empty = EmptyState(self.body, *empty)
        self._loading: tk.Label | None = label(self.body, "Loading…", style="small", colour=INK_3)
        self._loading.pack(anchor="w", padx=px(20), pady=px(16))
        self.canvas.configure(takefocus=1)
        self.canvas.bind("<Up>", lambda _e: self._step(-1))
        self.canvas.bind("<Down>", lambda _e: self._step(1))

    @property
    def selected(self) -> str | None:
        return self._selected

    @property
    def row_keys(self) -> list[str]:
        return list(self._order)

    def set_items(self, items: Sequence[tuple[str, T]]) -> None:
        """Diff against the current rows: drop gone keys, refill existing rows, build new ones."""
        if self._loading is not None:
            self._loading.destroy()
            self._loading = None
        keys = [key for key, _ in items]
        for key in [k for k in self._rows if k not in keys]:
            row = self._rows.pop(key)
            row.separator.destroy()
            row.destroy()
        for key, item in items:
            row = self._rows.get(key)
            if row is None:
                row = ListRow(self, key)
                self._build(row)
                self._fill(row, item)
                row.finish(self._clicked)
                self._rows[key] = row
            else:
                self._fill(row, item)
        # Repack only when the order changed; repacking on every poll would flicker.
        if keys != self._order:
            for key in self._order:
                if key in self._rows:
                    self._rows[key].pack_forget()
                    self._rows[key].separator.pack_forget()
            for key in keys:
                self._rows[key].pack(fill="x")
                self._rows[key].separator.pack(fill="x", padx=(px(20), 0))
            self._order = keys
        if keys:
            self.empty.pack_forget()
        else:
            self.empty.pack(pady=(px(72), 0))
        if self._selected is not None and self._selected not in self._rows:
            self.select(None)

    def select(self, key: str | None) -> None:
        if key is not None and key not in self._rows:
            key = None
        if not self._selectable:
            return
        previous = self._selected
        self._selected = key
        for row_key, row in self._rows.items():
            row.set_selected(row_key == key)
        if key != previous and self._on_select is not None:
            self._on_select(key)

    def row(self, key: str) -> ListRow | None:
        return self._rows.get(key)

    def _clicked(self, key: str) -> None:
        self.canvas.focus_set()
        self.select(key)
        if self._on_activate is not None:
            self._on_activate(key)

    def _step(self, delta: int) -> None:
        if not self._order:
            return
        index = self._order.index(self._selected) + delta if self._selected in self._order else 0
        self.select(self._order[max(0, min(index, len(self._order) - 1))])


def section_title(parent: tk.Misc, text: str, *, count: str = "") -> tk.Frame:
    """A small heading inside a pane, e.g. 'Access requests  2'."""
    frame = tk.Frame(parent, background=surface_of(parent))
    label(frame, text, style="strong").pack(side="left")
    if count:
        label(frame, count, style="small", colour=INK_3).pack(side="left", padx=(px(8), 0))
    return frame


def field_row(parent: tk.Misc, row: int, name: str, *, mono: bool = False, wrap: int = 0) -> tk.Label:
    """'Name   value' in a two-column grid; returns the value label."""
    label(parent, name, style="small", colour=INK_2).grid(row=row, column=0, sticky="nw", padx=(0, px(16)), pady=px(4))
    value = label(parent, "", style="mono" if mono else "body", colour=INK, wrap=wrap)
    value.grid(row=row, column=1, sticky="w", pady=px(4))
    return value
