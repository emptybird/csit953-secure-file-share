"""Feedback: the step chain, toasts and the account banner (DESIGN.md 8; task brief 2.5).

The step chain is how the GUI shows security work. Protect & Register and
Retrieve & Verify both run as a chain of nodes joined by a rail: a node fills
green with a check when its step passes, red with a cross when it fails, and
the rail turns green behind every passed step. Sub-checks (V1–V6) are listed
under the step they belong to.

Toasts report transactions (pending, confirmed with block and gas, failed
with the reason) and request status changes that arrive from the chain.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable, Hashable, Sequence
from dataclasses import dataclass
from enum import Enum

from app.gui import icons
from app.gui.host import Level
from app.gui.theme import (
    ACCENT,
    ACCENT_SOFT,
    AMBER,
    AMBER_SOFT,
    INK,
    INK_2,
    INK_3,
    LINE,
    LINE_STRONG,
    RED,
    RED_SOFT,
    SLATE_SOFT,
    SURFACE,
    WHITE,
    font,
    line_height,
    px,
)
from app.gui.widgets import Button, Link, label, surface_of

SPIN_MS = 45


class StepState(Enum):
    WAITING = "waiting"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class SubCheck:
    code: str
    title: str
    state: StepState
    detail: str = ""


class _Spinner:
    """Rotates an arc on a canvas until stopped."""

    def __init__(self, canvas: tk.Canvas, box: tuple[float, float, float, float], colour: str, width: float) -> None:
        self._canvas, self._box, self._colour, self._width = canvas, box, colour, width
        self._angle = 90
        self._job: str | None = None
        self._tick()

    def _tick(self) -> None:
        canvas = self._canvas
        if not canvas.winfo_exists():
            return
        canvas.delete("spinner")
        canvas.create_arc(
            *self._box,
            start=self._angle,
            extent=110,
            style="arc",
            outline=self._colour,
            width=self._width,
            tags="spinner",
        )
        self._angle = (self._angle - 24) % 360
        self._job = canvas.after(SPIN_MS, self._tick)

    def stop(self) -> None:
        if self._job is not None:
            try:
                self._canvas.after_cancel(self._job)
            except tk.TclError:
                pass
            self._job = None
        if self._canvas.winfo_exists():
            self._canvas.delete("spinner")


# ------------------------------------------------------------- step chain


class _Step(tk.Frame):
    def __init__(self, chain: StepChain, index: int, title: str, detail: str, wrap: int, last: bool) -> None:
        background = surface_of(chain)
        super().__init__(chain, background=background)
        self.index, self.last = index, last
        self.state = StepState.WAITING
        self.previous_done = False
        self.default_detail = detail
        self._spinner: _Spinner | None = None
        node = px(24)
        self.rail = tk.Canvas(
            self, width=node + px(4), height=1, background=background, highlightthickness=0, borderwidth=0
        )
        self.rail.grid(row=0, column=0, sticky="ns")
        self.body = tk.Frame(self, background=background)
        title_pad = max(0, (node - line_height("strong")) // 2)
        self.body.grid(row=0, column=1, sticky="nw", padx=(px(12), 0), pady=(title_pad, 0 if last else px(20)))
        self.columnconfigure(1, weight=1)
        self.title = label(self.body, title, style="strong", colour=INK_2)
        self.title.configure(wraplength=wrap)
        self.title.pack(anchor="w")
        self.detail = label(self.body, detail, style="small", colour=INK_3)
        self.detail.configure(wraplength=wrap)
        self.detail.pack(anchor="w", pady=(px(3), 0))
        self.checks = tk.Frame(self.body, background=background)
        self.checks.pack(anchor="w", fill="x")
        self._wrap = wrap  # pixels
        self._check_details: list[tk.Label] = []
        self.bind("<Configure>", lambda _e: self.draw())

    def set_wrap(self, wrap: int) -> None:
        self._wrap = wrap
        self.title.configure(wraplength=wrap)
        self.detail.configure(wraplength=wrap)
        for detail in self._check_details:
            detail.configure(wraplength=wrap - px(24))

    def draw(self) -> None:
        rail = self.rail
        if self._spinner is not None:
            self._spinner.stop()
            self._spinner = None
        rail.delete("all")
        height = self.winfo_height()
        node = px(24)
        x, r, y = (node + px(4)) / 2, node / 2, node / 2
        line = max(2, px(2))
        if self.index > 0:
            rail.create_line(x, 0, x, y - r, fill=ACCENT if self.previous_done else LINE, width=line)
        if not self.last:
            rail.create_line(x, y + r, x, height, fill=ACCENT if self.state is StepState.DONE else LINE, width=line)
        box = (x - r + 1, y - r + 1, x + r - 1, y + r - 1)
        stroke = max(1.6, px(2))
        if self.state is StepState.DONE:
            rail.create_oval(*box, fill=ACCENT, outline=ACCENT)
            icons.draw(rail, "check", x, y, node * 0.62, WHITE, stroke)
        elif self.state is StepState.FAILED:
            rail.create_oval(*box, fill=RED, outline=RED)
            icons.draw(rail, "cross", x, y, node * 0.62, WHITE, stroke)
        elif self.state is StepState.SKIPPED:
            rail.create_oval(*box, fill=SLATE_SOFT, outline=SLATE_SOFT)
            icons.draw(rail, "dash", x, y, node * 0.6, INK_3, stroke)
        elif self.state is StepState.RUNNING:
            rail.create_oval(*box, fill=SURFACE, outline=ACCENT_SOFT, width=line)
            self._spinner = _Spinner(rail, box, ACCENT, line)
        else:
            rail.create_oval(*box, fill=SURFACE, outline=LINE_STRONG, width=max(1, px(1.5)))
            rail.create_text(x, y, text=str(self.index + 1), fill=INK_3, font=font("small_strong"))

    def set(self, state: StepState, detail: str | None, on_click: Callable[[], None] | None) -> None:
        self.state = state
        self.title.configure(foreground=INK_2 if state is StepState.WAITING else INK)
        text = self.default_detail if detail is None else detail
        colour = (
            RED if state is StepState.FAILED else ACCENT if on_click else INK_3 if state is StepState.WAITING else INK_2
        )
        self.detail.configure(text=text, foreground=colour, cursor="hand2" if on_click else "")
        self.detail.unbind("<Button-1>")
        if on_click is not None:
            self.detail.bind("<Button-1>", lambda _e: on_click())
        if text:
            self.detail.pack(anchor="w", pady=(px(3), 0), before=self.checks)
        else:
            self.detail.pack_forget()
        self.draw()

    def set_checks(self, checks: Sequence[SubCheck]) -> None:
        # A fresh frame each time: Tk keeps an emptied frame at its old size.
        background = surface_of(self)
        self.checks.destroy()
        self.checks = tk.Frame(self.body, background=background)
        self.checks.pack(anchor="w", fill="x")
        self._check_details = []
        for row, check in enumerate(checks):
            mark = tk.Canvas(self.checks, width=px(16), height=px(16), background=background, highlightthickness=0)
            mark.grid(row=2 * row, column=0, sticky="nw", pady=(px(9), 0))
            _draw_mark(mark, check.state)
            head = tk.Frame(self.checks, background=background)
            head.grid(row=2 * row, column=1, sticky="w", padx=(px(8), 0), pady=(px(8), 0))
            label(head, check.code, style="small_strong", colour=INK_2).pack(side="left", padx=(0, px(6)))
            label(head, check.title, style="small", colour=INK).pack(side="left")
            if check.detail:
                colour = RED if check.state is StepState.FAILED else INK_2
                detail = label(self.checks, check.detail, style="small", colour=colour)
                detail.configure(wraplength=self._wrap - px(24))
                detail.grid(row=2 * row + 1, column=1, sticky="w", padx=(px(8), 0), pady=(px(1), 0))
                self._check_details.append(detail)


def _draw_mark(canvas: tk.Canvas, state: StepState) -> None:
    size = int(canvas.cget("width"))
    centre, stroke = size / 2, max(1.6, px(1.8))
    if state is StepState.DONE:
        icons.draw(canvas, "check", centre, centre, size, ACCENT, stroke)
    elif state is StepState.FAILED:
        icons.draw(canvas, "cross", centre, centre, size, RED, stroke)
    elif state is StepState.SKIPPED:
        icons.draw(canvas, "dash", centre, centre, size, INK_3, stroke)
    else:
        r = size * 0.28
        colour = ACCENT if state is StepState.RUNNING else LINE_STRONG
        canvas.create_oval(centre - r, centre - r, centre + r, centre + r, outline=colour, width=max(1, px(1.5)))


class StepChain(tk.Frame):
    """Steps given as (key, title, what happens); each shows a state and a detail line."""

    def __init__(self, parent: tk.Misc, steps: Sequence[tuple[Hashable, str, str]], *, wrap: int = 380) -> None:
        super().__init__(parent, background=surface_of(parent))
        self._steps: dict[Hashable, _Step] = {}
        self._max_wrap = self._wrap = px(wrap)
        for index, (key, title, detail) in enumerate(steps):
            step = _Step(self, index, title, detail, self._wrap, last=index == len(steps) - 1)
            step.pack(fill="x", anchor="w")
            self._steps[key] = step
        self._keys = [key for key, _, _ in steps]
        self.bind("<Configure>", self._resized)

    def _resized(self, event: tk.Event) -> None:
        """Wrap text to the width the chain actually got, up to the width it asked for."""
        wrap = max(px(180), min(self._max_wrap, event.width - px(48)))
        if abs(wrap - self._wrap) >= px(4):
            self._wrap = wrap
            for step in self._steps.values():
                step.set_wrap(wrap)

    def set(
        self, key: Hashable, state: StepState, detail: str | None = None, *, on_click: Callable[[], None] | None = None
    ) -> None:
        step = self._steps[key]
        step.set(state, detail, on_click)
        index = self._keys.index(key)
        if index + 1 < len(self._keys):
            following = self._steps[self._keys[index + 1]]
            following.previous_done = state is StepState.DONE
            following.draw()

    def set_checks(self, key: Hashable, checks: Sequence[SubCheck]) -> None:
        self._steps[key].set_checks(checks)

    def state(self, key: Hashable) -> StepState:
        return self._steps[key].state

    def running(self) -> Hashable | None:
        return next((key for key in self._keys if self._steps[key].state is StepState.RUNNING), None)

    def reset(self) -> None:
        for key in self._keys:
            self.set(key, StepState.WAITING)
            self.set_checks(key, ())


# ------------------------------------------------------------------ toasts

_LEVEL_STYLE = {
    Level.INFO: ("info", ACCENT, ACCENT_SOFT),
    Level.PENDING: ("", ACCENT, ACCENT_SOFT),
    Level.SUCCESS: ("check", ACCENT, ACCENT_SOFT),
    Level.WARNING: ("warning", AMBER, AMBER_SOFT),
    Level.ERROR: ("cross", RED, RED_SOFT),
}
TOAST_WIDTH = 372
MAX_TOASTS = 4


class Toast(tk.Frame):
    def __init__(self, stack: Toasts, level: Level, title: str, message: str) -> None:
        super().__init__(stack.root, background=SURFACE, highlightthickness=1, highlightbackground=LINE_STRONG)
        self._stack = stack
        self._timer: str | None = None
        self._spinner: _Spinner | None = None
        self.level = level
        size = px(30)
        self._icon = tk.Canvas(self, width=size, height=size, background=SURFACE, highlightthickness=0)
        self._icon.grid(row=0, column=0, rowspan=3, sticky="n", padx=(px(14), px(12)), pady=px(14))
        self._title = label(self, title, style="strong")
        self._title.grid(row=0, column=1, sticky="w", pady=(px(13), 0))
        self._message = label(self, message, style="small", colour=INK_2, wrap=TOAST_WIDTH - 110)
        self._message.grid(row=1, column=1, sticky="w", pady=(px(2), 0))
        self._action = Link(self, "", None)
        self._action.grid(row=2, column=1, sticky="w", pady=(px(6), px(12)))
        close = Button(self, "", self.close, kind="quiet", size="sm", icon="cross")
        close.grid(row=0, column=2, rowspan=2, sticky="ne", padx=(px(4), px(6)), pady=(px(6), 0))
        self.columnconfigure(1, weight=1)
        self.update_toast(level=level, title=title, message=message)

    def update_toast(
        self,
        *,
        level: Level | None = None,
        title: str | None = None,
        message: str | None = None,
        action: tuple[str, Callable[[], None]] | None = None,
        timeout_ms: int | None = None,
    ) -> None:
        if level is not None:
            self.level = level
            self._draw_icon()
        if title is not None:
            self._title.configure(text=title)
        if message is not None:
            self._message.configure(text=message)
            if message:
                self._message.grid()
            else:
                self._message.grid_remove()
        if action is not None:
            self._action.set(*action)
        if self._action.cget("text"):
            self._action.grid()
        else:
            self._action.grid_remove()
            self._message.grid_configure(pady=(px(2), px(13)))
        if self._timer is not None:
            self.after_cancel(self._timer)
            self._timer = None
        if timeout_ms:
            self._timer = self.after(timeout_ms, self.close)
        self._stack.layout()

    def _draw_icon(self) -> None:
        canvas = self._icon
        if self._spinner is not None:
            self._spinner.stop()
            self._spinner = None
        canvas.delete("all")
        name, colour, disc = _LEVEL_STYLE[self.level]
        size = int(canvas.cget("width"))
        canvas.create_oval(0, 0, size, size, fill=disc, outline=disc)
        if name:
            icons.draw(canvas, name, size / 2, size / 2, size * 0.55, colour, max(1.6, px(2)))
        else:
            inset = size * 0.24
            self._spinner = _Spinner(canvas, (inset, inset, size - inset, size - inset), colour, max(2, px(2)))

    def close(self) -> None:
        if self._spinner is not None:
            self._spinner.stop()
        self._stack.remove(self)
        self.destroy()


class Toasts:
    """Notifications stacked in the bottom-right corner of the window."""

    def __init__(self, root: tk.Misc) -> None:
        self.root = root
        self._items: list[Toast] = []

    def show(
        self,
        level: Level,
        title: str,
        message: str = "",
        *,
        action: tuple[str, Callable[[], None]] | None = None,
        timeout_ms: int | None = 6000,
    ) -> Toast:
        toast = Toast(self, level, title, message)
        self._items.append(toast)
        while len(self._items) > MAX_TOASTS:
            self._items[0].close()
        toast.update_toast(action=action, timeout_ms=timeout_ms)
        return toast

    def remove(self, toast: Toast) -> None:
        if toast in self._items:
            self._items.remove(toast)
            self.layout()

    def layout(self) -> None:
        offset = px(20)
        for toast in reversed(self._items):
            toast.update_idletasks()
            toast.place(relx=1.0, rely=1.0, x=-px(20), y=-offset, anchor="se", width=px(TOAST_WIDTH))
            toast.lift()
            offset += toast.winfo_reqheight() + px(10)

    def clear(self) -> None:
        for toast in list(self._items):
            toast.close()


# ------------------------------------------------------------------ banner

_BANNER_TONES = {
    "amber": (AMBER_SOFT, AMBER, "warning"),
    "red": (RED_SOFT, RED, "warning"),
    "accent": (ACCENT_SOFT, ACCENT, "info"),
}


class Banner(tk.Frame):
    """A full-width notice above the page, e.g. 'Register your public keys'."""

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, background=AMBER_SOFT)
        self._icon = tk.Canvas(self, width=px(18), height=px(18), background=AMBER_SOFT, highlightthickness=0)
        self._icon.pack(side="left", padx=(px(28), px(10)), pady=px(12))
        self._text = label(self, "", style="body", colour=INK)
        self._text.pack(side="left", pady=px(12))
        self._actions = tk.Frame(self, background=AMBER_SOFT)
        self._actions.pack(side="right", padx=px(24))

    def show(
        self, message: str, *, tone: str = "amber", actions: Sequence[tuple[str, Callable[[], None]]] = ()
    ) -> None:
        background, colour, icon = _BANNER_TONES[tone]
        for widget in (self, self._icon, self._text, self._actions):
            widget.configure(background=background)
        self._icon.delete("all")
        icons.draw(self._icon, icon, px(9), px(9), px(16), colour, max(1.6, px(1.8)))
        self._text.configure(text=message)
        for child in self._actions.winfo_children():
            child.destroy()
        for index, (text, command) in enumerate(actions):
            kind = "primary" if index == 0 else "ghost"
            Button(self._actions, text, command, kind=kind, size="sm").pack(side="left", padx=(px(8), 0))
