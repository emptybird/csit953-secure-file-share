"""Controls drawn on canvases: buttons, text fields, selects, segmented controls,
checkboxes, badges and links (DESIGN.md 8).

Plain Tk cannot round corners or show hover states the same way on every
platform, so these controls draw themselves with the tokens in theme.py. Each
one can be reached with Tab, shows a focus ring, and can be driven from code
(`invoke`, `set`), which the screenshot scripts and tests rely on.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable, Sequence
from tkinter import font as tkfont

from app.gui import icons
from app.gui.theme import (
    ACCENT,
    ACCENT_HOVER,
    ACCENT_PRESSED,
    ACCENT_RING,
    ACCENT_SOFT,
    ACCENT_SOFT_PRESSED,
    AMBER,
    AMBER_SOFT,
    DISABLED_BG,
    DISABLED_FG,
    HOVER,
    INK,
    INK_2,
    INK_3,
    LINE,
    LINE_STRONG,
    ON_ACCENT,
    PAPER,
    RADIUS,
    RED,
    RED_HOVER,
    RED_PRESSED,
    RED_SOFT,
    RED_SOFT_PRESSED,
    SLATE_SOFT,
    SUCCESS_SOFT,
    SUCCESS_TEXT,
    SUNKEN,
    SURFACE,
    font,
    measure,
    px,
)

RING = 2  # px of room around a control for its focus ring


def surface_of(widget: tk.Misc) -> str:
    try:
        return str(widget.cget("background"))
    except tk.TclError:
        return PAPER


def rounded_rect(canvas: tk.Canvas, x1: float, y1: float, x2: float, y2: float, r: float, **kwargs: object) -> int:
    r = max(0.0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    points = (
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
        x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    )  # fmt: skip
    return canvas.create_polygon(points, smooth=True, splinesteps=16, **kwargs)


class _CanvasControl(tk.Canvas):
    """Shared plumbing: hover, press, focus and redraw on resize."""

    def __init__(self, parent: tk.Misc, *, width: int, height: int, focusable: bool = True) -> None:
        self._surface = surface_of(parent)
        super().__init__(
            parent,
            width=width,
            height=height,
            background=self._surface,
            highlightthickness=0,
            borderwidth=0,
            takefocus=1 if focusable else 0,
        )
        self._hover = False
        self._pressed = False
        self._focus = False
        self._enabled = True
        self.bind("<Enter>", lambda _e: self._set_flags(hover=True))
        self.bind("<Leave>", lambda _e: self._set_flags(hover=False, pressed=False))
        self.bind("<FocusIn>", lambda _e: self._set_flags(focus=True))
        self.bind("<FocusOut>", lambda _e: self._set_flags(focus=False))
        self.bind("<Configure>", lambda _e: self.redraw())

    def _set_flags(self, **flags: bool) -> None:
        for name, value in flags.items():
            setattr(self, f"_{name}", value)
        self.redraw()

    def set_surface(self, colour: str) -> None:
        """The background behind the control changed (e.g. a selected list row)."""
        self._surface = colour
        self.configure(background=colour)
        self.redraw()

    def extent(self) -> tuple[int, int]:
        width = self.winfo_width() if self.winfo_width() > 1 else int(self.cget("width"))
        height = self.winfo_height() if self.winfo_height() > 1 else int(self.cget("height"))
        return width, height

    def redraw(self) -> None:
        raise NotImplementedError


# ----------------------------------------------------------------- button

# kind: background, text, border, hover, pressed (None = the surface behind the button)
_BUTTON_KINDS: dict[str, tuple[str | None, str, str | None, str, str]] = {
    "primary": (ACCENT, ON_ACCENT, None, ACCENT_HOVER, ACCENT_PRESSED),
    "secondary": (SURFACE, INK, LINE_STRONG, HOVER, SUNKEN),
    "ghost": (None, ACCENT, None, ACCENT_SOFT, ACCENT_SOFT_PRESSED),
    "danger": (RED, ON_ACCENT, None, RED_HOVER, RED_PRESSED),
    "danger_ghost": (None, RED, None, RED_SOFT, RED_SOFT_PRESSED),
    "danger_outline": (SURFACE, RED, RED_SOFT_PRESSED, RED_SOFT, RED_SOFT_PRESSED),
    "quiet": (None, INK_2, None, HOVER, SUNKEN),
}
# size: visible height, horizontal padding, font
_BUTTON_SIZES = {"sm": (28, 10, "small_strong"), "md": (34, 14, "strong"), "lg": (40, 18, "strong")}


class Button(_CanvasControl):
    def __init__(
        self,
        parent: tk.Misc,
        text: str = "",
        command: Callable[[], None] | None = None,
        *,
        kind: str = "secondary",
        size: str = "md",
        icon: str | None = None,
        fill: bool = False,
    ) -> None:
        height, pad, font_name = _BUTTON_SIZES[size]
        self._text, self._command, self._kind, self._icon = text, command, kind, icon
        self._pad, self._font, self._fill = px(pad), font_name, fill
        self._height = px(height) + 2 * px(RING)
        super().__init__(parent, width=self._natural_width(), height=self._height)
        self.bind("<ButtonPress-1>", lambda _e: self._set_flags(pressed=True) if self._enabled else None)
        self.bind("<ButtonRelease-1>", self._released)
        self.bind("<KeyPress-space>", lambda _e: self.invoke())
        self.bind("<Return>", lambda _e: self.invoke())

    def _natural_width(self) -> int:
        icon = px(16) if self._icon else 0
        if not self._text:
            return self._height  # square icon button
        gap = px(7) if self._icon else 0
        return measure(self._font, self._text) + icon + gap + 2 * self._pad + 2 * px(RING)

    def _released(self, event: tk.Event) -> None:
        was_pressed = self._pressed
        self._set_flags(pressed=False)
        width, height = self.extent()
        if was_pressed and 0 <= event.x < width and 0 <= event.y < height:
            self.invoke()

    def invoke(self) -> None:
        if self._enabled and self._command is not None:
            self._command()

    def set_command(self, command: Callable[[], None] | None) -> None:
        self._command = command

    def set_enabled(self, enabled: bool) -> None:
        if enabled != self._enabled:
            self._enabled = enabled
            self.configure(takefocus=1 if enabled else 0)
            self.redraw()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def configure_button(
        self, *, text: str | None = None, kind: str | None = None, icon: str | None = None, enabled: bool | None = None
    ) -> None:
        self._text = self._text if text is None else text
        self._kind = self._kind if kind is None else kind
        self._icon = self._icon if icon is None else (icon or None)
        if not self._fill:
            self.configure(width=self._natural_width())
        if enabled is not None:
            self._enabled = not enabled  # force set_enabled to apply
            self.set_enabled(enabled)
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        width, height = self.extent()
        background, text, border, hover, pressed = _BUTTON_KINDS[self._kind]
        if not self._enabled:
            fill = DISABLED_BG if background else self._surface
            text, border = DISABLED_FG, None
        elif self._pressed:
            fill = pressed
        elif self._hover:
            fill = hover
        else:
            fill = background or self._surface
        ring = px(RING)
        if self._focus and self._enabled:
            rounded_rect(self, 1, 1, width - 1, height - 1, px(RADIUS) + ring, fill="", outline=ACCENT_RING, width=ring)
        rounded_rect(
            self, ring, ring, width - ring, height - ring, px(RADIUS), fill=fill, outline=border or fill, width=1
        )
        icon_size = px(16) if self._icon else 0
        gap = px(7) if self._icon and self._text else 0
        content = icon_size + gap + (measure(self._font, self._text) if self._text else 0)
        x = (width - content) / 2
        if self._icon:
            icons.draw(self, self._icon, x + icon_size / 2, height / 2, icon_size, text, max(1.4, px(1.6)))
        if self._text:
            self.create_text(
                x + icon_size + gap, height / 2, text=self._text, fill=text, font=font(self._font), anchor="w"
            )


# ------------------------------------------------------------------ field


class Field(_CanvasControl):
    """A single-line text input with a rounded border, focus ring and placeholder."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        placeholder: str = "",
        secret: bool = False,
        mono: bool = False,
        width: int = 240,
        on_change: Callable[[str], None] | None = None,
        on_return: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent, width=px(width), height=px(34) + 2 * px(RING), focusable=False)
        self._placeholder = "" if secret else placeholder
        self._showing_placeholder = False
        self._error = False
        self._text_font = font("mono" if mono else "body")
        self.entry = tk.Entry(
            self,
            borderwidth=0,
            relief="flat",
            highlightthickness=0,
            background=SURFACE,
            foreground=INK,
            insertbackground=INK,
            insertwidth=1,
            font=self._text_font,
            show="•" if secret else "",
            disabledbackground=SURFACE,
            readonlybackground=SURFACE,
            selectbackground=ACCENT_SOFT,
            selectforeground=INK,
        )
        self._window = self.create_window(px(12) + px(RING), 0, window=self.entry, anchor="w")
        self.entry.bind("<FocusIn>", lambda _e: self._focus_changed(True))
        self.entry.bind("<FocusOut>", lambda _e: self._focus_changed(False))
        if on_change is not None:
            self.entry.bind("<KeyRelease>", lambda _e: on_change(self.get()))
        if on_return is not None:
            self.entry.bind("<Return>", lambda _e: on_return())
        self.bind("<Button-1>", lambda _e: self.entry.focus_set())
        self.configure(cursor="xterm")
        self._show_placeholder()

    def _focus_changed(self, focused: bool) -> None:
        if focused:
            self._hide_placeholder()
        else:
            self._show_placeholder()
        self._set_flags(focus=focused)

    def _show_placeholder(self) -> None:
        if self._placeholder and not self.entry.get():
            self._showing_placeholder = True
            self.entry.insert(0, self._placeholder)
            self.entry.configure(foreground=INK_3, font=font("body"))

    def _hide_placeholder(self) -> None:
        if self._showing_placeholder:
            self.entry.delete(0, "end")
            self.entry.configure(foreground=INK, font=self._text_font)
            self._showing_placeholder = False

    def get(self) -> str:
        return "" if self._showing_placeholder else self.entry.get()

    def set(self, text: str) -> None:
        self._hide_placeholder()
        self.entry.delete(0, "end")
        self.entry.insert(0, text)
        if self.focus_get() is not self.entry:
            self._show_placeholder()

    def clear(self) -> None:
        self.set("")

    def focus(self) -> None:
        self.entry.focus_set()

    def set_error(self, error: bool) -> None:
        self._error = error
        self.redraw()

    def redraw(self) -> None:
        self.delete("frame")
        width, height = self.extent()
        ring = px(RING)
        if self._focus:
            rounded_rect(
                self,
                1,
                1,
                width - 1,
                height - 1,
                px(RADIUS) + ring,
                fill="",
                outline=ACCENT_RING,
                width=ring,
                tags="frame",
            )
        border = RED if self._error else ACCENT if self._focus else LINE_STRONG
        rounded_rect(
            self, ring, ring, width - ring, height - ring, px(RADIUS), fill=SURFACE, outline=border, tags="frame"
        )
        self.tag_lower("frame")
        self.coords(self._window, px(12) + ring, height / 2)
        self.itemconfigure(self._window, width=max(px(20), width - 2 * px(12) - 2 * ring))


# ----------------------------------------------------------------- select


class Select(_CanvasControl):
    """A dropdown showing one of `options` (value, label); opens a native menu."""

    def __init__(
        self,
        parent: tk.Misc,
        options: Sequence[tuple[str, str]],
        *,
        value: str | None = None,
        width: int = 240,
        on_change: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(parent, width=px(width), height=px(34) + 2 * px(RING))
        self._choices = list(options)
        self._var = tk.StringVar(self, value=value or (self._choices[0][0] if self._choices else ""))
        self._on_change = on_change
        self.bind("<Button-1>", lambda _e: self._open())
        self.bind("<KeyPress-space>", lambda _e: self._open())
        self.bind("<Down>", lambda _e: self._open())

    def get(self) -> str:
        return self._var.get()

    def set(self, value: str) -> None:
        self._var.set(value)
        self.redraw()

    def set_options(self, options: Sequence[tuple[str, str]], value: str | None = None) -> None:
        self._choices = list(options)
        values = [v for v, _ in self._choices]
        current = value if value in values else (self.get() if self.get() in values else (values[0] if values else ""))
        self.set(current)

    def _open(self) -> None:
        if not self._choices:
            return
        menu = tk.Menu(self, tearoff=0, font=font("body"), background=SURFACE, foreground=INK)
        menu.configure(activebackground=ACCENT_SOFT, activeforeground=INK, borderwidth=0, relief="flat")
        for value, label in self._choices:
            menu.add_radiobutton(label=label, value=value, variable=self._var, command=self._changed)
        try:
            menu.tk_popup(self.winfo_rootx(), self.winfo_rooty() + self.winfo_height())
        finally:
            menu.grab_release()

    def _changed(self) -> None:
        self.redraw()
        if self._on_change is not None:
            self._on_change(self.get())

    def redraw(self) -> None:
        self.delete("all")
        width, height = self.extent()
        ring = px(RING)
        if self._focus:
            rounded_rect(self, 1, 1, width - 1, height - 1, px(RADIUS) + ring, fill="", outline=ACCENT_RING, width=ring)
        border = ACCENT if self._focus else INK_3 if self._hover else LINE_STRONG
        rounded_rect(self, ring, ring, width - ring, height - ring, px(RADIUS), fill=SURFACE, outline=border)
        label = dict(self._choices).get(self.get(), "Choose…")
        self.create_text(ring + px(12), height / 2, text=label, anchor="w", fill=INK, font=font("body"))
        icons.draw(self, "chevron_down", width - ring - px(16), height / 2, px(14), INK_2, max(1.4, px(1.6)))


# -------------------------------------------------------------- segmented


class Segmented(_CanvasControl):
    """Two or three mutually exclusive views, e.g. All files / My requests."""

    def __init__(
        self,
        parent: tk.Misc,
        options: Sequence[tuple[str, str]],
        *,
        value: str,
        on_change: Callable[[str], None] | None = None,
    ) -> None:
        self._choices = list(options)
        self._value = value
        self._on_change = on_change
        self._widths = [measure("small_strong", label) + 2 * px(16) for _, label in self._choices]
        width = sum(self._widths) + 2 * px(3) + 2 * px(RING)
        super().__init__(parent, width=width, height=px(32) + 2 * px(RING))
        self.bind("<Button-1>", self._clicked)
        self.bind("<Left>", lambda _e: self._step(-1))
        self.bind("<Right>", lambda _e: self._step(1))

    def get(self) -> str:
        return self._value

    def set(self, value: str, *, notify: bool = True) -> None:
        if value == self._value:
            return
        self._value = value
        self.redraw()
        if notify and self._on_change is not None:
            self._on_change(value)

    def _clicked(self, event: tk.Event) -> None:
        x = px(RING) + px(3)
        for (value, _), width in zip(self._choices, self._widths, strict=True):
            if x <= event.x < x + width:
                self.set(value)
                return
            x += width

    def _step(self, delta: int) -> None:
        values = [v for v, _ in self._choices]
        self.set(values[(values.index(self._value) + delta) % len(values)])

    def redraw(self) -> None:
        self.delete("all")
        width, height = self.extent()
        ring, inset = px(RING), px(3)
        if self._focus:
            rounded_rect(self, 1, 1, width - 1, height - 1, px(RADIUS) + ring, fill="", outline=ACCENT_RING, width=ring)
        rounded_rect(self, ring, ring, width - ring, height - ring, px(RADIUS), fill=SUNKEN, outline=SUNKEN)
        x = ring + inset
        for (value, label), segment in zip(self._choices, self._widths, strict=True):
            selected = value == self._value
            if selected:
                rounded_rect(
                    self,
                    x,
                    ring + inset,
                    x + segment,
                    height - ring - inset,
                    px(RADIUS - 2),
                    fill=SURFACE,
                    outline=LINE_STRONG,
                )
            colour = INK if selected else INK_2
            self.create_text(x + segment / 2, height / 2, text=label, fill=colour, font=font("small_strong"))
            x += segment


# --------------------------------------------------------------- checkbox


class Checkbox(tk.Frame):
    def __init__(
        self, parent: tk.Misc, text: str, *, value: bool = False, command: Callable[[bool], None] | None = None
    ) -> None:
        surface = surface_of(parent)
        super().__init__(parent, background=surface)
        self._value = value
        self._command = command
        self._focus = False
        size = px(18)
        self._box = tk.Canvas(self, width=size, height=size, background=surface, highlightthickness=0, takefocus=1)
        self._box.pack(side="left")
        self._label = tk.Label(self, text=text, background=surface, foreground=INK, font=font("small"))
        self._label.pack(side="left", padx=(px(7), 0))
        for widget in (self, self._box, self._label):
            widget.bind("<Button-1>", lambda _e: self.toggle())
        self._box.bind("<KeyPress-space>", lambda _e: self.toggle())
        self._box.bind("<FocusIn>", lambda _e: self._set_focus(True))
        self._box.bind("<FocusOut>", lambda _e: self._set_focus(False))
        self._draw()

    def get(self) -> bool:
        return self._value

    def set(self, value: bool) -> None:
        self._value = value
        self._draw()

    def toggle(self) -> None:
        self.set(not self._value)
        if self._command is not None:
            self._command(self._value)

    def _set_focus(self, focused: bool) -> None:
        self._focus = focused
        self._draw()

    def _draw(self) -> None:
        box = self._box
        box.delete("all")
        size = int(box.cget("width"))
        inset = px(1)
        outline = ACCENT if self._value or self._focus else LINE_STRONG
        rounded_rect(
            box,
            inset,
            inset,
            size - inset,
            size - inset,
            px(4),
            fill=ACCENT if self._value else SURFACE,
            outline=outline,
        )
        if self._value:
            icons.draw(box, "check", size / 2, size / 2, size * 0.8, ON_ACCENT, max(1.6, px(2)))


# ------------------------------------------------------------------ badge

# tone: background, text. "success" is for outcomes (approved, registered, verified);
# "accent" is neutral emphasis (network, shared files).
TONES = {
    "accent": (ACCENT_SOFT, ACCENT_HOVER),
    "success": (SUCCESS_SOFT, SUCCESS_TEXT),
    "amber": (AMBER_SOFT, AMBER),
    "red": (RED_SOFT, RED),
    "slate": (SLATE_SOFT, INK_2),
    "solid": (ACCENT, ON_ACCENT),
}


class Badge(tk.Canvas):
    """A small rounded label for a status, e.g. Pending or Approved."""

    def __init__(self, parent: tk.Misc, text: str = "", tone: str = "slate", *, dot: bool = False) -> None:
        self._surface = surface_of(parent)
        self._text, self._tone, self._dot = text, tone, dot
        super().__init__(parent, height=px(22), width=1, background=self._surface, highlightthickness=0, borderwidth=0)
        self._draw()

    def set(self, text: str, tone: str | None = None) -> None:
        self._text = text
        self._tone = tone or self._tone
        self._draw()

    def set_surface(self, colour: str) -> None:
        self._surface = colour
        self.configure(background=colour)
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        if not self._text:
            self.configure(width=1)
            return
        background, colour = TONES[self._tone]
        height = px(22)
        dot = px(12) if self._dot else 0
        width = measure("small_strong", self._text) + 2 * px(9) + dot
        self.configure(width=width)
        rounded_rect(self, 0, 0, width, height, height / 2, fill=background, outline=background)
        if self._dot:
            r = px(3)
            self.create_oval(
                px(9) - r + px(1), height / 2 - r, px(9) + r + px(1), height / 2 + r, fill=colour, outline=colour
            )
        self.create_text(px(9) + dot, height / 2, text=self._text, anchor="w", fill=colour, font=font("small_strong"))


# ------------------------------------------------------------------- link


class Link(tk.Label):
    """Text that runs `command` when clicked; underlined while the pointer is over it."""

    def __init__(self, parent: tk.Misc, text: str, command: Callable[[], None] | None, *, mono: bool = False) -> None:
        self._font_name = "mono_small" if mono else "small_strong"
        super().__init__(
            parent,
            text=text,
            background=surface_of(parent),
            foreground=ACCENT,
            font=font(self._font_name),
            padx=0,
            pady=0,
        )
        self._command = command
        self.bind("<Button-1>", lambda _e: self._command() if self._command else None)
        self.bind("<Enter>", lambda _e: self.configure(font=(*_font_tuple(self._font_name), "underline")))
        self.bind("<Leave>", lambda _e: self.configure(font=font(self._font_name)))

    def set(self, text: str, command: Callable[[], None] | None) -> None:
        self.configure(text=text)
        self._command = command


def _font_tuple(name: str) -> tuple[str, int, str]:
    actual = tkfont.nametofont(font(name)).actual()
    return (actual["family"], actual["size"], actual["weight"])


def label(
    parent: tk.Misc,
    text: str = "",
    *,
    style: str = "body",
    colour: str = INK,
    wrap: int = 0,
    **kwargs: object,
) -> tk.Label:
    """A tk.Label on the parent's background with the given font and colour."""
    widget = tk.Label(
        parent,
        text=text,
        background=surface_of(parent),
        foreground=colour,
        font=font(style),
        justify="left",
        anchor="w",
        padx=0,
        pady=0,
        **kwargs,
    )
    if wrap:
        widget.configure(wraplength=px(wrap))
    return widget


def hline(parent: tk.Misc, colour: str = LINE) -> tk.Frame:
    return tk.Frame(parent, height=1, background=colour)


def vline(parent: tk.Misc, colour: str = LINE) -> tk.Frame:
    return tk.Frame(parent, width=1, background=colour)


class IconCanvas(tk.Canvas):
    """A fixed-size canvas showing one icon, optionally on a filled circle."""

    def __init__(
        self, parent: tk.Misc, name: str, *, size: int = 16, colour: str = INK_2, disc: str | None = None
    ) -> None:
        surface = surface_of(parent)
        box = px(size) if disc is None else px(size) * 2
        super().__init__(parent, width=box, height=box, background=surface, highlightthickness=0, borderwidth=0)
        self._icon_name, self._size, self._colour, self._disc = name, size, colour, disc
        self._draw()

    def set(self, name: str | None = None, colour: str | None = None, disc: str | None = None) -> None:
        self._icon_name = name or self._icon_name
        self._colour = colour or self._colour
        self._disc = disc or self._disc
        self._draw()

    def set_surface(self, colour: str) -> None:
        self.configure(background=colour)

    def _draw(self) -> None:
        self.delete("all")
        box = int(self.cget("width"))
        if self._disc is not None:
            self.create_oval(0, 0, box, box, fill=self._disc, outline=self._disc)
        icons.draw(self, self._icon_name, box / 2, box / 2, px(self._size), self._colour, max(1.4, px(1.6)))
