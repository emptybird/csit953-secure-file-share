"""Line icons drawn on a Tk canvas, so they stay sharp on Retina and high-DPI screens.

Each icon fits a square of side `size` centred on (x, y) and is drawn with
round caps in a single colour. `draw(canvas, name, x, y, size, colour)` is the
only entry point; `logo` draws the app mark used on the login page and sidebar.
"""

from __future__ import annotations

import math
import tkinter as tk
from collections.abc import Callable

Icon = Callable[[tk.Canvas, float, float, float, str, float], None]


def _line(canvas: tk.Canvas, points: list[float], colour: str, width: float, **kwargs: object) -> None:
    canvas.create_line(*points, fill=colour, width=width, capstyle="round", joinstyle="round", **kwargs)


def _file(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    left, right, top, bottom, fold = x - s * 0.3, x + s * 0.3, y - s * 0.4, y + s * 0.4, s * 0.2
    _line(c, [right - fold, top, left, top, left, bottom, right, bottom, right, top + fold, right - fold, top], col, w)
    _line(c, [right - fold, top, right - fold, top + fold, right, top + fold], col, w)


def _files(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    _file(c, x + s * 0.07, y + s * 0.06, s * 0.88, col, w)
    left, top = x - s * 0.36, y - s * 0.42
    _line(c, [left, y + s * 0.24, left, top, x + s * 0.12, top], col, w)


def _shield(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    top, bottom, half = y - s * 0.42, y + s * 0.44, s * 0.33
    points = [x, top, x + half, top + s * 0.13, x + half, y + s * 0.02, x, bottom, x - half, y + s * 0.02]
    _line(c, [*points, x - half, top + s * 0.13, x, top], col, w)
    _line(c, [x - s * 0.14, y, x - s * 0.03, y + s * 0.11, x + s * 0.16, y - s * 0.1], col, w)


def _search(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    r, cx, cy = s * 0.26, x - s * 0.07, y - s * 0.07
    c.create_oval(cx - r, cy - r, cx + r, cy + r, outline=col, width=w)
    _line(c, [cx + r * 0.72, cy + r * 0.72, x + s * 0.36, y + s * 0.36], col, w)


def _activity(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    h = s * 0.32
    points = [x - s * 0.42, y, x - s * 0.2, y, x - s * 0.08, y - h, x + s * 0.08, y + h, x + s * 0.2, y]
    _line(c, [*points, x + s * 0.42, y], col, w)


def _key(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    r, cx = s * 0.17, x - s * 0.22
    c.create_oval(cx - r, y - r, cx + r, y + r, outline=col, width=w)
    _line(c, [cx + r, y, x + s * 0.4, y], col, w)
    _line(c, [x + s * 0.28, y, x + s * 0.28, y + s * 0.16], col, w)
    _line(c, [x + s * 0.14, y, x + s * 0.14, y + s * 0.12], col, w)


def _flask(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    top, bottom, neck = y - s * 0.4, y + s * 0.4, s * 0.1
    points = [x - neck, top, x - neck, y - s * 0.08, x - s * 0.34, bottom, x + s * 0.34, bottom]
    _line(c, [*points, x + neck, y - s * 0.08, x + neck, top], col, w)
    _line(c, [x - s * 0.17, top, x + s * 0.17, top], col, w)
    _line(c, [x - s * 0.2, y + s * 0.16, x + s * 0.2, y + s * 0.16], col, w)


def _lock(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    left, right, top, bottom = x - s * 0.3, x + s * 0.3, y - s * 0.02, y + s * 0.4
    _line(c, [left, top, right, top, right, bottom, left, bottom, left, top], col, w)
    r = s * 0.19
    c.create_arc(x - r, y - s * 0.42, x + r, y - s * 0.04, start=0, extent=180, style="arc", outline=col, width=w)
    _line(c, [x - r, y - s * 0.23, x - r, top], col, w)
    _line(c, [x + r, y - s * 0.23, x + r, top], col, w)


def _copy(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    a = s * 0.26
    _line(
        c,
        [x - a - s * 0.08, y + a - s * 0.08, x - a - s * 0.08, y - a - s * 0.08, x + a - s * 0.08, y - a - s * 0.08],
        col,
        w,
    )
    left, top = x - a + s * 0.08, y - a + s * 0.08
    _line(c, [left, top, left + 2 * a, top, left + 2 * a, top + 2 * a, left, top + 2 * a, left, top], col, w)


def _external(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    a = s * 0.34
    _line(c, [x - s * 0.05, y - a, x - a, y - a, x - a, y + a, x + a, y + a, x + a, y + s * 0.05], col, w)
    _line(c, [x, y, x + a, y - a], col, w)
    _line(c, [x + s * 0.08, y - a, x + a, y - a, x + a, y - s * 0.08], col, w)


def _check(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    _line(c, [x - s * 0.3, y + s * 0.02, x - s * 0.08, y + s * 0.24, x + s * 0.32, y - s * 0.22], col, w)


def _cross(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    a = s * 0.25
    _line(c, [x - a, y - a, x + a, y + a], col, w)
    _line(c, [x - a, y + a, x + a, y - a], col, w)


def _dash(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    _line(c, [x - s * 0.22, y, x + s * 0.22, y], col, w)


def _chevron_down(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    _line(c, [x - s * 0.24, y - s * 0.1, x, y + s * 0.14, x + s * 0.24, y - s * 0.1], col, w)


def _plus(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    a = s * 0.3
    _line(c, [x - a, y, x + a, y], col, w)
    _line(c, [x, y - a, x, y + a], col, w)


def _arrow_left(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    _line(c, [x + s * 0.32, y, x - s * 0.3, y], col, w)
    _line(c, [x - s * 0.08, y - s * 0.22, x - s * 0.3, y, x - s * 0.08, y + s * 0.22], col, w)


def _refresh(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    r = s * 0.3
    c.create_arc(x - r, y - r, x + r, y + r, start=40, extent=290, style="arc", outline=col, width=w)
    tip_x, tip_y = x + r * math.cos(math.radians(40)), y - r * math.sin(math.radians(40))
    _line(c, [tip_x - s * 0.16, tip_y - s * 0.04, tip_x, tip_y, tip_x + s * 0.02, tip_y - s * 0.16], col, w)


def _download(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    _line(c, [x, y - s * 0.38, x, y + s * 0.1], col, w)
    _line(c, [x - s * 0.18, y - s * 0.08, x, y + s * 0.1, x + s * 0.18, y - s * 0.08], col, w)
    _line(
        c,
        [
            x - s * 0.36,
            y + s * 0.18,
            x - s * 0.36,
            y + s * 0.36,
            x + s * 0.36,
            y + s * 0.36,
            x + s * 0.36,
            y + s * 0.18,
        ],
        col,
        w,
    )


def _warning(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    top, bottom, half = y - s * 0.38, y + s * 0.34, s * 0.42
    _line(c, [x, top, x + half, bottom, x - half, bottom, x, top], col, w)
    _line(c, [x, y - s * 0.1, x, y + s * 0.1], col, w)
    _line(c, [x, y + s * 0.22, x, y + s * 0.23], col, w)


def _info(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    r = s * 0.38
    c.create_oval(x - r, y - r, x + r, y + r, outline=col, width=w)
    _line(c, [x, y - s * 0.02, x, y + s * 0.18], col, w)
    _line(c, [x, y - s * 0.17, x, y - s * 0.16], col, w)


def _user(c: tk.Canvas, x: float, y: float, s: float, col: str, w: float) -> None:
    r = s * 0.16
    c.create_oval(x - r, y - s * 0.38, x + r, y - s * 0.38 + 2 * r, outline=col, width=w)
    c.create_arc(
        x - s * 0.32, y - s * 0.02, x + s * 0.32, y + s * 0.62, start=0, extent=180, style="arc", outline=col, width=w
    )


_ICONS: dict[str, Icon] = {
    "file": _file,
    "files": _files,
    "shield": _shield,
    "search": _search,
    "activity": _activity,
    "key": _key,
    "flask": _flask,
    "lock": _lock,
    "copy": _copy,
    "external": _external,
    "check": _check,
    "cross": _cross,
    "dash": _dash,
    "chevron_down": _chevron_down,
    "plus": _plus,
    "arrow_left": _arrow_left,
    "refresh": _refresh,
    "download": _download,
    "warning": _warning,
    "info": _info,
    "user": _user,
}


def draw(canvas: tk.Canvas, name: str, x: float, y: float, size: float, colour: str, width: float = 1.6) -> None:
    _ICONS[name](canvas, x, y, size, colour, width)


def logo(canvas: tk.Canvas, x: float, y: float, size: float, colour: str, paper: str) -> None:
    """A seal: filled disc with a shield and a check cut out of it."""
    r = size / 2
    canvas.create_oval(x - r, y - r, x + r, y + r, fill=colour, outline=colour)
    _shield(canvas, x, y + size * 0.01, size * 0.62, paper, max(1.5, size * 0.07))
