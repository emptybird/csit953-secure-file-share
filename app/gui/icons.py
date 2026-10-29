"""Line icons drawn on a Tk canvas, so they stay sharp on Retina and high-DPI screens.

Each icon fits a square of side `size` centred on (x, y), drawn with round caps
in one colour. `draw(canvas, name, x, y, size, colour)` renders a named icon;
`logo` renders the app mark (login page, sidebar), matching assets/app-icon.png.
"""

from __future__ import annotations

import math
import tkinter as tk
from collections.abc import Callable

# (canvas, centre x, centre y, size, colour, stroke width)
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
    """Draw icon `name` centred on (x, y)."""
    _ICONS[name](canvas, x, y, size, colour, width)


def logo(canvas: tk.Canvas, x: float, y: float, size: float, colour: str, paper: str) -> None:
    """The app mark: a key whose bow is a block, on a rounded tile of side `size`.

    The geometry follows assets/app-icon.png, drawn on a 1024-unit grid whose
    tile spans units 100 to 924; the key is scaled by 1.06 about (466, 518)."""
    left, top = x - size / 2, y - size / 2
    unit = size / 824

    def at(gx: float, gy: float) -> tuple[float, float]:
        return left + (512 + 1.06 * (gx - 466) - 100) * unit, top + (512 + 1.06 * (gy - 518) - 100) * unit

    _tile(canvas, left, top, left + size, top + size, 2 * 184 * unit, colour)  # smoothing halves the radius
    cx, cy, r = 400.0, 392.0, 148.0
    corners = [
        (cx + r * math.cos(math.radians(a)), cy - r * math.sin(math.radians(a))) for a in (90, 30, -30, -90, -150, 150)
    ]
    _, upper_right, lower_right, bottom, _, upper_left = corners
    stroke = 1.06 * unit
    block = [c for corner in corners for c in at(*corner)]
    canvas.create_polygon(*block, fill="", outline=paper, width=52 * stroke, joinstyle="round")
    _line(canvas, [*at(*upper_left), *at(cx, cy), *at(*upper_right)], paper, 40 * stroke)
    _line(canvas, [*at(cx, cy), *at(*bottom)], paper, 40 * stroke)
    # The shaft leaves the block's lower-right face at right angles; two teeth point up and right.
    sx, sy = (lower_right[0] + bottom[0]) / 2, (lower_right[1] + bottom[1]) / 2
    along, across = (0.5, math.sqrt(3) / 2), (math.sqrt(3) / 2, -0.5)
    _line(canvas, [*at(sx, sy), *at(sx + along[0] * 360, sy + along[1] * 360)], paper, 56 * stroke)
    for distance in (250, 322):
        bx, by = sx + along[0] * distance, sy + along[1] * distance
        _line(canvas, [*at(bx, by), *at(bx + across[0] * 78, by + across[1] * 78)], paper, 56 * stroke)


def _tile(canvas: tk.Canvas, x1: float, y1: float, x2: float, y2: float, r: float, colour: str) -> None:
    """A filled square whose smoothed corners curve over about r / 2 (like widgets.rounded_rect)."""
    points = (
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
        x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    )  # fmt: skip
    canvas.create_polygon(points, smooth=True, splinesteps=16, fill=colour, outline=colour)
