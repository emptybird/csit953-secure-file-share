"""Design tokens: colours, type scale and sizes (DESIGN.md 8, 8.1).

The GUI uses plain Tk widgets and draws its own controls on canvases, so it
looks the same on macOS, Windows and Linux and needs no ttk theme. One accent,
"ledger green", marks what is trusted or actionable; amber, red and slate are
kept for request and check states.

Sizes are written in logical pixels. `px` scales them on high-DPI Windows and
Linux screens; fonts are created from the platform UI font at the same scale.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import font as tkfont

# --------------------------------------------------------------- colours

PAPER = "#F4F6F5"  # window, sidebar
SURFACE = "#FFFFFF"  # content area, inputs
SUNKEN = "#EAEEEC"  # segmented-control track
HOVER = "#F2F5F3"  # list row under the pointer
SELECTED = "#E6F2EC"  # selected list row
SIDEBAR_HOVER = "#E8ECEA"
LINE = "#E1E6E3"  # hairlines
LINE_STRONG = "#C8D1CC"  # input borders

INK = "#17201C"
INK_2 = "#5A6661"
INK_3 = "#8E9994"

ACCENT = "#0F6E56"
ACCENT_HOVER = "#0B5C48"
ACCENT_PRESSED = "#084A3A"
ACCENT_SOFT = "#E2F1EA"
ACCENT_SOFT_PRESSED = "#CFE7DC"
ACCENT_RING = "#9CD0BC"

AMBER = "#955600"
AMBER_SOFT = "#FCEFD8"
RED = "#B3261E"
RED_HOVER = "#951F18"
RED_PRESSED = "#7A1913"
RED_SOFT = "#FBE9E7"
RED_SOFT_PRESSED = "#F5D3CF"
SLATE_SOFT = "#ECF0EE"

DISABLED_BG = "#E6EBE8"
DISABLED_FG = "#9BA6A0"
WHITE = "#FFFFFF"

# ---------------------------------------------------------------- sizes

SIDEBAR_WIDTH = 236
DETAIL_WIDTH = 392
PAGE_PAD = 32
RADIUS = 7
PANEL_RADIUS = 11

# name: (logical pixels, weight)
_UI_FONTS = {
    "display": (26, "bold"),
    "title": (21, "bold"),
    "heading": (15, "bold"),
    "body": (13, "normal"),
    "strong": (13, "bold"),
    "small": (12, "normal"),
    "small_strong": (12, "bold"),
    "caption": (11, "normal"),
}
_MONO_FONTS = {
    "mono": (12, "normal"),
    "mono_small": (11, "normal"),
    "mono_strong": (14, "bold"),
}
_MONO_CANDIDATES = ("Menlo", "SF Mono", "Cascadia Mono", "Consolas", "DejaVu Sans Mono")

_scale = 1.0
_FONTS: dict[str, tkfont.Font] = {}


def init(root: tk.Tk) -> None:
    """Create the named fonts and set the scale; call once per process before building widgets."""
    global _scale
    # macOS measures in points that are already logical pixels; elsewhere 96 dpi is 1.0.
    _scale = 1.0 if sys.platform == "darwin" else max(1.0, root.winfo_fpixels("1i") / 96.0)
    ui_family = tkfont.nametofont("TkDefaultFont").actual("family")
    installed = set(tkfont.families(root))
    mono_family = next(
        (name for name in _MONO_CANDIDATES if name in installed), tkfont.nametofont("TkFixedFont").actual("family")
    )
    for name, (size, weight) in _UI_FONTS.items():
        _named_font(root, name, ui_family, size, weight)
    for name, (size, weight) in _MONO_FONTS.items():
        _named_font(root, name, mono_family, size, weight)
    root.configure(background=PAPER)
    root.option_add("*Font", font("body"))


def _named_font(root: tk.Misc, name: str, family: str, size: int, weight: str) -> None:
    # Tk sizes are points; 0.75 pt per px at 96 dpi, and Tk itself scales points on high-DPI screens.
    points = size if sys.platform == "darwin" else max(1, round(size * 0.75))
    try:
        # Keep a reference: tkinter deletes a named font when its Font object is garbage-collected.
        _FONTS[name] = tkfont.Font(root=root, name=font(name), family=family, size=points, weight=weight)
    except tk.TclError:  # an earlier window in this process created it
        tkfont.nametofont(font(name)).configure(family=family, size=points, weight=weight)


def font(name: str) -> str:
    """The Tk name of one of the fonts above, usable as a `font=` option."""
    return f"sfs-{name}"


def measure(name: str, text: str) -> int:
    return tkfont.nametofont(font(name)).measure(text)


def line_height(name: str) -> int:
    return tkfont.nametofont(font(name)).metrics("linespace")


def px(value: float) -> int:
    return round(value * _scale)
