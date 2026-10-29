"""Design tokens: colours, type scale and sizes.

The GUI uses plain Tk widgets and draws its own controls on canvases, so it
looks the same on macOS, Windows and Linux and needs no ttk theme. The palette
is "graphite": neutral greys and a near-black accent for actions and selection.
Colour is reserved for state: green for passed checks and approvals, amber for
pending requests, red for failures and destructive actions.

Sizes are written in logical pixels. `px` scales them on high-DPI Windows and
Linux screens; fonts are created from the platform UI font at the same scale.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import font as tkfont

# --------------------------------------------------------------- colours

PAPER = "#F4F4F5"  # window, sidebar
SURFACE = "#FFFFFF"  # content area, inputs
SUNKEN = "#EAEAEC"  # segmented-control track
HOVER = "#F7F7F8"  # list row under the pointer
SELECTED = "#F0F0F2"  # selected list row
SIDEBAR_HOVER = "#E9E9EC"
LINE = "#E4E4E7"  # hairlines
LINE_STRONG = "#CDCDD3"  # input borders

INK = "#18181B"
INK_2 = "#52525B"
INK_3 = "#6E6E78"  # 5:1 on white, so captions meet WCAG AA

ACCENT = "#18181B"  # primary buttons, links, selection, focus
ACCENT_HOVER = "#2E2E33"
ACCENT_PRESSED = "#000000"
ACCENT_SOFT = "#EDEDF0"
ACCENT_SOFT_PRESSED = "#E1E1E6"
ACCENT_RING = "#A9A9B2"
ON_ACCENT = "#FFFFFF"  # text and icons on accent, success and red fills

SUCCESS = "#15803D"  # passed checks, approvals, "Verified"
SUCCESS_SOFT = "#E3F5E8"
SUCCESS_TEXT = "#166534"

AMBER = "#AA5008"
AMBER_SOFT = "#FDF1DC"
RED = "#B91C1C"
RED_HOVER = "#991B1B"
RED_PRESSED = "#7F1D1D"
RED_SOFT = "#FDECEC"
RED_SOFT_PRESSED = "#F9D2D2"
SLATE_SOFT = "#EFEFF1"

DISABLED_BG = "#EDEDEF"
DISABLED_FG = "#A1A1AA"

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
    """Logical pixels to device pixels."""
    return round(value * _scale)
