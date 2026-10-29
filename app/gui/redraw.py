"""Repaint after a window is mapped mid-draw (Tk on macOS).

Tk on macOS draws only inside the content view's drawRect, which sends Expose to
the windows mapped at that moment and then runs every pending idle task,
geometry management included. A window mapped by those idle tasks gets no
Expose, and Tk does not mark the view dirty while drawing (XMapWindow in
macosx/tkMacOSXSubwindows.c, Tk 8.6.13 to 8.6.16). It stays blank until
something else redraws that area, e.g. a hover effect.

Switching pages is the usual trigger: grid_remove unmaps the old page at once
and requests a redraw, grid maps the new page only when the idle queue runs, and
AppKit may call drawRect in between.

Workaround: after any mapping, request one more redraw from a timer. Timers never
run inside drawRect, so the request always lands after the mapping. Restacking a
hidden frame is a cheap way to ask: Tk marks its bounds dirty and AppKit redraws
the whole view.
"""

from __future__ import annotations

import tkinter as tk

DELAY_MS = 1


class Repainter:
    """One timer-driven repaint after each burst of <Map> events."""

    def __init__(self, root: tk.Misc, marker: tk.Misc) -> None:
        self._root = root
        self._marker = marker
        self._job: str | None = None
        root.bind_all("<Map>", self._mapped, add="+")

    def _mapped(self, _event: object = None) -> None:
        if self._job is None:  # one repaint for a burst of mappings
            self._job = self._root.after(DELAY_MS, self.repaint)

    def repaint(self) -> None:
        self._job = None
        try:
            # At least one of the two changes the stacking order, which is
            # what makes Tk mark the window dirty.
            self._marker.lower()
            self._marker.tkraise()
        except tk.TclError:  # the window is closing
            pass


def install(root: tk.Tk) -> Repainter | None:
    """Repaint after mappings on macOS; elsewhere Tk redraws mapped windows itself."""
    if root.tk.call("tk", "windowingsystem") != "aqua":
        return None
    marker = tk.Frame(root, width=1, height=1)  # never placed, so never visible
    marker.winfo_id()  # restacking reaches AppKit only once the window exists
    return Repainter(root, marker)
