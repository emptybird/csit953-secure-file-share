"""The macOS repaint workaround in app/gui/redraw.py. Needs a display; skipped without one."""

from __future__ import annotations

import time
import tkinter as tk
from collections.abc import Iterator

import pytest

from app.gui import redraw


@pytest.fixture
def root() -> Iterator[tk.Tk]:
    try:
        window = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"no display: {exc}")
    window.withdraw()
    yield window
    window.destroy()


def _run_timers(root: tk.Tk) -> None:
    """Let the repaint timer come due, then process it."""
    time.sleep(redraw.DELAY_MS / 1000 + 0.02)
    root.update()


def test_installed_only_on_aqua(root: tk.Tk) -> None:
    aqua = root.tk.call("tk", "windowingsystem") == "aqua"
    assert (redraw.install(root) is not None) is aqua


def test_one_repaint_for_a_burst_of_mappings(root: tk.Tk, monkeypatch: pytest.MonkeyPatch) -> None:
    repainter = redraw.Repainter(root, tk.Frame(root, width=1, height=1))
    repaints: list[None] = []
    original = repainter.repaint
    monkeypatch.setattr(repainter, "repaint", lambda: (repaints.append(None), original()))
    frames = [tk.Frame(root) for _ in range(3)]
    for frame in frames:
        frame.winfo_id()  # Tk drops generated events for windows that do not exist yet
        frame.event_generate("<Map>")
    _run_timers(root)
    assert len(repaints) == 1
    frames[0].event_generate("<Map>")
    _run_timers(root)
    assert len(repaints) == 2
