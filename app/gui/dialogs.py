"""Confirmation dialog for actions that send a transaction.

Shows exactly what is about to be signed: the file, the account and, for an
approval, the fingerprint of the key the DEK will be wrapped to. The signing
screen is a security boundary. No button has focus on open, so a stray Enter
confirms nothing; Escape cancels.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Sequence
from dataclasses import dataclass

from app.gui.theme import INK, INK_2, LINE, PAPER, SURFACE, px
from app.gui.widgets import Button, hline, label


@dataclass(frozen=True)
class DialogField:
    """One label/value row; `mono` for ids and hashes, `emphasis` for the key fact."""

    label: str
    value: str
    mono: bool = False
    emphasis: bool = False


def confirm(
    parent: tk.Misc,
    title: str,
    heading: str,
    fields: Sequence[DialogField],
    note: str,
    confirm_text: str,
    *,
    danger: bool = False,
) -> bool:
    """Show a modal dialog; True only if the confirm button was pressed."""
    window = parent.winfo_toplevel()
    dialog = tk.Toplevel(window)
    dialog.title(title)
    dialog.configure(background=SURFACE)
    dialog.resizable(False, False)
    dialog.transient(window)
    result = {"ok": False}

    body = tk.Frame(dialog, background=SURFACE)
    body.pack(fill="both", expand=True, padx=px(28), pady=(px(24), px(20)))
    label(body, heading, style="heading").grid(row=0, column=0, columnspan=2, sticky="w")
    for index, field in enumerate(fields, start=1):
        label(body, field.label, style="small", colour=INK_2).grid(
            row=index, column=0, sticky="nw", padx=(0, px(20)), pady=(px(14) if index == 1 else px(6), 0)
        )
        style = (
            ("mono_strong" if field.emphasis else "mono") if field.mono else ("strong" if field.emphasis else "body")
        )
        label(body, field.value, style=style, colour=INK, wrap=440).grid(
            row=index, column=1, sticky="w", pady=(px(14) if index == 1 else px(6), 0)
        )
    row = len(fields) + 1
    hline(body, LINE).grid(row=row, column=0, columnspan=2, sticky="ew", pady=px(18))
    label(body, note, style="small", colour=INK_2, wrap=540).grid(row=row + 1, column=0, columnspan=2, sticky="w")

    footer = tk.Frame(dialog, background=PAPER)
    footer.pack(fill="x")
    hline(footer, LINE).pack(fill="x")
    buttons = tk.Frame(footer, background=PAPER)
    buttons.pack(side="right", padx=px(24), pady=px(14))

    def close(ok: bool) -> None:
        result["ok"] = ok
        dialog.grab_release()
        dialog.destroy()

    Button(buttons, "Cancel", lambda: close(False)).pack(side="left")
    accept = Button(buttons, confirm_text, lambda: close(True), kind="danger" if danger else "primary")
    accept.pack(side="left", padx=(px(10), 0))
    dialog.bind("<Escape>", lambda _e: close(False))
    dialog.protocol("WM_DELETE_WINDOW", lambda: close(False))

    # Centre over the parent, a third of the way down, then go modal.
    dialog.update_idletasks()
    x = window.winfo_rootx() + (window.winfo_width() - dialog.winfo_reqwidth()) // 2
    y = window.winfo_rooty() + (window.winfo_height() - dialog.winfo_reqheight()) // 3
    dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")
    dialog.wait_visibility()
    dialog.grab_set()
    dialog.focus_set()  # no button has focus, so a stray Enter confirms nothing
    dialog.wait_window()
    return result["ok"]
