"""Protect a file page: encrypt, sign, upload and register one file, each stage
shown as it finishes.

    1 Encrypt     new DEK, AES-256-GCM over header + content
    2 Sign        ECDSA over the manifest (ctHash, salted plaintext digest)
    3 Upload      ciphertext object and signed manifest to storage
    4 Register    registerFile(...) transaction; tx hash as soon as it is sent
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog

from app.chain.client import SubmittedCallback
from app.gui import icons
from app.gui.feedback import StepChain, StepState
from app.gui.format import file_id_text, format_size, short_hex
from app.gui.host import Host
from app.gui.layout import Panel
from app.gui.page import Page
from app.gui.theme import (
    ACCENT,
    ACCENT_SOFT,
    INK,
    INK_2,
    INK_3,
    LINE_STRONG,
    PAGE_PAD,
    RADIUS,
    RED,
    SUCCESS,
    SUCCESS_SOFT,
    SURFACE,
    font,
    measure,
    px,
)
from app.gui.widgets import Button, Field, Link, hline, label, rounded_rect
from app.gui.worker import describe_error
from app.services.models import ProtectedFile, ProtectStage
from app.services.owner import MAX_FILE_BYTES, MAX_LABEL_BYTES, OwnerService

FORM_WIDTH = 380
STEPS_WRAP = 400
# (key, title, what happens)
_STEPS = (
    ("encrypt", "Encrypt with AES-256-GCM", "A new 256-bit file key is generated for this file only."),
    ("sign", "Sign the manifest", "Your signing key signs the ciphertext hash and a salted content digest."),
    ("upload", "Upload the ciphertext", "Only the encrypted object and the signed manifest are stored."),
    ("register", "Register on-chain", "registerFile records the hashes and your wrapped copy of the file key."),
)
# finished stage -> (step to mark done, step to start)
_STAGE_DONE = {
    ProtectStage.ENCRYPTED: ("encrypt", "sign"),
    ProtectStage.SIGNED: ("sign", "upload"),
    ProtectStage.UPLOADED: ("upload", "register"),
}


class FilePicker(tk.Canvas):
    """A dashed drop-zone style button that opens the file dialog."""

    def __init__(self, parent: tk.Misc, on_pick: Callable[[], None]) -> None:
        super().__init__(parent, height=px(92), width=px(FORM_WIDTH), background=SURFACE, highlightthickness=0)
        self._on_pick = on_pick
        self._path: Path | None = None
        self._size = 0
        self._protected = False
        self._hover = False
        self.bind("<Configure>", lambda _e: self._draw())
        self.bind("<Button-1>", lambda _e: self._on_pick())
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))

    def show(self, path: Path | None, size: int = 0, *, protected: bool = False) -> None:
        self._path, self._size, self._protected = path, size, protected
        self._draw()

    def _set_hover(self, hover: bool) -> None:
        self._hover = hover
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        width, height = self.winfo_width(), self.winfo_height()
        fill = ACCENT_SOFT if self._hover else SURFACE
        outline = ACCENT if self._hover else LINE_STRONG
        rounded_rect(self, 1, 1, width - 1, height - 1, px(RADIUS + 3), fill=fill, outline=outline, dash=(5, 4))
        x, y = px(36), height / 2
        icons.draw(self, "file", x, y, px(28), ACCENT, max(1.6, px(1.8)))
        if self._path is None:
            self.create_text(px(64), y - px(9), text="Choose a file", anchor="w", fill=ACCENT, font=font("strong"))
            limit = f"Any type, up to {round(MAX_FILE_BYTES / (1024 * 1024))} MB"
            self.create_text(px(64), y + px(10), text=limit, anchor="w", fill=INK_3, font=font("small"))
            return
        action = "Choose another" if self._protected else "Change"
        name = _fit(self._path.name, width - px(84) - measure("small_strong", action))
        self.create_text(px(64), y - px(9), text=name, anchor="w", fill=INK, font=font("strong"))
        if self._protected:
            note, colour = "Protected and registered", SUCCESS
        else:
            note, colour = format_size(self._size), INK_2
        self.create_text(px(64), y + px(10), text=note, anchor="w", fill=colour, font=font("small"))
        self.create_text(width - px(18), y, text=action, anchor="e", fill=ACCENT, font=font("small_strong"))


def _fit(text: str, width: int) -> str:
    """Shorten `text` with an ellipsis until it fits `width` pixels in the strong font."""
    if measure("strong", text) <= width:
        return text
    while text and measure("strong", text + "…") > width:
        text = text[:-1]
    return text + "…"


class ProtectPage(Page):
    key = "protect"

    def __init__(self, parent: tk.Misc, host: Host) -> None:
        super().__init__(
            parent,
            host,
            "Protect a file",
            "Files are encrypted and signed on this computer. Only ciphertext is uploaded.",
        )
        self._owner = OwnerService(host.session)
        self._chosen: Path | None = None
        self._running = False
        self._tx_hash = ""
        hline(self.content).pack(fill="x")
        body = tk.Frame(self.content, background=SURFACE)
        body.pack(fill="both", expand=True, padx=px(PAGE_PAD), pady=px(28))
        form = tk.Frame(body, background=SURFACE, width=px(FORM_WIDTH))
        form.pack(side="left", anchor="n")
        steps = tk.Frame(body, background=SURFACE)
        steps.pack(side="left", anchor="n", fill="x", expand=True, padx=(px(56), 0))
        self._build_form(form)
        self._build_steps(steps)

    def _build_form(self, form: tk.Frame) -> None:
        label(form, "File", style="small_strong").pack(anchor="w", pady=(0, px(8)))
        self._picker = FilePicker(form, self._choose)
        self._picker.pack(fill="x")
        caption = tk.Frame(form, background=SURFACE)
        caption.pack(fill="x", pady=(px(22), px(8)))
        label(caption, "Public label", style="small_strong").pack(side="left")
        label(caption, "Optional", style="small", colour=INK_3).pack(side="right")
        self._label = Field(form, placeholder="For example: Q3 report", width=FORM_WIDTH)
        self._label.pack(fill="x")
        note = (
            f"The label is public on-chain (up to {MAX_LABEL_BYTES} bytes). The file name is encrypted "
            "with the file, so only you and approved recipients can read it."
        )
        label(form, note, style="small", colour=INK_2, wrap=FORM_WIDTH).pack(anchor="w", pady=(px(8), 0))
        self._button = Button(form, "Protect and register", self._protect, kind="primary", size="lg", fill=True)
        self._button.pack(fill="x", pady=(px(26), 0))
        self._button.set_enabled(False)
        self._error = label(form, "", style="small", colour=RED, wrap=FORM_WIDTH)
        self._error.pack(anchor="w", pady=(px(10), 0))

    def _build_steps(self, column: tk.Frame) -> None:
        label(column, "Steps", style="heading").pack(anchor="w", pady=(0, px(16)))
        self._steps = StepChain(column, _STEPS, wrap=STEPS_WRAP)
        self._steps.pack(anchor="w", fill="x")
        self._result = Panel(column, padding=20, background=SUCCESS_SOFT, border=SUCCESS_SOFT)
        result = self._result.body
        label(result, "Registered", style="heading").pack(anchor="w")
        text = "Share the file ID with the intended recipients. They use it to request access."
        label(result, text, style="small", colour=INK_2, wrap=STEPS_WRAP).pack(anchor="w", pady=(px(4), px(10)))
        self._result_id = label(result, "", style="mono", wrap=STEPS_WRAP)
        self._result_id.pack(anchor="w")
        buttons = tk.Frame(result, background=SUCCESS_SOFT)
        buttons.pack(anchor="w", pady=(px(14), 0))
        Button(buttons, "Copy file ID", self._copy_id, kind="secondary", size="sm", icon="copy").pack(side="left")
        Link(buttons, "Open in My files", self._open_file).pack(side="left", padx=(px(16), 0))
        self._protected: ProtectedFile | None = None

    # --------------------------------------------------------------- actions

    def _choose(self) -> None:
        """Pick a file; resets the steps for a fresh run."""
        if self._running:
            return
        name = filedialog.askopenfilename(parent=self, title="Choose a file to protect")
        if not name:
            return
        path = Path(name)
        try:
            size = path.stat().st_size
        except OSError as exc:
            self._error.configure(text=f"Cannot read {path.name}: {exc.strerror or exc}")
            return
        self._chosen = path
        self._picker.show(path, size)
        self._error.configure(text="")
        self._steps.reset()
        self._result.pack_forget()
        self._update_button()

    def _protect(self) -> None:
        """Run protect_file as one transaction; its progress reports drive the step chain."""
        path, text = self._chosen, self._label.get().strip()
        if path is None:
            return
        self._running = True
        self._tx_hash = ""
        self._error.configure(text="")
        self._result.pack_forget()
        self._steps.reset()
        self._steps.set("encrypt", StepState.RUNNING, "Generating a file key and encrypting…")
        self._update_button()
        worker = self.host.worker

        def job(on_submitted: SubmittedCallback) -> ProtectedFile:
            # Runs on the worker thread: pass the tx hash on, hand UI updates to the Tk thread.
            def progress(stage: ProtectStage, detail: str) -> None:
                if stage is ProtectStage.SUBMITTED:
                    on_submitted(detail)
                worker.call_soon(lambda: self._stage(stage, detail), owner=self)

            return self._owner.protect_file(path, text, on_progress=progress)

        if not self.host.run_transaction("Protect and register", job, self._done, self._failed, done="File registered"):
            # Another transaction is pending: roll back the optimistic UI.
            self._running = False
            self._steps.reset()
            self._update_button()

    def _stage(self, stage: ProtectStage, detail: str) -> None:
        """Map one progress report onto the step chain."""
        if stage in _STAGE_DONE:
            done, running = _STAGE_DONE[stage]
            self._steps.set(done, StepState.DONE, _describe(stage, detail))
            self._steps.set(running, StepState.RUNNING, "Submitting the transaction…" if running == "register" else "")
        elif stage is ProtectStage.SUBMITTED:
            self._tx_hash = detail
            self._steps.set(
                "register",
                StepState.RUNNING,
                f"Submitted as {short_hex(detail, 8, 6)}. Awaiting confirmation.",
                on_click=self.host.tx_action(detail)[1],
            )
        elif stage is ProtectStage.CONFIRMED:
            self._steps.set(
                "register",
                StepState.DONE,
                f"Confirmed: {detail}. Transaction {short_hex(self._tx_hash, 8, 6)}.",
                on_click=self.host.tx_action(self._tx_hash)[1] if self._tx_hash else None,
            )

    def _done(self, protected: ProtectedFile) -> None:
        self._running = False
        self._protected = protected
        self._picker.show(self._chosen, protected.size, protected=True)
        self._chosen = None
        self._label.clear()
        self._result_id.configure(text=file_id_text(protected.file_id))
        self._result.pack(anchor="w", fill="x", pady=(px(24), 0))
        self._update_button()

    def _failed(self, exc: BaseException) -> None:
        """Fail the running step, or show the error under the form if none was running."""
        self._running = False
        running = self._steps.running()
        message = describe_error(exc)
        if running is not None:
            self._steps.set(running, StepState.FAILED, message)
        else:
            self._error.configure(text=message)
        self._update_button()

    def _copy_id(self) -> None:
        if self._protected is not None:
            self.host.copy_to_clipboard(file_id_text(self._protected.file_id), "File ID")

    def _open_file(self) -> None:
        if self._protected is not None:
            self.host.navigate("files", file_id=self._protected.file_id)

    def on_busy_changed(self) -> None:
        self._update_button()

    def _update_button(self) -> None:
        ready = self._chosen is not None and not self._running and not self.host.tx_in_flight
        self._button.set_enabled(ready)


def _describe(stage: ProtectStage, detail: str) -> str:
    """Step detail text for a stage's raw progress detail."""
    if stage is ProtectStage.ENCRYPTED:
        return f"{detail.replace('AES-256-GCM, ', '')} of ciphertext, with a 16-byte authentication tag."
    if stage is ProtectStage.SIGNED:
        return f"Manifest hash {detail.removeprefix('manifest ')}"
    return f"Stored under hash {detail.removeprefix('ctHash ')}"
