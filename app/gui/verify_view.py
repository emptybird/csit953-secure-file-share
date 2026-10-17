"""Retrieve and verify (DESIGN.md 4.3, 6.1; task brief 2.4, 2.5): the requester's side.

    1 Read your authorization       the approved request and its 93-byte wrapped key
    2 Check integrity and signature V1 ctHash, V2 manifestHash, V3 context, V4 ECDSA
    3 Recover the file key          ECIES unwrap with my K_enc
    4 Decrypt and compare           V5 AES-256-GCM tag, V6 signed plaintext digest

Results appear one at a time in the order they ran. "Save decrypted file" is
enabled only when every check passed, and the plaintext is dropped from memory
once it is saved or another file is opened.
"""

from __future__ import annotations

import subprocess  # nosec B404 - only to show a saved file in the file manager
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

from app.chain import RequestStatus
from app.gui import icons
from app.gui.feedback import StepChain, StepState, SubCheck
from app.gui.format import format_size, format_time, label_text, plural, short_hex
from app.gui.host import Host, Level
from app.gui.layout import Panel, ScrollArea, field_row
from app.gui.page import Page, clear
from app.gui.theme import ACCENT, INK_2, INK_3, PAGE_PAD, RED, SURFACE, WHITE, px
from app.gui.widgets import Badge, Button, Checkbox, Link, hline, label
from app.gui.worker import describe_error
from app.services import AccessDeniedError
from app.services.models import Check, CheckResult, FileSummary, KeyGrant, Outcome, RetrievedFile
from app.services.requester import RequesterService, save_plaintext

SIDE_WIDTH = 344
STEPS_WRAP = 430
REVEAL_MS = 140
_STAGES = (
    ("grant", "Read your authorization", "The contract must hold an approved request with a wrapped key for you."),
    (
        "integrity",
        "Check integrity and signature",
        (
            "What storage returns is compared with the on-chain record, and the owner's signature is checked "
            "with the key the owner registered."
        ),
    ),
    ("key", "Recover the file key", "Your encryption key opens the wrapped key (ECIES). Nobody else's can."),
    (
        "decrypt",
        "Decrypt and compare",
        "AES-256-GCM checks its tag, then the content is compared with the digest the owner signed.",
    ),
)
_STAGE_CHECKS = {
    "integrity": (Check.V1_CT_HASH, Check.V2_MANIFEST_HASH, Check.V3_CONTEXT, Check.V4_SIGNATURE),
    "key": (Check.UNWRAP,),
    "decrypt": (Check.V5_DECRYPT, Check.V6_PT_DIGEST),
}
_STATE = {Outcome.PASSED: StepState.DONE, Outcome.FAILED: StepState.FAILED, Outcome.SKIPPED: StepState.SKIPPED}
_SHORT_TITLES = {
    Check.V1_CT_HASH: "Ciphertext hash matches the chain",
    Check.V2_MANIFEST_HASH: "Manifest hash matches the chain",
    Check.V3_CONTEXT: "Manifest belongs to this file, owner and chain",
    Check.V4_SIGNATURE: "Owner's signature is valid",
    Check.UNWRAP: "Wrapped key opened with your key",
    Check.V5_DECRYPT: "AES-256-GCM tag verified",
    Check.V6_PT_DIGEST: "Content matches the signed digest",
}

Outcome_ = tuple[KeyGrant | None, RetrievedFile | None, BaseException | None]


class VerifyPage(Page):
    key = "verify"

    def __init__(self, parent: tk.Misc, host: Host) -> None:
        super().__init__(parent, host, "Retrieve and verify", "Choose a file under Browse files first.")
        self._requester = RequesterService(host.session)
        self._summary: FileSummary | None = None
        self._retrieved: RetrievedFile | None = None
        self._running = False
        self._run_id = 0
        Button(self.actions, "Back to files", lambda: host.navigate("browse"), kind="quiet", icon="arrow_left").pack(
            side="right"
        )
        self._again = Button(self.actions, "Run again", self._run, size="sm", icon="refresh")
        self._again.pack(side="right", padx=(0, px(8)))
        self._again.set_enabled(False)
        hline(self.content).pack(fill="x")
        scroll = ScrollArea(self.content, background=SURFACE)
        scroll.pack(fill="both", expand=True)
        body = scroll.body
        body.columnconfigure(0, weight=1)
        left = tk.Frame(body, background=SURFACE)
        left.grid(row=0, column=0, sticky="new", padx=(px(PAGE_PAD), px(40)), pady=px(28))
        self._side = tk.Frame(body, background=SURFACE, width=px(SIDE_WIDTH))
        self._side.grid(row=0, column=1, sticky="n", padx=(0, px(PAGE_PAD)), pady=px(28))
        self._chain = StepChain(left, _STAGES, wrap=STEPS_WRAP)
        self._chain.pack(anchor="w", fill="x")
        self._force: Checkbox | None = None
        if host.demo:
            self._force = Checkbox(left, "Demo: decrypt even if a check fails, to show the GCM tag check")
            self._force.pack(anchor="w", pady=(px(24), 0))
        self._key_panel = Panel(self._side, padding=20)
        self._key_panel.pack(fill="x")
        self._result_panel = Panel(self._side, padding=20)
        self._result_panel.pack(fill="x", pady=(px(16), 0))
        self._show_grant(None)
        self._show_result()

    # ------------------------------------------------------------ navigation

    def on_show(self, **options: object) -> None:
        file_id = options.get("file_id")
        if not isinstance(file_id, bytes):
            return
        self._retrieved = None
        self._summary = None
        self.set_heading("Retrieve and verify", "Loading the file record…")
        self._chain.reset()
        self._show_grant(None)
        self._show_result()
        self.host.worker.submit(
            lambda: self._requester.file(file_id),
            self._opened,
            lambda exc: self.set_heading("Retrieve and verify", describe_error(exc)),
            owner=self,
            name="verify-file",
        )

    def _opened(self, summary: FileSummary) -> None:
        self._summary = summary
        owner = "you" if summary.is_mine else short_hex(summary.owner)
        self.set_heading(
            label_text(summary.label), f"Owned by {owner}. Registered {format_time(summary.registered_at)}."
        )
        self._run()

    # ------------------------------------------------------------------ run

    def _run(self) -> None:
        summary = self._summary
        if summary is None or self._running:
            return
        self._running = True
        self._run_id += 1
        run_id = self._run_id
        self._retrieved = None
        self._again.set_enabled(False)
        self._chain.reset()
        self._chain.set("grant", StepState.RUNNING, "Reading the file record and your request from the contract…")
        self._show_grant(None)
        self._show_result(working=True)
        force = self._force is not None and self._force.get()

        def job() -> Outcome_:
            try:
                grant = self._requester.key_grant(summary.file_id)
            except AccessDeniedError as exc:
                return None, None, exc
            return grant, self._requester.retrieve(summary.file_id, force_decrypt=force), None

        self.host.worker.submit(
            job,
            lambda outcome: self._reveal_grant(run_id, *outcome),
            lambda exc: self._crashed(run_id, exc),
            owner=self,
            name="retrieve",
        )

    def _crashed(self, run_id: int, exc: BaseException) -> None:
        if run_id != self._run_id:
            return
        self._running = False
        self._chain.set("grant", StepState.FAILED, describe_error(exc))
        self._show_result(error=describe_error(exc))
        self._again.set_enabled(True)

    def _reveal_grant(
        self, run_id: int, grant: KeyGrant | None, retrieved: RetrievedFile | None, denied: BaseException | None
    ) -> None:
        if run_id != self._run_id:
            return
        if grant is None or retrieved is None:
            self._running = False
            self._chain.set("grant", StepState.FAILED, _denied_text(self._summary, denied))
            for stage in ("integrity", "key", "decrypt"):
                self._chain.set(stage, StepState.SKIPPED, "Not attempted without an authorization.")
            self._show_result(denied=True)
            self._again.set_enabled(True)
            return
        if grant.is_owner_copy:
            detail = f"You own this file. Your own wrapped copy of the key ({grant.size} bytes) is in the file record."
        else:
            detail = f"Approved {format_time(grant.updated_at)}. A {grant.size}-byte wrapped key is stored for you."
        self._chain.set("grant", StepState.DONE, detail)
        self._show_grant(grant)
        results = {r.check: r for r in retrieved.report.results}
        steps = [(stage, check) for stage in ("integrity", "key", "decrypt") for check in _STAGE_CHECKS[stage]]
        self.after(REVEAL_MS, lambda: self._reveal_checks(run_id, retrieved, results, steps, 0))

    def _reveal_checks(self, run_id: int, retrieved: RetrievedFile, results: dict, steps: list, index: int) -> None:
        if run_id != self._run_id or not self.winfo_exists():
            return
        if index == len(steps):
            self._finish(retrieved)
            return
        stage, _check = steps[index]
        shown = [c for s, c in steps[: index + 1] if s == stage]
        checks = [_sub_check(results[c]) for c in shown]
        self._chain.set_checks(stage, checks)
        last_of_stage = index + 1 == len(steps) or steps[index + 1][0] != stage
        if last_of_stage:
            states = [results[c].outcome for c in _STAGE_CHECKS[stage]]
            if Outcome.FAILED in states:
                self._chain.set(stage, StepState.FAILED, _stage_summary(stage, states))
            elif all(s is Outcome.SKIPPED for s in states):
                self._chain.set(stage, StepState.SKIPPED, "Not attempted because a check above failed.")
            else:
                self._chain.set(stage, StepState.DONE, "")
            if index + 1 < len(steps):
                self._chain.set(steps[index + 1][0], StepState.RUNNING, "")
        elif self._chain.state(stage) is not StepState.RUNNING:
            self._chain.set(stage, StepState.RUNNING, "")
        self.after(REVEAL_MS, lambda: self._reveal_checks(run_id, retrieved, results, steps, index + 1))

    def _finish(self, retrieved: RetrievedFile) -> None:
        self._running = False
        self._again.set_enabled(True)
        if retrieved.ok:
            self._retrieved = retrieved
        self._show_result(retrieved=retrieved)

    # ---------------------------------------------------------- side panels

    def _show_grant(self, grant: KeyGrant | None) -> None:
        body = self._key_panel.body
        clear(body)
        heading = tk.Frame(body, background=SURFACE)
        heading.pack(fill="x")
        label(heading, "Authorized key", style="strong").pack(side="left")
        if grant is None:
            text = "The wrapped file key the contract holds for you appears here."
            label(body, text, style="small", colour=INK_3, wrap=SIDE_WIDTH - 40).pack(anchor="w", pady=(px(8), 0))
            return
        Badge(heading, "Owner copy" if grant.is_owner_copy else "Approved", "accent").pack(side="right")
        fields = tk.Frame(body, background=SURFACE)
        fields.pack(fill="x", pady=(px(12), 0))
        field_row(fields, 0, "For").configure(text=f"You, {short_hex(grant.recipient)}")
        field_row(fields, 1, "Wrapped key").configure(text=f"{grant.size} bytes, stored on-chain")
        field_row(fields, 2, "One-time key", mono=True).configure(text=grant.ephemeral_fingerprint)
        field_row(fields, 3, "Scheme", wrap=190).configure(text="ECIES on secp256k1 with HKDF-SHA256 and AES-256-GCM")
        note = "Bound to this file and your address, so it cannot be reused for another file or person."
        label(body, note, style="small", colour=INK_2, wrap=SIDE_WIDTH - 40).pack(anchor="w", pady=(px(10), 0))

    def _show_result(
        self,
        *,
        retrieved: RetrievedFile | None = None,
        working: bool = False,
        denied: bool = False,
        error: str = "",
        saved: Path | None = None,
    ) -> None:
        body = self._result_panel.body
        clear(body)
        wrap = SIDE_WIDTH - 40
        if retrieved is not None and retrieved.ok and retrieved.plaintext is not None:
            header = retrieved.plaintext.header
            _seal(body, ACCENT, "check")
            label(body, "Verified", style="display", colour=ACCENT).pack(anchor="w", pady=(px(12), 0))
            owner = (
                "you"
                if self._summary and self._summary.is_mine
                else short_hex(self._summary.owner if self._summary else "")
            )
            text = f"The file is exactly what {owner} signed, and nobody changed it in storage."
            label(body, text, style="small", colour=INK_2, wrap=wrap).pack(anchor="w", pady=(px(4), px(14)))
            fields = tk.Frame(body, background=SURFACE)
            fields.pack(fill="x")
            field_row(fields, 0, "Name", wrap=180).configure(text=header.name)
            field_row(fields, 1, "Size").configure(text=format_size(header.size))
            field_row(fields, 2, "Type", wrap=180).configure(text=header.mime)
            if saved is not None:
                label(body, f"Saved to {saved}", style="small", colour=INK_2, wrap=wrap).pack(
                    anchor="w", pady=(px(14), 0)
                )
                Link(body, "Show in folder", lambda: _reveal_in_folder(saved)).pack(anchor="w", pady=(px(6), 0))
            else:
                save = Button(
                    body, "Save decrypted file", self._save, kind="primary", size="lg", fill=True, icon="download"
                )
                save.pack(fill="x", pady=(px(18), 0))
                self._save_button = save
        elif retrieved is not None:
            failed = retrieved.report.failures
            _seal(body, RED, "cross")
            label(body, "Verification failed", style="heading", colour=RED).pack(anchor="w", pady=(px(12), 0))
            text = (
                f"{plural(len(failed), 'check')} failed, so the file was not decrypted to disk. What storage "
                "returned does not match what the owner registered and signed."
            )
            label(body, text, style="small", colour=INK_2, wrap=wrap).pack(anchor="w", pady=(px(4), 0))
        elif denied:
            label(body, "No access yet", style="heading").pack(anchor="w")
            text = "Request access under Browse files. The owner has to approve before a key exists for you."
            label(body, text, style="small", colour=INK_2, wrap=wrap).pack(anchor="w", pady=(px(4), px(14)))
            Button(body, "Back to files", lambda: self.host.navigate("browse"), size="sm").pack(anchor="w")
        elif error:
            label(body, "Could not finish", style="heading", colour=RED).pack(anchor="w")
            label(body, error, style="small", colour=INK_2, wrap=wrap).pack(anchor="w", pady=(px(4), 0))
        else:
            label(body, "Result", style="strong").pack(anchor="w")
            text = "Checking…" if working else "Save becomes available when every check has passed."
            label(body, text, style="small", colour=INK_3, wrap=wrap).pack(anchor="w", pady=(px(8), 0))

    # ------------------------------------------------------------------ save

    def _save(self) -> None:
        retrieved = self._retrieved
        if retrieved is None:
            return
        downloads = Path.home() / "Downloads"
        directory = filedialog.askdirectory(
            parent=self, title="Save the decrypted file to", initialdir=downloads if downloads.is_dir() else Path.home()
        )
        if not directory:
            return
        self._save_button.configure_button(text="Saving…", enabled=False)

        def saved(path: Path) -> None:
            self._retrieved = None  # the plaintext is not kept once it is on disk
            self._show_result(retrieved=retrieved, saved=path)

        def failed(exc: BaseException) -> None:
            self._save_button.configure_button(text="Save decrypted file", enabled=True)
            self.host.notify(describe_error(exc), Level.ERROR, title="Could not save the file")

        self.host.worker.submit(
            lambda: save_plaintext(retrieved, Path(directory)), saved, failed, owner=self, name="save"
        )


def _sub_check(result: CheckResult) -> SubCheck:
    return SubCheck(result.check.code, _SHORT_TITLES[result.check], _STATE[result.outcome], result.detail)


def _denied_text(summary: FileSummary | None, denied: BaseException | None) -> str:
    status = summary.my_status if summary is not None else None
    return {
        RequestStatus.NONE: "You have not requested this file, so the contract holds no key for you.",
        RequestStatus.PENDING: "Your request is still pending. The owner has not shared the key yet.",
        RequestStatus.REJECTED: "The owner rejected your request, so no key was shared.",
        RequestStatus.REVOKED: "The owner revoked your access and the wrapped key was deleted.",
    }.get(status, str(denied) if denied else "No key is stored for you.")


def _stage_summary(stage: str, outcomes: list[Outcome]) -> str:
    failed = outcomes.count(Outcome.FAILED)
    if stage == "integrity":
        return f"{plural(failed, 'check')} failed. Storage returned something the owner did not register."
    if stage == "key":
        return "The wrapped key does not open with your key."
    return "The content does not match what the owner encrypted and signed."


def _seal(parent: tk.Misc, colour: str, icon: str) -> None:
    size = px(48)
    canvas = tk.Canvas(parent, width=size, height=size, background=SURFACE, highlightthickness=0)
    canvas.create_oval(1, 1, size - 1, size - 1, fill=colour, outline=colour)
    icons.draw(canvas, icon, size / 2, size / 2, size * 0.5, WHITE, max(2.4, px(3)))
    canvas.pack(anchor="w")


def _reveal_in_folder(path: Path) -> None:
    if sys.platform == "darwin":
        subprocess.Popen(["open", "-R", str(path)])  # nosec B603 B607 - fixed command, a path we wrote
    elif sys.platform == "win32":
        subprocess.Popen(["explorer", "/select,", str(path)])  # nosec B603 B607
    else:
        subprocess.Popen(["xdg-open", str(path.parent)])  # nosec B603 B607
