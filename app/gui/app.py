"""Main window (DESIGN.md 8): the login page, then a sidebar with one page per task.

    My files        owner: requests for my files, approve / reject / revoke
    Protect a file  owner: encrypt, sign, upload, register
    Browse files    requester: request access, see the status
    Retrieve        requester: authorized key, V1–V6, key recovery, decryption
    Activity        the contract's events, CSV export
    Account         keys, network, balance
    Security demo   tampering and unauthorized calls (SFS_DEMO=1 only)

The window polls the chain for new events (every 3 s on the local chain, once a
block elsewhere), tells each page, and raises a toast when a request for one of
my files arrives or my own request is decided. Transactions go through
`run_transaction`: one at a time, each with a toast that shows the tx hash
while pending and the block and gas once confirmed.
"""

from __future__ import annotations

import re
import sys
import time
import tkinter as tk
import webbrowser
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from tkinter import messagebox
from typing import TypeVar

from app.chain import TransactionFailedError, TransactionTimeoutError
from app.chain.client import SubmittedCallback, TxReceipt
from app.chain.events import ChainEvent
from app.config import AppConfig
from app.gui import theme
from app.gui.account_view import AccountPage
from app.gui.audit_view import ActivityPage
from app.gui.demo_view import DemoPage
from app.gui.dialogs import DialogField, confirm
from app.gui.feedback import Banner, Toast, Toasts
from app.gui.format import format_eth, is_low_balance, label_text, short_hex
from app.gui.host import Action, Level
from app.gui.layout import install_mousewheel
from app.gui.login_view import LoginView
from app.gui.owner_view import FilesPage
from app.gui.page import Page
from app.gui.protect_view import ProtectPage
from app.gui.requester_view import BrowsePage
from app.gui.sidebar import Sidebar
from app.gui.theme import PAPER, SURFACE, px
from app.gui.verify_view import VerifyPage
from app.gui.widgets import vline
from app.gui.worker import Worker, describe_error
from app.services import ServiceError
from app.services.account import AccountService, Session
from app.services.models import AccountInfo, KeyStatus

T = TypeVar("T")

WINDOW_TITLE = "Secure File Share"
WINDOW_SIZE = (1280, 820)
WINDOW_MIN_SIZE = (1080, 700)
SCREEN_MARGIN = (40, 80)
LOCAL_CHAIN_ID = 31337
LOCAL_POLL_MS = 3_000
REMOTE_POLL_MS = 12_000  # one Sepolia block; keeps a rate-limited public RPC happy
SLOW_TX_SECONDS = 120
FUND_WEI = 100 * 10**18
# Tk before 8.6.13 can ignore mouse clicks on macOS 14+ (python/cpython#110218).
MIN_MAC_TK = (8, 6, 13)

NAVIGATION = [
    ("files", "My files", "files"),
    ("protect", "Protect a file", "shield"),
    ("browse", "Browse files", "search"),
    ("activity", "Activity", "activity"),
    ("account", "Account", "key"),
]
DEMO_NAVIGATION = ("demo", "Security demo", "flask")
_DECISIONS = {
    "AccessApproved": ("Access approved", "{name} is ready to retrieve and verify."),
    "AccessRejected": ("Request rejected", "The owner of {name} rejected your request. You may request access again."),
    "AccessRevoked": ("Access revoked", "The owner of {name} revoked your access."),
}


@dataclass
class _PendingTx:
    action: str
    done: str
    started: float
    toast: Toast
    tx_hash: str = ""


class SecureFileShareApp(tk.Tk):
    def __init__(self, *, network: str | None = None, alias: str | None = None, demo: bool = False) -> None:
        super().__init__()
        theme.init(self)
        self.demo = demo
        self.worker = Worker(self)
        self._session: Session | None = None
        self._config: AppConfig | None = None
        self._alias = ""
        self._account: AccountInfo | None = None
        self._shell: _Shell | None = None
        self._login: LoginView | None = None
        self._tx: _PendingTx | None = None
        self._seen_events: int | None = None
        self._polling = False
        self._poll_job: str | None = None
        self._poll_failing = False
        self.title(WINDOW_TITLE)
        self.minsize(px(WINDOW_MIN_SIZE[0]), px(WINDOW_MIN_SIZE[1]))
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.toasts = Toasts(self)
        install_mousewheel(self)
        self._place_window()
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._show_login(network, alias)
        warning = _old_tk_warning(self)
        if warning:
            self.notify(warning, Level.WARNING, title="Unsupported Tk version")

    # ------------------------------------------------------------ host API

    @property
    def session(self) -> Session:
        if self._session is None:
            raise RuntimeError("No account is unlocked")
        return self._session

    @property
    def app_config(self) -> AppConfig:
        if self._config is None:
            raise RuntimeError("No network is selected")
        return self._config

    @property
    def alias(self) -> str:
        return self._alias

    @property
    def is_local(self) -> bool:
        return self._config is not None and self._config.network.chain_id == LOCAL_CHAIN_ID

    @property
    def tx_in_flight(self) -> bool:
        return self._tx is not None

    @property
    def account(self) -> AccountInfo | None:
        return self._account

    def notify(self, message: str, level: Level = Level.INFO, *, title: str = "", action: Action | None = None) -> None:
        timeout = None if level is Level.ERROR else 6000
        self.toasts.show(level, title or message, message if title else "", action=action, timeout_ms=timeout)

    def copy_to_clipboard(self, text: str, what: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.toasts.show(Level.SUCCESS, f"{what} copied", text, timeout_ms=3000)

    def tx_action(self, tx_hash: str) -> Action:
        url = self._config.network.tx_url(tx_hash) if self._config else ""
        if url:
            return ("View transaction", lambda: webbrowser.open(url))
        return ("Copy transaction hash", lambda: self.copy_to_clipboard(tx_hash, "Transaction hash"))

    def navigate(self, page: str, **options: object) -> None:
        if self._shell is not None:
            self._shell.show(page, **options)

    def set_badge(self, page: str, count: int) -> None:
        if self._shell is not None:
            self._shell.sidebar.set_badge(page, count)

    def account_changed(self, info: AccountInfo | None = None) -> None:
        if info is not None:
            self._account = info
            if self._shell is not None:
                self._shell.show_account(info)
            return
        session = self._session
        if session is None:
            return
        self.worker.submit(
            lambda: AccountService(session).info(),
            lambda fresh: self.account_changed(fresh) if session is self._session else None,
            lambda exc: self.notify(describe_error(exc), Level.WARNING, title="Could not read the balance"),
            name="balance",
        )

    def register_keys(self, *, rotate: bool = False) -> None:
        session, info = self.session, self._account
        if (
            rotate
            and info is not None
            and not confirm(
                self,
                "Replace keys",
                "Replace the on-chain keys for this address?",
                [
                    DialogField("Address", info.address, mono=True),
                    DialogField("New signing key", info.sig_fingerprint, mono=True),
                    DialogField("New encryption key", info.enc_fingerprint, mono=True),
                ],
                "Files signed with the old key will fail the signature check (V4). File keys wrapped for "
                "the old encryption key can only be opened with the old keystore.",
                "Replace keys",
                danger=True,
            )
        ):
            return
        self.run_transaction(
            "Register keys",
            lambda on_submitted: AccountService(session).register_keys(rotate=rotate, on_submitted=on_submitted),
            lambda _receipt: None,
            done="Keys registered",
        )

    def fund_local(self) -> None:
        session = self.session

        def job() -> AccountInfo:
            response = session.chain.web3.provider.make_request("anvil_setBalance", [session.address, hex(FUND_WEI)])
            if response.get("error"):
                raise ServiceError("This node does not support anvil_setBalance. Test ETH is available on Anvil only.")
            return AccountService(session).info()

        def done(info: AccountInfo) -> None:
            self.account_changed(info)
            self.notify(f"Balance: {format_eth(info.balance_wei)}.", Level.SUCCESS, title="Test ETH added")

        def failed(exc: BaseException) -> None:
            self.notify(describe_error(exc), Level.ERROR, title="Could not add test ETH")

        self.worker.submit(job, done, failed, name="fund")

    def run_transaction(
        self,
        action: str,
        job: Callable[[SubmittedCallback], T],
        on_success: Callable[[T], None],
        on_error: Callable[[BaseException], None] | None = None,
        *,
        done: str = "",
    ) -> bool:
        if self._tx is not None:
            self.notify(
                f"“{self._tx.action}” must be confirmed first.", Level.WARNING, title="Transaction in progress"
            )
            return False
        toast = self.toasts.show(Level.PENDING, action, "Preparing the transaction…", timeout_ms=None)
        pending = _PendingTx(action, done or action, time.monotonic(), toast)
        self._tx = pending
        self._busy_changed()

        def submitted(tx_hash: str) -> None:  # runs on the worker thread
            self.worker.call_soon(lambda: self._tx_submitted(pending, tx_hash))

        self.worker.submit(
            lambda: job(submitted),
            lambda result: self._tx_finished(pending, result, on_success),
            lambda exc: self._tx_failed(pending, exc, on_error),
            name="tx",
        )
        return True

    # ------------------------------------------------------ login / logout

    def attach_session(self, session: Session, alias: str, config: AppConfig) -> None:
        self._session, self._alias, self._config = session, alias, config
        self._seen_events = None
        self.title(f"{WINDOW_TITLE} ({alias}, {config.network.name})")
        if self._login is not None:
            self._login.destroy()
            self._login = None
        self._shell = _Shell(self, self)
        self._shell.grid(row=0, column=0, sticky="nsew")
        self._shell.sidebar.show_identity(alias, session.address, config)
        self._shell.show("files")
        self.account_changed()
        self._schedule_poll()

    def logout(self) -> None:
        if self._tx is not None:
            self.notify("A transaction is still pending.", Level.WARNING, title="Cannot lock")
            return
        if self._poll_job is not None:
            self.after_cancel(self._poll_job)
            self._poll_job = None
        if self._shell is not None:
            self._shell.destroy()
            self._shell = None
        self._session = None  # drops the unlocked keys
        self._account = None
        self.toasts.clear()
        self.title(WINDOW_TITLE)
        previous = self._config.network.name if self._config else None
        self._show_login(previous, self._alias or None)

    def _show_login(self, network: str | None, alias: str | None) -> None:
        self._login = LoginView(self, self, network=network, alias=alias)
        self._login.grid(row=0, column=0, sticky="nsew")

    # ---------------------------------------------------------- transactions

    def _tx_submitted(self, pending: _PendingTx, tx_hash: str) -> None:
        pending.tx_hash = tx_hash
        self._tick(pending)

    def _tick(self, pending: _PendingTx) -> None:
        if self._tx is not pending:
            return
        elapsed = int(time.monotonic() - pending.started)
        message = f"Submitted as {short_hex(pending.tx_hash, 8, 6)}. Awaiting confirmation ({elapsed} s)."
        if elapsed >= SLOW_TX_SECONDS:
            message += " Confirmation is taking longer than usual."
        pending.toast.update_toast(message=message, action=self.tx_action(pending.tx_hash))
        self.after(1000, lambda: self._tick(pending))

    def _tx_finished(self, pending: _PendingTx, result: T, on_success: Callable[[T], None]) -> None:
        self._tx = None
        receipt = result if isinstance(result, TxReceipt) else getattr(result, "receipt", None)
        if isinstance(receipt, TxReceipt):
            pending.toast.update_toast(
                level=Level.SUCCESS,
                title=pending.done,
                message=f"Confirmed in block {receipt.block_number}. Gas used: {receipt.gas_used:,}.",
                action=self.tx_action(receipt.tx_hash),
                timeout_ms=7000,
            )
        else:
            pending.toast.update_toast(level=Level.SUCCESS, title=pending.done, message="", timeout_ms=6000)
        self._busy_changed()
        on_success(result)
        self.account_changed()
        self._schedule_poll(0)

    def _tx_failed(
        self, pending: _PendingTx, exc: BaseException, on_error: Callable[[BaseException], None] | None
    ) -> None:
        self._tx = None
        tx_hash = exc.tx_hash if isinstance(exc, (TransactionFailedError, TransactionTimeoutError)) else ""
        if isinstance(exc, TransactionFailedError):
            message = f"Reverted on-chain: {exc.revert}" if exc.revert else "Reverted on-chain."
        else:
            message = describe_error(exc)
        pending.toast.update_toast(
            level=Level.ERROR,
            title=f"{pending.action} failed",
            message=message,
            action=self.tx_action(tx_hash) if tx_hash else None,
            timeout_ms=None,
        )
        self._busy_changed()
        if on_error is not None:
            on_error(exc)
        if tx_hash:
            self.account_changed()

    def _busy_changed(self) -> None:
        if self._shell is not None:
            self._shell.busy_changed()

    # --------------------------------------------------------------- polling

    def _schedule_poll(self, delay: int | None = None) -> None:
        if self._poll_job is not None:
            self.after_cancel(self._poll_job)
        if delay is None:
            delay = LOCAL_POLL_MS if self.is_local else REMOTE_POLL_MS
        self._poll_job = self.after(delay, self._poll)

    def _poll(self) -> None:
        self._poll_job = None
        session = self._session
        if session is None or self._shell is None:
            return
        if self._polling:
            self._schedule_poll()
            return
        self._polling = True
        self.worker.submit(
            session.events.refresh,
            lambda _new: self._polled(session),
            lambda exc: self._poll_error(session, exc),
            name="poll",
        )

    def _polled(self, session: Session) -> None:
        self._polling = False
        if session is not self._session or self._shell is None:
            return
        if self._poll_failing:
            self._poll_failing = False
            self.notify("Chain data is up to date.", Level.SUCCESS, title="Connection restored")
        events = session.events.events
        if self._seen_events is None:  # first poll: history, nothing to announce
            self._seen_events = len(events)
            self._shell.chain_changed(events)
        elif len(events) > self._seen_events:
            new = events[self._seen_events :]
            self._seen_events = len(events)
            self._shell.chain_changed(new)
            self._announce(session, new)
            self.account_changed()
        self._schedule_poll()

    def _poll_error(self, session: Session, exc: BaseException) -> None:
        self._polling = False
        if session is not self._session:
            return
        if not self._poll_failing:
            self._poll_failing = True
            self.notify(describe_error(exc), Level.WARNING, title="Connection to the chain lost")
        self._schedule_poll()

    def _announce(self, session: Session, events: Sequence[ChainEvent]) -> None:
        """Toasts for what other people did to me: a new request, or a decision on mine."""
        me = session.address
        files = {e.file_id: e for e in session.events.events if e.name == "FileRegistered"}
        for event in events:
            registration = files.get(event.file_id)
            name = label_text(registration.label) if registration else short_hex(event.file_id or b"")
            file_id = event.file_id
            if event.name == "AccessRequested" and registration and registration.args["owner"] == me:
                self.notify(
                    f"{short_hex(event.account or '')} requested access to {name}.",
                    title="New access request",
                    action=("Review request", lambda f=file_id: self.navigate("files", file_id=f)),
                )
            elif event.name in _DECISIONS and event.account == me:
                title, message = _DECISIONS[event.name]
                approved = event.name == "AccessApproved"
                action = (
                    ("Retrieve and verify", lambda f=file_id: self.navigate("verify", file_id=f))
                    if approved
                    else ("Open file", lambda f=file_id: self.navigate("browse", file_id=f))
                )
                level = Level.SUCCESS if approved else Level.WARNING
                self.notify(message.format(name=name), level, title=title, action=action)

    # ---------------------------------------------------------------- window

    def _place_window(self) -> None:
        width = min(px(WINDOW_SIZE[0]), self.winfo_screenwidth() - SCREEN_MARGIN[0])
        height = min(px(WINDOW_SIZE[1]), self.winfo_screenheight() - SCREEN_MARGIN[1])
        left = max((self.winfo_screenwidth() - width) // 2, 0)
        top = max((self.winfo_screenheight() - height) // 3, 0)
        self.geometry(f"{width}x{height}+{left}+{top}")

    def _close(self) -> None:
        if self._tx is not None and not messagebox.askokcancel(
            "Transaction pending",
            f"“{self._tx.action}” is not yet confirmed. It may still be mined after you quit, "
            "but its result will not be shown. Quit anyway?",
            parent=self,
        ):
            return
        self.worker.close()
        self.destroy()


class _Shell(tk.Frame):
    """Sidebar, account banner and the page area."""

    def __init__(self, parent: tk.Misc, app: SecureFileShareApp) -> None:
        super().__init__(parent, background=PAPER)
        self._app = app
        self.columnconfigure(2, weight=1)
        self.rowconfigure(0, weight=1)
        items = [*NAVIGATION, DEMO_NAVIGATION] if app.demo else NAVIGATION
        self.sidebar = Sidebar(
            self,
            items,
            on_navigate=lambda key: self.show(key),
            on_copy_address=lambda: app.copy_to_clipboard(app.session.address, "Address"),
            on_lock=app.logout,
        )
        self.sidebar.grid(row=0, column=0, sticky="ns")
        vline(self).grid(row=0, column=1, sticky="ns")
        main = tk.Frame(self, background=SURFACE)
        main.grid(row=0, column=2, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)
        self.banner = Banner(main)
        self._pages_area = tk.Frame(main, background=SURFACE)
        self._pages_area.grid(row=1, column=0, sticky="nsew")
        self._pages_area.columnconfigure(0, weight=1)
        self._pages_area.rowconfigure(0, weight=1)
        page_types: list[type[Page]] = [FilesPage, ProtectPage, BrowsePage, VerifyPage, ActivityPage, AccountPage]
        if app.demo:
            page_types.append(DemoPage)
        self.pages: dict[str, Page] = {}
        for page_type in page_types:
            page = page_type(self._pages_area, app)
            page.grid(row=0, column=0, sticky="nsew")
            page.grid_remove()
            self.pages[page_type.key] = page
        self._current = ""

    def show(self, key: str, **options: object) -> None:
        if key not in self.pages:
            return
        if self._current and self._current != key:
            self.pages[self._current].grid_remove()
        self._current = key
        page = self.pages[key]
        page.grid()
        self.sidebar.set_active("browse" if key == "verify" else key)
        page.on_show(**options)
        self._app.toasts.layout()

    def chain_changed(self, events: Sequence[ChainEvent]) -> None:
        for page in self.pages.values():
            if page.wants(events):
                page.reload()

    def busy_changed(self) -> None:
        self.sidebar.lock_button.set_enabled(not self._app.tx_in_flight)
        for page in self.pages.values():
            page.on_busy_changed()

    def show_account(self, info: AccountInfo) -> None:
        self.sidebar.show_account(info)
        app = self._app
        if is_low_balance(info.balance_wei):
            actions = [("Add 100 test ETH", app.fund_local)] if app.is_local else []
            hint = "" if app.is_local else " Fund it from a faucet or another account."
            self.banner.show(f"The balance is too low to pay for gas.{hint}", actions=actions)
            self.banner.grid(row=0, column=0, sticky="ew")
        elif info.key_status is KeyStatus.NOT_REGISTERED:
            self.banner.show(
                "Register your public keys to protect or request files.",
                actions=[("Register keys", app.register_keys)],
            )
            self.banner.grid(row=0, column=0, sticky="ew")
        elif info.key_status is KeyStatus.MISMATCH:
            self.banner.show(
                "The on-chain keys for this address differ from this keystore.",
                tone="red",
                actions=[("Open account", lambda: self.show("account"))],
            )
            self.banner.grid(row=0, column=0, sticky="ew")
        else:
            self.banner.grid_remove()
        for page in self.pages.values():
            refresh = getattr(page, "on_account_changed", None)
            if refresh is not None:
                refresh()


def _old_tk_warning(root: tk.Tk) -> str | None:
    if sys.platform != "darwin":
        return None
    patchlevel = str(root.tk.call("info", "patchlevel"))
    version = tuple(int(part) for part in re.findall(r"\d+", patchlevel)[:3])
    if version >= MIN_MAC_TK:
        return None
    return f"Tk {patchlevel} may not respond to clicks on this macOS. Run the app from the 953-a2 conda environment."


def enable_dpi_awareness() -> None:
    """Sharp text on high-DPI Windows screens (DESIGN.md 8.1); a no-op elsewhere."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
