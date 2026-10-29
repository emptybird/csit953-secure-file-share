"""What the pages need from the main window (implemented by app.SecureFileShareApp).

Pages talk to the window only through this protocol: the session, the worker,
transactions (one at a time, reported in toasts), navigation and notifications.
That keeps pages independent of each other and of the window layout.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
from typing import Protocol, TypeVar

from app.chain.client import SubmittedCallback
from app.config import AppConfig
from app.gui.worker import Worker
from app.services.account import Session
from app.services.models import AccountInfo

T = TypeVar("T")
Action = tuple[str, Callable[[], None]]


class Level(Enum):
    INFO = "info"
    PENDING = "pending"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


class Host(Protocol):
    worker: Worker
    demo: bool

    @property
    def session(self) -> Session: ...

    @property
    def app_config(self) -> AppConfig: ...

    @property
    def alias(self) -> str: ...

    @property
    def is_local(self) -> bool:
        """True on the Anvil development chain (chainId 31337)."""
        ...

    @property
    def tx_in_flight(self) -> bool: ...

    @property
    def account(self) -> AccountInfo | None:
        """The latest balance and key status, or None before the first read."""
        ...

    def run_transaction(
        self,
        action: str,
        job: Callable[[SubmittedCallback], T],
        on_success: Callable[[T], None],
        on_error: Callable[[BaseException], None] | None = None,
        *,
        done: str = "",
    ) -> bool:
        """Run a job that sends one transaction. `job` gets the callback to pass as
        `on_submitted`. A toast titled `action` shows the tx hash while pending and
        `done` (or the error) at the end. Returns False while another is pending."""
        ...

    def notify(
        self, message: str, level: Level = Level.INFO, *, title: str = "", action: Action | None = None
    ) -> None: ...

    def tx_action(self, tx_hash: str) -> Action:
        """('View transaction', open explorer) or ('Copy transaction hash', copy) on a local chain."""
        ...

    def copy_to_clipboard(self, text: str, what: str) -> None: ...

    def account_changed(self, info: AccountInfo | None = None) -> None:
        """Balance or key status may have changed: refresh the sidebar and banner."""
        ...

    def register_keys(self, *, rotate: bool = False) -> None: ...

    def fund_local(self) -> None:
        """Set this account's balance to 100 ETH (Anvil only)."""
        ...

    def navigate(self, page: str, **options: object) -> None: ...

    def set_badge(self, page: str, count: int) -> None: ...


class LoginHost(Protocol):
    """The subset the login page needs before a session exists."""

    worker: Worker

    def attach_session(self, session: Session, alias: str, config: AppConfig) -> None: ...

    def notify(
        self, message: str, level: Level = Level.INFO, *, title: str = "", action: Action | None = None
    ) -> None: ...
