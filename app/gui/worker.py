"""Background jobs for the Tk GUI.

Tk is not thread-safe. Chain calls, scrypt and encryption run on worker threads;
results go onto a queue that the Tk thread drains with after(), so every widget
update happens on the Tk thread. A Sepolia confirmation takes 10-30 s and the
window stays responsive throughout.

Errors from the four layers (ServiceError, ChainError, StorageError, CryptoError)
and ConfigError carry user-facing messages and are shown as is. Anything else is
a bug: the user gets a short message, the traceback goes to the log. No exception
message here contains key material.
"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from collections.abc import Callable
from typing import TypeVar

from app.chain import ChainError
from app.config import ConfigError
from app.crypto import CryptoError
from app.services import ServiceError
from app.storage import StorageError

POLL_MS = 40

T = TypeVar("T")
log = logging.getLogger("app.gui")

USER_ERRORS = (ServiceError, ChainError, StorageError, CryptoError, ConfigError)


def describe_error(exc: BaseException) -> str:
    """The text shown for `exc`; unexpected errors are logged with their traceback."""
    if isinstance(exc, USER_ERRORS):
        return str(exc)
    log.error("Unexpected error in a background job", exc_info=exc)
    return f"Unexpected error ({type(exc).__name__}). Details were written to the log."


class Worker:
    """Runs jobs on threads and hands their callbacks back to the Tk thread."""

    def __init__(self, root: tk.Misc, *, poll_ms: int = POLL_MS) -> None:
        self._root = root
        self._poll_ms = poll_ms
        self._queue: queue.SimpleQueue[Callable[[], None]] = queue.SimpleQueue()
        self._closed = False
        root.after(poll_ms, self._drain)

    def submit(
        self,
        job: Callable[[], T],
        on_success: Callable[[T], None],
        on_error: Callable[[BaseException], None],
        *,
        owner: tk.Misc | None = None,
        name: str = "job",
    ) -> None:
        """Run `job()` on a new daemon thread; one of the callbacks then runs on the Tk
        thread. Callbacks are dropped if `owner` was destroyed in the meantime."""

        def run() -> None:
            try:
                result = job()
            except Exception as exc:  # noqa: BLE001 - every failure must reach the GUI
                # Bind now: Python deletes `exc` when the except block ends.
                self._post(lambda error=exc: on_error(error), owner)
            else:
                self._post(lambda: on_success(result), owner)

        threading.Thread(target=run, name=f"sfs-{name}", daemon=True).start()

    def call_soon(self, callback: Callable[[], None], *, owner: tk.Misc | None = None) -> None:
        """Thread-safe: run `callback` on the Tk thread, e.g. a progress update."""
        self._post(callback, owner)

    def close(self) -> None:
        """Stop polling; callbacks still queued are dropped."""
        self._closed = True

    def _post(self, callback: Callable[[], None], owner: tk.Misc | None) -> None:
        self._queue.put(lambda: _run_if_alive(callback, owner))

    def _drain(self) -> None:
        """Run every queued callback on the Tk thread, then poll again."""
        if self._closed:
            return
        try:
            while True:
                self._queue.get_nowait()()
        except queue.Empty:
            pass
        finally:
            self._root.after(self._poll_ms, self._drain)


def _run_if_alive(callback: Callable[[], None], owner: tk.Misc | None) -> None:
    try:
        if owner is not None and not owner.winfo_exists():
            return
        callback()
    except tk.TclError:
        # The widget went away between the check and the update (window closing).
        log.debug("Dropped a GUI update for a destroyed widget", exc_info=True)
    except Exception:
        log.exception("GUI callback failed")
