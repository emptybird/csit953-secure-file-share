"""Login page (DESIGN.md 4.1, 8): choose a network and a keystore, then unlock it,
or create a new keystore with three fresh keys.

scrypt (n = 2^17) and the RPC calls run on the worker, so the window stays
responsive. A wrong password and a damaged keystore give the same message.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path

from app.config import ROOT_DIR, AppConfig, ConfigError, available_networks, load_config
from app.crypto import KeystoreError
from app.crypto.keystore import (
    MIN_PASSWORD_CHARS,
    UserKeys,
    decrypt_keystore,
    encrypt_keystore,
    generate_user_keys,
    keystore_path,
    load_keystore,
    save_keystore,
)
from app.gui import icons
from app.gui.format import short_hex
from app.gui.host import LoginHost
from app.gui.layout import Panel
from app.gui.theme import ACCENT, INK_2, INK_3, ON_ACCENT, PAPER, RED, px
from app.gui.widgets import Button, Field, Link, Select, label
from app.gui.worker import describe_error
from app.services.account import Session, open_session

FORM_WIDTH = 380
_NETWORK_NAMES = {"local": "Local chain (Anvil)", "sepolia": "Sepolia testnet"}


class LoginView(tk.Frame):
    def __init__(self, parent: tk.Misc, host: LoginHost, *, network: str | None, alias: str | None) -> None:
        super().__init__(parent, background=PAPER)
        self._host = host
        self._keystore_dir = ROOT_DIR / "keystore"
        self._busy = False
        self._build()
        self._load_networks(network)
        self._load_keystores(alias)

    # ----------------------------------------------------------------- layout

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(5, weight=2)
        mark = tk.Canvas(self, width=px(48), height=px(48), background=PAPER, highlightthickness=0)
        icons.logo(mark, px(24), px(24), px(48), ACCENT, ON_ACCENT)
        mark.grid(row=1, column=0, pady=(px(16), px(14)))
        label(self, "Secure File Share", style="display").grid(row=2, column=0)
        tagline = "Files are encrypted and signed on this computer. A smart contract controls who receives the key."
        intro = label(self, tagline, style="body", colour=INK_2, wrap=420)
        intro.configure(justify="center")
        intro.grid(row=3, column=0, pady=(px(6), px(22)))

        panel = Panel(self, padding=26)
        panel.grid(row=4, column=0)
        self._form = panel.body
        self._form.columnconfigure(0, minsize=px(FORM_WIDTH))
        self._caption(0, "Network")
        self._network = Select(self._form, [], width=FORM_WIDTH, on_change=lambda _v: self._describe_network())
        self._network.grid(row=1, column=0, sticky="ew")
        self._network_note = label(self._form, "", style="small", colour=INK_3, wrap=FORM_WIDTH)
        self._network_note.grid(row=2, column=0, sticky="w", pady=(px(5), 0))

        self._unlock_page = self._build_unlock(self._form)
        self._create_page = self._build_create(self._form)
        self._error = label(self._form, "", style="small", colour=RED, wrap=FORM_WIDTH)
        self._error.grid(row=4, column=0, sticky="w", pady=(px(12), 0))
        self._error.grid_remove()

        note = "Keys are decrypted locally. Only ciphertext and signed transactions leave this computer."
        footer = label(self, note, style="small", colour=INK_3, wrap=420)
        footer.configure(justify="center")
        footer.grid(row=6, column=0, pady=(0, px(24)))

    def _caption(self, row: int, text: str, parent: tk.Misc | None = None) -> None:
        top = 0 if row == 0 and parent is None else px(16)
        label(parent or self._form, text, style="small_strong").grid(row=row, column=0, sticky="w", pady=(top, px(6)))

    def _build_unlock(self, form: tk.Frame) -> tk.Frame:
        page = tk.Frame(form, background=form.cget("background"))
        page.columnconfigure(0, weight=1)
        self._caption(0, "Keystore", page)
        self._alias = Select(page, [], width=FORM_WIDTH)
        self._alias.grid(row=1, column=0, sticky="ew")
        self._caption(2, "Password", page)
        self._password = Field(page, secret=True, width=FORM_WIDTH, on_return=self._unlock)
        self._password.grid(row=3, column=0, sticky="ew")
        self._unlock_button = Button(page, "Unlock", self._unlock, kind="primary", size="lg", fill=True)
        self._unlock_button.grid(row=4, column=0, sticky="ew", pady=(px(22), 0))
        Link(page, "Create a new keystore", lambda: self._show(self._create_page)).grid(
            row=5, column=0, pady=(px(16), 0)
        )
        return page

    def _build_create(self, form: tk.Frame) -> tk.Frame:
        page = tk.Frame(form, background=form.cget("background"))
        page.columnconfigure(0, weight=1)
        self._caption(0, "Name", page)
        self._new_alias = Field(page, placeholder="For example: alice", width=FORM_WIDTH)
        self._new_alias.grid(row=1, column=0, sticky="ew")
        self._caption(2, "Password", page)
        self._new_password = Field(page, secret=True, width=FORM_WIDTH)
        self._new_password.grid(row=3, column=0, sticky="ew")
        self._caption(4, "Confirm password", page)
        self._new_confirm = Field(page, secret=True, width=FORM_WIDTH, on_return=self._create_keystore)
        self._new_confirm.grid(row=5, column=0, sticky="ew")
        text = (
            "Generates three keys (transactions, file signing, file encryption) and saves them to "
            f"keystore/<name>.json, encrypted with this password (at least {MIN_PASSWORD_CHARS} characters). "
            "A lost password cannot be recovered."
        )
        label(page, text, style="small", colour=INK_2, wrap=FORM_WIDTH).grid(
            row=6, column=0, sticky="w", pady=(px(12), 0)
        )
        self._create_button = Button(
            page, "Create keystore", self._create_keystore, kind="primary", size="lg", fill=True
        )
        self._create_button.grid(row=7, column=0, sticky="ew", pady=(px(20), 0))
        Link(page, "Use an existing keystore", lambda: self._show(self._unlock_page)).grid(
            row=8, column=0, pady=(px(16), 0)
        )
        return page

    def _show(self, page: tk.Frame) -> None:
        for other in (self._unlock_page, self._create_page):
            other.grid_remove()
        page.grid(row=3, column=0, sticky="ew")
        self._fail("")
        (self._password if page is self._unlock_page else self._new_alias).focus()

    # ------------------------------------------------------------ choices

    def _load_networks(self, preferred: str | None) -> None:
        names = available_networks()
        self._network.set_options([(name, _NETWORK_NAMES.get(name, name)) for name in names], preferred)
        self._describe_network()

    def _describe_network(self) -> None:
        name = self._network.get()
        if not name:
            text = (
                "No network is configured. Copy .env.example to .env.local, start the chain and run scripts/deploy.py."
            )
            self._network_note.configure(text=text, foreground=RED)
            return
        try:
            network = load_config(name).network
        except ConfigError as exc:
            self._network_note.configure(text=str(exc), foreground=RED)
            return
        text = f"{network.rpc_host}, chain {network.chain_id}, contract {short_hex(network.contract_address)}"
        self._network_note.configure(text=text, foreground=INK_3)

    def _load_keystores(self, preferred: str | None) -> None:
        aliases = keystore_aliases(self._keystore_dir)
        self._alias.set_options([(alias, alias) for alias in aliases], preferred)
        self._show(self._unlock_page if aliases else self._create_page)

    # ------------------------------------------------------------ actions

    def _unlock(self) -> None:
        network, alias, password = self._network.get(), self._alias.get(), self._password.get()
        if not network or not alias:
            self._fail("Select a network and a keystore.")
            return
        if not password:
            self._fail("Enter the keystore password.")
            self._password.focus()
            return
        path = self._keystore_dir / f"{alias}.json"
        self._start(self._unlock_button, "Unlocking…")

        def job() -> tuple[AppConfig, Session]:
            config = load_config(network)
            keys = decrypt_keystore(load_keystore(path), password)
            return config, _connect(config, keys)

        self._host.worker.submit(
            job,
            lambda result: self._connected(alias, *result),
            lambda exc: self._failed(self._unlock_button, "Unlock", exc),
            owner=self,
            name="unlock",
        )

    def _create_keystore(self) -> None:
        network, alias = self._network.get(), self._new_alias.get().strip()
        password, again = self._new_password.get(), self._new_confirm.get()
        try:
            path = keystore_path(self._keystore_dir, alias)
        except KeystoreError as exc:
            self._fail(str(exc))
            return
        problem = (
            f"A keystore named {alias} already exists." if path.exists()
            else f"The password must be at least {MIN_PASSWORD_CHARS} characters." if len(password) < MIN_PASSWORD_CHARS
            else "The passwords do not match." if password != again
            else "Configure a network first." if not network
            else ""
        )  # fmt: skip
        if problem:
            self._fail(problem)
            return
        self._start(self._create_button, "Generating keys…")

        def job() -> tuple[AppConfig, Session]:
            config = load_config(network)
            keys = generate_user_keys()
            save_keystore(path, encrypt_keystore(keys, password))
            return config, _connect(config, keys)

        def failed(exc: BaseException) -> None:
            if path.exists():  # saved, but the network failed: unlock it later
                self._load_keystores(alias)
                self._failed(self._create_button, "Create keystore", exc)
            else:
                self._failed(self._create_button, "Create keystore", exc)

        self._host.worker.submit(job, lambda result: self._connected(alias, *result), failed, owner=self, name="create")

    def _start(self, button: Button, text: str) -> None:
        self._fail("")
        button.configure_button(text=text, enabled=False)
        self.configure(cursor="watch")

    def _fail(self, message: str) -> None:
        self._error.configure(text=message)
        if message:
            self._error.grid()
        else:
            self._error.grid_remove()

    def _failed(self, button: Button, text: str, exc: BaseException) -> None:
        button.configure_button(text=text, enabled=True)
        self.configure(cursor="")
        self._fail(describe_error(exc))

    def _connected(self, alias: str, config: AppConfig, session: Session) -> None:
        self.configure(cursor="")
        for field in (self._password, self._new_password, self._new_confirm):
            field.clear()
        self._host.attach_session(session, alias, config)


def _connect(config: AppConfig, keys: UserKeys) -> Session:
    return open_session(config, keys)


def keystore_aliases(directory: Path) -> list[str]:
    return sorted(path.stem for path in directory.glob("*.json") if not path.name.startswith("."))
