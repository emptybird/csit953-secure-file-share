"""Account page: identity, public keys, network and balance.

Only public-key fingerprints are shown; private keys stay inside the encrypted
keystore. Key registration is offered here and in the banner; replacing on-chain
keys that differ from this keystore is deliberately offered here only.
"""

from __future__ import annotations

import tkinter as tk

from app.gui.format import format_eth, is_low_balance, short_hex
from app.gui.host import Host
from app.gui.layout import ScrollArea, field_row
from app.gui.page import Page
from app.gui.theme import AMBER, INK, INK_2, PAGE_PAD, SURFACE, px
from app.gui.widgets import Badge, Button, Link, hline, label
from app.services.models import KeyStatus

WIDTH = 640
# key status: badge text, tone, note
_KEY_STATUS = {
    KeyStatus.NOT_REGISTERED: ("Not registered", "amber", "Required for signing files and receiving shared files."),
    KeyStatus.MATCHES: ("Registered", "success", "The on-chain keys match this keystore."),
    KeyStatus.MISMATCH: ("Mismatch", "red", "The on-chain keys for this address differ from this keystore."),
}


class AccountPage(Page):
    key = "account"

    def __init__(self, parent: tk.Misc, host: Host) -> None:
        super().__init__(
            parent, host, "Account", "Keys, network and balance. Private keys never leave the keystore."
        )
        hline(self.content).pack(fill="x")
        scroll = ScrollArea(self.content, background=SURFACE)
        scroll.pack(fill="both", expand=True)
        column = tk.Frame(scroll.body, background=SURFACE, width=px(WIDTH))
        column.pack(anchor="w", padx=px(PAGE_PAD), pady=px(24))
        session, config = host.session, host.app_config

        identity = self._section(column, "Identity")
        field_row(identity, 0, "Name").configure(text=host.alias)
        field_row(identity, 1, "Address", mono=True).configure(text=session.address)
        Link(identity, "Copy address", lambda: host.copy_to_clipboard(session.address, "Address")).grid(
            row=2, column=1, sticky="w"
        )

        keys = self._section(column, "Public keys")
        self._sig = field_row(keys, 0, "Signing key", mono=True)
        self._enc = field_row(keys, 1, "Encryption key", mono=True)
        label(keys, "On-chain", style="small", colour=INK_2).grid(row=2, column=0, sticky="nw", pady=px(6))
        status = tk.Frame(keys, background=SURFACE)
        status.grid(row=2, column=1, sticky="w", pady=px(6))
        self._status_badge = Badge(status, "", "slate")
        self._status_badge.pack(anchor="w")
        self._status_note = label(status, "", style="small", colour=INK_2, wrap=360)
        self._status_note.pack(anchor="w", pady=(px(6), 0))
        self._key_button = Button(status, "Register keys", host.register_keys, kind="primary", size="sm")
        self._key_button.pack(anchor="w", pady=(px(10), 0))
        explain = (
            "The signing key signs protected files; the encryption key receives file keys from owners. "
            "Both are bound to this address by an on-chain transaction and cannot be replaced by another account."
        )
        label(keys, explain, style="small", colour=INK_2, wrap=480).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(px(10), 0)
        )

        network = config.network
        chain = self._section(column, "Network")
        field_row(chain, 0, "Network").configure(text=network.name)
        field_row(chain, 1, "Node").configure(text=f"{network.rpc_host}, chain {network.chain_id}")
        field_row(chain, 2, "Contract", mono=True).configure(text=network.contract_address)
        field_row(chain, 3, "Storage folder", wrap=440).configure(text=str(config.storage_dir))

        balance = self._section(column, "Balance", last=True)
        self._balance = label(balance, "", style="heading")
        self._balance.grid(row=0, column=0, sticky="w")
        self._balance_note = label(balance, "", style="small", colour=INK_2, wrap=420)
        self._balance_note.grid(row=1, column=0, sticky="w", pady=(px(4), 0))
        if host.is_local:
            Button(balance, "Add 100 test ETH", host.fund_local, size="sm").grid(
                row=2, column=0, sticky="w", pady=(px(10), 0)
            )
        self.on_account_changed()

    def _section(self, column: tk.Frame, title: str, *, last: bool = False) -> tk.Frame:
        """Heading plus a two-column grid; a hairline follows unless `last`."""
        label(column, title, style="heading").pack(anchor="w")
        grid = tk.Frame(column, background=SURFACE)
        grid.pack(fill="x", pady=(px(10), 0))
        grid.columnconfigure(0, minsize=px(140))
        grid.columnconfigure(1, weight=1)
        if not last:
            hline(column).pack(fill="x", pady=px(24))
        return grid

    def on_account_changed(self) -> None:
        """Refresh keys, key status and balance from the host's latest AccountInfo."""
        info = self.host.account
        if info is None:
            return
        self._sig.configure(text=info.sig_fingerprint)
        self._enc.configure(text=info.enc_fingerprint)
        text, tone, note = _KEY_STATUS[info.key_status]
        self._status_badge.set(text, tone)
        self._status_note.configure(text=note)
        if info.key_status is KeyStatus.MATCHES:
            self._key_button.pack_forget()
        elif info.key_status is KeyStatus.MISMATCH:
            # The only place a key rotation can start; it asks for confirmation.
            self._key_button.configure_button(text="Replace on-chain keys", kind="danger")
            self._key_button.set_command(lambda: self.host.register_keys(rotate=True))
            self._key_button.pack(anchor="w", pady=(px(10), 0))
        else:
            self._key_button.pack(anchor="w", pady=(px(10), 0))
        low = is_low_balance(info.balance_wei)
        self._balance.configure(text=format_eth(info.balance_wei), foreground=AMBER if low else INK)
        if low:
            self._balance_note.configure(
                text="Insufficient to pay for gas. Each registration, request and decision is a transaction."
            )
        else:
            self._balance_note.configure(text=f"Covers gas for transactions sent from {short_hex(info.address)}.")

    def on_busy_changed(self) -> None:
        self._key_button.set_enabled(not self.host.tx_in_flight)
