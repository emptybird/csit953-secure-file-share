"""Sidebar: app mark, navigation, and who is signed in on which network.

The account block at the bottom stays visible, so with two windows open it is
clear which account each one belongs to and whether it can still pay for gas.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable, Sequence

from app.config import AppConfig
from app.gui import icons
from app.gui.format import format_eth, is_low_balance, short_hex
from app.gui.theme import (
    ACCENT,
    AMBER,
    AMBER_SOFT,
    INK,
    INK_2,
    LINE,
    ON_ACCENT,
    PAPER,
    RADIUS,
    SIDEBAR_HOVER,
    SIDEBAR_WIDTH,
    SURFACE,
    font,
    measure,
    px,
)
from app.gui.widgets import Badge, Button, label, rounded_rect
from app.services.models import AccountInfo

LOCAL_CHAIN_ID = 31337  # Anvil


class NavItem(tk.Canvas):
    """Canvas-drawn navigation entry with an optional pending-count badge."""

    def __init__(self, parent: tk.Misc, key: str, text: str, icon: str, command: Callable[[str], None]) -> None:
        super().__init__(
            parent,
            width=1,
            height=px(36),
            background=PAPER,
            highlightthickness=0,
            borderwidth=0,
            takefocus=1,
        )
        self.key, self._text, self._icon = key, text, icon
        self._active = self._hover = self._focus = False
        self._badge = 0
        self.bind("<Configure>", lambda _e: self.redraw())
        self.bind("<Enter>", lambda _e: self._set(hover=True))
        self.bind("<Leave>", lambda _e: self._set(hover=False))
        self.bind("<FocusIn>", lambda _e: self._set(focus=True))
        self.bind("<FocusOut>", lambda _e: self._set(focus=False))
        self.bind("<Button-1>", lambda _e: command(key))
        self.bind("<KeyPress-space>", lambda _e: command(key))
        self.bind("<Return>", lambda _e: command(key))

    def _set(self, **flags: bool) -> None:
        for name, value in flags.items():
            setattr(self, f"_{name}", value)
        self.redraw()

    def set_active(self, active: bool) -> None:
        self._set(active=active)

    def set_badge(self, count: int) -> None:
        self._badge = count
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        width, height = self.winfo_width(), self.winfo_height()
        if self._active:
            rounded_rect(self, 1, 1, width - 1, height - 1, px(RADIUS), fill=SURFACE, outline=LINE)
        elif self._hover or self._focus:
            rounded_rect(self, 1, 1, width - 1, height - 1, px(RADIUS), fill=SIDEBAR_HOVER, outline=SIDEBAR_HOVER)
        colour = ACCENT if self._active else INK_2
        icons.draw(self, self._icon, px(22), height / 2, px(17), colour, max(1.4, px(1.6)))
        self.create_text(
            px(40), height / 2, text=self._text, anchor="w", fill=INK if self._active else INK_2,
            font=font("strong" if self._active else "body"),
        )  # fmt: skip
        if self._badge:
            text = str(self._badge)
            pill = max(px(20), measure("small_strong", text) + px(12))
            x2 = width - px(10)
            rounded_rect(
                self,
                x2 - pill,
                height / 2 - px(10),
                x2,
                height / 2 + px(10),
                px(10),
                fill=AMBER_SOFT,
                outline=AMBER_SOFT,
            )
            self.create_text(x2 - pill / 2, height / 2, text=text, fill=AMBER, font=font("small_strong"))


class Sidebar(tk.Frame):
    """App mark, navigation items and the signed-in account block."""

    def __init__(
        self,
        parent: tk.Misc,
        items: Sequence[tuple[str, str, str]],
        *,
        on_navigate: Callable[[str], None],
        on_copy_address: Callable[[], None],
        on_lock: Callable[[], None],
    ) -> None:
        super().__init__(parent, background=PAPER, width=px(SIDEBAR_WIDTH))
        self.pack_propagate(False)
        brand = tk.Frame(self, background=PAPER)
        brand.pack(fill="x", padx=px(20), pady=(px(22), px(26)))
        mark = tk.Canvas(brand, width=px(28), height=px(28), background=PAPER, highlightthickness=0)
        icons.logo(mark, px(14), px(14), px(28), ACCENT, ON_ACCENT)
        mark.pack(side="left")
        label(brand, "Secure File Share", style="strong").pack(side="left", padx=(px(10), 0))

        self._items: dict[str, NavItem] = {}
        for key, text, icon in items:
            item = NavItem(self, key, text, icon, on_navigate)
            item.pack(fill="x", padx=px(12), pady=px(1))
            self._items[key] = item

        # Packed bottom-up: the Lock button sits lowest, the account block above it.
        lock = Button(self, "Lock", on_lock, kind="quiet", icon="lock", size="sm")
        lock.pack(side="bottom", anchor="w", padx=px(14), pady=(px(6), px(18)))
        self.lock_button = lock
        account = tk.Frame(self, background=PAPER)
        account.pack(side="bottom", fill="x", padx=px(22))
        tk.Frame(account, height=1, background=LINE).pack(fill="x", pady=(0, px(16)))
        self._alias = label(account, "", style="strong")
        self._alias.pack(anchor="w")
        address_row = tk.Frame(account, background=PAPER)
        address_row.pack(fill="x", pady=(px(2), 0))
        self._address = label(address_row, "", style="mono_small", colour=INK_2)
        self._address.pack(side="left")
        Button(address_row, "", on_copy_address, kind="quiet", size="sm", icon="copy").pack(
            side="left", padx=(px(2), 0)
        )
        self._network = Badge(account, "", "accent", dot=True)
        self._network.pack(anchor="w", pady=(px(6), 0))
        self._balance = label(account, "", style="small", colour=INK_2)
        self._balance.pack(anchor="w", pady=(px(8), 0))

    def set_active(self, key: str) -> None:
        for item_key, item in self._items.items():
            item.set_active(item_key == key)

    def set_badge(self, key: str, count: int) -> None:
        if key in self._items:
            self._items[key].set_badge(count)

    def show_identity(self, alias: str, address: str, config: AppConfig) -> None:
        self._alias.configure(text=alias)
        self._address.configure(text=short_hex(address))
        network = config.network
        if network.chain_id == LOCAL_CHAIN_ID:
            self._network.set("Local chain", "accent")
        else:
            self._network.set(network.name.capitalize(), "slate")

    def show_account(self, info: AccountInfo) -> None:
        low = is_low_balance(info.balance_wei)
        self._balance.configure(text=format_eth(info.balance_wei), foreground=AMBER if low else INK_2)
