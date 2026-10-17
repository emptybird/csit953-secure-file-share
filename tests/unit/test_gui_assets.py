"""The app icon shipped with the GUI; no display needed."""

from __future__ import annotations

import struct

from app.gui.app import ICON_FILE

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def test_app_icon_is_a_square_png_with_alpha() -> None:
    data = ICON_FILE.read_bytes()
    assert data[:8] == PNG_SIGNATURE
    width, height, bit_depth, colour_type = struct.unpack(">IIBB", data[16:26])
    assert width == height == 512
    assert (bit_depth, colour_type) == (8, 6)  # 8-bit RGBA, so the corners stay transparent
