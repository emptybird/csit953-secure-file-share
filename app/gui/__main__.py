"""Start the GUI.

python -m app.gui                                  pick network and keystore on the login page
python -m app.gui --network local --keystore alice preselect both (handy for two demo windows)
SFS_DEMO=1 python -m app.gui                       add the Security demo page (tampering, unauthorized calls)
"""

from __future__ import annotations

import argparse
import logging
import os

from app.gui.app import SecureFileShareApp, enable_dpi_awareness


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m app.gui", description="Secure File Share desktop client")
    parser.add_argument("--network", help="preselect .env.<network>, e.g. local or sepolia")
    parser.add_argument("--keystore", help="preselect keystore/<alias>.json")
    parser.add_argument("--demo", action="store_true", help="show the Security demo page (same as SFS_DEMO=1)")
    args = parser.parse_args(argv)
    # Messages only: no key material is ever logged.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    enable_dpi_awareness()
    app = SecureFileShareApp(
        network=args.network, alias=args.keystore, demo=args.demo or os.environ.get("SFS_DEMO") == "1"
    )
    app.mainloop()


if __name__ == "__main__":
    main()
