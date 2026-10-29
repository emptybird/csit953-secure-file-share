"""Tkinter desktop GUI: `python -m app.gui`.

app              main window: login, sidebar, pages, toasts, chain polling, transactions
login_view       choose network and keystore, unlock, or create a keystore
owner_view       My files: requests per file, approve / reject / revoke / deactivate
protect_view     Protect a file: encrypt, sign, upload, register, step by step
requester_view   Browse files: every file and the user's access, request access
verify_view      Retrieve and verify: authorized key, V1-V6, key recovery, decryption, save
audit_view       Activity: contract events, CSV export
account_view     Account: key fingerprints, registration, network, balance
demo_view        Security demo: tampering and unauthorized calls (SFS_DEMO=1)
sidebar, page    navigation and the page base class
host             the protocol pages use to reach the main window
widgets, layout  canvas-drawn controls, panels, scroll areas, lists
feedback         step chain, toasts, account banner
dialogs          transaction confirmation dialog
theme, icons     colours, type scale, sizes; line icons drawn on canvases
worker, format   background threads (Tk is not thread-safe); Tk-free text formatting
redraw           macOS repaint workaround

The GUI only renders what the services return. It never handles a DEK and never
shows a private key; the most it shows of any key is its fingerprint.
"""
