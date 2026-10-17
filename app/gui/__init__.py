"""Tkinter desktop GUI (DESIGN.md 8; task brief 2.5): `python -m app.gui`.

app              main window: login, sidebar, pages, toasts, chain polling, transactions
login_view       choose network and keystore, unlock, or create a keystore
owner_view       My files: requests per file, approve / reject / revoke / deactivate
protect_view     Protect a file: encrypt, sign, upload, register, step by step
requester_view   Browse files: every file and my access, request access
verify_view      Retrieve and verify: authorized key, V1–V6, key recovery, decryption, save
audit_view       Activity: contract events, CSV export
account_view     Account: key fingerprints, registration, network, balance
demo_view        Security demo: tampering and unauthorized calls (SFS_DEMO=1)
sidebar, page    navigation and the page base class
widgets, layout  canvas-drawn controls, panels, scroll areas, lists
feedback         step chain, toasts, banner; dialogs: confirmation dialog
theme, icons     colours, type scale, sizes; line icons drawn on canvases
worker, format   background threads (Tk is not thread-safe); text formatting without Tk

The GUI only renders what the services return. It never handles a DEK and never
shows a private key; the most it shows of any key is its fingerprint.
"""
