"""The Demo tab's storage tampering, checked against the real V1–V6 pipeline (DESIGN.md 10.2: S6, S7, S9).

Uses the tamper functions behind the Demo tab buttons directly, so no display is needed.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from app.chain import ContractRevertError, TransactionFailedError
from app.crypto.ecies import WRAPPED_KEY_LEN
from app.crypto.encoding import to_hex32
from app.gui import demo_view
from app.services.account import Session
from app.services.models import Check, Outcome, ProtectedFile
from app.services.owner import OwnerService
from app.services.requester import RequesterService
from app.storage.object_store import LocalObjectStore


def _approved_copy(owner: Session, requester: Session, protected: ProtectedFile) -> None:
    RequesterService(requester).request_access(protected.file_id)
    service = OwnerService(owner)
    service.approve(service.prepare_approval(protected.file_id, requester.address))


def _tamper(session: Session, protected: ProtectedFile, action: str) -> str:
    store = session.store
    assert isinstance(store, LocalObjectStore)
    obj = store.object_path(protected.ct_hash.hex())
    manifest = store.manifest_path(to_hex32(protected.file_id))
    return demo_view._TAMPER[action](store.root, obj, manifest)


def _failed_checks(session: Session, protected: ProtectedFile, *, force: bool = False) -> set[Check]:
    report = RequesterService(session).retrieve(protected.file_id, force_decrypt=force).report
    return {r.check for r in report.results if r.outcome is Outcome.FAILED}


@pytest.mark.parametrize(
    ("action", "expected", "expected_forced"),
    [
        ("flip", {Check.V1_CT_HASH}, {Check.V1_CT_HASH, Check.V5_DECRYPT}),
        (
            "manifest",
            {Check.V2_MANIFEST_HASH, Check.V4_SIGNATURE},
            {Check.V2_MANIFEST_HASH, Check.V4_SIGNATURE, Check.V6_PT_DIGEST},
        ),
        ("delete", {Check.V1_CT_HASH}, {Check.V1_CT_HASH}),
    ],
)
def test_each_tamper_is_caught_and_restore_undoes_it(
    alice: Session,
    bob: Session,
    protected: ProtectedFile,
    action: str,
    expected: set[Check],
    expected_forced: set[Check],
) -> None:
    _approved_copy(alice, bob, protected)
    assert _failed_checks(bob, protected) == set()

    _tamper(bob, protected, action)
    assert _failed_checks(bob, protected) == expected
    assert _failed_checks(bob, protected, force=True) == expected_forced

    assert "Restored" in _tamper(bob, protected, "restore")
    retrieved = RequesterService(bob).retrieve(protected.file_id)
    assert retrieved.ok


def test_restore_keeps_the_first_original(alice: Session, protected: ProtectedFile) -> None:
    obj = alice.store.object_path(protected.ct_hash.hex())  # type: ignore[attr-defined]
    original = obj.read_bytes()
    _tamper(alice, protected, "flip")
    _tamper(alice, protected, "flip")  # flips the same bit back, but the backup is still the original
    _tamper(alice, protected, "delete")
    _tamper(alice, protected, "restore")
    assert obj.read_bytes() == original
    assert "Nothing to restore" in _tamper(alice, protected, "restore")


def test_unauthorized_approve_is_rejected_before_and_after_broadcast(
    mallory: Session, bob: Session, make_protected: Callable[..., ProtectedFile]
) -> None:
    """What the Demo tab's "Call approveAccess" does, with and without gas estimation."""
    protected = make_protected()
    RequesterService(bob).request_access(protected.file_id)
    wrapped_key = bytes(WRAPPED_KEY_LEN)

    with pytest.raises(ContractRevertError) as estimated:
        mallory.chain.approve_access(mallory.account(), protected.file_id, bob.address, wrapped_key)
    assert estimated.value.error_name == "NotFileOwner"

    with pytest.raises(TransactionFailedError) as mined:
        mallory.chain.transact(
            mallory.account(),
            "approveAccess",
            protected.file_id,
            bob.address,
            wrapped_key,
            gas_limit=demo_view.BROADCAST_GAS,
        )
    assert mined.value.revert is not None and mined.value.revert.error_name == "NotFileOwner"
    assert RequesterService(bob).file(protected.file_id).my_status.name == "PENDING"
