"""Which decisions the owner's request table offers (app/gui/owner_view.py); no display needed.

They must match what SecureFileShare accepts (contracts/test/AccessControl.t.sol):
approveAccess needs an active file, while rejectAccess and revokeAccess also work
after the owner deactivated it.
"""

from __future__ import annotations

import pytest

from app.chain import RequestStatus
from app.gui.owner_view import request_actions


@pytest.mark.parametrize(
    ("status", "active", "expected"),
    [
        (RequestStatus.PENDING, True, ("approve", "reject")),
        (RequestStatus.PENDING, False, ("reject",)),
        (RequestStatus.APPROVED, True, ("revoke",)),
        (RequestStatus.APPROVED, False, ("revoke",)),
        (RequestStatus.REJECTED, True, ()),
        (RequestStatus.REVOKED, False, ()),
        (RequestStatus.NONE, True, ()),
    ],
)
def test_actions_match_what_the_contract_accepts(
    status: RequestStatus, active: bool, expected: tuple[str, ...]
) -> None:
    assert request_actions(status, active=active) == expected
