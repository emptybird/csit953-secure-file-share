"""RequesterService.key_grant: the authorized key information a requester can see (task brief 2.5)."""

from __future__ import annotations

import pytest

from app.chain import RequestStatus
from app.crypto import ecies
from app.crypto.encoding import PUBLIC_KEY_LEN, fingerprint
from app.services import AccessDeniedError
from app.services.account import Session
from app.services.models import ProtectedFile
from app.services.owner import OwnerService
from app.services.requester import RequesterService


def test_grant_after_approval_is_the_on_chain_wrapped_key(
    alice: Session, carol: Session, protected: ProtectedFile
) -> None:
    requester = RequesterService(carol)
    with pytest.raises(AccessDeniedError, match="None"):
        requester.key_grant(protected.file_id)

    requester.request_access(protected.file_id)
    with pytest.raises(AccessDeniedError, match="Pending"):
        requester.key_grant(protected.file_id)

    owner = OwnerService(alice)
    owner.approve(owner.prepare_approval(protected.file_id, carol.address))
    grant = requester.key_grant(protected.file_id)

    on_chain = carol.chain.get_request(protected.file_id, carol.address)
    assert grant.status is RequestStatus.APPROVED
    assert grant.recipient == carol.address
    assert not grant.is_owner_copy
    assert grant.updated_at == on_chain.updated_at
    assert grant.wrapped_key == on_chain.wrapped_key
    assert grant.size == ecies.WRAPPED_KEY_LEN
    assert grant.ephemeral_fingerprint == fingerprint(on_chain.wrapped_key[:PUBLIC_KEY_LEN])
    assert "wrapped_key" not in repr(grant)

    owner.revoke(protected.file_id, carol.address)
    with pytest.raises(AccessDeniedError, match="Revoked"):
        requester.key_grant(protected.file_id)


def test_owner_sees_their_own_copy(alice: Session, protected: ProtectedFile) -> None:
    grant = RequesterService(alice).key_grant(protected.file_id)
    record = alice.chain.get_file(protected.file_id)
    assert grant.is_owner_copy
    assert grant.wrapped_key == record.owner_wrapped_key
    assert grant.updated_at == record.registered_at
