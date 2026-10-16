"""End-to-end owner and requester workflows on Anvil (DESIGN.md 7, 10.1)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from app.chain import ContractRevertError, RequestStatus
from app.chain.client import ChainClient
from app.config import NetworkConfig, load_config
from app.crypto.encoding import fingerprint, to_hex32
from app.crypto.keystore import generate_user_keys
from app.services import (
    AccessDeniedError,
    KeyMismatchError,
    KeysNotRegisteredError,
    NotFileOwnerError,
    ServiceError,
    StaleApprovalError,
)
from app.services import owner as owner_module
from app.services.account import AccountService, Session, open_session
from app.services.models import Check, KeyStatus, ProtectedFile, ProtectStage
from app.services.owner import OwnerService
from app.services.requester import RequesterService, save_plaintext


def _share(owner: Session, requester: Session, file_id: bytes) -> None:
    """requestAccess by the requester, then approval by the owner."""
    RequesterService(requester).request_access(file_id)
    service = OwnerService(owner)
    service.approve(service.prepare_approval(file_id, requester.address))


def _status(chain: ChainClient, file_id: bytes, requester: Session) -> RequestStatus:
    return chain.get_request(file_id, requester.address).status


class TestAccount:
    def test_first_login_then_register(self, make_session: Callable[..., Session]) -> None:
        session = make_session(register=False)
        account = AccountService(session)
        info = account.info()
        assert info.key_status is KeyStatus.NOT_REGISTERED
        assert info.network == "local"
        assert info.balance_wei > 0
        assert info.enc_fingerprint == fingerprint(session.keys.enc_public_key)

        submitted: list[str] = []
        receipt = account.register_keys(on_submitted=submitted.append)
        assert submitted == [receipt.tx_hash]
        assert account.key_status() is KeyStatus.MATCHES
        with pytest.raises(ServiceError, match="already registered"):
            account.register_keys()

    def test_different_keys_need_explicit_rotation(self, make_session: Callable[..., Session]) -> None:
        original = make_session()
        # Same Ethereum account, new signing and encryption keys (e.g. a second import).
        replacement = make_session(register=False, keys=generate_user_keys(original.keys.eth_key))
        assert AccountService(replacement).key_status() is KeyStatus.MISMATCH
        with pytest.raises(KeyMismatchError):
            AccountService(replacement).register_keys()
        with pytest.raises(KeyMismatchError):
            AccountService(replacement).require_registered()

        AccountService(replacement).register_keys(rotate=True)
        assert AccountService(replacement).key_status() is KeyStatus.MATCHES
        assert AccountService(original).key_status() is KeyStatus.MISMATCH

    def test_unregistered_user_can_neither_share_nor_request(
        self, make_session: Callable[..., Session], plaintext: Path, protected: ProtectedFile
    ) -> None:
        newcomer = make_session(register=False)
        with pytest.raises(KeysNotRegisteredError):
            OwnerService(newcomer).protect_file(plaintext)
        with pytest.raises(KeysNotRegisteredError):
            RequesterService(newcomer).request_access(protected.file_id)


class TestHappyPath:
    def test_share_end_to_end(self, alice: Session, bob: Session, plaintext: Path, tmp_path: Path) -> None:
        """Alice registers -> Bob requests -> Alice approves -> Bob verifies and decrypts."""
        stages: list[ProtectStage] = []
        protected = OwnerService(alice).protect_file(
            plaintext, label="Q3 report", on_progress=lambda stage, _detail: stages.append(stage)
        )
        assert stages == list(ProtectStage)
        assert protected.name == plaintext.name
        assert protected.size == plaintext.stat().st_size
        file_id = protected.file_id

        browse = RequesterService(bob)
        entry = next(f for f in browse.catalogue() if f.file_id == file_id)
        assert (entry.owner, entry.label, entry.my_status, entry.can_retrieve) == (
            alice.address,
            "Q3 report",
            RequestStatus.NONE,
            False,
        )

        browse.request_access(file_id)
        owner = OwnerService(alice)
        [request] = owner.requests_for(file_id)
        assert (request.requester, request.status) == (bob.address, RequestStatus.PENDING)
        assert request.enc_fingerprint == fingerprint(bob.keys.enc_public_key)

        preview = owner.prepare_approval(file_id, bob.address)
        assert preview.enc_fingerprint == fingerprint(bob.keys.enc_public_key)
        assert preview.label == "Q3 report"
        receipt = owner.approve(preview)
        assert receipt.event("AccessApproved") is not None
        assert browse.file(file_id).can_retrieve

        result = browse.retrieve(file_id)
        assert result.ok, result.report.failures
        assert result.plaintext is not None
        assert result.plaintext.content == plaintext.read_bytes()
        assert result.plaintext.header.name == plaintext.name

        downloads = tmp_path / "downloads"
        downloads.mkdir()
        assert save_plaintext(result, downloads).read_bytes() == plaintext.read_bytes()
        assert [f.my_status for f in browse.my_requests() if f.file_id == file_id] == [RequestStatus.APPROVED]

    def test_storage_holds_only_ciphertext(self, alice: Session, plaintext: Path, protected: ProtectedFile) -> None:
        content = plaintext.read_bytes()
        stored_object = alice.store.get_object(protected.ct_hash.hex())
        stored_manifest = alice.store.get_manifest(to_hex32(protected.file_id))
        assert content[:64] not in stored_object
        for blob in (stored_object, stored_manifest):
            assert plaintext.name.encode() not in blob
            assert b"Q3 report" not in blob

    def test_owner_retrieves_own_file(self, alice: Session, plaintext: Path, protected: ProtectedFile) -> None:
        result = RequesterService(alice).retrieve(protected.file_id)
        assert result.ok
        assert result.plaintext is not None
        assert result.plaintext.content == plaintext.read_bytes()

    def test_my_files(self, alice: Session, bob: Session, protected: ProtectedFile, plaintext: Path) -> None:
        bobs_file = OwnerService(bob).protect_file(plaintext)
        mine = {f.file_id: f for f in OwnerService(alice).my_files()}
        assert protected.file_id in mine
        assert bobs_file.file_id not in mine
        assert mine[protected.file_id].label == "Q3 report"
        assert mine[protected.file_id].is_mine and mine[protected.file_id].active

    def test_two_requesters_get_their_own_wrapped_keys(
        self, chain: ChainClient, alice: Session, bob: Session, carol: Session, protected: ProtectedFile
    ) -> None:
        _share(alice, bob, protected.file_id)
        _share(alice, carol, protected.file_id)
        bobs = chain.get_request(protected.file_id, bob.address).wrapped_key
        carols = chain.get_request(protected.file_id, carol.address).wrapped_key
        assert len(bobs) == len(carols) == 93
        assert bobs != carols
        assert RequesterService(bob).retrieve(protected.file_id).ok
        assert RequesterService(carol).retrieve(protected.file_id).ok


class TestRejectBranch:
    def test_rejected_then_asks_again(
        self, chain: ChainClient, alice: Session, bob: Session, protected: ProtectedFile
    ) -> None:
        file_id = protected.file_id
        RequesterService(bob).request_access(file_id)
        OwnerService(alice).reject(file_id, bob.address)
        assert _status(chain, file_id, bob) is RequestStatus.REJECTED

        with pytest.raises(AccessDeniedError, match="Rejected"):
            RequesterService(bob).retrieve(file_id)
        with pytest.raises(StaleApprovalError, match="Rejected"):
            OwnerService(alice).prepare_approval(file_id, bob.address)

        RequesterService(bob).request_access(file_id)
        assert _status(chain, file_id, bob) is RequestStatus.PENDING
        OwnerService(alice).approve(OwnerService(alice).prepare_approval(file_id, bob.address))
        assert RequesterService(bob).retrieve(file_id).ok


class TestRevokeBranch:
    def test_revoked_access_and_new_request(
        self, chain: ChainClient, alice: Session, bob: Session, protected: ProtectedFile
    ) -> None:
        file_id = protected.file_id
        _share(alice, bob, file_id)
        assert RequesterService(bob).retrieve(file_id).ok

        OwnerService(alice).revoke(file_id, bob.address)
        request = chain.get_request(file_id, bob.address)
        assert request.status is RequestStatus.REVOKED
        assert request.wrapped_key == b""
        with pytest.raises(AccessDeniedError, match="Revoked"):
            RequesterService(bob).retrieve(file_id)

        RequesterService(bob).request_access(file_id)
        assert _status(chain, file_id, bob) is RequestStatus.PENDING
        with pytest.raises(AccessDeniedError, match="Pending"):
            RequesterService(bob).retrieve(file_id)


class TestApprovalSafety:
    def test_only_the_owner_can_prepare_or_approve(
        self, alice: Session, bob: Session, mallory: Session, protected: ProtectedFile
    ) -> None:
        RequesterService(bob).request_access(protected.file_id)
        preview = OwnerService(alice).prepare_approval(protected.file_id, bob.address)
        with pytest.raises(NotFileOwnerError):
            OwnerService(mallory).prepare_approval(protected.file_id, bob.address)
        with pytest.raises(NotFileOwnerError):
            OwnerService(mallory).approve(preview)

    def test_key_change_after_review_aborts(
        self,
        chain: ChainClient,
        alice: Session,
        make_session: Callable[..., Session],
        protected: ProtectedFile,
    ) -> None:
        """The owner confirmed one fingerprint; if the requester's key changes before the
        approval is sent, nothing is sent and the owner has to review again."""
        requester = make_session()
        RequesterService(requester).request_access(protected.file_id)
        preview = OwnerService(alice).prepare_approval(protected.file_id, requester.address)

        rotated = make_session(register=False, keys=generate_user_keys(requester.keys.eth_key))
        AccountService(rotated).register_keys(rotate=True)
        with pytest.raises(StaleApprovalError, match="changed"):
            OwnerService(alice).approve(preview)
        assert _status(chain, protected.file_id, requester) is RequestStatus.PENDING

    def test_nothing_to_approve(self, alice: Session, carol: Session, protected: ProtectedFile) -> None:
        with pytest.raises(StaleApprovalError, match="None"):
            OwnerService(alice).prepare_approval(protected.file_id, carol.address)

    def test_deactivated_file(
        self, alice: Session, bob: Session, carol: Session, mallory: Session, protected: ProtectedFile
    ) -> None:
        file_id = protected.file_id
        _share(alice, bob, file_id)
        RequesterService(carol).request_access(file_id)
        OwnerService(alice).deactivate(file_id)

        assert not RequesterService(bob).file(file_id).active
        with pytest.raises(ContractRevertError, match="deactivated"):
            RequesterService(mallory).request_access(file_id)
        with pytest.raises(ServiceError, match="deactivated"):
            OwnerService(alice).prepare_approval(file_id, carol.address)
        OwnerService(alice).reject(file_id, carol.address)
        # Access granted before deactivation still works.
        assert RequesterService(bob).retrieve(file_id).ok


class TestRequesterErrors:
    def test_contract_rules_come_back_as_readable_errors(
        self, alice: Session, bob: Session, protected: ProtectedFile
    ) -> None:
        with pytest.raises(ContractRevertError, match="You own this file"):
            RequesterService(alice).request_access(protected.file_id)
        with pytest.raises(ContractRevertError, match="No file"):
            RequesterService(bob).request_access(b"\x42" * 32)
        RequesterService(bob).request_access(protected.file_id)
        with pytest.raises(ContractRevertError, match="Pending"):
            RequesterService(bob).request_access(protected.file_id)

    def test_retrieve_without_approval(self, mallory: Session, protected: ProtectedFile) -> None:
        with pytest.raises(AccessDeniedError, match="None"):
            RequesterService(mallory).retrieve(protected.file_id)

    def test_retrieve_unknown_file(self, bob: Session) -> None:
        with pytest.raises(ContractRevertError) as info:
            RequesterService(bob).retrieve(b"\x42" * 32)
        assert info.value.error_name == "FileNotFound"


class TestStorageFailures:
    """Detection through the real store; the full S-matrix lives in tests/security."""

    def test_tampered_object_is_reported_not_decrypted(
        self, alice: Session, bob: Session, protected: ProtectedFile
    ) -> None:
        _share(alice, bob, protected.file_id)
        path = alice.store.object_path(protected.ct_hash.hex())
        data = bytearray(path.read_bytes())
        data[100] ^= 0x01
        path.write_bytes(bytes(data))

        result = RequesterService(bob).retrieve(protected.file_id)
        assert not result.ok
        assert result.plaintext is None
        assert [r.check for r in result.report.failures] == [Check.V1_CT_HASH]
        forced = RequesterService(bob).retrieve(protected.file_id, force_decrypt=True)
        assert [r.check for r in forced.report.failures] == [Check.V1_CT_HASH, Check.V5_DECRYPT]

    def test_deleted_manifest_is_reported(self, alice: Session, bob: Session, protected: ProtectedFile) -> None:
        _share(alice, bob, protected.file_id)
        alice.store.manifest_path(to_hex32(protected.file_id)).unlink()
        result = RequesterService(bob).retrieve(protected.file_id)
        v2 = result.report.result(Check.V2_MANIFEST_HASH)
        assert not result.ok
        assert "missing from storage" in v2.detail


class TestOwnerInputChecks:
    def test_label_too_long(self, alice: Session, plaintext: Path) -> None:
        with pytest.raises(ServiceError, match="128 bytes"):
            OwnerService(alice).protect_file(plaintext, label="é" * 65)

    def test_unreadable_file(self, alice: Session, tmp_path: Path) -> None:
        with pytest.raises(ServiceError, match="Cannot read"):
            OwnerService(alice).protect_file(tmp_path / "absent.txt")

    def test_file_too_large(self, alice: Session, plaintext: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(owner_module, "MAX_FILE_BYTES", 100)
        with pytest.raises(ServiceError, match="larger than"):
            OwnerService(alice).protect_file(plaintext)

    def test_S14_off_curve_encryption_key_is_refused(
        self, chain: ChainClient, alice: Session, make_session: Callable[..., Session], protected: ProtectedFile
    ) -> None:
        """The contract checks only length and prefix; the owner's client must refuse to
        wrap a file key to a point that is not on secp256k1 (invalid-curve attack)."""
        attacker = make_session(register=False)
        off_curve = b"\x02" + b"\xff" * 32  # x is above the field prime
        chain.register_keys(attacker.account(), attacker.keys.sig_public_key, off_curve)
        chain.request_access(attacker.account(), protected.file_id)
        with pytest.raises(ServiceError, match="invalid"):
            OwnerService(alice).prepare_approval(protected.file_id, attacker.address)

    def test_owner_who_lost_the_old_keystore_cannot_approve(
        self, make_session: Callable[..., Session], bob: Session, plaintext: Path
    ) -> None:
        """ownerWrappedKey opens only with the encryption key the file was registered under."""
        owner = make_session()
        protected = OwnerService(owner).protect_file(plaintext)
        RequesterService(bob).request_access(protected.file_id)
        preview = OwnerService(owner).prepare_approval(protected.file_id, bob.address)

        new_keystore = make_session(register=False, keys=generate_user_keys(owner.keys.eth_key))
        AccountService(new_keystore).register_keys(rotate=True)
        with pytest.raises(ServiceError, match="Cannot recover the file key"):
            OwnerService(new_keystore).approve(preview)


def test_open_session_from_env_file(network: NetworkConfig, tmp_path: Path) -> None:
    """The login path: .env.<network> -> load_config -> open_session."""
    (tmp_path / ".env.local").write_text(
        f"RPC_URL={network.rpc_url}\nCHAIN_ID={network.chain_id}\n"
        f"CONTRACT_ADDRESS={network.contract_address}\nDEPLOY_BLOCK={network.deploy_block}\n"
        "STORAGE_DIR=shared\n",
        encoding="utf-8",
    )
    session = open_session(load_config("local", root=tmp_path), generate_user_keys())
    assert session.store.root == tmp_path / "shared"
    assert AccountService(session).key_status() is KeyStatus.NOT_REGISTERED
    assert session.events.refresh()
