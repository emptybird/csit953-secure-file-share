"""ChainClient against a live Anvil: connection checks, views, transactions, events."""

from __future__ import annotations

import dataclasses
import os
import threading
from collections.abc import Callable

import pytest
from web3.exceptions import Web3RPCError

from app.chain import (
    ChainConnectionError,
    ChainError,
    ContractRevertError,
    RequestStatus,
    TransactionError,
    TransactionFailedError,
    TransactionTimeoutError,
)
from app.chain import client as client_module
from app.chain.client import ChainClient, load_abi
from app.chain.events import EventLog
from app.config import NetworkConfig
from app.crypto import ecies
from app.crypto.encoding import compute_file_id
from app.crypto.keystore import generate_user_keys
from app.services.account import Session
from app.services.models import ProtectedFile


class TestConnect:
    def test_wrong_chain_id(self, network: NetworkConfig) -> None:
        with pytest.raises(ChainConnectionError, match="is chain 31337"):
            ChainClient.connect(dataclasses.replace(network, chain_id=11155111))

    def test_no_contract_at_address(self, network: NetworkConfig) -> None:
        empty = dataclasses.replace(network, contract_address=generate_user_keys().address)
        with pytest.raises(ChainConnectionError, match="No contract"):
            ChainClient.connect(empty)

    def test_unreachable_node_does_not_leak_the_url(self, network: NetworkConfig, free_port: int) -> None:
        offline = dataclasses.replace(network, rpc_url=f"http://127.0.0.1:{free_port}/v2/SECRETKEY")
        with pytest.raises(ChainConnectionError) as info:
            ChainClient.connect(offline, timeout=2)
        assert "SECRETKEY" not in str(info.value)
        assert info.value.__cause__ is None and info.value.__suppress_context__


class TestViews:
    def test_file_id_matches_the_contract(self, chain: ChainClient, alice: Session) -> None:
        """The client builds the AAD from a locally computed fileId before registering."""
        for _ in range(5):
            salt = os.urandom(32)
            assert chain.compute_file_id(alice.address, salt) == compute_file_id(alice.address, salt)

    def test_unknown_values(self, chain: ChainClient) -> None:
        stranger = generate_user_keys().address
        assert not chain.get_user_keys(stranger).is_registered
        assert chain.get_request(b"\x01" * 32, stranger).status is RequestStatus.NONE
        with pytest.raises(ContractRevertError) as info:
            chain.get_file(b"\x01" * 32)
        assert info.value.error_name == "FileNotFound"

    def test_registered_keys(self, chain: ChainClient, alice: Session) -> None:
        keys = chain.get_user_keys(alice.address)
        assert keys.sig_public_key == alice.keys.sig_public_key
        assert keys.enc_public_key == alice.keys.enc_public_key

    def test_file_record(self, chain: ChainClient, alice: Session, protected: ProtectedFile) -> None:
        record = chain.get_file(protected.file_id)
        assert record.owner == alice.address
        assert record.active
        assert record.ct_hash == protected.ct_hash
        assert record.manifest_hash == protected.manifest_hash
        assert len(record.owner_wrapped_key) == ecies.WRAPPED_KEY_LEN
        assert "owner_wrapped_key" not in repr(record)

    def test_input_validation(self, chain: ChainClient) -> None:
        with pytest.raises(ValueError):
            chain.get_file(b"short")
        with pytest.raises(ValueError):
            chain.get_user_keys("0x1234")


class TestTransactions:
    def test_receipt_and_submitted_callback(self, chain: ChainClient, bob: Session, protected: ProtectedFile) -> None:
        submitted: list[str] = []
        receipt = chain.request_access(bob.account(), protected.file_id, on_submitted=submitted.append)
        assert submitted == [receipt.tx_hash]
        assert receipt.gas_used > 21_000
        event = receipt.event("AccessRequested")
        assert event is not None
        assert (event.file_id, event.account) == (protected.file_id, bob.address)
        assert receipt.event("AccessApproved") is None

    def test_revert_is_caught_before_sending(
        self, chain: ChainClient, mallory: Session, bob: Session, protected: ProtectedFile
    ) -> None:
        chain.request_access(bob.account(), protected.file_id)
        nonce = chain.web3.eth.get_transaction_count(mallory.address)
        balance = chain.balance(mallory.address)
        with pytest.raises(ContractRevertError) as info:
            chain.approve_access(mallory.account(), protected.file_id, bob.address, bytes(93))
        assert info.value.error_name == "NotFileOwner"
        assert "Only the owner" in str(info.value)
        assert chain.web3.eth.get_transaction_count(mallory.address) == nonce
        assert chain.balance(mallory.address) == balance

    def test_fixed_gas_limit_mines_the_revert(
        self, chain: ChainClient, mallory: Session, bob: Session, protected: ProtectedFile
    ) -> None:
        """A fixed gas limit skips estimation, so the reverting call is mined and costs gas."""
        chain.request_access(bob.account(), protected.file_id)
        balance = chain.balance(mallory.address)
        with pytest.raises(TransactionFailedError) as info:
            chain.transact(
                mallory.account(), "approveAccess", protected.file_id, bob.address, bytes(93), gas_limit=200_000
            )
        assert info.value.revert is not None
        assert info.value.revert.error_name == "NotFileOwner"
        receipt = chain.web3.eth.get_transaction_receipt(info.value.tx_hash)
        assert receipt["status"] == 0
        assert chain.balance(mallory.address) < balance
        assert chain.get_request(protected.file_id, bob.address).status is RequestStatus.PENDING

    def test_replayed_transaction_is_rejected(
        self, chain: ChainClient, bob: Session, protected: ProtectedFile
    ) -> None:
        contract = chain.web3.eth.contract(address=chain.contract_address, abi=load_abi())
        tx = contract.functions.requestAccess(protected.file_id).build_transaction(
            {
                "from": bob.address,
                "chainId": chain.chain_id,
                "nonce": chain.web3.eth.get_transaction_count(bob.address, "pending"),
            }
        )
        raw = bob.account().sign_transaction(tx).raw_transaction
        chain.web3.eth.wait_for_transaction_receipt(chain.web3.eth.send_raw_transaction(raw))
        with pytest.raises(Web3RPCError, match="(?i)nonce"):
            chain.web3.eth.send_raw_transaction(raw)

    def test_not_enough_eth(self, chain: ChainClient) -> None:
        broke = generate_user_keys()
        with pytest.raises(TransactionError, match="Not enough ETH"):
            chain.register_keys(broke.account(), broke.sig_public_key, broke.enc_public_key)

    def test_one_account_from_many_threads(
        self, chain: ChainClient, bob: Session, make_protected: Callable[..., ProtectedFile]
    ) -> None:
        """GUI workers share one client; the send lock keeps their nonces apart."""
        files = [make_protected() for _ in range(4)]
        failures: list[ChainError] = []

        def request(file_id: bytes) -> None:
            try:
                chain.request_access(bob.account(), file_id)
            except ChainError as exc:
                failures.append(exc)

        threads = [threading.Thread(target=request, args=(f.file_id,)) for f in files]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert failures == []
        assert all(chain.get_request(f.file_id, bob.address).status is RequestStatus.PENDING for f in files)


class TestEvents:
    def test_full_lifecycle_in_small_chunks(
        self, chain: ChainClient, alice: Session, bob: Session, carol: Session, protected: ProtectedFile
    ) -> None:
        file_id = protected.file_id
        start = chain.latest_block()
        chain.request_access(bob.account(), file_id)
        chain.request_access(carol.account(), file_id)
        chain.approve_access(alice.account(), file_id, bob.address, bytes(93))
        chain.reject_access(alice.account(), file_id, carol.address)
        chain.revoke_access(alice.account(), file_id, bob.address)
        chain.deactivate_file(alice.account(), file_id)

        log = EventLog(chain, chunk_blocks=2)
        log.refresh()
        mine = [e for e in log.events if e.file_id == file_id]
        assert [e.name for e in mine] == [
            "FileRegistered",
            "AccessRequested",
            "AccessRequested",
            "AccessApproved",
            "AccessRejected",
            "AccessRevoked",
            "FileDeactivated",
        ]
        assert mine[0].label == "Q3 report"
        assert mine[0].args["ctHash"] == protected.ct_hash
        assert [e.account for e in mine[1:6]] == [bob.address, carol.address, bob.address, carol.address, bob.address]
        assert log.requesters(file_id) == (bob.address, carol.address)
        assert all(e.block_number > start for e in mine[1:])
        assert log.refresh() == ()

    def test_keys_registered_event(self, chain: ChainClient, make_session: Callable[..., Session]) -> None:
        session = make_session()
        log = EventLog(chain)
        log.refresh()
        registered = [e for e in log.events if e.name == "KeysRegistered" and e.account == session.address]
        assert len(registered) == 1
        assert registered[0].args["encPubKey"] == session.keys.enc_public_key


class TestTimeout:
    def test_no_receipt_in_time(
        self, chain: ChainClient, bob: Session, protected: ProtectedFile, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With mining paused the transaction stays pending; the error keeps its hash
        so the GUI can say it may still be mined."""
        monkeypatch.setattr(client_module, "RECEIPT_TIMEOUT_SECONDS", 0.3)
        provider = chain.web3.provider
        provider.make_request("evm_setAutomine", [False])
        try:
            with pytest.raises(TransactionTimeoutError) as info:
                chain.request_access(bob.account(), protected.file_id)
        finally:
            provider.make_request("evm_setAutomine", [True])
        provider.make_request("evm_mine", [])
        assert chain.web3.eth.get_transaction_receipt(info.value.tx_hash)["status"] == 1
        assert chain.get_request(protected.file_id, bob.address).status is RequestStatus.PENDING
