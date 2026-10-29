"""The logged-in user's session and public-key registration.

A Session ties one unlocked keystore to one network: chain client, object store
and event log. Owner and requester services both run on it. It also caches, in
memory only, the original names of files it has decrypted, since a name exists
only inside the encrypted object.

Keys are registered once per account. Registering different keys later is a
rotation and breaks older files, so it needs an explicit `rotate=True`:
manifests the user signed no longer verify against the new sigPubKey (V4), and
wrapped keys addressed to the old encPubKey only open with the old keystore.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from eth_account.signers.local import LocalAccount

from app.chain.client import ChainClient, SubmittedCallback, TxReceipt
from app.chain.events import EventLog
from app.config import AppConfig
from app.crypto.encoding import FileContext, fingerprint
from app.crypto.keystore import UserKeys
from app.services import KeyMismatchError, KeysNotRegisteredError, ServiceError
from app.services.models import AccountInfo, KeyStatus
from app.storage.object_store import LocalObjectStore, ObjectStore


@dataclass(frozen=True, eq=False)
class Session:
    """One unlocked keystore bound to one network."""

    keys: UserKeys
    chain: ChainClient
    store: ObjectStore
    events: EventLog
    names: dict[bytes, str] = field(default_factory=dict, repr=False)  # fileId -> original name

    @property
    def address(self) -> str:
        return self.keys.address

    def account(self) -> LocalAccount:
        return self.keys.account()

    def file_context(self, file_id: bytes, owner: str) -> FileContext:
        """The binding used for AAD, manifest and key wrapping of one file on this deployment."""
        return FileContext(
            chain_id=self.chain.chain_id, contract=self.chain.contract_address, file_id=file_id, owner=owner
        )


def open_session(config: AppConfig, keys: UserKeys) -> Session:
    """Connect to the configured network (checks chainId and contract) and open storage."""
    chain = ChainClient.connect(config.network)
    return Session(keys=keys, chain=chain, store=LocalObjectStore(config.storage_dir), events=EventLog(chain))


class AccountService:
    """Key registration and account status."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def key_status(self) -> KeyStatus:
        """Compare the keys registered on-chain with this keystore."""
        keys = self._session.keys
        registered = self._session.chain.get_user_keys(keys.address)
        if not registered.is_registered:
            return KeyStatus.NOT_REGISTERED
        if (registered.sig_public_key, registered.enc_public_key) == (keys.sig_public_key, keys.enc_public_key):
            return KeyStatus.MATCHES
        return KeyStatus.MISMATCH

    def info(self) -> AccountInfo:
        keys, chain = self._session.keys, self._session.chain
        return AccountInfo(
            address=keys.address,
            network=chain.config.name,
            balance_wei=chain.balance(keys.address),
            key_status=self.key_status(),
            sig_fingerprint=fingerprint(keys.sig_public_key),
            enc_fingerprint=fingerprint(keys.enc_public_key),
        )

    def register_keys(self, *, rotate: bool = False, on_submitted: SubmittedCallback | None = None) -> TxReceipt:
        """registerKeys(sigPub, encPub) from this keystore; the first step for every user."""
        status = self.key_status()
        if status is KeyStatus.MATCHES:
            raise ServiceError("Your public keys are already registered on this network")
        if status is KeyStatus.MISMATCH and not rotate:
            raise KeyMismatchError(
                "This account already registered different keys. Replacing them breaks files you shared "
                "before (their signatures no longer verify) and keys sent to the old encryption key."
            )
        keys = self._session.keys
        return self._session.chain.register_keys(
            self._session.account(), keys.sig_public_key, keys.enc_public_key, on_submitted=on_submitted
        )

    def require_registered(self) -> None:
        """Raise unless the on-chain keys match this keystore. Owners need that for their
        signatures to verify; requesters, for the wrapped keys they receive to open."""
        status = self.key_status()
        if status is KeyStatus.NOT_REGISTERED:
            raise KeysNotRegisteredError("Register your public keys first.")
        if status is KeyStatus.MISMATCH:
            raise KeyMismatchError("The keys registered on-chain for this account are not the keys in this keystore")
