"""Owner and requester workflows on top of crypto/, storage/ and chain/.

models        result types the GUI renders (summaries, previews, the V1-V6 report)
account       Session (keys + chain + storage + event log) and key registration
owner         Protect & Register, request table, approve / reject / revoke / deactivate
requester     catalogue, request access, retrieve & verify, save plaintext
verification  the V1-V6 pipeline as pure functions: no network, no disk

No GUI imports, so tests and scripts call the services directly. Callers catch
ServiceError, ChainError, StorageError and CryptoError; all four carry messages
that are safe to show.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Base class for every workflow failure; catch this one type."""


class KeysNotRegisteredError(ServiceError):
    """The user (or the other party) has no public keys on-chain yet."""


class KeyMismatchError(ServiceError):
    """The keys registered on-chain are not the keys in this keystore."""


class NotFileOwnerError(ServiceError):
    """An owner-only action on a file someone else owns."""


class AccessDeniedError(ServiceError):
    """The request for this file is not Approved, so there is no wrapped key to open."""


class StaleApprovalError(ServiceError):
    """What the owner reviewed in the confirmation dialog is no longer current."""
