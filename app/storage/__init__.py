"""Off-chain storage for ciphertext objects and signed manifests.

object_store  ObjectStore protocol and LocalObjectStore, a directory that
              simulates an untrusted cloud object store

Storage is outside the trust boundary. It only ever holds ciphertext and signed
manifests, and nothing read back from it is trusted: the services layer checks
every byte against the hashes registered on-chain (V1, V2).

Exceptions below are shared by all stores; their messages are safe to show to users.
"""

from __future__ import annotations


class StorageError(Exception):
    """Base class for every storage failure; catch this one type."""


class ObjectNotFoundError(StorageError):
    """No object or manifest is stored under that name."""


class ObjectTooLargeError(StorageError):
    """An object or manifest is above the size limit."""


class InvalidNameError(StorageError, ValueError):
    """A ctHash or fileId is not in the expected hex form."""
