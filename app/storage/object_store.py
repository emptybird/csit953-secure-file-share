"""A local directory that simulates an untrusted cloud object store (DESIGN.md 2.2).

    <root>/objects/ab/ab3f…e9.bin     ciphertext object, named by SHA-256 of its content
    <root>/manifests/0x7c…41.json     signed manifest, named by fileId

Content addressing makes the on-chain ctHash the download address, so the chain
never stores a URL or path, and writing the same object twice keeps one copy.
Names are checked against strict patterns before any path is built, so a crafted
ctHash or fileId cannot reach outside the store (e.g. "../../keystore").

Reads return the bytes exactly as stored. The store does not check them: that is
the job of the services layer (V1, V2), because the store itself is untrusted.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Protocol

from app.storage import InvalidNameError, ObjectNotFoundError, ObjectTooLargeError, StorageError

MAX_OBJECT_BYTES = 50 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
OBJECTS_DIR = "objects"
MANIFESTS_DIR = "manifests"
_FANOUT_CHARS = 2

_CT_HASH = re.compile(r"[0-9a-f]{64}")
_FILE_ID = re.compile(r"0x[0-9a-f]{64}")


class ObjectStore(Protocol):
    """What the services need from storage; a remote HTTP store can implement the same four calls."""

    def put_object(self, data: bytes) -> str:
        """Store a ciphertext object and return its ctHash (lowercase hex SHA-256)."""
        ...

    def get_object(self, ct_hash: str) -> bytes: ...

    def put_manifest(self, file_id: str, signed_manifest: bytes) -> None: ...

    def get_manifest(self, file_id: str) -> bytes: ...


class LocalObjectStore:
    def __init__(self, root: Path, *, max_object_bytes: int = MAX_OBJECT_BYTES) -> None:
        self._root = Path(root)
        self._max_object_bytes = max_object_bytes

    @property
    def root(self) -> Path:
        return self._root

    def object_path(self, ct_hash: str) -> Path:
        """Where an object lives; tamper scripts and tests use this to edit it directly."""
        name = _checked_name(ct_hash, _CT_HASH, "ctHash must be 64 lowercase hex characters")
        return self._root / OBJECTS_DIR / name[:_FANOUT_CHARS] / f"{name}.bin"

    def manifest_path(self, file_id: str) -> Path:
        name = _checked_name(file_id, _FILE_ID, "fileId must be 0x followed by 64 lowercase hex characters")
        return self._root / MANIFESTS_DIR / f"{name}.json"

    def put_object(self, data: bytes) -> str:
        _check_size(data, self._max_object_bytes, "Encrypted file")
        ct_hash = hashlib.sha256(data).hexdigest()
        path = self.object_path(ct_hash)
        # An intact copy is already there; a damaged one is replaced.
        if not _has_content(path, data):
            _atomic_write(path, data)
        return ct_hash

    def get_object(self, ct_hash: str) -> bytes:
        return _read(self.object_path(ct_hash), self._max_object_bytes, f"Encrypted object {ct_hash[:12]}…")

    def put_manifest(self, file_id: str, signed_manifest: bytes) -> None:
        _check_size(signed_manifest, MAX_MANIFEST_BYTES, "Signed manifest")
        _atomic_write(self.manifest_path(file_id), signed_manifest)

    def get_manifest(self, file_id: str) -> bytes:
        return _read(self.manifest_path(file_id), MAX_MANIFEST_BYTES, f"Manifest of {file_id[:12]}…")


def _checked_name(value: object, pattern: re.Pattern[str], message: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise InvalidNameError(message)
    return value


def _check_size(data: bytes, limit: int, what: str) -> None:
    if not isinstance(data, bytes):
        raise TypeError(f"{what} must be bytes")
    if len(data) > limit:
        raise ObjectTooLargeError(f"{what} is {len(data):,} bytes; the limit is {limit:,}")


def _has_content(path: Path, data: bytes) -> bool:
    try:
        return path.stat().st_size == len(data) and path.read_bytes() == data
    except OSError:
        return False


def _atomic_write(path: Path, data: bytes) -> None:
    """Write to a temporary file in the same directory, then rename it into place,
    so a crash never leaves a half-written object behind."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise StorageError(f"Could not write {path.name}: {exc.strerror or exc}") from exc


def _read(path: Path, limit: int, what: str) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except FileNotFoundError:
        raise ObjectNotFoundError(f"{what} is missing from storage") from None
    except OSError as exc:
        raise StorageError(f"Could not read {what}: {exc.strerror or exc}") from exc
    if len(data) > limit:
        raise ObjectTooLargeError(f"{what} is larger than the {limit:,}-byte limit")
    return data
