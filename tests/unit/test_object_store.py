"""Local object store: content addressing, size limits and path safety."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.storage import InvalidNameError, ObjectNotFoundError, ObjectTooLargeError
from app.storage.object_store import MAX_MANIFEST_BYTES, LocalObjectStore

FILE_ID = "0x" + "7c" * 32


@pytest.fixture
def store(tmp_path: Path) -> LocalObjectStore:
    return LocalObjectStore(tmp_path / "storage", max_object_bytes=1024)  # small limit for the limit tests


class TestObjects:
    def test_content_addressed_round_trip(self, store: LocalObjectStore) -> None:
        data = b"SFS1 ciphertext"
        ct_hash = store.put_object(data)
        assert ct_hash == hashlib.sha256(data).hexdigest()
        assert store.get_object(ct_hash) == data
        assert store.object_path(ct_hash) == store.root / "objects" / ct_hash[:2] / f"{ct_hash}.bin"

    def test_same_content_is_stored_once(self, store: LocalObjectStore) -> None:
        first = store.put_object(b"same")
        second = store.put_object(b"same")
        assert first == second
        assert len(list((store.root / "objects").rglob("*.bin"))) == 1

    def test_put_repairs_a_damaged_copy(self, store: LocalObjectStore) -> None:
        ct_hash = store.put_object(b"original")
        store.object_path(ct_hash).write_bytes(b"damaged!")
        store.put_object(b"original")
        assert store.get_object(ct_hash) == b"original"

    def test_get_returns_tampered_bytes_unchecked(self, store: LocalObjectStore) -> None:
        """The store is untrusted; detecting this is V1's job, not the store's."""
        ct_hash = store.put_object(b"original")
        store.object_path(ct_hash).write_bytes(b"tampered")
        assert store.get_object(ct_hash) == b"tampered"

    def test_missing_object(self, store: LocalObjectStore) -> None:
        with pytest.raises(ObjectNotFoundError, match="missing from storage"):
            store.get_object("ab" * 32)

    def test_no_temporary_files_left(self, store: LocalObjectStore) -> None:
        store.put_object(b"x")
        store.put_manifest(FILE_ID, b"{}")
        assert not [p for p in store.root.rglob("*") if p.name.startswith(".tmp-")]


class TestLimits:
    def test_object_over_limit_is_rejected(self, store: LocalObjectStore) -> None:
        store.put_object(bytes(1024))
        with pytest.raises(ObjectTooLargeError):
            store.put_object(bytes(1025))

    def test_oversized_object_on_disk_is_not_read(self, store: LocalObjectStore) -> None:
        ct_hash = store.put_object(b"small")
        store.object_path(ct_hash).write_bytes(bytes(2048))
        with pytest.raises(ObjectTooLargeError):
            store.get_object(ct_hash)

    def test_manifest_limit(self, store: LocalObjectStore) -> None:
        with pytest.raises(ObjectTooLargeError):
            store.put_manifest(FILE_ID, bytes(MAX_MANIFEST_BYTES + 1))
        store.manifest_path(FILE_ID).parent.mkdir(parents=True)
        store.manifest_path(FILE_ID).write_bytes(bytes(MAX_MANIFEST_BYTES + 1))
        with pytest.raises(ObjectTooLargeError):
            store.get_manifest(FILE_ID)

    def test_data_must_be_bytes(self, store: LocalObjectStore) -> None:
        with pytest.raises(TypeError):
            store.put_object("text")  # type: ignore[arg-type]


class TestManifests:
    def test_round_trip_and_overwrite(self, store: LocalObjectStore) -> None:
        store.put_manifest(FILE_ID, b"v1")
        store.put_manifest(FILE_ID, b"v2")
        assert store.get_manifest(FILE_ID) == b"v2"
        assert store.manifest_path(FILE_ID) == store.root / "manifests" / f"{FILE_ID}.json"

    def test_missing_manifest(self, store: LocalObjectStore) -> None:
        with pytest.raises(ObjectNotFoundError):
            store.get_manifest(FILE_ID)


class TestNames:
    @pytest.mark.parametrize(
        "ct_hash",
        ["AB" * 32, "ab" * 31, "ab" * 33, "0x" + "ab" * 32, "../../keystore/alice", "ab" * 31 + "/.", "", None],
    )
    def test_invalid_ct_hash(self, store: LocalObjectStore, ct_hash: object) -> None:
        with pytest.raises(InvalidNameError):
            store.get_object(ct_hash)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "file_id",
        ["7c" * 32, "0x" + "7C" * 32, "0x" + "7c" * 31, "0x../../../etc/passwd", "0x" + "7c" * 32 + "\n", 7],
    )
    def test_invalid_file_id(self, store: LocalObjectStore, file_id: object) -> None:
        with pytest.raises(InvalidNameError):
            store.put_manifest(file_id, b"{}")  # type: ignore[arg-type]
        with pytest.raises(InvalidNameError):
            store.get_manifest(file_id)  # type: ignore[arg-type]

    def test_paths_stay_inside_the_root(self, store: LocalObjectStore) -> None:
        root = store.root.resolve()
        assert store.object_path("ff" * 32).resolve().is_relative_to(root)
        assert store.manifest_path(FILE_ID).resolve().is_relative_to(root)
