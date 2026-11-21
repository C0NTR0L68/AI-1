"""Scratch-only qualification for Windows immutable archive publication."""
from contextlib import contextmanager, closing
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest

from app.memory_archive_v2 import ArchiveUnavailable, build_archive, restore_archive
from app.memory_archive_publish_v2 import (
    PublicationUnconfirmed, archive_quiescent_image, publish_archive, read_published_archive,
)
from app.memory_crypto import protect_for_current_user, unprotect_for_current_user
from app.memory_keys_v2 import issue_receipt_key, open_receipt_key
from app.memory_ledger import MemoryLedger
from app.memory_reconciliation import OperationIdentity
from app.windows_storage_inspector import hold_archive_directory, inspect_component, read_pinned_artifact

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI and rename behavior")
TEXT = "Синтетическая заметка 📚".encode()


@pytest.fixture
def scratch():
    root = Path(os.environ["AI1_TEST_ROOT"]) / uuid4().hex
    root.mkdir()
    db = root / "source.sqlite3"
    generation = uuid4()
    key = issue_receipt_key(generation)
    with closing(sqlite3.connect(db)) as conn:
        ledger = MemoryLedger(conn, enabled=True, receipt_budget=8)
        ledger.initialize_empty(generation)
        ledger.mutate(OperationIdentity(uuid4(), generation, b"fixture"), "create",
                      sealed=protect_for_current_user(TEXT))
    folder = inspect_component(str(root), expected_kind="directory")
    locked = []

    @contextmanager
    def hold(directory):
        assert directory == root
        # Scratch is private to this test; this does not attest production ACL.
        with hold_archive_directory(str(root), require_private_acl=False) as actual:
            assert actual.identity == folder.identity
            locked.append(True)
            try:
                yield
            finally:
                locked.pop()

    def read_bound(path, limit):
        assert locked and path.parent == root
        expected = inspect_component(str(path), expected_kind="file")
        return read_pinned_artifact(str(path), expected=expected, max_bytes=limit, require_private_acl=False)

    return root, db, key, {"hold_directory": hold, "read_bound": read_bound}


def backup(scratch):
    _, db, key, admission = scratch
    pin = sha256(db.read_bytes()).digest()
    archive = archive_quiescent_image(db, approved_database_pin=pin, capsule=key,
                                      approved_key_pin=key.fingerprint, **admission)
    return archive, pin


def test_offline_image_and_published_restore_never_replace_existing_history(scratch):
    root, db, _, admission = scratch
    archive, original = backup(scratch)
    published = publish_archive(archive, root, **admission)
    assert not published.reused
    assert publish_archive(archive, root, **admission).reused
    assert list(root.glob("*.v2a")) == [published.path]
    data = read_published_archive(root, fingerprint=archive.fingerprint, **admission)
    restored = restore_archive(data, approved_archive_pin=archive.fingerprint, restore_generation=uuid4())
    with closing(sqlite3.connect(":memory:")) as conn:
        conn.deserialize(restored.sqlite_image)
        ledger = MemoryLedger(conn, enabled=True, receipt_budget=8)
        note, = ledger.read(restored.generation)
        assert unprotect_for_current_user(note.sealed) == TEXT
        new_archive = build_archive(conn, capsule=restored.key, approved_key_pin=restored.key.fingerprint)
    new_release = publish_archive(new_archive, root, **admission)
    assert new_release.path != published.path
    assert sha256(db.read_bytes()).digest() == original
    assert read_published_archive(root, fingerprint=archive.fingerprint, **admission) == data
    assert len(open_receipt_key(restored.generation, restored.key.sealed,
                                approved_fingerprint=restored.key.fingerprint)) == 32
    assert TEXT not in published.path.read_bytes() and TEXT not in new_release.path.read_bytes()


@pytest.mark.parametrize("failure", ["flush", "before_rename", "after_rename", "collision"])
def test_publication_failure_does_not_overwrite_and_is_reconciled_by_read(scratch, monkeypatch, failure):
    root, db, _, admission = scratch
    archive, original = backup(scratch)
    real_rename = os.rename
    final = root / ("memory-" + archive.fingerprint.hex() + ".v2a")

    def rename(source, destination):
        if failure == "after_rename":
            real_rename(source, destination)
        elif failure == "collision":
            # Simulate an existing unrelated artifact appearing before rename.
            with destination.open("xb") as rival:
                rival.write(b"existing")
            return real_rename(source, destination)
        raise OSError("synthetic interruption")

    def bad_flush(_):
        raise OSError("synthetic flush failure")

    if failure == "flush":
        monkeypatch.setattr(os, "fsync", bad_flush)
    else:
        monkeypatch.setattr(os, "rename", rename)
    with pytest.raises(PublicationUnconfirmed):
        publish_archive(archive, root, **admission)
    if failure == "after_rename":
        assert read_published_archive(root, fingerprint=archive.fingerprint, **admission) == archive.data
    else:
        with pytest.raises(PublicationUnconfirmed):
            read_published_archive(root, fingerprint=archive.fingerprint, **admission)
        assert list(root.glob("*.pending"))
    if failure == "collision":
        assert final.read_bytes() == b"existing"
    assert sha256(db.read_bytes()).digest() == original


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_disk_sidecars_rejected_before_sqlite_deserialization(scratch, monkeypatch, suffix):
    _, db, capsule, admission = scratch
    pin = sha256(db.read_bytes()).digest()
    Path(str(db) + suffix).write_bytes(b"synthetic sidecar")

    def unexpected(*args, **kwargs):
        pytest.fail("SQLite must not open when a sidecar is present")

    monkeypatch.setattr(sqlite3, "connect", unexpected)
    with pytest.raises(ArchiveUnavailable, match="offline_image_unavailable"):
        archive_quiescent_image(db, approved_database_pin=pin, capsule=capsule,
                                approved_key_pin=capsule.fingerprint, **admission)


def test_sidecar_appearing_during_bound_read_refuses_archive(scratch):
    _, db, capsule, admission = scratch
    pin = sha256(db.read_bytes()).digest()
    original_read = admission["read_bound"]
    def read_and_add_sidecar(path, limit):
        data = original_read(path, limit)
        Path(str(db) + "-journal").write_bytes(b"synthetic late sidecar")
        return data
    with pytest.raises(ArchiveUnavailable, match="offline_image_unavailable"):
        archive_quiescent_image(db, approved_database_pin=pin, capsule=capsule,
                                approved_key_pin=capsule.fingerprint, hold_directory=admission["hold_directory"],
                                read_bound=read_and_add_sidecar)
    assert sha256(db.read_bytes()).digest() == pin
