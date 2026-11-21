"""Synthetic Windows files; no production path, external process or network."""
from contextlib import closing
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest

from app import memory_archive_v2
from app.memory_archive_v2 import ArchiveUnavailable, build_archive, restore_archive
from app.memory_crypto import protect_for_current_user, unprotect_for_current_user
from app.memory_keys_v2 import issue_receipt_key, open_receipt_key
from app.memory_ledger import MemoryLedger
from app.memory_reconciliation import OperationIdentity
from app.windows_storage_inspector import WindowsStorageInspectionError, inspect_component, read_pinned_artifact

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI and file handles")
VALUE = "Синтетика для восстановления 🧭".encode()


@pytest.fixture
def synthetic():
    root = Path(os.environ["AI1_TEST_ROOT"]) / uuid4().hex
    root.mkdir()
    db = root / "synthetic.sqlite3"
    generation = uuid4()
    capsule = issue_receipt_key(generation)
    conn = sqlite3.connect(db, timeout=.2)
    ledger = MemoryLedger(conn, enabled=True, receipt_budget=8)
    ledger.initialize_empty(generation)
    operation = OperationIdentity(uuid4(), generation, b"synthetic")
    receipt = ledger.mutate(operation, "create", sealed=protect_for_current_user(VALUE))
    try:
        yield root, db, generation, capsule, conn, ledger, operation, receipt
    finally:
        conn.close()


def test_disk_archive_roundtrip_reads_the_verified_handle_and_rekeys(synthetic):
    root, db, generation, capsule, source, ledger, operation, receipt = synthetic
    before = db.read_bytes()
    archive = build_archive(source, capsule=capsule, approved_key_pin=capsule.fingerprint)
    path = root / "synthetic-backup.bin"
    with path.open("xb") as output:
        output.write(archive.data)
        output.flush()
        os.fsync(output.fileno())
    evidence = inspect_component(str(path), expected_kind="file")
    data = read_pinned_artifact(str(path), expected=evidence, max_bytes=len(archive.data),
                                require_private_acl=False)
    assert data == archive.data and VALUE not in data

    restored = restore_archive(data, approved_archive_pin=archive.fingerprint, restore_generation=uuid4())
    with closing(sqlite3.connect(":memory:")) as conn:
        conn.deserialize(restored.sqlite_image)
        target = MemoryLedger(conn, enabled=True, receipt_budget=8)
        note, = target.read(restored.generation)
        assert restored.notes == 1 and note.id == receipt.note_id
        assert unprotect_for_current_user(note.sealed) == VALUE
        assert target.snapshot(operation.operation_id).receipt is None
    old = open_receipt_key(generation, capsule.sealed, approved_fingerprint=capsule.fingerprint)
    new = open_receipt_key(restored.generation, restored.key.sealed, approved_fingerprint=restored.key.fingerprint)
    assert old != new
    assert ledger.snapshot(operation.operation_id).receipt is not None
    assert before == db.read_bytes()


@pytest.mark.parametrize("fault", ["pin", "wrong_key", "dpapi", "generation", "authenticated_bad_image",
                                    "staging_failure", "rekey_failure"])
def test_failed_backup_or_restore_preserves_source(synthetic, monkeypatch, fault):
    _, db, generation, capsule, source, ledger, operation, _ = synthetic
    before = db.read_bytes()
    archive = build_archive(source, capsule=capsule, approved_key_pin=capsule.fingerprint)
    data, pin, new = archive.data, archive.fingerprint, uuid4()
    def failed(*args, **kwargs):
        raise OSError("synthetic failure")
    with pytest.raises(ArchiveUnavailable, match="^archive_unavailable$"):
        if fault == "wrong_key":
            build_archive(source, capsule=issue_receipt_key(generation), approved_key_pin=capsule.fingerprint)
        else:
            if fault == "pin":
                data = data[:-1] + bytes([data[-1] ^ 1])
            if fault == "dpapi":
                monkeypatch.setattr(memory_archive_v2, "unprotect_for_current_user", failed)
            if fault == "generation":
                new = generation
            if fault == "authenticated_bad_image":
                raw = bytearray(unprotect_for_current_user(data))
                tail = len(memory_archive_v2._TAG) + 52 + len(capsule.sealed)
                raw[tail + 18] = 2  # refuse a WAL image before deserializing
                data = protect_for_current_user(raw)
                pin = sha256(data).digest()
            if fault in ("staging_failure", "rekey_failure"):
                monkeypatch.setattr(memory_archive_v2, "stage_snapshot" if fault == "staging_failure"
                                    else "issue_receipt_key", failed)
            restore_archive(data, approved_archive_pin=pin, restore_generation=new)
    assert db.read_bytes() == before and ledger.snapshot(operation.operation_id).receipt is not None


def test_handle_reader_refuses_substitution_size_and_unproven_acl(synthetic):
    root = synthetic[0]
    path, new, kept = (root / name for name in ("artifact.bin", "new.bin", "kept.bin"))
    path.write_bytes(b"old fixture")
    new.write_bytes(b"new fixture")
    evidence = inspect_component(str(path), expected_kind="file")
    with pytest.raises(WindowsStorageInspectionError, match="artifact_size"):
        read_pinned_artifact(str(path), expected=evidence, max_bytes=1, require_private_acl=False)
    with pytest.raises(WindowsStorageInspectionError, match="private_acl"):
        read_pinned_artifact(str(path), expected=evidence, max_bytes=20)
    path.rename(kept)
    new.rename(path)
    with pytest.raises(WindowsStorageInspectionError, match="artifact_identity"):
        read_pinned_artifact(str(path), expected=evidence, max_bytes=20, require_private_acl=False)
    assert kept.read_bytes() == b"old fixture" and path.read_bytes() == b"new fixture"
