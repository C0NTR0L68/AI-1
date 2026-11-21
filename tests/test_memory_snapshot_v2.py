"""Synthetic staging only; no path replacement or production backup."""
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest

from app.memory_ledger import MemoryLedger
from app.memory_reconciliation import OperationIdentity


def test_restore_stage_rotates_generation_and_preserves_inputs():
    from app.memory_snapshot_v2 import stage_snapshot
    path = Path(os.environ["AI1_TEST_ROOT"]) / (uuid4().hex + ".sqlite3")
    src = sqlite3.connect(path)
    dst = sqlite3.connect(":memory:")
    gen, new = uuid4(), uuid4()
    try:
        old = MemoryLedger(src, enabled=True, receipt_budget=8)
        old.initialize_empty(gen)
        op = OperationIdentity(uuid4(), gen, b"synthetic")
        original = old.mutate(op, "create", sealed=b"sealed:test")
        prior = path.read_bytes()
        result = stage_snapshot(src, dst, verify=lambda data: data == b"sealed:test", restore_generation=new)
        restored = MemoryLedger(dst, enabled=True, receipt_budget=8)
        assert result.notes == 1 and result.generation == new
        assert restored.read(new)[0].id == original.note_id
        assert restored.snapshot(op.operation_id).receipt is None
        assert old.snapshot(op.operation_id).receipt is not None
        assert path.read_bytes() == prior
    finally:
        dst.close()
        src.close()


@pytest.mark.parametrize("failure", ["key", "schema", "copy", "same_generation"])
def test_unacceptable_source_never_returns_staged_snapshot(failure):
    from app.memory_snapshot_v2 import SnapshotUnavailable, stage_snapshot
    class FailedCopy(sqlite3.Connection):
        def backup(self, target, **kwargs):
            raise sqlite3.OperationalError("synthetic")

    src = sqlite3.connect(":memory:", factory=FailedCopy if failure == "copy" else sqlite3.Connection)
    dst = sqlite3.connect(":memory:")
    gen = uuid4()
    try:
        if failure != "schema":
            old = MemoryLedger(src, enabled=True, receipt_budget=8)
            old.initialize_empty(gen)
            old.mutate(OperationIdentity(uuid4(), gen, b"synthetic"), "create", sealed=b"opaque")
        with pytest.raises(SnapshotUnavailable):
            stage_snapshot(src, dst, verify=lambda data: failure != "key",
                           restore_generation=gen if failure == "same_generation" else None)
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            dst.execute("SELECT 1")
    finally:
        dst.close()
        src.close()


@pytest.mark.skipif(os.name != "nt", reason="Current-user Windows DPAPI")
def test_backup_authenticates_dpapi_ciphertext_and_keeps_receipts():
    from app.memory_crypto import protect_for_current_user, unprotect_for_current_user
    from app.memory_snapshot_v2 import stage_snapshot
    src, target = sqlite3.connect(":memory:"), sqlite3.connect(":memory:")
    gen = uuid4()
    try:
        ledger = MemoryLedger(src, enabled=True, receipt_budget=8)
        ledger.initialize_empty(gen)
        op = OperationIdentity(uuid4(), gen, b"synthetic-binding")
        ledger.mutate(op, "create", sealed=protect_for_current_user(b"synthetic restore only"))
        verified = stage_snapshot(src, target, verify=lambda sealed:
                                  unprotect_for_current_user(sealed) == b"synthetic restore only")
        assert verified.generation == gen and verified.notes == 1
        assert MemoryLedger(target, enabled=True, receipt_budget=8).snapshot(op.operation_id).receipt.identity == op
    finally:
        src.close()
        target.close()
