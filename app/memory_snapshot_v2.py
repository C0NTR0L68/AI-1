"""Trusted-connection backup/restore rehearsal. No filesystem publication."""
from dataclasses import dataclass
import sqlite3
from time import monotonic
from uuid import UUID

from app.memory import _log_cleanup_failure
from app.memory_ledger import MemoryLedger


class SnapshotUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class StagedSnapshot:
    generation: UUID
    notes: int


def stage_snapshot(source, staging, *, verify, restore_generation=None):
    """Copy into a new private in-memory DB, check and optionally rotate identity.

    Trusted caller owns two idle connections and excludes external writers on
    source for the duration. On failure discard staging; never publish it.
    verify must authenticate each sealed note with the intended profile/key.
    This is neither a filesystem backup tool nor a production restore path.
    """
    if (not isinstance(source, sqlite3.Connection) or not isinstance(staging, sqlite3.Connection)
            or source is staging or not callable(verify)
            or (restore_generation is not None and type(restore_generation) is not UUID)):
        raise ValueError("Two distinct dedicated connections and verifier required")
    if (staging.in_transaction or staging.execute("PRAGMA database_list").fetchall() != [(0, "main", "")]
            or MemoryLedger._objects(staging) or staging.execute("PRAGMA page_count").fetchone()[0]):
        raise ValueError("Staging must be a fresh private in-memory database")
    end = monotonic() + 3
    page_size = 0

    def progress(status, remaining, total):
        if (monotonic() > end or status in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
                or total * page_size > 64 * 1024 * 1024):
            raise SnapshotUnavailable("snapshot_copy_refused")

    try:
        if source.in_transaction:
            raise SnapshotUnavailable("snapshot_source_busy")
        page_size = source.execute("PRAGMA page_size").fetchone()[0]
        page_count = source.execute("PRAGMA page_count").fetchone()[0]
        if not 0 < page_size * page_count <= 64 * 1024 * 1024:
            raise SnapshotUnavailable("snapshot_size")
        MemoryLedger(source, enabled=True, receipt_budget=1).check_integrity()
        source.backup(staging, pages=32, progress=progress, sleep=0)
        target = MemoryLedger(staging, enabled=True, receipt_budget=1)
        generation = target.check_integrity()
        with target._transaction(write=restore_generation is not None) as conn:
            if generation != target._generation(conn):
                raise SnapshotUnavailable("snapshot_generation")
            count = 0
            for (sealed,) in conn.execute("SELECT sealed FROM main.sealed_notes"):
                count += 1
                if count > 500 or verify(sealed) is not True:
                    raise SnapshotUnavailable("snapshot_key_or_note")
            if restore_generation is not None:
                if restore_generation == generation:
                    raise SnapshotUnavailable("snapshot_generation")
                conn.execute("UPDATE main.memory_generation SET generation=? WHERE singleton=1",
                             (str(restore_generation),))
                conn.execute("DELETE FROM main.memory_receipts")
                generation = restore_generation
        if target.check_integrity() != generation:
            raise SnapshotUnavailable("snapshot_generation")
        return StagedSnapshot(generation, count)
    except BaseException as error:
        try:
            staging.close()
        except BaseException as cleanup:
            _log_cleanup_failure("snapshot staging close", cleanup)
        if isinstance(error, Exception) and not isinstance(error, SnapshotUnavailable):
            raise SnapshotUnavailable("snapshot_unavailable") from error
        raise
