"""Opt-in SQLite transaction core for sealed notes and operation receipts.

The caller supplies an already admitted, dedicated connection and sealed bytes.
Path admission, authenticated encryption, binding derivation and M3 are separate.
No application route, path opening, provider, automatic restore or retry.
"""
from dataclasses import dataclass, field
from contextlib import contextmanager
from uuid import UUID
import hmac
import sqlite3

from app.memory import _log_cleanup_failure
from app.memory_security import MemoryAccessGuard
from app.memory_reconciliation import (
    OperationIdentity, OperationReceipt, OperationSnapshot, ReceiptState,
    ReconciliationDisabled,
)


_ID = 0x4149324D
_SCHEMA = {
    "memory_generation": "CREATE TABLE memory_generation (singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation TEXT NOT NULL)",
    "sealed_notes": "CREATE TABLE sealed_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, revision INTEGER NOT NULL CHECK(revision>0), sealed BLOB NOT NULL CHECK(typeof(sealed)='blob' AND length(sealed) BETWEEN 1 AND 65536))",
    "memory_receipts": "CREATE TABLE memory_receipts (operation TEXT PRIMARY KEY NOT NULL, binding BLOB NOT NULL CHECK(typeof(binding)='blob' AND length(binding) BETWEEN 1 AND 256), kind TEXT NOT NULL CHECK(kind IN ('create','update','delete')), note_id INTEGER NOT NULL, revision INTEGER NOT NULL, previous_revision INTEGER)",
}
_MAX_ID = 2**63 - 1


class MemoryLedgerConflict(ValueError):
    """A different operation, store generation or note revision was observed."""


@dataclass(frozen=True)
class SealedNote:
    id: int
    revision: int
    sealed: bytes = field(repr=False)


@dataclass(frozen=True)
class MutationReceipt:
    note_id: int
    revision: int
    replayed: bool


def _integer(value):
    return type(value) is int and 1 <= value <= _MAX_ID


class MemoryLedger:
    def __init__(self, connection: sqlite3.Connection | None = None, *, enabled=False, receipt_budget=None,
                 max_notes=500, max_live_bytes=2 * 1024 * 1024):
        if type(enabled) is not bool:
            raise ValueError("Boolean enable flag required")
        if enabled and (not isinstance(connection, sqlite3.Connection) or not _integer(receipt_budget)):
            raise ValueError("Dedicated connection and explicit receipt budget required")
        if enabled and (not _integer(max_notes) or not _integer(max_live_bytes)):
            raise ValueError("Positive note and sealed byte budgets required")
        self._connection = connection if enabled else None
        self._budget = receipt_budget
        self._max_notes = max_notes
        self._max_live_bytes = max_live_bytes

    @contextmanager
    def _transaction(self, *, write=False, authorization=None):
        conn = self._connection
        if conn is None:
            raise ReconciliationDisabled("MEMORY_LEDGER_DISABLED")
        if conn.autocommit != sqlite3.LEGACY_TRANSACTION_CONTROL:
            raise ValueError("Ledger requires a connection in legacy transaction control mode")
        if conn.in_transaction:
            raise ValueError("Ledger requires an idle dedicated connection")
        try:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            # main qualification prevents TEMP objects shadowing persistent tables.
            yield conn
            if authorization is None:
                conn.commit()
            else:
                guard, admission = authorization
                guard._commit_mutation(admission, conn)
        except BaseException:
            try:
                conn.rollback()
            except BaseException as error:
                _log_cleanup_failure("ledger rollback", error)
            raise

    @staticmethod
    def _objects(conn):
        return {tuple(row) for row in conn.execute("SELECT type,name,sql FROM main.sqlite_schema")}

    @classmethod
    def _generation(cls, conn):
        expected = {("table", name, sql) for name, sql in _SCHEMA.items()}
        expected.update({("table", "sqlite_sequence", "CREATE TABLE sqlite_sequence(name,seq)"),
                         ("index", "sqlite_autoindex_memory_receipts_1", None)})
        if (conn.execute("PRAGMA main.application_id").fetchone()[0] != _ID
                or conn.execute("PRAGMA main.user_version").fetchone()[0] != 1
                or cls._objects(conn) != expected):
            raise MemoryLedgerConflict("Unrecognized memory schema")
        rows = conn.execute("SELECT singleton,generation FROM main.memory_generation LIMIT 2").fetchall()
        if len(rows) != 1 or rows[0][0] != 1:
            raise MemoryLedgerConflict("Invalid store generation")
        generation = UUID(rows[0][1])
        if str(generation) != rows[0][1]:
            raise MemoryLedgerConflict("Invalid store generation")
        return generation

    def initialize_empty(self, generation: UUID):
        if type(generation) is not UUID:
            raise ValueError("Store generation must be a UUID")
        with self._transaction(write=True) as conn:
            if (self._objects(conn) or conn.execute("PRAGMA main.application_id").fetchone()[0]
                    or conn.execute("PRAGMA main.user_version").fetchone()[0]):
                raise MemoryLedgerConflict("Initialization requires an empty database")
            for sql in _SCHEMA.values():
                conn.execute(sql.replace("CREATE TABLE ", "CREATE TABLE main.", 1))
            conn.execute("INSERT INTO main.memory_generation VALUES (1,?)", (str(generation),))
            conn.execute(f"PRAGMA main.application_id={_ID}")
            conn.execute("PRAGMA main.user_version=1")
            self._generation(conn)

    def check_integrity(self):
        with self._transaction() as conn:
            generation = self._generation(conn)
            if [row[0] for row in conn.execute("PRAGMA main.integrity_check(1)")] != ["ok"]:
                raise MemoryLedgerConflict("Memory storage integrity check failed")
            return generation

    def read(self, generation: UUID, *, after=0, limit=50):
        if (type(generation) is not UUID or type(after) is not int or not 0 <= after <= _MAX_ID
                or type(limit) is not int or not 1 <= limit <= 100):
            raise ValueError("Invalid memory page")
        with self._transaction() as conn:
            if generation != self._generation(conn):
                raise MemoryLedgerConflict("Store generation changed")
            rows = conn.execute("SELECT id,revision,sealed FROM main.sealed_notes WHERE id>? ORDER BY id LIMIT ?",
                                (after, limit)).fetchall()
            return tuple(SealedNote(*row) for row in rows)

    def snapshot(self, operation_id: UUID):
        if type(operation_id) is not UUID:
            raise ValueError("Operation ID must be a UUID")
        with self._transaction() as conn:
            generation = self._generation(conn)
            row = conn.execute("SELECT binding FROM main.memory_receipts WHERE operation=?",
                               (str(operation_id),)).fetchone()
            receipt = None if row is None else OperationReceipt(
                OperationIdentity(operation_id, generation, row[0]), ReceiptState.COMPLETED)
            return OperationSnapshot(generation, receipt)

    def mutate(self, identity: OperationIdentity, kind: str, *, note_id=None, revision=None, sealed=None):
        """Trusted storage primitive; never use directly for a request."""
        return self._mutate(identity, kind, note_id, revision, sealed)

    def mutate_authorized(self, guard, method, headers, identity: OperationIdentity, kind: str,
                          *, note_id=None, revision=None, sealed=None):
        """Disconnected M3 candidate; no endpoint or file can be opened here.

        Authentication precedes storage access. Revocation is serialized with
        COMMIT via the guard after SQLite's write transaction has been obtained.
        Use only a dedicated, finite-timeout connection without callbacks into
        the guard. A COMMIT error is surfaced; callers reconcile, never retry.
        """
        if type(guard) is not MemoryAccessGuard:
            raise TypeError("Memory access guard required")
        if (kind, method) not in (("create", "POST"), ("update", "POST"), ("delete", "DELETE")):
            raise ValueError("Invalid memory mutation method")
        admission = guard._admit_mutation(method, headers)
        return self._mutate(identity, kind, note_id, revision, sealed, authorization=(guard, admission))

    def _mutate(self, identity, kind, note_id, revision, sealed, *, authorization=None):
        if type(identity) is not OperationIdentity or kind not in ("create", "update", "delete"):
            raise ValueError("Invalid memory mutation")
        if kind == "create":
            if note_id is not None or revision is not None:
                raise ValueError("A new note has no previous revision")
        elif not _integer(note_id) or not _integer(revision):
            raise ValueError("Existing note and revision required")
        if kind == "delete":
            if sealed is not None:
                raise ValueError("Deletion cannot carry note content")
        elif type(sealed) is not bytes or not 1 <= len(sealed) <= 65536:
            raise ValueError("Sealed note is required")

        with self._transaction(write=True, authorization=authorization) as conn:
            if identity.store_generation != self._generation(conn):
                raise MemoryLedgerConflict("Store generation changed")
            previous = conn.execute(
                "SELECT binding,kind,note_id,revision,previous_revision FROM main.memory_receipts WHERE operation=?",
                (str(identity.operation_id),)).fetchone()
            if previous is not None:
                binding, previous_kind, existing_id, resulting_revision, old_revision = previous
                if (not hmac.compare_digest(binding, identity.binding) or previous_kind != kind
                        or (kind != "create" and (note_id, revision) != (existing_id, old_revision))):
                    raise MemoryLedgerConflict("Operation identity already bound")
                return MutationReceipt(existing_id, resulting_revision, True)

            receipts = conn.execute("SELECT count(*) FROM main.memory_receipts").fetchone()[0]
            notes, live_bytes = conn.execute("SELECT count(*),coalesce(sum(length(sealed)),0) FROM main.sealed_notes").fetchone()
            # Reserve one receipt per live note so a full ledger still permits deletion.
            growth = {"create": 2, "update": 1, "delete": 0}[kind]
            if kind != "delete" and receipts + notes + growth > self._budget:
                raise MemoryLedgerConflict("Receipt budget exhausted")
            if kind == "create":
                if notes >= self._max_notes or live_bytes + len(sealed) > self._max_live_bytes:
                    raise MemoryLedgerConflict("Live note budget exhausted")
                note_id = conn.execute("INSERT INTO main.sealed_notes(revision,sealed) VALUES (1,?)", (sealed,)).lastrowid
                result_revision = 1
            elif kind == "update":
                existing = conn.execute("SELECT length(sealed) FROM main.sealed_notes WHERE id=? AND revision=?",
                                        (note_id, revision)).fetchone()
                if existing is None:
                    raise MemoryLedgerConflict("Note revision changed")
                if live_bytes - existing[0] + len(sealed) > self._max_live_bytes:
                    raise MemoryLedgerConflict("Live note budget exhausted")
                result_revision = revision + 1
                if result_revision > _MAX_ID:
                    raise MemoryLedgerConflict("Note revision exhausted")
                changed = conn.execute("UPDATE main.sealed_notes SET revision=?,sealed=? WHERE id=? AND revision=?",
                                       (result_revision, sealed, note_id, revision)).rowcount
            else:
                result_revision = revision
                changed = conn.execute("DELETE FROM main.sealed_notes WHERE id=? AND revision=?", (note_id, revision)).rowcount
            if kind != "create" and changed != 1:
                raise MemoryLedgerConflict("Note revision changed")
            conn.execute("INSERT INTO main.memory_receipts VALUES (?,?,?,?,?,?)",
                         (str(identity.operation_id), identity.binding, kind, note_id, result_revision, revision))
            return MutationReceipt(note_id, result_revision, False)
