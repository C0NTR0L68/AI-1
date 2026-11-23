"""Offline write core for a trusted reducer in the enrolled DPAPI profile.

There is no IPC adapter. Only the trusted deployment may construct the writer.
The public desktop principal cannot serve as proof of reducer identity.
"""
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
import hmac
import json
import sqlite3
from uuid import UUID

from app.memory_archive_v2 import build_archive, open_archived_state
from app.memory_crypto import protect_for_current_user
from app.memory_head_v2 import Head, HeadUnavailable
from app.memory_keys_v2 import open_receipt_key
from app.memory_ledger import MemoryLedger
from app.memory_reconciliation import OperationIdentity


_MAX = 2**63 - 1
_DDL = (
    "CREATE TABLE memory_commits ("
    "revision INTEGER PRIMARY KEY CHECK(revision >= 0), "
    "generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=16), "
    "digest BLOB NOT NULL UNIQUE CHECK(typeof(digest)='blob' AND length(digest)=32), "
    "operation BLOB UNIQUE, binding BLOB, "
    "CHECK((revision=0 AND operation IS NULL AND binding IS NULL) OR "
    "(revision>0 AND typeof(operation)='blob' AND length(operation)=16 "
    "AND typeof(binding)='blob' AND length(binding)=32)))"
)
_SCHEMA = [
    ("index", "sqlite_autoindex_memory_commits_1", None),
    ("index", "sqlite_autoindex_memory_commits_2", None),
    ("table", "memory_commits", _DDL),
]


class WriteRefused(ValueError):
    """Known refusal before commit. Never implies permission to resend."""


@dataclass(frozen=True, slots=True)
class Mutation:
    kind: str
    text: str | None = field(default=None, repr=False)
    note_id: int | None = None
    note_revision: int | None = None

    def __post_init__(self):
        if self.kind == "create":
            if (type(self.text) is not str or not self.text.strip() or "\0" in self.text
                    or len(self.text) > 4096 or len(self.text.encode("utf8")) > 16384
                    or self.note_id is not None or self.note_revision is not None):
                raise ValueError("Invalid memory creation")
        elif self.kind == "delete":
            if self.text is not None or any(type(value) is not int or not 1 <= value <= _MAX
                                            for value in (self.note_id, self.note_revision)):
                raise ValueError("Invalid memory deletion")
        else:
            raise ValueError("Unsupported memory mutation")


class ArchiveReducer:
    """Apply a typed mutation to the verified current image in the DPAPI owner profile."""

    def __init__(self, archives, *, receipt_budget):
        if type(receipt_budget) is not int or not 1 <= receipt_budget <= _MAX:
            raise ValueError("Explicit receipt budget required")
        self._archives = archives
        self._budget = receipt_budget

    @contextmanager
    def _open(self, head):
        with open_archived_state(self._archives.read(head.digest), approved_archive_pin=head.digest) as state:
            if state[1] != head.generation:
                raise HeadUnavailable("archive_generation_mismatch")
            yield state

    @staticmethod
    def _binding(head, operation_id, mutation, capsule):
        key = open_receipt_key(head.generation, capsule.sealed, approved_fingerprint=capsule.fingerprint)
        payload = json.dumps([str(head.generation), head.revision, head.digest.hex(), str(operation_id),
                              mutation.kind, mutation.note_id, mutation.note_revision, mutation.text],
                             ensure_ascii=False, separators=(",", ":")).encode("utf8")
        return hmac.digest(key, b"ai1-authority-mutation-v1\0" + payload, "sha256")

    def identify(self, head, operation_id, mutation, *, current=None):
        """Create the exact request identity before submission; retain it for status."""
        if (type(head) is not Head or type(operation_id) is not UUID or operation_id.int == 0
                or type(mutation) is not Mutation):
            raise ValueError("Invalid operation")
        key_head = head if current is None else current
        if type(key_head) is not Head or key_head.generation != head.generation:
            raise WriteRefused("operation_generation_mismatch")
        with self._open(key_head) as (_, _, capsule):
            binding = self._binding(head, operation_id, mutation, capsule)
        return OperationIdentity(operation_id, head.generation, binding)

    def read(self, head):
        with self._open(head) as (conn, generation, _):
            return MemoryLedger(conn, enabled=True, receipt_budget=self._budget).read(generation)

    def validate_genesis(self, head):
        with self._open(head) as (conn, _, _):
            if conn.execute("SELECT 1 FROM main.sealed_notes UNION ALL "
                            "SELECT 1 FROM main.memory_receipts LIMIT 1").fetchone() is not None:
                raise WriteRefused("genesis_archive_not_empty")

    def publish(self, head, identity, mutation):
        with self._open(head) as (conn, generation, capsule):
            if not hmac.compare_digest(identity.binding, self._binding(head, identity.operation_id, mutation, capsule)):
                raise WriteRefused("mutation_binding_mismatch")
            sealed = None if mutation.text is None else protect_for_current_user(mutation.text.encode("utf8"))
            receipt = MemoryLedger(conn, enabled=True, receipt_budget=self._budget).mutate(
                identity, mutation.kind, note_id=mutation.note_id, revision=mutation.note_revision, sealed=sealed)
            if receipt.replayed:
                raise WriteRefused("operation_already_recorded")
            artifact = build_archive(conn, capsule=capsule, approved_key_pin=capsule.fingerprint)
        self._archives.publish(artifact)
        candidate = Head(generation, head.revision + 1, artifact.fingerprint)
        if candidate.digest == head.digest:
            raise WriteRefused("archive_digest_reused")
        with self._open(candidate) as (conn, _, _):
            observed = MemoryLedger(conn, enabled=True, receipt_budget=self._budget).snapshot(identity.operation_id)
            if observed.receipt is None or observed.receipt.identity != identity:
                raise HeadUnavailable("published_archive_receipt_mismatch")
        return candidate


class MemoryWriter:
    """Private writer. An offline reducer is explicit and can never accept a caller digest."""

    def __init__(self, connect, *, reducer, enabled=False):
        if type(enabled) is not bool:
            raise ValueError("Explicit write configuration required")
        if type(reducer) is not ArchiveReducer:
            raise ValueError("Trusted archive reducer required")
        self._connect = connect
        self._reducer = reducer
        self._enabled = enabled

    @contextmanager
    def _transaction(self, *, write=False, provision=False):
        if not self._enabled:
            raise WriteRefused("memory_write_disabled")
        try:
            with closing(self._connect()) as conn, conn:
                if conn.in_transaction or conn.execute("PRAGMA journal_mode").fetchone() != ("delete",):
                    raise HeadUnavailable("write_authority_connection_refused")
                conn.execute("PRAGMA trusted_schema=OFF")
                conn.execute("PRAGMA synchronous=FULL")
                conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                schema = conn.execute(
                    "SELECT type, name, sql FROM main.sqlite_schema ORDER BY type, name").fetchall()
                if schema != ([] if provision else _SCHEMA):
                    raise HeadUnavailable("write_authority_schema_refused")
                yield conn
        except sqlite3.Error as error:
            raise HeadUnavailable("write_authority_outcome_unconfirmed") from error

    @staticmethod
    def _head(conn):
        row = conn.execute(
            "SELECT generation, revision, digest FROM main.memory_commits ORDER BY revision DESC LIMIT 1").fetchone()
        if row is None:
            raise HeadUnavailable("write_authority_missing_head")
        return Head(UUID(bytes=row[0]), row[1], row[2])

    @staticmethod
    def _validate(expected, identity):
        if (type(expected) is not Head or type(identity) is not OperationIdentity or identity.operation_id.int == 0
                or expected.generation != identity.store_generation or len(identity.binding) != 32):
            raise WriteRefused("invalid_operation_identity")

    def provision(self, initial):
        """Explicit offline provisioning; an existing authority is never migrated in place."""
        if type(initial) is not Head or initial.revision != 0:
            raise ValueError("A genesis head is required")
        with self._transaction(write=True, provision=True) as conn:
            self._reducer.validate_genesis(initial)
            conn.execute(_DDL)
            conn.execute("INSERT INTO main.memory_commits VALUES (0, ?, ?, NULL, NULL)",
                         (initial.generation.bytes, initial.digest))

    def head(self):
        with self._transaction() as conn:
            return self._head(conn)

    def commit(self, expected, identity, mutation):
        self._validate(expected, identity)
        if type(mutation) is not Mutation:
            raise WriteRefused("invalid_mutation")
        with self._transaction(write=True) as conn:
            if conn.execute("SELECT 1 FROM main.memory_commits WHERE operation=?",
                            (identity.operation_id.bytes,)).fetchone():
                raise WriteRefused("operation_already_recorded_use_status")
            if self._head(conn) != expected:
                raise WriteRefused("stale_head")
            if expected.revision == _MAX:
                raise WriteRefused("head_revision_exhausted")
            candidate = self._reducer.publish(expected, identity, mutation)
            # One row constitutes both the head advance and the durable receipt.
            conn.execute("INSERT INTO main.memory_commits VALUES (?, ?, ?, ?, ?)",
                         (candidate.revision, candidate.generation.bytes, candidate.digest,
                          identity.operation_id.bytes, identity.binding))
        return candidate

    def status(self, expected, identity):
        """A matching historical receipt or None (unknown). No replay is authorized."""
        self._validate(expected, identity)
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT new.generation, new.revision, new.digest, new.binding, old.digest "
                "FROM main.memory_commits AS new JOIN main.memory_commits AS old "
                "ON old.revision=new.revision-1 AND old.generation=new.generation "
                "WHERE new.operation=?", (identity.operation_id.bytes,)).fetchone()
            if row is None:
                return None
            generation, revision, digest, binding, old_digest = row
            if (generation != expected.generation.bytes or revision != expected.revision + 1
                    or old_digest != expected.digest or not hmac.compare_digest(binding, identity.binding)):
                raise WriteRefused("operation_receipt_conflict")
            return Head(expected.generation, revision, digest)
