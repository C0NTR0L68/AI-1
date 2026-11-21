"""Private head registry for a separately trusted, live authority.

Never instantiate from the client store or import the ledger's head from backups.
The caller owns the authority's connection factory and rollback boundary.
"""
from contextlib import closing
from dataclasses import dataclass
import sqlite3
from uuid import UUID


_MAX_REVISION = 2**63 - 1


class HeadUnavailable(RuntimeError):
    """No authoritative result, including a potentially committed write."""


@dataclass(frozen=True, slots=True)
class Head:
    generation: UUID
    revision: int
    digest: bytes

    def __post_init__(self):
        if (
            type(self.generation) is not UUID or self.generation.int == 0
            or type(self.revision) is not int or not 0 <= self.revision <= _MAX_REVISION
            or type(self.digest) is not bytes or len(self.digest) != 32
        ):
            raise ValueError("Invalid head")


class DurableHeadRegistry:
    """Single-generation journal with serialized compare-and-advance.

    Each call obtains its own authority-owned connection. Provisioning must use
    a fresh database. Normal startup must use mode=rw and call read(), so an
    absent or rolled-back registry cannot be routinely initialized.
    """

    def __init__(self, connect):
        self._connect = connect

    def _connection(self):
        conn = self._connect()
        try:
            if conn.in_transaction:
                raise HeadUnavailable("head_connection_in_transaction")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA synchronous=FULL")
            if conn.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise HeadUnavailable("head_journal_not_delete")
            return conn
        except BaseException:
            conn.close()
            raise

    @staticmethod
    def _current(conn):
        row = conn.execute(
            "SELECT generation, revision, digest FROM head_journal ORDER BY revision DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise HeadUnavailable("head_missing")
        try:
            generation, revision, digest = row
            if type(generation) is not bytes or len(generation) != 16:
                raise ValueError("Invalid serialized generation")
            return Head(UUID(bytes=generation), revision, digest)
        except (ValueError, TypeError) as exc:
            raise HeadUnavailable("head_invalid") from exc

    def provision(self, initial):
        if type(initial) is not Head or initial.revision != 0:
            raise ValueError("Explicit initial head required")
        try:
            with closing(self._connection()) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                if conn.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone() is not None:
                    raise HeadUnavailable("head_database_not_empty")
                conn.execute(
                    "CREATE TABLE head_journal (revision INTEGER PRIMARY KEY CHECK(revision >= 0), "
                    "generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=16), "
                    "digest BLOB NOT NULL UNIQUE CHECK(typeof(digest)='blob' AND length(digest)=32))"
                )
                conn.execute("INSERT INTO head_journal VALUES (?, ?, ?)",
                             (initial.revision, initial.generation.bytes, initial.digest))
        except sqlite3.Error as exc:
            raise HeadUnavailable("head_provision_unconfirmed") from exc

    def read(self):
        try:
            with closing(self._connection()) as conn:
                return self._current(conn)
        except sqlite3.Error as exc:
            raise HeadUnavailable("head_read_unavailable") from exc

    def advance(self, expected, candidate):
        if (
            type(expected) is not Head or type(candidate) is not Head
            or expected.generation != candidate.generation
            or candidate.revision != expected.revision + 1
        ):
            raise ValueError("Next revision of the same generation required")
        try:
            with closing(self._connection()) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                if self._current(conn) != expected:
                    return False
                if conn.execute("SELECT 1 FROM head_journal WHERE digest=?", (candidate.digest,)).fetchone():
                    return False
                conn.execute("INSERT INTO head_journal VALUES (?, ?, ?)",
                             (candidate.revision, candidate.generation.bytes, candidate.digest))
        except sqlite3.Error as exc:
            raise HeadUnavailable("head_advance_unconfirmed") from exc
        return True


def require_current_head(observed, authority):
    """Check a local candidate against the live authority, with no offline fallback."""
    if type(observed) is not Head:
        raise ValueError("Observed head required")
    live = authority.read()
    if type(live) is not Head or live != observed:
        raise HeadUnavailable("head_mismatch")
    return live
