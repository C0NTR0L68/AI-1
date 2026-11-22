"""Candidate offline PRE-EPOCH export, never invoked by application startup."""
import sqlite3

from app.history_preflight import INDEXES, READY_DDL, _tokens


class LegacyExportRefused(ValueError):
    """The source profile or export target is outside the approved contract."""


# Exact predecessor represented by the frozen provenance fixture.
_LEGACY = """CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL,
    content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'complete', request_id TEXT,
    provider_id TEXT, model_name TEXT
)"""
_ADDED = ("requested_model", "provider_model", "lifecycle_status")
_NORMALIZED = _LEGACY[:-1] + ", " + ", ".join(f"{name} TEXT" for name in _ADDED) + ")"
_COLUMNS = ("id", "role", "content", "created_at", "status", "request_id", "provider_id",
            "model_name", *_ADDED)
_MAX_BYTES = 16 * 1024 * 1024


def _version_zero(conn):
    return (
        conn.execute("PRAGMA main.user_version").fetchone()[0] == 0
        and conn.execute("PRAGMA main.application_id").fetchone()[0] == 0
        and conn.execute("PRAGMA main.journal_mode").fetchone()[0] == "delete"
    )


def _private_schema(conn):
    return all(row[1] in ("main", "temp") for row in conn.execute("PRAGMA database_list")) and (
        conn.execute("SELECT 1 FROM temp.sqlite_schema LIMIT 1").fetchone() is None
    )


def _source_columns(conn):
    if not _version_zero(conn):
        raise LegacyExportRefused("Unsupported source identity or journal mode")
    size = conn.execute("PRAGMA main.page_count").fetchone()[0] * conn.execute(
        "PRAGMA main.page_size"
    ).fetchone()[0]
    if size > _MAX_BYTES:
        raise LegacyExportRefused("Source exceeds the reviewed size")
    objects = {
        (kind, name, table): sql
        for kind, name, table, sql in conn.execute(
            "SELECT type, name, tbl_name, sql FROM main.sqlite_schema"
        )
    }
    ddl = objects.pop(("table", "messages", "messages"), None)
    seq_ddl = objects.pop(("table", "sqlite_sequence", "sqlite_sequence"), None)
    if ddl is None or seq_ddl != "CREATE TABLE sqlite_sequence(name,seq)":
        raise LegacyExportRefused("Missing predecessor table or sequence")
    if _tokens(ddl) == _tokens(_LEGACY) and not objects:
        return ", ".join((*_COLUMNS[:-3], "NULL", "NULL", "NULL"))
    expected = {("index", name, "messages"): _tokens(sql) for name, sql in INDEXES.items()}
    if (_tokens(ddl) == _tokens(_NORMALIZED) and set(objects) == set(expected)
            and all(sql is not None and _tokens(sql) == expected[key] for key, sql in objects.items())):
        return ", ".join(_COLUMNS)
    raise LegacyExportRefused("Unsupported source schema or extra objects")


def _rows(conn, fields):
    for row in conn.execute(f"SELECT {fields} FROM main.messages ORDER BY id"):
        row = tuple(row)
        if (type(row[0]) is not int or row[0] < 1 or row[1] not in ("user", "assistant")
                or any(type(value) is not str for value in row[1:5])
                or row[4] not in ("complete", "pending", "failed")
                or any(value is not None and type(value) is not str for value in row[5:])
                or row[-1] not in (None, "pending", "dispatching", "completed", "failed", "unknown")):
            raise LegacyExportRefused("Unsupported source row")
        yield row


def export_legacy_history(source, destination):
    """Copy from a caller-owned query-only snapshot into a fresh SQLite database.

    Caller must provide two dedicated idle connections and independently select
    and protect their files. It must run file-based READY preflight on the
    closed destination before selecting it for startup. No files are replaced.
    """
    if (not isinstance(source, sqlite3.Connection) or not isinstance(destination, sqlite3.Connection)
            or source is destination or source.in_transaction or destination.in_transaction
            or not _private_schema(source) or not _private_schema(destination)
            or source.execute("PRAGMA query_only").fetchone()[0] != 1
            or source.execute("PRAGMA trusted_schema").fetchone()[0] != 0):
        raise LegacyExportRefused("Dedicated idle connections and read guards required")

    try:
        with source:
            source.execute("BEGIN")
            fields = _source_columns(source)
            if [tuple(row) for row in source.execute("PRAGMA main.quick_check")] != [("ok",)]:
                raise LegacyExportRefused("Invalid source integrity")
            maximum = source.execute("SELECT MAX(id) FROM main.messages").fetchone()[0]
            sequence = [tuple(row) for row in source.execute("SELECT name,seq FROM main.sqlite_sequence")]
            if (not sequence and maximum is not None or sequence and
                    (len(sequence) != 1 or sequence[0][0] != "messages"
                     or type(sequence[0][1]) is not int or sequence[0][1] < (maximum or 0))):
                raise LegacyExportRefused("Unsupported source sequence")

            with destination:
                destination.execute("BEGIN IMMEDIATE")
                if (not _version_zero(destination) or destination.execute(
                        "SELECT 1 FROM main.sqlite_schema LIMIT 1").fetchone() is not None):
                    raise LegacyExportRefused("Fresh destination required")
                destination.execute(READY_DDL)
                for statement in INDEXES.values():
                    destination.execute(statement)
                destination.executemany(
                    f"INSERT INTO main.messages ({', '.join(_COLUMNS)}) VALUES ({', '.join('?' for _ in _COLUMNS)})",
                    _rows(source, fields),
                )
                if sequence:
                    destination.execute("DELETE FROM main.sqlite_sequence WHERE name = 'messages'")
                    destination.execute("INSERT INTO main.sqlite_sequence(name,seq) VALUES (?,?)", sequence[0])
                if ([tuple(row) for row in destination.execute("PRAGMA main.integrity_check")] != [("ok",)]
                        or destination.execute("PRAGMA main.foreign_key_check").fetchone() is not None):
                    raise LegacyExportRefused("Destination verification failed")
                return destination.execute("SELECT COUNT(*) FROM main.messages").fetchone()[0]
    except sqlite3.Error as exc:
        raise LegacyExportRefused("SQLite export did not complete") from exc
