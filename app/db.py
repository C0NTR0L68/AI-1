import logging
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from app.runtime_lock import DatabaseProcessLock, canonical_database_path


def recover_dispatching_requests(database_path: str | Path) -> int:
    """Explicit offline operation. Never initializes/migrates a database or dispatches work."""
    if not Path(database_path).is_absolute():
        raise ValueError("Offline recovery requires an absolute database path")
    path = canonical_database_path(database_path)
    # Acquire BEFORE opening SQLite, even if the caller already has a ChatStore.
    with DatabaseProcessLock(path):
        with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)) as conn:
            with conn:
                conn.execute("BEGIN IMMEDIATE")
                result = conn.execute(
                    "UPDATE messages SET lifecycle_status = 'unknown', status = 'pending' "
                    "WHERE role = 'user' AND COALESCE(lifecycle_status, "
                    "CASE status WHEN 'complete' THEN 'completed' ELSE status END) "
                    "= 'dispatching'"
                )
                return result.rowcount


LIFECYCLE_STATUSES = {"pending", "dispatching", "completed", "failed", "unknown"}
_LEGACY_TO_LIFECYCLE = {"complete": "completed"}


class ActiveRequestsError(RuntimeError):
    """Raised when history cannot be cleared while a request is active."""


class DatabaseBusyError(RuntimeError):
    """Raised when SQLite cannot acquire a lock for a storage operation."""


class RequestIdConflict(ValueError):
    """Raised when a request ID is reused with different message text."""


def _tokenize_sql(sql: str) -> list[tuple[str, str]]:
    """Tokenize SQLite DDL so lifecycle CHECK expressions can fail closed."""
    tokens: list[tuple[str, str]] = []
    i = 0
    while i < len(sql):
        char = sql[i]
        if char.isspace():
            i += 1
            continue
        if sql.startswith("--", i):
            end = sql.find("\n", i + 2)
            i = len(sql) if end < 0 else end + 1
            continue
        if sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end < 0:
                raise ValueError("Unterminated comment in messages table DDL")
            i = end + 2
            continue
        if char == "'":
            i += 1
            value: list[str] = []
            while i < len(sql):
                if sql[i] == "'":
                    if i + 1 < len(sql) and sql[i + 1] == "'":
                        value.append("'")
                        i += 2
                        continue
                    i += 1
                    break
                value.append(sql[i])
                i += 1
            else:
                raise ValueError("Unterminated string in messages table DDL")
            tokens.append(("STRING", "".join(value)))
            continue
        if char in ('"', "`", "["):
            closing = "]" if char == "[" else char
            i += 1
            value = []
            while i < len(sql):
                if sql[i] == closing:
                    if closing != "]" and i + 1 < len(sql) and sql[i + 1] == closing:
                        value.append(closing)
                        i += 2
                        continue
                    i += 1
                    break
                value.append(sql[i])
                i += 1
            else:
                raise ValueError("Unterminated quoted identifier in messages table DDL")
            tokens.append(("IDENT", "".join(value)))
            continue
        if char.isalpha() or char == "_":
            start = i
            i += 1
            while i < len(sql) and (sql[i].isalnum() or sql[i] in "_$"):
                i += 1
            tokens.append(("IDENT", sql[start:i]))
            continue
        if char.isdigit():
            start = i
            i += 1
            while i < len(sql) and (sql[i].isalnum() or sql[i] in "._"):
                i += 1
            tokens.append(("NUMBER", sql[start:i]))
            continue
        tokens.append(("PUNCT", char))
        i += 1
    return tokens


def _strip_outer_parens(tokens: list[tuple[str, str]]) -> list[tuple[str, str]]:
    while len(tokens) >= 2 and tokens[0] == ("PUNCT", "("):
        depth = 0
        closes_at_end = False
        for index, token in enumerate(tokens):
            if token == ("PUNCT", "("):
                depth += 1
            elif token == ("PUNCT", ")"):
                depth -= 1
                if depth == 0:
                    closes_at_end = index == len(tokens) - 1
                    break
                if depth < 0:
                    return tokens
        if not closes_at_end:
            break
        tokens = tokens[1:-1]
    return tokens


def _parse_lifecycle_in(tokens: list[tuple[str, str]]) -> set[str] | None:
    tokens = _strip_outer_parens(tokens)
    if len(tokens) < 5:
        return None
    if tokens[0][0] != "IDENT" or tokens[0][1].lower() != "lifecycle_status":
        return None
    if tokens[1][0] != "IDENT" or tokens[1][1].upper() != "IN":
        return None
    if tokens[2] != ("PUNCT", "(") or tokens[-1] != ("PUNCT", ")"):
        return None
    values: set[str] = set()
    inner = tokens[3:-1]
    if not inner:
        return None
    expect_value = True
    for kind, value in inner:
        if expect_value:
            if kind != "STRING" or value in values:
                return None
            values.add(value)
        elif (kind, value) != ("PUNCT", ","):
            return None
        expect_value = not expect_value
    if expect_value:
        return None
    return values


def _check_allows_lifecycle_values(tokens: list[tuple[str, str]]) -> bool:
    tokens = _strip_outer_parens(tokens)
    canonical = LIFECYCLE_STATUSES
    if _parse_lifecycle_in(tokens) == canonical:
        return True

    # Only the two explicitly approved IS NULL disjunct forms are accepted.
    for separator, token in enumerate(tokens):
        if token[0] != "IDENT" or token[1].upper() != "OR":
            continue
        left = _strip_outer_parens(tokens[:separator])
        right = _strip_outer_parens(tokens[separator + 1 :])

        def is_null_clause(part: list[tuple[str, str]]) -> bool:
            part = _strip_outer_parens(part)
            return (
                len(part) == 3
                and part[0][0] == "IDENT"
                and part[0][1].lower() == "lifecycle_status"
                and part[1][0] == "IDENT"
                and part[1][1].upper() == "IS"
                and part[2][0] == "IDENT"
                and part[2][1].upper() == "NULL"
            )

        if is_null_clause(left) and _parse_lifecycle_in(right) == canonical:
            return True
        if _parse_lifecycle_in(left) == canonical and is_null_clause(right):
            return True
    return False


def _lifecycle_checks(sql: str) -> list[list[tuple[str, str]]]:
    tokens = _tokenize_sql(sql)
    checks: list[list[tuple[str, str]]] = []
    i = 0
    while i < len(tokens):
        kind, value = tokens[i]
        if kind == "IDENT" and value.upper() == "CHECK":
            if i + 1 >= len(tokens) or tokens[i + 1] != ("PUNCT", "("):
                i += 1
                continue
            depth = 0
            end = None
            for j in range(i + 1, len(tokens)):
                if tokens[j] == ("PUNCT", "("):
                    depth += 1
                elif tokens[j] == ("PUNCT", ")"):
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
            if end is None:
                raise ValueError("Unbalanced CHECK expression in messages table DDL")
            expression = tokens[i + 2 : end]
            if any(
                token_kind == "IDENT" and token_value.lower() == "lifecycle_status"
                for token_kind, token_value in expression
            ):
                checks.append(expression)
            i = end + 1
            continue
        i += 1
    return checks


def _lifecycle_column_collation_is_supported(sql: str) -> bool:
    tokens = _tokenize_sql(sql)
    table_open = next(
        (index for index, token in enumerate(tokens) if token == ("PUNCT", "(")),
        None,
    )
    if table_open is None:
        return False
    segments: list[list[tuple[str, str]]] = []
    depth = 1
    start = table_open + 1
    for index in range(table_open + 1, len(tokens)):
        token = tokens[index]
        if token == ("PUNCT", "("):
            depth += 1
        elif token == ("PUNCT", ")"):
            depth -= 1
            if depth == 0:
                segments.append(tokens[start:index])
                break
        elif token == ("PUNCT", ",") and depth == 1:
            segments.append(tokens[start:index])
            start = index + 1
    else:
        return False

    for segment in segments:
        if not segment or segment[0][0] != "IDENT":
            continue
        if segment[0][1].lower() != "lifecycle_status":
            continue
        depth = 0
        for index, token in enumerate(segment[1:], start=1):
            if token == ("PUNCT", "("):
                depth += 1
            elif token == ("PUNCT", ")"):
                depth -= 1
            elif (
                depth == 0
                and token[0] == "IDENT"
                and token[1].upper() == "COLLATE"
            ):
                if index + 1 >= len(segment):
                    return False
                collation = segment[index + 1]
                return (
                    collation[0] == "IDENT"
                    and collation[1].upper() == "BINARY"
                )
        return True
    return False


def _canonical_lifecycle_status(
    role: str, lifecycle_status: str | None, legacy_status: str
) -> str:
    if role == "assistant" and lifecycle_status is None:
        return legacy_status
    if lifecycle_status is not None:
        if lifecycle_status not in LIFECYCLE_STATUSES:
            raise ValueError("Unknown lifecycle_status value in messages")
        return lifecycle_status
    return {"complete": "completed"}.get(legacy_status, legacy_status)


def _api_status(role: str, lifecycle_status: str | None, legacy_status: str) -> str:
    canonical = _canonical_lifecycle_status(role, lifecycle_status, legacy_status)
    return "complete" if canonical == "completed" else canonical


logger = logging.getLogger(__name__)


def _log_connection_cleanup_failure(phase: str, error: BaseException) -> None:
    try:
        logger.error("Chat connection cleanup failed during %s (%s)", phase, type(error).__name__)
    except BaseException:
        pass


class ChatStore:
    def __init__(self, database_path: str):
        self.path = canonical_database_path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path)
        error_pending = False
        try:
            conn.row_factory = sqlite3.Row
            yield conn
            conn.commit()
        except BaseException:
            error_pending = True
            try:
                conn.rollback()
            except BaseException as error:
                _log_connection_cleanup_failure("rollback", error)
            raise
        finally:
            try:
                conn.close()
            except BaseException as error:
                if not error_pending:
                    raise
                _log_connection_cleanup_failure("close", error)

    @staticmethod
    def _preflight_messages(conn: sqlite3.Connection) -> tuple[set[str], str | None]:
        table = conn.execute(
            "SELECT type, sql FROM sqlite_master WHERE name = 'messages'"
        ).fetchone()
        if table is None:
            return set(), None
        if table["type"] != "table" or not table["sql"]:
            raise ValueError("messages must be an ordinary SQLite table")

        tokens = _tokenize_sql(table["sql"])
        leading = [token[1].upper() for token in tokens[:3] if token[0] == "IDENT"]
        if leading[:3] == ["CREATE", "VIRTUAL", "TABLE"]:
            raise ValueError("Virtual messages tables are not supported by this migration")

        info = conn.execute("PRAGMA table_xinfo(messages)").fetchall()
        columns = {row["name"] for row in info}
        required = {"id", "role", "content", "created_at"}
        missing = required - columns
        if missing:
            raise ValueError(
                "messages table is missing required columns: " + ", ".join(sorted(missing))
            )

        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        for table_row in tables:
            table_name = table_row["name"]
            quoted_table = '"' + table_name.replace('"', '""') + '"'
            for fk in conn.execute(f"PRAGMA foreign_key_list({quoted_table})"):
                if fk["table"] == "messages" and fk["to"] == "lifecycle_status":
                    raise ValueError(
                        "lifecycle_status cannot be referenced by an existing foreign key"
                    )

        if "lifecycle_status" in columns:
            column = next(row for row in info if row["name"] == "lifecycle_status")
            if (
                column["type"].strip().upper() != "TEXT"
                or column["notnull"]
                or column["pk"]
                or column["hidden"]
                or column["dflt_value"] is not None
            ):
                raise ValueError(
                    "Existing lifecycle_status must be a nullable, ordinary TEXT column "
                    "without a default or primary-key constraint"
                )

            if not _lifecycle_column_collation_is_supported(table["sql"]):
                raise ValueError(
                    "Existing lifecycle_status must use the default BINARY collation"
                )
            for index in conn.execute("PRAGMA index_list(messages)"):
                if not index["unique"]:
                    continue
                quoted_index = '"' + index["name"].replace('"', '""') + '"'
                indexed_columns = {
                    row["name"]
                    for row in conn.execute(f"PRAGMA index_info({quoted_index})")
                }
                index_sql = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
                    (index["name"],),
                ).fetchone()[0]
                index_references_lifecycle = index_sql is not None and any(
                    kind == "IDENT" and value.lower() == "lifecycle_status"
                    for kind, value in _tokenize_sql(index_sql)
                )
                if "lifecycle_status" in indexed_columns or index_references_lifecycle:
                    raise ValueError(
                        "Existing lifecycle_status cannot participate in a UNIQUE index"
                    )
            for fk in conn.execute("PRAGMA foreign_key_list(messages)"):
                if fk["from"] == "lifecycle_status":
                    raise ValueError(
                        "Existing lifecycle_status cannot be constrained by a foreign key"
                    )
            checks = _lifecycle_checks(table["sql"])
            if any(not _check_allows_lifecycle_values(check) for check in checks):
                raise ValueError(
                    "Existing lifecycle_status CHECK must allow exactly the five "
                    "canonical lifecycle values"
                )
            values = {
                row[0]
                for row in conn.execute(
                    "SELECT DISTINCT lifecycle_status FROM messages "
                    "WHERE lifecycle_status IS NOT NULL"
                )
            }
            unknown = values - LIFECYCLE_STATUSES
            if unknown:
                raise ValueError(
                    "Existing lifecycle_status contains unknown values: "
                    + ", ".join(sorted(str(value) for value in unknown))
                )

        return columns, table["sql"]

    @staticmethod
    def _postflight_messages(
        conn: sqlite3.Connection, *, check_foreign_keys: bool
    ) -> None:
        columns, _ = ChatStore._preflight_messages(conn)
        if "lifecycle_status" not in columns:
            raise RuntimeError("lifecycle_status postflight verification failed")
        if check_foreign_keys:
            violations = conn.execute("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise RuntimeError("SQLite foreign_key_check found violations after migration")

    @staticmethod
    def _schema_objects(conn: sqlite3.Connection) -> list[tuple[Any, ...]]:
        return [
            tuple(row)
            for row in conn.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE type IN ('index','trigger','view') ORDER BY type, name"
            )
        ]

    @staticmethod
    def _verify_schema_objects(
        conn: sqlite3.Connection, original_objects: list[tuple[Any, ...]]
    ) -> None:
        current = set(ChatStore._schema_objects(conn))
        missing_or_changed = [item for item in original_objects if item not in current]
        if missing_or_changed:
            raise RuntimeError("Existing SQLite indexes, triggers, or views changed during migration")
        views = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY name"
        ).fetchall()
        for row in views:
            quoted = '"' + row["name"].replace('"', '""') + '"'
            conn.execute(f"SELECT * FROM {quoted} LIMIT 0").fetchall()

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            original_schema_version = conn.execute("PRAGMA schema_version").fetchone()[0]
            columns, _ = self._preflight_messages(conn)
            original_objects = self._schema_objects(conn)
            if not columns:
                conn.execute("""CREATE TABLE messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    role TEXT NOT NULL CHECK(role IN ('user','assistant')),
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    status TEXT NOT NULL DEFAULT 'complete'
                        CHECK(status IN ('pending','failed','complete')),
                    request_id TEXT,
                    provider_id TEXT,
                    model_name TEXT,
                    requested_model TEXT,
                    provider_model TEXT,
                    lifecycle_status TEXT
                )""")
                columns = {
                    row["name"] for row in conn.execute("PRAGMA table_xinfo(messages)")
                }
            if "status" not in columns:
                conn.execute(
                    "ALTER TABLE messages ADD COLUMN status TEXT NOT NULL DEFAULT 'complete' "
                    "CHECK(status IN ('pending','failed','complete'))"
                )
            if "request_id" not in columns:
                conn.execute("ALTER TABLE messages ADD COLUMN request_id TEXT")
            if "provider_id" not in columns:
                conn.execute("ALTER TABLE messages ADD COLUMN provider_id TEXT")
            if "model_name" not in columns:
                conn.execute("ALTER TABLE messages ADD COLUMN model_name TEXT")
            if "requested_model" not in columns:
                conn.execute("ALTER TABLE messages ADD COLUMN requested_model TEXT")
            if "provider_model" not in columns:
                conn.execute("ALTER TABLE messages ADD COLUMN provider_model TEXT")
            if "lifecycle_status" not in columns:
                conn.execute("ALTER TABLE messages ADD COLUMN lifecycle_status TEXT")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_user_request_id "
                "ON messages(request_id) WHERE role = 'user' AND request_id IS NOT NULL"
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_assistant_request_id "
                "ON messages(request_id) WHERE role = 'assistant' AND request_id IS NOT NULL"
            )
            schema_changed = (
                conn.execute("PRAGMA schema_version").fetchone()[0]
                != original_schema_version
            )
            self._postflight_messages(conn, check_foreign_keys=schema_changed)
            if schema_changed:
                self._verify_schema_objects(conn, original_objects)

    def add_message(self, role: str, content: str) -> int:
        if role not in ("user", "assistant"):
            raise ValueError("Unsupported role")
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO messages(role, content) VALUES (?, ?)", (role, content)
            )
            return int(cur.lastrowid)

    def claim_pending_user(self, content: str, request_id: str) -> tuple[int, bool]:
        """Claim a request ID once, serializing concurrent claims in SQLite."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT id, content FROM messages "
                "WHERE role = 'user' AND request_id = ?",
                (request_id,),
            ).fetchone()
            if existing is not None:
                if existing["content"] != content:
                    raise RequestIdConflict("Request ID was already used with different text")
                return int(existing["id"]), False
            cur = conn.execute(
                "INSERT INTO messages(role, content, status, request_id, lifecycle_status) "
                "VALUES ('user', ?, 'pending', ?, 'pending')",
                (content, request_id),
            )
            return int(cur.lastrowid), True

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            # Keep both reads on one SQLite snapshot if the turn completes concurrently.
            conn.execute("BEGIN")
            user = conn.execute(
                "SELECT id, role, content, status, lifecycle_status, request_id FROM messages "
                "WHERE role = 'user' AND request_id = ?",
                (request_id,),
            ).fetchone()
            if user is None:
                return None
            assistant = conn.execute(
                "SELECT content, provider_id, model_name, requested_model, provider_model "
                "FROM messages "
                "WHERE role = 'assistant' AND request_id = ?",
                (request_id,),
            ).fetchone()
        return {
            "message_id": int(user["id"]),
            "message": user["content"],
            "status": _api_status(
                user["role"], user["lifecycle_status"], user["status"]
            ),
            "request_id": user["request_id"],
            "reply": assistant["content"] if assistant is not None else None,
            "provider_id": assistant["provider_id"] if assistant is not None else None,
            "model_name": assistant["model_name"] if assistant is not None else None,
            "requested_model": assistant["requested_model"] if assistant is not None else None,
            "provider_model": assistant["provider_model"] if assistant is not None else None,
        }

    def mark_failed(self, message_id: int) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE messages SET lifecycle_status = 'failed', status = 'failed' "
                "WHERE id = ? AND role = 'user' "
                "AND COALESCE(lifecycle_status, CASE status WHEN 'complete' "
                "THEN 'completed' ELSE status END) = 'dispatching'",
                (message_id,),
            )
            if cur.rowcount != 1:
                raise ValueError("Dispatching user message was not found")

    def mark_dispatching(self, message_id: int) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE messages SET lifecycle_status = 'dispatching', status = 'pending' "
                "WHERE id = ? AND role = 'user' "
                "AND COALESCE(lifecycle_status, CASE status WHEN 'complete' "
                "THEN 'completed' ELSE status END) = 'pending'",
                (message_id,),
            )
            if cur.rowcount != 1:
                raise ValueError("Pending user message was not found")

    def mark_unknown(self, message_id: int) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE messages SET lifecycle_status = 'unknown', status = 'pending' "
                "WHERE id = ? AND role = 'user' "
                "AND COALESCE(lifecycle_status, CASE status WHEN 'complete' "
                "THEN 'completed' ELSE status END) = 'dispatching'",
                (message_id,),
            )
            if cur.rowcount != 1:
                raise ValueError("Dispatching user message was not found")

    def complete_turn(
        self,
        user_message_id: int,
        answer: str,
        provider_id: str | None = None,
        model_name: str | None = None,
        requested_model: str | None = None,
        provider_model: str | None = None,
    ) -> int:
        """Atomically complete a dispatched user message and insert its reply."""
        if requested_model is None:
            requested_model = model_name
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            user = conn.execute(
                "SELECT request_id FROM messages WHERE id = ? AND role = 'user' "
                "AND COALESCE(lifecycle_status, CASE status WHEN 'complete' "
                "THEN 'completed' ELSE status END) = 'dispatching'",
                (user_message_id,),
            ).fetchone()
            if user is None:
                raise ValueError("Dispatching user message was not found")
            cur = conn.execute(
                "UPDATE messages SET lifecycle_status = 'completed', status = 'complete' "
                "WHERE id = ? AND role = 'user' "
                "AND COALESCE(lifecycle_status, CASE status WHEN 'complete' "
                "THEN 'completed' ELSE status END) = 'dispatching'",
                (user_message_id,),
            )
            if cur.rowcount != 1:
                raise ValueError("Dispatching user message was not found")
            assistant = conn.execute(
                "INSERT INTO messages(role, content, status, request_id, provider_id, model_name, "
                "requested_model, provider_model) "
                "VALUES ('assistant', ?, 'complete', ?, ?, ?, ?, ?)",
                (
                    answer,
                    user["request_id"],
                    provider_id,
                    requested_model,
                    requested_model,
                    provider_model,
                ),
            )
            return int(assistant.lastrowid)

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, role, content, created_at, status, lifecycle_status, request_id, "
                "provider_id, model_name, requested_model, provider_model FROM messages "
                "ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        history = []
        for row in reversed(rows):
            item = dict(row)
            item["status"] = _api_status(
                item["role"], item.pop("lifecycle_status"), item["status"]
            )
            history.append(item)
        return history

    def clear(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                active = conn.execute(
                    "SELECT 1 FROM messages WHERE role = 'user' "
                    "AND COALESCE(lifecycle_status, CASE status WHEN 'complete' "
                    "THEN 'completed' ELSE status END) IN ('pending','dispatching') "
                    "LIMIT 1"
                ).fetchone()
                if active is not None:
                    raise ActiveRequestsError(
                        "History cannot be cleared while a request is pending or dispatching"
                    )
                conn.execute("DELETE FROM messages")
        except sqlite3.OperationalError as exc:
            code = getattr(exc, "sqlite_errorcode", None)
            primary_code = code & 0xFF if code is not None else None
            if primary_code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise DatabaseBusyError("SQLite is busy or locked") from exc
            raise
