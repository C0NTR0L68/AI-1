import sqlite3
from pathlib import Path
from typing import Any


class RequestIdConflict(ValueError):
    """Raised when a request ID is reused with different message text."""


class ChatStore:
    def __init__(self, database_path: str):
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role TEXT NOT NULL CHECK(role IN ('user','assistant')),
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'complete'
                    CHECK(status IN ('pending','failed','complete')),
                request_id TEXT
            )""")
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(messages)")}
            if "status" not in columns:
                conn.execute(
                    "ALTER TABLE messages ADD COLUMN status TEXT NOT NULL DEFAULT 'complete' "
                    "CHECK(status IN ('pending','failed','complete'))"
                )
            if "request_id" not in columns:
                conn.execute("ALTER TABLE messages ADD COLUMN request_id TEXT")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_user_request_id "
                "ON messages(request_id) WHERE role = 'user' AND request_id IS NOT NULL"
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_assistant_request_id "
                "ON messages(request_id) WHERE role = 'assistant' AND request_id IS NOT NULL"
            )

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
                "INSERT INTO messages(role, content, status, request_id) "
                "VALUES ('user', ?, 'pending', ?)",
                (content, request_id),
            )
            return int(cur.lastrowid), True

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            # Keep both reads on one SQLite snapshot if the turn completes concurrently.
            conn.execute("BEGIN")
            user = conn.execute(
                "SELECT id, content, status, request_id FROM messages "
                "WHERE role = 'user' AND request_id = ?",
                (request_id,),
            ).fetchone()
            if user is None:
                return None
            assistant = conn.execute(
                "SELECT content FROM messages "
                "WHERE role = 'assistant' AND request_id = ?",
                (request_id,),
            ).fetchone()
        return {
            "message_id": int(user["id"]),
            "message": user["content"],
            "status": user["status"],
            "request_id": user["request_id"],
            "reply": assistant["content"] if assistant is not None else None,
        }

    def mark_failed(self, message_id: int) -> None:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE messages SET status = 'failed' "
                "WHERE id = ? AND role = 'user' AND status = 'pending'",
                (message_id,),
            )
            if cur.rowcount != 1:
                raise ValueError("Pending user message was not found")

    def complete_turn(self, user_message_id: int, answer: str) -> int:
        """Atomically mark the pending user message complete and insert its reply."""
        with self._connect() as conn:
            user = conn.execute(
                "SELECT request_id FROM messages "
                "WHERE id = ? AND role = 'user' AND status = 'pending'",
                (user_message_id,),
            ).fetchone()
            if user is None:
                raise ValueError("Pending user message was not found")
            cur = conn.execute(
                "UPDATE messages SET status = 'complete' "
                "WHERE id = ? AND role = 'user' AND status = 'pending'",
                (user_message_id,),
            )
            if cur.rowcount != 1:
                raise ValueError("Pending user message was not found")
            assistant = conn.execute(
                "INSERT INTO messages(role, content, status, request_id) "
                "VALUES ('assistant', ?, 'complete', ?)",
                (answer, user["request_id"]),
            )
            return int(assistant.lastrowid)

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, role, content, created_at, status, request_id FROM messages "
                "ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM messages")
