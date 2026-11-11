import sqlite3
from pathlib import Path
from typing import Any

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
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")

    def add_message(self, role: str, content: str) -> int:
        if role not in ("user", "assistant"):
            raise ValueError("Unsupported role")
        with self._connect() as conn:
            cur = conn.execute("INSERT INTO messages(role, content) VALUES (?, ?)", (role, content))
            return int(cur.lastrowid)

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, role, content, created_at FROM messages ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM messages")
