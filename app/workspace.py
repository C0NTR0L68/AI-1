"""Opt-in NEW chat workspace. Never imports or migrates the legacy chat DB.

Per-chat epochs and request fingerprints bind atomic context/claim operations.
Existing workspaces must match this exact schema; no automatic repair/reseed.
"""
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import time
from uuid import UUID, uuid4

from app.context import (
    HISTORY_RECALL_PROVIDER, UNCONFIRMED_RECALL, context_from_history,
    is_exact_history_recall, recall_previous_identifier,
)
from app.document_context import LOCAL_EXTRACTION_PROVIDER
from app.db import ChatStore, ActiveRequestsError
from app.runtime_lock import canonical_database_path

VERSION = 1
APPLICATION_ID = 0x41493157
CHAT_SQL = """CREATE TABLE chats (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, epoch TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"""
TURN_SQL = """CREATE TABLE turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL UNIQUE,
    chat_id TEXT NOT NULL REFERENCES chats(id), epoch TEXT NOT NULL,
    fingerprint TEXT NOT NULL, question TEXT NOT NULL, reply TEXT,
    status TEXT NOT NULL CHECK(status IN ('pending','dispatching','completed','failed','unknown')),
    provider_id TEXT, requested_model TEXT, provider_model TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"""


class WorkspaceConflict(ValueError):
    """Stale epoch, reused identity or incompatible operation; HTTP409."""


def identifier(value):
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError("Canonical UUID required")
    return value


def fingerprint(question, target, sources):
    # Sources are explicit bounded JSON data, never filesystem references.
    data = json.dumps([question, target, sources], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8", errors="strict")).hexdigest()


class WorkspaceStore:
    # Reuse the already-tested primary-error-preserving connection lifecycle.
    @contextmanager
    def _connect(self):
        with ChatStore._connect(self) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn

    def __init__(self, database_path, *, create=False):
        from app.start import local_configuration
        local_configuration(str(database_path), "path-validation-only")
        candidate = Path(database_path)
        if not candidate.is_absolute():
            raise ValueError("Explicit absolute workspace path required")
        for part in (candidate, *candidate.parents):
            if part.is_symlink() or part.is_junction():
                raise ValueError("Linked workspace path refused")
        self.path = canonical_database_path(candidate)
        if not self.path.parent.is_dir():
            raise ValueError("Workspace parent directory must exist")
        if create:
            from app.history_preflight import _sidecars
            _sidecars(self.path)
            # Exclusive creation cannot overwrite an existing legacy/user DB.
            with self.path.open("xb"):
                pass
            with self._connect() as conn:
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(CHAT_SQL)
                conn.execute(TURN_SQL)
                conn.execute(f"PRAGMA application_id={APPLICATION_ID}")
                conn.execute(f"PRAGMA user_version={VERSION}")
        else:
            self.preflight(self.path)

    @staticmethod
    def preflight(path):
        from app.history_preflight import _sidecars
        path = Path(path)
        if not path.is_file() or path.is_symlink() or path.is_junction() or path.stat().st_nlink != 1:
            raise ValueError("Existing regular single-link workspace required")
        _sidecars(path)
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("Workspace exceeds initial preflight read budget; review required")
        conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0)
        failed = False
        try:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA trusted_schema=OFF")
            deadline = time.monotonic() + 3
            conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            conn.execute("BEGIN")
            if conn.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID or conn.execute("PRAGMA user_version").fetchone()[0] != VERSION:
                raise ValueError("Unsupported workspace identity/version")
            rows = conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
            expected = {("table", "chats", CHAT_SQL), ("table", "turns", TURN_SQL),
                        ("table", "sqlite_sequence", "CREATE TABLE sqlite_sequence(name,seq)"),
                        ("index", "sqlite_autoindex_chats_1", None), ("index", "sqlite_autoindex_turns_1", None)}
            if set(rows) != expected:
                raise ValueError("Unreviewed workspace schema objects")
            if conn.execute("PRAGMA quick_check").fetchall() != [("ok",)] or conn.execute("PRAGMA foreign_key_check").fetchall():
                raise ValueError("Workspace integrity failure")
        except BaseException:
            failed = True
            raise
        finally:
            try:
                conn.close()
            except BaseException:
                if not failed:
                    raise

    @staticmethod
    def _chat(conn, chat_id, epoch=None):
        identifier(chat_id)
        row = conn.execute("SELECT * FROM chats WHERE id=?", (chat_id,)).fetchone()
        if row is None:
            raise KeyError("Chat not found")
        if epoch is not None and row["epoch"] != identifier(epoch):
            raise WorkspaceConflict("History changed; refresh this chat. Nothing was sent.")
        return dict(row)

    def chats(self):
        with self._connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM chats ORDER BY created_at,id")]

    def create_chat(self, chat_id, title):
        identifier(chat_id)
        title = self._title(title)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            old = conn.execute("SELECT * FROM chats WHERE id=?", (chat_id,)).fetchone()
            if old:
                if old["title"] != title:
                    raise WorkspaceConflict("Chat ID already used")
                return dict(old)
            conn.execute("INSERT INTO chats(id,title,epoch) VALUES(?,?,?)", (chat_id, title, str(uuid4())))
            return self._chat(conn, chat_id)

    @staticmethod
    def _title(title):
        if type(title) is not str or not title.strip() or len(title) > 100 or any(ord(c) < 32 for c in title):
            raise ValueError("Chat title must be 1–100 plain characters")
        title.encode("utf-8", errors="strict")
        return title.strip()

    @staticmethod
    def _rows(conn, chat_id, *, before=None, limit=100):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid history page size")
        if before is not None and (type(before) is not int or not 1 <= before <= 2**63 - 1):
            raise ValueError("Invalid history cursor")
        if before is None:
            return conn.execute("SELECT * FROM turns WHERE chat_id=? ORDER BY id DESC LIMIT ?", (chat_id, limit + 1)).fetchall()
        return conn.execute("SELECT * FROM turns WHERE chat_id=? AND id<? ORDER BY id DESC LIMIT ?", (chat_id, before, limit + 1)).fetchall()

    @staticmethod
    def _messages(rows):
        messages = []
        for row in reversed(rows):
            common = {"request_id": row["request_id"], "provider_id": row["provider_id"],
                      "requested_model": row["requested_model"], "provider_model": row["provider_model"],
                      "model_name": row["requested_model"], "created_at": row["created_at"]}
            status = "complete" if row["status"] == "completed" else row["status"]
            messages.append({**common, "id": row["id"] * 2, "role": "user", "content": row["question"], "status": status})
            if row["status"] == "completed":
                messages.append({**common, "id": row["id"] * 2 + 1, "role": "assistant", "content": row["reply"], "status": "complete"})
        return messages

    @classmethod
    def _history(cls, conn, chat_id):
        return cls._messages(cls._rows(conn, chat_id, limit=100)[:100])

    def history(self, chat_id, *, epoch=None, before=None, limit=50):
        if before is not None and epoch is None:
            raise ValueError("History cursor requires its epoch")
        with self._connect() as conn:
            conn.execute("BEGIN")
            chat = self._chat(conn, chat_id, epoch)
            rows = self._rows(conn, chat_id, before=before, limit=limit)
            more = len(rows) > limit
            selected = rows[:limit]
            return {"chat": chat, "messages": self._messages(selected),
                    "next_before": selected[-1]["id"] if more else None}

    def claim(self, chat_id, epoch, request_id, question, digest, *, exact_document_answer=None, allow_history_recall=True):
        identifier(request_id)
        if type(question) is not str or not question.strip() or len(question) > 12000 or "\x00" in question:
            raise ValueError("Invalid message")
        if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid request fingerprint")
        if exact_document_answer is not None and (
            type(exact_document_answer) is not str or not exact_document_answer.strip()
            or "\x00" in exact_document_answer or len(exact_document_answer.encode("utf-8")) > 16000
        ):
            raise ValueError("Invalid local document answer")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._chat(conn, chat_id, epoch)  # Before duplicate lookup/context.
            old = conn.execute("SELECT * FROM turns WHERE request_id=?", (request_id,)).fetchone()
            if old:
                if old["chat_id"] != chat_id or old["epoch"] != epoch or old["fingerprint"] != digest or old["question"] != question:
                    raise WorkspaceConflict("Request identity already bound to a different payload")
                return False, self._state(old), None
            answer, provider_id = exact_document_answer, LOCAL_EXTRACTION_PROVIDER
            if answer is None and allow_history_recall and is_exact_history_recall(question):
                previous = conn.execute(
                    "SELECT question,reply,status,provider_id FROM turns "
                    "WHERE chat_id=? AND epoch=? ORDER BY id DESC LIMIT 1", (chat_id, epoch),
                ).fetchone()
                answer, provider_id = UNCONFIRMED_RECALL, HISTORY_RECALL_PROVIDER
                if (previous is not None and previous["status"] == "completed"
                        and previous["provider_id"] not in (None, LOCAL_EXTRACTION_PROVIDER, HISTORY_RECALL_PROVIDER)):
                    answer = recall_previous_identifier(previous["question"], previous["reply"])
            if answer is None:
                history = [row for row in self._history(conn, chat_id)
                           if row["provider_id"] not in (LOCAL_EXTRACTION_PROVIDER, HISTORY_RECALL_PROVIDER)]
                context = context_from_history(history[-20:], question)
                conn.execute("INSERT INTO turns(request_id,chat_id,epoch,fingerprint,question,status) VALUES(?,?,?,?,?,'pending')",
                             (request_id, chat_id, epoch, digest, question))
            else:
                context = None
                conn.execute("INSERT INTO turns(request_id,chat_id,epoch,fingerprint,question,status,reply,provider_id) VALUES(?,?,?,?,?,'completed',?,?)",
                             (request_id, chat_id, epoch, digest, question, answer, provider_id))
            row = conn.execute("SELECT * FROM turns WHERE request_id=?", (request_id,)).fetchone()
            return True, self._state(row), context

    @staticmethod
    def _state(row):
        return {"request_id": row["request_id"], "message_id": row["id"] * 2,
                "status": "complete" if row["status"] == "completed" else row["status"],
                "reply": row["reply"], "provider_id": row["provider_id"],
                "requested_model": row["requested_model"], "model_name": row["requested_model"],
                "provider_model": row["provider_model"]}

    def request(self, chat_id, epoch, request_id):
        identifier(request_id)
        with self._connect() as conn:
            conn.execute("BEGIN")
            self._chat(conn, chat_id, epoch)
            row = conn.execute("SELECT * FROM turns WHERE request_id=? AND chat_id=? AND epoch=?", (request_id, chat_id, epoch)).fetchone()
            if row is None:
                raise KeyError("Request not found")
            return self._state(row)

    def transition(self, chat_id, epoch, request_id, status, result=None):
        if status not in ("dispatching", "completed", "failed", "unknown"):
            raise ValueError("Invalid lifecycle transition")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._chat(conn, chat_id, epoch)
            expected = "pending" if status == "dispatching" else "dispatching"
            if status == "completed":
                if result is None or type(result.text) is not str or not result.text.strip():
                    raise ValueError("Missing successful result")
                if len(result.text) > 64000 or len(result.text.encode("utf-8", errors="strict")) > 256000:
                    raise ValueError("Result exceeds initial response budget")
                cursor = conn.execute("UPDATE turns SET status=?,reply=?,provider_id=?,requested_model=?,provider_model=? WHERE request_id=? AND chat_id=? AND epoch=? AND status=?",
                    (status, result.text, result.provider_id, result.requested_model, result.provider_model, request_id, chat_id, epoch, expected))
            else:
                cursor = conn.execute("UPDATE turns SET status=? WHERE request_id=? AND chat_id=? AND epoch=? AND status=?",
                                      (status, request_id, chat_id, epoch, expected))
            if cursor.rowcount != 1:
                raise WorkspaceConflict("Request state changed; no generation may be started")
            # The caller receives this snapshot only after _connect commits.
            # Do not read again after commit: a concurrent clear may rotate the
            # epoch/delete the row before that second lookup.
            row = conn.execute("SELECT * FROM turns WHERE request_id=? AND chat_id=? AND epoch=?",
                               (request_id, chat_id, epoch)).fetchone()
            return self._state(row)

    def change_chat(self, chat_id, epoch, *, title=None, delete=False, clear=False):
        if sum((title is not None, delete is True, clear is True)) != 1:
            raise ValueError("Select exactly one chat operation")
        if title is not None:
            title = self._title(title)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._chat(conn, chat_id, epoch)
            if title is not None:
                conn.execute("UPDATE chats SET title=? WHERE id=?", (title, chat_id))
            else:
                if conn.execute("SELECT 1 FROM turns WHERE chat_id=? AND status IN ('pending','dispatching') LIMIT 1", (chat_id,)).fetchone():
                    raise ActiveRequestsError("Chat has active requests")
                conn.execute("DELETE FROM turns WHERE chat_id=?", (chat_id,))
                if delete:
                    conn.execute("DELETE FROM chats WHERE id=?", (chat_id,))
                    return {"ok": True}
                conn.execute("UPDATE chats SET epoch=? WHERE id=?", (str(uuid4()), chat_id))
            return {"ok": True, "chat": self._chat(conn, chat_id)}


def recover_workspace_dispatching(database_path):
    """Explicit OFFLINE operation only; never invoked by startup/constructor.

    The same OS-exclusive database lock as ApplicationRuntime proves no
    cooperating handler remains. No PID/age/user flag substitutes for it.
    """
    from app.runtime_lock import DatabaseProcessLock
    from app.start import local_configuration
    local_configuration(str(database_path), "path-validation-only")
    path = Path(database_path)
    if not path.is_file() or any(item.is_symlink() or item.is_junction() for item in (path, *path.parents)):
        raise ValueError("Existing non-linked workspace required")
    with DatabaseProcessLock(path):
        store = WorkspaceStore(str(path))  # Read-only schema preflight under lock.
        with store._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute("UPDATE turns SET status='unknown' WHERE status='dispatching'").rowcount
            return changed
