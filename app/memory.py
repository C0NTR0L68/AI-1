"""Standalone opt-in prototype. Never imports chat, configuration or providers.

Notes are plain local text, not instructions. No extraction, secret detection,
encryption, provider upload or application integration is implemented.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import logging
import sqlite3


logger = logging.getLogger(__name__)


def _log_cleanup_failure(phase: str, error: BaseException) -> None:
    try:
        # Never include SQLite messages, note contents, paths or tracebacks.
        logger.error("Memory cleanup failed during %s (%s)", phase, type(error).__name__)
    except BaseException:
        # Even a broken logging handler must not replace the original failure.
        pass


class MemoryDisabledError(RuntimeError):
    """An explicit memory operation was requested while memory is disabled."""


class MemoryStorageError(RuntimeError):
    """The selected file is not a compatible dedicated memory store."""


@dataclass(frozen=True)
class MemoryNote:
    id: int
    content: str
    created_at: str


_APPLICATION_ID = 0x4149314D
_SCHEMA = """CREATE TABLE memory_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL CHECK(length(content) BETWEEN 1 AND 4096),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
)"""


class MemoryService:
    """Explicit add/list/delete only; create a new instance to enable memory.

    The parent directory must already exist. Existing databases are accepted
    only if they have this prototype's exact schema and ownership/version tags.
    SQLite errors propagate; no operation retries or logs note contents.
    """

    MAX_NOTE_CHARS = 4096

    def __init__(self, database_path: str | Path | None = None, *, enabled: bool = False):
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        self._enabled = enabled
        self._path: Path | None = None
        if not enabled:
            return
        if not isinstance(database_path, (str, Path)) or not Path(database_path).is_absolute():
            raise ValueError("Enabled memory requires an absolute SQLite file path")
        path = Path(database_path).resolve()
        chat_path = Path(__file__).resolve().parent.parent / "data" / "ai1.sqlite3"
        if path == chat_path.resolve() or (
            path.exists() and chat_path.exists() and path.samefile(chat_path)
        ):
            raise ValueError("The working chat database cannot be used for memory")
        self._path = path
        self._initialize()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _require_enabled(self) -> None:
        if not self._enabled:
            raise MemoryDisabledError("Memory is disabled")

    def _connect(self) -> sqlite3.Connection:
        self._require_enabled()
        return sqlite3.connect(str(self._path), timeout=2.0)

    @contextmanager
    def _write(self):
        connection = self._connect()
        error_pending = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            error_pending = True
            try:
                connection.rollback()
            except BaseException as error:
                _log_cleanup_failure("rollback", error)
            raise
        finally:
            try:
                connection.close()
            except BaseException as error:
                if not error_pending:
                    # COMMIT returned, but cleanup failed: do not return success.
                    raise
                _log_cleanup_failure("close", error)

    def _initialize(self) -> None:
        with self._write() as connection:
            objects = connection.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE name NOT GLOB 'sqlite_*' ORDER BY type, name"
            ).fetchall()
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if objects:
                if (application_id != _APPLICATION_ID or version != 1 or
                        objects != [("table", "memory_notes", _SCHEMA)]):
                    raise MemoryStorageError("Expected a dedicated compatible memory database")
            else:
                if application_id != 0 or version != 0:
                    raise MemoryStorageError("Refusing a database owned by another application")
                connection.execute(_SCHEMA)
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute("PRAGMA user_version=1")

    def add_note(self, content: str) -> MemoryNote:
        self._require_enabled()
        if not isinstance(content, str):
            raise ValueError("Note content must be text")
        if len(content) > self.MAX_NOTE_CHARS:
            raise ValueError("Note exceeds 4096 characters")
        content = content.strip()
        if not content or "\x00" in content:
            raise ValueError("Note must contain nonblank text without NUL characters")
        try:
            content.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("Note must be valid UTF-8 text") from None
        with self._write() as connection:
            cursor = connection.execute("INSERT INTO memory_notes (content) VALUES (?)", (content,))
            row = connection.execute(
                "SELECT id, content, created_at FROM memory_notes WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
            note = MemoryNote(*row)
        return note

    def list_notes(self) -> list[MemoryNote]:
        self._require_enabled()
        connection = self._connect()
        error_pending = False
        try:
            rows = connection.execute(
                "SELECT id, content, created_at FROM memory_notes ORDER BY id"
            ).fetchall()
            return [MemoryNote(*row) for row in rows]
        except BaseException:
            error_pending = True
            raise
        finally:
            try:
                connection.close()
            except BaseException as error:
                if not error_pending:
                    raise
                _log_cleanup_failure("close", error)

    def delete_note(self, note_id: int) -> bool:
        self._require_enabled()
        if type(note_id) is not int or not 1 <= note_id <= 9223372036854775807:
            raise ValueError("Note ID must be a positive SQLite integer")
        with self._write() as connection:
            deleted = connection.execute("DELETE FROM memory_notes WHERE id=?", (note_id,)).rowcount
        return deleted == 1
