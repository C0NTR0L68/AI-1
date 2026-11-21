"""Read-only admission for reviewed READY pre-epoch schemas; never a migration."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import errno
import stat
import time

from app.db import ChatStore, _tokenize_sql
from app.runtime_lock import canonical_database_path

class SchemaRefused(RuntimeError):
    """No initializer may run after this refusal."""

# Exact known READY table shape from current source, not an arbitrary SQL parser.
READY_DDL = "CREATE TABLE messages (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    role TEXT NOT NULL CHECK(role IN ('user','assistant')),\n                    content TEXT NOT NULL,\n                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,\n                    status TEXT NOT NULL DEFAULT 'complete'\n                        CHECK(status IN ('pending','failed','complete')),\n                    request_id TEXT,\n                    provider_id TEXT,\n                    model_name TEXT,\n                    requested_model TEXT,\n                    provider_model TEXT,\n                    lifecycle_status TEXT\n                )"
INDEXES = {
    "idx_messages_user_request_id": "CREATE UNIQUE INDEX idx_messages_user_request_id ON messages(request_id) WHERE role = 'user' AND request_id IS NOT NULL",
    "idx_messages_assistant_request_id": "CREATE UNIQUE INDEX idx_messages_assistant_request_id ON messages(request_id) WHERE role = 'assistant' AND request_id IS NOT NULL",
}

def _tokens(sql):
    values=_tokenize_sql(sql.rstrip().rstrip(";"))
    if any(k=="IDENT" and not v.isascii() for k,v in values):
        raise SchemaRefused("Unreviewed schema identifier")
    result=[(k,v.lower() if k=="IDENT" else v) for k,v in values]
    # CREATE [UNIQUE INDEX] IF NOT EXISTS spelling is equivalent.
    optional=[("IDENT","if"),("IDENT","not"),("IDENT","exists")]
    return tuple(t for i,t in enumerate(result)
                 if not any(result[j:j+3]==optional and j<=i<j+3 for j in range(max(0,i-2),i+1)))


def _sidecars(path):
    # Accepted B2 lstat rule: only unambiguous absence permits SQLite access.
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            Path(str(path)+suffix).lstat()
        except FileNotFoundError as error:
            if error.errno != errno.ENOENT or getattr(error,"winerror",None) not in (None,2):
                raise SchemaRefused("Sidecar state unverified") from None
            try:
                parent=path.parent.lstat()
            except (OSError,ValueError):
                raise SchemaRefused("Sidecar state unverified") from None
            if not stat.S_ISDIR(parent.st_mode) or getattr(parent,"st_file_attributes",0)&0x400:
                raise SchemaRefused("Sidecar parent unverified")
        except (OSError,ValueError):
            raise SchemaRefused("Sidecar state unverified") from None
        else:
            raise SchemaRefused("Sidecars or database activity require review")

@dataclass(frozen=True)
class SchemaAdmission:
    path: Path
    user_version: int
    fingerprint: str
    message_count: int

def preflight_history(database_path):
    raw=Path(database_path)
    if not raw.is_absolute():
        raise SchemaRefused("Absolute database path required")
    # Refuse aliases before canonicalization hides the spelling.
    for item in (raw,*raw.parents):
        if item.is_symlink() or (hasattr(item,"is_junction") and item.is_junction()):
            raise SchemaRefused("Linked database path requires review")
    path=canonical_database_path(raw)
    if not path.is_file() or path.stat().st_nlink!=1:
        raise SchemaRefused("Existing single-link database required; no auto-create")
    _sidecars(path)
    if path.stat().st_size > 16 * 1024 * 1024:
        raise SchemaRefused("Read budget size requires review")
    with path.open("rb") as stream:header=stream.read(100)
    if len(header)!=100 or header[:16]!=b"SQLite format 3\x00":
        raise SchemaRefused("Not a reviewed SQLite file")
    if header[18:20]!=bytes((1,1)):
        raise SchemaRefused("WAL/unknown journal format requires review")
    conn=None
    deadline=time.monotonic()+3
    primary=None
    try:
        conn=sqlite3.connect(path.as_uri()+"?mode=ro",uri=True,timeout=0,isolation_level=None)
        conn.row_factory=sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.set_progress_handler(lambda: int(time.monotonic()>deadline),1000)
        if conn.execute("PRAGMA query_only").fetchone()[0]!=1:
            raise SchemaRefused("Read-only guard unavailable")
        if conn.execute("PRAGMA trusted_schema").fetchone()[0]!=0 or conn.execute("PRAGMA temp_store").fetchone()[0]!=2:
            raise SchemaRefused("Additional read guards unavailable")
        conn.execute("BEGIN")
        if conn.execute("PRAGMA user_version").fetchone()[0]!=0:
            raise SchemaRefused("Unsupported schema version; no downgrade or migration")
        if conn.execute("PRAGMA application_id").fetchone()[0]!=0:
            raise SchemaRefused("Foreign application identity")
        objects=[tuple(r) for r in conn.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")]
        ddl=next((r[3] for r in objects if r[:2]==("table","messages")),None)
        if not ddl:raise SchemaRefused("messages is not a reviewed ordinary table")
        profiles=(READY_DDL,READY_DDL.replace("'pending','failed','complete'",
                     "'pending','dispatching','unknown','failed','complete'"))
        if _tokens(ddl) not in tuple(_tokens(s) for s in profiles):
            raise SchemaRefused("Unreviewed table definition; no implicit upgrade")
        expected={("table","messages"),("table","sqlite_sequence"),*(("index",name) for name in INDEXES)}
        actual={(r[0],r[1]) for r in objects}
        if actual!=expected:
            raise SchemaRefused("Unknown or missing schema objects")
        for name,sql in INDEXES.items():
            actual_sql=next(r[3] for r in objects if r[:2]==("index",name))
            if actual_sql is None or _tokens(actual_sql)!=_tokens(sql):
                raise SchemaRefused("Unreviewed request identity index")
        # Existing reviewed validator is read-only; no ChatStore instance is made.
        ChatStore._preflight_messages(conn)
        for role,status in conn.execute("SELECT DISTINCT role,status FROM messages"):
            if role not in ("user","assistant") or status not in ("complete","pending","failed","dispatching","unknown"):
                raise SchemaRefused("Unrecognized message state")
        if [tuple(r) for r in conn.execute("PRAGMA integrity_check")]!=[("ok",)]:
            raise SchemaRefused("Integrity check failed")
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise SchemaRefused("Foreign key check failed")
        fingerprint=hashlib.sha256(json.dumps(objects,ensure_ascii=True).encode()).hexdigest()
        count=conn.execute("SELECT count(*) FROM messages").fetchone()[0]
        _sidecars(path)
        if time.monotonic()>deadline:
            raise SchemaRefused("Read budget exceeded")
        return SchemaAdmission(path,0,fingerprint,count)
    except SchemaRefused as error:
        primary=error
        raise
    except (sqlite3.Error,ValueError,TypeError) as error:
        primary=SchemaRefused("SQLite schema admission failed")
        raise primary from error
    except BaseException as error:
        primary=error
        raise
    finally:
        errors=[]
        if conn is not None:
            try:
                if conn.in_transaction:conn.rollback()
            except BaseException as error:errors.append(error)
            try:conn.close()
            except BaseException as error:errors.append(error)
        if errors:
            if primary is None:
                raise SchemaRefused("Read-only cleanup failed; admission refused") from errors[0]
            for error in errors:
                primary.add_note("Read-only cleanup failed: "+type(error).__name__)
