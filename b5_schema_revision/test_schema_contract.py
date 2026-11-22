"""Additional review cases for the two preserved frozen controls."""
from contextlib import closing
import sqlite3
from uuid import uuid4

import httpx
import pytest

from app.db import ChatStore
from app.history_preflight import SchemaRefused, preflight_history
from app.history_migration import LegacyExportRefused, export_legacy_history
from app.main import create_app


LEGACY_DDL = """CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'complete',
    request_id TEXT,
    provider_id TEXT,
    model_name TEXT
)"""
TRIGGER = (
    "TRIGGER reject_lifecycle_assistant BEFORE INSERT ON main.messages "
    "WHEN NEW.role = 'assistant' BEGIN SELECT RAISE(ABORT, 'forced failure'); END"
)
BASE = "http://127.0.0.1:8000"


class Provider:
    def __init__(self):
        self.calls = []

    async def reply(self, messages):
        self.calls.append(messages)
        return "synthetic reply"


def app_for(path):
    store = ChatStore(str(path))
    provider = Provider()
    assets = {name: b"synthetic" for name in ("index.html", "app.js", "style.css")}
    return store, provider, create_app(store=store, provider=provider, assets=assets)


def inline(coro):
    # HTTPX ASGI transport and this immediate provider perform no scheduling.
    # Fail explicitly if a code change requires a real event loop.
    try:
        coro.send(None)
    except StopIteration as stop:
        return stop.value
    finally:
        coro.close()
    pytest.fail("Candidate ASGI verification attempted to suspend")


def client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                             headers={"Origin": BASE}, trust_env=False)


def legacy_database(path):
    request_id = str(uuid4())
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute(LEGACY_DDL)
        conn.executemany(
            "INSERT INTO messages(id,role,content,status,request_id,provider_id,model_name) VALUES (?,?,?,?,?,?,?)",
            [(3, "user", "старый вопрос", "complete", request_id, None, None),
             (6, "assistant", "старый ответ", "complete", request_id, "gemini", "gemini-legacy-alias")],
        )
        conn.execute("INSERT INTO messages(id,role,content) VALUES (90,'user','deleted synthetic row')")
        conn.execute("DELETE FROM messages WHERE id=90")
    return request_id


def export(source_path, destination_path):
    with (closing(sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)) as source,
          closing(sqlite3.connect(destination_path)) as destination):
        source.execute("PRAGMA query_only=ON")
        source.execute("PRAGMA trusted_schema=OFF")
        return export_legacy_history(source, destination)


def test_existing_trigger_is_refused_before_provider_and_without_writes(tmp_path):
    path = tmp_path / "history.sqlite3"
    _, provider, app = app_for(path)
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute("CREATE " + TRIGGER)
    before = path.read_bytes()

    async def startup():
        async with app.router.lifespan_context(app):
            pytest.fail("Unreviewed stored trigger admitted")

    with pytest.raises(SchemaRefused, match="Unknown or missing schema objects"):
        inline(startup())
    assert path.read_bytes() == before and provider.calls == []


def test_post_admission_sqlite_failure_rolls_back_turn_and_reports_unknown(tmp_path, monkeypatch):
    path = tmp_path / "history.sqlite3"
    store, provider, app = app_for(path)
    fingerprint = preflight_history(path).fingerprint
    actual_complete, actual_connect = store.complete_turn, store._connect
    injected = []

    def fault(*args, **kwargs):
        with closing(actual_connect()) as conn, monkeypatch.context() as scoped:
            conn.execute("CREATE TEMP " + TRIGGER)
            injected.append(True)
            scoped.setattr(store, "_connect", lambda: conn)
            return actual_complete(*args, **kwargs)

    monkeypatch.setattr(store, "complete_turn", fault)
    request_id = str(uuid4())

    async def scenario():
        async with app.router.lifespan_context(app), client(app) as http:
            response = await http.post("/api/chat", json={"message": "synthetic", "request_id": request_id})
            assert response.status_code == 500
            assert len(provider.calls) == len(injected) == 1
            assert [(row["role"], row["status"]) for row in store.history()] == [("user", "unknown")]
            status = await http.get(f"/api/requests/{request_id}")
            assert status.status_code == 200
            assert status.json()["status"] == "unknown" and status.json()["reply"] is None
            assert (await http.get("/api/history")).json()["messages"][-1]["status"] == "unknown"
        async with app.router.lifespan_context(app), client(app) as http:
            assert (await http.get(f"/api/requests/{request_id}")).json()["status"] == "unknown"

    inline(scenario())
    verified = preflight_history(path)
    assert (verified.fingerprint, verified.message_count) == (fingerprint, 1)


@pytest.mark.parametrize("store_initialized", [False, True])
def test_explicit_legacy_export_preserves_api_provenance_and_source(tmp_path, store_initialized):
    source, destination = tmp_path / "legacy.sqlite3", tmp_path / "ready.sqlite3"
    request_id = legacy_database(source)
    if store_initialized:
        ChatStore(str(source))
    before = source.read_bytes()

    with pytest.raises(SchemaRefused, match="Unreviewed table definition"):
        preflight_history(source)
    assert source.read_bytes() == before
    assert export(source, destination) == 2
    assert source.read_bytes() == before
    approved = preflight_history(destination)
    assert approved.message_count == 2

    async def read_api():
        _, provider, app = app_for(destination)
        async with app.router.lifespan_context(app), client(app) as http:
            history = (await http.get("/api/history")).json()["messages"]
            status = await http.get(f"/api/requests/{request_id}")
        assert status.status_code == 200 and provider.calls == []
        return history, status.json()

    history, status = inline(read_api())
    assistant = history[-1]
    assert [entry["id"] for entry in history] == [3, 6]
    assert assistant["status"] == "complete"
    assert status["reply"] == "старый ответ"
    for value in (assistant, status):
        assert value["model_name"] == "gemini-legacy-alias"
        assert value["requested_model"] is None and value["provider_model"] is None
    assert inline(read_api()) == (history, status)
    assert preflight_history(destination).fingerprint == approved.fingerprint
    assert source.read_bytes() == before
    assert ChatStore(str(destination)).add_message("user", "after conversion") == 91


@pytest.mark.parametrize("invalid", ["trigger", "duplicate", "unknown_status"])
def test_export_refuses_unreviewed_sources_and_rolls_back(tmp_path, invalid):
    source, destination = tmp_path / "legacy.sqlite3", tmp_path / "target.sqlite3"
    legacy_database(source)
    with closing(sqlite3.connect(source)) as conn, conn:
        if invalid == "trigger":
            conn.execute("CREATE " + TRIGGER)
        elif invalid == "duplicate":
            conn.execute("INSERT INTO messages(role,content,request_id) "
                         "SELECT role,content,request_id FROM messages WHERE id=3")
        else:
            conn.execute("UPDATE messages SET status='unreviewed' WHERE id=6")
    before = source.read_bytes()
    with pytest.raises(LegacyExportRefused):
        export(source, destination)
    with closing(sqlite3.connect(destination)) as conn:
        assert conn.execute("SELECT name FROM sqlite_schema").fetchall() == []
    assert source.read_bytes() == before


def test_export_does_not_modify_existing_target(tmp_path):
    source, destination = tmp_path / "legacy.sqlite3", tmp_path / "keep.sqlite3"
    legacy_database(source)
    ChatStore(str(destination)).add_message("user", "retain")
    before = destination.read_bytes()
    with pytest.raises(LegacyExportRefused, match="Fresh destination"):
        export(source, destination)
    assert destination.read_bytes() == before
