"""Real Windows DPAPI and FastAPI lifespan; no native HTTP or user data."""
from contextlib import nullcontext
import json
import os
from pathlib import Path
import sqlite3
from uuid import UUID, uuid4

import pytest

from app.memory_crypto import protect_for_current_user, unprotect_for_current_user
from app.memory_http_v2 import create_memory_test_binding
from app.memory_keys_v2 import ReceiptKeyUnavailable, issue_receipt_key, open_receipt_key
from app.memory_ledger import MemoryLedger
from app.memory_security import MemoryAccessGuard, SecurityDenied
from app.memory_snapshot_v2 import stage_snapshot


pytestmark = pytest.mark.skipif(os.name != "nt", reason="CurrentUser DPAPI and Windows runtime lock")
HOST = [("host", "127.0.0.1:8000"), ("origin", "http://127.0.0.1:8000"),
        ("content-type", "application/json")]


def immediate(awaitable):
    iterator = awaitable.__await__()
    try:
        next(iterator)
    except StopIteration as done:
        return done.value
    finally:
        iterator.close()
    raise AssertionError("Unexpected asynchronous suspension")


def call(app, method, path, payload=None, auth=(), *, headers=HOST):
    events = []

    async def receive():
        return {"type": "http.request", "body": b"" if payload is None else json.dumps(payload).encode()}

    async def send(event):
        events.append(event)

    scope = {"type": "http", "http_version": "1.1", "scheme": "http", "method": method,
             "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
             "headers": [(k.encode(), v.encode()) for k, v in [*headers, *auth]]}
    immediate(app(scope, receive, send))
    return events[0]["status"], json.loads(events[-1]["body"])


def pair(app, guard):
    status, data = call(app, "POST", "/api/memory/pair",
                        {"secret": guard.issue_pairing_challenge().secret})
    assert status == 200
    return [("authorization", "Bearer " + data["bearer"]), ("x-ai1-memory-csrf", data["csrf"])]


class NoModel:
    async def generate(self, messages):
        pytest.fail("Memory must never call the provider")


@pytest.fixture
def scratch():
    # Establish the synthetic environment before any import of app.main.
    root = Path(os.environ["AI1_TEST_ROOT"]).resolve(strict=True)
    assert os.environ.get("PYTHON_DOTENV_DISABLED") == "1"
    assert Path(os.environ["AI1_DATABASE_PATH"]).parent.resolve(strict=True) == root
    assert os.environ.get("AI1_MODE") == "LOCAL_ONLY" and os.environ.get("AI1_API_KEY") == ""
    return root


def test_capsules_fail_closed_on_bad_key_wrong_generation_or_other_profile(monkeypatch):
    from app import memory_keys_v2
    generation = uuid4()
    capsule = issue_receipt_key(generation)
    key = open_receipt_key(generation, capsule.sealed, approved_fingerprint=capsule.fingerprint)
    assert len(key) == 32 and key not in capsule.sealed
    other = issue_receipt_key(generation)
    for gen, sealed, pin in ((generation, other.sealed, capsule.fingerprint),
                             (generation, b"", capsule.fingerprint),
                             (uuid4(), capsule.sealed, capsule.fingerprint)):
        with pytest.raises(ReceiptKeyUnavailable):
            open_receipt_key(gen, sealed, approved_fingerprint=pin)

    def inaccessible(blob):
        raise OSError("synthetic unavailable Windows profile")

    monkeypatch.setattr(memory_keys_v2, "unprotect_for_current_user", inaccessible)
    with pytest.raises(ReceiptKeyUnavailable, match="^receipt_key_unavailable$"):
        open_receipt_key(generation, capsule.sealed, approved_fingerprint=capsule.fingerprint)


def test_real_factory_default_off_rejects_memory_even_in_local_workspace(scratch):
    from app.main import create_app
    workspace_path = scratch / (uuid4().hex + ".sqlite3")
    app = create_app(workspace_path=str(workspace_path), provider=NoModel())
    context = app.router.lifespan_context(app)
    immediate(context.__aenter__())
    try:
        assert call(app, "GET", "/api/memory/notes")[0] == 404
        assert call(app, "POST", "/api/memory/pair", {"secret": "synthetic"})[0] == 404
    finally:
        immediate(context.__aexit__(None, None, None))
    assert app.state.runtime.process_lock._handle is None


def test_factory_restart_preserves_sealed_notes_and_receipt_without_old_session(monkeypatch, scratch):
    from app import memory_http_v2
    from app.main import create_app

    monkeypatch.setattr(memory_http_v2, "timeout", lambda _: nullcontext())
    notes, workspace, capsule_path = (scratch / (uuid4().hex + suffix)
                                       for suffix in (".sqlite3", ".sqlite3", ".capsule"))
    generation = uuid4()
    capsule = issue_receipt_key(generation)
    with capsule_path.open("xb") as stream:
        stream.write(capsule.sealed)

    def connect():
        return sqlite3.connect(notes, timeout=.2)

    conn = connect()
    try:
        MemoryLedger(conn, enabled=True, receipt_budget=30).initialize_empty(generation)
    finally:
        conn.close()

    draft = {"operation": str(uuid4()), "generation": str(generation), "kind": "create",
             "consent": True, "text": "Синтетический маркер 🧭"}
    old_auth = []
    for restart in (False, True):
        guard = MemoryAccessGuard(enabled=True)
        binding = create_memory_test_binding(
            guard=guard, connect=connect, receipt_budget=30, seal=protect_for_current_user,
            unseal=unprotect_for_current_user, bind_key=open_receipt_key(
                generation, capsule_path.read_bytes(), approved_fingerprint=capsule.fingerprint),
        )
        with pytest.raises(ValueError):
            create_app(provider=NoModel(), memory_test_binding=binding)
        app = create_app(workspace_path=str(workspace), provider=NoModel(), memory_test_binding=binding)
        assert call(app, "GET", "/api/memory/notes")[0] == 503  # runtime not active
        context = app.router.lifespan_context(app)
        immediate(context.__aenter__())
        try:
            if restart:
                assert call(app, "GET", "/api/memory/notes", auth=old_auth)[0] == 401
            assert call(app, "GET", "/api/memory/notes",
                        headers=[("host", "foreign.invalid")])[0] == 400
            auth = pair(app, guard)
            status, receipt = call(app, "POST", "/api/memory/notes", draft, auth)
            assert status == 200 and receipt["replayed"] is restart
            status, page = call(app, "GET", "/api/memory/notes", auth=auth)
            assert status == 200 and [n["text"] for n in page["notes"]] == [draft["text"]]
            assert draft["text"].encode() not in notes.read_bytes()
            if restart:
                src, dst = connect(), sqlite3.connect(":memory:")
                try:
                    new_gen = uuid4()
                    snapshot = stage_snapshot(src, dst, restore_generation=new_gen,
                                              verify=lambda data: unprotect_for_current_user(data) == draft["text"].encode())
                    assert snapshot.generation == new_gen and snapshot.notes == 1
                    assert MemoryLedger(src, enabled=True, receipt_budget=30).check_integrity() == generation
                    assert MemoryLedger(dst, enabled=True, receipt_budget=30).snapshot(
                        UUID(draft["operation"])).receipt is None
                finally:
                    src.close()
                    dst.close()
            old_auth = auth
        finally:
            immediate(context.__aexit__(None, None, None))
        assert app.state.runtime.process_lock._handle is None
        with pytest.raises(SecurityDenied):
            guard.authorize("GET", old_auth)
