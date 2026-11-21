"""Opt-in ASGI integration, on a disposable file and an explicit fake codec."""
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest

from app.memory_ledger import MemoryLedger
from app.memory_security import MemoryAccessGuard


def run_now(awaitable):
    try:
        awaitable.send(None)
    except StopIteration as done:
        return done.value
    finally:
        awaitable.close()
    raise AssertionError("Expected an immediate synthetic HTTP exchange")


@pytest.fixture
def circuit(monkeypatch):
    from app import memory_http_v2 as module
    from contextlib import nullcontext
    monkeypatch.setattr(module, "timeout", lambda value: nullcontext())
    path = Path(os.environ["AI1_TEST_ROOT"]) / (uuid4().hex + ".sqlite3")
    generation = uuid4()
    opened = []
    state = {"before_commit": None, "commit_ack_lost": False, "begin_ack_lost": False}

    class FaultConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            result = super().execute(sql, *args)
            if sql == "BEGIN IMMEDIATE" and state["begin_ack_lost"]:
                state["begin_ack_lost"] = False
                raise sqlite3.OperationalError("synthetic lost begin acknowledgement")
            return result

        def close(self):
            state["in_transaction_at_close"] = self.in_transaction
            super().close()

        def commit(self):
            super().commit()
            if state["commit_ack_lost"]:
                state["commit_ack_lost"] = False
                raise sqlite3.OperationalError("synthetic lost commit acknowledgement")

    def connection():
        opened.append(True)
        conn = sqlite3.connect(path, timeout=0.1, factory=FaultConnection)
        def on_sql(sql):
            if sql.startswith("INSERT INTO main.memory_receipts") and state["before_commit"]:
                state["before_commit"]()
        conn.set_trace_callback(on_sql)
        return conn

    conn = connection()
    try:
        MemoryLedger(conn, enabled=True, receipt_budget=32).initialize_empty(generation)
    finally:
        conn.close()
    opened.clear()
    guard = MemoryAccessGuard(enabled=True)
    args = dict(enabled=True, guard=guard, connect=connection, seal=lambda value: b"S" + value,
                unseal=lambda value: value[1:], bind_key=b"k" * 32, receipt_budget=160)
    app = module.create_memory_test_app(**args)
    origin = [("host", guard.HOST), ("origin", guard.ORIGIN), ("content-type", "application/json")]

    def request(method, route, body=None, headers=None, *, raw=None, root=""):
        sent = []
        async def receive():
            data = json.dumps(body).encode() if body is not None else b""
            return {"type": "http.request", "body": data if raw is None else raw}
        async def send(event):
            sent.append(event)
        scope = {"type": "http", "http_version": "1.1", "scheme": "http", "path": route,
                 "raw_path": route.encode(), "root_path": root, "query_string": b"",
                 "method": method, "headers": [(k.encode(), v.encode()) for k, v in
                                                (origin if headers is None else headers)]}
        run_now(app(scope, receive, send))
        assert (b"cache-control", b"no-store") in sent[0]["headers"]
        return sent[0]["status"], json.loads(sent[-1]["body"])

    def pair():
        status, tokens = request("POST", "/api/memory/pair", {"secret": guard.issue_pairing_challenge().secret})
        assert status == 200
        return origin + [("authorization", "Bearer " + tokens["bearer"]),
                         ("x-ai1-memory-csrf", tokens["csrf"])]

    def body(**kwargs):
        return dict(generation=str(generation), operation=str(uuid4()), kind="create", text="Ёж 🧭",
                    consent=True) | kwargs

    return request, pair, body, opened, state, guard, args


def test_default_off_and_no_legacy_chat_route():
    from app.memory_http_v2 import create_memory_test_app
    app = create_memory_test_app()
    sent = []
    async def receive():
        pytest.fail("disabled app read the body")
    async def send(event):
        sent.append(event)
    run_now(app({"type": "http", "path": "/api/memory/notes", "method": "GET"}, receive, send))
    assert sent[0]["status"] == 404


def test_denials_happen_before_opening_storage(circuit):
    call, pair, body, opened, *_ = circuit
    auth = pair()
    assert call("GET", "/api/memory/notes")[0] == 401
    assert call("POST", "/api/memory/notes", body(), auth[:-1])[0] == 403
    assert call("POST", "/api/memory/notes", body(consent=False), auth)[0] == 422
    assert call("POST", "/api/memory/notes", headers=auth, raw=b'{"kind":"create","kind":"delete"}')[0] == 422
    assert call("POST", "/api/memory/notes", headers=auth, raw=b'{"x":[[[[[]]]]]}')[0] == 422
    assert call("GET", "/api/memory/notes", headers=auth + [("host", "other.invalid")])[0] >= 400
    assert call("GET", "/api/memory/notes", headers=auth, root="/mounted")[0] >= 400
    assert call("POST", "/api/memory/pair/", {"secret": "invalid"})[0] == 404
    assert not opened


def test_mutations_and_replay_use_generation_and_revision(circuit):
    call, pair, body, *_ = circuit
    auth = pair()
    route = "/api/memory/notes"
    create = body()
    status, receipt = call("POST", route, create, auth)
    assert status == 200 and not receipt["replayed"]
    assert call("POST", route, create, auth)[1]["replayed"]
    assert call("POST", route, create | {"text": "different"}, auth)[0] == 409
    assert call("GET", route, headers=auth)[1]["notes"][0]["text"] == "Ёж 🧭"
    note = receipt["id"]
    assert call("POST", route, body(kind="update", id=note, revision=1, text="new"), auth)[1]["revision"] == 2
    delete = body(kind="delete", id=note, revision=2)
    del delete["text"]
    assert call("DELETE", route, delete, auth)[0] == 200
    assert call("GET", route, headers=auth)[1]["notes"] == []


def test_logout_before_commit_rolls_back_and_lost_ack_can_be_read(circuit):
    call, pair, body, _, state, guard, _ = circuit
    auth = pair()
    route = "/api/memory/notes"
    state["before_commit"] = lambda: guard.logout(auth)
    aborted = body()
    assert call("POST", route, aborted, auth)[0] == 401
    state["before_commit"] = None
    other = pair()
    assert call("GET", route, headers=auth)[0] == 401
    assert call("GET", route, headers=other)[1]["notes"] == []
    assert call("GET", "/api/memory/operations/" + aborted["operation"], headers=other)[1]["state"] == "unknown"
    ambiguous = body()
    state["commit_ack_lost"] = True
    assert call("POST", route, ambiguous, other) == (503, {"error": "operation_not_confirmed"})
    status_route = "/api/memory/operations/" + ambiguous["operation"]
    receipt = call("GET", status_route, headers=other)[1]
    assert receipt["state"] == "recorded"
    assert call("POST", status_route, ambiguous, other)[1]["state"] == "complete"
    assert call("POST", status_route, ambiguous | {"text": "different"}, other)[1]["state"] == "conflict"
    changed = call("POST", status_route, ambiguous | {"generation": str(uuid4())}, other)[1]
    assert changed == {"state": "unknown", "reason": "store_changed", "retry_allowed": False}
    assert len(call("GET", route, headers=other)[1]["notes"]) == 1


def test_begin_failure_rolls_back_before_close(circuit):
    call, pair, body, _, state, *_ = circuit
    auth = pair()
    state["begin_ack_lost"] = True
    assert call("POST", "/api/memory/notes", body(), auth)[0] == 503
    assert state["in_transaction_at_close"] is False
    assert call("GET", "/api/memory/notes", headers=auth)[1]["notes"] == []


def test_page_cursor_is_bounded_and_generation_checked(circuit):
    call, pair, body, *_ = circuit
    auth = pair()
    route = "/api/memory/notes"
    for index in range(51):
        assert call("POST", route, body(text=f"synthetic {index}"), auth)[0] == 200
    status, first = call("GET", route, headers=auth)
    assert status == 200 and len(first["notes"]) == 50
    assert first["next_after"] == first["notes"][-1]["id"]
    status, second = call("GET", f'{route}/{first["generation"]}/{first["next_after"]}', headers=auth)
    assert status == 200 and [n["text"] for n in second["notes"]] == ["synthetic 50"]
    assert second["next_after"] is None
    assert call("GET", f"{route}/{uuid4()}/50", headers=auth)[0] == 409
