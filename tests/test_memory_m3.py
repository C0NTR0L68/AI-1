"""Synthetic M3 checks. No live routes, storage factory, or provider."""
import os
from pathlib import Path
import sqlite3
from threading import Event, Thread
from uuid import uuid4

import pytest

from app.memory_ledger import MemoryLedger
from app.memory_reconciliation import OperationIdentity
from app.memory_security import MemoryAccessGuard, SecurityDenied


@pytest.fixture
def setup():
    now = [1000]
    guard = MemoryAccessGuard(enabled=True, clock=lambda: now[0])
    headers = [("Host", guard.HOST), ("Origin", guard.ORIGIN), ("Content-Type", "application/json")]
    pair = guard.pair("POST", headers, guard.issue_pairing_challenge().secret)
    auth = headers + [("Authorization", "Bearer " + pair.bearer_token),
                      ("X-AI1-Memory-CSRF", pair.csrf_token)]
    return now, guard, auth


def storage():
    return Path(os.environ["AI1_TEST_ROOT"]) / (uuid4().hex + ".sqlite3")


@pytest.fixture
def ledger():
    conn = sqlite3.connect(storage(), timeout=0.1)
    generation = uuid4()
    store = MemoryLedger(conn, enabled=True, receipt_budget=8)
    store.initialize_empty(generation)
    try:
        yield conn, store, OperationIdentity(uuid4(), generation, b"synthetic-binding")
    finally:
        conn.close()


def write(guard, auth, store, op):
    return store.mutate_authorized(guard, "POST", auth, op, "create", sealed=b"opaque-synthetic")


def test_unauthorized_request_never_accesses_storage(ledger, setup):
    conn, store, op = ledger
    _, guard, auth = setup
    statements = []
    conn.set_trace_callback(statements.append)
    with pytest.raises(SecurityDenied, match="csrf"):
        write(guard, auth[:-1], store, op)
    guard.logout(auth)
    with pytest.raises(SecurityDenied, match="unauthorized"):
        write(guard, auth, store, op)
    assert statements == []


@pytest.mark.parametrize("invalidate", ["logout", "disable", "idle"])
def test_revocation_before_commit_rolls_back_note_and_receipt(ledger, setup, invalidate):
    conn, store, op = ledger
    now, guard, auth = setup
    seen = []
    def after_admission(sql):
        if sql.startswith("INSERT INTO main.memory_receipts"):
            seen.append(True)
            if invalidate == "logout":
                guard.logout(auth)
            elif invalidate == "disable":
                guard.disable()
            else:
                now[0] += guard.IDLE_TTL
    conn.set_trace_callback(after_admission)
    with pytest.raises(SecurityDenied):
        write(guard, auth, store, op)
    assert seen == [True]
    assert store.read(op.store_generation) == ()
    assert store.snapshot(op.operation_id).receipt is None


def test_commit_orders_before_concurrent_logout(ledger, setup):
    conn, store, op = ledger
    _, guard, auth = setup
    entered, logged_out, commit_entered, joining = Event(), Event(), Event(), Event()
    failures, observations = [], []
    def logout():
        try:
            if not entered.wait(3):
                raise AssertionError("COMMIT not reached")
            joining.set()
            guard.logout(auth)
            logged_out.set()
        except BaseException as error:
            failures.append(error)
    def inside_commit(sql):
        if sql == "COMMIT" and not commit_entered.is_set():
            commit_entered.set()
            entered.set()
            observations.append(joining.wait(2))
            observations.append(not logged_out.is_set())
    th = Thread(target=logout, daemon=True)
    th.start()
    conn.set_trace_callback(inside_commit)
    try:
        receipt = write(guard, auth, store, op)
    finally:
        entered.set()
        th.join(4)
        conn.set_trace_callback(None)
    assert observations == [True, True]
    assert not th.is_alive() and not failures and logged_out.is_set()
    assert not receipt.replayed and store.snapshot(op.operation_id).receipt is not None
    with pytest.raises(SecurityDenied):
        write(guard, auth, store, op)


def test_commit_ack_loss_exposes_error_but_receipt_is_durable(setup):
    class Fault(sqlite3.Connection):
        fail = False

        def commit(self):
            super().commit()
            if self.fail:
                self.fail = False
                raise sqlite3.OperationalError("synthetic lost acknowledgement")

    _, guard, auth = setup
    path = storage()
    conn = sqlite3.connect(path, factory=Fault, timeout=0.1)
    generation = uuid4()
    store = MemoryLedger(conn, enabled=True, receipt_budget=8)
    op = OperationIdentity(uuid4(), generation, b"synthetic-binding")
    try:
        store.initialize_empty(generation)
        conn.fail = True
        with pytest.raises(sqlite3.OperationalError, match="lost acknowledgement"):
            write(guard, auth, store, op)
    finally:
        conn.close()
    read = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        reopened = MemoryLedger(read, enabled=True, receipt_budget=8)
        assert len(reopened.read(generation)) == 1
        assert reopened.snapshot(op.operation_id).receipt.identity == op
    finally:
        read.close()


def test_waiting_for_sqlite_does_not_hold_the_guard_lock(setup):
    _, guard, auth = setup
    begin, revoked = Event(), Event()
    failure = []

    class PausedBegin(sqlite3.Connection):
        pause = False

        def execute(self, sql, *args):
            if self.pause and sql == "BEGIN IMMEDIATE":
                begin.set()
                if not revoked.wait(3):
                    raise AssertionError("guard lock held while acquiring SQLite")
            return super().execute(sql, *args)

    def logout():
        try:
            if not begin.wait(3):
                raise AssertionError("BEGIN not reached")
            guard.logout(auth)
            revoked.set()
        except BaseException as error:
            failure.append(error)

    conn = sqlite3.connect(storage(), factory=PausedBegin, timeout=0.1)
    store = MemoryLedger(conn, enabled=True, receipt_budget=8)
    generation = uuid4()
    store.initialize_empty(generation)
    op = OperationIdentity(uuid4(), generation, b"synthetic-binding")
    thread = Thread(target=logout, daemon=True)
    thread.start()
    try:
        conn.pause = True
        with pytest.raises(SecurityDenied, match="unauthorized"):
            write(guard, auth, store, op)
        assert store.read(generation) == ()
        assert store.snapshot(op.operation_id).receipt is None
    finally:
        conn.close()
        begin.set()
        thread.join(4)
    assert not thread.is_alive() and revoked.is_set() and not failure
