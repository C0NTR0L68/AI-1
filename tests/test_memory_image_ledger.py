"""Windows synthetic qualification; the authoritative head is a fixture, not C7."""
from contextlib import closing, contextmanager
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
from threading import Barrier, Lock
from uuid import uuid4

import pytest

from app import memory_image_ledger
from app.memory_archive_publish_v2 import publish_archive, read_published_archive
from app.memory_archive_v2 import ArchiveUnavailable, build_archive
from app.memory_crypto import unprotect_for_current_user
from app.memory_image_ledger import ImageCommitUnconfirmed, MemoryImageLedger
from app.memory_keys_v2 import issue_receipt_key
from app.memory_ledger import MemoryLedger, MemoryLedgerConflict
from app.memory_security import MemoryAccessGuard, SecurityDenied
from app.windows_storage_inspector import hold_archive_directory, inspect_component, read_pinned_artifact

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows DPAPI and archive handles")


@pytest.fixture
def test_store(monkeypatch):
    root = Path(os.environ["AI1_TEST_ROOT"]) / uuid4().hex
    root.mkdir()
    directory = inspect_component(str(root), expected_kind="directory")
    generation = uuid4()
    capsule = issue_receipt_key(generation)
    connect = sqlite3.connect
    inputs = []

    def only_memory(path, *args, **kwargs):
        inputs.append(path)
        assert path == ":memory:", "SQLite must not open a filesystem name"
        conn = connect(path, *args, **kwargs)
        assert conn.execute("PRAGMA database_list").fetchall() == [(0, "main", "")]
        return conn

    monkeypatch.setattr(sqlite3, "connect", only_memory)

    @contextmanager
    def hold(path):
        assert path == root
        with hold_archive_directory(str(path), require_private_acl=False) as held:
            assert held.identity == directory.identity
            yield

    def bound(path, limit):
        assert path.parent == root
        evidence = inspect_component(str(path), expected_kind="file")
        return read_pinned_artifact(str(path), expected=evidence, max_bytes=limit, require_private_acl=False)

    class Backend:
        value = None
        published = 0
        fail = None
        compare_lock = Lock()

        def head(self):
            return self.value

        def read(self, fingerprint):
            if self.fail == "readback" and fingerprint != self.value:
                return b"wrong archived bytes"
            return read_published_archive(root, fingerprint=fingerprint, hold_directory=hold, read_bound=bound)

        def publish(self, artifact):
            publish_archive(artifact, root, hold_directory=hold, read_bound=bound)
            self.published += 1
            if self.fail == "publish_ack":
                raise OSError("synthetic acknowledgement loss")

        def advance(self, expected, new):
            with self.compare_lock:
                if self.value != expected or self.fail == "conflict":
                    return False
                self.value = new
                if self.fail == "advance_ack":
                    raise OSError("synthetic acknowledgement loss")
                return True

    backend = Backend()
    with closing(sqlite3.connect(":memory:")) as conn:
        MemoryLedger(conn, enabled=True, receipt_budget=32).initialize_empty(generation)
        initial = build_archive(conn, capsule=capsule, approved_key_pin=capsule.fingerprint)
    backend.publish(initial)
    backend.value = initial.fingerprint
    yield root, backend, generation
    assert inputs and all(v == ":memory:" for v in inputs)
    assert not list(root.glob("*.sqlite3*"))


def session():
    guard = MemoryAccessGuard(enabled=True)
    headers = [("Host", guard.HOST), ("Origin", guard.ORIGIN), ("Content-Type", "application/json")]
    pair = guard.pair("POST", headers, guard.issue_pairing_challenge().secret)
    return guard, headers + [("Authorization", "Bearer " + pair.bearer_token),
                             ("X-AI1-Memory-CSRF", pair.csrf_token)]


def make(ledger, guard, headers, generation, rid, text="Синтетика 🧭"):
    return ledger.mutate_authorized(guard, "POST", headers, generation=generation,
                                    operation_id=rid, kind="create", consent=True, text=text)


def test_reopens_same_key_and_deduplicates_without_any_sqlite_file(test_store):
    root, backend, generation = test_store
    first = MemoryImageLedger(backend, receipt_budget=32)
    guard, headers = session()
    rid = uuid4()
    receipt = make(first, guard, headers, generation, rid)
    assert not receipt.replayed and backend.published == 2
    reopened = MemoryImageLedger(backend, receipt_budget=32)
    new_guard, new_headers = session()
    assert make(reopened, new_guard, new_headers, generation, rid).replayed
    with pytest.raises(MemoryLedgerConflict):
        make(reopened, new_guard, new_headers, generation, rid, "Changed")
    assert backend.published == 2 and len(list(root.glob("*.v2a"))) == 2
    note, = reopened.read(generation)
    assert unprotect_for_current_user(note.sealed).decode() == "Синтетика 🧭"
    deleted = reopened.mutate_authorized(new_guard, "DELETE", new_headers, generation=generation,
                                          operation_id=uuid4(), kind="delete", consent=True,
                                          note_id=note.id, revision=note.revision)
    assert deleted.note_id == note.id and reopened.read(generation) == ()


@pytest.mark.parametrize("failure,committed", [
    ("publish_ack", False), ("conflict", False), ("readback", False), ("advance_ack", True),
])
def test_only_authoritative_head_defines_a_committed_receipt(test_store, failure, committed):
    _, backend, generation = test_store
    original = backend.head()
    ledger = MemoryImageLedger(backend, receipt_budget=32)
    guard, headers = session()
    rid = uuid4()
    backend.fail = failure
    with pytest.raises(ImageCommitUnconfirmed):
        make(ledger, guard, headers, generation, rid)
    reopened = MemoryImageLedger(backend, receipt_budget=32)
    assert (backend.head() != original) is committed
    assert (reopened.snapshot(rid).receipt is not None) is committed
    assert len(reopened.read(generation)) == int(committed)


def test_logout_before_durable_effect_never_publishes_mutation(test_store, monkeypatch):
    _, backend, generation = test_store
    ledger = MemoryImageLedger(backend, receipt_budget=32)
    guard, headers = session()
    original = backend.head()
    def revoke(*args, **kwargs):
        result = build_archive(*args, **kwargs)
        guard.logout(headers)
        return result
    monkeypatch.setattr(memory_image_ledger, "build_archive", revoke)
    rid = uuid4()
    with pytest.raises(SecurityDenied):
        make(ledger, guard, headers, generation, rid)
    assert backend.published == 1 and backend.head() == original
    assert ledger.snapshot(rid).receipt is None


def test_authenticated_archive_is_not_interchangeable_with_authoritative_digest(test_store, monkeypatch):
    _, backend, generation = test_store
    initial = backend.read(backend.head())
    guard, headers = session()
    ledger = MemoryImageLedger(backend, receipt_budget=32)
    make(ledger, guard, headers, generation, uuid4())
    monkeypatch.setattr(backend, "read", lambda _: initial)
    with pytest.raises(ArchiveUnavailable):
        ledger.read(generation)


def test_two_writers_cannot_replace_each_others_head(test_store, monkeypatch):
    _, backend, generation = test_store
    ledger = MemoryImageLedger(backend, receipt_budget=32)
    original_publish = backend.publish
    both_published = Barrier(2, timeout=8)

    def contested(archive):
        original_publish(archive)
        both_published.wait()

    monkeypatch.setattr(backend, "publish", contested)
    operations = [uuid4(), uuid4()]

    def write(rid):
        guard, headers = session()
        try:
            make(ledger, guard, headers, generation, rid)
        except ImageCommitUnconfirmed:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(write, operations))
    assert outcomes.count(True) == 1
    assert len(ledger.read(generation)) == 1
    assert [(ledger.snapshot(rid).receipt is not None) for rid in operations] == outcomes
