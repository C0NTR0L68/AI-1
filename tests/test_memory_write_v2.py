from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import secrets
import sqlite3
from threading import Barrier
from uuid import uuid4

import pytest

from app import memory_archive_v2, memory_keys_v2, memory_write_v2
from app.memory_head_v2 import DurableHeadRegistry, Head, HeadUnavailable
from app.memory_ledger import MemoryLedger, MemoryLedgerConflict
from app.memory_reconciliation import OperationIdentity
from app.memory_write_v2 import ArchiveReducer, MemoryWriter, Mutation, WriteRefused


class Archives:
    def __init__(self):
        self.items = {}
        self.fail_publish = False

    def publish(self, artifact):
        if self.fail_publish:
            raise OSError("synthetic publication failure")
        self.items[artifact.fingerprint] = artifact.data

    def read(self, digest):
        return self.items[digest]


@pytest.fixture
def store(tmp_path, monkeypatch):
    # A process-local codec stub. Native DPAPI is exercised in the Windows guest.
    payloads = {}

    def protect(data):
        token = secrets.token_bytes(32)
        payloads[token] = data
        return token

    for module in (memory_archive_v2, memory_keys_v2, memory_write_v2):
        monkeypatch.setattr(module, "protect_for_current_user", protect)
        if hasattr(module, "unprotect_for_current_user"):
            monkeypatch.setattr(module, "unprotect_for_current_user", payloads.__getitem__)
    archive = Archives()
    generation = uuid4()
    key = memory_keys_v2.issue_receipt_key(generation)
    with closing(sqlite3.connect(":memory:")) as conn:
        MemoryLedger(conn, enabled=True, receipt_budget=8).initialize_empty(generation)
        artifact = memory_archive_v2.build_archive(conn, capsule=key, approved_key_pin=key.fingerprint)
    archive.publish(artifact)
    genesis = Head(generation, 0, artifact.fingerprint)
    path = tmp_path / "authority.sqlite3"
    path.touch()
    reducer = ArchiveReducer(archive, receipt_budget=8)

    def connect():
        return sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)

    writer = MemoryWriter(connect, reducer=reducer, enabled=True)
    writer.provision(genesis)
    return writer, reducer, archive, connect, genesis


def test_reconcile_lost_response_and_delete_after_reopen(store):
    writer, reducer, archive, connect, genesis = store
    create = Mutation("create", text="мой тестовый код — 12345")
    identity = reducer.identify(genesis, uuid4(), create)
    writer.commit(genesis, identity, create)  # Discard the acknowledgement.
    reopened = MemoryWriter(connect, reducer=reducer, enabled=True)
    saved = reopened.head()
    assert saved.revision == 1 and reopened.status(genesis, identity) == saved
    note, = reducer.read(saved)
    assert memory_archive_v2.unprotect_for_current_user(note.sealed).decode() == create.text
    with pytest.raises(WriteRefused, match="already_recorded"):
        reopened.commit(genesis, identity, create)
    assert len(archive.items) == 2 and reopened.head() == saved
    delete = Mutation("delete", note_id=note.id, note_revision=note.revision)
    receipt = reducer.identify(saved, uuid4(), delete)
    final = reopened.commit(saved, receipt, delete)
    assert final.revision == 2 and reducer.read(final) == ()
    assert reopened.status(genesis, identity) == saved
    assert reopened.status(saved, receipt) == final


def test_no_publication_on_payload_generation_or_identity_mismatch(store):
    writer, reducer, archive, _, genesis = store
    mutation = Mutation("create", text="original")
    identity = reducer.identify(genesis, uuid4(), mutation)
    with pytest.raises(WriteRefused, match="binding_mismatch"):
        writer.commit(genesis, identity, Mutation("create", text="other"))
    wrong_generation = OperationIdentity(identity.operation_id, uuid4(), identity.binding)
    with pytest.raises(WriteRefused, match="invalid_operation_identity"):
        writer.commit(genesis, wrong_generation, mutation)
    assert writer.head() == genesis and writer.status(genesis, identity) is None
    assert len(archive.items) == 1
    writer.commit(genesis, identity, mutation)
    different = reducer.identify(genesis, identity.operation_id, Mutation("create", text="other"))
    with pytest.raises(WriteRefused, match="receipt_conflict"):
        writer.status(genesis, different)


def test_disabled_writer_never_opens_authority(store):
    _, reducer, _, _, genesis = store
    mutation = Mutation("create", text="synthetic")
    identity = reducer.identify(genesis, uuid4(), mutation)

    def forbidden():
        pytest.fail("Disabled writer opened SQLite")

    writer = MemoryWriter(forbidden, reducer=reducer)
    with pytest.raises(WriteRefused, match="disabled"):
        writer.commit(genesis, identity, mutation)
    with pytest.raises(WriteRefused, match="disabled"):
        writer.status(genesis, identity)


def test_two_writers_for_same_head(store):
    writer, reducer, archive, _, genesis = store
    gate = Barrier(2, timeout=5)

    def write(text):
        mutation = Mutation("create", text=text)
        identity = reducer.identify(genesis, uuid4(), mutation)
        gate.wait()
        try:
            writer.commit(genesis, identity, mutation)
        except WriteRefused as error:
            assert str(error) == "stale_head"
            return None
        return identity

    with ThreadPoolExecutor(max_workers=2) as pool:
        identities = [identity for identity in pool.map(write, ("first", "second")) if identity is not None]
    assert len(identities) == 1 and len(archive.items) == 2
    assert writer.status(genesis, identities[0]) == writer.head()


def test_publication_and_commit_failures_leave_no_receipt(store):
    writer, reducer, archive, connect, genesis = store
    mutation = Mutation("create", text="synthetic")
    identity = reducer.identify(genesis, uuid4(), mutation)
    archive.fail_publish = True
    with pytest.raises(OSError, match="publication failure"):
        writer.commit(genesis, identity, mutation)
    assert len(archive.items) == 1
    archive.fail_publish = False

    def deny_commit():
        conn = connect()
        conn.set_authorizer(lambda action, arg, *_:
                            sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and arg == "COMMIT"
                            else sqlite3.SQLITE_OK)
        return conn

    faulty = MemoryWriter(deny_commit, reducer=reducer, enabled=True)
    with pytest.raises(HeadUnavailable, match="outcome_unconfirmed"):
        faulty.commit(genesis, identity, mutation)
    assert len(archive.items) == 2  # Unreferenced archive. Never becomes the fallback head.
    assert writer.head() == genesis and writer.status(genesis, identity) is None


def test_error_after_sqlite_commit_is_reconciled_without_mutation_replay(store):
    writer, reducer, archive, connect, genesis = store
    mutation = Mutation("create", text="synthetic")
    identity = reducer.identify(genesis, uuid4(), mutation)

    class LostCommitReply(sqlite3.Connection):
        def __exit__(self, *exception):
            result = super().__exit__(*exception)
            if exception[0] is None:
                raise sqlite3.OperationalError("synthetic committed but unknown")
            return result

    def fault():
        with closing(connect()) as existing:
            path = existing.execute("PRAGMA database_list").fetchone()[2]
        return sqlite3.connect(path, factory=LostCommitReply)

    with pytest.raises(HeadUnavailable, match="outcome_unconfirmed"):
        MemoryWriter(fault, reducer=reducer, enabled=True).commit(genesis, identity, mutation)
    assert writer.status(genesis, identity) == writer.head()
    assert writer.head().revision == 1 and len(archive.items) == 2


def test_receipt_limit_keeps_deletion_available(store):
    writer, reducer, _, _, _ = store
    for index in range(4):
        head = writer.head()
        mutation = Mutation("create", text=str(index))
        writer.commit(head, reducer.identify(head, uuid4(), mutation), mutation)
    head = writer.head()
    mutation = Mutation("create", text="over budget")
    with pytest.raises(MemoryLedgerConflict, match="budget"):
        writer.commit(head, reducer.identify(head, uuid4(), mutation), mutation)
    for note in reducer.read(head):
        head = writer.head()
        delete = Mutation("delete", note_id=note.id, note_revision=note.revision)
        writer.commit(head, reducer.identify(head, uuid4(), delete), delete)
    assert writer.head().revision == 8 and reducer.read(writer.head()) == ()


def test_old_authority_schema_is_not_migrated(store, tmp_path):
    _, reducer, _, _, genesis = store
    path = tmp_path / "previous-schema.sqlite3"

    def connect():
        return sqlite3.connect(path)

    old = DurableHeadRegistry(connect)
    old.provision(genesis)
    stable = path.read_bytes()
    writer = MemoryWriter(connect, reducer=reducer, enabled=True)
    with pytest.raises(HeadUnavailable, match="schema_refused"):
        writer.provision(genesis)
    with pytest.raises(HeadUnavailable, match="schema_refused"):
        writer.head()
    assert path.read_bytes() == stable and old.read() == genesis


def test_archive_readback_mismatch_never_advances_head(store, monkeypatch):
    writer, reducer, archive, _, genesis = store
    mutation = Mutation("create", text="test")
    identity = reducer.identify(genesis, uuid4(), mutation)
    read = archive.read
    monkeypatch.setattr(archive, "read", lambda digest: read(genesis.digest))
    with pytest.raises(memory_archive_v2.ArchiveUnavailable):
        writer.commit(genesis, identity, mutation)
    assert writer.head() == genesis and writer.status(genesis, identity) is None
