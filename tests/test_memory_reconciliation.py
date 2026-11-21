"""NEW V2 reconciliation tests; test-only schema, no production memory store."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import os
import sqlite3
import unittest
from uuid import UUID, uuid4

from app.memory_reconciliation import (
    InvalidObservation, MemoryOperationReconciler, OperationIdentity,
    OperationReceipt, OperationSnapshot, ReceiptState, ReconciliationDisabled,
    ReconciliationOutcome as Outcome, ReconciliationReason as Reason,
)


class FakeProvider:
    def __init__(self): self.calls = 0
    async def reply(self, messages):
        self.calls += 1
        return "Заметка сохранена"  # Deliberately false claim, not a store receipt.
    async def generate(self, messages):
        self.calls += 1
        raise AssertionError("Memory reconciliation must not invoke any model")


class SyntheticLedger:
    """Fixture only. Plain synthetic data/schema are NOT a V2 storage design."""
    def __init__(self, path):
        self.path = path
        self.generation = uuid4()
        with sqlite3.connect(path) as connection:
            connection.executescript("""
                CREATE TABLE fixture_meta(generation TEXT NOT NULL);
                CREATE TABLE fixture_notes(id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT NOT NULL);
                CREATE TABLE fixture_receipts(operation_id TEXT PRIMARY KEY, generation TEXT NOT NULL, binding BLOB NOT NULL, state TEXT NOT NULL);
            """)
            connection.execute("INSERT INTO fixture_meta VALUES(?)", (str(self.generation),))

    def write(self, identity, *, fail_before_commit=False, lose_commit_ack=False):
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT INTO fixture_notes(content) VALUES(?)", ("SYNTHETIC_NOTE_ONLY",))
            if fail_before_commit: raise sqlite3.OperationalError("synthetic pre-commit failure")
            connection.execute("INSERT INTO fixture_receipts VALUES(?,?,?,?)",
                (str(identity.operation_id), str(identity.store_generation), identity.binding, ReceiptState.COMPLETED.value))
            connection.commit()
            if lose_commit_ack: raise sqlite3.OperationalError("synthetic lost commit acknowledgement")
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def read(self, operation_id):
        connection = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            generation = UUID(connection.execute("SELECT generation FROM fixture_meta").fetchone()[0])
            row = connection.execute("SELECT operation_id,generation,binding,state FROM fixture_receipts WHERE operation_id=?", (str(operation_id),)).fetchone()
            receipt = None if row is None else OperationReceipt(OperationIdentity(UUID(row[0]), UUID(row[1]), row[2]), ReceiptState(row[3]))
            return OperationSnapshot(generation, receipt)
        finally:
            connection.close()

    def counts(self):
        with sqlite3.connect(self.path) as connection:
            return (connection.execute("SELECT count(*) FROM fixture_notes").fetchone()[0],
                    connection.execute("SELECT count(*) FROM fixture_receipts").fetchone()[0])


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.core = MemoryOperationReconciler(enabled=True)
        self.identity = OperationIdentity(uuid4(), uuid4(), b"synthetic-opaque-binding")
        self.provider = FakeProvider()

    def result(self, snapshot):
        result = self.core.reconcile(self.identity, snapshot)
        self.assertFalse(result.retry_allowed)
        self.assertEqual(self.provider.calls, 0)
        return result

    def snapshot(self, state=ReceiptState.COMPLETED, identity=None):
        return OperationSnapshot(self.identity.store_generation, OperationReceipt(identity or self.identity, state))

    def test_disabled_by_default_without_touching_observation(self):
        class Poison:
            def __getattribute__(self, name): raise AssertionError("disabled core examined input")
        with self.assertRaises(ReconciliationDisabled): MemoryOperationReconciler().reconcile(Poison(), Poison())
        for value in (1, "yes", None):
            with self.assertRaises(ValueError): MemoryOperationReconciler(enabled=value)

    def test_matching_historical_completion_confirmed(self):
        result = self.result(self.snapshot())
        self.assertEqual((result.outcome, result.reason), (Outcome.CONFIRMED, Reason.MATCHING_COMPLETION))
        self.assertFalse(hasattr(result, "note_content"))

    def test_missing_and_unavailable_never_allow_repeat(self):
        for snapshot, reason in ((None, Reason.UNAVAILABLE), (OperationSnapshot(self.identity.store_generation), Reason.RECEIPT_MISSING)):
            result = self.result(snapshot)
            self.assertEqual((result.outcome, result.reason), (Outcome.UNKNOWN, reason))

    def test_pending_unknown_failed_are_not_completion_proof(self):
        for state in (ReceiptState.PENDING, ReceiptState.UNKNOWN, ReceiptState.FAILED):
            result = self.result(self.snapshot(state))
            self.assertEqual((result.outcome, result.reason), (Outcome.UNKNOWN, Reason.NOT_COMPLETED))

    def test_binding_conflict_not_a_replay_or_success(self):
        other = OperationIdentity(self.identity.operation_id, self.identity.store_generation, b"different")
        result = self.result(self.snapshot(identity=other))
        self.assertEqual((result.outcome, result.reason), (Outcome.CONFLICT, Reason.PAYLOAD_CONFLICT))

    def test_other_operation_or_store_receipt_is_unknown(self):
        for identity in (OperationIdentity(uuid4(), self.identity.store_generation, self.identity.binding),
                         OperationIdentity(self.identity.operation_id, uuid4(), self.identity.binding)):
            self.assertEqual(self.result(self.snapshot(identity=identity)).reason, Reason.RECEIPT_IDENTITY_MISMATCH)

    def test_restore_generation_mismatch_overrides_apparent_completion(self):
        result = self.result(OperationSnapshot(uuid4(), OperationReceipt(self.identity, ReceiptState.COMPLETED)))
        self.assertEqual((result.outcome, result.reason), (Outcome.UNKNOWN, Reason.STORE_CHANGED))

    def test_plain_model_text_and_json_cannot_become_receipts(self):
        for fake in ("Saved successfully", {"state": "completed"}, '{"state":"completed"}'):
            with self.assertRaises(InvalidObservation) as error: self.core.reconcile(self.identity, fake)
            self.assertEqual(str(error.exception), "UNVERIFIED_OPERATION_SNAPSHOT")
        self.assertEqual(self.provider.calls, 0)

    def test_invalid_types_and_bounds(self):
        for binding in (b"", b"x" * 257, "text", bytearray(b"binding")):
            with self.assertRaises(InvalidObservation): OperationIdentity(uuid4(), uuid4(), binding)
        with self.assertRaises(InvalidObservation): OperationIdentity("uuid", uuid4(), b"x")
        with self.assertRaises(InvalidObservation): OperationReceipt(self.identity, "completed")
        with self.assertRaises(InvalidObservation): OperationSnapshot("uuid")

    def test_values_are_immutable_and_bindings_not_in_repr(self):
        self.assertNotIn("synthetic-opaque-binding", repr(self.identity))
        with self.assertRaises(FrozenInstanceError): self.identity.binding = b"changed"
        result = self.result(self.snapshot())
        with self.assertRaises(FrozenInstanceError): result.retry_allowed = True

    def ledger(self):
        path = Path(os.environ["AI1_TEST_ROOT"]) / (uuid4().hex + ".sqlite3")
        ledger = SyntheticLedger(path)
        self.identity = OperationIdentity(self.identity.operation_id, ledger.generation, self.identity.binding)
        return ledger

    def test_lost_real_sqlite_commit_ack_reconciles_without_second_insert(self):
        ledger = self.ledger()
        with self.assertRaises(sqlite3.OperationalError): ledger.write(self.identity, lose_commit_ack=True)
        before = ledger.counts()
        self.assertEqual(self.result(ledger.read(self.identity.operation_id)).outcome, Outcome.CONFIRMED)
        self.assertEqual(ledger.counts(), before)
        self.assertEqual(before, (1, 1))

    def test_real_sqlite_rollback_leaves_no_receipt_and_no_automatic_retry(self):
        ledger = self.ledger()
        with self.assertRaises(sqlite3.OperationalError): ledger.write(self.identity, fail_before_commit=True)
        result = self.result(ledger.read(self.identity.operation_id))
        self.assertEqual(result.outcome, Outcome.UNKNOWN)
        self.assertEqual(ledger.counts(), (0, 0))

    def test_repeated_status_reads_and_new_reconciler_do_not_mutate_store(self):
        ledger = self.ledger(); ledger.write(self.identity)
        before = ledger.path.read_bytes()
        for _ in range(3):
            snapshot = ledger.read(self.identity.operation_id)
            self.assertEqual(MemoryOperationReconciler(enabled=True).reconcile(self.identity, snapshot).outcome, Outcome.CONFIRMED)
        self.assertEqual(ledger.path.read_bytes(), before)
        self.assertEqual(ledger.counts(), (1, 1))

    def test_historical_receipt_not_a_claim_that_deleted_note_exists(self):
        ledger = self.ledger(); ledger.write(self.identity)
        with sqlite3.connect(ledger.path) as connection: connection.execute("DELETE FROM fixture_notes")
        result = self.result(ledger.read(self.identity.operation_id))
        self.assertEqual(result.outcome, Outcome.CONFIRMED)
        self.assertEqual(ledger.counts(), (0, 1))
        self.assertFalse(hasattr(result, "note_exists"))

    def test_fake_model_claim_never_substitutes_receipt_or_regenerates(self):
        ledger = self.ledger()
        coroutine = self.provider.reply([{"role": "user", "content": "SYNTHETIC_ONLY"}])
        try:
            coroutine.send(None)
        except StopIteration as completed:
            claim = completed.value
        finally:
            coroutine.close()
        with self.assertRaises(InvalidObservation): self.core.reconcile(self.identity, claim)
        result = self.core.reconcile(self.identity, ledger.read(self.identity.operation_id))
        self.assertEqual(result.outcome, Outcome.UNKNOWN)
        self.assertFalse(result.retry_allowed)
        self.assertEqual(self.provider.calls, 1)  # No model retry by reconciliation.
        self.assertEqual(ledger.counts(), (0, 0))

    def test_uncommitted_receipt_is_not_confirmation(self):
        ledger = self.ledger()
        writer = sqlite3.connect(ledger.path)
        try:
            writer.execute("BEGIN IMMEDIATE")
            writer.execute("INSERT INTO fixture_notes(content) VALUES(?)", ("SYNTHETIC_ONLY",))
            writer.execute("INSERT INTO fixture_receipts VALUES(?,?,?,?)", (str(self.identity.operation_id),
                str(self.identity.store_generation), self.identity.binding, ReceiptState.COMPLETED.value))
            self.assertEqual(self.result(ledger.read(self.identity.operation_id)).outcome, Outcome.UNKNOWN)
            writer.commit()
            self.assertEqual(self.result(ledger.read(self.identity.operation_id)).outcome, Outcome.CONFIRMED)
        finally:
            writer.close()
