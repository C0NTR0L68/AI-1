import os
from pathlib import Path
import sqlite3
import unittest
from uuid import uuid4

from app.memory_ledger import MemoryLedger, MemoryLedgerConflict
from app.memory_reconciliation import OperationIdentity, ReconciliationDisabled


class MemoryLedgerTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(os.environ["AI1_TEST_ROOT"]) / (uuid4().hex + ".sqlite3")
        self.connection = sqlite3.connect(self.path)
        self.addCleanup(self.connection.close)
        self.generation = uuid4()
        self.ledger = MemoryLedger(self.connection, enabled=True, receipt_budget=8)
        self.ledger.initialize_empty(self.generation)

    def operation(self, binding=b"synthetic-opaque-binding"):
        return OperationIdentity(uuid4(), self.generation, binding)

    def test_disabled_default_never_touches_connection(self):
        self.connection.close()
        with self.assertRaises(ReconciliationDisabled):
            MemoryLedger(self.connection).check_integrity()

    def test_durable_create_update_delete_and_readonly_receipt(self):
        create = self.operation()
        receipt = self.ledger.mutate(create, "create", sealed=b"opaque-v1")
        update = self.operation()
        updated = self.ledger.mutate(update, "update", note_id=receipt.note_id, revision=1, sealed=b"opaque-v2")
        self.assertEqual(updated.revision, 2)
        reopened = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)
        self.addCleanup(reopened.close)
        reader = MemoryLedger(reopened, enabled=True, receipt_budget=8)
        self.assertEqual(reader.check_integrity(), self.generation)
        note, = reader.read(self.generation)
        self.assertEqual((note.revision, note.sealed), (2, b"opaque-v2"))
        self.assertEqual(reader.snapshot(update.operation_id).receipt.identity, update)
        delete = self.operation()
        self.ledger.mutate(delete, "delete", note_id=note.id, revision=2)
        self.assertEqual(reader.read(self.generation), ())
        self.assertTrue(self.ledger.mutate(delete, "delete", note_id=note.id, revision=2).replayed)
        self.assertTrue(self.ledger.mutate(create, "create", sealed=b"new-random-sealing").replayed)
        self.assertEqual(reader.read(self.generation), ())
        replacement = self.ledger.mutate(self.operation(), "create", sealed=b"opaque-new")
        self.assertGreater(replacement.note_id, note.id)

    def test_conflicts_and_no_plaintext_argument(self):
        create = self.operation()
        note = self.ledger.mutate(create, "create", sealed=b"opaque")
        altered = OperationIdentity(create.operation_id, self.generation, b"another-binding")
        for operation in (altered, OperationIdentity(uuid4(), uuid4(), b"old-generation")):
            with self.assertRaises(MemoryLedgerConflict):
                self.ledger.mutate(operation, "create", sealed=b"opaque")
        with self.assertRaises(MemoryLedgerConflict):
            self.ledger.mutate(self.operation(), "delete", note_id=note.note_id, revision=2)
        with self.assertRaises(ValueError):
            self.ledger.mutate(self.operation(), "create", sealed="plaintext")
        self.assertEqual(len(self.ledger.read(self.generation)), 1)

    def test_ledger_capacity_preserves_delete_and_historical_replay(self):
        ledger = MemoryLedger(self.connection, enabled=True, receipt_budget=2)
        create = self.operation()
        note = ledger.mutate(create, "create", sealed=b"opaque")
        with self.assertRaises(MemoryLedgerConflict):
            ledger.mutate(self.operation(), "update", note_id=note.note_id, revision=1, sealed=b"opaque-other")
        ledger.mutate(self.operation(), "delete", note_id=note.note_id, revision=1)
        self.assertTrue(ledger.mutate(create, "create", sealed=b"opaque").replayed)
        self.assertEqual(ledger.read(self.generation), ())

    def test_failed_receipt_write_rolls_back_note(self):
        def deny_receipt(action, arg1, _arg2, _db, _source):
            if action == sqlite3.SQLITE_INSERT and arg1 == "memory_receipts":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        operation = self.operation()
        self.connection.set_authorizer(deny_receipt)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                self.ledger.mutate(operation, "create", sealed=b"opaque")
        finally:
            self.connection.set_authorizer(None)
        self.assertEqual(self.ledger.read(self.generation), ())
        self.assertIsNone(self.ledger.snapshot(operation.operation_id).receipt)

    def test_extra_schema_object_refuses_before_mutation(self):
        self.connection.execute("CREATE INDEX unrecognized ON sealed_notes(revision)")
        with self.assertRaises(MemoryLedgerConflict):
            self.ledger.mutate(self.operation(), "create", sealed=b"opaque")
        self.assertEqual(self.connection.execute("SELECT count(*) FROM sealed_notes").fetchone()[0], 0)

    def test_commit_ack_loss_is_reconciled_read_only(self):
        class LostAcknowledgement(sqlite3.Connection):
            def commit(self):
                super().commit()
                raise OSError("Synthetic acknowledgement lost after commit")

        writer = sqlite3.connect(self.path, factory=LostAcknowledgement)
        self.addCleanup(writer.close)
        operation = self.operation()
        with self.assertRaises(OSError):
            MemoryLedger(writer, enabled=True, receipt_budget=8).mutate(operation, "create", sealed=b"opaque")
        self.assertEqual(self.ledger.snapshot(operation.operation_id).receipt.identity, operation)
        self.assertEqual(len(self.ledger.read(self.generation)), 1)

    def test_live_quotas_allow_delete_and_charge_update_delta(self):
        ledger = MemoryLedger(self.connection, enabled=True, receipt_budget=16,
                              max_notes=1, max_live_bytes=6)
        created = ledger.mutate(self.operation(), "create", sealed=b"abcde")
        rejected = self.operation()
        with self.assertRaises(MemoryLedgerConflict):
            ledger.mutate(rejected, "create", sealed=b"x")
        self.assertIsNone(ledger.snapshot(rejected.operation_id).receipt)
        with self.assertRaises(MemoryLedgerConflict):
            ledger.mutate(self.operation(), "update", note_id=created.note_id, revision=1, sealed=b"1234567")
        updated = ledger.mutate(self.operation(), "update", note_id=created.note_id, revision=1, sealed=b"123456")
        self.assertEqual(updated.revision, 2)
        ledger.mutate(self.operation(), "delete", note_id=created.note_id, revision=2)
        ledger.mutate(self.operation(), "create", sealed=b"z")
        self.assertEqual([row.sealed for row in ledger.read(self.generation)], [b"z"])

    def test_update_obeys_a_lower_quota_on_an_existing_store(self):
        created = self.ledger.mutate(self.operation(), "create", sealed=b"12345")
        stricter = MemoryLedger(
            self.connection,
            enabled=True,
            receipt_budget=8,
            max_live_bytes=4,
        )
        with self.assertRaises(MemoryLedgerConflict):
            stricter.mutate(
                self.operation(),
                "update",
                note_id=created.note_id,
                revision=created.revision,
                sealed=b"12345",
            )
        note, = stricter.read(self.generation)
        self.assertEqual((note.revision, note.sealed), (1, b"12345"))

    def test_autocommit_connection_cannot_report_success_without_commit(self):
        connection = sqlite3.connect(self.path, autocommit=True)
        self.addCleanup(connection.close)
        ledger = MemoryLedger(connection, enabled=True, receipt_budget=8)
        with self.assertRaises(ValueError):
            ledger.mutate(self.operation(), "create", sealed=b"opaque")
        self.assertFalse(connection.in_transaction)
        self.assertEqual(self.ledger.read(self.generation), ())
