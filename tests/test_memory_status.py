"""NEW guard + reconciliation integration, synthetic RO SQLite only."""
import os
from pathlib import Path
import sqlite3
import unittest
from uuid import UUID, uuid4

from app.memory_reconciliation import OperationIdentity, OperationReceipt, OperationSnapshot, ReceiptState, ReconciliationDisabled, ReconciliationOutcome
from app.memory_security import MemoryAccessGuard, SecurityDenied
from app.memory_status import MemoryOperationStatusService, ReceiptReadUnavailable


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0; self.random_counter = 0; self.calls = 0
        def random_bytes(size):
            self.random_counter += 1
            return self.random_counter.to_bytes(size, "big")
        self.guard = MemoryAccessGuard(enabled=True, clock=lambda: self.now, random_bytes=random_bytes)
        self.base = [("host", "127.0.0.1:8000")]
        pair_headers = self.base + [("origin", "http://127.0.0.1:8000"), ("content-type", "application/json")]
        challenge = self.guard.issue_pairing_challenge()
        self.credentials = self.guard.pair("POST", pair_headers, challenge.secret)
        self.headers = self.base + [("authorization", "Bearer " + self.credentials.bearer_token)]
        self.identity = OperationIdentity(uuid4(), uuid4(), b"synthetic-binding")
        self.path = Path(os.environ["AI1_TEST_ROOT"]) / (uuid4().hex + ".sqlite3")
        # This fixture is not a production ledger design.
        with sqlite3.connect(self.path) as connection:
            connection.executescript("CREATE TABLE fixture_meta(generation TEXT); CREATE TABLE fixture_receipt(op TEXT,generation TEXT,binding BLOB,state TEXT);")
            connection.execute("INSERT INTO fixture_meta VALUES(?)", (str(self.identity.store_generation),))
            connection.execute("INSERT INTO fixture_receipt VALUES(?,?,?,?)", (str(self.identity.operation_id), str(self.identity.store_generation), self.identity.binding, "completed"))
        self.service = MemoryOperationStatusService(enabled=True, guard=self.guard, read_snapshot=self.read)

    def read(self, principal, operation):
        self.calls += 1
        self.assertEqual(principal.profile, "local-user")
        connection = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON"); connection.execute("BEGIN")
            generation = UUID(connection.execute("SELECT generation FROM fixture_meta").fetchone()[0])
            row = connection.execute("SELECT generation,binding,state FROM fixture_receipt WHERE op=?", (str(operation),)).fetchone()
            receipt = None if row is None else OperationReceipt(OperationIdentity(operation, UUID(row[0]), row[1]), ReceiptState(row[2]))
            return OperationSnapshot(generation, receipt)
        finally:
            connection.close()

    def logout_headers(self):
        return self.headers + [("origin", "http://127.0.0.1:8000"), ("content-type", "application/json"), ("x-ai1-memory-csrf", self.credentials.csrf_token)]

    def test_default_off_does_not_authorize_or_read(self):
        service = MemoryOperationStatusService(guard=self.guard, read_snapshot=self.read)
        with self.assertRaises(ReconciliationDisabled): service.query(self.headers, self.identity)
        self.assertEqual(self.calls, 0)

    def test_authorized_get_without_origin_reads_consistent_receipt(self):
        before = self.path.read_bytes()
        result = self.service.query(self.headers, self.identity)
        self.assertEqual(result.outcome, ReconciliationOutcome.CONFIRMED)
        self.assertFalse(result.retry_allowed)
        self.assertEqual(self.calls, 1)
        self.assertEqual(self.path.read_bytes(), before)

    def test_denied_headers_never_open_repository(self):
        invalid = [self.base, [("host", "foreign.invalid")] + self.headers[1:],
            self.headers + [("origin", "http://foreign.invalid")], self.headers + self.headers[1:],
            self.base + [("x-ai1-client", "local-cli")]]
        for headers in invalid:
            with self.subTest(headers_count=len(headers)), self.assertRaises(SecurityDenied):
                self.service.query(headers, self.identity)
        self.assertEqual(self.calls, 0)

    def test_logout_not_cached_for_later_reads(self):
        self.service.query(self.headers, self.identity)
        self.guard.logout(self.logout_headers())
        with self.assertRaises(SecurityDenied): self.service.query(self.headers, self.identity)
        self.assertEqual(self.calls, 1)

    def test_expired_session_denied_before_read(self):
        self.now += self.guard.IDLE_TTL
        with self.assertRaises(SecurityDenied): self.service.query(self.headers, self.identity)
        self.assertEqual(self.calls, 0)

    def test_disabled_guard_denies_before_read(self):
        self.guard.disable()
        with self.assertRaises(SecurityDenied): self.service.query(self.headers, self.identity)
        self.assertEqual(self.calls, 0)

    def test_reader_error_is_unknown_fixed_message_preserved_cause_no_retry(self):
        count = []
        original = sqlite3.OperationalError("SYNTHETIC_SENSITIVE_VALUE")
        def unavailable(*args): count.append(1); raise original
        service = MemoryOperationStatusService(enabled=True, guard=self.guard, read_snapshot=unavailable)
        with self.assertRaises(ReceiptReadUnavailable) as error: service.query(self.headers, self.identity)
        self.assertIs(error.exception.__cause__, original)
        self.assertNotIn("SYNTHETIC_SENSITIVE_VALUE", str(error.exception))
        self.assertFalse(error.exception.retry_allowed); self.assertEqual(count, [1])

    def test_existing_read_admission_semantics_unchanged_by_later_logout(self):
        def read_after_logout(principal, operation):
            self.guard.logout(self.logout_headers())
            return self.read(principal, operation)
        service = MemoryOperationStatusService(enabled=True, guard=self.guard, read_snapshot=read_after_logout)
        # Existing approved admission-only read semantics, NOT a new M3 write rule.
        self.assertEqual(service.query(self.headers, self.identity).outcome, ReconciliationOutcome.CONFIRMED)
        with self.assertRaises(SecurityDenied): service.query(self.headers, self.identity)
        self.assertEqual(self.calls, 1)
