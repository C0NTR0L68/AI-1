"""Disconnected, default-OFF Memory V2 operation-status admission service.

No HTTP endpoint, path, ledger schema, note text, encryption or mutation here.
The future C7-admitted reader must return an authorized consistent RO snapshot.
Reads use the EXISTING guard's admission semantics; this does not decide M3
mutation authorization or claim protection from arbitrary native Python code.
"""
from typing import Callable
from uuid import UUID

from app.memory_reconciliation import (
    InvalidObservation, MemoryOperationReconciler, OperationIdentity,
    OperationSnapshot, ReconciliationDisabled, ReconciliationOutcome,
)
from app.memory_security import MemoryAccessGuard, Principal


class ReceiptReadUnavailable(RuntimeError):
    outcome = ReconciliationOutcome.UNKNOWN
    retry_allowed = False


class MemoryOperationStatusService:
    def __init__(self, *, enabled: bool = False, guard: MemoryAccessGuard | None = None,
                 read_snapshot: Callable[[Principal, UUID], OperationSnapshot | None] | None = None):
        if type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        if enabled and (type(guard) is not MemoryAccessGuard or not callable(read_snapshot)):
            raise ValueError("Explicit memory guard and admitted snapshot reader required")
        self._enabled = enabled
        self._guard = guard if enabled else None
        self._read_snapshot = read_snapshot if enabled else None
        self._core = MemoryOperationReconciler(enabled=enabled)

    def query(self, headers, expected: OperationIdentity):
        if not self._enabled:
            raise ReconciliationDisabled("MEMORY_OPERATION_STATUS_DISABLED")
        # No client-supplied principal or local-cli marker grants admission.
        principal = self._guard.authorize("GET", headers)
        if type(principal) is not Principal:
            raise InvalidObservation("UNVERIFIED_MEMORY_PRINCIPAL")
        if type(expected) is not OperationIdentity:
            raise InvalidObservation("INVALID_EXPECTED_IDENTITY")
        try:
            snapshot = self._read_snapshot(principal, expected.operation_id)
        except Exception as error:
            # Preserve internal cause, expose no SQLite values/paths/note text.
            # No retry or conversion of a failed read into a missing receipt.
            raise ReceiptReadUnavailable("MEMORY_RECEIPT_READ_UNAVAILABLE") from error
        return self._core.reconcile(expected, snapshot)
