"""Disabled Memory V2 receipt reconciliation core; no I/O or model access.

The future authorized store reader must supply one consistent, committed
snapshot. These value types do NOT authenticate a caller or prove a database
commit. C7 storage/crypto, M3 authorization and ledger retention remain outside
this module. In particular, absence of a receipt never authorizes repetition.
"""
from dataclasses import dataclass, field
from enum import Enum
import hmac
from uuid import UUID


class ReconciliationDisabled(RuntimeError):
    """No memory operation or observation is examined while disabled."""


class InvalidObservation(ValueError):
    """Fixed diagnostic; never includes note text, bindings or identifiers."""


@dataclass(frozen=True)
class OperationIdentity:
    operation_id: UUID
    store_generation: UUID
    # Opaque comparison bytes supplied by a future trusted adapter. We choose
    # no hash/HMAC derivation, secret key, normalization or storage policy here.
    binding: bytes = field(repr=False)

    def __post_init__(self):
        if (type(self.operation_id) is not UUID or type(self.store_generation) is not UUID
                or type(self.binding) is not bytes or not 1 <= len(self.binding) <= 256):
            raise InvalidObservation("INVALID_OPERATION_IDENTITY")


class ReceiptState(str, Enum):
    COMPLETED = "completed"
    PENDING = "pending"
    UNKNOWN = "unknown"
    FAILED = "failed"


@dataclass(frozen=True)
class OperationReceipt:
    identity: OperationIdentity = field(repr=False)
    state: ReceiptState

    def __post_init__(self):
        if type(self.identity) is not OperationIdentity or type(self.state) is not ReceiptState:
            raise InvalidObservation("INVALID_OPERATION_RECEIPT")


@dataclass(frozen=True)
class OperationSnapshot:
    current_store_generation: UUID
    receipt: OperationReceipt | None = field(default=None, repr=False)

    def __post_init__(self):
        if (type(self.current_store_generation) is not UUID
                or self.receipt is not None and type(self.receipt) is not OperationReceipt):
            raise InvalidObservation("INVALID_OPERATION_SNAPSHOT")


class ReconciliationOutcome(str, Enum):
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class ReconciliationReason(str, Enum):
    MATCHING_COMPLETION = "matching_completion"
    UNAVAILABLE = "unavailable"
    STORE_CHANGED = "store_changed"
    RECEIPT_MISSING = "receipt_missing"
    RECEIPT_IDENTITY_MISMATCH = "receipt_identity_mismatch"
    PAYLOAD_CONFLICT = "payload_conflict"
    NOT_COMPLETED = "not_completed"


@dataclass(frozen=True)
class ReconciliationResult:
    outcome: ReconciliationOutcome
    reason: ReconciliationReason

    @property
    def retry_allowed(self) -> bool:
        # Reconciliation reports evidence; it never schedules/authorizes writes.
        return False


class MemoryOperationReconciler:
    """Compare trusted snapshot evidence after an uncertain memory operation.

    CONFIRMED means a matching historical operation receipt was observed; it
    does not mean that a note still exists, has the same contents, or may be
    disclosed/used by a model. Reads and mutations need their own authorization.
    No API, real ledger schema, retention or storage provisioning is enabled.
    """
    def __init__(self, *, enabled: bool = False):
        if type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        self._enabled = enabled

    def reconcile(self, expected: OperationIdentity,
                  snapshot: OperationSnapshot | None) -> ReconciliationResult:
        if not self._enabled:
            raise ReconciliationDisabled("MEMORY_RECONCILIATION_DISABLED")
        if type(expected) is not OperationIdentity:
            raise InvalidObservation("INVALID_EXPECTED_IDENTITY")
        if snapshot is None:
            return ReconciliationResult(ReconciliationOutcome.UNKNOWN, ReconciliationReason.UNAVAILABLE)
        if type(snapshot) is not OperationSnapshot:
            raise InvalidObservation("UNVERIFIED_OPERATION_SNAPSHOT")
        if snapshot.current_store_generation != expected.store_generation:
            return ReconciliationResult(ReconciliationOutcome.UNKNOWN, ReconciliationReason.STORE_CHANGED)
        receipt = snapshot.receipt
        if receipt is None:
            # Missing can mean rollback, ledger pruning, restore, or wrong view.
            # No retention/incarnation policy is assumed to turn absence into proof.
            return ReconciliationResult(ReconciliationOutcome.UNKNOWN, ReconciliationReason.RECEIPT_MISSING)
        if (receipt.identity.operation_id != expected.operation_id
                or receipt.identity.store_generation != snapshot.current_store_generation):
            return ReconciliationResult(ReconciliationOutcome.UNKNOWN, ReconciliationReason.RECEIPT_IDENTITY_MISMATCH)
        if not hmac.compare_digest(receipt.identity.binding, expected.binding):
            return ReconciliationResult(ReconciliationOutcome.CONFLICT, ReconciliationReason.PAYLOAD_CONFLICT)
        if receipt.state is not ReceiptState.COMPLETED:
            return ReconciliationResult(ReconciliationOutcome.UNKNOWN, ReconciliationReason.NOT_COMPLETED)
        return ReconciliationResult(ReconciliationOutcome.CONFIRMED, ReconciliationReason.MATCHING_COMPLETION)
