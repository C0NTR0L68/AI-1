"""Experimental Memory V2 persistence without path-based SQLite I/O.

SQLite only materializes an authenticated private RAM image. A trusted backend
must supply handle-verified sealed files and a durable, non-rollback head CAS.
No production backend, HTTP wiring, or automatic initialization is provided.
"""
import hashlib
import hmac
import json

from app.memory_archive_v2 import build_archive, open_archived_state
from app.memory_crypto import protect_for_current_user
from app.memory_keys_v2 import open_receipt_key
from app.memory_ledger import MemoryLedger, MemoryLedgerConflict
from app.memory_reconciliation import OperationIdentity
from app.memory_security import MemoryAccessGuard


class ImageCommitUnconfirmed(RuntimeError):
    """The authoritative head may have changed; consult the receipt, no retry."""


def _pin(value):
    return type(value) is bytes and len(value) == 32


class MemoryImageLedger:
    def __init__(self, backend, *, receipt_budget):
        if type(receipt_budget) is not int or not 1 <= receipt_budget <= 2**63 - 1:
            raise ValueError("Receipt budget required")
        self._backend = backend
        self._budget = receipt_budget

    def _head(self):
        value = self._backend.head()
        if not _pin(value):
            raise ImageCommitUnconfirmed("memory_head_unavailable")
        return value

    def _open(self, head):
        return open_archived_state(self._backend.read(head), approved_archive_pin=head)

    def read(self, generation, *, after=0, limit=50):
        """Storage primitive: a future caller must admit authorization first."""
        with self._open(self._head()) as (conn, _, _):
            return MemoryLedger(conn, enabled=True, receipt_budget=self._budget).read(generation, after=after, limit=limit)

    def snapshot(self, operation_id):
        """Read the authoritative receipt, never an unpublished archive."""
        with self._open(self._head()) as (conn, _, _):
            return MemoryLedger(conn, enabled=True, receipt_budget=self._budget).snapshot(operation_id)

    def mutate_authorized(self, guard, method, headers, *, generation, operation_id, kind,
                          consent=False, note_id=None, revision=None, text=None):
        if type(guard) is not MemoryAccessGuard:
            raise TypeError("Explicit memory guard required")
        if (consent is not True
                or (method, kind) not in (("POST", "create"), ("POST", "update"), ("DELETE", "delete"))):
            raise ValueError("Invalid memory mutation")
        admission = guard._admit_mutation(method, headers)
        if kind == "delete":
            if text is not None:
                raise ValueError("Deletion cannot carry data")
        elif (type(text) is not str or not text.strip() or len(text) > 4096 or "\0" in text
              or len(text.encode("utf8", "strict")) > 16384):
            raise ValueError("Invalid memory text")
        head = self._head()
        with self._open(head) as (conn, actual_generation, capsule):
            if generation != actual_generation:
                raise MemoryLedgerConflict("Store generation changed")
            key = open_receipt_key(generation, capsule.sealed, approved_fingerprint=capsule.fingerprint)
            # Match the already accepted HTTP receipt representation.
            payload = json.dumps([str(generation), str(operation_id), kind, note_id, revision, text],
                                 ensure_ascii=False, separators=(",", ":")).encode("utf8")
            identity = OperationIdentity(operation_id, generation,
                                         hmac.digest(key, b"ai1-memory-v2\0" + payload, hashlib.sha256))
            sealed = None if text is None else protect_for_current_user(text.encode("utf8", "strict"))
            receipt = MemoryLedger(conn, enabled=True, receipt_budget=self._budget).mutate(
                identity, kind, note_id=note_id, revision=revision, sealed=sealed)
            candidate = None if receipt.replayed else build_archive(
                conn, capsule=capsule, approved_key_pin=capsule.fingerprint)

        def durable_effect():
            # A stale replay must not report a receipt from a replaced generation.
            if self._head() != head:
                raise ImageCommitUnconfirmed("memory_head_changed")
            if candidate is None:
                return receipt
            try:
                self._backend.publish(candidate)
                saved = self._backend.read(candidate.fingerprint)
                if type(saved) is not bytes or not hmac.compare_digest(saved, candidate.data):
                    raise ImageCommitUnconfirmed("archive_readback_mismatch")
                if self._backend.advance(head, candidate.fingerprint) is not True:
                    raise ImageCommitUnconfirmed("memory_head_changed")
            except ImageCommitUnconfirmed:
                raise
            except Exception:
                raise ImageCommitUnconfirmed("memory_commit_unconfirmed") from None
            return receipt

        # A revoke that wins here means no ciphertext for the mutation reaches disk.
        return guard._finish_mutation(admission, durable_effect)
