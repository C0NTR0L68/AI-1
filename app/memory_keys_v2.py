"""DPAPI-protected receipt keys; no implicit file reads, creation or fallback."""
from dataclasses import dataclass, field
import hashlib
import hmac
import secrets
from uuid import UUID

from app.memory_crypto import protect_for_current_user, unprotect_for_current_user


_DOMAIN = b"AI1-MEMORY-RECEIPTS-v1\0"
_KEY_SIZE = 32
_BLOB_LIMIT = 65536


class ReceiptKeyUnavailable(RuntimeError):
    """Redacted failure: an existing store must not silently get a new key."""


@dataclass(frozen=True)
class ReceiptKeyCapsule:
    sealed: bytes = field(repr=False)
    fingerprint: bytes = field(repr=False)


def issue_receipt_key(generation: UUID) -> ReceiptKeyCapsule:
    """Explicit provisioning candidate. The caller must atomically persist the
    capsule with its independently trusted fingerprint before accepting writes.
    """
    if type(generation) is not UUID:
        raise ValueError("Expected store generation")
    sealed = protect_for_current_user(_DOMAIN + generation.bytes + secrets.token_bytes(_KEY_SIZE))
    if type(sealed) is not bytes or not 1 <= len(sealed) <= _BLOB_LIMIT:
        raise ReceiptKeyUnavailable("receipt_key_unavailable")
    return ReceiptKeyCapsule(sealed, hashlib.sha256(sealed).digest())


def open_receipt_key(generation: UUID, sealed: bytes, *, approved_fingerprint: bytes) -> bytes:
    """Load only a previously provisioned key for this store and generation."""
    if (type(generation) is not UUID or type(sealed) is not bytes or not 1 <= len(sealed) <= _BLOB_LIMIT
            or type(approved_fingerprint) is not bytes or len(approved_fingerprint) != 32
            or not hmac.compare_digest(hashlib.sha256(sealed).digest(), approved_fingerprint)):
        raise ReceiptKeyUnavailable("receipt_key_unavailable")
    try:
        payload = unprotect_for_current_user(sealed)
    except Exception:
        raise ReceiptKeyUnavailable("receipt_key_unavailable") from None
    expected = _DOMAIN + generation.bytes
    if (type(payload) is not bytes or len(payload) != len(expected) + _KEY_SIZE
            or not hmac.compare_digest(payload[:len(expected)], expected)):
        raise ReceiptKeyUnavailable("receipt_key_unavailable")
    return payload[len(expected):]
