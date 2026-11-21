"""DPAPI backup and restore staging; never opens or replaces a disk path."""
from dataclasses import dataclass, field
import hashlib
import hmac
import sqlite3
from uuid import UUID

from app.memory_crypto import protect_for_current_user, unprotect_for_current_user
from app.memory_keys_v2 import ReceiptKeyCapsule, issue_receipt_key, open_receipt_key
from app.memory_ledger import MemoryLedger
from app.memory_snapshot_v2 import stage_snapshot

_TAG = b"AI1-MEMORY-ARCHIVE-v1\0"
MAX_ARCHIVE = 16 * 1024 * 1024


class ArchiveUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class BackupArchive:
    data: bytes = field(repr=False)
    fingerprint: bytes = field(repr=False)


@dataclass(frozen=True)
class RestoreCandidate:
    generation: UUID
    notes: int
    sqlite_image: bytes = field(repr=False)
    key: ReceiptKeyCapsule = field(repr=False)


def _verify_note(value):
    text = unprotect_for_current_user(value).decode("utf8", "strict")
    return bool(text.strip()) and "\0" not in text and len(text) <= 4096 and len(text.encode("utf8")) <= 16384


def _image(conn):
    data = conn.serialize()
    if (not data.startswith(b"SQLite format 3\0") or data[18:20] != b"\x01\x01"
            or not 100 <= len(data) < MAX_ARCHIVE):
        raise ArchiveUnavailable("archive_unavailable")
    return data


def build_archive(source, *, capsule, approved_key_pin):
    """Make a key-consistent, checked archive from a quiescent trusted source."""
    try:
        if type(capsule) is not ReceiptKeyCapsule:
            raise ValueError("Expected sealed key")
        generation = MemoryLedger(source, enabled=True, receipt_budget=1).check_integrity()
        open_receipt_key(generation, capsule.sealed, approved_fingerprint=approved_key_pin)
        with _private_db() as frozen:
            snapshot = stage_snapshot(source, frozen, verify=_verify_note)
            if snapshot.generation != generation:
                raise ArchiveUnavailable("archive_unavailable")
            payload = (_TAG + generation.bytes + len(capsule.sealed).to_bytes(4, "big")
                       + approved_key_pin + capsule.sealed + _image(frozen))
            # Leave room for the DPAPI envelope in the bounded archive.
            if len(payload) > MAX_ARCHIVE - 65536:
                raise ArchiveUnavailable("archive_unavailable")
            data = protect_for_current_user(payload)
            if not 1 <= len(data) <= MAX_ARCHIVE:
                raise ArchiveUnavailable("archive_unavailable")
            return BackupArchive(data, hashlib.sha256(data).digest())
    except Exception:
        raise ArchiveUnavailable("archive_unavailable") from None


def restore_archive(data, *, approved_archive_pin, restore_generation):
    """Authenticate before SQLite parses. Return a verified, unpublished image."""
    if (type(data) is not bytes or not 1 <= len(data) <= MAX_ARCHIVE
            or type(approved_archive_pin) is not bytes or len(approved_archive_pin) != 32
            or not hmac.compare_digest(hashlib.sha256(data).digest(), approved_archive_pin)
            or type(restore_generation) is not UUID):
        raise ArchiveUnavailable("archive_unavailable")
    try:
        raw = unprotect_for_current_user(data)
        if not raw.startswith(_TAG) or len(raw) < len(_TAG) + 52 + 100:
            raise ArchiveUnavailable("archive_unavailable")
        offset = len(_TAG)
        generation = UUID(bytes=raw[offset:offset + 16])
        length = int.from_bytes(raw[offset + 16:offset + 20], "big")
        end = offset + 52 + length
        if not 1 <= length <= 65536 or end + 100 > len(raw) or generation == restore_generation:
            raise ArchiveUnavailable("archive_unavailable")
        pin, capsule, image = raw[offset + 20:offset + 52], raw[offset + 52:end], raw[end:]
        open_receipt_key(generation, capsule, approved_fingerprint=pin)
        if not image.startswith(b"SQLite format 3\0") or image[18:20] != b"\x01\x01":
            raise ArchiveUnavailable("archive_unavailable")
        with _private_db() as source, _private_db() as staging:
            source.deserialize(image)
            source.execute("PRAGMA trusted_schema=OFF")
            source.execute("PRAGMA query_only=ON")
            if MemoryLedger(source, enabled=True, receipt_budget=1).check_integrity() != generation:
                raise ArchiveUnavailable("archive_unavailable")
            report = stage_snapshot(source, staging, verify=_verify_note, restore_generation=restore_generation)
            key = issue_receipt_key(report.generation)
            return RestoreCandidate(report.generation, report.notes, _image(staging), key)
    except Exception:
        raise ArchiveUnavailable("archive_unavailable") from None


def _private_db():
    # sqlite3.Connection's context manager does not close the connection.
    from contextlib import closing
    return closing(sqlite3.connect(":memory:"))
