"""Publish immutable Windows backup artifacts in an independently admitted directory.

No production caller is wired. Admission must pin the directory for the whole
operation and exclude other writers; read_bound must verify file identity/ACL
and read through the checked handle. This does not publish a live SQLite DB
or make the directory entry durable across a power cut.
"""
from dataclasses import dataclass
from contextlib import closing
import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

from app.memory_archive_v2 import ArchiveUnavailable, BackupArchive, MAX_ARCHIVE, build_archive
from app.windows_storage_inspector import _sidecars_absent


class PublicationUnconfirmed(RuntimeError):
    """Do not retry a restore or assume that a final artifact does not exist."""


@dataclass(frozen=True)
class PublishedArchive:
    path: Path
    reused: bool


def _target(directory, fingerprint):
    if (os.name != "nt" or not isinstance(directory, Path) or not directory.is_absolute()
            or type(fingerprint) is not bytes or len(fingerprint) != 32):
        raise ValueError("Windows archive directory and approved SHA-256 required")
    return directory / ("memory-" + fingerprint.hex() + ".v2a")


def _matches(value, fingerprint):
    return (type(value) is bytes and 1 <= len(value) <= MAX_ARCHIVE
            and hmac.compare_digest(hashlib.sha256(value).digest(), fingerprint))


def read_published_archive(directory, *, fingerprint, hold_directory, read_bound):
    """Reconcile by approved digest; pending artifacts never count as published."""
    target = _target(directory, fingerprint)
    try:
        with hold_directory(directory):
            data = read_bound(target, MAX_ARCHIVE)
            if not _matches(data, fingerprint):
                raise PublicationUnconfirmed("archive_publication_unconfirmed")
            return data
    except Exception:
        raise PublicationUnconfirmed("archive_publication_unconfirmed") from None


def publish_archive(archive, directory, *, hold_directory, read_bound):
    """Flush a new candidate, rename without overwrite, then verify by handle.

    Existing final files are never replaced. Failed/ambiguous operations leave
    their evidence in place; the only reconciliation is read_published_archive.
    No source DB or active generation can be selected through this API.
    """
    if type(archive) is not BackupArchive or type(archive.fingerprint) is not bytes:
        raise ValueError("Approved archive required")
    final = _target(directory, archive.fingerprint)
    if not _matches(archive.data, archive.fingerprint):
        raise ValueError("Approved archive digest mismatch")
    try:
        with hold_directory(directory):
            try:
                final.lstat()
            except FileNotFoundError:
                reused = False
            else:
                reused = True  # includes a dangling link; read_bound must reject it
            if not reused:
                pending = directory / (".memory-" + uuid4().hex + ".pending")
                with pending.open("xb") as stream:
                    if stream.write(archive.data) != len(archive.data):
                        raise PublicationUnconfirmed("archive_publication_unconfirmed")
                    stream.flush()
                    os.fsync(stream.fileno())
                if not _matches(read_bound(pending, MAX_ARCHIVE), archive.fingerprint):
                    raise PublicationUnconfirmed("archive_publication_unconfirmed")
                # Same-directory Windows rename fails if destination exists.
                # Do not use replace() or copy-and-delete.
                os.rename(pending, final)
            if not _matches(read_bound(final, MAX_ARCHIVE), archive.fingerprint):
                raise PublicationUnconfirmed("archive_publication_unconfirmed")
        return PublishedArchive(final, reused)
    except Exception:
        raise PublicationUnconfirmed("archive_publication_unconfirmed") from None


def archive_quiescent_image(database, *, approved_database_pin, capsule, approved_key_pin,
                            hold_directory, read_bound):
    """Build an offline archive without passing a user filename to SQLite.

    Caller must already own the namespace and exclude writers. read_bound must
    use an independently pinned, admitted file handle. WAL images and all
    sidecars (also dangling entries) are refused. No recovery is attempted here.
    """
    if (not isinstance(database, Path) or not database.is_absolute() or database.suffix != ".sqlite3"
            or type(approved_database_pin) is not bytes or len(approved_database_pin) != 32):
        raise ValueError("Approved offline SQLite image required")
    try:
        with hold_directory(database.parent):
            if not _sidecars_absent(str(database)):
                raise ArchiveUnavailable("offline_image_unavailable")
            image = read_bound(database, MAX_ARCHIVE)
            if (not _matches(image, approved_database_pin)
                    or not image.startswith(b"SQLite format 3\0") or image[18:20] != b"\x01\x01"
                    or not _sidecars_absent(str(database))):
                raise ArchiveUnavailable("offline_image_unavailable")
        with closing(sqlite3.connect(":memory:")) as source:
            source.deserialize(image)
            source.execute("PRAGMA trusted_schema=OFF")
            source.execute("PRAGMA query_only=ON")
            return build_archive(source, capsule=capsule, approved_key_pin=approved_key_pin)
    except Exception:
        raise ArchiveUnavailable("offline_image_unavailable") from None
