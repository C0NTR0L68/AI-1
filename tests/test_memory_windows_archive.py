"""C7-v1 positive and negative tests on new Windows synthetic objects."""
import ctypes
from contextlib import closing
from ctypes import wintypes
from hashlib import sha256
import os
import sqlite3
from uuid import uuid4

import pytest

from app import memory_windows_archive
from app.memory_archive_publish_v2 import PublicationUnconfirmed
from app.memory_archive_v2 import BackupArchive, build_archive
from app.memory_head_v2 import AuthorityArchiveBackend, DurableHeadRegistry, Head
from app.memory_image_ledger import MemoryImageLedger
from app.memory_keys_v2 import issue_receipt_key
from app.memory_ledger import MemoryLedger
from app.memory_security import MemoryAccessGuard
from app.memory_windows_archive import PrivateArchiveDirectory, _creation_security
from app.windows_storage_inspector import WindowsStorageInspectionError, _windows_apis, inspect_component


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows ACL and handle tests")


def private_dir(path, owner):
    kernel, advapi = _windows_apis()
    create = kernel.CreateDirectoryW
    create.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    create.restype = wintypes.BOOL
    with _creation_security(kernel, advapi, owner, directory=True) as attrs:
        if not create(str(path), attrs):
            raise ctypes.WinError(ctypes.get_last_error())


@pytest.fixture
def admitted(tmp_path):
    # Synthetic enrollment only. Real deployment must independently pin identities.
    owner = inspect_component(str(tmp_path), expected_kind="directory").owner
    path = tmp_path / "protected"
    private_dir(path, owner)
    chain = tuple(reversed(path.parents)) + (path,)
    pins = tuple(inspect_component(str(p), expected_kind="directory").identity for p in chain)
    ns = PrivateArchiveDirectory(str(path), owner_sid=owner, ancestors=pins)
    data = b"synthetic archive bytes"
    return path, ns, BackupArchive(data, sha256(data).digest()), owner, pins


def test_publishes_once_with_private_acl_and_verified_bytes(admitted):
    path, ns, artifact, owner, _ = admitted
    published = ns.publish(artifact)
    assert not published.reused and published.path.parent == path
    proof = inspect_component(str(published.path), expected_kind="file", owner_sid=owner,
                              require_private_acl=True)
    assert proof.owner == owner and proof.links == 1 and proof.untrusted_mutation is False
    assert ns.read(artifact.fingerprint) == artifact.data
    assert ns.publish(artifact).reused


def test_corruption_or_unexpected_file_acl_fails_closed(admitted):
    path, ns, artifact, _, _ = admitted
    final = path / ("memory-" + artifact.fingerprint.hex() + ".v2a")
    final.write_bytes(artifact.data)  # same correct digest, inherited rather than protected DACL
    with pytest.raises(PublicationUnconfirmed):
        ns.read(artifact.fingerprint)
    with pytest.raises(PublicationUnconfirmed):
        ns.publish(artifact)
    final.unlink()
    ns.publish(artifact)
    final.write_bytes(b"synthetic corruption")  # preserve the explicit ACL
    with pytest.raises(PublicationUnconfirmed):
        ns.read(artifact.fingerprint)


def test_wrong_or_replaced_archive_directory_denied(admitted):
    path, ns, artifact, owner, pins = admitted
    with pytest.raises(WindowsStorageInspectionError, match="archive_directory"):
        with ns.hold(path.parent):
            pytest.fail("Wrong directory was admitted")
    moved = path.with_name("original")
    with ns.hold(path):
        with pytest.raises(OSError):
            path.rename(moved)
    path.rename(moved)
    private_dir(path, owner)
    with pytest.raises(WindowsStorageInspectionError, match="archive_directory_identity"):
        with PrivateArchiveDirectory(str(path), owner_sid=owner, ancestors=pins).hold(path):
            pytest.fail("Replacement directory was admitted")
    with pytest.raises(PublicationUnconfirmed):
        ns.publish(artifact)


def test_rejects_inherited_directory_acl(tmp_path):
    root = tmp_path / "inherited"
    root.mkdir()
    owner = inspect_component(str(root), expected_kind="directory").owner
    chain = tuple(reversed(root.parents)) + (root,)
    pins = tuple(inspect_component(str(p), expected_kind="directory").identity for p in chain)
    ns = PrivateArchiveDirectory(str(root), owner_sid=owner, ancestors=pins)
    with pytest.raises(WindowsStorageInspectionError, match="private_acl"):
        with ns.hold(root):
            pytest.fail("Inherited directory ACL was admitted")


def test_refuses_real_junction_at_admitted_path(admitted):
    import _winapi

    path, ns, _, _, _ = admitted
    target = path.with_name("original")
    path.rename(target)
    _winapi.CreateJunction(str(target), str(path))
    try:
        assert path.is_junction()
        with pytest.raises(WindowsStorageInspectionError, match="reparse"):
            with ns.hold(path):
                pytest.fail("Junction was admitted")
    finally:
        path.rmdir()
    assert target.is_dir()


def test_refuses_real_hardlinked_archive(admitted):
    path, ns, artifact, _, _ = admitted
    published = ns.publish(artifact)
    os.link(published.path, path / "synthetic-alias")
    with pytest.raises(PublicationUnconfirmed):
        ns.read(artifact.fingerprint)


def test_refuses_replaced_file_between_identity_check_and_read(admitted, monkeypatch):
    path, ns, artifact, owner, _ = admitted
    final = ns.publish(artifact).path
    retired = path / "retired.v2a"
    replacement = path / "replacement.v2a"
    memory_windows_archive._create_private_file(replacement, artifact.data, owner)
    real_read = memory_windows_archive.read_pinned_artifact

    def swap_then_read(path, **kwargs):
        final.rename(retired)
        replacement.rename(final)
        return real_read(path, **kwargs)

    monkeypatch.setattr(memory_windows_archive, "read_pinned_artifact", swap_then_read)
    with pytest.raises(PublicationUnconfirmed):
        ns.read(artifact.fingerprint)
    assert retired.read_bytes() == final.read_bytes() == artifact.data


def test_private_archives_and_trusted_head_survive_reopen(admitted):
    path, ns, _, _, _ = admitted
    generation = uuid4()
    capsule = issue_receipt_key(generation)
    with closing(sqlite3.connect(":memory:")) as conn:
        MemoryLedger(conn, enabled=True, receipt_budget=8).initialize_empty(generation)
        genesis = build_archive(conn, capsule=capsule, approved_key_pin=capsule.fingerprint)
    old = ns.publish(genesis).path
    authority_path = path.parent / "synthetic-authority.sqlite"
    initial = Head(generation, 0, genesis.fingerprint)
    DurableHeadRegistry(lambda: sqlite3.connect(authority_path)).provision(initial)

    def reopen():
        authority = DurableHeadRegistry(
            lambda: sqlite3.connect(authority_path.as_uri() + "?mode=rw", uri=True)
        )
        backend = AuthorityArchiveBackend(authority, generation=generation,
                                          read_archive=ns.read, publish_archive=ns.publish)
        return authority, MemoryImageLedger(backend, receipt_budget=8)

    authority, ledger = reopen()
    guard = MemoryAccessGuard(enabled=True)
    headers = [("Host", guard.HOST), ("Origin", guard.ORIGIN), ("Content-Type", "application/json")]
    pair = guard.pair("POST", headers, guard.issue_pairing_challenge().secret)
    headers += [("Authorization", "Bearer " + pair.bearer_token), ("X-AI1-Memory-CSRF", pair.csrf_token)]
    operation = uuid4()

    def create(ledger):
        return ledger.mutate_authorized(guard, "POST", headers, generation=generation,
                                        operation_id=operation, kind="create", consent=True,
                                        text="synthetic C7 note")

    assert not create(ledger).replayed
    live = authority.read()
    assert live.revision == 1
    authority, ledger = reopen()
    assert create(ledger).replayed
    final = path / ("memory-" + live.digest.hex() + ".v2a")
    final.write_bytes(old.read_bytes())
    with pytest.raises(PublicationUnconfirmed):
        ledger.read(generation)
    assert authority.read() == live
