"""Pure chain orchestration tests; no access to D:."""
from contextlib import contextmanager
from dataclasses import replace
import ctypes
import os

import pytest

from app import windows_storage_inspector as inspector
from app.memory_storage_policy import FileIdentity, HandleEvidence, MEMORY_PATH, StoragePolicyDenied


@pytest.mark.parametrize("failure", [None, "chain", "sidecar", "access"])
def test_chain_retains_ancestors_and_cleans_in_reverse(monkeypatch, failure):
    calls, seen = [], []
    owner = "S-1-5-21-1-2-3-1000"
    volume = "synthetic-volume"

    @contextmanager
    def hold(path, **options):
        i = len(seen) + 1
        seen.append(path)
        calls.append(("open", path, options["require_private_acl"]))
        item = HandleEvidence(path, options["expected_kind"], FileIdentity(volume, bytes([i]) * 16),
                              False, False, owner, frozenset((owner, "S-1-5-18")), 1)
        try:
            yield replace(item, reparse=True) if i == 2 and failure == "chain" else item
        finally:
            calls.append(("close", path))

    def sidecars(path):
        assert path == MEMORY_PATH
        assert len(seen) == 5 and not any(row[0] == "close" for row in calls)
        if failure == "access":
            raise PermissionError("synthetic")
        return failure != "sidecar"

    monkeypatch.setattr(inspector, "hold_component_evidence", hold)
    monkeypatch.setattr(inspector, "_sidecars_absent", sidecars)
    args = dict(owner_sid=owner, observed_volume=volume, pinned_volume=volume, fixed_local_ntfs=True,
                protected_identities=frozenset((FileIdentity(volume, b"\x08" * 16),)))
    if failure:
        with pytest.raises((StoragePolicyDenied, inspector.WindowsStorageInspectionError)):
            inspector.inspect_memory_chain(**args)
    else:
        assert inspector.inspect_memory_chain(**args) is None
    assert [row[1] for row in calls if row[0] == "close"] == seen[::-1]
    if failure == "chain":
        assert len(seen) == 2
    else:
        assert [row[2] for row in calls if row[0] == "open"] == [False, False, False, True, True]


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-sharing check")
def test_held_file_blocks_delete_access_until_released(tmp_path):
    path = tmp_path / "only-synthetic.txt"
    path.write_bytes(b"synthetic")
    kernel, _ = inspector._windows_apis()

    def open_delete():
        # Request access, without renaming or deleting anything.
        handle = kernel.CreateFileW(str(path), 0x10000, 7, None, 3, 0, None)
        error = ctypes.get_last_error()
        if handle != inspector._INVALID_HANDLE_VALUE and handle is not None:
            assert kernel.CloseHandle(handle)
            return 0
        return error

    assert open_delete() == 0
    with inspector.hold_component_evidence(str(path), expected_kind="file") as evidence:
        assert evidence.links == 1
        assert open_delete() == 32
    assert open_delete() == 0
    assert path.read_bytes() == b"synthetic"


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_sidecar_probe_uses_lstat_without_needing_a_link_privilege(monkeypatch, suffix):
    visited = []
    def lstat(path):
        visited.append(path)
        if path == "synthetic.sqlite3" + suffix:
            # Entry metadata exists; the target is intentionally not inspected.
            return object()
        raise FileNotFoundError()
    monkeypatch.setattr(inspector.os, "lstat", lstat)
    assert not inspector._sidecars_absent("synthetic.sqlite3")
    assert visited[-1] == "synthetic.sqlite3" + suffix
