import os

import pytest
import app.windows_storage_inspector as inspector

from app.memory_storage_policy import HandleEvidence
from app.windows_storage_inspector import (
    WindowsStorageInspectionError,
    inspect_component,
)


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Uses native Windows security APIs")


def test_native_inspector_returns_policy_evidence_for_synthetic_file(tmp_path):
    path = tmp_path / "synthetic-notes.txt"
    path.write_bytes(b"synthetic-only")

    evidence = inspect_component(str(path), expected_kind="file")

    assert type(evidence) is HandleEvidence
    assert evidence.kind == "file"
    assert evidence.final_path == str(path)
    assert evidence.reparse is False
    assert evidence.links == 1
    assert evidence.identity.volume.startswith("\\\\?\\Volume{")
    assert len(evidence.identity.native_id) == 16
    assert any(evidence.identity.native_id)
    assert evidence.owner and evidence.owner.startswith("S-1-")
    assert (
        evidence.untrusted_mutation is None
        or type(evidence.untrusted_mutation) is bool
    )
    assert (
        evidence.private_acl_principals is None
        or type(evidence.private_acl_principals) is frozenset
    )

    owner_bound = inspect_component(
        str(path), expected_kind="file", owner_sid=evidence.owner
    )
    assert owner_bound.identity == evidence.identity
    assert owner_bound.untrusted_mutation is not None


def test_native_inspector_requires_private_acl_proof_for_temp_file(tmp_path):
    path = tmp_path / "inherited-acl.txt"
    path.write_bytes(b"synthetic-only")
    evidence = inspect_component(str(path), expected_kind="file")
    assert evidence.owner is not None

    with pytest.raises(WindowsStorageInspectionError, match="^private_acl$"):
        inspect_component(
            str(path),
            expected_kind="file",
            owner_sid=evidence.owner,
            require_private_acl=True,
        )


def test_native_inspector_rejects_reparse_point_created_in_temp_directory(tmp_path):
    target = tmp_path / "synthetic-target.txt"
    target.write_bytes(b"synthetic-only")
    link = tmp_path / "synthetic-link.txt"
    try:
        os.symlink(str(target), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("Creating a temporary symlink is unavailable in this Windows environment")

    with pytest.raises(WindowsStorageInspectionError) as error:
        inspect_component(str(link), expected_kind="file")
    assert error.value.reason in {"open", "reparse"}


def test_native_inspector_reports_hardlink_count(tmp_path):
    path = tmp_path / "synthetic.dat"
    alias = tmp_path / "synthetic-alias.dat"
    path.write_bytes(b"synthetic-only")
    os.link(path, alias)
    first = inspect_component(str(path), expected_kind="file")
    second = inspect_component(str(alias), expected_kind="file")
    assert first.identity == second.identity
    assert first.links == second.links == 2


@pytest.mark.parametrize("attributes_succeed", [True, False])
def test_close_failure_prevents_evidence_and_preserves_primary(monkeypatch, attributes_succeed):
    calls = []

    class Kernel:
        def CreateFileW(self, *args):
            return 123

        def GetFileInformationByHandleEx(self, handle, kind, output, size):
            if kind == inspector._FILE_ATTRIBUTE_TAG_INFO_CLASS:
                return attributes_succeed
            if kind == inspector._FILE_ID_INFO_CLASS:
                output._obj.FileId.Identifier[0] = 1
            return True

        def CloseHandle(self, handle):
            calls.append(handle)
            return False

    monkeypatch.setattr(inspector, "_windows_apis", lambda: (Kernel(), None))
    monkeypatch.setattr(inspector, "_final_path", lambda kernel, handle, flag:
                        "\\\\?\\Volume{synthetic}\\test.txt" if flag else "\\\\?\\C:\\test.txt")
    monkeypatch.setattr(inspector, "_read_acl", lambda *args: (None, None, None, False))
    with pytest.raises(WindowsStorageInspectionError) as error:
        inspect_component("C:\\test.txt", expected_kind="file")
    assert error.value.reason == ("release" if attributes_succeed else "attributes")
    assert calls == [123]


def test_inspector_does_not_report_unproven_acl_as_private(monkeypatch, tmp_path):
    path = tmp_path / "synthetic.dat"
    path.write_bytes(b"synthetic-only")
    guessed_principals = frozenset(("S-1-5-18", "S-1-5-21-1-2-3-1000"))
    monkeypatch.setattr(inspector, "_read_acl", lambda *args: (None, guessed_principals, False, False))
    evidence = inspect_component(str(path), expected_kind="file")
    assert evidence.private_acl_principals is None


@pytest.mark.parametrize("path", [
    r"C:\synthetic\CON.txt", r"C:\synthetic\LPT²", "C:\\synthetic\\notes. ",
    r"C:\synthetic\\notes", r"C:\synthetic\notes:stream", r"C:\synthetic\..\notes",
    r"\\?\C:\synthetic\notes", r"C:\synthetic\notes?.txt",
])
def test_ambiguous_path_is_refused_before_native_open(monkeypatch, path):
    def unexpected():
        pytest.fail("native inspection reached for an ambiguous path")
    monkeypatch.setattr(inspector, "_windows_apis", unexpected)
    with pytest.raises(WindowsStorageInspectionError, match="^path$"):
        inspect_component(path, expected_kind="file")
