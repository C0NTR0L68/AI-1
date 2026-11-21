"""Pure constructed evidence, treating native facts as unverified in this lane."""
from dataclasses import replace

import pytest

from app.memory_storage_policy import (
    FileIdentity, HandleEvidence, MEMORY_PATH, StoragePolicyDenied, evaluate_existing_notes,
)


def identity(number, volume="synthetic-volume"):
    return FileIdentity(volume, number.to_bytes(16, "big"))


@pytest.fixture
def evidence():
    owner = "S-1-5-21-100-200-300-1000"
    paths = ("D:\\", "D:\\AI-1", "D:\\AI-1\\data", "D:\\AI-1\\data\\memory", MEMORY_PATH)
    handles = tuple(HandleEvidence(path, "file" if i == 4 else "directory",
                                   identity(i + 1), False, False, owner,
                                   frozenset((owner, "S-1-5-18")), 1)
                    for i, path in enumerate(paths))
    return dict(path=MEMORY_PATH, owner_sid=owner, observed_volume="synthetic-volume",
                pinned_volume="synthetic-volume", fixed_local_ntfs=True, chain=handles,
                protected_identities=frozenset((identity(8), identity(9, "other-volume"))),
                sidecars_absent=True)


def test_complete_policy_evidence_does_not_return_handle(evidence):
    assert evaluate_existing_notes(**evidence) is None


@pytest.mark.parametrize(("key", "value", "reason"), [
    ("path", "C:\\memory.sqlite3", "target"),
    ("path", MEMORY_PATH + ":stream", "target"),
    ("path", MEMORY_PATH.lower(), "target"),
    ("fixed_local_ntfs", None, "volume"),
    ("fixed_local_ntfs", 1, "volume"),
    ("observed_volume", "unapproved", "volume"),
    ("owner_sid", "S-1-5-21-unverified", "owner"),
    ("protected_identities", None, "protected_identity"),
    ("protected_identities", frozenset((identity(5),)), "file_identity"),
    ("sidecars_absent", None, "sidecars"),
    ("sidecars_absent", False, "sidecars"),
    ("chain", (), "chain"),
])
def test_unknown_or_mismatched_input_denies(evidence, key, value, reason):
    evidence[key] = value
    with pytest.raises(StoragePolicyDenied, match=f"^{reason}$"):
        evaluate_existing_notes(**evidence)


@pytest.mark.parametrize(("index", "changes", "reason"), [
    (1, {"reparse": True}, "component"),
    (1, {"reparse": None}, "component"),
    (2, {"untrusted_mutation": True}, "component"),
    (2, {"untrusted_mutation": None}, "component"),
    (2, {"final_path": "D:\\elsewhere"}, "component"),
    (3, {"owner": "S-1-5-18"}, "private_acl"),
    (3, {"private_acl_principals": None}, "private_acl"),
    (4, {"identity": identity(5, "other-volume")}, "component"),
    (4, {"identity": identity(1)}, "component"),
    (4, {"links": True}, "file_identity"),
    (4, {"links": 2}, "file_identity"),
])
def test_component_identity_acl_and_links_fail_closed(evidence, index, changes, reason):
    chain = list(evidence["chain"])
    chain[index] = replace(chain[index], **changes)
    evidence["chain"] = tuple(chain)
    with pytest.raises(StoragePolicyDenied, match=f"^{reason}$"):
        evaluate_existing_notes(**evidence)
