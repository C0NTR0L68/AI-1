"""Pure C7 policy prototype. It never opens a path or grants a storage handle.

Only a future trusted Windows inspector can supply facts obtained from live
handles and effective ACL analysis. A successful policy evaluation alone does
not authorize SQLite, DPAPI, provisioning, restore, or runtime activation.
"""
from dataclasses import dataclass
import re


MEMORY_PATH = r"D:\AI-1\data\memory\notes-v2.sqlite3"
_DIRECTORIES = ("D:\\", r"D:\AI-1", r"D:\AI-1\data", r"D:\AI-1\data\memory")
_SYSTEM = "S-1-5-18"
_OWNER = re.compile(r"S-1-5-21(?:-(?:0|[1-9][0-9]{0,9})){4}")


class StoragePolicyDenied(PermissionError):
    """Stable diagnostic category without paths, ACLs or account information."""


@dataclass(frozen=True)
class FileIdentity:
    volume: str
    native_id: bytes


@dataclass(frozen=True)
class HandleEvidence:
    final_path: str
    kind: str
    identity: FileIdentity
    reparse: bool | None
    untrusted_mutation: bool | None
    owner: str | None = None
    # This set must be derived by a native inspector that rejects unknown ACEs,
    # NULL DACLs, unexpected rights and insufficient inheritance/protection.
    private_acl_principals: frozenset[str] | None = None
    links: int | None = None


def _known_identity(value):
    return (type(value) is FileIdentity and type(value.volume) is str and bool(value.volume)
            and type(value.native_id) is bytes and len(value.native_id) == 16
            and any(value.native_id))


def evaluate_existing_notes(*, path, owner_sid, observed_volume, pinned_volume,
                            fixed_local_ntfs, chain, protected_identities, sidecars_absent):
    """Check already collected evidence for the exact existing store candidate.

    protected_identities must come from a complete inspected inventory including
    configured chat and protected backups. None means incomplete. Handles and
    any live guarantees remain the responsibility of the future inspector.
    """
    if type(path) is not str or path != MEMORY_PATH:
        raise StoragePolicyDenied("target")
    if (fixed_local_ntfs is not True or type(pinned_volume) is not str or not pinned_volume
            or type(observed_volume) is not str or observed_volume != pinned_volume):
        raise StoragePolicyDenied("volume")
    if (type(owner_sid) is not str or not _OWNER.fullmatch(owner_sid)
            or any(int(part) > 2**32 - 1 for part in owner_sid.split("-")[-4:])):
        raise StoragePolicyDenied("owner")
    if (type(protected_identities) is not frozenset or not protected_identities
            or not all(_known_identity(i) for i in protected_identities)):
        raise StoragePolicyDenied("protected_identity")
    if sidecars_absent is not True:
        raise StoragePolicyDenied("sidecars")
    expected = (*_DIRECTORIES, MEMORY_PATH)
    if type(chain) is not tuple or len(chain) != len(expected):
        raise StoragePolicyDenied("chain")
    seen = set()
    for index, (item, final) in enumerate(zip(chain, expected)):
        db = index == len(_DIRECTORIES)
        if (type(item) is not HandleEvidence or item.final_path != final
                or item.kind != ("file" if db else "directory")
                or item.reparse is not False or item.untrusted_mutation is not False
                or not _known_identity(item.identity) or item.identity.volume != observed_volume
                or item.identity in seen):
            raise StoragePolicyDenied("component")
        seen.add(item.identity)
        if index >= len(_DIRECTORIES) - 1 and (
            item.owner != owner_sid or type(item.private_acl_principals) is not frozenset
            or item.private_acl_principals != frozenset((owner_sid, _SYSTEM))
        ):
            raise StoragePolicyDenied("private_acl")
        if db and (type(item.links) is not int or item.links != 1 or item.identity in protected_identities):
            raise StoragePolicyDenied("file_identity")
