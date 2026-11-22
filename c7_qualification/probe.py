"""Exercise C7 against an offline, disposable Windows Sandbox parcel."""

import argparse
from contextlib import closing
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from uuid import uuid4


def require(condition):
    if not condition:
        raise AssertionError("C7 invariant failed")


def private_directory(path, owner):
    from app.memory_windows_archive import _creation_security
    from app.windows_storage_inspector import _windows_apis

    kernel, advapi = _windows_apis()
    create = kernel.CreateDirectoryW
    create.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    create.restype = wintypes.BOOL
    with _creation_security(kernel, advapi, owner, directory=True) as attrs:
        if not create(str(path), attrs):
            raise ctypes.WinError(ctypes.get_last_error())


def namespace(path, owner):
    from app.memory_windows_archive import PrivateArchiveDirectory
    from app.windows_storage_inspector import inspect_component

    chain = (*reversed(path.parents), path)
    pins = tuple(inspect_component(str(item), expected_kind="directory").identity for item in chain)
    return PrivateArchiveDirectory(str(path), owner_sid=owner, ancestors=pins)


def ledger_for(authority, archives, generation):
    from app.memory_head_v2 import AuthorityArchiveBackend
    from app.memory_image_ledger import MemoryImageLedger

    backend = AuthorityArchiveBackend(authority, generation=generation,
                                      read_archive=archives.read, publish_archive=archives.publish)
    return MemoryImageLedger(backend, receipt_budget=8)


def prepare(scratch):
    from app.memory_archive_v2 import build_archive
    from app.memory_head_v2 import DurableHeadRegistry, Head
    from app.memory_keys_v2 import issue_receipt_key
    from app.memory_ledger import MemoryLedger
    from app.memory_security import MemoryAccessGuard
    from app.memory_windows_archive import _create_private_file
    from app.windows_storage_inspector import inspect_component

    owner = os.environ["AI1_C7_OWNER"]
    path = scratch / "archives"
    head_path = scratch / "authority"
    private_directory(path, owner)
    private_directory(head_path, owner)
    archives = namespace(path, owner)
    generation = uuid4()
    capsule = issue_receipt_key(generation)
    with closing(sqlite3.connect(":memory:")) as conn:
        MemoryLedger(conn, enabled=True, receipt_budget=8).initialize_empty(generation)
        genesis = build_archive(conn, capsule=capsule, approved_key_pin=capsule.fingerprint)
    archives.publish(genesis)

    db = head_path / "head.sqlite"
    _create_private_file(db, b"", owner)
    inspect_component(str(db), expected_kind="file", owner_sid=owner, require_private_acl=True)

    def open_existing():
        return sqlite3.connect(db.as_uri() + "?mode=rw", uri=True)

    authority = DurableHeadRegistry(open_existing)
    authority.provision(Head(generation, 0, genesis.fingerprint))
    guard = MemoryAccessGuard(enabled=True)
    headers = [("Host", guard.HOST), ("Origin", guard.ORIGIN), ("Content-Type", "application/json")]
    pair = guard.pair("POST", headers, guard.issue_pairing_challenge().secret)
    headers += [("Authorization", "Bearer " + pair.bearer_token), ("X-AI1-Memory-CSRF", pair.csrf_token)]
    operation = uuid4()

    def create(ledger):
        return ledger.mutate_authorized(guard, "POST", headers, generation=generation,
                                        operation_id=operation, kind="create", consent=True,
                                        text="synthetic acceptance note")

    require(not create(ledger_for(authority, archives, generation)).replayed)
    head = authority.read()
    require(head.revision == 1 and head.generation == generation)
    require(head.digest != genesis.fingerprint)
    require(create(ledger_for(DurableHeadRegistry(open_existing), namespace(path, owner), generation)).replayed)
    require(DurableHeadRegistry(open_existing).read() == head)
    guard.disable()
    with (scratch / "synthetic-proof.json").open("x", encoding="ascii") as stream:
        json.dump({"digest": head.digest.hex(), "generation": str(generation)}, stream)


def digest_and_archive(scratch):
    from uuid import UUID

    with (scratch / "synthetic-proof.json").open(encoding="ascii") as stream:
        state = json.load(stream)
    require(type(state["digest"]) is str and re.fullmatch("[0-9a-f]{64}", state["digest"]) is not None)
    digest = bytes.fromhex(state["digest"])
    return digest, UUID(state["generation"]), scratch / "archives" / ("memory-" + state["digest"] + ".v2a")


def verify_reopened(scratch):
    from app.memory_crypto import unprotect_for_current_user
    from app.memory_head_v2 import DurableHeadRegistry, Head, HeadUnavailable
    from app.windows_storage_inspector import inspect_component

    digest, generation, file = digest_and_archive(scratch)
    db = scratch / "authority" / "head.sqlite"
    owner = inspect_component(str(file.parent), expected_kind="directory").owner
    archives = namespace(file.parent, owner)
    authority = DurableHeadRegistry(lambda: sqlite3.connect(db.as_uri() + "?mode=rw", uri=True))
    require(authority.read() == Head(generation, 1, digest))
    require(archives.read(digest) == file.read_bytes())
    notes = ledger_for(authority, archives, generation).read(generation)
    require(len(notes) == 1 and unprotect_for_current_user(notes[0].sealed) == b"synthetic acceptance note")

    unavailable = db.with_name("absent.sqlite")
    empty = DurableHeadRegistry(lambda: sqlite3.connect(unavailable.as_uri() + "?mode=rw", uri=True))
    try:
        ledger_for(empty, archives, generation).read(generation)
    except HeadUnavailable:
        require(not unavailable.exists())
    else:
        raise AssertionError("ledger accepted an absent authority")


def make_links(scratch):
    """A separate Sandbox SYSTEM process only materializes owned fixtures."""
    _, _, final = digest_and_archive(scratch)
    target = final.with_name("original.v2a")
    require(final.is_file() and not final.is_symlink())
    final.rename(target)
    try:
        os.symlink(target, final)
    except OSError:
        target.rename(final)
        raise
    os.symlink(scratch / "archives", scratch / "archive-directory-link", target_is_directory=True)
    require(final.is_symlink() and (scratch / "archive-directory-link").is_symlink())


def reject_links(scratch):
    from app.memory_archive_publish_v2 import PublicationUnconfirmed
    from app.memory_head_v2 import DurableHeadRegistry, Head
    from app.windows_storage_inspector import WindowsStorageInspectionError, inspect_component

    digest, generation, final = digest_and_archive(scratch)
    db = scratch / "authority" / "head.sqlite"
    authority = DurableHeadRegistry(lambda: sqlite3.connect(db.as_uri() + "?mode=rw", uri=True))
    expected = Head(generation, 1, digest)
    require(authority.read() == expected)
    owner = inspect_component(str(final.parent), expected_kind="directory").owner
    archives = namespace(final.parent, owner)
    for link, kind in ((final, "file"), (scratch / "archive-directory-link", "directory")):
        require(link.is_symlink())
        try:
            inspect_component(str(link), expected_kind=kind)
        except WindowsStorageInspectionError as error:
            require(error.reason == "reparse")
        else:
            raise AssertionError("native symlink admitted")
    try:
        ledger_for(authority, archives, generation).read(generation)
    except PublicationUnconfirmed as error:
        require(str(error) == "archive_publication_unconfirmed")
    else:
        raise AssertionError("ledger accepted symlink at authoritative digest")
    require(authority.read() == expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    cases = {"prepare": prepare, "verify-reopened": verify_reopened,
             "make-links": make_links, "reject-links": reject_links}
    parser.add_argument("mode", choices=cases)
    args = parser.parse_args()
    payload = Path(__file__).resolve().parent
    parcel = payload.parent
    require(os.name == "nt" and payload.name == "payload")
    require(parcel.parent == Path(r"C:\Users\Public\Documents"))
    require(re.fullmatch("AI1-C7-[0-9a-f]{32}", parcel.name) is not None)
    scratch = parcel / "scratch"
    if args.mode == "prepare":
        require(os.getlogin().casefold() == "wdagutilityaccount")
        scratch.mkdir()
    elif args.mode != "make-links":
        require(os.getlogin().casefold() == "wdagutilityaccount")
    require(scratch.is_dir() and not scratch.is_symlink() and not scratch.is_junction())
    sys.path.insert(0, str(payload))
    try:
        cases[args.mode](scratch)
    except OSError as error:
        if args.mode == "make-links" and getattr(error, "winerror", None) == 1314:
            return 71
        raise
    return 42


if __name__ == "__main__":
    raise SystemExit(main())
