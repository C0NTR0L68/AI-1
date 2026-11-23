"""Snapshot proof for an explicitly stopped, disposable SCM fixture."""
from contextlib import closing
from hashlib import sha256
import ctypes
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import sqlite3
from uuid import UUID

from app.memory_archive_v2 import open_archived_state
from app.memory_crypto import unprotect_for_current_user
from app.memory_head_v2 import Head
from app.memory_ledger import MemoryLedger
from app.memory_write_v2 import _SCHEMA
from app.windows_storage_inspector import _windows_apis, inspect_component, read_pinned_artifact


def require(value):
    if not value:
        raise AssertionError("Synthetic backup invariant failed")


def profile_probe(state, sid):
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    resolve = shell.SHGetFolderPathW
    resolve.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint, ctypes.c_wchar_p]
    resolve.restype = ctypes.c_long
    path = ctypes.create_unicode_buffer(260)
    code = resolve(None, 0x001A, None, 0, path)  # CSIDL_APPDATA for the actual service token
    key_root = Path(path.value) / "Microsoft" / "Protect" / sid if code == 0 else None
    (state / "profile-location.json").write_text(json.dumps({
        "sid": sid, "resolve_hresult": code, "key_root": str(key_root) if key_root else None,
    }), encoding="ascii")


def _profile_root(state, sid):
    location = json.loads((state / "profile-location.json").read_bytes())
    dedicated = (Path(r"C:\Windows\ServiceProfiles\AI1MemoryAuthority"),
                 Path(r"C:\Users\AI1MemoryAuthority"))
    expected = {root / "AppData" / "Roaming" / "Microsoft" / "Protect" / sid for root in dedicated}
    require(location["sid"] == sid and location["resolve_hresult"] == 0)
    source = Path(location["key_root"])
    require(source in expected)
    return source


def snapshot_profile(state, sid):
    """Copy only the disposable service's known DPAPI profile members."""
    source = _profile_root(state, sid)
    for directory in (*reversed(source.parents), source):
        inspect_component(str(directory), expected_kind="directory")
    require(inspect_component(str(source), expected_kind="directory").owner in (sid, "S-1-5-18"))
    members = tuple(source.iterdir())
    require(1 <= len(members) <= 64)
    backup = state / "profile-backup"
    backup.mkdir()
    pins = {}
    for member in members:
        require(re.fullmatch(r"(?i:preferred|credhist|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})", member.name))
        data = _read_bound(member)
        require(len(data) <= 1024 * 1024)
        with (backup / member.name).open("xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        pins[member.name] = sha256(data).hexdigest()
    (state / "profile-backup-pins.json").write_text(json.dumps(pins), encoding="ascii")
    return 42


def restore_profile(state, sid):
    """Exercise the backup operator privilege only inside the disposable guest."""
    key_root = _profile_root(state, sid)
    require(not key_root.exists() and not key_root.is_symlink())
    for directory in reversed(key_root.parents):
        inspect_component(str(directory), expected_kind="directory")
    pins = json.loads((state / "profile-backup-pins.json").read_bytes())
    descriptors = json.loads((state / "profile-security.json").read_bytes())
    require(descriptors.keys() == {"root", "files"} and descriptors["files"].keys() == pins.keys())
    require(1 <= len(pins) <= 64)
    kernel, adv = _windows_apis()

    def bind(dll, name, result, *arguments):
        function = getattr(dll, name)
        function.argtypes, function.restype = arguments, result
        return function

    class Luid(ctypes.Structure):
        _fields_ = [("low", W.DWORD), ("high", W.LONG)]

    class Privilege(ctypes.Structure):
        _fields_ = [("size", W.DWORD), ("luid", Luid), ("attributes", W.DWORD)]

    current = bind(kernel, "GetCurrentProcess", W.HANDLE)
    open_token = bind(adv, "OpenProcessToken", W.BOOL, W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE))
    lookup = bind(adv, "LookupPrivilegeValueW", W.BOOL, W.LPCWSTR, W.LPCWSTR, ctypes.POINTER(Luid))
    adjust = bind(adv, "AdjustTokenPrivileges", W.BOOL, W.HANDLE, W.BOOL, ctypes.POINTER(Privilege),
                  W.DWORD, ctypes.c_void_p, ctypes.c_void_p)
    convert = bind(adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", W.BOOL, W.LPCWSTR,
                   W.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p)
    set_security = bind(adv, "SetFileSecurityW", W.BOOL, W.LPCWSTR, W.DWORD, ctypes.c_void_p)
    token = W.HANDLE()
    if not open_token(current(), 0x20, ctypes.byref(token)):  # TOKEN_ADJUST_PRIVILEGES
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        luid = Luid()
        if not lookup(None, "SeRestorePrivilege", ctypes.byref(luid)):
            raise ctypes.WinError(ctypes.get_last_error())
        enabled = Privilege(1, luid, 2)
        if not adjust(token, False, ctypes.byref(enabled), 0, None, None) or ctypes.get_last_error() != 0:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(token)

    def apply(path, sddl):
        descriptor = ctypes.c_void_p()
        if type(sddl) is not str or len(sddl) > 8192 or not convert(sddl, 1, ctypes.byref(descriptor), None):
            raise ValueError("Profile descriptor unavailable")
        try:
            if not set_security(str(path), 7, descriptor):  # OWNER | GROUP | DACL
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.LocalFree(descriptor)

    key_root.mkdir()
    apply(key_root, descriptors["root"])
    for name, digest in pins.items():
        require(re.fullmatch(r"(?i:preferred|credhist|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})", name))
        data = _read_bound(state / "profile-backup" / name)
        require(sha256(data).hexdigest() == digest)
        destination = key_root / name
        with destination.open("xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        apply(destination, descriptors["files"][name])
        require(sha256(_read_bound(destination)).hexdigest() == digest)
    return 42


def _rows(path):
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            path.with_name(path.name + suffix).lstat()
        except FileNotFoundError:
            continue
        raise ValueError("Snapshot has a SQLite sidecar")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as database:
        database.execute("PRAGMA query_only=ON")
        database.execute("PRAGMA trusted_schema=OFF")
        require(database.execute("PRAGMA integrity_check").fetchall() == [("ok",)])
        require(database.execute(
            "SELECT type, name, sql FROM sqlite_schema ORDER BY type, name").fetchall() == _SCHEMA)
        rows = database.execute(
            "SELECT generation, revision, digest, operation, binding FROM memory_commits ORDER BY revision").fetchall()
    require(len(rows) == 2 and rows[0][0] == rows[1][0] and [row[1] for row in rows] == [0, 1])
    require(rows[0][3:] == (None, None) and len(rows[1][3]) == 16 and len(rows[1][4]) == 32)
    return rows


def _read_bound(path):
    evidence = inspect_component(str(path), expected_kind="file")
    return read_pinned_artifact(str(path), expected=evidence, max_bytes=16*1024*1024,
                                require_private_acl=False)


def snapshot(state):
    """Never replace the original. Only known committed members are exported."""
    require(os.name == "nt" and state.parent.parent == Path(r"C:\Program Files")
            and re.fullmatch("AI1-C7-[a-f0-9]{32}", state.parent.name) and state.name == "state")
    database = state / "head.sqlite3"
    rows = _rows(database)
    members = {"head.sqlite3": _read_bound(database)}
    for _, _, digest, _, _ in rows:
        name = "memory-" + digest.hex() + ".v2a"
        data = _read_bound(state / "archives" / name)
        require(sha256(data).digest() == digest)
        members[name] = data
    partial, backup, restore = (state / name for name in ("backup.pending", "backup", "recovered"))
    require(not backup.exists() and not restore.exists())
    partial.mkdir()
    pins = {name: sha256(data).hexdigest() for name, data in members.items()}
    for name, data in members.items():
        with (partial / name).open("xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    manifest = json.dumps(pins, sort_keys=True).encode("ascii")
    with (partial / "manifest.json").open("xb") as output:
        output.write(manifest)
        output.flush()
        os.fsync(output.fileno())
    require(_rows(partial / "head.sqlite3") == rows)
    partial.rename(backup)
    restore.mkdir()
    for name, pin in pins.items():
        data = _read_bound(backup / name)
        require(sha256(data).hexdigest() == pin)
        with (restore / name).open("xb") as output:
            output.write(data)
    require(_rows(restore / "head.sqlite3") == rows)
    (restore / "manifest.json").write_bytes(manifest)
    (state / "snapshot-head.json").write_text(
        json.dumps([str(UUID(bytes=rows[-1][0])), rows[-1][1], rows[-1][2].hex()]), encoding="ascii")
    return 42


def verify_restored(state, live, *, budget):
    restore = state / "recovered"
    rows = _rows(restore / "head.sqlite3")
    expected = Head(UUID(bytes=rows[-1][0]), rows[-1][1], rows[-1][2])
    require(expected == live and expected.revision == 1)
    pins = json.loads((restore / "manifest.json").read_bytes())
    names = {("memory-" + row[2].hex() + ".v2a") for row in rows}
    require(pins.keys() == names | {"head.sqlite3"})
    for name, pin in pins.items():
        require(sha256(_read_bound(restore / name)).hexdigest() == pin)
    for row in rows:
        data = _read_bound(restore / ("memory-" + row[2].hex() + ".v2a"))
        with open_archived_state(data, approved_archive_pin=row[2]) as (conn, generation, _):
            require(generation == live.generation)
            ledger = MemoryLedger(conn, enabled=True, receipt_budget=budget)
            if row[1] == 0:
                require(ledger.read(generation) == ())
            else:
                note, = ledger.read(generation)
                require(unprotect_for_current_user(note.sealed).decode("utf8") == "мой тестовый код — 12345")
                receipt = ledger.snapshot(UUID(bytes=row[3])).receipt
                require(receipt is not None and receipt.identity.binding == row[4])
