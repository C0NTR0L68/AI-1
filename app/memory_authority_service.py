"""Fixed SCM worker. Requires protected installer enrollment and a restricted account."""
from contextlib import ExitStack, closing, contextmanager
import ctypes
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from threading import Event, Thread
from uuid import UUID

# The SCM binary pins both trees and refuses extra files before spawning Python.
PAYLOAD = Path(__file__).absolute().parents[1]
INSTALL = PAYLOAD.parent
if __name__ == "__main__":
    sys.path.insert(0, str(PAYLOAD))

from app.memory_archive_v2 import build_archive
from app.memory_head_v2 import Head
from app.memory_keys_v2 import issue_receipt_key
from app.memory_authority_identity import READ_PIPE, WRITE_PIPE, _bind, _service_sid
from app.memory_ledger import MemoryLedger
from app.memory_service_pipe import SemanticMemory, _object, semantic_listener
from app.memory_storage_policy import FileIdentity
from app.memory_windows_archive import PrivateArchiveDirectory, _creation_security, _require_fixed_ntfs
from app.memory_write_v2 import ArchiveReducer, MemoryWriter
from app.windows_storage_inspector import (
    _sid_string, _validate_local_path, _windows_apis, hold_archive_directory,
    hold_component_evidence, inspect_component, read_pinned_artifact,
)


_LOCAL_USER = re.compile(r"S-1-5-21(?:-[0-9]{1,10}){4}\Z")


def require(value):
    if not value:
        raise ValueError("Authority admission refused")


def service_identity(kernel, adv):
    expected = _service_sid(kernel, adv)
    current = _bind(kernel, "GetCurrentProcess", W.HANDLE)
    open_token = _bind(adv, "OpenProcessToken", W.BOOL, W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE))
    query = _bind(adv, "GetTokenInformation", W.BOOL, W.HANDLE, ctypes.c_int, ctypes.c_void_p,
                  W.DWORD, ctypes.POINTER(W.DWORD))
    token = W.HANDLE()
    require(open_token(current(), 8, ctypes.byref(token)))
    try:
        def info(kind):
            size = W.DWORD()
            query(token, kind, None, 0, ctypes.byref(size))
            require(0 < size.value < 65536)
            buffer = ctypes.create_string_buffer(size.value)
            require(query(token, kind, buffer, size, ctypes.byref(size)))
            return buffer

        user = info(1)
        user_sid = ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p)).contents
        require(_sid_string(adv, kernel.LocalFree, user_sid) == expected)

        class Entry(ctypes.Structure):
            _fields_ = [("sid", ctypes.c_void_p), ("attributes", W.DWORD)]

        data = info(11)
        count = W.DWORD.from_buffer(data).value
        require(0 < count <= 256)

        class Groups(ctypes.Structure):
            _fields_ = [("count", W.DWORD), ("entries", Entry * count)]

        require(ctypes.sizeof(Groups) <= len(data))
        require(any(_sid_string(adv, kernel.LocalFree, entry.sid) == expected
                    for entry in Groups.from_buffer(data).entries))
    finally:
        require(kernel.CloseHandle(token))
    return expected


def _file(path, sid):
    evidence = inspect_component(str(path), expected_kind="file", owner_sid=sid, allow_service_owner=True)
    require(evidence.untrusted_mutation is False and evidence.links == 1)
    return evidence


def _bind_file(path, sid):
    return read_pinned_artifact(str(path), expected=_file(path, sid), max_bytes=16384,
                                require_private_acl=False)


def enrollment(kernel, sid):
    path = INSTALL / "authority-enrollment.json"
    require(_file(path, sid).owner == "S-1-5-18")
    for right in (2, 4, 0x10000, 0x40000, 0x80000):  # write, append, delete, WRITE_DAC, WRITE_OWNER
        handle = kernel.CreateFileW(str(path), right, 7, None, 3, 0x00200000, None)
        if handle not in (None, ctypes.c_void_p(-1).value):
            kernel.CloseHandle(handle)
            raise PermissionError("Service can mutate its enrollment")
        require(ctypes.get_last_error() == 5)
    config = json.loads(_bind_file(path, sid), object_pairs_hook=_object)
    require(type(config) is dict and config.keys() == {
        "version", "generation", "state", "pins", "reader_sid", "writer_sid",
        "client_integrity", "receipt_budget"
    } and type(config["version"]) is int and config["version"] == 1)
    generation = UUID(config["generation"])
    require(generation.int and str(generation) == config["generation"])
    require(_LOCAL_USER.fullmatch(config["reader_sid"]) and _LOCAL_USER.fullmatch(config["writer_sid"]))
    require(type(config["client_integrity"]) is int and config["client_integrity"] in (8192, 12288))
    require(type(config["receipt_budget"]) is int and 2 <= config["receipt_budget"] <= 1024)
    state = Path(config["state"])
    _validate_local_path(str(state))
    require(state.name == "authority")
    return config, generation, state


def _pins(data):
    return tuple(FileIdentity(volume, bytes.fromhex(native)) for volume, native in data)


@contextmanager
def pinned_state(state, pins, sid):
    chain = (*reversed(state.parents), state)
    require(len(pins) == len(chain))
    _require_fixed_ntfs(state.anchor)
    with ExitStack() as stack:
        for directory, pin in zip(chain[:-1], pins[:-1]):
            current = stack.enter_context(hold_component_evidence(str(directory), expected_kind="directory"))
            require(current.identity == pin)
        current = stack.enter_context(hold_archive_directory(str(state), owner_sid=sid,
                                                             require_private_acl=False, allow_service_owner=True))
        require(current.identity == pins[-1] and current.untrusted_mutation is False)
        yield


def run_worker(action):
    require(os.name == "nt" and action in ("serve", "provision"))
    kernel, adv = _windows_apis()
    sid = service_identity(kernel, adv)
    config, generation, state = enrollment(kernel, sid)
    parents = _pins(config["pins"])
    archive_dir, database, metadata = (state / name for name in ("archives", "head.sqlite3", "archive-pin.json"))
    fresh = action == "provision"
    with pinned_state(state, parents, sid):
        if fresh:
            require(not any(state.iterdir()))
            create = _bind(kernel, "CreateDirectoryW", W.BOOL, W.LPCWSTR, ctypes.c_void_p)
            with _creation_security(kernel, adv, sid, directory=True, allow_service_owner=True) as attrs:
                require(create(str(archive_dir), attrs))
            archive_id = inspect_component(str(archive_dir), expected_kind="directory").identity
            with metadata.open("x", encoding="ascii") as output:
                json.dump([archive_id.volume, archive_id.native_id.hex()], output)
                output.flush()
                os.fsync(output.fileno())
        else:
            archive_id, = _pins([json.loads(_bind_file(metadata, sid))])
        archives = PrivateArchiveDirectory(str(archive_dir), owner_sid=sid, ancestors=(*parents, archive_id),
                                           allow_service_owner=True)
        reducer = ArchiveReducer(archives, receipt_budget=config["receipt_budget"])

        def connect():
            admitted = _file(database, sid)
            require(admitted.identity.volume == parents[-1].volume)
            for suffix in ("-wal", "-shm", "-journal"):
                candidate = database.with_name(database.name + suffix)
                try:
                    candidate.lstat()
                except FileNotFoundError:
                    continue
                require(suffix == "-journal" and _file(candidate, sid).identity.volume == parents[-1].volume)
            return sqlite3.connect(database.as_uri() + "?mode=rw", uri=True, timeout=1)

        writer = MemoryWriter(connect, reducer=reducer, enabled=True)
        if fresh:
            key = issue_receipt_key(generation)
            with closing(sqlite3.connect(":memory:")) as conn:
                MemoryLedger(conn, enabled=True, receipt_budget=config["receipt_budget"]).initialize_empty(generation)
                initial = build_archive(conn, capsule=key, approved_key_pin=key.fingerprint)
            archives.publish(initial)
            database.touch(exist_ok=False)
            writer.provision(Head(generation, 0, initial.fingerprint))
        current = writer.head()
        require(current.generation == generation)
        reducer.read(current)
        semantic = SemanticMemory(writer, reducer)
        options = dict(server_sid=sid, handler=semantic.execute, integrity=config["client_integrity"], timeout=5)
        with (semantic_listener(READ_PIPE, client_sid=config["reader_sid"], **options) as read,
              semantic_listener(WRITE_PIPE, client_sid=config["writer_sid"], writable=True, **options) as write):
            stop = Event()
            Thread(target=lambda: (sys.stdin.readline(), stop.set()), daemon=True).start()
            print("READY", flush=True)
            while not stop.is_set():
                read(0.25)
                if not stop.is_set():
                    write(0.25)


if __name__ == "__main__":
    try:
        run_worker(*sys.argv[1:])
    except Exception as error:
        print(type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
