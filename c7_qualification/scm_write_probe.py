"""Disposable SCM write exercise. Never imported by the LOCAL launcher."""
from contextlib import closing
import ctypes
from ctypes import wintypes
import json
import os
import sqlite3
from time import monotonic
from uuid import UUID, uuid5

from app.memory_archive_v2 import build_archive
from app.memory_authority_pipe import _receive, _send
from app.memory_commands import MemoryAction, parse_memory_command
from app.memory_head_v2 import Head, HeadUnavailable
from app.memory_keys_v2 import issue_receipt_key
from app.memory_ledger import MemoryLedger
from app.memory_service_pipe import SemanticMemory, SemanticPipeClient, pack_head, semantic_listener, unpack_head
from app.memory_storage_policy import FileIdentity
from app.memory_windows_archive import PrivateArchiveDirectory, _creation_security
from app.memory_write_v2 import ArchiveReducer, MemoryWriter, Mutation, WriteRefused
from app.windows_storage_inspector import _windows_apis, inspect_component


def require(value):
    if not value:
        raise AssertionError("SCM write qualification invariant failed")


def open_probe(phase, root, state, scratch, facts, enrollment, generation):
    sid = enrollment["authority"]
    name = root.name
    write_pipe = "AI1-C7-" + uuid5(UUID(name[7:]), "semantic-write").hex
    client_sid = enrollment["client"]
    use_http = enrollment.get("http_fixture") is True
    if use_http:
        from app.memory_launch_v2 import READ_PIPE, WRITE_PIPE
        name, write_pipe = READ_PIPE, WRITE_PIPE
    reader = SemanticPipeClient(name, server_sid=sid, client_sid=client_sid, timeout=8.0)
    writer = SemanticPipeClient(write_pipe, server_sid=sid, client_sid=client_sid, timeout=8.0)
    if phase == "serve":
        require(facts["sid"] == sid and sid in facts["restrictions"])
        return serve(state, sid, client_sid, name, write_pipe, generation, recovery=use_http)
    if phase == "snapshot":
        require(use_http and facts["sid"] == "S-1-5-18")
        from c7_qualification.scm_recovery_probe import snapshot
        return snapshot(state)
    if phase in ("snapshot-profile", "restore-profile"):
        require(use_http and facts["sid"] == "S-1-5-18")
        from c7_qualification.scm_recovery_probe import restore_profile, snapshot_profile
        return (snapshot_profile if phase == "snapshot-profile" else restore_profile)(state, sid)
    if phase == "wrong-peer":
        require(facts["sid"] == "S-1-5-18" and facts["sid"] != client_sid)
        for endpoint in (reader, writer):
            try:
                endpoint.request({"op": "head"})
            except HeadUnavailable as error:
                require(getattr(error.__cause__, "winerror", None) == 5)
            else:
                raise AssertionError("Unexpected Windows principal opened the pipe")
        return 42
    require(facts["sid"] == client_sid and facts["integrity"] == 8192 and not facts["elevated"])
    if phase == "write":
        wrong_owner = SemanticPipeClient(name, server_sid="S-1-5-18", client_sid=client_sid)
        try:
            wrong_owner.request({"op": "head"})
        except HeadUnavailable as error:
            require(str(error) == "authority_wrong_owner")
        else:
            raise AssertionError("Unpinned server owner was accepted")
        expected = reader.request({"op": "head"})
        require(unpack_head(expected).revision == 0)
        try:
            with writer._connection() as (api, handle, deadline):
                _send(api, handle, b"V", deadline)
                require(_receive(api, handle, 1, deadline) == b"1")
                nonce = _receive(api, handle, 32, deadline)
                _send(api, handle, bytes([nonce[0] ^ 1]) + nonce[1:], deadline)
                _receive(api, handle, 1, deadline)
        except HeadUnavailable:
            pass
        else:
            raise AssertionError("Invalid connection challenge was accepted")
        intent = parse_memory_command("Запомни, что мой тестовый код — 12345", enabled=True)
        require(intent.action is MemoryAction.SAVE and intent.requires_confirmation)
        request = {"op": "mutate", "head": expected, "id": str(uuid5(generation, "save")),
                   "kind": "create", "text": intent.text, "note": None, "revision": None}
        refuse(reader, request)
        refuse(writer, {**request, "archive": "client-supplied bytes are never accepted"})
        if use_http:
            from c7_qualification.scm_http_probe import local_action
            require(local_action(scratch, reader, writer, "off") is None)
            committed = local_action(scratch, reader, writer, "write", request)
        else:
            committed = writer.request(request)
        require(unpack_head(committed).revision == 1)
        refuse(writer, request)
        refuse(writer, {**request, "id": str(uuid5(generation, "stale"))})
        require(writer.request({**request, "op": "status"}) == committed)
        refuse(writer, {**request, "op": "status", "text": "different"})
        archive = state / "archives" / ("memory-" + committed[2] + ".v2a")
        pin_name = "archive-pin.json" if enrollment.get("production_fixture") is True else "archive-pins.json"
        for protected in (state / "head.sqlite3", archive, state / pin_name):
            try:
                protected.open("rb").close()
            except PermissionError:
                continue
            raise AssertionError("Interactive client could inspect service storage")
        return 42
    if phase == "resume":
        require(parse_memory_command("Что ты помнишь?", enabled=True).action is MemoryAction.LIST)
        if use_http:
            from c7_qualification.scm_http_probe import local_action
            notes = local_action(scratch, reader, writer, "recall")
        else:
            notes = reader.request({"op": "recall"})
        (note, revision, text), = notes
        require(text == "мой тестовый код — 12345")
        request = {"op": "mutate", "head": reader.request({"op": "head"}),
                   "id": str(uuid5(generation, "delete")), "kind": "delete", "text": None,
                   "note": note, "revision": revision}
        with (scratch / "pending-delete.json").open("x", encoding="ascii") as output:
            json.dump(request, output)
        if enrollment.get("production_fixture") is True:
            require(unpack_head(writer.request(request)).revision == 2)
            return 42
        if use_http:
            require(local_action(scratch, reader, writer, "delete", request) is None)
            return 42
        try:
            writer.request(request)
        except HeadUnavailable:
            return 42
        raise AssertionError("Fault injection did not lose the acknowledgement")
    require(phase == "verify-write")
    request = json.loads((scratch / "pending-delete.json").read_bytes())
    committed = writer.request({**request, "op": "status"})
    if use_http:
        from c7_qualification.scm_http_probe import local_action
        require(local_action(scratch, reader, writer, "reconcile", request) == committed)
    require(unpack_head(committed).revision == 2 and reader.request({"op": "head"}) == committed)
    require(reader.request({"op": "recall"}) == [])
    return 42


def refuse(pipe, request):
    try:
        pipe.request(request)
    except WriteRefused:
        return
    raise AssertionError("Forbidden mutation was accepted")


def serve(state, sid, client_sid, name, write_pipe, generation, *, recovery):
    directory = state / "archives"
    database = state / "head.sqlite3"
    manifest = state / "archive-pins.json"
    initialize = state / "initialize-write"
    fresh = initialize.exists()
    if fresh:
        require(not database.exists() and not manifest.exists() and not directory.exists())
        initialize.unlink()
        kernel, advapi = _windows_apis()
        create = kernel.CreateDirectoryW
        create.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
        create.restype = wintypes.BOOL
        with _creation_security(kernel, advapi, sid, directory=True, allow_service_owner=True) as attributes:
            if not create(str(directory), attributes):
                raise ctypes.WinError(ctypes.get_last_error())
        chain = (*reversed(directory.parents), directory)
        pins = [inspect_component(str(path), expected_kind="directory").identity for path in chain]
        with manifest.open("x", encoding="ascii") as output:
            json.dump([[pin.volume, pin.native_id.hex()] for pin in pins], output)
    pins = tuple(FileIdentity(volume, bytes.fromhex(file_id))
                 for volume, file_id in json.loads(manifest.read_bytes()))
    archives = PrivateArchiveDirectory(str(directory), owner_sid=sid, ancestors=pins, allow_service_owner=True)
    reducer = ArchiveReducer(archives, receipt_budget=8)

    def connect():
        return sqlite3.connect(database.as_uri() + "?mode=rw", uri=True, timeout=1)

    writer = MemoryWriter(connect, reducer=reducer, enabled=True)
    if fresh:
        key = issue_receipt_key(generation)
        with closing(sqlite3.connect(":memory:")) as conn:
            MemoryLedger(conn, enabled=True, receipt_budget=8).initialize_empty(generation)
            genesis = build_archive(conn, capsule=key, approved_key_pin=key.fingerprint)
        archives.publish(genesis)
        database.touch(exist_ok=False)
        writer.provision(Head(generation, 0, genesis.fingerprint))
    live = writer.head()
    require(live.generation == generation)
    reducer.read(live)  # Reopen with the same service CurrentUser profile before accepting any client.
    if recovery:
        from c7_qualification.scm_recovery_probe import profile_probe, verify_restored
        if fresh:
            profile_probe(state, sid)
        if live.revision == 1 and (state / "snapshot-head.json").exists():
            verify_restored(state, live, budget=8)
            (state / "verified-restore").write_bytes(b"ok")
    semantic = SemanticMemory(writer, reducer)

    def handler(request, *, writable):
        result = semantic.execute(request, writable=writable)
        marker = state / "lose-write-ack"
        if writable and request["op"] == "mutate" and marker.exists():
            marker.unlink()
            os._exit(73)
        return result

    settings = dict(server_sid=sid, client_sid=client_sid, handler=handler, integrity=8192, timeout=8.0)
    with semantic_listener(name, **settings) as read, semantic_listener(write_pipe, writable=True, **settings) as write:
        (state / "ready").write_text(str(os.getpid()), encoding="ascii")
        deadline = monotonic() + 150
        while monotonic() < deadline and not (state / "stop").exists():
            read(0.25)
            write(0.25)
        require((state / "stop").exists())
    return 42
