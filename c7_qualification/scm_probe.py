"""Read-only IPC and recovery fixture for a disposable SCM deployment."""
from contextlib import closing
import ctypes
from ctypes import wintypes as W
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from threading import Thread
from time import monotonic
import traceback
from uuid import UUID


PAYLOAD = Path(__file__).resolve().parents[1]
ROOT = PAYLOAD.parent
STATE = ROOT / "state"
DB = STATE / "head.sqlite3"
GENERATION = UUID("635f83dd-3bb7-4041-b4c8-7d39cb25d13a")
sys.path.insert(0, str(PAYLOAD))

from app.memory_authority_pipe import PipeAuthorityClient, authority_listener
from app.memory_head_v2 import DurableHeadRegistry, Head, HeadUnavailable
from app.windows_storage_inspector import _sid_string, _windows_apis


def require(condition):
    if not condition:
        raise AssertionError("Synthetic SCM invariant failed")


def bind(dll, name, result, *args):
    function = getattr(dll, name)
    function.argtypes, function.restype = args, result
    return function


def token_facts():
    kernel, adv = _windows_apis()
    token = W.HANDLE()
    current = bind(kernel, "GetCurrentProcess", W.HANDLE)
    open_token = bind(adv, "OpenProcessToken", W.BOOL, W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE))
    query = bind(adv, "GetTokenInformation", W.BOOL, W.HANDLE, ctypes.c_int,
                 ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD))
    if not open_token(current(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        def info(kind):
            size = W.DWORD()
            query(token, kind, None, 0, ctypes.byref(size))
            require(0 < size.value < 65536)
            result = ctypes.create_string_buffer(size.value)
            if not query(token, kind, result, size, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            return result

        def sid(kind):
            buffer = info(kind)
            return _sid_string(adv, kernel.LocalFree, ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents)

        groups = info(11)  # TokenRestrictedSids
        count = W.DWORD.from_buffer(groups).value

        class Entry(ctypes.Structure):
            _fields_ = [("sid", ctypes.c_void_p), ("attributes", W.DWORD)]

        class GroupArray(ctypes.Structure):
            _fields_ = [("count", W.DWORD), ("groups", Entry * count)]

        require(ctypes.sizeof(GroupArray) <= len(groups) or count == 0)
        restricted = [_sid_string(adv, kernel.LocalFree, entry.sid)
                      for entry in GroupArray.from_buffer(groups).groups] if count else []
        return {"sid": sid(1), "integrity": int(sid(25).rsplit("-", 1)[1]),
                "elevated": bool(W.DWORD.from_buffer(info(20)).value), "restrictions": restricted}
    finally:
        require(kernel.CloseHandle(token))


def digest(revision):
    return sha256(str(revision).encode("ascii")).digest()


def head(revision):
    return Head(GENERATION, revision, digest(revision))


def registry():
    return DurableHeadRegistry(lambda: sqlite3.connect(DB.as_uri() + "?mode=rw", uri=True, timeout=1))


def prove_scm_denials():
    _, adv = _windows_apis()
    open_manager = bind(adv, "OpenSCManagerW", W.HANDLE, W.LPCWSTR, W.LPCWSTR, W.DWORD)
    open_service = bind(adv, "OpenServiceW", W.HANDLE, W.HANDLE, W.LPCWSTR, W.DWORD)
    close = bind(adv, "CloseServiceHandle", W.BOOL, W.HANDLE)
    manager = open_manager(None, None, 1)
    require(manager)
    try:
        for right in (2, 0x10, 0x20, 0x10000, 0x40000, 0x80000):
            handle = open_service(manager, "AI1C7GuestAuthority", right)
            if handle:
                close(handle)
                raise AssertionError("Ordinary client acquired SCM mutation rights")
            require(ctypes.get_last_error() == 5)
    finally:
        require(close(manager))


def register_fixture():
    _, adv = _windows_apis()
    open_manager = bind(adv, "OpenSCManagerW", W.HANDLE, W.LPCWSTR, W.LPCWSTR, W.DWORD)
    create = bind(adv, "CreateServiceW", W.HANDLE, W.HANDLE, W.LPCWSTR, W.LPCWSTR,
                  W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.LPCWSTR, W.LPCWSTR,
                  ctypes.POINTER(W.DWORD), W.LPCWSTR, W.LPCWSTR, W.LPCWSTR)
    change = bind(adv, "ChangeServiceConfig2W", W.BOOL, W.HANDLE, W.DWORD, ctypes.c_void_p)
    delete = bind(adv, "DeleteService", W.BOOL, W.HANDLE)
    close = bind(adv, "CloseServiceHandle", W.BOOL, W.HANDLE)
    manager = open_manager(None, None, 3)  # CONNECT | CREATE_SERVICE
    if not manager:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        name = "AI1C7GuestAuthority"
        service = create(manager, name, name, 0x10002, 16, 3, 1, f'"{ROOT / "Authority.exe"}"',
                         None, None, None, "NT SERVICE\\" + name, None)
        if not service:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            sid_type = W.DWORD(3)  # SERVICE_SID_TYPE_RESTRICTED
            if not change(service, 5, ctypes.byref(sid_type)):  # SERVICE_CONFIG_SERVICE_SID_INFO
                error = ctypes.get_last_error()
                require(delete(service))
                raise ctypes.WinError(error)
        finally:
            require(close(service))
    finally:
        require(close(manager))


def hashes():
    return [sha256(path.read_bytes()).hexdigest()
            for path in (DB, ROOT / "archives" / "archive.synthetic")]


def main():
    require(os.name == "nt" and ROOT.parent == Path(r"C:\Program Files")
            and re.fullmatch(r"AI1-C7-[a-f0-9]{32}", ROOT.name))
    phase, = sys.argv[1:]
    facts = token_facts()
    if phase == "register":
        require(facts["sid"] == "S-1-5-18")
        register_fixture()
        return 42
    enrollment = json.loads((ROOT / "enrollment.json").read_bytes())
    registry_instance = registry()
    journal = DB.with_name(DB.name + "-journal")
    scratch = Path(r"C:\Users\Public\Documents") / ROOT.name / "ordinary"
    if phase == "provision":
        require(facts["sid"] == "S-1-5-18")
        with DB.open("xb"):
            pass
        registry_instance.provision(head(0))
        (STATE / "before.json").write_text(json.dumps(hashes()), encoding="ascii")
        return 42
    if phase == "serve":
        require(facts["sid"] == enrollment["authority"] and facts["sid"] in facts["restrictions"])
        require(registry_instance.read() == head(0))
        class FixtureAuthority:
            def read(self):
                drop = STATE / "drop-next"
                if drop.exists():
                    drop.unlink()
                    raise HeadUnavailable("synthetic_service_drop")
                return registry_instance.read()

        with authority_listener(ROOT.name, server_sid=facts["sid"], client_sid=enrollment["client"],
                                generation=GENERATION, registry=FixtureAuthority(),
                                client_integrity=enrollment["integrity"]) as serve:
            (STATE / "ready").write_text(str(os.getpid()), encoding="ascii")
            deadline = monotonic() + 160
            while monotonic() < deadline and not (STATE / "stop").exists():
                if (STATE / "crash").exists():
                    (STATE / "crash").unlink()
                    connection = sqlite3.connect(DB.as_uri() + "?mode=rw", uri=True)
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("INSERT INTO main.head_journal VALUES (?, ?, ?)",
                                       (1, GENERATION.bytes, digest(1)))
                    require(journal.is_file() and journal.stat().st_size > 0)
                    os._exit(73)
                serve(0.5)
            require((STATE / "stop").exists())
        return 42
    if phase == "verify":
        require(facts["sid"] == "S-1-5-18")
        require(json.loads((STATE / "before.json").read_bytes()) == hashes())
        require(registry_instance.read() == head(0))
        return 42
    client = PipeAuthorityClient(ROOT.name, server_sid=enrollment["authority"],
                                 client_sid=enrollment["client"])
    if phase == "wrong-peer":
        require(facts["sid"] == "S-1-5-18" and facts["sid"] != enrollment["client"])
        try:
            client.read()
        except HeadUnavailable as error:
            require(getattr(error.__cause__, "winerror", None) == 5)
            return 42
        raise AssertionError("Unenrolled Windows principal connected to the service")
    require(facts["sid"] == enrollment["client"] and facts["integrity"] == 8192
            and not facts["elevated"] and facts["sid"] != enrollment["authority"])
    if phase == "preflight":
        return 42
    if phase in ("ipc", "ipc-recovered"):
        try:
            require(client.read() == head(0))
        except HeadUnavailable as error:
            cause = error.__cause__
            if getattr(cause, "winerror", None) == 5:
                return 65
            raise
        for operation, reason in ((lambda: client._exchange(b"W"), "authority_operation_refused"),
                                  (lambda: client.advance(head(0), head(1)), "authority_read_only")):
            try:
                operation()
            except HeadUnavailable as error:
                require(str(error) == reason)
            else:
                raise AssertionError("Read-only authority admitted mutation")
        return 42
    if phase == "dropped":
        try:
            client.read()
        except HeadUnavailable as error:
            require(str(error) == "authority_pipe_unavailable"
                    and getattr(error.__cause__, "winerror", None) in (109, 232, 233))
            return 42
        raise AssertionError("Incomplete reply was accepted as a head")
    if phase == "counterfeit":
        class UnexpectedRead:
            def read(self):
                raise AssertionError("Client sent a request to an untrusted endpoint")

        with authority_listener(ROOT.name, server_sid=facts["sid"], client_sid=enrollment["authority"],
                                registry=UnexpectedRead(), generation=GENERATION, client_integrity=8192) as serve:
            outcomes = []
            actor = Thread(target=lambda: outcomes.append(serve(3)))
            actor.start()
            try:
                client.read()
            except HeadUnavailable as error:
                require(str(error) == "authority_wrong_owner")
            else:
                raise AssertionError("Client accepted a same-name pipe under the wrong owner")
            finally:
                actor.join(5)
            require(not actor.is_alive() and outcomes == ["disconnected"])
        return 42
    require(phase == "denied")
    prove_scm_denials()
    source = scratch / "replacement.synthetic"
    with source.open("xb") as stream:
        stream.write(b"stale synthetic snapshot")
    for path in (DB, journal, ROOT / "archives" / "archive.synthetic",
                 ROOT / "enrollment.json", ROOT / "Authority.exe"):
        for attempt in (lambda: path.open("r+b").close(), path.unlink,
                        lambda: os.replace(source, path), lambda: path.rename(path.with_suffix(".moved"))):
            try:
                attempt()
            except PermissionError:
                continue
            raise AssertionError("Ordinary client changed protected entry")
    for path in (ROOT, STATE, ROOT / "archives"):
        try:
            path.rename(path.with_name(path.name + "-moved"))
        except PermissionError:
            continue
        raise AssertionError("Ordinary client moved protected directory")
    return 42


if __name__ == "__main__":
    attempt = sys.argv[1] if len(sys.argv) == 2 else ""
    ordinary = Path(r"C:\Users\Public\Documents") / ROOT.name / "ordinary"
    try:
        result = main()
        if attempt in ("preflight", "ipc", "ipc-recovered", "denied", "counterfeit", "dropped"):
            (ordinary / (attempt + ".json")).write_text(
                json.dumps({"pid": os.getpid(), "code": result, "token": token_facts()}), encoding="ascii")
        raise SystemExit(result)
    except Exception:
        if sys.argv[1:] == ["serve"] and os.name == "nt" and ROOT.parent == Path(r"C:\Program Files"):
            (STATE / "worker-failure.log").write_text(traceback.format_exc(limit=6), encoding="utf8")
        elif attempt in ("preflight", "ipc", "ipc-recovered", "denied", "counterfeit", "dropped") and os.name == "nt":
            (ordinary / (attempt + "-failure.log")).write_text(traceback.format_exc(limit=6), encoding="utf8")
        raise
