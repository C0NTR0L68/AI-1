"""Run the IPC authority integration only in an attested disposable guest."""
import argparse
import asyncio
from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from time import monotonic
from uuid import UUID, uuid4


def require(value):
    if not value:
        raise AssertionError("IPC qualification invariant failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("enroll", "provision", "serve", "drop", "impostor",
                                           "startup", "denied", "unavailable", "disconnected",
                                           "wrong-server", "substitute", "substituted"))
    parser.add_argument("parcel", type=Path)
    args = parser.parse_args()
    root, action = args.parcel, args.action
    require(root.parent == Path(r"C:\Users\Public\Documents")
            and re.fullmatch(r"AI1-C7-[a-f0-9]{32}", root.name))
    payload = Path(__file__).resolve().parents[1]
    system = Path(os.environ["SystemRoot"]) / "System32/config/systemprofile" / root.name
    privileged = action in ("provision", "serve", "drop", "denied")
    require(payload.parent == (system if privileged else root))
    owner = os.environ["AI1_C7_OWNER"]
    require((owner == "S-1-5-18") == privileged)
    sys.path[:0] = [str(payload), str(payload / "deps")]

    from app.memory_authority_pipe import PipeAuthorityClient, authority_listener
    from app.memory_head_v2 import DurableHeadRegistry, Head, HeadUnavailable
    from app.memory_storage_policy import FileIdentity
    from app.memory_windows_archive import PrivateArchiveDirectory
    from app.windows_storage_inspector import inspect_component
    from probe import private_directory

    scratch = root / "ipc-scratch"
    archive_root = scratch / "archives"
    handoff = scratch / "enrollment.json"
    pipe = root.name
    database = system / "ipc-head.sqlite3"

    def registry():
        return DurableHeadRegistry(lambda: sqlite3.connect(database.as_uri() + "?mode=rw", uri=True,
                                                            timeout=1.0))

    if action == "enroll":
        from app.memory_archive_v2 import build_archive
        from app.memory_keys_v2 import issue_receipt_key
        from app.memory_ledger import MemoryLedger

        scratch.mkdir()
        private_directory(archive_root, owner)
        chain = (*reversed(archive_root.parents), archive_root)
        pins = tuple(inspect_component(str(p), expected_kind="directory").identity for p in chain)
        namespace = PrivateArchiveDirectory(str(archive_root), owner_sid=owner, ancestors=pins)
        generation = uuid4()
        capsule = issue_receipt_key(generation)
        with closing(sqlite3.connect(":memory:")) as conn:
            MemoryLedger(conn, enabled=True, receipt_budget=8).initialize_empty(generation)
            initial = build_archive(conn, capsule=capsule, approved_key_pin=capsule.fingerprint)
        namespace.publish(initial)
        with handoff.open("x", encoding="ascii") as file:
            json.dump({"owner": owner, "generation": str(generation), "digest": initial.fingerprint.hex(),
                       "pins": [(p.volume, p.native_id.hex()) for p in pins]}, file)
        return 42

    sealed_enrollment = system / "ipc-enrollment.json"
    if action == "provision":
        # Enrollment is a synthetic administrator action, never a protocol operation.
        require(not handoff.is_symlink() and not handoff.is_junction())
        with sealed_enrollment.open("xb") as file:
            file.write(handoff.read_bytes())
        data = json.loads(sealed_enrollment.read_bytes())
        initial = Head(UUID(data["generation"]), 0, bytes.fromhex(data["digest"]))
        with database.open("xb"):
            pass
        registry().provision(initial)
        return 42

    data = json.loads((sealed_enrollment if privileged else handoff).read_bytes())
    generation = UUID(data["generation"])
    client_sid = data["owner"]
    client = PipeAuthorityClient(pipe, server_sid="S-1-5-18", client_sid=client_sid)
    if action in ("serve", "drop", "impostor"):
        actor = owner
        allowed = client_sid if privileged else "S-1-5-18"
        service = registry() if action == "serve" else None

        class NoReply:
            def read(self):
                raise HeadUnavailable("test_lost_authority")

        if service is None:
            service = NoReply()
        stop = (system if privileged else scratch) / "stop"
        with authority_listener(pipe, server_sid=actor, client_sid=allowed, registry=service,
                                generation=generation) as serve:
            deadline = monotonic() + 90
            while not stop.exists() and monotonic() < deadline:
                serve(0.5)
        return 42 if stop.exists() else 72

    if action == "denied":
        try:
            client.read()  # SYSTEM can open the pipe. It is not the enrolled client SID.
        except HeadUnavailable as error:
            require(str(error) == "authority_operation_refused")
            return 42
        raise AssertionError("Wrong Windows client SID was admitted")
    if action == "substitute":
        archive_root.rename(archive_root.with_name("archived-original"))
        private_directory(archive_root, owner)
        return 42

    if action == "startup":
        head = client.read()
        require(head == Head(generation, 0, bytes.fromhex(data["digest"])))
        for operation, expected in ((lambda: client._exchange(b"W"), "authority_operation_refused"),
                                    (lambda: client.advance(head, head), "authority_read_only")):
            try:
                operation()
            except HeadUnavailable as error:
                require(str(error) == expected)
            else:
                raise AssertionError("Mutation was admitted while memory is OFF")
    elif action == "wrong-server":
        try:
            client.read()
        except HeadUnavailable as error:
            require(str(error) == "authority_wrong_owner")
            return 42
        raise AssertionError("Impostor accepted as authority")

    # Read-only launcher composition. No environment switch can create the factory.
    from app.memory_storage_binding import MemoryStorageFactory

    @contextmanager
    def session():
        yield client

    pins = tuple(FileIdentity(volume, bytes.fromhex(native)) for volume, native in data["pins"])
    factory = MemoryStorageFactory(session, PrivateArchiveDirectory(str(archive_root), owner_sid=owner,
                                                                   ancestors=pins), generation, 8)
    configuration = scratch / "ipc-workspace.sqlite3"
    os.environ.update(PYTHON_DOTENV_DISABLED="1", AI1_API_KEY="", AI1_MODE="LOCAL_ONLY",
                      AI1_PROVIDER="ollama", AI1_DATABASE_PATH=str(configuration))
    from app import start
    from app.memory_archive_publish_v2 import PublicationUnconfirmed
    import httpx
    import uvicorn

    def run(target, **options):
        require(options == {"factory": True, "host": "127.0.0.1", "port": 8000,
                            "workers": 1, "reload": False, "proxy_headers": False})

        async def check():
            app = target()
            try:
                async with app.router.lifespan_context(app):
                    require(action == "startup")
                    require(app.state.memory_storage.read(generation) == ())
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                                 base_url="http://127.0.0.1:8000") as http:
                        require((await http.get("/api/memory/notes")).status_code == 404)
            except HeadUnavailable as error:
                require(action in ("unavailable", "disconnected"))
                require(str(error) == "authority_pipe_unavailable")
            except PublicationUnconfirmed:
                require(action == "substituted")
            require(app.state.memory_storage is None)

        asyncio.run(check())

    uvicorn.run = run
    require(start.main(["--workspace", "--database", str(configuration)],
                       memory_storage_factory=factory) == 0)
    return 42


if __name__ == "__main__":
    raise SystemExit(main())
