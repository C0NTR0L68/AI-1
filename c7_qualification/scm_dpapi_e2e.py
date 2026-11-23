"""Synthetic DPAPI archive checks for the disposable SCM fixture."""
import asyncio
from contextlib import closing, contextmanager
from hashlib import sha256
import json
import sqlite3
from uuid import uuid4

from c7_qualification.probe import private_directory
from app.memory_archive_publish_v2 import PublicationUnconfirmed
from app.memory_archive_v2 import ArchiveUnavailable, build_archive, open_archived_state
from app.memory_crypto import MemoryCryptoError, protect_for_current_user, unprotect_for_current_user
from app.memory_head_v2 import Head, HeadUnavailable
from app.memory_keys_v2 import issue_receipt_key
from app.memory_ledger import MemoryLedger
from app.memory_reconciliation import OperationIdentity
from app.memory_storage_binding import MemoryStorageFactory
from app.memory_storage_policy import FileIdentity
from app.memory_windows_archive import PrivateArchiveDirectory
from app.windows_storage_inspector import inspect_component


NOTE = b"synthetic-local-memory-check"


def require(value):
    if not value:
        raise AssertionError("Synthetic archive invariant failed")


def archive_namespace(root, owner, enrolled_pins=None):
    if enrolled_pins is None:
        chain = (*reversed(root.parents), root)
        pins = tuple(inspect_component(str(path), expected_kind="directory").identity for path in chain)
    else:
        pins = tuple(FileIdentity(volume, bytes.fromhex(native)) for volume, native in enrolled_pins)
    return PrivateArchiveDirectory(str(root), owner_sid=owner, ancestors=pins), pins


def prepare(scratch, owner, generation):
    directory = scratch / "dpapi-archives"
    private_directory(directory, owner)
    namespace, pins = archive_namespace(directory, owner)
    key = issue_receipt_key(generation)
    with closing(sqlite3.connect(":memory:")) as conn:
        ledger = MemoryLedger(conn, enabled=True, receipt_budget=8)
        ledger.initialize_empty(generation)
        previous = build_archive(conn, capsule=key, approved_key_pin=key.fingerprint)
        sealed = protect_for_current_user(NOTE)
        require(unprotect_for_current_user(sealed) == NOTE)
        ledger.mutate(OperationIdentity(uuid4(), generation, sha256(NOTE).digest()), "create", sealed=sealed)
        current = build_archive(conn, capsule=key, approved_key_pin=key.fingerprint)
    namespace.publish(previous)
    namespace.publish(current)
    (scratch / "dpapi-canary.bin").write_bytes(sealed)
    (scratch / "dpapi-enrollment.json").write_text(json.dumps({
        "generation": str(generation), "previous": previous.fingerprint.hex(),
        "current": current.fingerprint.hex(), "canary": sha256(sealed).hexdigest(),
        "pins": [(pin.volume, pin.native_id.hex()) for pin in pins],
    }), encoding="ascii")


def verify_as_authority(root, enrolled):
    archive = (root / "archives" / "dpapi-current.v2a").read_bytes()
    canary = (root / "archives" / "dpapi-canary.bin").read_bytes()
    digest = bytes.fromhex(enrolled["current"])
    require(sha256(archive).digest() == digest and sha256(canary).hexdigest() == enrolled["canary"])
    try:
        unprotect_for_current_user(canary)
    except MemoryCryptoError as error:
        require(error.operation == "unprotect" and type(error.winerror) is int and error.winerror != 0)
        code = error.winerror
    else:
        raise AssertionError("Service unexpectedly opened CurrentUser ciphertext")
    try:
        with open_archived_state(archive, approved_archive_pin=digest):
            raise AssertionError("Service unexpectedly opened the client archive")
    except ArchiveUnavailable:
        pass
    return code


def qualify(phase, scratch, enrollment, generation, client):
    enrolled = enrollment["dpapi"]
    require(enrolled["generation"] == str(generation))
    directory = scratch / "dpapi-archives"
    owner = enrollment["client"]
    namespace, _ = archive_namespace(directory, owner, enrolled["pins"])
    digest = bytes.fromhex(enrolled["current"])

    @contextmanager
    def session():
        yield client

    factory = MemoryStorageFactory(session, namespace, generation, 8)
    from app import start
    import httpx
    import uvicorn

    def launch(label, expected=None):
        configuration = scratch / (label + "-workspace.sqlite3")
        require(not configuration.exists())

        def run(target, **options):
            require(options == {"factory": True, "host": "127.0.0.1", "port": 8000,
                                "workers": 1, "reload": False, "proxy_headers": False})

            async def check():
                app = target()
                require(app.state.memory_storage is None)
                entered = False
                try:
                    async with app.router.lifespan_context(app):
                        entered = True
                        require(expected is None)
                        require(client.read() == Head(generation, 1, digest))
                        notes = app.state.memory_storage.read(generation)
                        require(len(notes) == 1 and unprotect_for_current_user(notes[0].sealed) == NOTE)
                        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                                     base_url="http://127.0.0.1:8000") as http:
                            require((await http.get("/api/memory/notes")).status_code == 404)
                except (HeadUnavailable, PublicationUnconfirmed) as error:
                    require(not entered and expected is not None and expected(error))
                else:
                    require(entered and expected is None)
                require(app.state.memory_storage is None)

            asyncio.run(check())

        original = uvicorn.run
        uvicorn.run = run
        try:
            require(start.main(["--workspace", "--database", str(configuration)],
                               memory_storage_factory=factory) == 0)
        finally:
            uvicorn.run = original
        require(configuration.exists() == (expected is None))

    def pipe_failure(error):
        return isinstance(error, HeadUnavailable) and str(error) == "authority_pipe_unavailable"

    def archive_failure(error):
        return isinstance(error, PublicationUnconfirmed) and str(error) == "archive_publication_unconfirmed"

    if phase in ("e2e-drop", "e2e-down", "e2e-timeout"):
        def refusal(error):
            if not pipe_failure(error):
                return False
            cause = error.__cause__
            if phase == "e2e-timeout":
                return isinstance(cause, TimeoutError)
            codes = (109, 232, 233) if phase == "e2e-drop" else (2,)
            return getattr(cause, "winerror", None) in codes
        launch(phase, refusal)
        return [phase]
    launch(phase)
    if phase != "e2e-live":
        return [phase]
    current = directory / ("memory-" + enrolled["current"] + ".v2a")
    verified = namespace.read(digest)
    stale_digest = bytes.fromhex(enrolled["previous"])
    stale = namespace.read(stale_digest)
    with open_archived_state(stale, approved_archive_pin=stale_digest) as (conn, actual, _):
        require(actual == generation and MemoryLedger(conn, enabled=True, receipt_budget=8).read(actual) == ())
    try:
        current.write_bytes(verified[:-1] + bytes((verified[-1] ^ 1,)))
        launch("corrupt", archive_failure)
        current.write_bytes(stale)
        launch("stale", archive_failure)
    finally:
        current.write_bytes(verified)
    saved = directory.with_name("actual-dpapi-archives")
    directory.rename(saved)
    try:
        private_directory(directory, owner)
        replacement, _ = archive_namespace(directory, owner)
        from app.memory_archive_v2 import BackupArchive
        replacement.publish(BackupArchive(verified, digest))
        launch("replaced-path", archive_failure)
    finally:
        if directory.exists():
            (directory / current.name).unlink(missing_ok=True)
            directory.rmdir()
        saved.rename(directory)
    launch("e2e-restored")
    return [phase, "corrupt", "stale", "replaced-path", "e2e-restored"]
