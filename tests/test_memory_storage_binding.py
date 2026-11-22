"""Tests for the dormant launcher/lifespan binding on scratch storage."""
import asyncio
from contextlib import closing, contextmanager
import os
import sqlite3
from uuid import uuid4

import httpx
import pytest

from app import main, start
from app.memory_archive_v2 import build_archive
from app.memory_head_v2 import DurableHeadRegistry, Head, HeadUnavailable
from app.memory_keys_v2 import issue_receipt_key
from app.memory_ledger import MemoryLedger
from app.memory_storage_binding import MemoryStorageFactory
from app.memory_windows_archive import PrivateArchiveDirectory
from app.windows_storage_inspector import inspect_component
from test_memory_windows_archive import private_dir


@pytest.fixture
def deployment(tmp_path):
    owner = os.environ["AI1_C7_OWNER"]
    path = tmp_path / "protected-archives"
    private_dir(path, owner)
    chain = (*reversed(path.parents), path)
    pins = tuple(inspect_component(str(item), expected_kind="directory").identity for item in chain)
    archives = PrivateArchiveDirectory(str(path), owner_sid=owner, ancestors=pins)
    generation = uuid4()
    capsule = issue_receipt_key(generation)
    with closing(sqlite3.connect(":memory:")) as conn:
        MemoryLedger(conn, enabled=True, receipt_budget=8).initialize_empty(generation)
        artifact = build_archive(conn, capsule=capsule, approved_key_pin=capsule.fingerprint)
    archive = archives.publish(artifact).path
    database = path.parent / "test-head.sqlite"
    DurableHeadRegistry(lambda: sqlite3.connect(database)).provision(Head(generation, 0, artifact.fingerprint))
    events = []

    @contextmanager
    def test_session():
        events.append("enter")
        try:
            yield DurableHeadRegistry(lambda: sqlite3.connect(database.as_uri() + "?mode=rw", uri=True))
        finally:
            events.append("exit")

    return path.parent, archive, database, MemoryStorageFactory(test_session, archives, generation, 8), events


def configured(monkeypatch):
    from dataclasses import replace

    monkeypatch.setattr(main, "settings", replace(main.settings, provider="ollama", mode="LOCAL_ONLY"))


@pytest.mark.skipif(os.name != "nt", reason="Native protected NTFS deployment")
def test_lifespan_opens_only_explicit_storage_and_keeps_api_off(deployment, monkeypatch):
    root, _, _, factory, events = deployment
    configured(monkeypatch)

    async def check():
        app = main.create_app(workspace_path=str(root / "workspace.sqlite3"), provider=object(),
                              memory_storage_factory=factory)
        assert events == [] and app.state.memory_storage is None
        async with app.router.lifespan_context(app):
            assert events == ["enter"]
            assert app.state.memory_storage.read(factory.generation) == ()
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://127.0.0.1:8000") as client:
                assert (await client.get("/api/memory/notes")).status_code == 404
        assert app.state.memory_storage is None and events == ["enter", "exit"]
        off = main.create_app(workspace_path=str(root / "off.sqlite3"), provider=object())
        async with off.router.lifespan_context(off):
            assert off.state.memory_storage is None
        assert events == ["enter", "exit"]

    asyncio.run(check())


@pytest.mark.skipif(os.name != "nt", reason="Native protected NTFS deployment")
def test_rejected_head_releases_runtime_before_workspace_creation(deployment, monkeypatch):
    root, _, database, factory, events = deployment
    configured(monkeypatch)
    database.rename(database.with_suffix(".moved"))
    workspace = root / "workspace.sqlite3"

    async def check():
        app = main.create_app(workspace_path=str(workspace), provider=object(), memory_storage_factory=factory)
        for _ in range(2):
            with pytest.raises(HeadUnavailable):
                async with app.router.lifespan_context(app):
                    pytest.fail("Absent authority admitted")
        assert app.state.memory_storage is None

    asyncio.run(check())
    assert events == ["enter", "exit", "enter", "exit"]
    assert not workspace.exists() and not database.exists()


@pytest.mark.skipif(os.name != "nt", reason="Native protected NTFS deployment")
def test_launcher_passes_factory_and_keeps_safe_server_settings(deployment, monkeypatch):
    import uvicorn

    root, _, _, factory, _ = deployment
    captured = {}
    monkeypatch.setattr(uvicorn, "run", lambda target, **kwargs: captured.update(target=target, **kwargs))
    for name in start.local_configuration(str(root / "launcher.sqlite3"), "test"):
        monkeypatch.setenv(name, os.environ.get(name, ""))
    assert start.main(["--workspace", "--database", str(root / "launcher.sqlite3")],
                      memory_storage_factory=factory) == 0
    assert captured["target"].keywords["memory_storage_factory"] is factory
    assert (captured["host"], captured["workers"], captured["reload"], captured["proxy_headers"]) == (
        "127.0.0.1", 1, False, False,
    )
