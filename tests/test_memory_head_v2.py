from concurrent.futures import ThreadPoolExecutor
import sqlite3
from threading import Barrier
from uuid import UUID

import pytest

from app.memory_head_v2 import DurableHeadRegistry, Head, HeadUnavailable, require_current_head


GENERATION = UUID(int=1)
FIRST = Head(GENERATION, 0, b"a" * 32)
SECOND = Head(GENERATION, 1, b"b" * 32)
THIRD = Head(GENERATION, 2, b"c" * 32)


def registry(path, *, provision=False, factory=sqlite3.connect):
    if provision:
        return DurableHeadRegistry(lambda: factory(path))
    return DurableHeadRegistry(lambda: factory(path.as_uri() + "?mode=rw", uri=True))


def test_restart_and_stale_archive(tmp_path):
    path = tmp_path / "authority.sqlite"
    registry(path, provision=True).provision(FIRST)
    assert registry(path).advance(FIRST, SECOND)
    restarted = registry(path)
    assert restarted.read() == SECOND
    with pytest.raises(HeadUnavailable, match="head_mismatch"):
        require_current_head(FIRST, restarted)
    with pytest.raises(HeadUnavailable, match="head_mismatch"):
        require_current_head(Head(GENERATION, 1, FIRST.digest), restarted)
    assert require_current_head(SECOND, restarted) == SECOND


def test_refuses_missing_authority_and_reprovision(tmp_path):
    path = tmp_path / "authority.sqlite"
    with pytest.raises(HeadUnavailable, match="head_read_unavailable"):
        require_current_head(FIRST, registry(path))
    assert not path.exists()
    registry(path, provision=True).provision(FIRST)
    with pytest.raises(HeadUnavailable, match="head_database_not_empty"):
        registry(path).provision(FIRST)
    assert registry(path).read() == FIRST


def test_refuses_generation_change_and_digest_replay(tmp_path):
    path = tmp_path / "authority.sqlite"
    registry(path, provision=True).provision(FIRST)
    authority = registry(path)
    with pytest.raises(ValueError, match="Next revision"):
        authority.advance(FIRST, Head(UUID(int=2), 1, SECOND.digest))
    with pytest.raises(ValueError, match="Next revision"):
        authority.advance(FIRST, THIRD)
    assert authority.advance(FIRST, SECOND)
    assert not authority.advance(SECOND, Head(GENERATION, 2, FIRST.digest))
    assert not authority.advance(FIRST, Head(GENERATION, 1, THIRD.digest))
    assert authority.read() == SECOND


def test_competing_advances_have_one_winner(tmp_path):
    path = tmp_path / "authority.sqlite"
    registry(path, provision=True).provision(FIRST)
    authority = registry(path)
    other = Head(GENERATION, 1, THIRD.digest)
    barrier = Barrier(2, timeout=5)

    def change(head):
        barrier.wait()
        return authority.advance(FIRST, head)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(change, (SECOND, other), timeout=10))
    assert results.count(True) == 1
    assert authority.read() == (SECOND if results[0] else other)


@pytest.mark.parametrize("when", ("before", "after"))
def test_commit_uncertainty_never_reports_success(tmp_path, when):
    path = tmp_path / "authority.sqlite"
    registry(path, provision=True).provision(FIRST)

    class LostCommitReply(sqlite3.Connection):
        def __exit__(self, *exc):
            if when == "after":
                super().__exit__(*exc)
            raise sqlite3.OperationalError("synthetic ambiguous COMMIT")

    def connect(*args, **kwargs):
        return sqlite3.connect(*args, factory=LostCommitReply, **kwargs)

    with pytest.raises(HeadUnavailable, match="head_advance_unconfirmed"):
        registry(path, factory=connect).advance(FIRST, SECOND)
    assert registry(path).read() == (SECOND if when == "after" else FIRST)


def test_rollback_of_client_head_copy_is_detected(tmp_path):
    root = tmp_path / "service"
    root.mkdir()
    authority = registry(root / "authority.sqlite", provision=True)
    authority.provision(FIRST)
    client = tmp_path / "client-head"
    client.write_bytes(FIRST.digest)
    snapshot = client.read_bytes()
    assert authority.advance(FIRST, SECOND)
    client.write_bytes(SECOND.digest)
    client.write_bytes(snapshot)
    with pytest.raises(HeadUnavailable, match="head_mismatch"):
        require_current_head(Head(GENERATION, 0, client.read_bytes()), authority)


def test_rejects_invalid_head_types():
    for generation, revision, digest in ((UUID(int=0), 0, FIRST.digest),
                                          (GENERATION, True, FIRST.digest),
                                          (GENERATION, 0, b"short")):
        with pytest.raises(ValueError):
            Head(generation, revision, digest)
