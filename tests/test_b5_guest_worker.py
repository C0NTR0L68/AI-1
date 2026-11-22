"""Synthetic worker regressions. Never create native sockets or processes."""
import socket
import subprocess

import pytest

from b5_admission import AdmissionDenied, ChildPlan, ScopedWorkerAudit
from b5_guest import CanonicalFixturePath, _candidate_assets, _member
from b5_worker_adapters import _node_summary, _private_pair, scoped_worker_adapters
import b5_worker_adapters as adapters
import b5_worker_job as job


@pytest.mark.parametrize("name", ["../user", "C:/file", "a//b", "d/file:stream", "d/a."])
def test_rejects_unowned_archive_member(name):
    with pytest.raises(ValueError, match="Unsafe member"):
        _member(name)


def test_canonical_fixture_scope_accepts_only_exact_alias(tmp_path):
    fixture = CanonicalFixturePath()
    base = tmp_path / "unused"
    alias = base / ".." / "identity.sqlite3"
    other = base / ".." / "other.sqlite3"
    assert fixture.inspect(alias) == alias
    fixture.arm(tmp_path)
    assert fixture.inspect(alias) == tmp_path / "identity.sqlite3"
    assert fixture.inspect(other) == other
    fixture.disarm()
    assert fixture.inspect(alias) == alias
    base.mkdir()
    with pytest.raises(PermissionError):
        fixture.arm(tmp_path)


def test_candidate_assets_substitution_is_bound_to_exact_fixture(tmp_path):
    test_file = tmp_path / "test_schema_contract.py"
    namespace = {}
    exec(compile("def app_for(factory, assets): return factory(assets=assets)",
                 str(test_file), "exec"), namespace)
    adapter = _candidate_assets(lambda *, assets: assets, test_file)
    placeholder = {name: b"synthetic" for name in ("index.html", "app.js", "style.css")}
    assert namespace["app_for"](adapter, placeholder) is None
    assert adapter(assets=placeholder) == placeholder
    changed = {**placeholder, "app.js": b"unreviewed"}
    assert namespace["app_for"](adapter, changed) == changed


def test_node_summary_requires_all_unique_tap_counters():
    expected = {"tests": 22, "pass": 22, "fail": 0, "cancelled": 0, "skipped": 0, "todo": 0}
    output = "\n".join(f"# {name} {count}" for name, count in expected.items())
    assert _node_summary(output) == expected
    assert _node_summary(output + "\n# fail 1") is None
    assert _node_summary("# pass 22") is None


def test_partial_self_pipe_cleans_owned_resources(monkeypatch):
    closed = []

    class Socket:
        def __init__(self, *args):
            self.closed = False

        def settimeout(self, seconds):
            assert seconds == 2

        def bind(self, address):
            assert address == ("127.0.0.1", 0)

        def listen(self, backlog):
            raise OSError("synthetic listener failure")

        def fileno(self):
            return -1 if self.closed else 4

        def close(self):
            self.closed = True
            closed.append(self)

    monkeypatch.setattr(socket, "socket", Socket)
    with pytest.raises(OSError, match="synthetic listener failure"):
        _private_pair(ScopedWorkerAudit(lambda *_: None))
    assert len(closed) == 1 and closed[0].closed


def test_wrapper_preserves_child_admission_and_cleans_up(monkeypatch, tmp_path):
    from subprocess import list2cmdline

    def denied(*_):
        raise AdmissionDenied("DENIED")
    audit = ScopedWorkerAudit(denied)
    python = tmp_path / "python.exe"
    node = tmp_path / "node.exe"
    args = (str(node), "--test")
    plan = ChildPlan(str(node), args, str(tmp_path), (("TEMP", str(tmp_path)),))
    monkeypatch.setattr(adapters, "child_plan", lambda *args, **kwargs: plan)
    evidence = []

    class Child:
        def __init__(self, argv, **kwargs):
            audit.audit("subprocess.Popen", (kwargs["executable"], list2cmdline(argv),
                                            kwargs["cwd"], kwargs["env"]))
            evidence.append("spawned")

        def poll(self):
            return None

        def kill(self):
            evidence.append("killed")

        def communicate(self, *, timeout):
            assert timeout == 3
            evidence.append("joined")

    monkeypatch.setattr(subprocess, "Popen", Child)
    original_pair = socket.socketpair
    with scoped_worker_adapters(audit, python=python, node=node, suite=tmp_path,
                                scratch=tmp_path, system_root=tmp_path):
        with pytest.raises(AdmissionDenied, match="ASYNCIO_CALLER"):
            socket.socketpair()
        with pytest.raises(AdmissionDenied, match="CHILD_POPEN_OPTIONS"):
            subprocess.Popen(args, shell=True)
        subprocess.Popen((str(node.with_suffix(".EXE")), *args[1:]))
    assert subprocess.Popen is Child and socket.socketpair is original_pair
    assert evidence == ["spawned", "killed", "joined"]


@pytest.mark.parametrize("timeout", [False, True])
def test_worker_is_suspended_until_job_assignment_and_bounded_cleanup(monkeypatch, tmp_path, timeout):
    seen = []

    class Kernel:
        def CreateJobObjectW(self, *_):
            return 13

        def SetInformationJobObject(self, handle, kind, limits, size):
            assert (handle, kind) == (13, 9)
            assert limits._obj.basic.flags == 0x2008
            return True

        def AssignProcessToJobObject(self, handle, process):
            assert (handle, process) == (13, 21)
            seen.append("assigned")
            return True

        def IsProcessInJob(self, process, handle, result):
            result._obj.value = True
            return True

        def ResumeThread(self, thread):
            assert thread == 34
            seen.append("resumed")
            return 1

        def QueryInformationJobObject(self, handle, kind, accounting, size, result):
            accounting._obj.active = int(timeout and "terminated" not in seen)
            return True

        def TerminateJobObject(self, handle, code):
            seen.append("terminated")
            return True

    def create(program, command, *args):
        assert args[2] is False and args[3] & 4
        seen.append("created_suspended")
        return 21, 34, 101, 102

    monkeypatch.setattr(job, "_kernel", Kernel)
    monkeypatch.setattr(job._winapi, "CreateProcess", create)
    monkeypatch.setattr(job._winapi, "WaitForSingleObject",
                        lambda *_: job._winapi.WAIT_TIMEOUT if timeout else job._winapi.WAIT_OBJECT_0)
    monkeypatch.setattr(job._winapi, "GetExitCodeProcess", lambda *_: 5)
    monkeypatch.setattr(job._winapi, "CloseHandle", lambda handle: seen.append(handle))
    if timeout:
        with pytest.raises(TimeoutError):
            job.run_worker(tmp_path / "python.exe", tmp_path / "runner.py", tmp_path, {},
                           deadline_ms=500, mode="preflight")
    else:
        assert job.run_worker(tmp_path / "python.exe", tmp_path / "runner.py", tmp_path, {},
                              deadline_ms=500, mode="preflight") == 5
    assert seen[:3] == ["created_suspended", "assigned", "resumed"]
    assert ("terminated" in seen) is timeout
    assert seen[-3:] == [13, 34, 21]
