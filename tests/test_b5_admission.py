from hashlib import sha256
from subprocess import list2cmdline

import pytest

import b5_admission as admission


class SocketEvidence:
    def __init__(self, address, peer=None, descriptor=8):
        self.address, self.peer, self.descriptor = address, peer, descriptor

    def getsockname(self):
        return self.address

    def getpeername(self):
        return self.peer

    def fileno(self):
        return self.descriptor


def test_only_expected_private_socketpair_is_admitted():
    policy = admission.PrivateSocketAudit(family=2, kind=1)
    server_addr, client_addr = ("127.0.0.1", 50100), ("127.0.0.1", 50101)
    listener = SocketEvidence(server_addr, descriptor=7)
    writer = SocketEvidence(client_addr, server_addr)
    reader = SocketEvidence(server_addr, client_addr, descriptor=9)
    policy.accept_event("socket.__new__", (listener, 2, 1, 0))
    with pytest.raises(admission.AdmissionDenied):
        policy.accept_event("socket.bind", (listener, server_addr))
    policy.accept_event("socket.bind", (listener, ("127.0.0.1", 0)))
    policy.accept_event("socket.__new__", (writer, 2, 1, 0))
    for address in (("127.0.0.1", 50101), ("192.0.2.1", 50100)):
        with pytest.raises(admission.AdmissionDenied):
            policy.accept_event("socket.connect", (writer, address))
    with pytest.raises(admission.AdmissionDenied):
        policy.accept_event("socket.connect", (reader, server_addr))
    policy.accept_event("socket.connect", (writer, server_addr))
    with pytest.raises(admission.AdmissionDenied):
        policy.accept_event("socket.__new__", (reader, 2, 1, 0))
    policy.adopt_accepted(listener, reader, writer, client_addr)
    listener.descriptor = -1
    policy.verify_pair(reader, writer)
    with pytest.raises(admission.AdmissionDenied):
        policy.verify_pair(writer, reader)
    with pytest.raises(admission.AdmissionDenied):
        policy.accept_event("socket.__new__", (object(), 2, 1, 0))
    with pytest.raises(admission.AdmissionDenied):
        policy.accept_event("socket.getaddrinfo", ("localhost", 0, 2, 1, 0))


def test_unfinished_socketpair_is_rejected():
    with pytest.raises(admission.AdmissionDenied, match="SOCKET_PAIR_UNCONFIRMED"):
        admission.PrivateSocketAudit(family=2, kind=1).verify_pair(object(), object())


@pytest.fixture
def staged(tmp_path, monkeypatch):
    suite = tmp_path / "suite"
    suite.mkdir()
    script = suite / "tests/ui/app.test.cjs"
    script.parent.mkdir(parents=True)
    script.write_bytes(b"synthetic JS fixture")
    python = tmp_path / "runtime/python/python.exe"
    node = tmp_path / "runtime/node/node.exe"
    for path in (python, node):
        path.parent.mkdir(parents=True)
        path.write_bytes(path.name.encode())
    scratch = suite / "scratch"
    scratch.mkdir()
    for key, path in (("NODE_SHA", node), ("PYTHON_SHA", python), ("NODE_TEST_SHA", script)):
        monkeypatch.setattr(admission, key, sha256(path.read_bytes()).hexdigest())
    return dict(python=python, node=node, suite=suite, scratch=scratch, system_root=tmp_path)


def test_node_argv_executable_cwd_and_environment_must_all_match(staged):
    argv = (str(staged["node"]), "--test", "--test-isolation=none", "tests/ui/app.test.cjs")
    plan = admission.child_plan("node_ui", argv, **staged)
    def observed(executable=argv[0], command=list2cmdline(argv), cwd=plan.cwd, env=dict(plan.environment)):
        return plan.matches("subprocess.Popen", (executable, command, cwd, env))
    assert observed()
    assert not observed(executable=None)
    assert not observed(command=list2cmdline(argv + ("--eval",)))
    assert not observed(cwd=None)
    assert not observed(env={**dict(plan.environment), "NODE_OPTIONS": "synthetic"})
    def deny(event, args):
        raise admission.AdmissionDenied("FALLBACK")
    audit = admission.ScopedWorkerAudit(deny)
    event_args = argv[0], list2cmdline(argv), plan.cwd, dict(plan.environment)
    with pytest.raises(admission.AdmissionDenied):
        audit.audit("subprocess.Popen", event_args)
    with audit.scoped(plan):
        audit.audit("subprocess.Popen", event_args)
        with pytest.raises(admission.AdmissionDenied):
            audit.audit("subprocess.Popen", event_args)
        with pytest.raises(admission.AdmissionDenied):
            audit.audit("socket.__new__", (object(), 2, 1, 0))
    with pytest.raises(admission.AdmissionDenied):
        audit.audit("subprocess.Popen", event_args)
    with pytest.raises(admission.AdmissionDenied):
        admission.child_plan("node_ui", (*argv, "--inspect"), **staged)
    staged["node"].write_bytes(b"changed")
    with pytest.raises(admission.AdmissionDenied, match="PIN_CHANGED"):
        admission.child_plan("node_ui", argv, **staged)


def test_recovery_rejects_other_script_and_non_owned_paths(staged, monkeypatch):
    script = "synthetic Python Script"
    monkeypatch.setattr(admission, "RECOVERY_SHA", sha256(script.encode()).hexdigest())
    payload = (str(staged["python"]), "-B", "-u", "-c", script, str(staged["suite"]),
               str(staged["scratch"] / "two-recoveries.sqlite3"), str(staged["scratch"] / ("ready-" + "f" * 32)),
               str(staged["scratch"] / ("proceed-" + "a" * 32)), "gated")
    assert admission.child_plan("recovery", payload, **staged).argv == payload
    with pytest.raises(admission.AdmissionDenied, match="PYTHON_ARGV"):
        admission.child_plan("recovery", (*payload[:4], "other", *payload[5:]), **staged)
    with pytest.raises(admission.AdmissionDenied, match="CHILD_PATH"):
        admission.child_plan("recovery", (*payload[:6], str(staged["suite"] / "foreign.sqlite3"), *payload[7:]), **staged)
