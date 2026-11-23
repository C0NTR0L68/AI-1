"""Targeted synthetic recovery and cancellation checks. Windows Sandbox only."""
import argparse
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from time import monotonic
import unittest
from uuid import UUID, uuid4


ROOT = Path(__file__).resolve().parents[1]
PARCEL = ROOT.parent
SCRATCH = PARCEL / "deployment-safety"
DB = SCRATCH / "synthetic-head.sqlite3"
GENERATION = UUID("41294742-5d72-49f8-8393-d283e433e7ed")


def require(condition):
    if not condition:
        raise AssertionError("Synthetic deployment invariant failed")


def registry():
    from app.memory_head_v2 import DurableHeadRegistry

    return DurableHeadRegistry(lambda: sqlite3.connect(DB.as_uri() + "?mode=rw", uri=True, timeout=2))


def digest(revision):
    return sha256(str(revision).encode("ascii")).digest()


def head(revision):
    from app.memory_head_v2 import Head

    return Head(GENERATION, revision, digest(revision))


def prepared():
    require(os.name == "nt" and os.getlogin().casefold() == "wdagutilityaccount")
    require(PARCEL.parent == Path(r"C:\Users\Public\Documents"))
    require(re.fullmatch("AI1-C7-[a-f0-9]{32}", PARCEL.name) is not None and ROOT.name == "payload")
    require(not SCRATCH.is_symlink() and not SCRATCH.is_junction())
    sys.path.insert(0, str(ROOT))


def child(phase):
    if phase == "interrupted":
        connection = sqlite3.connect(DB.as_uri() + "?mode=rw", uri=True)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA cache_size=1")
        connection.execute("PRAGMA cache_spill=ON")
        connection.execute("BEGIN IMMEDIATE")
        connection.executemany("UPDATE main.head_journal SET digest=? WHERE revision=?",
                               ((digest(i + 4096), i) for i in range(1, 2049)))
        # Stop while the real rollback journal is needed. The parent verifies
        # that cache spill changed the main file and the journal header is hot.
        os._exit(73)
    require(phase == "lost-ack" and registry().advance(head(2048), head(2049)))
    os._exit(74)


def run_child(phase, expected):
    result = subprocess.run([sys.executable, "-I", "-S", "-B", __file__, "--child", phase],
                            cwd=SCRATCH, timeout=12, check=False)
    require(result.returncode == expected)


class DeploymentChecks(unittest.TestCase):
    def test_offline_gate_denies_unknown_mismatch_and_shared_identity(self):
        import deployment_gate as gate

        plan = {"authority_sid": "S-1-5-80-1-2-3-4-5", "client_sid": "S-1-5-21-1-2-3-1001",
                "client_integrity": 12288, "runtime_sha256": "a"*64, "enrollment_sha256": "b"*64,
                "runtime_root": r"C:\AuthorityRuntime", "head_root": r"C:\AuthorityState",
                "archive_root": r"D:\Archive"}
        for index, name in enumerate(("runtime_chain", "head_chain", "archive_chain")):
            volume = f"e5a67686-feb2-4dc8-a5cf-{int(index == 2) + 1:012x}"
            plan[name] = [f"{volume}:{1:032x}", f"{volume}:{index + 2:032x}"]
        self.assertEqual(gate.evaluate(plan, {})["checks"]["archive_chain"], "UNKNOWN")
        same = dict(plan, client_sid=plan["authority_sid"])
        with self.assertRaises(ValueError):
            gate.evaluate(same, {})
        nested = dict(plan, head_root=r"C:\AuthorityRuntime\State")
        with self.assertRaises(ValueError):
            gate.evaluate(nested, {})
        evidence = {name: {"result": "PASS", "sha256": "c"*64} for name in gate._CHECKS}
        result = gate.evaluate(plan, {**plan, **evidence})
        self.assertTrue(result["review_ready"])
        self.assertEqual(result["release"], "NO-GO")
        result = gate.evaluate(plan, {**plan, **evidence, "client_integrity": 8192})
        self.assertEqual(result["checks"]["client_integrity"], "FAIL")
        self.assertFalse(result["review_ready"])

    def test_real_hot_journal_recovery_then_lost_ack(self):
        with DB.open("xb"):
            pass
        authority = registry()
        authority.provision(head(0))
        with closing(sqlite3.connect(DB.as_uri() + "?mode=rw", uri=True)) as connection, connection:
            connection.executemany("INSERT INTO main.head_journal VALUES (?,?,?)",
                                   ((i, GENERATION.bytes, digest(i)) for i in range(1, 2049)))
        self.assertEqual(authority.read(), head(2048))
        original = sha256(DB.read_bytes()).digest()
        run_child("interrupted", 73)
        journal = DB.with_name(DB.name + "-journal")
        self.assertEqual(journal.read_bytes()[:8], bytes.fromhex("d9d505f920a163d7"))
        self.assertNotEqual(sha256(DB.read_bytes()).digest(), original)
        self.assertEqual(registry().read(), head(2048))
        self.assertFalse(journal.exists())
        self.assertEqual(sha256(DB.read_bytes()).digest(), original)
        run_child("lost-ack", 74)
        self.assertEqual(registry().read(), head(2049))
        self.assertFalse(registry().advance(head(2048), head(2049)))

    def test_native_overlapped_accept_read_and_reuse(self):
        import _winapi as api
        from app.memory_authority_pipe import _io_result, _receive, _send

        for _ in range(16):
            address = r"\\.\pipe\AI1-C7-" + uuid4().hex
            pipe = api.CreateNamedPipe(address, api.PIPE_ACCESS_DUPLEX | api.FILE_FLAG_OVERLAPPED |
                                       api.FILE_FLAG_FIRST_PIPE_INSTANCE, 8, 1, 4096, 4096, 1000, api.NULL)
            try:
                pending = api.ConnectNamedPipe(pipe, overlapped=True)
                with self.assertRaises(TimeoutError):
                    _io_result(api, pending, monotonic() + 0.02)
                pending = api.ConnectNamedPipe(pipe, overlapped=True)
                client = api.CreateFile(address, 0x0012008B, 0, api.NULL, api.OPEN_EXISTING,
                                        api.FILE_FLAG_OVERLAPPED, api.NULL)
                try:
                    _io_result(api, pending, monotonic() + 1)
                    with self.assertRaises(TimeoutError):
                        _receive(api, pipe, 1, monotonic() + 0.02)
                    _send(api, client, b"x", monotonic() + 1)
                    self.assertEqual(_receive(api, pipe, 1, monotonic() + 1), b"x")
                finally:
                    api.CloseHandle(client)
            finally:
                api.CloseHandle(pipe)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", choices=("interrupted", "lost-ack"))
    args = parser.parse_args()
    prepared()
    if args.child:
        require(SCRATCH.is_dir() and DB.is_file())
        child(args.child)
    SCRATCH.mkdir()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(DeploymentChecks))
    report = {"tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skips": len(result.skipped)}
    (SCRATCH / "result.json").write_text(json.dumps(report), encoding="ascii")
    return 42 if result.wasSuccessful() and report == {"tests": 3, "failures": 0, "errors": 0, "skips": 0} else 1


if __name__ == "__main__":
    raise SystemExit(main())
