"""Disposable Windows B5 entry. The host must attest the Windows Sandbox first."""
import ast
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
from uuid import uuid4
from zipfile import ZipFile


ARCHIVE_SHA = "569FD484C31746A0A3A2DA0D133C2EEB8D426C607E71888F2CE113A43F69D8E7"
SCHEMA_REVISION_SHA = "4BCE5F2BEF7CB4374CB42F8AFDD56C6BC5304CAD7A5754282E5808C417A66D15"
SCHEMA_DESCRIPTOR_SHA = "56B59923D8A4BB7E6E03D620019467B6B2C55729B4A8F3722503F276B81D8134"
SCHEMA_FROZEN_MANIFEST_SHA = "52997E9F64227787DCD56D36D3D07978F161CAA169DDAC589D861A23DCCCADCC"
SCHEMA_COLLECTION_SHA = "e94ca9c3a4dfb44926d5d059ccdfb24df3fbecdfd30f462f48d5d252364d83fa"
SCHEMA_CASES = {
    "test_existing_trigger_is_refused_before_provider_and_without_writes",
    "test_post_admission_sqlite_failure_rolls_back_turn_and_reports_unknown",
    "test_explicit_legacy_export_preserves_api_provenance_and_source[False]",
    "test_explicit_legacy_export_preserves_api_provenance_and_source[True]",
    "test_export_refuses_unreviewed_sources_and_rolls_back[trigger]",
    "test_export_refuses_unreviewed_sources_and_rolls_back[duplicate]",
    "test_export_refuses_unreviewed_sources_and_rolls_back[unknown_status]",
    "test_export_does_not_modify_existing_target",
}


def _sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _member(name):
    rel = PurePosixPath(name)
    if rel.is_absolute() or rel.as_posix() != name or any(
        p in ("", ".", "..") or ":" in p or "\\" in p or p.endswith((".", " ")) for p in rel.parts
    ):
        raise ValueError("Unsafe member")
    return rel


def _verify_packages(root):
    archive = root.parent / "AI-1-B5-Offline.zip"
    archive_pin = _sha(archive).upper()
    if archive_pin not in (ARCHIVE_SHA, SCHEMA_REVISION_SHA):
        raise RuntimeError("Offline package hash mismatch")
    with ZipFile(archive) as original:
        expected = json.loads(original.read("MANIFEST.json"))
    if len(expected) != (700 if archive_pin == SCHEMA_REVISION_SHA else 697):
        raise RuntimeError("Offline manifest shape")
    for name, pin in expected.items():
        path = root.joinpath(*_member(name).parts)
        for component in (path, *path.parents):
            if component.is_symlink() or component.is_junction():
                raise RuntimeError("Linked package path")
            if component == root:
                break
        info = path.lstat()
        if path.is_symlink() or path.is_junction() or info.st_nlink != 1 or _sha(path) != pin.lower():
            raise RuntimeError("Unverified package member")
    if (archive_pin == SCHEMA_REVISION_SHA) != (_schema_revision(root) is not None):
        raise RuntimeError("Archive revision descriptor mismatch")


def _schema_revision(root):
    path = root / "REVISION.json"
    if not path.exists():
        return None
    if (_sha(path).upper() != SCHEMA_DESCRIPTOR_SHA
            or _sha(root / "frozen/release-manifest.json").upper() != SCHEMA_FROZEN_MANIFEST_SHA):
        raise RuntimeError("Unverified candidate revision")
    return json.loads(path.read_bytes())


def _prepare(root):
    suite, frozen = root / "suite", root / "frozen"
    deps = root / "deps"
    deps.mkdir()
    for wheel in sorted((root / "wheels").glob("*.whl")):
        with ZipFile(wheel) as source:
            for member in source.infolist():
                if member.is_dir():
                    continue
                rel = _member(member.filename)
                if rel.parts[0].endswith(".data"):
                    # Wheels with only package-root payload are required.
                    raise RuntimeError("Unsupported wheel .data layout")
                dest = deps.joinpath(*rel.parts)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with source.open(member) as stream, dest.open("xb") as target:
                    shutil.copyfileobj(stream, target)
    shutil.copytree(frozen / "release/app", suite / "app")
    (root / "input").mkdir()
    (root / "temp").mkdir()
    (root / "pytest.ini").write_text("[pytest]\n", encoding="ascii")


def _clean_environment(root):
    system = Path(os.environ["SystemRoot"])
    return {
        "SystemRoot": str(system), "WINDIR": str(system),
        "PATH": str(root / "runtime/node"), "TMP": str(root / "temp"), "TEMP": str(root / "temp"),
        "PYTHON_DOTENV_DISABLED": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }


def _inventory(suite):
    expected = set()
    for path in (suite / "tests").glob("test_*.py"):
        source = ast.parse(path.read_bytes())
        expected.update((path.name, node.name) for node in source.body
                        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"))
    revision = _schema_revision(suite.parent)
    if len(expected) != (198 if revision else 195):
        raise RuntimeError("Unexpected frozen test inventory")
    if revision and {f"tests/{name}::{case}" for name, case in expected} != set(revision["expected_base_ids"]):
        raise RuntimeError("Frozen candidate test identifiers changed")
    return expected


def _candidate_assets(factory, test_file):
    """Substitute admitted assets only at the reviewed placeholder fixture."""
    placeholder = {name: b"synthetic" for name in ("index.html", "app.js", "style.css")}

    def create_app(*args, **kwargs):
        caller = sys._getframe(1).f_code
        if (Path(caller.co_filename) == test_file and caller.co_name == "app_for"
                and kwargs.get("assets") == placeholder):
            kwargs["assets"] = None
        return factory(*args, **kwargs)
    return create_app


@contextmanager
def _disable_pytest_current_link(pathlib_module, basetemp):
    """Omit pytest's optional newest-directory shortcut inside this run."""
    original = pathlib_module._force_symlink
    allocator = pathlib_module.make_numbered_dir.__code__

    def force_symlink(root, name, directory):
        if (sys._getframe(1).f_code is allocator and root == basetemp
                and directory.parent == root and name.endswith("current")):
            prefix = name.removesuffix("current")
            if directory.name.startswith(prefix) and directory.name[len(prefix):].isdecimal():
                return
        return original(root, name, directory)

    pathlib_module._force_symlink = force_symlink
    try:
        yield
    finally:
        pathlib_module._force_symlink = original


def verify_collection(items, expected, revision):
    collected = {(Path(item.path).name, item.originalname or item.name.split("[", 1)[0])
                 for item in items}
    if collected != expected:
        raise RuntimeError("Collected tests differ from frozen inventory")
    result = {"base_functions": len(collected), "collected": len(items)}
    if revision:
        case_ids = sorted(item.nodeid.replace("\\", "/") for item in items)
        overlay = {case.rsplit("::", 1)[-1] for case in case_ids
                   if case.startswith("tests/test_schema_contract.py::")}
        if (len(case_ids) != revision["expected_collected"]
                or len(set(case_ids)) != len(case_ids) or overlay != SCHEMA_CASES):
            raise RuntimeError("Expanded candidate inventory differs")
        result["collection_sha256"] = hashlib.sha256(
            ("\n".join(case_ids) + "\n").encode("utf8")
        ).hexdigest()
        if result["collection_sha256"] != SCHEMA_COLLECTION_SHA:
            raise RuntimeError("Expanded candidate collection hash mismatch")
    return result


class CanonicalFixturePath:
    """One temporary alias supplied by the unchanged runtime-lock test."""

    def __init__(self):
        self.alias = self.canonical = None

    def arm(self, directory):
        unused = directory / "unused"
        try:
            unused.lstat()
        except FileNotFoundError:
            pass
        else:
            raise PermissionError("Canonical fixture parent must not exist")
        self.canonical = directory / "identity.sqlite3"
        self.alias = unused / ".." / self.canonical.name

    def disarm(self):
        self.alias = self.canonical = None

    def inspect(self, value):
        return self.canonical if self.alias is not None and Path(os.fsdecode(value)) == self.alias else value


def _worker(root, mode):
    sys.path[:0] = [str(root.parent / "runner"), str(root / "deps")]
    import adapters
    from guard import Policy
    from harness import pytest_plan
    from b5_admission import AdmissionDenied, ScopedWorkerAudit
    from b5_worker_adapters import scoped_worker_adapters
    import asyncio
    import socket
    import subprocess
    import pytest
    from _pytest import pathlib as pytest_pathlib

    suite, temp = root / "suite", root / "temp"
    revision = _schema_revision(root)
    if revision:
        adapters.MANIFEST_SHA = SCHEMA_FROZEN_MANIFEST_SHA
    python = root / "runtime/python/python.exe"
    node = root / "runtime/node/node.exe"
    fixture_path = CanonicalFixturePath()

    class WorkerPolicy(Policy):
        def sqlite(self, value):
            return super().sqlite(fixture_path.inspect(value))

        def audit(self, event, args):
            if event == "sqlite3.connect":
                # The runtime lock may inspect the fixture alias, but SQLite
                # itself must still receive a canonical path.
                Policy.sqlite(self, args[0])
            return super().audit(event, args)

    policy = WorkerPolicy(root, root / "unavailable-live-project")
    policy.read_roots += (root.parent / "runner",)
    audit = ScopedWorkerAudit(policy.audit)
    expected = _inventory(suite)
    evidence = {"mode": mode, "socketpair": False, "external_socket_denied": False, "items": []}
    node_results = []

    class Results:
        def pytest_collection_finish(self, session):
            evidence.update(verify_collection(session.items, expected, revision))

        def pytest_runtest_logreport(self, report):
            evidence["items"].append([report.nodeid, report.when, report.outcome])

        @pytest.hookimpl(hookwrapper=True)
        def pytest_runtest_call(self, item):
            if item.nodeid == "tests/test_app.py::test_runtime_lock_uses_canonical_path_and_blocks_recovery_before_sqlite":
                fixture_path.arm(policy.owned(item.funcargs["tmp_path"]))
            try:
                yield
            finally:
                fixture_path.disarm()

    async def smoke():
        await asyncio.sleep(0)
        return True

    def pinned_child_canary():
        tree = ast.parse((suite / "tests/test_memory_security.py").read_bytes())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == "test_module_import_and_disabled_state_have_no_app_storage_or_network_dependencies")
        source = next(node.value.value for node in function.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "script" for target in node.targets))
        result = subprocess.run([str(python), "-I", "-B", "-c", source, str(suite)],
                                capture_output=True, text=True, timeout=15)
        return result.returncode == 0 and result.stdout.strip() == "SECURITY_ISOLATION_OK"

    sys.addaudithook(audit.audit)
    with scoped_worker_adapters(audit, python=python, node=node, suite=suite,
                                scratch=temp, system_root=Path(os.environ["SystemRoot"]),
                                node_results=node_results):
        evidence["socketpair"] = asyncio.run(smoke()) is True
        try:
            socket.socket()
        except PermissionError:
            evidence["external_socket_denied"] = True
        if not all(evidence[k] for k in ("socketpair", "external_socket_denied")):
            raise AdmissionDenied("GUEST_SOCKET_CANARY")
        policy.denials.clear()
        if mode == "preflight":
            evidence["pinned_python_child"] = pinned_child_canary()
            if not evidence["pinned_python_child"]:
                raise AdmissionDenied("GUEST_CHILD_CANARY")
            code = 0
        else:
            app_main, restore = adapters.prepare_candidate(root / "frozen", policy)
            if revision:
                app_main.create_app = _candidate_assets(
                    app_main.create_app, suite / "tests/test_schema_contract.py"
                )
            try:
                args = pytest_plan(root, suite)
                basetemp = temp / ("pytest-" + uuid4().hex)
                args[args.index("--basetemp") + 1] = str(basetemp)
                shortcuts = _disable_pytest_current_link(pytest_pathlib, basetemp) if revision else nullcontext()
                with shortcuts:
                    code = pytest.main([*args, "--noconftest", "-p", "no:faulthandler"], plugins=[Results()])
            finally:
                restore()
    evidence["node_results"] = node_results
    if code == 0 and (policy.denials or revision and mode == "suite" and node_results != [
        {"tests": 22, "pass": 22, "fail": 0, "cancelled": 0, "skipped": 0, "todo": 0}
    ]):
        code = 75
    evidence["exit"] = int(code)
    evidence["denials"] = policy.denials
    (root / ("result-" + mode + ".json")).write_text(json.dumps(evidence), encoding="utf8")
    return int(code)


def main():
    args = sys.argv[1:]
    if len(args) not in (2, 3) or os.name != "nt":
        raise RuntimeError("Disposable Windows guest required")
    if os.getlogin().casefold() != "wdagutilityaccount":
        raise RuntimeError("Windows Sandbox guest account required")
    if len(args) == 3:
        if args[0] != "worker" or args[1] not in ("preflight", "suite"):
            raise RuntimeError("Invalid worker mode")
        root = _guest_root(args[2])
        sys.path.insert(0, str(root.parent / "runner"))
        from b5_worker_job import require_worker_job

        require_worker_job()
        return _worker(root, args[1])
    root, mode = _guest_root(args[0]), args[1]
    if mode not in ("preflight", "suite"):
        raise RuntimeError("Invalid supervisor mode")
    sys.path.insert(0, str(root.parent / "runner"))
    from b5_worker_job import run_worker

    _verify_packages(root)
    if mode == "preflight":
        _prepare(root)
    else:
        proof = json.loads((root / "result-preflight.json").read_text(encoding="utf8"))
        if (proof["exit"] != 0 or proof["mode"] != "preflight" or not proof["socketpair"]
                or not proof["external_socket_denied"] or not proof["pinned_python_child"]):
            raise RuntimeError("Guest preflight not approved")
    report = root / ("result-" + mode + ".json")
    if report.exists():
        report.rename(root / ("previous-" + mode + "-" + uuid4().hex + ".json"))
    code = run_worker(root / "runtime/python/python.exe", Path(__file__), root,
                      _clean_environment(root), deadline_ms=180_000, mode=mode)
    failure = root / ("failure-" + mode + ".txt")
    if code != 0 and failure.is_file():
        print(failure.read_text(encoding="utf8"))
    _verify_packages(root)
    return code


def _guest_root(value):
    root = Path(value)
    if (not root.is_absolute() or root.name != "payload"
            or not root.parent.name.startswith("AI1-B5-")
            or root.parent.parent != Path(r"C:\Users\Public\Documents")):
        raise RuntimeError("Dedicated guest parcel path required")
    return root


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        if len(sys.argv) == 4 and sys.argv[1] == "worker" and sys.argv[2] in ("preflight", "suite"):
            if os.name == "nt" and os.getlogin().casefold() == "wdagutilityaccount":
                import traceback

                root = _guest_root(sys.argv[3])
                path = root / ("failure-" + sys.argv[2] + ".txt")
                path.write_text(traceback.format_exc(limit=8), encoding="utf8")
        raise
