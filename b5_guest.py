"""Disposable Windows B5 entry. The host must attest the Windows Sandbox first."""
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
from uuid import uuid4
from zipfile import ZipFile


ARCHIVE_SHA = "569FD484C31746A0A3A2DA0D133C2EEB8D426C607E71888F2CE113A43F69D8E7"


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
    if _sha(archive) != ARCHIVE_SHA.lower():
        raise RuntimeError("Offline package hash mismatch")
    with ZipFile(archive) as original:
        expected = json.loads(original.read("MANIFEST.json"))
    if len(expected) != 697:
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
    if len(expected) != 195:
        raise RuntimeError("Unexpected frozen test inventory")
    return expected


def _worker(root, mode):
    sys.path[:0] = [str(root.parent / "runner"), str(root / "deps")]
    from adapters import prepare_candidate
    from guard import Policy
    from harness import pytest_plan
    from b5_admission import AdmissionDenied, ScopedWorkerAudit
    from b5_worker_adapters import scoped_worker_adapters
    import asyncio
    import socket
    import subprocess
    import pytest

    suite, temp = root / "suite", root / "temp"
    python = root / "runtime/python/python.exe"
    node = root / "runtime/node/node.exe"
    policy = Policy(root, root / "unavailable-live-project")
    policy.read_roots += (root.parent / "runner",)
    audit = ScopedWorkerAudit(policy.audit)
    expected = _inventory(suite)
    evidence = {"mode": mode, "socketpair": False, "external_socket_denied": False, "items": []}

    class Results:
        def pytest_collection_finish(self, session):
            collected = {(Path(item.path).name, item.originalname or item.name.split("[", 1)[0])
                         for item in session.items}
            if collected != expected:
                raise RuntimeError("Collected tests differ from frozen inventory")
            evidence["base_functions"] = len(collected)
            evidence["collected"] = len(session.items)

        def pytest_runtest_logreport(self, report):
            evidence["items"].append([report.nodeid, report.when, report.outcome])

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
                                scratch=temp, system_root=Path(os.environ["SystemRoot"])):
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
            _, restore = prepare_candidate(root / "frozen", policy)
            try:
                args = pytest_plan(root, suite)
                args[args.index("--basetemp") + 1] = str(temp / ("pytest-" + uuid4().hex))
                code = pytest.main([*args, "--noconftest", "-p", "no:faulthandler"], plugins=[Results()])
            finally:
                restore()
    if code == 0 and policy.denials:
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
    raise SystemExit(main())
