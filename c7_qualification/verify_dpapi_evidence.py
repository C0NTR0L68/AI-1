"""Reconcile redacted Windows receipts with exact Git bytes."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument("repo", type=Path)
parser.add_argument("evidence", type=Path)
parser.add_argument("archive", type=Path)
args = parser.parse_args()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(data):
    return sha256(data).hexdigest().upper()


def git(*command):
    return subprocess.check_output(("git", "-C", str(args.repo), *command))


previous = "9e58189325c2d705e1d8480df37b26b095f56ba1"
historical_test = "55f003f7aa5276f544daa03598151b36bc654325"
path = "c7_qualification/standard-client-evidence/"
old = json.loads(git("show", previous + ":" + path + "qualification.json"))
for name, pin in old["sha256"].items():
    assert digest(git("show", previous + ":" + path + name)) == pin, name
assert not git("diff", historical_test, previous, "--", "app", "tests")

evidence = args.evidence
candidate = read_json(evidence / "medium-e2e.json")
revision = candidate["revision"]
assert not git("diff", previous, revision, "--", "app", "tests")
assert candidate["guest_exit"] == candidate["ordinary_bridge_exit"] == 42
assert candidate["profile"] == "medium" and candidate["end_to_end"] is True
assert candidate["client-unqualified"] is None
phases = [
    "compile", "scm-registration", "roles", "provision", "ordinary-preflight", "start",
    "ipc", "wrong-peer", "dropped", "ipc-recovered", "stop", "counterfeit",
    "restart", "crash", "storage-denials", "recovery", "cleanup", "application-pins",
    "archive-enrollment", "dpapi-boundary", "e2e-live", "wrong-generation",
    "corrupt", "stale", "replaced-path", "e2e-restored", "e2e-drop", "e2e-timeout",
    "e2e-down", "e2e-restart",
]
assert len(set(phases)) == 30
assert all(candidate.get(phase) == 42 for phase in phases)
assert int(candidate["dpapi_native_error_hex"], 16) != 0
pins = candidate["source_sha256"]
staged = {f"c7_qualification/{name}": pins[name] for name in
          ("scm_service.cs", "scm_probe.py", "scm_dpapi_e2e.py")}
staged["app/memory_authority_pipe.py"] = pins["memory_authority_pipe.py"]
staged["c7_qualification/scm_guest.ps1"] = candidate["guest_script_sha256"]
staged["c7_qualification/standard_user_preflight.ps1"] = candidate["ordinary_bridge_sha256"]
for name, pin in {**staged, **pins["application"]}.items():
    assert digest(git("show", revision + ":" + name)) == pin, name
required = set(git("ls-tree", "-r", "--name-only", revision, "app").decode().splitlines())
assert set(pins["application"]) == required | {"c7_qualification/probe.py"}

runtime_sha = "9D56A383933EA9D5469A3CE8588262376CDCDFC59438AF6779B3CE2FA85D7500"
assert digest(args.archive.read_bytes()) == runtime_sha
with zipfile.ZipFile(args.archive) as frozen:
    assert frozen.testzip() is None
    manifest = frozen.read("MANIFEST.json")
    assert digest(manifest) == "9E3363DAA02196EF011ED68BD8335838ED64992AA3854A625A2972D0FDC52E15"
    for name, pin in pins["application"].items():
        if name != "app/memory_authority_pipe.py":
            assert digest(frozen.read(name)) == pin, name

assert read_json(evidence / "isolation.json")["ExitCode"] == 42
cleanup = read_json(evidence / "sandbox-cleanup.json")
assert cleanup["stop_exit"] == cleanup["list_exit"] == 0 and cleanup["owned_session_absent"] is True
assert "GUEST_FROZEN_SHA256_MATCH=" + runtime_sha in (evidence / "transfer.log").read_text(encoding="utf-8-sig")
assert "Implicit medium rejected before guest operation PASS" in (evidence / "static.log").read_text(encoding="utf-8-sig")
failed = read_json(evidence / "medium-e2e-enrollment-fail.json")
assert failed["guest_exit"] == 1 and failed["failed_phase_code"] == 112
assert failed["cleanup"] == failed["ordinary_bridge_exit"] == 42
print(json.dumps({
    "native_medium_read_only_e2e": "PASS", "checkpoints": phases,
    "tested_commit": revision, "previous_report_commit": previous,
    "verified_previous_receipts": len(old["sha256"]),
    "guest_application_and_fixture_helper_git_sha256": len(pins["application"]),
    "native_dpapi_authority_denied_hex": candidate["dpapi_native_error_hex"],
    "high_default": "PASS_STATIC_PRIOR_NATIVE",
    "uvicorn_listener": "NOT_RUN_ASGI_ONLY", "ipc_cas": "NOT_RUN",
    "production": "NO-GO", "memory_v2": "OFF",
    "sha256": {file.name: digest(file.read_bytes()) for file in sorted(evidence.iterdir())
               if file.is_file() and file.name not in {"qualification.json", "verify_evidence.py"}},
}, indent=2))
