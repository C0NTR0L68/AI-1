"""Build the approved B5 revision without altering the immutable control ZIP."""
import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


CONTROL_SHA = "569FD484C31746A0A3A2DA0D133C2EEB8D426C607E71888F2CE113A43F69D8E7"
APPROVAL_SHA = "2794577BC556D85A6341C4B97BAD70DD4197D776E9BDB8D9EE6596C74389B0D8"
TEST_APP = "suite/tests/test_app.py"
RELEASE_MANIFEST = "frozen/release-manifest.json"
REVISED_TEST = "suite/tests/test_schema_contract.py"


def digest(data):
    return sha256(data).hexdigest().upper()


def dump(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")


def functions(data):
    return [node for node in ast.parse(data).body
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]


def inventory(files):
    return sorted(f"{name.removeprefix('suite/')}::{node.name}"
                  for name, data in files.items()
                  if name.startswith("suite/tests/test_") and name.endswith(".py")
                  for node in functions(data))


def build(control, destination):
    approved = Path(__file__).resolve().parent
    proposal_bytes = (approved / "revision-manifest.json").read_bytes()
    if digest(proposal_bytes) != APPROVAL_SHA or digest(control.read_bytes()) != CONTROL_SHA:
        raise ValueError("Immutable input hash mismatch")
    proposal = json.loads(proposal_bytes)
    for name, expected in proposal["proposal_sha256"].items():
        if digest((approved / name).read_bytes()) != expected:
            raise ValueError("Reviewed proposal bytes changed")
    with ZipFile(control) as bundle:
        old = json.loads(bundle.read("MANIFEST.json"))
        if bundle.testzip() or set(bundle.namelist()) != (set(old) | {"MANIFEST.json"}):
            raise ValueError("Invalid control bundle")
        files = {name: bundle.read(name) for name in old}
    if any(digest(data) != old[name] for name, data in files.items()):
        raise ValueError("Control component changed")
    if {name: old[name] for name in old if name.startswith("suite/tests/")} != proposal["original_test_sha256"]:
        raise ValueError("Original test pins changed")

    removed = set(proposal["candidate_case_mapping"])
    before = inventory(files)
    matches = [node for node in functions(files[TEST_APP]) if node.name in removed]
    if (len(matches) != 2 or {node.name for node in matches} != removed
            or any(node.decorator_list for node in matches)):
        raise ValueError("Reviewed replacement boundaries changed")
    lines = files[TEST_APP].splitlines(keepends=True)
    for node in sorted(matches, key=lambda node: node.lineno, reverse=True):
        del lines[node.lineno - 1:node.end_lineno]
    files[TEST_APP] = b"".join(lines)

    manifest = json.loads(files[RELEASE_MANIFEST])
    for source_name, target_name in proposal["overlay"].items():
        if target_name in files:
            raise ValueError("Overlay would overwrite frozen input")
        data = (approved / source_name).read_bytes()
        files[target_name] = data
        if target_name.startswith("frozen/release/"):
            manifest["files"][target_name.removeprefix("frozen/release/")] = digest(data)
    # Preserve the frozen launcher's original serialization and SHA pin contract.
    files[RELEASE_MANIFEST] = dump(manifest)
    after = inventory(files)
    new_names = {name for group in proposal["candidate_case_mapping"].values() for name in group}
    if (len(before) != 195 or len(after) != 198 or len(set(after)) != len(after)
            or set(before) - set(after) != {f"tests/test_app.py::{name}" for name in removed}
            or set(after) - set(before) != {f"tests/test_schema_contract.py::{name}" for name in new_names}):
        raise ValueError("Unexpected candidate inventory")
    if digest(files["frozen/release/app/history_preflight.py"]) != proposal["unchanged_preflight_sha256"]:
        raise ValueError("Production admission changed")

    revision = {
        "approved_commit": "b81238102d688b39ee0a6f11db4f85936416ac76",
        "control_sha256": CONTROL_SHA,
        "control_result": proposal["baseline_control"],
        "proposal_manifest_sha256": APPROVAL_SHA,
        "release_manifest_sha256": digest(files[RELEASE_MANIFEST]),
        "expected_base_ids": after,
        "expected_collected": 609,
        "removed_control_ids": sorted(set(before) - set(after)),
        "new_candidate_ids": sorted(set(after) - set(before)),
    }
    files["REVISION.json"] = dump(revision)
    files["MANIFEST.json"] = dump({name: digest(data) for name, data in files.items()})
    with ZipFile(destination, "x") as result:
        for name, data in sorted(files.items()):
            info = ZipInfo(name)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            result.writestr(info, data, compress_type=ZIP_DEFLATED, compresslevel=9)
    with ZipFile(destination) as result:
        if result.testzip() or any(result.read(name) != data for name, data in files.items()):
            raise ValueError("Candidate verification failed")
    return {"archive_sha256": digest(destination.read_bytes()),
            "manifest_sha256": digest(files["MANIFEST.json"]),
            "revision_sha256": digest(files["REVISION.json"]),
            "release_manifest_sha256": revision["release_manifest_sha256"],
            "size": destination.stat().st_size,
            "base_functions": len(after), "expected_cases": 609,
            "control_sha256": CONTROL_SHA}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.control, args.output), indent=2))
