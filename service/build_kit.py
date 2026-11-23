"""Assemble only a byte-identical, Sandbox-qualified SCM binary and pinned inputs."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_inputs import RUNTIME_SHA, sha


QUALIFICATION = (
    "application-pins", "compile", "scm-registration", "roles", "production-enrollment",
    "write-start", "write", "wrong-peer", "write-stop", "resume", "verify-write",
    "write-final-stop", "production-rollback", "cleanup",
)


def build(receipt, binary, inputs, runtime, launch_template, output):
    q = json.loads(receipt.read_text(encoding="utf-8-sig"))
    if (q["guest_exit"] != 42 or q["ordinary_bridge_exit"] != 42 or q["production_binary"] is not True
            or not all(q[key] == 42 for key in QUALIFICATION)):
        raise ValueError("Exact binary qualification missing")
    exe = binary.read_bytes()
    manifest = inputs.read_bytes()
    runtime_bytes = runtime.read_bytes()
    if (sha(exe) != q["production_sha256"]["binary-sha"] or not exe.startswith(b"MZ")
            or sha(manifest) != q["source_sha256"]["inputs.sha256"] or sha(runtime_bytes) != RUNTIME_SHA):
        raise ValueError("Candidate package input hash mismatch")
    members = {}
    with zipfile.ZipFile(runtime) as frozen:
        for row in manifest.decode("ascii").splitlines():
            digest, name = row.split(" ", 1)
            if (name in members or ".." in name or not re.fullmatch(
                    r"payload/(?:runtime/python|app)/[a-zA-Z0-9_./+\-]+", name)):
                raise ValueError("Invalid install member")
            source = name.removeprefix("payload/")
            if source.startswith("runtime/python/"):
                data = frozen.read(source)
            else:
                data = subprocess.check_output(["git", "show", q["revision"] + ":" + source])
            if sha(data) != digest:
                raise ValueError("Install member hash mismatch")
            members[name] = data
    members["Authority.exe"] = exe
    members["inputs.sha256"] = manifest
    members["scm-launch.template.json"] = launch_template.read_bytes()
    members["release.json"] = json.dumps({
        "tested_commit": q["revision"], "activation": "OFF", "production": "NO-GO",
        "sha256": {name: sha(data) for name, data in sorted(members.items())},
    }, indent=2).encode("ascii") + b"\n"
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as package:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            package.writestr(info, data)
    with zipfile.ZipFile(output) as package:
        if package.testzip() is not None or any(package.read(name) != data for name, data in members.items()):
            raise ValueError("Assembled ZIP comparison failed")
    return sha(output.read_bytes())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("receipt", "binary", "inputs", "runtime", "launch_template", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(build(**vars(args)))
