"""Freeze exact Git blobs with the previously verified offline wheels/runtime."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


FROZEN = "4BCE5F2BEF7CB4374CB42F8AFDD56C6BC5304CAD7A5754282E5808C417A66D15"
TESTS = ("tests/test_memory_storage_binding.py", "tests/test_memory_windows_archive.py")
PROBES = ("c7_qualification/probe.py", "c7_qualification/authority_fixture.py",
          "c7_qualification/binding_suite.py")


def pin(data):
    return sha256(data).hexdigest().upper()


def build(checkout, revision, frozen, output):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(checkout), *args])

    revision = git("rev-parse", "--verify", revision + "^{commit}").decode().strip()
    if pin(frozen.read_bytes()) != FROZEN:
        raise ValueError("Frozen runtime pin mismatch")
    app = git("ls-tree", "-r", "--name-only", "-z", revision, "--", "app").decode().split("\0")
    files = {name: git("show", f"{revision}:{name}")
             for name in (*app, *TESTS, *PROBES)
             if name.endswith((".py", ".html", ".css", ".js"))}
    files["probe.py"] = files["c7_qualification/probe.py"]
    with ZipFile(frozen) as source:
        supplied = json.loads(source.read("MANIFEST.json"))
        for name, expected in supplied.items():
            if name.startswith(("runtime/python/", "wheels/")):
                data = source.read(name)
                if pin(data) != expected:
                    raise ValueError("Frozen member pin mismatch")
                files[name] = data
    pins = {"git_revision": revision, "files": {name: pin(data) for name, data in files.items()}}
    manifest = (json.dumps(pins, indent=2, sort_keys=True) + "\n").encode()
    with ZipFile(output, "x") as z:
        for name, data in sorted({**files, "MANIFEST.json": manifest}.items()):
            z.writestr(ZipInfo(name), data, compress_type=ZIP_DEFLATED, compresslevel=6)
    with ZipFile(output) as z:
        if z.testzip() or any(pin(z.read(name)) != digest for name, digest in pins["files"].items()):
            raise RuntimeError("Bundle readback mismatch")
    return {"revision": revision, "members": len(files), "archive_sha256": pin(output.read_bytes()),
            "manifest_sha256": pin(manifest)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("revision")
    parser.add_argument("frozen", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.checkout, args.revision, args.frozen, args.output), indent=2))
