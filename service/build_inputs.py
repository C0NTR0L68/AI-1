"""Generate pinned production inputs from an exact Git revision and offline runtime."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import zipfile


RUNTIME_SHA = "9D56A383933EA9D5469A3CE8588262376CDCDFC59438AF6779B3CE2FA85D7500"
MODULES = (
    "__init__", "memory", "memory_archive_publish_v2", "memory_archive_v2",
    "memory_authority_identity", "memory_authority_pipe", "memory_authority_service",
    "memory_crypto", "memory_head_v2", "memory_keys_v2", "memory_ledger", "memory_reconciliation",
    "memory_security", "memory_service_pipe", "memory_snapshot_v2", "memory_storage_policy",
    "memory_windows_archive", "memory_write_v2", "windows_storage_inspector",
)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if sha(args.archive.read_bytes()) != RUNTIME_SHA:
        raise ValueError("Only the qualified frozen runtime is accepted")
    with zipfile.ZipFile(args.archive) as bundle:
        entries = {name: sha(bundle.read(name)) for name in bundle.namelist()
                   if name.startswith("runtime/python/") and not name.endswith("/")}
    if "runtime/python/python.exe" not in entries:
        raise ValueError("Windows Python executable missing")
    for module in MODULES:
        name = "app/" + module + ".py"
        entries[name] = sha(subprocess.check_output(["git", "show", args.revision + ":" + name]))
    manifest = "".join(f"{entries[name]} payload/{name}\n" for name in sorted(entries))
    with args.output.open("xb") as output:
        output.write(manifest.encode("ascii"))
    print(sha(manifest.encode("ascii")), len(entries))


if __name__ == "__main__":
    main()
