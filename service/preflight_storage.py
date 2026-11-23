"""Read Windows metadata for the approved Memory V2 path without reading file contents."""
import argparse
from contextlib import ExitStack
import ctypes
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.memory_windows_archive import _require_fixed_ntfs
from app.windows_storage_inspector import _component, _release_after, _free_local, _windows_apis


DIRECTORIES = (
    "D:\\", r"D:\AI-1", r"D:\AI-1\data", r"D:\AI-1\data\memory",
    r"D:\AI-1\data\memory\authority", r"D:\AI-1\data\memory\authority\archives",
)
FILES = tuple(DIRECTORIES[-2] + "\\" + leaf for leaf in (
    "archive-pin.json", "head.sqlite3", "head.sqlite3-journal", "head.sqlite3-wal", "head.sqlite3-shm",
))


def _descriptor(handle):
    kernel, adv = _windows_apis()
    descriptor = ctypes.c_void_p()
    error = adv.GetSecurityInfo(handle, 1, 7, None, None, None, None, ctypes.byref(descriptor))
    with _release_after(lambda: _free_local(kernel.LocalFree, descriptor.value)):
        if error:
            raise ctypes.WinError(error)
        convert = adv.ConvertSecurityDescriptorToStringSecurityDescriptorW
        convert.argtypes = [ctypes.c_void_p, W.DWORD, W.DWORD, ctypes.POINTER(W.LPWSTR),
                            ctypes.POINTER(W.DWORD)]
        convert.restype = W.BOOL
        sddl = W.LPWSTR()
        if not convert(descriptor, 1, 7, ctypes.byref(sddl), None):
            raise ctypes.WinError(ctypes.get_last_error())
        with _release_after(lambda: _free_local(kernel.LocalFree, ctypes.cast(sddl, ctypes.c_void_p).value)):
            return sddl.value


def _collect(stack, name, kind):
    try:
        Path(name).lstat()
    except FileNotFoundError:
        return {"path": name, "status": "ABSENT"}
    evidence, _, handle, _ = stack.enter_context(_component(
        name, expected_kind=kind, owner_sid=None, require_private_acl=False, pinned=True, include_handle=True))
    if kind == "file" and evidence.links != 1:
        return {"path": name, "status": "BLOCKED", "reason": "file_hardlink"}
    return {"path": name, "status": "OWNER_REVIEW_REQUIRED", "kind": kind,
            "volume": evidence.identity.volume, "file_id": evidence.identity.native_id.hex(),
            "links": evidence.links, "owner": evidence.owner, "dacl_sddl": _descriptor(handle)}


def inventory():
    _require_fixed_ntfs(DIRECTORIES[0])
    results = []
    with ExitStack() as stack:
        for pos, directory in enumerate(DIRECTORIES):
            item = _collect(stack, directory, "directory")
            results.append(item)
            if item["status"] == "ABSENT":
                if pos == len(DIRECTORIES) - 1:
                    break  # Examine exact database filenames if the authority root exists.
                return results
            if item["volume"] != results[0]["volume"]:
                raise ValueError("Volume identity mismatch")
        for name in FILES:
            item = _collect(stack, name, "file")
            if item.get("volume", results[0]["volume"]) != results[0]["volume"]:
                raise ValueError("Volume identity mismatch")
            if name.endswith(("-journal", "-wal", "-shm")) and item["status"] != "ABSENT":
                item["status"] = "BLOCKED"
                item["reason"] = "sqlite_sidecar_present"
            results.append(item)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect-approved-path", action="store_true")
    args = parser.parse_args()
    if not args.inspect_approved_path:
        print(json.dumps({"status": "NOT_RUN", "metadata_only": [*DIRECTORIES, *FILES]}))
        return 0
    if os.name != "nt":
        parser.error("A Windows metadata inspection is required")
    try:
        results = inventory()
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": getattr(error, "reason", type(error).__name__),
                          "winerror": getattr(error, "winerror", None)}))
        return 1
    status = "BLOCKED" if any(item["status"] == "BLOCKED" for item in results) else "OWNER_REVIEW_REQUIRED"
    print(json.dumps({"status": status, "paths": results}, indent=2))
    return int(status == "BLOCKED")


if __name__ == "__main__":
    raise SystemExit(main())
