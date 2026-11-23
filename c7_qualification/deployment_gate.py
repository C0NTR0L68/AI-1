"""Offline comparison of an approved deployment plan and observed evidence."""

from pathlib import PureWindowsPath
import re


_SID = re.compile(r"S-1-5-(?:21(?:-[0-9]{1,10}){4}|80(?:-[0-9]{1,10}){5})\Z")
_SHA = re.compile(r"[0-9A-Fa-f]{64}\Z")
_IDENTITY = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}:[0-9a-f]{32}\Z")
_PATHS = ("runtime_root", "head_root", "archive_root")
_PINS = ("authority_sid", "client_sid", "client_integrity", "runtime_sha256",
         "enrollment_sha256", *_PATHS, "runtime_chain", "head_chain", "archive_chain")
_CHECKS = (
    "service_token_and_scm_acl", "runtime_and_enrollment_acl", "head_journal_and_parent_acl",
    "archive_acl_and_identity", "verified_fixed_ntfs", "native_pipe_peers",
    "restart_and_recovery", "bounded_shutdown", "memory_disabled",
)


def _digest(value):
    return isinstance(value, str) and bool(_SHA.fullmatch(value))


def _path(value):
    if not isinstance(value, str):
        raise ValueError("Canonical Windows directory required")
    path = PureWindowsPath(value)
    if (path.drive.upper() not in ("C:", "D:") or not path.is_absolute()
            or str(path) != value or len(path.parts) < 2
            or any(part in (".", "..") or part.rstrip(" .") != part or PureWindowsPath(part).is_reserved()
                   or any(ord(char) < 32 or char in ':*?<>|"'
                          for char in part) for part in path.parts[1:])):
        raise ValueError("Canonical Windows directory required")
    return path


def _reviewed_plan(plan):
    if not isinstance(plan, dict) or set(plan) != set(_PINS):
        raise ValueError("All reviewed pins are required")
    authority, client = plan["authority_sid"], plan["client_sid"]
    if (authority == client or not all(isinstance(sid, str) and _SID.fullmatch(sid)
                                      for sid in (authority, client))):
        raise ValueError("Distinct dedicated authority and client SIDs required")
    if type(plan["client_integrity"]) is not int or plan["client_integrity"] != 12288:
        raise ValueError("Reviewed read-only IPC profile requires a high-integrity client")
    if not all(_digest(plan[name]) for name in ("runtime_sha256", "enrollment_sha256")):
        raise ValueError("Complete SHA-256 pins required")
    paths = tuple(_path(plan[name]) for name in _PATHS)
    if paths[2].drive.upper() != "D:":
        raise ValueError("Archive root must use the reviewed D: volume")
    for index, path in enumerate(paths):
        if any(path.is_relative_to(other) or other.is_relative_to(path) for other in paths[:index]):
            raise ValueError("Runtime, head and archive roots must be separate")
    enrolled = {}
    locations = {}
    for name, path in zip(("runtime_chain", "head_chain", "archive_chain"), paths):
        values = plan[name]
        if (not isinstance(values, list) or len(values) != len(path.parts)
                or any(not isinstance(value, str) or not _IDENTITY.fullmatch(value)
                       or not int(value.split(":")[1], 16) for value in values)):
            raise ValueError("Pin every directory including the volume root")
        if len({value.split(":")[0] for value in values}) != 1:
            raise ValueError("Directory identities must be unique within one volume")
        for location, identity in zip((*reversed(path.parents), path), values):
            if enrolled.setdefault(location, identity) != identity or locations.setdefault(identity, location) != location:
                raise ValueError("Inconsistent or aliased directory enrollment")


def evaluate(plan, observed):
    """No I/O or trust elevation. Positive comparison permits independent review."""
    _reviewed_plan(plan)
    if not isinstance(observed, dict) or set(observed) - set((*_PINS, *_CHECKS)):
        raise ValueError("Unrecognized observations")
    results = {}
    for name in _PINS:
        actual = observed.get(name)
        results[name] = ("UNKNOWN" if actual is None else "PASS" if type(actual) is type(plan[name])
                         and actual == plan[name] else "FAIL")
    for name in _CHECKS:
        row = observed.get(name)
        if row is None:
            results[name] = "UNKNOWN"
            continue
        if (not isinstance(row, dict) or set(row) != {"result", "sha256"}
                or row["result"] not in ("PASS", "FAIL") or not _digest(row["sha256"])):
            raise ValueError("A concrete observation needs its evidence digest")
        results[name] = row["result"]
    return {"release": "NO-GO", "review_ready": all(value == "PASS" for value in results.values()),
            "checks": results}
