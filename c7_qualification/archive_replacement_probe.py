"""Prove that the enrolled archive path cannot switch to a new directory."""
from pathlib import Path
import re
import sys


def main():
    payload = Path(__file__).resolve().parents[1]
    parcel = payload.parent
    if (parcel.parent != Path(r"C:\Users\Public\Documents")
            or not re.fullmatch("AI1-C7-[0-9a-f]{32}", parcel.name)):
        raise RuntimeError("Disposable guest parcel required")
    sys.path.insert(0, str(payload))
    from probe import namespace, private_directory
    from app.windows_storage_inspector import WindowsStorageInspectionError, inspect_component

    original = parcel / "scratch" / "archives"
    owner = inspect_component(str(original), expected_kind="directory").owner
    enrolled = namespace(original, owner)
    retired = original.with_name("enrolled-archive-directory")
    original.rename(retired)
    private_directory(original, owner)
    inspect_component(str(original), expected_kind="directory", owner_sid=owner, require_private_acl=True)
    try:
        with enrolled.hold(original):
            raise AssertionError("An unenrolled archive directory was admitted")
    except WindowsStorageInspectionError as error:
        if error.reason != "archive_directory_identity":
            raise
    return 42


if __name__ == "__main__":
    raise SystemExit(main())
