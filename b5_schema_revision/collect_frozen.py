"""Collect a hash-pinned frozen B5 candidate. Executes no test cases."""
from argparse import ArgumentParser
import json
import os
from pathlib import Path
import shutil
import sys
from uuid import uuid4
from zipfile import ZipFile


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--scratch-parent", type=Path, required=True)
    parser.add_argument("--frozen-harness", type=Path, required=True)
    args = parser.parse_args()
    review = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(review))
    from b5_guest import (
        ARCHIVE_SHA, SCHEMA_FROZEN_MANIFEST_SHA, SCHEMA_REVISION_SHA, _inventory, _prepare,
        _schema_revision, _sha, _verify_packages, verify_collection,
    )

    archive_sha = _sha(args.archive).upper()
    if archive_sha not in (ARCHIVE_SHA, SCHEMA_REVISION_SHA):
        raise RuntimeError("Collection archive hash mismatch")
    for name, pin in {
        "guard.py": "D643E34C31CAC0CA1446669C873681E4783F771F872385803C82B9DBC1F6D044",
        "adapters.py": "9FE23C1DBBDCC2F420B45EA5FEF6ADB6BC235DF647618A16507D7115D5EF9EC4",
        "harness.py": "25C7279F1EE4180649D4CB855CB51177298B35DA23713C9BE42E2BC477C5F9C3",
    }.items():
        if _sha(args.frozen_harness / name).upper() != pin:
            raise RuntimeError("Adapter pin mismatch")

    stage = args.scratch_parent / ("candidate-collection-" + uuid4().hex)
    stage.mkdir()
    copy, root = stage / "AI-1-B5-Offline.zip", stage / "payload"
    shutil.copyfile(args.archive, copy)
    with ZipFile(copy) as source:
        source.extractall(root)
    _verify_packages(root)
    _prepare(root)
    suite, temp = root / "suite", root / "temp"
    os.chdir(root)
    os.environ.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHON_DOTENV_DISABLED="1", TMP=str(temp), TEMP=str(temp))
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH"):
        os.environ.pop(name, None)
    sys.path[:0] = [str(args.frozen_harness), str(root / "deps")]
    sys.dont_write_bytecode = True
    import adapters
    from guard import Policy
    from harness import pytest_plan
    import pytest

    policy = Policy(root, root / "unavailable-live-project")
    expected, revision = _inventory(suite), _schema_revision(root)
    if revision:
        adapters.MANIFEST_SHA = SCHEMA_FROZEN_MANIFEST_SHA
    evidence = {}

    class CollectionOnly:
        def pytest_collection_finish(self, session):
            evidence.update(verify_collection(session.items, expected, revision))
            ids = sorted(item.nodeid.replace("\\", "/") for item in session.items)
            if len(ids) != (609 if revision else 603) or len(ids) != len(set(ids)):
                raise RuntimeError("Unexpected expanded collection")
            inventory = root / "collected-nodeids.txt"
            inventory.write_bytes(("\n".join(ids) + "\n").encode("utf8"))
            evidence["collection_sha256"] = _sha(inventory)

        def pytest_runtest_call(self, item):
            pytest.exit("Collection-only guard refused test execution", returncode=75)

    sys.addaudithook(policy.audit)
    _, restore = adapters.prepare_candidate(root / "frozen", policy)
    try:
        run_args = pytest_plan(root, suite)
        code = pytest.main([
            *run_args, "--collect-only", "--noconftest", "-p", "no:faulthandler",
        ], plugins=[CollectionOnly()])
    finally:
        restore()
    print("COLLECTION_RESULT=" + json.dumps(evidence, sort_keys=True))
    print("COLLECTION_FILE=" + str(root / "collected-nodeids.txt"))
    return int(code)


if __name__ == "__main__":
    raise SystemExit(main())
