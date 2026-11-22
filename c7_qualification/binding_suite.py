"""Run the focused lifecycle tests with package-local dependencies and data."""
import json
import os
from pathlib import Path
import re
import sys


def main():
    payload = Path(__file__).resolve().parents[1]
    parcel = payload.parent
    if (os.name != "nt" or parcel.parent != Path(r"C:\Users\Public\Documents")
            or not re.fullmatch("AI1-C7-[0-9a-f]{32}", parcel.name)
            or os.getlogin().casefold() != "wdagutilityaccount"):
        raise RuntimeError("Dedicated isolated guest required")
    scratch = parcel / "binding-suite"
    scratch.mkdir()
    os.environ.update(PYTHON_DOTENV_DISABLED="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
                      AI1_PROVIDER="ollama", AI1_MODE="LOCAL_ONLY", AI1_API_KEY="",
                      AI1_DATABASE_PATH=str(scratch / "unopened.sqlite3"),
                      TMP=str(scratch), TEMP=str(scratch))
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
        os.environ.pop(name, None)
    sys.path[:0] = [str(payload), str(payload / "deps")]
    import pytest

    phases = {}

    class Results:
        def pytest_runtest_logreport(self, report):
            phases.setdefault(report.nodeid, {})[report.when] = report.outcome

    configuration = scratch / "pytest.ini"
    configuration.write_text("[pytest]\n", encoding="ascii")
    status = pytest.main(["-q", "--noconftest", "-c", str(configuration),
                          "--basetemp", str(scratch / "tmp"), "--log-file", str(scratch / "pytest.log"),
                          "-p", "no:cacheprovider", "-p", "no:faulthandler",
                          str(payload / "tests/test_memory_storage_binding.py")], plugins=[Results()])
    (scratch / "result.json").write_text(json.dumps(phases, indent=2), encoding="ascii")
    if status != 0 or len(phases) != 3 or any(
        value != {"setup": "passed", "call": "passed", "teardown": "passed"} for value in phases.values()
    ):
        return 1
    return 42


if __name__ == "__main__":
    raise SystemExit(main())
