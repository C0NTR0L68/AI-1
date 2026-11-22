"""Run candidate-only tests from the immutable bundle, with sockets denied."""
from argparse import ArgumentParser
from hashlib import file_digest
import json
import os
from pathlib import Path
import shutil
import sys
from uuid import uuid4
from zipfile import ZipFile

PROPOSAL = Path(__file__).resolve().parent
parser = ArgumentParser(description=__doc__)
parser.add_argument("--archive", type=Path, required=True)
parser.add_argument("--scratch-parent", type=Path, required=True)
args = parser.parse_args()
if not args.archive.is_absolute() or not args.scratch_parent.is_absolute():
    parser.error("Absolute archive and scratch paths required")
sys.dont_write_bytecode = True
RUN = args.scratch_parent / ("schema-proposal-" + uuid4().hex[:10])
BASE_PYTHON = Path(sys.base_prefix).resolve()
INPUT_SHA = "569fd484c31746a0a3a2da0d133c2eeb8d426c607e71888f2ce113a43f69d8e7"
archive = args.archive
with archive.open("rb") as stream:
    if file_digest(stream, "sha256").hexdigest() != INPUT_SHA:
        raise SystemExit("Frozen archive hash mismatch")
RUN.mkdir()
with ZipFile(archive) as bundle:
    pins = json.loads(bundle.read("MANIFEST.json"))
    for name in bundle.namelist():
        if name.startswith(("frozen/release/", "wheels/", "suite/tests/")):
            target = RUN / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(name))
            with target.open("rb") as stream:
                if file_digest(stream, "sha256").hexdigest() != pins[name].lower():
                    raise SystemExit("Frozen member hash mismatch")
for wheel in (RUN / "wheels").glob("*.whl"):
    with ZipFile(wheel) as content:
        content.extractall(RUN / "deps")
release = RUN / "frozen/release"
shutil.copyfile(PROPOSAL / "history_migration.py", release / "app/history_migration.py")
shutil.copyfile(PROPOSAL / "test_schema_contract.py", RUN / "test_schema_contract.py")
(RUN / "pytest.ini").write_text("[pytest]\n", encoding="ascii")
os.environ.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHON_DOTENV_DISABLED="1")
os.environ.update(TMP=str(RUN), TEMP=str(RUN), TMPDIR=str(RUN))
for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH"):
    os.environ.pop(key, None)
sys.path[:0] = [str(release), str(RUN / "deps")]


def guard(event, args):
    if event.startswith(("socket.", "subprocess.")) or event in {"os.system", "os.startfile"}:
        raise PermissionError(event)
    if event == "open" and not isinstance(args[0], int):
        path = Path(os.fsdecode(args[0])).absolute()
        flags = args[2]
        write = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        permitted = path.is_relative_to(RUN) or (not write and path.is_relative_to(BASE_PYTHON))
        if path.name.lower().startswith(".env") or ".git" in path.parts or not permitted:
            raise PermissionError(event)
    if event == "sqlite3.connect":
        from urllib.parse import unquote, urlsplit

        value = os.fspath(args[0])
        if value.startswith("file:"):
            uri = urlsplit(value)
            if uri.netloc or uri.query != "mode=ro" or uri.fragment:
                raise PermissionError(event)
            value = unquote(uri.path).removeprefix("/")
        db = Path(value).absolute()
        if not db.is_relative_to(RUN / "tmp"):
            raise PermissionError(event)
    if event in {"os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.chmod"}:
        values = args[:2] if event == "os.rename" else args[:1]
        if not all(Path(os.fsdecode(value)).absolute().is_relative_to(RUN) for value in values):
            raise PermissionError(event)


sys.addaudithook(guard)
from app import config

config.settings = config.Settings(database_path=str(RUN / "tmp/unopened.sqlite3"), provider="ollama")
import pytest

raise SystemExit(pytest.main([
    "-q", "--noconftest", "-c", str(RUN / "pytest.ini"), "--basetemp", str(RUN / "tmp"),
    "--log-file", str(RUN / "pytest.log"), "--capture=sys", "-p", "no:cacheprovider", "-p", "no:faulthandler",
    str(RUN / "test_schema_contract.py"),
]))
