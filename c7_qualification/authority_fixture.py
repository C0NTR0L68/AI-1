"""Native ACL and rollback probe for a separate disposable guest principal."""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from uuid import UUID


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(condition):
    if not condition:
        raise AssertionError("Authority fixture invariant failed")


def run():
    phase, parcel = sys.argv[1:]
    parcel = Path(parcel)
    verify(parcel.parent == Path(r"C:\Users\Public\Documents"))
    verify(re.fullmatch("AI1-C7-[0-9a-f]{32}", parcel.name))
    system_root = Path(os.environ["SystemRoot"]) / "System32/config/systemprofile" / parcel.name
    # The privileged actor is staged independently in its protected directory.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app.memory_head_v2 import DurableHeadRegistry, Head

    generation = UUID("afe2e32e-b202-4d63-b2ed-f5b88ebb4a21")
    before = Head(generation, 0, b"0" * 32)
    after = Head(generation, 1, b"1" * 32)
    db = system_root / "head.sqlite3"
    journal = system_root / "head.sqlite3-journal"
    proof = system_root / "proof.json"
    registry = DurableHeadRegistry(lambda: sqlite3.connect(db.as_uri() + "?mode=rw", uri=True))

    if phase == "provision":
        verify(system_root.is_dir() and not db.exists())
        with db.open("xb"):
            pass
        registry.provision(before)
        with (parcel / "old-head.synthetic").open("xb") as output:
            output.write(db.read_bytes())
        verify(registry.advance(before, after))
        connection = sqlite3.connect(db.as_uri() + "?mode=rw", uri=True)
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("UPDATE main.head_journal SET digest=? WHERE revision=1", (b"2" * 32,))
        verify(journal.is_file() and journal.stat().st_size > 0)
        proof.write_text(json.dumps({"database": sha(db), "journal": sha(journal)}), encoding="ascii")
        # Deliberate fixture-owned process exit leaves SQLite's real journal in place.
        os._exit(42)
    if phase == "ordinary":
        old = parcel / "old-head.synthetic"
        verify(old.is_file() and old.stat().st_size > 0)
        for target in (db, journal):
            for action in (lambda: target.open("r+b").close(), target.unlink,
                           lambda: target.rename(target.with_name("moved")),
                           lambda: os.replace(old, target), lambda: target.open("rb").close()):
                try:
                    action()
                except PermissionError:
                    continue
                raise AssertionError("Untrusted file operation was allowed")
        try:
            system_root.rename(system_root.with_name(system_root.name + "-substitute"))
        except PermissionError:
            pass
        else:
            raise AssertionError("Untrusted directory substitution was allowed")
        try:
            sqlite3.connect(db.as_uri() + "?mode=rw", uri=True).close()
        except sqlite3.OperationalError:
            return 42
        raise AssertionError("Untrusted SQLite open was allowed")
    if phase == "verify":
        expected = json.loads(proof.read_text(encoding="ascii"))
        verify(expected == {"database": sha(db), "journal": sha(journal)})
        verify(registry.read() == after and not registry.advance(before, after))
        return 42
    raise ValueError("Unknown fixture phase")


if __name__ == "__main__":
    raise SystemExit(run())
