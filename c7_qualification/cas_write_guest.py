"""Synthetic native archive/CAS exercise with separate processes per phase."""
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from uuid import UUID, uuid4

PAYLOAD = Path(__file__).resolve().parents[1]
PARCEL = PAYLOAD.parent
if (os.name != "nt" or PARCEL.parent != Path(r"C:\Users\Public\Documents")
        or not re.fullmatch("AI1-C7-[a-f0-9]{32}", PARCEL.name)
        or os.environ.get("USERNAME", "").lower() != "wdagutilityaccount"):
    raise SystemExit(61)
sys.path.insert(0, str(PAYLOAD))

from app.memory_archive_v2 import build_archive
from app.memory_commands import MemoryAction, parse_memory_command
from app.memory_crypto import unprotect_for_current_user
from app.memory_head_v2 import Head, HeadUnavailable
from app.memory_keys_v2 import issue_receipt_key
from app.memory_ledger import MemoryLedger
from app.memory_reconciliation import OperationIdentity
from app.memory_write_v2 import ArchiveReducer, MemoryWriter, Mutation, WriteRefused
from c7_qualification.probe import namespace, private_directory


def require(condition):
    if not condition:
        raise AssertionError("Synthetic CAS guest invariant failed")


def main(phase):
    require(phase in ("write", "restart", "reconcile"))
    owner = os.environ["AI1_C7_OWNER"]
    scratch = PARCEL / "cas-fixture"
    directory = scratch / "archives"
    database = scratch / "authority.sqlite3"
    if phase == "write":
        private_directory(scratch, owner)
        private_directory(directory, owner)
        database.touch(exist_ok=False)
    archive = namespace(directory, owner)
    reducer = ArchiveReducer(archive, receipt_budget=8)

    def connect():
        return sqlite3.connect(database.as_uri() + "?mode=rw", uri=True)

    writer = MemoryWriter(connect, reducer=reducer, enabled=True)
    intent = parse_memory_command("Запомни, что мой тестовый код — 12345", enabled=True)
    require(intent.action is MemoryAction.SAVE and intent.requires_confirmation)
    mutation = Mutation("create", text=intent.text)

    def save_request(name, expected, identity):
        with (scratch / name).open("x", encoding="ascii") as stream:
            json.dump([str(expected.generation), expected.revision, expected.digest.hex(),
                       str(identity.operation_id), identity.binding.hex()], stream)

    def load_request(name):
        generation, rev, digest, operation, binding = json.loads((scratch / name).read_bytes())
        return (Head(UUID(generation), rev, bytes.fromhex(digest)),
                OperationIdentity(UUID(operation), UUID(generation), bytes.fromhex(binding)))

    if phase == "write":
        generation = uuid4()
        key = issue_receipt_key(generation)
        with closing(sqlite3.connect(":memory:")) as conn:
            MemoryLedger(conn, enabled=True, receipt_budget=8).initialize_empty(generation)
            artifact = build_archive(conn, capsule=key, approved_key_pin=key.fingerprint)
        archive.publish(artifact)
        initial = Head(generation, 0, artifact.fingerprint)
        writer.provision(initial)
        identity = reducer.identify(initial, uuid4(), mutation)
        save_request("initial.json", initial, identity)
        saved = writer.commit(initial, identity, mutation)
        require(saved.revision == 1 and writer.status(initial, identity) == saved)
        try:
            writer.commit(initial, identity, mutation)
        except WriteRefused as error:
            require(str(error) == "operation_already_recorded_use_status")
        else:
            raise AssertionError("Replay was admitted")
        require(writer.head() == saved and len(list(directory.glob("*.v2a"))) == 2)
        return 42

    initial, identity = load_request("initial.json")
    saved = writer.status(initial, identity)
    require(saved.revision == 1)
    if phase == "restart":
        require(writer.head() == saved)
        recall = parse_memory_command("Что ты помнишь?", enabled=True)
        require(recall.action is MemoryAction.LIST)
        note, = reducer.read(saved)
        require(unprotect_for_current_user(note.sealed).decode("utf8") == mutation.text)

        def reject_commit():
            conn = connect()
            conn.set_authorizer(lambda action, value, *_:
                                sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and value == "COMMIT"
                                else sqlite3.SQLITE_OK)
            return conn

        failed = Mutation("create", text="synthetic uncommitted archive")
        failed_id = reducer.identify(saved, uuid4(), failed)
        save_request("uncommitted.json", saved, failed_id)
        try:
            MemoryWriter(reject_commit, reducer=reducer, enabled=True).commit(saved, failed_id, failed)
        except HeadUnavailable:
            require(writer.head() == saved and writer.status(saved, failed_id) is None)
        else:
            raise AssertionError("COMMIT failure was hidden")
        delete = Mutation("delete", note_id=note.id, note_revision=note.revision)
        delete_id = reducer.identify(saved, uuid4(), delete)
        save_request("pending.json", saved, delete_id)
        writer.commit(saved, delete_id, delete)
        os._exit(43)  # No application acknowledgement. The next process only queries status.

    expected, operation = load_request("pending.json")
    confirmed = writer.status(expected, operation)
    require(confirmed == writer.head() and confirmed.revision == 2 and reducer.read(confirmed) == ())
    require(writer.status(*load_request("uncommitted.json")) is None)
    return 42


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
