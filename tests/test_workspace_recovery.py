"""NEW recovery semantics with a refusing/model lock; not Windows OS proof."""
import os
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from app.workspace import WorkspaceStore, fingerprint, recover_workspace_dispatching


class ModelLock:
    held = False
    def __init__(self, path): self.path = path
    def __enter__(self):
        if type(self).held: raise BlockingIOError("synthetic lock busy")
        type(self).held = True
        return self
    def __exit__(self, *args): type(self).held = False


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(os.environ["AI1_TEST_ROOT"]) / (uuid4().hex + ".sqlite3")
        self.store = WorkspaceStore(str(self.path), create=True)
        self.chat = self.store.create_chat(str(uuid4()), "Synthetic")
        ModelLock.held = False

    def row(self, state):
        rid = str(uuid4())
        self.store.claim(self.chat["id"], self.chat["epoch"], rid, "synthetic", fingerprint("synthetic", "LOCAL", []))
        if state != "pending": self.store.transition(self.chat["id"], self.chat["epoch"], rid, "dispatching")
        if state in ("unknown", "failed"): self.store.transition(self.chat["id"], self.chat["epoch"], rid, state)
        return rid

    def recover(self):
        with patch("app.runtime_lock.DatabaseProcessLock", ModelLock):
            return recover_workspace_dispatching(str(self.path))

    def test_only_dispatching_changes_and_duplicate_remains_nonexecuting(self):
        ids = {status: self.row(status) for status in ("pending", "dispatching", "unknown", "failed")}
        self.assertEqual(self.recover(), 1)
        for before, rid in ids.items():
            state = self.store.request(self.chat["id"], self.chat["epoch"], rid)
            self.assertEqual(state["status"], "unknown" if before == "dispatching" else before)
        fresh, state, context = self.store.claim(self.chat["id"], self.chat["epoch"], ids["dispatching"], "synthetic", fingerprint("synthetic", "LOCAL", []))
        self.assertFalse(fresh); self.assertIsNone(context); self.assertEqual(state["status"], "unknown")
        self.assertEqual(self.recover(), 0)

    def test_busy_lock_refuses_before_sqlite(self):
        self.row("dispatching")
        ModelLock.held = True
        with patch("app.runtime_lock.DatabaseProcessLock", ModelLock), patch("app.workspace.sqlite3.connect") as connect:
            with self.assertRaises(BlockingIOError): recover_workspace_dispatching(str(self.path))
            connect.assert_not_called()
        ModelLock.held = False
        self.assertEqual(len(self.store.history(self.chat["id"])["messages"]), 1)

    def test_preflight_reads_only_while_lock_owned(self):
        self.row("dispatching")
        original = self.store.preflight
        def preflight(path):
            self.assertTrue(ModelLock.held)
            return original(path)
        with patch.object(WorkspaceStore, "preflight", side_effect=preflight):
            self.assertEqual(self.recover(), 1)
        self.assertFalse(ModelLock.held)

    def test_transaction_error_rolls_back_all_rows_and_releases_lock(self):
        self.row("dispatching"); self.row("dispatching")
        # Keep schema accepted by injecting the fault only after preflight.
        original = WorkspaceStore.preflight
        def preflight(path):
            original(path)
            with self.store._connect() as connection:
                connection.execute("CREATE TRIGGER synthetic_fail BEFORE UPDATE ON turns WHEN OLD.id=2 BEGIN SELECT RAISE(ABORT,'synthetic'); END")
        with patch.object(WorkspaceStore, "preflight", side_effect=preflight):
            with self.assertRaises(sqlite3.IntegrityError): self.recover()
        self.assertFalse(ModelLock.held)
        self.assertEqual([row["status"] for row in self.store.history(self.chat["id"])["messages"]], ["dispatching", "dispatching"])

    def test_construction_never_recovers_automatically(self):
        rid = self.row("dispatching")
        reopened = WorkspaceStore(str(self.path))
        self.assertEqual(reopened.request(self.chat["id"], self.chat["epoch"], rid)["status"], "dispatching")
