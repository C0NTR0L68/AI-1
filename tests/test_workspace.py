"""NEW workspace/epoch checks using owned synthetic SQLite only."""
import hashlib
import os
from pathlib import Path
import sqlite3
import threading
import unittest
from uuid import uuid4
from dataclasses import dataclass

from app.db import ActiveRequestsError
from app.workspace import WorkspaceStore, WorkspaceConflict, fingerprint

ROOT = Path(os.environ["AI1_TEST_ROOT"])


@dataclass
class Answer:
    text: str = "answer"
    provider_id: str = "fake"
    requested_model: str = "asked"
    provider_model: str = "reported"


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / (uuid4().hex + ".sqlite3")
        self.store = WorkspaceStore(str(self.path), create=True)
        self.chat = self.store.create_chat(str(uuid4()), "Первый")

    def claim(self, chat=None, rid=None, text="question", sources=None):
        chat = chat or self.chat
        rid = rid or str(uuid4())
        fresh, state, context = self.store.claim(chat["id"], chat["epoch"], rid, text, fingerprint(text, "LOCAL", sources or []))
        return rid, fresh, state, context

    def complete(self, rid, chat=None):
        chat = chat or self.chat
        self.store.transition(chat["id"], chat["epoch"], rid, "dispatching")
        self.store.transition(chat["id"], chat["epoch"], rid, "completed", Answer())

    def test_create_duplicate_and_rename(self):
        self.assertEqual(self.store.create_chat(self.chat["id"], "Первый"), self.chat)
        self.store.change_chat(self.chat["id"], self.chat["epoch"], title="Второй")
        self.assertEqual(self.store.chats()[0]["title"], "Второй")
        with self.assertRaises(WorkspaceConflict):
            self.store.create_chat(self.chat["id"], "Первый")

    def test_context_and_history_do_not_cross_chats(self):
        rid, *_ = self.claim(text="private first")
        self.complete(rid)
        other = self.store.create_chat(str(uuid4()), "Other")
        rid2, _, _, context = self.claim(chat=other, text="second")
        self.assertNotIn("private first", str(context))
        self.assertEqual(len(self.store.history(self.chat["id"])["messages"]), 2)
        self.assertEqual(len(self.store.history(other["id"])["messages"]), 1)
        with self.assertRaises(KeyError):
            self.store.request(other["id"], other["epoch"], rid)

    def test_duplicate_and_document_payload_binding(self):
        source = [{"source": "a.md", "line": 1, "text": "synthetic"}]
        rid, fresh, state, _ = self.claim(sources=source)
        self.assertTrue(fresh)
        self.assertFalse(self.claim(rid=rid, sources=source)[1])
        with self.assertRaises(WorkspaceConflict):
            self.claim(rid=rid, sources=[{**source[0], "text": "changed"}])
        with self.assertRaises(WorkspaceConflict):
            self.claim(rid=rid, text="changed", sources=source)

    def test_lifecycle_and_external_complete(self):
        rid, _, state, _ = self.claim()
        self.assertEqual(state["status"], "pending")
        self.store.transition(self.chat["id"], self.chat["epoch"], rid, "dispatching")
        self.assertEqual(self.store.request(self.chat["id"], self.chat["epoch"], rid)["status"], "dispatching")
        self.store.transition(self.chat["id"], self.chat["epoch"], rid, "completed", Answer())
        state = self.store.request(self.chat["id"], self.chat["epoch"], rid)
        self.assertEqual((state["status"], state["provider_model"]), ("complete", "reported"))
        with self.store._connect() as conn:
            self.assertEqual(conn.execute("SELECT status FROM turns").fetchone()[0], "completed")

    def test_clear_changes_epoch_old_post_and_get_refused(self):
        rid, *_ = self.claim()
        self.complete(rid)
        newer = self.store.change_chat(self.chat["id"], self.chat["epoch"], clear=True)["chat"]
        self.assertNotEqual(newer["epoch"], self.chat["epoch"])
        self.assertEqual(self.store.history(self.chat["id"])["messages"], [])
        with self.assertRaises(WorkspaceConflict):
            self.claim(rid=rid)
        with self.assertRaises(WorkspaceConflict):
            self.store.request(self.chat["id"], self.chat["epoch"], rid)

    def test_clear_and_delete_refuse_pending_and_dispatching(self):
        rid, *_ = self.claim()
        for state in ("pending", "dispatching"):
            if state == "dispatching":
                self.store.transition(self.chat["id"], self.chat["epoch"], rid, state)
            for operation in ({"clear": True}, {"delete": True}):
                with self.assertRaises(ActiveRequestsError):
                    self.store.change_chat(self.chat["id"], self.chat["epoch"], **operation)
            self.assertEqual(self.store.history(self.chat["id"])["chat"]["epoch"], self.chat["epoch"])

    def test_unknown_is_not_completed_or_reclaimed(self):
        rid, *_ = self.claim()
        self.store.transition(self.chat["id"], self.chat["epoch"], rid, "dispatching")
        self.store.transition(self.chat["id"], self.chat["epoch"], rid, "unknown")
        _, fresh, state, context = self.claim(rid=rid)
        self.assertFalse(fresh)
        self.assertIsNone(context)
        self.assertEqual(state["status"], "unknown")

    def test_completion_rollback_is_atomic(self):
        rid, *_ = self.claim()
        self.store.transition(self.chat["id"], self.chat["epoch"], rid, "dispatching")
        with self.store._connect() as conn:
            conn.execute("CREATE TRIGGER synthetic_fail BEFORE UPDATE ON turns WHEN NEW.status='completed' BEGIN SELECT RAISE(ABORT,'synthetic'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.transition(self.chat["id"], self.chat["epoch"], rid, "completed", Answer())
        state = self.store.request(self.chat["id"], self.chat["epoch"], rid)
        self.assertEqual((state["status"], state["reply"]), ("dispatching", None))

    def test_clear_rollback_preserves_epoch_and_history(self):
        rid, *_ = self.claim()
        self.complete(rid)
        with self.store._connect() as conn:
            conn.execute("CREATE TRIGGER synthetic_fail BEFORE UPDATE ON chats BEGIN SELECT RAISE(ABORT,'synthetic'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.change_chat(self.chat["id"], self.chat["epoch"], clear=True)
        history = self.store.history(self.chat["id"])
        self.assertEqual(history["chat"]["epoch"], self.chat["epoch"])
        self.assertEqual(len(history["messages"]), 2)

    def test_restart_preserves_ids_status_and_epoch(self):
        rid, *_ = self.claim()
        self.complete(rid)
        before = self.store.history(self.chat["id"])
        reopened = WorkspaceStore(str(self.path))
        self.assertEqual(reopened.history(self.chat["id"]), before)
        self.assertFalse(reopened.claim(self.chat["id"], self.chat["epoch"], rid, "question", fingerprint("question", "LOCAL", []))[0])

    def test_autoincrement_not_reused_after_clear(self):
        rid, _, state, _ = self.claim()
        self.complete(rid)
        newchat = self.store.change_chat(self.chat["id"], self.chat["epoch"], clear=True)["chat"]
        _, _, newstate, _ = self.claim(chat=newchat)
        self.assertGreater(newstate["message_id"], state["message_id"])

    def test_unknown_schema_refused_without_changes(self):
        with self.store._connect() as conn:
            conn.execute("CREATE INDEX unreviewed ON turns(status)")
        before = hashlib.sha256(self.path.read_bytes()).digest()
        with self.assertRaises(ValueError):
            WorkspaceStore(str(self.path))
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)
        with self.assertRaises(FileExistsError):
            WorkspaceStore(str(self.path), create=True)

    def test_missing_epoch_no_legacy_method_bypass(self):
        for args in ((self.chat["id"], "bad", str(uuid4()), "q", "0"*64),):
            with self.assertRaises(ValueError): self.store.claim(*args)
        self.assertFalse(hasattr(self.store, "claim_pending_user"))
        with self.assertRaises(TypeError): self.store.history()

    def test_atomic_race_clear_vs_claim(self):
        barrier = threading.Barrier(2)
        outcomes = []
        def claim():
            barrier.wait(timeout=3)
            try: self.claim(); outcomes.append("claimed")
            except WorkspaceConflict: outcomes.append("stale")
        def clear():
            barrier.wait(timeout=3)
            try: self.store.change_chat(self.chat["id"], self.chat["epoch"], clear=True); outcomes.append("cleared")
            except ActiveRequestsError: outcomes.append("active")
        threads = [threading.Thread(target=claim), threading.Thread(target=clear)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(6); self.assertFalse(thread.is_alive())
        self.assertIn(set(outcomes), ({"claimed", "active"}, {"cleared", "stale"}))

    def test_atomic_race_completion_vs_clear(self):
        rid, *_ = self.claim()
        self.store.transition(self.chat["id"], self.chat["epoch"], rid, "dispatching")
        barrier = threading.Barrier(2); outcomes = []
        def complete():
            barrier.wait(timeout=3)
            self.store.transition(self.chat["id"], self.chat["epoch"], rid, "completed", Answer())
            outcomes.append("completed")
        def clear():
            barrier.wait(timeout=3)
            try: self.store.change_chat(self.chat["id"], self.chat["epoch"], clear=True); outcomes.append("cleared")
            except ActiveRequestsError: outcomes.append("active")
        threads = [threading.Thread(target=complete), threading.Thread(target=clear)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(6); self.assertFalse(thread.is_alive())
        self.assertIn(set(outcomes), ({"completed", "cleared"}, {"completed", "active"}))
        result = self.store.history(self.chat["id"])
        if "cleared" in outcomes:
            self.assertEqual(result["messages"], [])
            self.assertNotEqual(result["chat"]["epoch"], self.chat["epoch"])
        else:
            self.assertEqual(len(result["messages"]), 2)
            self.assertEqual(result["chat"]["epoch"], self.chat["epoch"])

    def test_legacy_database_not_adopted_or_modified(self):
        from app.db import ChatStore
        path = ROOT / (uuid4().hex + ".sqlite3")
        legacy = ChatStore(str(path))
        legacy.claim_pending_user("synthetic legacy", str(uuid4()))
        before = hashlib.sha256(path.read_bytes()).digest()
        with self.assertRaises(ValueError): WorkspaceStore(str(path))
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)
        self.assertEqual(legacy.history()[0]["content"], "synthetic legacy")

    def test_oversize_response_does_not_become_completed(self):
        rid, *_ = self.claim()
        self.store.transition(self.chat["id"], self.chat["epoch"], rid, "dispatching")
        with self.assertRaises(ValueError):
            self.store.transition(self.chat["id"], self.chat["epoch"], rid, "completed", Answer(text="x" * 64001))
        self.assertEqual(self.store.request(self.chat["id"], self.chat["epoch"], rid)["status"], "dispatching")

    def test_committed_snapshot_survives_racing_clear(self):
        rid, *_ = self.claim()
        self.store.transition(self.chat["id"], self.chat["epoch"], rid, "dispatching")
        completed = self.store.transition(self.chat["id"], self.chat["epoch"], rid, "completed", Answer())
        self.store.change_chat(self.chat["id"], self.chat["epoch"], clear=True)
        self.assertEqual((completed["status"], completed["reply"]), ("complete", "answer"))
        with self.assertRaises(WorkspaceConflict):
            self.store.request(self.chat["id"], self.chat["epoch"], rid)

    def test_keyset_pages_are_complete_ordered_and_epoch_bound(self):
        for index in range(5):
            rid, *_ = self.claim(text=f"q{index}")
            self.complete(rid)
        first = self.store.history(self.chat["id"], limit=2)
        second = self.store.history(self.chat["id"], before=first["next_before"], limit=2, epoch=self.chat["epoch"])
        third = self.store.history(self.chat["id"], before=second["next_before"], limit=2, epoch=self.chat["epoch"])
        combined = third["messages"] + second["messages"] + first["messages"]
        self.assertEqual([row["content"] for row in combined if row["role"] == "user"], [f"q{i}" for i in range(5)])
        self.assertEqual(len({row["id"] for row in combined}), 10)
        self.assertIsNone(third["next_before"])
        with self.assertRaises(ValueError): self.store.history(self.chat["id"], before=first["next_before"])
        self.store.change_chat(self.chat["id"], self.chat["epoch"], clear=True)
        with self.assertRaises(WorkspaceConflict): self.store.history(self.chat["id"], before=first["next_before"], epoch=self.chat["epoch"])

    def test_page_bounds_do_not_accept_boolean_or_unbounded_reads(self):
        for limit in (0, 101, True, "50"):
            with self.assertRaises(ValueError): self.store.history(self.chat["id"], limit=limit)
        for before in (0, True, "1", 2**63):
            with self.assertRaises(ValueError): self.store.history(self.chat["id"], before=before, epoch=self.chat["epoch"])
