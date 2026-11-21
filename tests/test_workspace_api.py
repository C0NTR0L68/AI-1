"""NEW immediate-coroutine route checks, not HTTP/event-loop qualification."""
from asyncio import CancelledError
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import patch
import unittest

from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
from app.context import HISTORY_RECALL_PROVIDER, UNCONFIRMED_RECALL
from app.ollama_provider import OllamaProvider
from app.provider import GenerationResult, ProviderError, ProviderErrorCategory, ProviderAttemptOutcome
from app.workspace import WorkspaceStore, WorkspaceConflict
from app.workspace_api import install_workspace_routes, WorkspaceMessage


def immediate(coroutine):
    try:
        value = coroutine.send(None)
    except StopIteration as done:
        return done.value
    finally:
        coroutine.close()
    raise AssertionError("Unexpected non-immediate await: " + repr(value))


class Fake:
    def __init__(self): self.calls = []; self.error = None; self.text = "answer [D1]"
    async def generate(self, messages):
        self.calls.append(messages)
        if self.error is not None: raise self.error
        return GenerationResult(self.text, "fake", "asked", "reported")


class WorkspaceApiTests(unittest.TestCase):
    def setUp(self):
        self.store = WorkspaceStore(str(Path(os.environ["AI1_TEST_ROOT"]) / (uuid4().hex + ".sqlite3")), create=True)
        self.chat = self.store.create_chat(str(uuid4()), "Synthetic")
        self.fake = Fake()
        self.app = FastAPI()
        self.app.state.store = self.store; self.app.state.provider = self.fake
        self.app.state.effective_mode = "LOCAL_ONLY"
        install_workspace_routes(self.app, lambda error, mode: HTTPException(status_code=502, detail="synthetic"))
        self.endpoint = next(route.endpoint for route in self.app.routes if getattr(route, "path", "").endswith('/messages'))
        self.request = SimpleNamespace(app=self.app)

    def body(self, **kwargs):
        return WorkspaceMessage(epoch=self.chat["epoch"], request_id=str(uuid4()), message="question", **kwargs)

    def send(self, body):
        return immediate(self.endpoint(self.chat["id"], body, self.request))

    def state(self, body):
        return self.store.request(self.chat["id"], self.chat["epoch"], str(body.request_id))

    def question(self, text, **kwargs):
        return self.body(**kwargs).model_copy(update={"message": text})

    def recall(self):
        return self.question("Какой проверочный код был в предыдущем сообщении? Напиши только этот код.")

    def test_exact_recall_persists_across_reopen_and_replays_without_generation(self):
        value = "Ёж+аA_X/47#"
        self.fake.text = value
        self.send(self.question("Ответь только этим кодом, с теми же буквами и регистром: " + value))
        body = self.recall()
        result = self.send(body)
        self.assertEqual((result["reply"], result["status"], result["provider_id"], result["provider_model"]),
                         (value, "complete", HISTORY_RECALL_PROVIDER, None))
        self.store = self.app.state.store = WorkspaceStore(str(self.store.path))
        self.assertEqual(self.state(body), result)
        self.assertEqual(self.send(body).status_code, 200)
        self.assertEqual(len(self.fake.calls), 1)
        self.send(self.question("Объясни обычную тему."))
        self.assertFalse(any(msg["content"] == body.message for msg in self.fake.calls[-1]))

    def test_empty_other_chat_cleared_and_stale_epoch(self):
        self.fake.text = "Лист-135"
        self.send(self.question("Код: Лист-135"))
        original = self.chat
        self.chat = self.store.create_chat(str(uuid4()), "Other chat")
        self.assertEqual(self.send(self.recall())["reply"], UNCONFIRMED_RECALL)
        self.chat = original
        stale = self.recall()
        self.chat = self.store.change_chat(original["id"], original["epoch"], clear=True)["chat"]
        with self.assertRaises(WorkspaceConflict):
            self.send(stale)
        self.assertEqual(self.send(self.recall())["reply"], UNCONFIRMED_RECALL)
        deleted = self.recall()
        self.store.change_chat(self.chat["id"], self.chat["epoch"], delete=True)
        with self.assertRaises(KeyError):
            self.send(deleted)
        self.assertEqual(len(self.fake.calls), 1)

    def test_previous_turn_ambiguity_mismatch_and_correction(self):
        for question, answer in (("Код: A-1 B-2", "A-1 B-2"), ("Код: A-1,B-2", "A-1,B-2"),
                                 ("Код: А-14", "A-14"), ("Код: Токен-7", "7"),
                                 ("Код: A\u202e-3", "A\u202e-3"), ("Код: A-1\nКод: A-2", "A-2"),
                                 ("Исправление: К-22, вместо Р-10", "К-22")):
            with self.subTest(question=question):
                self.fake.text = answer
                self.send(self.question(question))
                self.assertEqual(self.send(self.recall())["reply"], UNCONFIRMED_RECALL)
        self.fake.text = "К-22"
        self.send(self.question("Код: К-22"))
        self.assertEqual(self.send(self.recall())["reply"], "К-22")

    def test_incomplete_latest_turn_is_never_used_or_skipped(self):
        from app.workspace import fingerprint

        for lifecycle in ("pending", "dispatching", "failed", "unknown"):
            with self.subTest(lifecycle=lifecycle):
                self.fake.text = "Снег-204"
                self.send(self.question("Код: Снег-204"))
                chat, epoch, rid = self.chat["id"], self.chat["epoch"], str(uuid4())
                self.store.claim(chat, epoch, rid, "Код: A-3", fingerprint("Код: A-3", "LOCAL", []))
                if lifecycle != "pending":
                    self.store.transition(chat, epoch, rid, "dispatching")
                if lifecycle in ("failed", "unknown"):
                    self.store.transition(chat, epoch, rid, lifecycle)
                before = len(self.fake.calls)
                self.assertEqual(self.send(self.recall())["reply"], UNCONFIRMED_RECALL)
                self.assertEqual(len(self.fake.calls), before)

    def test_ordinary_question_keeps_literal_pair_at_ollama_json_boundary(self):
        value = "Ветер+Дx/91#"
        self.fake.text = value
        question = "Код: " + value
        self.send(self.question(question))
        payloads = []

        class Capture(OllamaProvider):
            async def check_available(self):
                pass

            async def _request(self, method, path, **kwargs):
                payloads.append((method, path, kwargs["json"]))
                return SimpleNamespace(json=lambda: {"message": {"content": "Обычный ответ."}})

        self.app.state.provider = Capture("qwen2.5:1.5b")
        body = self.question("Что такое проверочный код?")
        self.send(body)
        self.assertEqual([(method, path) for method, path, _ in payloads], [("POST", "/api/chat")])
        self.assertEqual(payloads[0][2]["messages"][1:], [
            {"role": "user", "content": question},
            {"role": "assistant", "content": value},
            {"role": "user", "content": body.message},
        ])

    def test_success_and_duplicate_do_not_regenerate(self):
        body = self.body()
        self.assertEqual(self.send(body)["status"], "complete")
        response = self.send(body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.fake.calls), 1)

    def test_documents_require_consent_and_bind_exact_snapshot(self):
        docs = [{"source": "note.md", "line": 2, "text": "RAW_SYNTHETIC_FRAGMENT"}]
        denied = self.body(documents=docs)
        with self.assertRaises(ValueError): self.send(denied)
        self.assertEqual(len(self.fake.calls), 0)
        body = self.body(documents=docs, document_consent=True)
        result = self.send(body)
        self.assertIn("note.md", result["reply"])
        self.assertIn("RAW_SYNTHETIC_FRAGMENT", self.fake.calls[-1][-1]["content"])
        history = self.store.history(self.chat["id"])["messages"]
        self.assertNotIn("RAW_SYNTHETIC_FRAGMENT", str(history))
        changed = body.model_copy(update={"documents": [type(body.documents[0])(**{**docs[0], "text": "DIFFERENT"})]})
        with self.assertRaises(WorkspaceConflict): self.send(changed)
        self.assertEqual(len(self.fake.calls), 1)

    def test_cloud_refused_before_claim(self):
        with self.assertRaises(HTTPException) as error: self.send(self.body(target="CLOUD"))
        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(self.store.history(self.chat["id"])["messages"], [])
        self.assertEqual(len(self.fake.calls), 0)

    def test_memory_command_never_fabricates_save_or_calls_model(self):
        for message in ("запомни: synthetic fact", "Что ты помнишь обо мне?"):
            body = self.body().model_copy(update={"message": message})
            with self.assertRaises(HTTPException) as error: self.send(body)
            self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(len(self.fake.calls), 0)
        self.assertEqual(self.store.history(self.chat["id"])["messages"], [])

    def test_missing_epoch_and_nonboolean_consent_invalid(self):
        with self.assertRaises(ValidationError): WorkspaceMessage(message="x", request_id=uuid4())
        with self.assertRaises(ValidationError): self.body(document_consent="true")

    def test_provider_outcomes_are_independent_of_category(self):
        for outcome, state in ((ProviderAttemptOutcome.NOT_SENT, "failed"), (ProviderAttemptOutcome.REJECTED, "failed"), (ProviderAttemptOutcome.UNKNOWN, "unknown")):
            body = self.body()
            self.fake.error = ProviderError(ProviderErrorCategory.AUTHENTICATION, "synthetic", provider_id="fake", attempt_outcome=outcome)
            with self.assertRaises(HTTPException): self.send(body)
            self.assertEqual(self.state(body)["status"], state)
            count = len(self.fake.calls)
            self.send(body)
            self.assertEqual(len(self.fake.calls), count)

    def test_unexpected_and_cancelled_become_unknown(self):
        for error, expected in ((ValueError("synthetic"), HTTPException), (CancelledError(), CancelledError)):
            body = self.body(); self.fake.error = error
            with self.assertRaises(expected): self.send(body)
            self.assertEqual(self.state(body)["status"], "unknown")

    def test_dispatch_write_failure_prevents_generation(self):
        body = self.body()
        with patch.object(self.store, "transition", side_effect=RuntimeError("synthetic dispatch")):
            with self.assertRaises(RuntimeError): self.send(body)
        self.assertEqual(len(self.fake.calls), 0)
        self.assertEqual(self.state(body)["status"], "pending")

    def test_lost_commit_ack_does_not_retry_or_fabricate_response(self):
        body = self.body(); original = self.store.transition
        def fault(*args, **kwargs):
            original(*args, **kwargs)
            if args[3] == "completed": raise OSError("synthetic lost COMMIT acknowledgement")
        with patch.object(self.store, "transition", side_effect=fault):
            with self.assertRaises(OSError): self.send(body)
        self.assertEqual(len(self.fake.calls), 1)
        # The caller got an error; only a later read establishes durable result.
        self.assertEqual(self.state(body)["status"], "complete")

    def test_stale_epoch_refuses_before_provider(self):
        body = self.body()
        self.store.change_chat(self.chat["id"], self.chat["epoch"], clear=True)
        with self.assertRaises(WorkspaceConflict): self.send(body)
        self.assertEqual(len(self.fake.calls), 0)

    def test_completion_returns_committed_snapshot_even_when_clear_wins_after_commit(self):
        body = self.body(); original = self.store.transition
        def clear_after_commit(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[3] == "completed":
                self.store.change_chat(self.chat["id"], self.chat["epoch"], clear=True)
            return result
        with patch.object(self.store, "transition", side_effect=clear_after_commit):
            result = self.send(body)
        self.assertEqual((result["status"], result["reply"]), ("complete", "answer [D1]"))
        self.assertEqual(self.store.history(self.chat["id"])["messages"], [])
        self.assertEqual(len(self.fake.calls), 1)

    def test_invented_document_citation_is_unknown_without_retry(self):
        self.fake.text = "Unsupported source [D99]"
        body = self.body(documents=[{"source": "a.md", "line": 1, "text": "synthetic"}], document_consent=True)
        with self.assertRaises(HTTPException): self.send(body)
        self.assertEqual(self.state(body)["status"], "unknown")
        self.assertIsNone(self.state(body)["reply"])
        self.send(body)
        self.assertEqual(len(self.fake.calls), 1)

    def test_exact_value_uncertainty_is_persisted_and_deduplicated(self):
        from app.document_context import UNCONFIRMED_EXTRACTION

        self.fake.text = "[D1] CODE-99"
        body = self.body(documents=[{"source": "a.md", "line": 1, "text": "Код: CODE-12\nКод: CODE-99"}],
                         document_consent=True).model_copy(update={"message": "Назови точный код."})
        result = self.send(body)
        self.assertEqual(result["reply"], UNCONFIRMED_EXTRACTION)
        self.assertEqual(self.state(body), result)
        self.assertEqual(self.send(body).status_code, 200)
        self.assertEqual(self.fake.calls, [])

    def test_exact_document_result_is_atomic_and_never_sent_to_model_later(self):
        docs = [{"source": "a.md", "line": 5, "text": "Новости\nКод: Клён+X_7/Ё#"}]
        body = self.body(documents=docs, document_consent=True).model_copy(update={"message": "Назови точный код."})
        result = self.send(body)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["provider_id"], "local-extraction")
        self.assertIsNone(result["provider_model"])
        self.assertIn("[D1] Клён+X_7/Ё#\n", result["reply"])
        self.assertIn("a.md · строка 6", result["reply"])
        self.assertEqual(self.state(body), result)
        self.assertEqual(self.send(body).status_code, 200)
        self.assertEqual(self.fake.calls, [])
        self.send(self.body())
        self.assertNotIn("Клён+X_7/Ё#", str(self.fake.calls))
