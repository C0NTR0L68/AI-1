import asyncio
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading
from uuid import uuid4

import httpx
import pytest

from app.db import ChatStore
from app.main import create_app


class FakeProvider:
    def __init__(self, error=None):
        self.error = error
        self.calls = []

    async def reply(self, messages):
        self.calls.append(messages)
        if self.error:
            raise self.error
        return "Тестовый ответ: " + messages[-1]["content"]


class BlockingProvider(FakeProvider):
    def __init__(self):
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    async def reply(self, messages):
        self.calls.append(messages)
        self.started.set()
        if not await asyncio.to_thread(self.release.wait, 5):
            raise RuntimeError("test provider release timed out")
        return "Конкурентный ответ"


class ASGITestClient:
    def __init__(self, app):
        self.app = app

    async def _request(self, method, path, **kwargs):
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, path, **kwargs)

    def request(self, method, path, **kwargs):
        return asyncio.run(self._request(method, path, **kwargs))

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)

    def delete(self, path, **kwargs):
        return self.request("DELETE", path, **kwargs)


@pytest.fixture
def app_parts(tmp_path):
    store = ChatStore(str(tmp_path / "isolated-test.sqlite3"))
    provider = FakeProvider()
    return store, provider, create_app(store=store, provider=provider)


@pytest.fixture
def client(app_parts):
    return ASGITestClient(app_parts[2])


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_chat_round_trip_persists_atomic_complete_pair(client, app_parts):
    request_id = str(uuid4())
    response = client.post("/api/chat", json={"message": "Привет", "request_id": request_id})
    assert response.status_code == 200
    assert response.json()["reply"] == "Тестовый ответ: Привет"
    history = client.get("/api/history").json()["messages"]
    assert [(m["role"], m["status"]) for m in history] == [
        ("user", "complete"),
        ("assistant", "complete"),
    ]
    assert [m["content"] for m in history] == ["Привет", "Тестовый ответ: Привет"]
    assert [m["request_id"] for m in history] == [request_id, request_id]

    client.post("/api/chat", json={"message": "Ещё вопрос", "request_id": str(uuid4())})
    assert app_parts[1].calls[-1][0] == {
        "role": "user",
        "content": "Привет",
    }
    assert app_parts[1].calls[-1][1] == {
        "role": "assistant",
        "content": "Тестовый ответ: Привет",
    }


def test_failed_provider_keeps_user_text_without_assistant(client, app_parts):
    app_parts[1].error = RuntimeError("provider unavailable")
    request_id = str(uuid4())
    response = client.post(
        "/api/chat", json={"message": "Не теряй этот текст", "request_id": request_id}
    )
    assert response.status_code == 503
    history = client.get("/api/history").json()["messages"]
    assert [(m["role"], m["content"], m["status"]) for m in history] == [
        ("user", "Не теряй этот текст", "failed")
    ]


def test_failed_turn_is_excluded_from_future_model_context(client, app_parts):
    app_parts[1].error = RuntimeError("provider unavailable")
    client.post(
        "/api/chat", json={"message": "Неуспешный запрос", "request_id": str(uuid4())}
    )
    app_parts[1].error = None
    client.post("/api/chat", json={"message": "Новый запрос", "request_id": str(uuid4())})
    assert app_parts[1].calls[-1] == [{"role": "user", "content": "Новый запрос"}]


def test_success_pair_write_rolls_back_as_a_unit(app_parts):
    store = app_parts[0]
    pending_id, created = store.claim_pending_user("Атомарный ход", str(uuid4()))
    assert created is True
    with pytest.raises(sqlite3.IntegrityError):
        store.complete_turn(pending_id, None)
    history = store.history()
    assert [(item["role"], item["status"]) for item in history] == [
        ("user", "pending")
    ]


def test_pending_user_message_can_be_marked_failed(app_parts):
    store = app_parts[0]
    message_id, created = store.claim_pending_user("Сохранить при сбое", str(uuid4()))
    assert created is True
    store.mark_failed(message_id)
    assert [(item["content"], item["status"]) for item in store.history()] == [
        ("Сохранить при сбое", "failed")
    ]


def test_legacy_database_messages_default_to_complete(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("""CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        connection.execute(
            "INSERT INTO messages(role, content) VALUES ('user', 'старое сообщение')"
        )
    store = ChatStore(str(database))
    assert store.history()[0]["status"] == "complete"
    assert store.history()[0]["request_id"] is None


def test_clear_history(client, app_parts):
    app_parts[0].add_message("user", "x")
    assert client.delete("/api/history").status_code == 200
    assert client.get("/api/history").json()["messages"] == []


def test_homepage_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "AI-1" in response.text


def test_local_provider_without_key_uses_mocked_compatible_endpoint(monkeypatch):
    original_client = httpx.AsyncClient

    def handler(request):
        assert "authorization" not in request.headers
        assert request.url.path == "/v1/chat/completions"
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "локальный ответ"}}]},
        )

    def mocked_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", mocked_client)

    from app.provider import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider(
        "", "https://example.invalid/v1", "test", api_key_required=False
    )
    answer = asyncio.run(provider.reply([{"role": "user", "content": "hi"}]))
    assert answer == "локальный ответ"


def test_cloud_provider_without_key_fails_before_http_request(monkeypatch):
    def unexpected_client(*args, **kwargs):
        raise AssertionError("HTTP client must not be created without the cloud API key")

    monkeypatch.setattr(httpx, "AsyncClient", unexpected_client)

    from app.provider import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider("", "https://cloud.invalid/v1", "test")
    with pytest.raises(RuntimeError, match="API key is not configured for the cloud provider"):
        asyncio.run(provider.reply([{"role": "user", "content": "hi"}]))


def test_cloud_provider_with_key_sends_authorization_header(monkeypatch):
    original_client = httpx.AsyncClient

    def handler(request):
        assert request.headers["authorization"] == "Bearer test-secret"
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "облачный ответ"}}]},
        )

    def mocked_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", mocked_client)

    from app.provider import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider("test-secret", "https://cloud.invalid/v1", "test")
    answer = asyncio.run(provider.reply([{"role": "user", "content": "hi"}]))
    assert answer == "облачный ответ"


def test_repeated_request_id_returns_saved_reply_without_provider_call(client, app_parts):
    request_id = str(uuid4())
    payload = {"message": "Повторяемый запрос", "request_id": request_id}
    first = client.post("/api/chat", json=payload)
    second = client.post("/api/chat", json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json() == first.json()
    assert len(app_parts[1].calls) == 1
    assert len(client.get("/api/history").json()["messages"]) == 2


def test_repeated_request_id_with_different_text_returns_conflict(client, app_parts):
    request_id = str(uuid4())
    first = client.post(
        "/api/chat", json={"message": "Первый текст", "request_id": request_id}
    )
    second = client.post(
        "/api/chat", json={"message": "Другой текст", "request_id": request_id}
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert len(app_parts[1].calls) == 1
    assert len(client.get("/api/history").json()["messages"]) == 2


def test_concurrent_duplicate_request_id_calls_provider_once(app_parts):
    store, _, application = app_parts
    blocking_provider = BlockingProvider()
    application.state.provider = blocking_provider
    client = ASGITestClient(application)
    request_id = str(uuid4())
    payload = {"message": "Конкурентный запрос", "request_id": request_id}

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(client.post, "/api/chat", json=payload)
        assert blocking_provider.started.wait(2)
        duplicate = client.post("/api/chat", json=payload)
        assert duplicate.status_code == 202
        assert duplicate.json()["status"] == "pending"
        assert len(blocking_provider.calls) == 1

        blocking_provider.release.set()
        first = first_future.result(timeout=5)

    assert first.status_code == 200
    assert len(blocking_provider.calls) == 1
    stored = store.get_request(request_id)
    assert stored["status"] == "complete"
    assert stored["reply"] == "Конкурентный ответ"


def test_failed_request_replay_returns_saved_state_without_provider_call(client, app_parts):
    app_parts[1].error = RuntimeError("provider unavailable")
    payload = {"message": "Сбой с сохранённым статусом", "request_id": str(uuid4())}
    first = client.post("/api/chat", json=payload)
    second = client.post("/api/chat", json=payload)

    assert first.status_code == 503
    assert second.status_code == 200
    assert second.json()["status"] == "failed"
    assert second.json()["reply"] is None
    assert len(app_parts[1].calls) == 1


def test_request_status_endpoint_returns_complete_state_and_reply(client):
    request_id = str(uuid4())
    client.post("/api/chat", json={"message": "Проверка статуса", "request_id": request_id})

    response = client.get(f"/api/requests/{request_id}")

    assert response.status_code == 200
    assert response.json()["request_id"] == request_id
    assert response.json()["status"] == "complete"
    assert response.json()["reply"] == "Тестовый ответ: Проверка статуса"


def test_request_status_endpoint_returns_pending_state(client, app_parts):
    request_id = str(uuid4())
    app_parts[0].claim_pending_user("Ожидающий запрос", request_id)

    response = client.get(f"/api/requests/{request_id}")

    assert response.status_code == 200
    assert response.json()["request_id"] == request_id
    assert response.json()["status"] == "pending"
    assert response.json()["reply"] is None


def test_request_status_endpoint_returns_failed_state(client, app_parts):
    request_id = str(uuid4())
    message_id, _ = app_parts[0].claim_pending_user("Неуспешный запрос", request_id)
    app_parts[0].mark_failed(message_id)

    response = client.get(f"/api/requests/{request_id}")

    assert response.status_code == 200
    assert response.json()["request_id"] == request_id
    assert response.json()["status"] == "failed"
    assert response.json()["reply"] is None


def test_request_status_endpoint_returns_404_for_unknown_id(client):
    response = client.get(f"/api/requests/{uuid4()}")

    assert response.status_code == 404


@pytest.mark.parametrize(
    ("provider_error", "expected_status"),
    [(RuntimeError("provider rejected request"), 503), (ValueError("provider crashed"), 502)],
)
def test_mark_failed_error_does_not_replace_provider_error(
    client, app_parts, monkeypatch, caplog, provider_error, expected_status
):
    app_parts[1].error = provider_error

    def fail_marking(message_id):
        raise OSError("database write failed")

    monkeypatch.setattr(app_parts[0], "mark_failed", fail_marking)
    request_id = str(uuid4())
    response = client.post(
        "/api/chat", json={"message": "Не теряй исходную ошибку", "request_id": request_id}
    )

    assert response.status_code == expected_status
    if expected_status == 503:
        assert response.json()["detail"] == "provider rejected request"
    else:
        assert response.json()["detail"].startswith("Could not reach the AI provider")
    assert "Could not mark chat message" in caplog.text
    history = client.get("/api/history").json()["messages"]
    assert [(message["role"], message["status"]) for message in history] == [
        ("user", "pending")
    ]
