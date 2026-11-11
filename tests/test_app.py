import os
from fastapi.testclient import TestClient

os.environ["AI1_DATABASE_PATH"] = "test-data/test.sqlite3"
from app import main

class FakeProvider:
    async def reply(self, messages):
        return "Тестовый ответ: " + messages[-1]["content"]

client = TestClient(main.app)

def setup_function():
    main.store.clear()
    main.provider = FakeProvider()

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200 and response.json()["ok"] is True

def test_chat_round_trip_and_history():
    response = client.post("/api/chat", json={"message": "Привет"})
    assert response.status_code == 200
    assert response.json()["reply"] == "Тестовый ответ: Привет"
    history = client.get("/api/history").json()["messages"]
    assert [m["role"] for m in history] == ["user", "assistant"]
    assert history[0]["content"] == "Привет"

def test_blank_message_rejected():
    response = client.post("/api/chat", json={"message": "   "})
    assert response.status_code == 422

def test_clear_history():
    main.store.add_message("user", "x")
    assert client.delete("/api/history").status_code == 200
    assert client.get("/api/history").json()["messages"] == []

def test_provider_missing_key_error():
    from app.provider import OpenAICompatibleProvider
    import asyncio
    provider = OpenAICompatibleProvider("", "https://example.invalid/v1", "test")
    try:
        asyncio.run(provider.reply([{"role": "user", "content": "hi"}]))
    except RuntimeError as exc:
        assert "API key is not configured" in str(exc)
    else:
        assert False, "Expected missing-key error"


def test_homepage_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "AI-1" in response.text
