from contextlib import asynccontextmanager
import logging
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.config import settings
from app.db import ChatStore, RequestIdConflict
from app.provider import OpenAICompatibleProvider

BASE_DIR = Path(__file__).resolve().parent
logger = logging.getLogger(__name__)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1)
    request_id: UUID


def _mark_failed_safely(chat_store: ChatStore, message_id: int) -> None:
    try:
        chat_store.mark_failed(message_id)
    except Exception as mark_error:
        logger.error(
            "Could not mark chat message %s as failed (%s)",
            message_id,
            type(mark_error).__name__,
        )


def _request_state(chat_store: ChatStore, request_id: str) -> dict:
    stored = chat_store.get_request(request_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Request was not found")
    return {
        "request_id": stored["request_id"],
        "message_id": stored["message_id"],
        "status": stored["status"],
        "reply": stored["reply"],
    }


def _build_provider():
    if settings.provider == "gemini":
        return OpenAICompatibleProvider(
            settings.api_key,
            settings.base_url,
            settings.model,
            api_key_required=True,
        )
    if settings.provider == "ollama":
        return OpenAICompatibleProvider(
            "",
            settings.ollama_base_url,
            settings.ollama_model,
            api_key_required=False,
        )
    raise ValueError("AI1_PROVIDER must be 'gemini' or 'ollama'")


def create_app(store: ChatStore | None = None, provider=None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        if application.state.store is None:
            application.state.store = ChatStore(settings.database_path)
        if application.state.provider is None:
            application.state.provider = _build_provider()
        yield

    application = FastAPI(title="AI-1", version="0.1.0", lifespan=lifespan)
    application.state.store = store
    application.state.provider = provider
    application.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    @application.get("/")
    async def index():
        return FileResponse(BASE_DIR / "static" / "index.html")

    @application.get("/api/health")
    async def health():
        return {
            "ok": True,
            "provider": settings.provider,
            "provider_configured": bool(settings.api_key) if settings.provider == "gemini" else True,
            "model": settings.model if settings.provider == "gemini" else settings.ollama_model,
        }

    @application.get("/api/history")
    async def history(request: Request):
        return {"messages": request.app.state.store.history()}

    @application.get("/api/requests/{request_id}")
    async def request_status(request_id: UUID, http_request: Request):
        return _request_state(http_request.app.state.store, str(request_id))

    @application.delete("/api/history")
    async def clear_history(request: Request):
        request.app.state.store.clear()
        return {"ok": True}

    @application.post("/api/chat")
    async def chat(request: ChatRequest, http_request: Request):
        message = request.message.strip()
        if not message:
            raise HTTPException(status_code=422, detail="Message cannot be empty")
        if len(message) > settings.max_message_chars:
            raise HTTPException(
                status_code=413,
                detail=f"Message is too long (max {settings.max_message_chars} characters)",
            )

        chat_store = http_request.app.state.store
        previous = chat_store.history(limit=20)
        context = [
            {"role": item["role"], "content": item["content"]}
            for item in previous
            if item["status"] == "complete"
        ]
        context.append({"role": "user", "content": message})
        request_id = str(request.request_id)
        try:
            message_id, is_new = chat_store.claim_pending_user(message, request_id)
        except RequestIdConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="This request ID was already used with different message text",
            ) from exc

        if not is_new:
            stored_state = _request_state(chat_store, request_id)
            response_status = 202 if stored_state["status"] == "pending" else 200
            return JSONResponse(status_code=response_status, content=stored_state)

        try:
            answer = await http_request.app.state.provider.reply(context)
            chat_store.complete_turn(message_id, answer)
            return {
                "reply": answer,
                "message_id": message_id,
                "request_id": request_id,
                "status": "complete",
            }
        except RuntimeError as exc:
            _mark_failed_safely(chat_store, message_id)
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            _mark_failed_safely(chat_store, message_id)
            print(f"AI-1 connection error: {type(exc).__name__}: {exc}", flush=True)
            raise HTTPException(
                status_code=502,
                detail="Could not reach the AI provider. Check the connection and provider settings.",
            ) from exc

    return application
app = create_app()
