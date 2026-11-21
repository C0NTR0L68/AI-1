"""Opt-in workspace routes. Local documents only; no Memory V1/API integration."""
from asyncio import CancelledError
import logging
import sqlite3
from typing import Literal
from uuid import UUID

from fastapi import HTTPException, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.db import ActiveRequestsError
from app.document_context import DocumentExcerpt, build_document_context, extract_exact_answer, format_document_answer
from app.memory_commands import parse_memory_command
from app.provider import GenerationResult, ProviderError, ProviderAttemptOutcome
from app.workspace import WorkspaceConflict, fingerprint

logger = logging.getLogger(__name__)


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NewChat(StrictRequest):
    chat_id: UUID
    title: str = Field(min_length=1, max_length=100)


class EpochRequest(StrictRequest):
    epoch: UUID


class ChatChange(EpochRequest):
    title: str = Field(min_length=1, max_length=100)


class Excerpt(StrictRequest):
    source: str = Field(min_length=1, max_length=160)
    line: int = Field(strict=True, ge=1, le=10000000)
    text: str = Field(min_length=1, max_length=1200)
    first_line_complete: bool = Field(default=True, strict=True)
    last_line_complete: bool = Field(default=True, strict=True)


class WorkspaceMessage(EpochRequest):
    request_id: UUID
    message: str = Field(min_length=1, max_length=12000)
    target: Literal["LOCAL", "CLOUD"] = "LOCAL"
    documents: list[Excerpt] = Field(default_factory=list, max_length=8)
    document_consent: bool = Field(default=False, strict=True)


def install_workspace_routes(app, provider_http_error):
    @app.exception_handler(WorkspaceConflict)
    async def conflict(request, error):
        return JSONResponse(status_code=409, content={"detail": str(error), "code": "WORKSPACE_CONFLICT"})

    @app.exception_handler(ActiveRequestsError)
    async def active(request, error):
        return JSONResponse(status_code=409, content={"detail": "Chat has pending or dispatching requests."})

    # These handlers exist only in the explicit workspace factory. SQLite errors
    # never fabricate a terminal result; clients may read the scoped request.
    @app.exception_handler(sqlite3.Error)
    async def storage_error(request, error):
        logger.error("Workspace SQLite operation failed (%s)", type(error).__name__)
        return JSONResponse(status_code=503, content={"detail": "Storage result is not confirmed; do not resend automatically."})

    @app.exception_handler(KeyError)
    async def missing(request, error):
        return JSONResponse(status_code=404, content={"detail": "Chat or request not found."})

    @app.exception_handler(ValueError)
    async def invalid(request, error):
        return JSONResponse(status_code=422, content={"detail": "Invalid workspace operation."})

    @app.get("/api/workspace/chats")
    async def chats(request: Request):
        return {"chats": request.app.state.store.chats()}

    @app.post("/api/workspace/chats")
    async def new_chat(body: NewChat, request: Request):
        return request.app.state.store.create_chat(str(body.chat_id), body.title)

    @app.get("/api/workspace/chats/{chat_id}")
    async def history(chat_id: UUID, request: Request, before: int | None = Query(default=None, ge=1, le=2**63 - 1),
                      limit: int = Query(default=50, ge=1, le=100), epoch: UUID | None = None):
        return request.app.state.store.history(str(chat_id), before=before, limit=limit,
                                               epoch=str(epoch) if epoch is not None else None)

    @app.post("/api/workspace/chats/{chat_id}/rename")
    async def rename(chat_id: UUID, body: ChatChange, request: Request):
        return request.app.state.store.change_chat(str(chat_id), str(body.epoch), title=body.title)

    @app.post("/api/workspace/chats/{chat_id}/clear")
    async def clear(chat_id: UUID, body: EpochRequest, request: Request):
        return request.app.state.store.change_chat(str(chat_id), str(body.epoch), clear=True)

    @app.delete("/api/workspace/chats/{chat_id}")
    async def delete(chat_id: UUID, body: EpochRequest, request: Request):
        return request.app.state.store.change_chat(str(chat_id), str(body.epoch), delete=True)

    @app.get("/api/workspace/chats/{chat_id}/requests/{request_id}")
    async def status(chat_id: UUID, request_id: UUID, epoch: UUID, request: Request):
        return request.app.state.store.request(str(chat_id), str(epoch), str(request_id))

    @app.post("/api/workspace/chats/{chat_id}/messages")
    async def send(chat_id: UUID, body: WorkspaceMessage, request: Request):
        if body.target != "LOCAL":
            raise HTTPException(status_code=409, detail="Explicit cloud-selection policy requires approval. Nothing was sent.")
        question = body.message.strip()
        if parse_memory_command(question, enabled=True) is not None:
            raise HTTPException(status_code=409, detail="Memory V2 is not enabled. No note was saved or sent to a model.")
        documents = [item.model_dump(exclude_defaults=True) for item in body.documents]
        prepared = None
        if documents:
            prepared = build_document_context(question, tuple(DocumentExcerpt(**item) for item in documents),
                                              mode="LOCAL_ONLY", consent=body.document_consent)
        store = request.app.state.store
        chat, epoch, rid = str(chat_id), str(body.epoch), str(body.request_id)
        exact_answer = extract_exact_answer(prepared) if prepared is not None and prepared.exact_values else None
        fresh, state, context = store.claim(chat, epoch, rid, question, fingerprint(question, body.target, documents),
                                            exact_document_answer=exact_answer, allow_history_recall=not documents)
        if not fresh:
            return JSONResponse(status_code=202 if state["status"] in ("pending", "dispatching") else 200, content=state)
        if state["status"] == "complete":
            return state
        # Failed durable transition prevents provider dispatch.
        store.transition(chat, epoch, rid, "dispatching")

        def terminal(status):
            try:
                store.transition(chat, epoch, rid, status)
            except Exception as error:
                logger.error("Workspace terminal state not confirmed (%s)", type(error).__name__)
        try:
            messages = prepared.context.provider_messages() if prepared else context
            result = await request.app.state.provider.generate(messages)
            if not isinstance(result, GenerationResult):
                raise TypeError("Invalid provider result")
            if prepared:
                result = GenerationResult(format_document_answer(result.text, prepared),
                                          result.provider_id, result.requested_model, result.provider_model)
        except CancelledError:
            terminal("unknown")
            raise
        except ProviderError as error:
            terminal("failed" if error.attempt_outcome in (ProviderAttemptOutcome.NOT_SENT, ProviderAttemptOutcome.REJECTED) else "unknown")
            raise provider_http_error(error, request.app.state.effective_mode) from error
        except Exception as error:
            terminal("unknown")
            raise HTTPException(status_code=500, detail="Generation result not confirmed. No automatic retry.") from error
        try:
            completed = store.transition(chat, epoch, rid, "completed", result)
        except Exception:
            terminal("unknown")
            raise
        return completed
