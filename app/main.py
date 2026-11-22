from asyncio import CancelledError
from contextlib import ExitStack, asynccontextmanager
from functools import partial
import logging
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.config import settings
from app.context import context_from_history
from app.history_preflight import preflight_history, _sidecars
from app.security_headers import SECURITY_HEADERS, SecurityHeadersMiddleware
from app.local_requests import LocalRequestBoundary, LocalRequestPolicy
from app.db import ActiveRequestsError, ChatStore, DatabaseBusyError, RequestIdConflict
from app.runtime_lock import ApplicationRuntime, canonical_database_path
from app.policy import ModelMode, build_policy_provider, resolve_mode
from app.ollama_provider import OllamaProvider
from app.provider import (
    CloudProvider,
    GenerationResult,
    ProviderAttemptOutcome,
    ProviderError,
    ProviderErrorCategory,
)

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
            "Could not mark chat message %s as failed (%s): %s",
            message_id,
            type(mark_error).__name__,
            mark_error,
        )


def _mark_unknown_safely(chat_store: ChatStore, message_id: int) -> None:
    try:
        chat_store.mark_unknown(message_id)
    except Exception as mark_error:
        logger.error(
            "Could not mark chat message %s as unknown (%s): %s",
            message_id,
            type(mark_error).__name__,
            mark_error,
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
        "provider_id": stored["provider_id"],
        "model_name": stored["model_name"],
        "requested_model": stored["requested_model"],
        "provider_model": stored["provider_model"],
    }


async def _generate_result(
    provider, messages: list[dict[str, str]]
) -> tuple[str, str | None, str | None, str | None]:
    generate = getattr(provider, "generate", None)
    if callable(generate):
        result = await generate(messages)
        if not isinstance(result, GenerationResult):
            raise TypeError("Provider returned an invalid generation result")
        return result.text, result.provider_id, result.requested_model, result.provider_model

    # Preserve support for existing injected providers that implement reply().
    return (
        await provider.reply(messages),
        getattr(provider, "provider_id", None),
        getattr(provider, "model", None),
        None,
    )


def _provider_http_error(error: ProviderError, mode: ModelMode | None = None) -> HTTPException:
    if error.category is ProviderErrorCategory.TRANSIENT_NETWORK:
        return HTTPException(
            status_code=502,
            detail=(
                "Could not reach local Ollama. Check the local service and configured model."
                if (
                    mode in (ModelMode.OFFLINE, ModelMode.LOCAL_ONLY)
                    and error.provider_id == "ollama"
                )
                else "Could not reach the AI provider. Check the connection and provider settings."
            ),
        )
    if error.category in (
        ProviderErrorCategory.TRANSIENT_SERVICE,
        ProviderErrorCategory.AUTHENTICATION,
        ProviderErrorCategory.CONFIGURATION,
    ):
        return HTTPException(status_code=503, detail=str(error))
    if error.category is ProviderErrorCategory.INVALID_REQUEST:
        return HTTPException(status_code=400, detail=str(error))
    return HTTPException(status_code=500, detail="AI provider failed unexpectedly.")


def _build_provider():
    mode = resolve_mode(settings.provider, getattr(settings, "mode", None))
    if mode in (ModelMode.OFFLINE, ModelMode.LOCAL_ONLY):
        # Do not even build a cloud factory or access cloud configuration here.
        return build_policy_provider(
            mode,
            local_factory=partial(OllamaProvider, settings.ollama_model, settings.ollama_base_url),
        )
    cloud_factory = partial(
        CloudProvider, settings.api_key, settings.base_url, settings.model,
        api_key_required=True, provider_id="gemini",
    )
    if mode is ModelMode.ONLINE:
        return build_policy_provider(mode, cloud_factory=cloud_factory)
    return build_policy_provider(
        mode, cloud_factory=cloud_factory,
        local_factory=partial(OllamaProvider, settings.ollama_model, settings.ollama_base_url),
    )


class RuntimeGuardMiddleware:
    def __init__(self, app, runtime: ApplicationRuntime):
        self.app = app
        self.runtime = runtime

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        if not self.runtime.enter_request():
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1013})
            else:
                response = JSONResponse(
                    status_code=503, content={"detail": "Application runtime is not accepting requests"}
                )
                await response(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            # Includes provider await, response sending and exception/cancellation unwinding.
            self.runtime.exit_request()


def create_app(store: ChatStore | None = None, provider=None, *, local_port: int = 8000,
               workspace_path: str | None = None, memory_test_binding=None,
               memory_storage_factory=None) -> FastAPI:
    # An injected test listener gets its own exact Host/Origin boundary; the
    # production address remains 127.0.0.1:8000 with no wildcard allowance.
    local_policy = LocalRequestPolicy(port=local_port, native_writes="marker")
    if memory_test_binding is not None:
        from app.memory_http_v2 import MemoryTestBinding, MemoryTestMiddleware
        if (type(memory_test_binding) is not MemoryTestBinding or workspace_path is None
                or provider is None or local_port != 8000):
            raise ValueError("Memory testing requires an explicit workspace, fake provider and canonical port")
    if memory_storage_factory is not None:
        from app.memory_storage_binding import MemoryStorageFactory
        if (type(memory_storage_factory) is not MemoryStorageFactory or workspace_path is None
                or memory_test_binding is not None or local_port != 8000):
            raise ValueError("Trusted storage requires a local workspace and no test memory binding")
    if workspace_path is not None and (store is not None or not Path(workspace_path).is_absolute()):
        raise ValueError("Workspace requires an explicit absolute path and its own store")
    if workspace_path is not None:
        from app.start import local_configuration
        local_configuration(workspace_path, "path-validation-only")
        if any(item.is_symlink() or item.is_junction() for item in (Path(workspace_path), *Path(workspace_path).parents)):
            raise ValueError("Linked workspace path refused before runtime lock")
    from app.start import reject_public_database
    selected_path = workspace_path if workspace_path is not None else store.path if store is not None else settings.database_path
    runtime = ApplicationRuntime(reject_public_database(selected_path))

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        effective_mode = resolve_mode(settings.provider, getattr(settings, "mode", None))
        if workspace_path is not None and effective_mode not in (ModelMode.OFFLINE, ModelMode.LOCAL_ONLY):
            raise ValueError("New workspace currently requires explicit local mode")
        runtime.start()
        ready = False
        storage = ExitStack()
        try:
            if memory_storage_factory is not None:
                application.state.memory_storage = storage.enter_context(memory_storage_factory.open())
            if application.state.store is None:
                if workspace_path is not None:
                    from app.workspace import WorkspaceStore
                    application.state.store = WorkspaceStore(str(runtime.database_path), create=not runtime.database_path.exists())
                else:
                    _sidecars(runtime.database_path)
                    if runtime.database_path.exists():
                        # Refuse unknown/EPOCH schemas before any initializer can write.
                        preflight_history(runtime.database_path)
                    application.state.store = ChatStore(str(runtime.database_path))
            if canonical_database_path(application.state.store.path) != runtime.database_path:
                raise RuntimeError("Store database does not match the application runtime lock")
            if application.state.provider is None:
                application.state.provider = _build_provider()
            application.state.effective_mode = effective_mode
            runtime.mark_ready()
            ready = True
            yield
        finally:
            # Active handlers retain their references after lifespan teardown.
            try:
                if memory_test_binding is not None:
                    memory_test_binding.guard.disable()
            finally:
                application.state.memory_storage = None
                try:
                    storage.close()
                finally:
                    runtime.stop(ready=ready)

    application = FastAPI(title="AI-1", version="0.1.0", lifespan=lifespan,
                          docs_url=None, redoc_url=None)

    @application.exception_handler(Exception)
    async def unexpected_error(request: Request, error: Exception):
        logger.error("Unhandled application error (%s)", type(error).__name__)
        return JSONResponse(status_code=500,
                            content={"detail": "AI-1 encountered an unexpected error."},
                            headers=SECURITY_HEADERS)
    application.state.store = store
    application.state.provider = provider
    application.state.runtime = runtime
    application.state.effective_mode = None
    application.state.memory_storage = None
    application.state.workspace_mode = workspace_path is not None
    if workspace_path is not None:
        from app.workspace_api import install_workspace_routes
        install_workspace_routes(application, _provider_http_error)
    if memory_test_binding is not None:
        application.add_middleware(MemoryTestMiddleware, binding=memory_test_binding)
    application.add_middleware(RuntimeGuardMiddleware, runtime=runtime)
    # Starlette runs the last-added user middleware first, before runtime/body.
    application.add_middleware(
        LocalRequestBoundary,
        policy=local_policy,
    )
    application.add_middleware(SecurityHeadersMiddleware)
    application.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    @application.get("/")
    async def index():
        return FileResponse(BASE_DIR / "static" / ("workspace.html" if workspace_path is not None else "index.html"))

    @application.get("/api/health")
    async def health():
        return {
            "ok": True,
            "provider": settings.provider,
            "provider_configured": bool(settings.api_key) if application.state.effective_mode in (ModelMode.ONLINE, ModelMode.HYBRID) else True,
            "model": settings.model if application.state.effective_mode in (ModelMode.ONLINE, ModelMode.HYBRID) else settings.ollama_model,
            "effective_mode": application.state.effective_mode.value,
            **({"workspace": True} if workspace_path is not None else {}),
        }

    def require_legacy():
        if workspace_path is not None:
            raise HTTPException(status_code=409, detail="Workspace clients must use chat ID and epoch endpoints.")

    @application.get("/api/history")
    async def history(request: Request):
        require_legacy()
        return {"messages": request.app.state.store.history()}

    @application.get("/api/requests/{request_id}")
    async def request_status(request_id: UUID, http_request: Request):
        require_legacy()
        return _request_state(http_request.app.state.store, str(request_id))

    @application.delete("/api/history")
    async def clear_history(request: Request):
        require_legacy()
        try:
            request.app.state.store.clear()
        except ActiveRequestsError as exc:
            raise HTTPException(
                status_code=409,
                detail="History cannot be cleared while a request is pending or dispatching.",
            ) from exc
        except DatabaseBusyError as exc:
            raise HTTPException(
                status_code=503,
                detail="The chat database is busy. History was not cleared.",
            ) from exc
        return {"ok": True}

    @application.post("/api/chat")
    async def chat(request: ChatRequest, http_request: Request):
        require_legacy()
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
        try:
            context = context_from_history(previous, message)
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail="Message or conversation context is invalid."
            ) from exc
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
            response_status = (
                202
                if stored_state["status"] in ("pending", "dispatching")
                else 200
            )
            return JSONResponse(status_code=response_status, content=stored_state)

        try:
            chat_store.mark_dispatching(message_id)
        except Exception as exc:
            logger.error(
                "Could not mark chat message %s as dispatching (%s): %s",
                message_id,
                type(exc).__name__,
                exc,
            )
            raise HTTPException(
                status_code=500,
                detail="AI-1 could not start this request.",
            ) from exc

        try:
            answer, provider_id, requested_model, provider_model = await _generate_result(
                http_request.app.state.provider, context
            )
        except CancelledError:
            # Cancellation after dispatch does not prove generation stopped.
            _mark_unknown_safely(chat_store, message_id)
            raise
        except ProviderError as exc:
            if exc.attempt_outcome in (
                ProviderAttemptOutcome.NOT_SENT,
                ProviderAttemptOutcome.REJECTED,
            ):
                _mark_failed_safely(chat_store, message_id)
            else:
                _mark_unknown_safely(chat_store, message_id)
            logger.warning(
                "Provider error category=%s provider=%s status_code=%s",
                exc.category.value,
                exc.provider_id,
                exc.status_code,
            )
            raise _provider_http_error(exc, http_request.app.state.effective_mode) from exc
        except RuntimeError as exc:
            _mark_unknown_safely(chat_store, message_id)
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            _mark_unknown_safely(chat_store, message_id)
            logger.error("AI-1 request failed unexpectedly (%s)", type(exc).__name__)
            raise HTTPException(
                status_code=500,
                detail="AI-1 could not complete this request.",
            ) from exc

        try:
            chat_store.complete_turn(
                message_id,
                answer,
                provider_id=provider_id,
                requested_model=requested_model,
                provider_model=provider_model,
            )
        except Exception as exc:
            _mark_unknown_safely(chat_store, message_id)
            logger.error(
                "Could not save completed chat message %s (%s): %s",
                message_id,
                type(exc).__name__,
                exc,
            )
            raise HTTPException(
                status_code=500,
                detail="AI-1 could not complete this request.",
            ) from exc

        return _request_state(chat_store, request_id)

    return application
app = create_app()
