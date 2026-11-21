"""Explicit synthetic ASGI memory circuit. No production factory installs it.

The trusted caller supplies scratch-only connections and a test codec. This
module does not select a path or imply C7, key persistence or live readiness.
"""
from asyncio import timeout
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import sqlite3
from uuid import UUID

from starlette.responses import JSONResponse

from app.local_requests import LocalRequestPolicy
from app.memory import _log_cleanup_failure
from app.memory_ledger import MemoryLedger, MemoryLedgerConflict
from app.memory_reconciliation import (
    MemoryOperationReconciler, OperationIdentity, ReconciliationDisabled, ReconciliationOutcome,
)
from app.memory_security import MemoryAccessGuard, SecurityDenied

_PREFIX = "/api/memory"
_NOTES = _PREFIX + "/notes"
_PAIR = _PREFIX + "/pair"
_LOGOUT = _PREFIX + "/logout"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_OP = re.compile(_PREFIX + "/operations/(" + _UUID + ")")
_PAGE = re.compile(_NOTES + "/(" + _UUID + ")/([1-9][0-9]{0,18})")
_MAX_INT = 2**63 - 1
_HEADERS = {"cache-control": "no-store", "x-content-type-options": "nosniff",
            "content-security-policy": "default-src 'none'; frame-ancestors 'none'"}
_LOCAL = LocalRequestPolicy(port=8000, native_writes="deny")


@dataclass(frozen=True)
class MemoryTestBinding:
    """Trusted in-process opt-in for a synthetic workspace only."""
    dispatch: object = field(repr=False)
    guard: MemoryAccessGuard = field(repr=False)

    def __post_init__(self):
        if not callable(self.dispatch) or type(self.guard) is not MemoryAccessGuard:
            raise ValueError("Expected an explicit synthetic memory binding")


class MemoryTestMiddleware:
    """Route only the memory namespace behind the application's H7/runtime."""
    def __init__(self, app, binding):
        self.app, self.binding = app, binding

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if scope["type"] in ("http", "websocket") and (path == _PREFIX or path.startswith(_PREFIX + "/")):
            return await self.binding.dispatch(scope, receive, send)
        return await self.app(scope, receive, send)


def create_memory_test_binding(*, guard, **kwargs):
    return MemoryTestBinding(create_memory_test_app(enabled=True, guard=guard, **kwargs), guard)


class _InvalidBody(ValueError):
    pass


def _error(status, code):
    return JSONResponse({"error": code}, status_code=status, headers=_HEADERS)


def _response(data):
    return JSONResponse(data, headers=_HEADERS)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidBody()
        result[key] = value
    return result


def _invalid_constant(_):
    raise _InvalidBody()


async def _object(receive, limit, length):
    data = bytearray()
    async with timeout(3):
        for _ in range(128):
            event = await receive()
            chunk = event.get("body", b"")
            more = event.get("more_body", False)
            if event.get("type") != "http.request" or type(chunk) is not bytes or type(more) is not bool:
                raise _InvalidBody()
            if len(data) + len(chunk) > limit:
                return None
            data.extend(chunk)
            if not more:
                break
        else:
            raise _InvalidBody()
    if length is not None and len(data) != int(length):
        raise _InvalidBody()
    # Reject nested containers before JSON parsing. This protocol is flat.
    quoted = escaped = False
    depth = 0
    try:
        source = data.decode("utf-8", "strict")
        for char in source:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char == "{":
                depth += 1
                if depth != 1:
                    raise _InvalidBody()
            elif char == "}":
                depth -= 1
            elif char in "[]":
                raise _InvalidBody()
        parsed = json.loads(source, object_pairs_hook=_unique, parse_constant=_invalid_constant)
        if type(parsed) is not dict:
            raise _InvalidBody()
        return parsed
    except (ValueError, UnicodeError) as error:
        raise _InvalidBody() from error


def _uuid(value):
    if type(value) is not str or re.fullmatch(_UUID, value) is None:
        raise _InvalidBody()
    return UUID(value)


def _note(value):
    if type(value) is not str or not value.strip() or len(value) > 4096 or "\x00" in value:
        raise _InvalidBody()
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise _InvalidBody() from error
    if len(raw) > 16384:
        raise _InvalidBody()
    return raw


@contextmanager
def _owned_connection(connect):
    conn = connect()
    failed = False
    try:
        yield conn
    except BaseException:
        failed = True
        raise
    finally:
        try:
            conn.close()
        except BaseException as error:
            if not failed:
                raise
            _log_cleanup_failure("HTTP close", error)


def create_memory_test_app(*, enabled=False, guard=None, connect=None, seal=None, unseal=None,
                           bind_key=None, receipt_budget=None):
    """Return a standalone ASGI callable, never auto-installed in AI-1."""
    if type(enabled) is not bool:
        raise ValueError("Explicit boolean required")
    if enabled and (type(guard) is not MemoryAccessGuard or not all(map(callable, (connect, seal, unseal)))
                    or type(bind_key) is not bytes or len(bind_key) < 32
                    or type(receipt_budget) is not int or not 1 <= receipt_budget <= _MAX_INT):
        raise ValueError("Explicit synthetic dependencies required")

    async def dispatch(scope, receive):
        path, method = scope.get("path"), scope.get("method")
        if not enabled or type(path) is not str:
            return _error(404, "disabled")
        operation, page = _OP.fullmatch(path), _PAGE.fullmatch(path)
        pairing = path == _PAIR
        methods = {"GET", "POST", "DELETE"} if path == _NOTES else {"POST"} if path in (_PAIR, _LOGOUT) else (
            {"GET", "POST"} if operation else {"GET"} if page else set()
        )
        if not methods:
            return _error(404, "route_denied")
        if method not in methods:
            return _error(405, "method_denied")
        if (not path.isascii() or scope.get("raw_path") != path.encode("ascii")
                or scope.get("root_path", "") or scope.get("query_string", b"")):
            return _error(400, "path_denied")
        denial = _LOCAL.check(scope)
        if denial is not None:
            return _error(denial, "access_denied")
        headers = [(key.decode("ascii"), value.decode("ascii")) for key, value in scope["headers"]]
        values = guard._check_request(method, headers, pairing=pairing)
        if not pairing:
            guard.authorize(method, headers)
        if method in ("POST", "DELETE"):
            if "content-type" not in values:
                return _error(415, "invalid_media_type")
            limit = 512 if pairing or path == _LOGOUT else 24576
            length = values.get("content-length")
            if length is not None and int(length) > limit:
                return _error(413, "body_too_large")
            payload = await _object(receive, limit, length)
            if payload is None:
                return _error(413, "body_too_large")
            if pairing:
                if set(payload) != {"secret"} or type(payload["secret"]) is not str:
                    raise _InvalidBody()
                tokens = guard.pair(method, headers, payload["secret"])
                return _response({"bearer": tokens.bearer_token, "csrf": tokens.csrf_token})
            if path == _LOGOUT:
                if payload:
                    raise _InvalidBody()
                guard.logout(headers)
                return _response({"state": "revoked"})
            kind = payload.get("kind")
            fields = {"generation", "operation", "kind", "consent"}
            if (kind not in ("create", "update", "delete") or payload.get("consent") is not True
                    or (operation is None and (method == "DELETE") != (kind == "delete"))):
                raise _InvalidBody()
            if kind != "delete":
                fields.add("text")
            if kind != "create":
                fields.update(("id", "revision"))
            if set(payload) != fields:
                raise _InvalidBody()
            operation_id, generation = _uuid(payload["operation"]), _uuid(payload["generation"])
            note_id, revision = payload.get("id"), payload.get("revision")
            if kind != "create" and not all(type(v) is int and 1 <= v <= _MAX_INT for v in (note_id, revision)):
                raise _InvalidBody()
            raw = _note(payload["text"]) if kind != "delete" else None
            material = json.dumps([str(generation), str(operation_id), kind, note_id, revision,
                                   payload.get("text")], ensure_ascii=False, separators=(",", ":"))
            binding = hmac.digest(bind_key, b"ai1-memory-v2\0" + material.encode("utf-8"), hashlib.sha256)
            identity = OperationIdentity(operation_id, generation, binding)
            # Recheck after body parsing and before touching codec or storage.
            guard.authorize(method, headers)
            if operation:
                if str(operation_id) != operation[1]:
                    raise _InvalidBody()
                with _owned_connection(connect) as conn:
                    ledger = MemoryLedger(conn, enabled=True, receipt_budget=receipt_budget)
                    resolution = MemoryOperationReconciler(enabled=True).reconcile(
                        identity, ledger.snapshot(operation_id),
                    )
                state = "complete" if resolution.outcome is ReconciliationOutcome.CONFIRMED else resolution.outcome.value
                return _response({"state": state, "reason": resolution.reason.value, "retry_allowed": False})
            sealed = seal(raw) if raw is not None else None
            if raw is not None and (type(sealed) is not bytes or not 1 <= len(sealed) <= 65536):
                raise RuntimeError("Invalid codec response")
            with _owned_connection(connect) as conn:
                ledger = MemoryLedger(conn, enabled=True, receipt_budget=receipt_budget)
                receipt = ledger.mutate_authorized(guard, method, headers,
                                                  identity, kind,
                                                  note_id=note_id, revision=revision, sealed=sealed)
            return _response({"id": receipt.note_id, "revision": receipt.revision, "replayed": receipt.replayed})

        with _owned_connection(connect) as conn:
            ledger = MemoryLedger(conn, enabled=True, receipt_budget=receipt_budget)
            if operation:
                snapshot = ledger.snapshot(UUID(operation[1]))
                return _response({"generation": str(snapshot.current_store_generation),
                                  "state": "recorded" if snapshot.receipt else "unknown",
                                  "retry_allowed": False})
            generation, after = (UUID(page[1]), int(page[2])) if page else (ledger.check_integrity(), 0)
            if after > _MAX_INT:
                raise _InvalidBody()
            notes = ledger.read(generation, after=after, limit=51)
            result = [{"id": n.id, "revision": n.revision, "text": unseal(n.sealed).decode("utf-8", "strict")}
                      for n in notes[:50]]
            return _response({"generation": str(generation), "notes": result,
                              "next_after": result[-1]["id"] if len(notes) == 51 else None})

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                event = await receive()
                if event["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif event["type"] == "lifespan.shutdown":
                    if enabled:
                        guard.disable()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            return
        try:
            response = await dispatch(scope, receive)
        except SecurityDenied as error:
            response = _error(401 if str(error) == "unauthorized" else 403, "access_denied")
        except _InvalidBody:
            response = _error(422, "invalid_body")
        except TimeoutError:
            response = _error(408, "request_timeout")
        except MemoryLedgerConflict:
            response = _error(409, "memory_conflict")
        except (sqlite3.Error, ReconciliationDisabled):
            response = _error(503, "operation_not_confirmed")
        except Exception:
            response = _error(503, "operation_not_confirmed")
        await response(scope, receive, send)

    return app
