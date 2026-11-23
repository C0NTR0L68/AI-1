"""Explicit guarded ASGI adapter, installed only by the synthetic workspace."""
from uuid import UUID

from starlette.concurrency import run_in_threadpool

from app.memory_commands import MemoryAction, parse_memory_command
from app.memory_head_v2 import HeadUnavailable
from app.memory_http_v2 import MemoryTestBinding, _InvalidBody, _LOCAL, _error, _object, _response
from app.memory_security import MemoryAccessGuard, SecurityDenied
from app.memory_service_pipe import SemanticPipeClient, unpack_head
from app.memory_write_v2 import WriteRefused


_PAIR = "/api/memory/pair"
_HEAD = "/api/memory/head"
_COMMAND = "/api/memory/command"
_DELETE = "/api/memory/notes"
_STATUS = "/api/memory/status"
_METHODS = {_PAIR: "POST", _HEAD: "GET", _COMMAND: "POST", _DELETE: "DELETE", _STATUS: "POST"}


def _mutation(payload, delete):
    fields = {"generation", "revision", "digest", "id", "consent"}
    fields |= {"note", "note_revision"} if delete else {"text"}
    if payload.keys() != fields or payload["consent"] is not True:
        raise _InvalidBody()
    head = [payload["generation"], payload["revision"], payload["digest"]]
    unpack_head(head)
    if type(payload["id"]) is not str or str(UUID(payload["id"])) != payload["id"]:
        raise _InvalidBody()
    return {"op": "mutate", "head": head, "id": payload["id"],
            "kind": "delete" if delete else "create", "text": payload.get("text"),
            "note": payload.get("note"), "revision": payload.get("note_revision")}


def semantic_test_binding(guard, reader, writer):
    if type(guard) is not MemoryAccessGuard or any(type(client) is not SemanticPipeClient for client in (reader, writer)):
        raise ValueError("Explicit synthetic service binding required")

    async def dispatch(scope, receive, send):
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        try:
            response = await route(scope, receive)
        except SecurityDenied:
            response = _error(403, "access_denied")
        except (ValueError, UnicodeError, TimeoutError):
            response = _error(400, "invalid_request")
        except HeadUnavailable:
            response = _error(503, "outcome_unconfirmed")
        await response(scope, receive, send)

    async def route(scope, receive):
        path, method = scope["path"], scope["method"]
        if path not in _METHODS:
            return _error(404, "route_denied")
        if method != _METHODS[path]:
            return _error(405, "method_denied")
        if scope.get("raw_path") != path.encode("ascii") or scope.get("root_path") or scope.get("query_string"):
            return _error(400, "path_denied")
        denial = _LOCAL.check(scope)
        if denial is not None:
            return _error(denial, "access_denied")
        headers = [(key.decode("ascii"), value.decode("ascii")) for key, value in scope["headers"]]
        values = guard._check_request(method, headers, pairing=path == _PAIR)
        if path != _PAIR:
            guard.authorize(method, headers)
        if path == _HEAD:
            return _response({"head": await run_in_threadpool(reader.request, {"op": "head"})})
        if "content-type" not in values:
            return _error(415, "invalid_media_type")
        length = values.get("content-length")
        if length is not None and int(length) > 24576:
            return _error(413, "body_too_large")
        payload = await _object(receive, 24576, length)
        if payload is None:
            return _error(413, "body_too_large")
        if path == _PAIR:
            if payload.keys() != {"secret"} or type(payload["secret"]) is not str:
                raise _InvalidBody()
            tokens = guard.pair(method, headers, payload["secret"])
            return _response({"bearer": tokens.bearer_token, "csrf": tokens.csrf_token})
        if path == _COMMAND:
            intent = parse_memory_command(payload.get("command"), enabled=True)
            if intent is not None and intent.action is MemoryAction.LIST and payload.keys() == {"command"}:
                return _response({"notes": await run_in_threadpool(reader.request, {"op": "recall"})})
            if intent is None or intent.action is not MemoryAction.SAVE or "text" in payload:
                raise _InvalidBody()
            fields = {key: value for key, value in payload.items() if key != "command"}
            request = _mutation({**fields, "text": intent.text}, False)
        else:
            request = _mutation(payload, path == _DELETE or "note" in payload and path == _STATUS)
        try:
            if path == _STATUS:
                request["op"] = "status"
                receipt = await run_in_threadpool(writer.request, request)
                return _response({"receipt": receipt, "retry_allowed": False})
            admission = guard._admit_mutation(method, headers)
            saved = await run_in_threadpool(guard._finish_mutation, admission, lambda: writer.request(request))
        except WriteRefused:
            return _error(409, "operation_refused")
        return _response({"receipt": saved})

    return MemoryTestBinding(dispatch, guard)
