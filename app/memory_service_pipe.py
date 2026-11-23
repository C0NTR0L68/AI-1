"""Explicit v1 semantic IPC for a separately enrolled Memory V2 service."""
from contextlib import contextmanager
import json
import secrets
from uuid import UUID

from app.memory_authority_pipe import PipeAuthorityClient, _authenticated_listener, _receive, _send
from app.memory_crypto import unprotect_for_current_user
from app.memory_head_v2 import Head, HeadUnavailable
from app.memory_ledger import MemoryLedgerConflict
from app.memory_write_v2 import Mutation, WriteRefused


_REQUEST_LIMIT = 24 * 1024
_RESPONSE_LIMIT = 1024 * 1024
_READ = frozenset(("head", "recall"))
_WRITE = frozenset(("mutate", "status"))


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _receive_json(api, handle, deadline, limit):
    count = int.from_bytes(_receive(api, handle, 4, deadline), "big")
    if not 1 <= count <= limit:
        raise ValueError("frame size")
    return json.loads(_receive(api, handle, count, deadline).decode("utf8"), object_pairs_hook=_object)


def _send_json(api, handle, deadline, value, limit):
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf8")
    if not 1 <= len(data) <= limit:
        raise ValueError("frame size")
    _send(api, handle, len(data).to_bytes(4, "big") + data, deadline)


def _uid(value):
    if type(value) is not str or len(value) != 36:
        raise ValueError("operation identity")
    parsed = UUID(value)
    if parsed.int == 0 or str(parsed) != value:
        raise ValueError("operation identity")
    return parsed


def pack_head(head):
    return [str(head.generation), head.revision, head.digest.hex()]


def unpack_head(fields):
    if (type(fields) is not list or len(fields) != 3 or type(fields[2]) is not str
            or len(fields[2]) != 64):
        raise ValueError("head")
    return Head(_uid(fields[0]), fields[1], bytes.fromhex(fields[2]))


class SemanticMemory:
    """Apply admitted operations under the service's own DPAPI identity."""

    def __init__(self, writer, reducer):
        self._writer = writer
        self._reducer = reducer

    def execute(self, command, *, writable):
        if type(command) is not dict or type(command.get("op")) is not str:
            raise WriteRefused("invalid_command")
        op = command["op"]
        if writable is False and op in _READ and command.keys() == {"op"}:
            head = self._writer.head()
            if op == "head":
                return pack_head(head)
            return [[note.id, note.revision, unprotect_for_current_user(note.sealed).decode("utf8")]
                    for note in self._reducer.read(head)]
        if (writable is not True or op not in _WRITE or command.keys() !=
                {"op", "head", "id", "kind", "text", "note", "revision"}):
            raise WriteRefused("role_or_command_refused")
        expected = unpack_head(command["head"])
        operation_id = _uid(command["id"])
        mutation = Mutation(command["kind"], command["text"], command["note"], command["revision"])
        live = self._writer.head()
        if op == "mutate" and expected != live:
            raise WriteRefused("stale_head")
        identity = self._reducer.identify(expected, operation_id, mutation, current=live)
        if op == "status":
            receipt = self._writer.status(expected, identity)
            return None if receipt is None else pack_head(receipt)
        return pack_head(self._writer.commit(expected, identity, mutation))


@contextmanager
def semantic_listener(name, *, server_sid, client_sid, handler, writable=False,
                      integrity=12288, timeout=5.0):
    if type(writable) is not bool:
        raise ValueError("Explicit pipe role required")

    def dispatch(api, handle, deadline, operation):
        if operation != b"V":
            _send(api, handle, b"!", deadline)
            return "denied"
        nonce = secrets.token_bytes(32)
        _send(api, handle, b"1" + nonce, deadline)
        if _receive(api, handle, len(nonce), deadline) != nonce:
            return "denied"
        try:
            request = _receive_json(api, handle, deadline, _REQUEST_LIMIT)
            reply = {"ok": handler(request, writable=writable)}
        except (WriteRefused, ValueError, MemoryLedgerConflict, RecursionError):
            reply = {"error": "refused"}
        except Exception:
            reply = {"error": "unconfirmed"}
        _send_json(api, handle, deadline, reply, _RESPONSE_LIMIT)
        return "served" if _receive(api, handle, 1, deadline) == b"A" else "disconnected"

    with _authenticated_listener(name, server_sid=server_sid, client_sid=client_sid, timeout=timeout,
                                 client_integrity=integrity, dispatch=dispatch) as serve:
        yield serve


class SemanticPipeClient(PipeAuthorityClient):
    def request(self, command):
        with self._connection() as (api, handle, deadline):
            _send(api, handle, b"V", deadline)
            if _receive(api, handle, 1, deadline) != b"1":
                raise HeadUnavailable("semantic_role_refused")
            nonce = _receive(api, handle, 32, deadline)
            _send(api, handle, nonce, deadline)
            reply = _receive_json(api, handle, deadline, _RESPONSE_LIMIT)
            _send(api, handle, b"A", deadline)
            if type(reply) is dict and reply.keys() == {"ok"}:
                return reply["ok"]
            if reply == {"error": "refused"}:
                raise WriteRefused("semantic_request_refused")
            raise HeadUnavailable("semantic_outcome_unconfirmed")
