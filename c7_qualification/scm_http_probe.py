"""Real loopback integration for a synthetic, already qualified SCM service."""
from http.client import HTTPConnection
import json
import os
from threading import Thread
from time import monotonic, sleep


def local_action(scratch, reader, writer, phase, request=None):
    from app import start
    database = str(scratch / "local-workspace.sqlite3")
    os.environ.update(start.local_configuration(database, "synthetic-never-called"))
    from app import main
    from app.memory_security import MemoryAccessGuard
    from app.memory_service_http import semantic_test_binding
    import uvicorn

    class NeverProvider:
        async def generate(self, *args, **kwargs):
            raise AssertionError("Memory commands cannot call a provider")

    guard = MemoryAccessGuard(enabled=True)
    secret = guard.issue_pairing_challenge().secret
    binding = semantic_test_binding(guard, reader, writer)
    result = []

    def exchange(method, path, body=None, *, session=None, host="127.0.0.1:8000"):
        headers = {"Host": host, "Origin": "http://127.0.0.1:8000"}
        if session is not None:
            headers["Authorization"] = "Bearer " + session["bearer"]
            headers["X-AI1-Memory-CSRF"] = session["csrf"]
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf8")
        connection = HTTPConnection("127.0.0.1", 8000, timeout=9)
        try:
            connection.request(method, path, data, headers)
            response = connection.getresponse()
            payload = response.read()
            return response.status, json.loads(payload) if payload else None
        finally:
            connection.close()

    def run(target, **options):
        assert options == {"factory": True, "host": "127.0.0.1", "port": 8000,
                           "workers": 1, "reload": False, "proxy_headers": False}
        app = target()
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=8000, proxy_headers=False,
                                               access_log=False, log_level="error", lifespan="on",
                                               timeout_graceful_shutdown=2))
        thread = Thread(target=server.run, name="synthetic-local-uvicorn")
        thread.start()
        try:
            deadline = monotonic() + 5
            while thread.is_alive() and not server.started and monotonic() < deadline:
                sleep(0.025)
            assert server.started and thread.is_alive()
            sockets = [sock.getsockname() for listener in server.servers for sock in listener.sockets]
            assert sockets == [("127.0.0.1", 8000)]
            prefix = "/api/memory"
            assert exchange("GET", prefix + "/head")[0] == 403
            assert exchange("GET", prefix + "/head", host="invalid.example")[0] in (400, 403)
            status, session = exchange("POST", prefix + "/pair", {"secret": secret})
            assert status == 200
            if phase == "recall":
                status, reply = exchange("POST", prefix + "/command", {"command": "Что ты помнишь?"}, session=session)
                assert status == 200
                result.append(reply["notes"])
                return
            generation, rev, digest = request["head"]
            fields = {"generation": generation, "revision": rev, "digest": digest,
                      "id": request["id"], "consent": True}
            if phase == "write":
                fields["command"] = "Запомни, что " + request["text"]
                status, reply = exchange("POST", prefix + "/command", fields, session=session)
                assert status == 200
                result.append(reply["receipt"])
            elif phase == "delete":
                fields.update(note=request["note"], note_revision=request["revision"])
                status, reply = exchange("DELETE", prefix + "/notes", fields, session=session)
                assert status == 503 and reply == {"error": "outcome_unconfirmed"}
                result.append(None)
            else:
                assert phase == "reconcile"
                fields.update(note=request["note"], note_revision=request["revision"])
                status, reply = exchange("POST", prefix + "/status", fields, session=session)
                assert status == 200 and reply["retry_allowed"] is False
                result.append(reply["receipt"])
        finally:
            server.should_exit = True
            thread.join(7)
            assert not thread.is_alive() and all(not listener.is_serving() for listener in server.servers)

    original_create, original_run = main.create_app, uvicorn.run

    def create(**kwargs):
        return original_create(**kwargs, provider=NeverProvider(), memory_test_binding=binding)

    main.create_app, uvicorn.run = create, run
    try:
        assert start.main(["--workspace", "--database", database]) == 0
    finally:
        main.create_app, uvicorn.run = original_create, original_run
    return result[0]
