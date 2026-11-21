"""No native lock, loop, server, dotenv or provider imports in these checks."""
import ast
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from app.start import local_configuration
from app.security_headers import SECURITY_HEADERS, SecurityHeadersMiddleware
from app.history_preflight import SchemaRefused, _sidecars, preflight_history

ROOT = Path(__file__).resolve().parents[1]

def complete(coroutine):
    """Only immediate synthetic ASGI callbacks; this is not real loop testing."""
    try:
        coroutine.send(None)
    except StopIteration as finished:
        return finished.value
    finally:
        coroutine.close()
    raise AssertionError("Unexpected suspension; native async is not admitted here")

class LaunchConfiguration(unittest.TestCase):
    def test_public_database_path_is_rejected_without_creating_files(self):
        from app.start import reject_public_database, local_configuration
        from uuid import uuid4
        public = Path(__file__).resolve().parent.parent / "app/static" / ("SYNTHETIC_DO_NOT_CREATE_" + uuid4().hex + ".sqlite3")
        self.assertFalse(public.exists())
        with self.assertRaises(ValueError): reject_public_database(str(public))
        with self.assertRaises(ValueError): local_configuration(str(public), "synthetic")
        self.assertFalse(public.exists())

    def test_local_path_rejects_windows_devices_streams_and_aliases_before_io(self):
        invalid = (
            r"C:\synthetic\CON.sqlite3", r"C:\NUL\history.sqlite3",
            r"C:\synthetic\history.sqlite3:extra.sqlite3", r"C:\synthetic\..\history.sqlite3",
            r"C:\trailing.\history.sqlite3", r"C:\trailing \history.sqlite3",
            r"C:\synthetic\*.sqlite3", r"C:\synthetic\bad?.sqlite3",
        )
        with patch.object(Path, "stat", side_effect=AssertionError("No filesystem access")):
            for path in invalid:
                with self.subTest(path=path), self.assertRaises(ValueError):
                    local_configuration(path, "qwen2.5:1.5b")

    def test_local_path_and_model_reject_invalid_environment_values(self):
        for path in (None, 1, "C:\\synthetic\\bad\x00.sqlite3"):
            with self.assertRaises(ValueError):
                local_configuration(path, "qwen2.5:1.5b")
        with self.assertRaises(ValueError):
            local_configuration(str(ROOT / "synthetic.sqlite3"), "qwen\x00bad")
        with self.assertRaises(ValueError):
            local_configuration(str(ROOT / "synthetic.sqlite3"), "qwen\nbad")
    def test_dotenv_disabled_flag_skips_loading_without_importing_config(self):
        from types import SimpleNamespace
        tree = ast.parse((ROOT / "app/config.py").read_bytes())
        condition = next(node for node in tree.body if isinstance(node, ast.If))
        for flag in ("1", "true", "yes", "on", " TRUE "):
            calls = []
            namespace = {"os": SimpleNamespace(getenv=lambda key, default="", flag=flag: flag),
                         "load_dotenv": lambda: calls.append("called")}
            exec(compile(ast.Module(body=[condition], type_ignores=[]), "dotenv-flag-only", "exec"), namespace)
            self.assertEqual(calls, [])
    def test_missing_database_with_orphan_sidecar_is_refused(self):
        import tempfile
        base = Path(os.environ["AI1_TEST_ROOT"]) if "AI1_TEST_ROOT" in os.environ else Path(tempfile.mkdtemp(prefix="ai1-sidecars-"))
        database = base / "not-created.sqlite3"
        Path(str(database) + "-wal").write_bytes(b"synthetic")
        with self.assertRaises(SchemaRefused):
            _sidecars(database)
        self.assertFalse(database.exists())

    def test_invalid_file_refused_before_sqlite_api(self):
        import tempfile
        base = Path(os.environ["AI1_TEST_ROOT"]) if "AI1_TEST_ROOT" in os.environ else Path(tempfile.mkdtemp(prefix="ai1-preflight-"))
        database = base / "invalid.sqlite3"
        database.write_bytes(b"synthetic, not a database")
        with patch("sqlite3.connect", side_effect=AssertionError("SQLite must not open")):
            with self.assertRaises(SchemaRefused):
                preflight_history(database)
    def test_local_has_no_cloud_key_or_dotenv(self):
        database = str(ROOT / "synthetic-not-opened.sqlite3")
        result = local_configuration(database, "qwen2.5:1.5b")
        self.assertEqual(result["AI1_PROVIDER"], "ollama")
        self.assertEqual(result["AI1_MODE"], "LOCAL_ONLY")
        self.assertEqual(result["AI1_API_KEY"], "")
        self.assertEqual(result["PYTHON_DOTENV_DISABLED"], "1")
        self.assertEqual(result["OLLAMA_BASE_URL"], "http://127.0.0.1:11434")
    def test_rejects_relative_and_non_database_names(self):
        for path in ("history.sqlite3", str(ROOT / ".env"), str(ROOT / "notes.txt")):
            with self.assertRaises(ValueError):
                local_configuration(path, "qwen2.5:1.5b")
    def test_rejects_empty_model(self):
        with self.assertRaises(ValueError):
            local_configuration(str(ROOT / "synthetic.sqlite3"), " ")
    def test_launcher_import_does_not_import_config(self):
        tree = ast.parse((ROOT / "app/start.py").read_bytes())
        imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any("app.main" in ast.unparse(node) or "app.config" in ast.unparse(node) for node in imports))
    def test_startup_preflight_precedes_store_constructor(self):
        tree = ast.parse((ROOT / "app/main.py").read_bytes())
        life = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "lifespan")
        calls = [n for n in ast.walk(life) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        before = next(n.lineno for n in calls if n.func.id == "preflight_history")
        after = next(n.lineno for n in calls if n.func.id == "ChatStore")
        self.assertLess(before, after)
    def test_cancellation_marks_unknown_and_reraises(self):
        tree = ast.parse((ROOT / "app/main.py").read_bytes())
        handler = next(n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)
                       and isinstance(n.type, ast.Name) and n.type.id == "CancelledError")
        self.assertIsInstance(handler.body[-1], ast.Raise)
        self.assertIn("_mark_unknown_safely", ast.unparse(handler))

class Headers(unittest.TestCase):
    def response(self, status):
        messages = []
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": status,
                        "headers": [(b"content-type", b"text/plain"),
                                    (b"Content-Security-Policy", b"default-src *")]})
            await send({"type": "http.response.body", "body": b"synthetic"})
        async def send(message):
            messages.append(message)
        async def receive():
            raise AssertionError("No body needed")
        complete(SecurityHeadersMiddleware(app)({"type":"http"}, receive, send))
        return messages
    def test_success_and_error_headers(self):
        for code in (200, 400, 403, 404, 409, 422, 500):
            with self.subTest(code=code):
                start, body = self.response(code)
                self.assertEqual(start["status"], code)
                for name,value in SECURITY_HEADERS.items():
                    matching = [v for k,v in start["headers"] if k.lower() == name.lower().encode()]
                    self.assertEqual(matching, [value.encode()])
                self.assertEqual(body["body"], b"synthetic")
    def test_strict_policy(self):
        policy = SECURITY_HEADERS["Content-Security-Policy"]
        self.assertNotIn("unsafe-inline", policy)
        self.assertNotIn("unsafe-eval", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertEqual(SECURITY_HEADERS["X-Frame-Options"], "DENY")
    def test_no_innerhtml_or_eval_in_shipped_scripts(self):
        for name in ("app.js", "documents.js"):
            text = (ROOT / "app/static" / name).read_text(encoding="utf-8")
            self.assertNotIn(".innerHTML", text)
            self.assertNotIn("eval(", text)
    def test_document_selectors_exist_in_html(self):
        import re
        script = (ROOT / "app/static/documents.js").read_text(encoding="utf-8")
        html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")
        for selected in re.findall(r"querySelector\('#([^']+)'\)", script):
            self.assertIn(f'id="{selected}"', html)
    def test_documents_never_constructs_requests(self):
        import re
        text = (ROOT / "app/static/documents.js").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\b(fetch|XMLHttpRequest|WebSocket|sendBeacon)\s*\(", text))

