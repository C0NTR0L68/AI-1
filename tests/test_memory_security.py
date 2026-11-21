from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
from threading import Barrier

import pytest

from app.memory_security import MemoryAccessGuard, SecurityDenied


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class RandomBytes:
    """Predictable SYNTHETIC tokens; never used by production defaults."""
    def __init__(self):
        self.calls = 0

    def __call__(self, size):
        assert size == 32
        self.calls += 1
        return self.calls.to_bytes(size, "big")


def headers(credentials=None, *, write=False, origin=False):
    result = [("Host", "127.0.0.1:8000")]
    if write or origin:
        result.append(("Origin", "http://127.0.0.1:8000"))
    if write:
        result.append(("Content-Type", "application/json; charset=utf-8"))
    if credentials:
        result.append(("Authorization", "Bearer " + credentials.bearer_token))
        if write:
            result.append(("X-AI1-Memory-CSRF", credentials.csrf_token))
    return result


@pytest.fixture
def setup_guard():
    clock, rng = Clock(), RandomBytes()
    guard = MemoryAccessGuard(enabled=True, clock=clock, random_bytes=rng)
    return guard, clock, rng


def session(guard):
    challenge = guard.issue_pairing_challenge()
    return guard.pair("POST", headers(write=True), challenge.secret)


def test_security_default_disabled_has_no_time_random_or_io_side_effects():
    def forbidden(*args):
        pytest.fail("Disabled security must not access clock/randomness")
    guard = MemoryAccessGuard(clock=forbidden, random_bytes=forbidden)
    for call in (guard.issue_pairing_challenge,
                 lambda: guard.pair("POST", [], "synthetic"),
                 lambda: guard.authorize("GET", []), lambda: guard.logout([])):
        with pytest.raises(SecurityDenied, match="disabled"):
            call()
    guard.disable()


@pytest.mark.parametrize("enabled", [1, "yes", None])
def test_security_requires_explicit_boolean(enabled):
    with pytest.raises(ValueError):
        MemoryAccessGuard(enabled=enabled)


def test_pairing_requires_trusted_challenge_and_consumes_it_once(setup_guard):
    guard, _, rng = setup_guard
    with pytest.raises(SecurityDenied, match="pairing"):
        guard.pair("POST", headers(write=True), "synthetic")
    challenge = guard.issue_pairing_challenge()
    assert challenge.expires_in == 120 and len(challenge.secret) == 43
    credentials = guard.pair("POST", headers(write=True), challenge.secret)
    assert len(credentials.bearer_token) == len(credentials.csrf_token) == 43
    assert len({challenge.secret, credentials.bearer_token, credentials.csrf_token}) == 3
    assert rng.calls == 3
    with pytest.raises(SecurityDenied, match="pairing"):
        guard.pair("POST", headers(write=True), challenge.secret)
    assert guard.authorize("GET", headers(credentials)).profile == "local-user"


def test_only_one_outstanding_challenge_and_reissue_invalidates_previous(setup_guard):
    guard, _, _ = setup_guard
    old = guard.issue_pairing_challenge()
    new = guard.issue_pairing_challenge()
    with pytest.raises(SecurityDenied, match="pairing"):
        guard.pair("POST", headers(write=True), old.secret)
    guard.pair("POST", headers(write=True), new.secret)


@pytest.mark.parametrize("elapsed,allowed", [(119.999, True), (120, False), (121, False)])
def test_pairing_expiry_boundary(setup_guard, elapsed, allowed):
    guard, clock, _ = setup_guard
    challenge = guard.issue_pairing_challenge()
    clock.now += elapsed
    if allowed:
        guard.pair("POST", headers(write=True), challenge.secret)
    else:
        with pytest.raises(SecurityDenied, match="pairing"):
            guard.pair("POST", headers(write=True), challenge.secret)


@pytest.mark.parametrize("failures", [4, 5])
def test_pairing_five_failed_attempts_exhaust_challenge(setup_guard, failures):
    guard, _, _ = setup_guard
    challenge = guard.issue_pairing_challenge()
    for _ in range(failures):
        with pytest.raises(SecurityDenied, match="pairing"):
            guard.pair("POST", headers(write=True), "invalid")
    if failures == 4:
        guard.pair("POST", headers(write=True), challenge.secret)
    else:
        with pytest.raises(SecurityDenied, match="pairing"):
            guard.pair("POST", headers(write=True), challenge.secret)
        session(guard)  # Explicit local reissue, no permanent account lockout.


def test_pairing_race_has_exactly_one_success(setup_guard):
    guard, _, rng = setup_guard
    challenge = guard.issue_pairing_challenge()
    barrier = Barrier(8, timeout=3)
    def consume(_):
        barrier.wait()
        try:
            return guard.pair("POST", headers(write=True), challenge.secret)
        except SecurityDenied:
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(consume, range(8)))
    assert sum(result is not None for result in results) == 1
    assert rng.calls == 3


def test_session_capacity_logout_and_expiry_free_slots(setup_guard):
    guard, clock, _ = setup_guard
    credentials = [session(guard) for _ in range(4)]
    challenge = guard.issue_pairing_challenge()
    with pytest.raises(SecurityDenied, match="capacity"):
        guard.pair("POST", headers(write=True), challenge.secret)
    guard.logout(headers(credentials[0], write=True))
    guard.pair("POST", headers(write=True), challenge.secret)
    clock.now += 900
    session(guard)


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_read_requires_authorization_but_origin_is_optional(setup_guard, method):
    guard, _, _ = setup_guard
    credentials = session(guard)
    with pytest.raises(SecurityDenied, match="unauthorized"):
        guard.authorize(method, headers())
    assert guard.authorize(method, headers(credentials)).profile == "local-user"
    assert guard.authorize(method, headers(credentials, origin=True)).profile == "local-user"


def test_idle_refresh_does_not_extend_absolute_lifetime(setup_guard):
    guard, clock, _ = setup_guard
    credentials = session(guard)
    for _ in range(4):
        clock.now += 800
        guard.authorize("GET", headers(credentials))
    clock.now += 400
    with pytest.raises(SecurityDenied, match="unauthorized"):
        guard.authorize("GET", headers(credentials))


def test_idle_boundary_and_denied_requests_do_not_refresh(setup_guard):
    guard, clock, _ = setup_guard
    credentials = session(guard)
    clock.now += 899
    bad = [pair for pair in headers(credentials, write=True) if pair[0] != "X-AI1-Memory-CSRF"]
    with pytest.raises(SecurityDenied, match="csrf"):
        guard.authorize("POST", bad)
    clock.now += 1
    with pytest.raises(SecurityDenied, match="unauthorized"):
        guard.authorize("GET", headers(credentials))


def test_valid_read_refreshes_idle_deadline(setup_guard):
    guard, clock, _ = setup_guard
    credentials = session(guard)
    clock.now += 899
    guard.authorize("GET", headers(credentials))
    clock.now += 899
    guard.authorize("GET", headers(credentials))
    clock.now += 900
    with pytest.raises(SecurityDenied, match="unauthorized"):
        guard.authorize("GET", headers(credentials))


def test_restart_logout_and_disable_revoke_authority(setup_guard):
    guard, clock, _ = setup_guard
    first, second = session(guard), session(guard)
    restarted = MemoryAccessGuard(enabled=True, clock=clock, random_bytes=RandomBytes())
    with pytest.raises(SecurityDenied, match="unauthorized"):
        restarted.authorize("GET", headers(first))
    guard.logout(headers(first, write=True))
    with pytest.raises(SecurityDenied, match="unauthorized"):
        guard.authorize("GET", headers(first))
    guard.authorize("GET", headers(second))
    guard.issue_pairing_challenge()
    guard.disable()
    with pytest.raises(SecurityDenied, match="disabled"):
        guard.authorize("GET", headers(second))
    with pytest.raises(SecurityDenied, match="disabled"):
        guard.issue_pairing_challenge()


def test_revocation_ordering_keeps_admission_not_permanent_capability(setup_guard):
    guard, _, _ = setup_guard
    credentials = session(guard)
    admitted = guard.authorize("GET", headers(credentials))
    guard.logout(headers(credentials, write=True))
    assert admitted.profile == "local-user"  # Already admitted work may finish.
    with pytest.raises(SecurityDenied, match="unauthorized"):
        guard.authorize("GET", headers(credentials))


@pytest.mark.parametrize("value", [None, "localhost:8000", "127.0.0.1", "127.0.0.1:8001",
    "127.0.0.1:08000", "127.0.0.1:8000.attacker.invalid", "user@127.0.0.1:8000",
    "[::1]:8000", "127.0.0.1:8000 "])
def test_host_must_equal_literal_approved_authority(setup_guard, value):
    guard, _, _ = setup_guard
    credentials = session(guard)
    request = [pair for pair in headers(credentials) if pair[0] != "Host"]
    if value is not None:
        request.append(("Host", value))
    request += [("X-Forwarded-Host", guard.HOST), ("X-Forwarded-Proto", "http")]
    with pytest.raises(SecurityDenied, match="host"):
        guard.authorize("GET", request)


@pytest.mark.parametrize("value", ["null", "http://evil.invalid", "http://localhost:8000",
    "http://127.0.0.1:8001", "https://127.0.0.1:8000", "http://127.0.0.1:8000/",
    "http://user@127.0.0.1:8000", "http://127.0.0.1:8000.attacker.invalid"])
def test_foreign_or_malformed_origin_denied_even_for_authorized_read(setup_guard, value):
    guard, _, _ = setup_guard
    credentials = session(guard)
    with pytest.raises(SecurityDenied, match="origin"):
        guard.authorize("GET", headers(credentials) + [("Origin", value)])


@pytest.mark.parametrize("method", ["POST", "DELETE"])
def test_mutations_require_origin_and_session_bound_csrf(setup_guard, method):
    guard, _, _ = setup_guard
    first, second = session(guard), session(guard)
    correct = headers(first, write=True)
    for missing, code in [("Origin", "origin"), ("Authorization", "unauthorized"), ("X-AI1-Memory-CSRF", "csrf")]:
        with pytest.raises(SecurityDenied, match=code):
            guard.authorize(method, [pair for pair in correct if pair[0] != missing])
    wrong = [(key, second.csrf_token if key == "X-AI1-Memory-CSRF" else value) for key, value in correct]
    with pytest.raises(SecurityDenied, match="csrf"):
        guard.authorize(method, wrong)
    guard.authorize(method, correct)


@pytest.mark.parametrize("name", ["Host", "Origin", "Authorization", "X-AI1-Memory-CSRF", "Content-Type", "Sec-Fetch-Site"])
def test_duplicate_headers_rejected_case_insensitively(setup_guard, name):
    guard, _, _ = setup_guard
    credentials = session(guard)
    request = headers(credentials, write=True) + [("Sec-Fetch-Site", "same-origin")]
    value = next(value for key, value in request if key == name)
    with pytest.raises(SecurityDenied, match="headers"):
        guard.authorize("POST", request + [(name.lower(), value)])


@pytest.mark.parametrize("header_pairs", [{"Host": "127.0.0.1:8000"}, [("Host",)], [("Host", 12)],
    [(" Host", "127.0.0.1:8000")], [("Host", "bad\r\nOrigin: evil")], [("Host", "é")],
    [("Host", "x" * 8193)], [("X", "value")] * 65])
def test_malformed_header_collection_fails_closed(setup_guard, header_pairs):
    guard, _, _ = setup_guard
    with pytest.raises(SecurityDenied, match="headers"):
        guard.authorize("GET", header_pairs)


@pytest.mark.parametrize("method", ["OPTIONS", "PUT", "PATCH", "TRACE", "get", None])
def test_unsupported_methods_cannot_authorize(setup_guard, method):
    guard, _, _ = setup_guard
    with pytest.raises(SecurityDenied, match="method"):
        guard.authorize(method, headers())


def test_pairing_origin_errors_do_not_consume_challenge(setup_guard):
    guard, _, _ = setup_guard
    challenge = guard.issue_pairing_challenge()
    for request in (headers(), headers(write=True) + [("Origin", guard.ORIGIN)]):
        with pytest.raises(SecurityDenied):
            guard.pair("POST", request, challenge.secret)
    with pytest.raises(SecurityDenied, match="method"):
        guard.pair("GET", headers(write=True), challenge.secret)
    guard.pair("POST", headers(write=True), challenge.secret)


@pytest.mark.parametrize("content_type", [None, "text/plain", "application/x-www-form-urlencoded"])
def test_pairing_and_post_require_json_media_type(setup_guard, content_type):
    guard, _, _ = setup_guard
    challenge = guard.issue_pairing_challenge()
    request = [pair for pair in headers(write=True) if pair[0] != "Content-Type"]
    if content_type is not None:
        request.append(("Content-Type", content_type))
    with pytest.raises(SecurityDenied, match="content_type"):
        guard.pair("POST", request, challenge.secret)


@pytest.mark.parametrize("site", ["cross-site", "same-site", "invalid"])
def test_fetch_metadata_is_additional_filter_not_authentication(setup_guard, site):
    guard, _, _ = setup_guard
    credentials = session(guard)
    with pytest.raises(SecurityDenied, match="origin"):
        guard.authorize("GET", headers(credentials) + [("Sec-Fetch-Site", site)])
    with pytest.raises(SecurityDenied, match="unauthorized"):
        guard.authorize("GET", headers() + [("Sec-Fetch-Site", "same-origin")])


@pytest.mark.parametrize("bad", [0, float('nan'), float('inf'), "time"])
def test_bad_or_backward_clock_invalidates_authority(setup_guard, bad):
    guard, clock, _ = setup_guard
    credentials = session(guard)
    clock.now = bad
    with pytest.raises(SecurityDenied, match="clock"):
        guard.authorize("GET", headers(credentials))
    clock.now = 1100
    with pytest.raises(SecurityDenied, match="unauthorized"):
        guard.authorize("GET", headers(credentials))


@pytest.mark.parametrize("value", [b"short", "not bytes", None])
def test_invalid_random_source_does_not_issue_credentials(value):
    guard = MemoryAccessGuard(enabled=True, clock=Clock(), random_bytes=lambda size: value)
    with pytest.raises(RuntimeError, match="32 bytes"):
        guard.issue_pairing_challenge()


def test_random_collision_fails_without_consuming_challenge():
    guard = MemoryAccessGuard(enabled=True, clock=Clock(), random_bytes=lambda size: bytes(32))
    challenge = guard.issue_pairing_challenge()
    with pytest.raises(RuntimeError, match="collision"):
        guard.pair("POST", headers(write=True), challenge.secret)


def test_repr_errors_and_logs_do_not_disclose_credentials(setup_guard, capsys, caplog):
    guard, _, _ = setup_guard
    challenge = guard.issue_pairing_challenge()
    credentials = guard.pair("POST", headers(write=True), challenge.secret)
    with pytest.raises(SecurityDenied) as error:
        guard.authorize("GET", [("Host", credentials.bearer_token)])
    exposed = repr(challenge) + repr(credentials) + repr(guard) + str(error.value) + caplog.text
    for secret in (challenge.secret, credentials.bearer_token, credentials.csrf_token):
        assert secret not in exposed
    assert capsys.readouterr() == ("", "")


def test_module_import_and_disabled_state_have_no_app_storage_or_network_dependencies():
    repo = Path(__file__).resolve().parents[1]
    script = r'''
import os, sys
def audit(event, args):
    assert event != 'sqlite3.connect' and not event.startswith('socket.'), 'Forbidden I/O'
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        assert os.path.basename(os.fsdecode(args[0])).lower() != '.env'
sys.addaudithook(audit)
sys.path.insert(0, sys.argv[1])
from app.memory_security import MemoryAccessGuard, SecurityDenied
guard = MemoryAccessGuard()
try: guard.issue_pairing_challenge()
except SecurityDenied: pass
else: raise AssertionError('Disabled guard issued a challenge')
assert not {'app.main','app.config','app.memory','app.db','app.provider','app.ollama_provider','app.router','fastapi','httpx','sqlite3'} & sys.modules.keys()
print('SECURITY_ISOLATION_OK')
'''
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(repo)],
                            capture_output=True, text=True, timeout=15,
                            env=dict(os.environ, PYTHON_DOTENV_DISABLED="1", PYTHONDONTWRITEBYTECODE="1"))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "SECURITY_ISOLATION_OK"
