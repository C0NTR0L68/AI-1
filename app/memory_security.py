"""Disconnected, default-disabled access foundation, not an HTTP endpoint.

Only a trusted future console caller may invoke issue_pairing_challenge().
This module cannot authenticate native Python callers or secure a browser from
same-origin XSS. Credentials belong only in volatile client memory. No storage,
logging, console output, provider access or automatic application integration.
"""
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import math
import re
import secrets
from threading import Lock
import time
from typing import Callable


class SecurityDenied(PermissionError):
    """A safe fixed error code; never includes request values or credentials."""


@dataclass(frozen=True)
class PairingChallenge:
    secret: str = field(repr=False)
    expires_in: int = 120


@dataclass(frozen=True)
class SessionCredentials:
    bearer_token: str = field(repr=False)
    csrf_token: str = field(repr=False)


@dataclass(frozen=True)
class Principal:
    # One trusted local profile, not a claim of Windows OS authentication.
    profile: str = "local-user"


@dataclass
class _Challenge:
    digest: bytes
    expires_at: float
    failures: int = 0


@dataclass
class _Session:
    csrf_digest: bytes
    created_at: float
    last_seen: float
    mutation_identity: object = field(default_factory=object, repr=False)


@dataclass(frozen=True)
class _MutationAdmission:
    session_key: bytes = field(repr=False)
    session_identity: object = field(repr=False)


class MemoryAccessGuard:
    ORIGIN = "http://127.0.0.1:8000"
    HOST = "127.0.0.1:8000"
    CHALLENGE_TTL = 120
    MAX_FAILURES = 5
    IDLE_TTL = 15 * 60
    ABSOLUTE_TTL = 60 * 60
    MAX_SESSIONS = 4

    def __init__(
        self, *, enabled: bool = False,
        clock: Callable[[], float] = time.monotonic,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ):
        if type(enabled) is not bool or not callable(clock) or not callable(random_bytes):
            raise ValueError("Invalid security configuration")
        self._enabled = enabled
        self._clock = clock
        self._random_bytes = random_bytes
        self._lock = Lock()
        self._challenge: _Challenge | None = None
        self._sessions: dict[bytes, _Session] = {}
        self._last_time: float | None = None

    def _require_enabled(self):
        if not self._enabled:
            raise SecurityDenied("disabled")

    def _now(self) -> float:
        try:
            now = self._clock()
            if type(now) not in (int, float) or not math.isfinite(now):
                raise ValueError
            if self._last_time is not None and now < self._last_time:
                raise ValueError
        except Exception:
            self._challenge = None
            self._sessions.clear()
            raise SecurityDenied("clock") from None
        self._last_time = now
        if self._challenge and now >= self._challenge.expires_at:
            self._challenge = None
        self._sessions = {
            key: session for key, session in self._sessions.items()
            if now - session.last_seen < self.IDLE_TTL
            and now - session.created_at < self.ABSOLUTE_TTL
        }
        return now

    @staticmethod
    def _digest(token: object) -> bytes | None:
        if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
            return None
        return hashlib.sha256(token.encode("ascii")).digest()

    def _new_token(self) -> tuple[str, bytes]:
        try:
            raw = self._random_bytes(32)
        except Exception:
            raise RuntimeError("Random source failed") from None
        if type(raw) is not bytes or len(raw) != 32:
            raise RuntimeError("Random source must return 32 bytes")
        token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return token, self._digest(token)

    @staticmethod
    def _headers(headers) -> dict[str, str]:
        # Ordered pairs preserve duplicate headers. A dict cannot prove uniqueness.
        if not isinstance(headers, (list, tuple)) or len(headers) > 64:
            raise SecurityDenied("headers")
        result = {}
        for pair in headers:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise SecurityDenied("headers")
            name, value = pair
            if (not isinstance(name, str) or not isinstance(value, str)
                    or len(value) > 8192 or not value.isascii()
                    or any(ord(char) < 32 or ord(char) == 127 for char in value)
                    or re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None):
                raise SecurityDenied("headers")
            name = name.lower()
            if name in result:
                raise SecurityDenied("headers")
            result[name] = value
        return result

    def _check_request(self, method: str, headers, *, pairing: bool = False) -> dict[str, str]:
        if method not in ("GET", "HEAD", "POST", "DELETE") or (pairing and method != "POST"):
            raise SecurityDenied("method")
        values = self._headers(headers)
        if values.get("host") != self.HOST:
            raise SecurityDenied("host")
        origin = values.get("origin")
        if origin is not None and origin != self.ORIGIN:
            raise SecurityDenied("origin")
        if method in ("POST", "DELETE") and origin != self.ORIGIN:
            raise SecurityDenied("origin")
        if values.get("sec-fetch-site") not in (None, "same-origin", "none"):
            raise SecurityDenied("origin")
        content_type = values.get("content-type")
        if ((method == "POST" or content_type is not None)
                and (content_type or "").split(";", 1)[0].strip().lower() != "application/json"):
            raise SecurityDenied("content_type")
        # Forwarded/X-Forwarded-* never supply identity, authority or origin.
        return values

    def _unique_digest(self, digest: bytes, extra=()) -> bool:
        occupied = list(self._sessions) + [s.csrf_digest for s in self._sessions.values()]
        if self._challenge:
            occupied.append(self._challenge.digest)
        return not any(hmac.compare_digest(digest, existing) for existing in occupied + list(extra))

    def issue_pairing_challenge(self) -> PairingChallenge:
        """Trusted local-console entry point ONLY; never expose this as a route.

        Explicit reissue replaces the outstanding challenge. No output occurs.
        """
        with self._lock:
            self._require_enabled()
            now = self._now()
            token, digest = self._new_token()
            if not self._unique_digest(digest):
                raise RuntimeError("Random source collision")
            self._challenge = _Challenge(digest, now + self.CHALLENGE_TTL)
            return PairingChallenge(token)

    def pair(self, method: str, headers, secret: str) -> SessionCredentials:
        with self._lock:
            self._require_enabled()
            now = self._now()
            self._check_request(method, headers, pairing=True)
            challenge = self._challenge
            if challenge is None:
                raise SecurityDenied("pairing")
            digest = self._digest(secret)
            if digest is None or not hmac.compare_digest(digest, challenge.digest):
                challenge.failures += 1
                if challenge.failures >= self.MAX_FAILURES:
                    self._challenge = None
                raise SecurityDenied("pairing")
            if len(self._sessions) >= self.MAX_SESSIONS:
                raise SecurityDenied("capacity")
            bearer, bearer_digest = self._new_token()
            csrf, csrf_digest = self._new_token()
            if not self._unique_digest(bearer_digest) or not self._unique_digest(csrf_digest, (bearer_digest,)):
                raise RuntimeError("Random source collision")
            self._sessions[bearer_digest] = _Session(csrf_digest, now, now)
            self._challenge = None
            return SessionCredentials(bearer, csrf)

    def _authorize(self, method: str, headers, now: float) -> bytes:
        values = self._check_request(method, headers)
        scheme, _, token = values.get("authorization", "").partition(" ")
        digest = self._digest(token) if scheme.lower() == "bearer" else None
        # Scan the bounded session set using timing-safe digest comparison.
        key = next((key for key in self._sessions
                    if digest is not None and hmac.compare_digest(key, digest)), None)
        if key is None:
            raise SecurityDenied("unauthorized")
        session = self._sessions[key]
        if method in ("POST", "DELETE"):
            csrf_digest = self._digest(values.get("x-ai1-memory-csrf"))
            if csrf_digest is None or not hmac.compare_digest(csrf_digest, session.csrf_digest):
                raise SecurityDenied("csrf")
        # Denied requests never extend idle lifetime.
        session.last_seen = now
        return key

    def authorize(self, method: str, headers) -> Principal:
        """Admission only: already admitted work may finish after later revocation.

        Future adapters must authorize before reading storage. This foundation
        does not parse bodies, enforce note quotas, supply CORS or return HTTP.
        """
        with self._lock:
            self._require_enabled()
            self._authorize(method, headers, self._now())
            return Principal()

    def _admit_mutation(self, method, headers):
        if method not in ("POST", "DELETE"):
            raise SecurityDenied("method")
        with self._lock:
            self._require_enabled()
            key = self._authorize(method, headers, self._now())
            return _MutationAdmission(key, self._sessions[key].mutation_identity)

    def _commit_mutation(self, admission, connection):
        # Ledger already owns the SQLite write transaction. No code acquires
        # SQLite while holding this lock except COMMIT of that transaction.
        # The dedicated connection must not call the guard from SQLite hooks.
        with self._lock:
            self._require_enabled()
            self._now()
            session = self._sessions.get(admission.session_key)
            if session is None or session.mutation_identity is not admission.session_identity:
                raise SecurityDenied("unauthorized")
            connection.commit()

    def logout(self, headers) -> None:
        with self._lock:
            self._require_enabled()
            key = self._authorize("POST", headers, self._now())
            del self._sessions[key]

    def disable(self) -> None:
        with self._lock:
            self._enabled = False
            self._challenge = None
            self._sessions.clear()
