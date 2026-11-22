"""Narrow admission predicates for an already isolated Windows B5 worker.

This module carries no guest attestation, process launcher or audit-hook installer.
Use an independently qualified guest and process custody before enabling a plan.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import file_digest, sha256
from pathlib import Path
import re
from subprocess import list2cmdline
import stat
from threading import get_ident


PYTHON_SHA = "42ac541168e97dedb9aabd8be335539fc41c682e414b9e8d137b164fb68683b0"
NODE_SHA = "6b9088f99e93cc50ec7f2e7a2f0b6380e0ec4288a4f558453e8a28785ed14bb0"
RECOVERY_SHA = "1973f51d6ee427cb74f36087e6614733a84d151c0abbbe3fbce34189514e88bc"
MEMORY_SHA = "fe15743187ec16eec0937745eda656bf0313b9ca896667f9c2b680e54bc88fbd"
SECURITY_SHA = "b8e2095bc284f33c23060a22940e67b84f4118da3a9780e915838cb4fa32e9bf"
NODE_TEST_SHA = "2867b8d5fe9e346ca1692f78f9f2e06c9e2bd3d5b2e19fbbE3EDB9182D3EEFFD".lower()


class AdmissionDenied(PermissionError):
    """Diagnostic with no filesystem data or argument contents."""


def _single_file(path, expected):
    for entry in (path, *path.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise AdmissionDenied("PIN_LINK")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise AdmissionDenied("PIN_FILE")
    with path.open("rb") as stream:
        digest = file_digest(stream, "sha256").hexdigest()
    after = path.stat()
    if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) != (
        after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns
    ) or digest != expected:
        raise AdmissionDenied("PIN_CHANGED")


def _owned_path(root, argument):
    path = Path(argument)
    if (not path.is_absolute() or not path.is_relative_to(root)
            or any(part in (".", "..") or ":" in part or part.endswith((".", " "))
                   for part in path.parts[1:]) or path.is_reserved()):
        raise AdmissionDenied("CHILD_PATH")
    for entry in (path, *path.parents):
        if not entry.is_relative_to(root):
            break
        try:
            info = entry.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                or stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
            raise AdmissionDenied("CHILD_ALIAS")
    return path


@dataclass(frozen=True)
class ChildPlan:
    executable: str
    argv: tuple
    cwd: str
    environment: tuple

    def matches(self, event, args):
        """Compare a Windows Popen audit event to one previously accepted plan."""
        if event != "subprocess.Popen" or not isinstance(args, tuple) or len(args) != 4:
            return False
        executable, command, cwd, env = args
        return (executable == self.executable and command == list2cmdline(self.argv)
                and cwd == self.cwd and type(env) is dict
                and env == dict(self.environment))


def child_plan(case, argv, *, python, node, suite, scratch, system_root):
    """Build one exact plan before launch. No PATH lookup, shell or user env."""
    if type(argv) is not tuple or not all(type(x) is str for x in argv):
        raise AdmissionDenied("CHILD_ARGV")
    for directory in (suite, scratch, system_root):
        if not isinstance(directory, Path) or not directory.is_absolute() or ".." in directory.parts:
            raise AdmissionDenied("CHILD_ROOT")
    if (python != suite.parent / "runtime/python/python.exe"
            or node != suite.parent / "runtime/node/node.exe"
            or not scratch.is_relative_to(suite.parent)):
        raise AdmissionDenied("CHILD_STAGE_LAYOUT")
    if case == "node_ui":
        expected = (str(node), "--test", "--test-isolation=none", "tests/ui/app.test.cjs")
        if argv != expected:
            raise AdmissionDenied("NODE_ARGV")
        _single_file(node, NODE_SHA)
        _single_file(suite / "tests/ui/app.test.cjs", NODE_TEST_SHA)
    elif case in ("recovery", "memory_import", "security_import"):
        prefix = ("-B", "-u", "-c") if case == "recovery" else ("-I", "-B", "-c")
        count, pin = {"recovery": (10, RECOVERY_SHA), "memory_import": (7, MEMORY_SHA),
                      "security_import": (6, SECURITY_SHA)}[case]
        if (len(argv) != count or argv[:4] != (str(python), *prefix)
                or sha256(argv[4].encode("utf-8")).hexdigest() != pin or argv[5] != str(suite)):
            raise AdmissionDenied("PYTHON_ARGV")
        if case == "recovery":
            database, ready, proceed = (_owned_path(scratch, arg) for arg in argv[6:9])
            databases = {"hold": "process-death.sqlite3", "gated": "two-recoveries.sqlite3"}
            if not (database.name == databases.get(argv[9])
                    and len({p.parent for p in (database, ready, proceed)}) == 1
                    and re.fullmatch("ready-[a-f0-9]{32}", ready.name)
                    and re.fullmatch("proceed-[a-f0-9]{32}", proceed.name)):
                raise AdmissionDenied("RECOVERY_PATHS")
        elif case == "memory_import":
            _owned_path(scratch, argv[6])
        _single_file(python, PYTHON_SHA)
    else:
        raise AdmissionDenied("CHILD_CASE")
    environment = (
        ("SystemRoot", str(system_root)), ("WINDIR", str(system_root)),
        ("TEMP", str(scratch)), ("TMP", str(scratch)),
        ("PYTHON_DOTENV_DISABLED", "1"), ("PYTHONDONTWRITEBYTECODE", "1"),
        ("PYTHONNOUSERSITE", "1"), ("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1"),
    )
    return ChildPlan(argv[0], argv, str(suite), environment)


class PrivateSocketAudit:
    """One CPython Windows IPv4 socketpair, with no resolver or arbitrary endpoint.

    A trusted wrapper must bind this policy to exactly one call from the verified
    asyncio self-pipe and require complete construction before returning the pair.
    The listener returned by CPython remains hidden from the calling test.
    """
    def __init__(self, *, family, kind):
        self._family = family
        self._kind = kind
        self._sockets = []
        self._bound = False
        self._connected = False
        self._accepted = None

    def accept_event(self, event, args):
        if event == "socket.__new__" and len(args) == 4:
            sock, family, kind, protocol = args
            position = len(self._sockets)
            if (position < 2 and (family, kind, protocol) == (self._family, self._kind, 0)
                    and all(sock is not prior for prior in self._sockets)
                    and (position != 1 or self._bound)):
                self._sockets.append(sock)
                return
        elif event == "socket.bind" and len(args) == 2:
            sock, address = args
            if len(self._sockets) == 1 and sock is self._sockets[0] and not self._bound and address == ("127.0.0.1", 0):
                self._bound = True
                return
        elif event == "socket.connect" and len(args) == 2:
            sock, address = args
            if len(self._sockets) == 2 and sock is self._sockets[1] and self._bound and not self._connected:
                endpoint = self._sockets[0].getsockname()
                if (type(endpoint) is tuple and len(endpoint) == 2 and endpoint[0] == "127.0.0.1"
                        and type(endpoint[1]) is int and 0 < endpoint[1] <= 65535 and address == endpoint):
                    self._connected = True
                    return
        raise AdmissionDenied("SOCKET_OPERATION")

    def adopt_accepted(self, listener, reader, writer, peer):
        # CPython Windows wraps the already accepted descriptor without
        # socket.__new__. Admit only the result from the owned listener.
        if (self._accepted is not None or not self._connected or len(self._sockets) != 2
                or listener is not self._sockets[0] or writer is not self._sockets[1]
                or reader is listener or reader is writer
                or reader.fileno() < 0 or reader.fileno() in (listener.fileno(), writer.fileno())
                or peer != writer.getsockname() or reader.getsockname() != listener.getsockname()
                or reader.getpeername() != peer or writer.getpeername() != reader.getsockname()):
            raise AdmissionDenied("SOCKET_PAIR_ACCEPT_IDENTITY")
        self._accepted = reader

    def verify_pair(self, reader, writer):
        if not self._connected or len(self._sockets) != 2 or self._accepted is None:
            raise AdmissionDenied("SOCKET_PAIR_UNCONFIRMED")
        if reader is not self._accepted or writer is not self._sockets[1]:
            raise AdmissionDenied("SOCKET_PAIR_IDENTITY")
        if self._sockets[0].fileno() != -1:
            raise AdmissionDenied("SOCKET_PAIR_LISTENER_NOT_CLOSED")
        if (reader.getsockname() != writer.getpeername()
                or writer.getsockname() != reader.getpeername()):
            raise AdmissionDenied("SOCKET_PAIR_PEER_MISMATCH")


class ScopedWorkerAudit:
    """Trusted worker hook adapter. Guest and broker must be admitted separately."""

    def __init__(self, fallback):
        self._fallback = fallback
        self._scope = None

    @contextmanager
    def scoped(self, permission):
        if self._scope is not None or type(permission) not in (ChildPlan, PrivateSocketAudit):
            raise AdmissionDenied("WORKER_SCOPE")
        self._scope = (get_ident(), permission)
        self._used = False
        try:
            yield
        finally:
            self._scope = None

    def audit(self, event, args):
        if self._scope is not None and self._scope[0] == get_ident():
            permission = self._scope[1]
            if type(permission) is PrivateSocketAudit and event.startswith("socket."):
                return permission.accept_event(event, args)
            if type(permission) is ChildPlan and permission.matches(event, args) and not self._used:
                self._used = True
                return
        return self._fallback(event, args)
