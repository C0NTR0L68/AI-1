"""Worker-side adapters for a trusted, Job-contained Windows Sandbox supervisor."""
from asyncio.proactor_events import BaseProactorEventLoop
from asyncio.selector_events import BaseSelectorEventLoop
from contextlib import contextmanager
from pathlib import Path
import re
import socket
import subprocess
import sys

from b5_admission import AdmissionDenied, PrivateSocketAudit, child_plan


def _private_pair(audit):
    """Actual TCP self-pipe, with bounded calls and owned-resource cleanup."""
    permission = PrivateSocketAudit(family=socket.AF_INET, kind=socket.SOCK_STREAM)
    listener = writer = reader = None
    try:
        with audit.scoped(permission):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.settimeout(2)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            writer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            writer.settimeout(2)
            writer.connect(listener.getsockname())
            reader, peer = listener.accept()
            permission.adopt_accepted(listener, reader, writer, peer)
            listener.close()
            permission.verify_pair(reader, writer)
            reader.setblocking(False)
            writer.setblocking(False)
        return reader, writer
    except BaseException as primary:
        for resource in (reader, writer, listener):
            if resource is not None and resource.fileno() != -1:
                try:
                    resource.close()
                except OSError:
                    primary.add_note("Self-pipe socket close failed; discard the guest")
        raise


def _node_summary(stdout):
    if type(stdout) is not str:
        return None
    metrics = re.findall(r"^# (tests|pass|fail|cancelled|skipped|todo) (\d+)\s*$", stdout, re.MULTILINE)
    if len(metrics) != 6 or len({name for name, _ in metrics}) != 6:
        return None
    return {name: int(count) for name, count in metrics}


@contextmanager
def scoped_worker_adapters(audit, *, python, node, suite, scratch, system_root, node_results=None):
    """Install only in a verified guest worker that is already in a private Job."""
    original_pair = socket.socketpair
    original_popen = subprocess.Popen
    self_pipe_callers = (BaseProactorEventLoop._make_self_pipe.__code__,
                         BaseSelectorEventLoop._make_self_pipe.__code__)
    children = []

    def socketpair(*args, **kwargs):
        if args or kwargs or sys._getframe(1).f_code not in self_pipe_callers:
            raise AdmissionDenied("ASYNCIO_CALLER")
        return _private_pair(audit)

    class PinnedPopen(original_popen):
        def __init__(self, args, **kwargs):
            allowed = {"stdin", "stdout", "stderr", "text", "encoding", "errors",
                       "universal_newlines", "cwd", "env"}
            if (set(kwargs) - allowed or not isinstance(args, (list, tuple))
                    or not all(type(item) is str for item in args)
                    or kwargs.get("stdin") not in (None, subprocess.PIPE, subprocess.DEVNULL)
                    or any(kwargs.get(key) not in (None, subprocess.PIPE, subprocess.DEVNULL)
                           for key in ("stdout", "stderr"))):
                raise AdmissionDenied("CHILD_POPEN_OPTIONS")
            argv = tuple(args)
            if not argv:
                raise AdmissionDenied("CHILD_EMPTY_ARGV")
            if kwargs.get("cwd") is not None and Path(kwargs["cwd"]) != suite:
                raise AdmissionDenied("CHILD_CWD")
            if Path(argv[0]) == node:
                case = "node_ui"
                # Windows shutil.which() commonly preserves the uppercase
                # PATHEXT extension. Launch through the verified canonical path.
                argv = (str(node), *argv[1:])
            elif len(argv) == 10:
                case = "recovery"
            elif len(argv) == 7:
                case = "memory_import"
            else:
                case = "security_import"
            plan = child_plan(case, argv, python=python, node=node, suite=suite,
                              scratch=scratch, system_root=system_root)
            self._b5_case = case
            self._b5_node_recorded = False
            kwargs.update(cwd=plan.cwd, executable=plan.executable, env=dict(plan.environment))
            with audit.scoped(plan):
                super().__init__(argv, **kwargs)
            children.append(self)

        def communicate(self, *args, **kwargs):
            result = super().communicate(*args, **kwargs)
            if node_results is not None and self._b5_case == "node_ui" and not self._b5_node_recorded:
                node_results.append(_node_summary(result[0]))
                self._b5_node_recorded = True
            return result

    socket.socketpair = socketpair
    subprocess.Popen = PinnedPopen
    try:
        yield
    finally:
        socket.socketpair = original_pair
        subprocess.Popen = original_popen
        failures = []
        for child in children:
            try:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=3)
            except (OSError, subprocess.SubprocessError) as exc:
                failures.append(type(exc).__name__)
        if failures:
            raise AdmissionDenied("CHILD_CLEANUP_REQUIRED")
