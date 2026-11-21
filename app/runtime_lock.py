"""Windows single-instance coordination; lock files are deliberately never deleted."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import threading


class RuntimeLockBusy(RuntimeError):
    """Another application or offline recovery owns this database's lock."""


def canonical_database_path(database_path: str | Path) -> Path:
    return Path(os.path.normcase(str(Path(database_path).resolve())))


class DatabaseProcessLock:
    """A non-inheritable exclusive Windows file handle, independent of PID/time."""

    def __init__(self, database_path: str | Path):
        self.database_path = canonical_database_path(database_path)
        self.lock_path = Path(str(self.database_path) + ".runtime.lock")
        self._handle = None
        self._kernel = None

    def acquire(self) -> None:
        if self._handle is not None:
            raise RuntimeError("This OS lock is already acquired")
        if os.name != "nt":
            raise RuntimeError("Database runtime coordination currently requires Windows")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = (
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        )
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL
        # GENERIC_READ|WRITE, share=0 (also denies rename/delete), OPEN_ALWAYS.
        # NULL security attributes make the handle non-inheritable.
        handle = kernel.CreateFileW(
            str(self.lock_path), 0xC0000000, 0, None, 4, 0x80, None
        )
        if handle == ctypes.c_void_p(-1).value:
            error = ctypes.get_last_error()
            if error in (32, 33):
                raise RuntimeLockBusy("Database is owned by another application or recovery")
            raise ctypes.WinError(error)
        self._kernel = kernel
        self._handle = handle

    def release(self) -> None:
        if self._handle is not None:
            if not self._kernel.CloseHandle(self._handle):
                raise ctypes.WinError(ctypes.get_last_error())
            self._handle = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.release()


class ApplicationRuntime:
    """Keep OS ownership until both lifespan and all request references end."""

    def __init__(self, database_path: str | Path):
        self.process_lock = DatabaseProcessLock(database_path)
        self.database_path = self.process_lock.database_path
        self._mutex = threading.Lock()
        self._lifespans = 0
        self._ready_lifespans = 0
        self._requests = 0

    def start(self) -> None:
        with self._mutex:
            if self._lifespans == 0:
                if self._requests:
                    raise RuntimeError("Previous application requests are still draining")
                self.process_lock.acquire()
            self._lifespans += 1

    def mark_ready(self) -> None:
        with self._mutex:
            if self._ready_lifespans >= self._lifespans:
                raise RuntimeError("No starting lifespan to activate")
            self._ready_lifespans += 1

    def stop(self, *, ready: bool) -> None:
        with self._mutex:
            if self._lifespans <= 0:
                raise RuntimeError("Unbalanced application lifespan")
            if ready:
                if self._ready_lifespans <= 0:
                    raise RuntimeError("Unbalanced ready application lifespan")
                self._ready_lifespans -= 1
            self._lifespans -= 1
            self._release_if_idle()

    def enter_request(self) -> bool:
        with self._mutex:
            if self._ready_lifespans == 0:
                return False
            self._requests += 1
            return True

    def exit_request(self) -> None:
        with self._mutex:
            if self._requests <= 0:
                raise RuntimeError("Unbalanced application request")
            self._requests -= 1
            self._release_if_idle()

    def _release_if_idle(self) -> None:
        if self._lifespans == 0 and self._requests == 0:
            self.process_lock.release()
