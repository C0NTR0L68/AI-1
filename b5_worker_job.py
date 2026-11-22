"""Windows worker process custody for the disposable B5 guest."""
from ctypes import Structure, WinDLL, WinError, get_last_error, byref, c_int, c_int64, c_size_t, c_uint64, c_void_p, sizeof
from ctypes import wintypes as W
from subprocess import STARTUPINFO, list2cmdline
import time
import _winapi


class BasicLimits(Structure):
    _fields_ = [("process_time", c_int64), ("job_time", c_int64), ("flags", W.DWORD),
                ("min_ws", c_size_t), ("max_ws", c_size_t), ("active_limit", W.DWORD),
                ("affinity", c_size_t), ("priority", W.DWORD), ("scheduling", W.DWORD)]


class ExtendedLimits(Structure):
    _fields_ = [("basic", BasicLimits), ("io", c_uint64 * 6), ("memory", c_size_t * 4)]


class Accounting(Structure):
    _fields_ = [("times", c_int64 * 4), ("faults", W.DWORD), ("total", W.DWORD),
                ("active", W.DWORD), ("terminated", W.DWORD)]


def _kernel():
    api = WinDLL("kernel32", use_last_error=True)
    for name, args, result in (
        ("CreateJobObjectW", [c_void_p, W.LPCWSTR], W.HANDLE),
        ("SetInformationJobObject", [W.HANDLE, c_int, c_void_p, W.DWORD], W.BOOL),
        ("AssignProcessToJobObject", [W.HANDLE, W.HANDLE], W.BOOL),
        ("IsProcessInJob", [W.HANDLE, W.HANDLE, c_void_p], W.BOOL),
        ("ResumeThread", [W.HANDLE], W.DWORD),
        ("TerminateJobObject", [W.HANDLE, W.UINT], W.BOOL),
        ("QueryInformationJobObject", [W.HANDLE, c_int, c_void_p, W.DWORD, c_void_p], W.BOOL),
    ):
        fn = getattr(api, name)
        fn.argtypes, fn.restype = args, result
    return api


def require_worker_job():
    api = _kernel()
    member = W.BOOL()
    _checked(api.IsProcessInJob(_winapi.GetCurrentProcess(), None, byref(member)))
    limits = ExtendedLimits()
    if not member.value:
        raise RuntimeError("Guest worker is not assigned to a Job")
    _checked(api.QueryInformationJobObject(None, 9, byref(limits), sizeof(limits), None))
    if limits.basic.flags != 0x2008 or limits.basic.active_limit != 4:
        raise RuntimeError("Guest worker Job limits differ")


def _checked(success):
    if not success:
        raise WinError(get_last_error())


def _wait_empty(api, job, seconds):
    counts = Accounting()
    limit = time.monotonic() + seconds
    while True:
        _checked(api.QueryInformationJobObject(job, 1, byref(counts), sizeof(counts), None))
        if not counts.active:
            return True
        if time.monotonic() >= limit:
            return False
        time.sleep(.01)


def run_worker(python, launcher, root, env, *, deadline_ms, mode):
    """Launch the fixed guest entry suspended; resume only inside the private Job."""
    if not 0 < deadline_ms <= 600_000 or mode not in ("preflight", "suite"):
        raise ValueError("Fixed worker mode and finite deadline required")
    api = _kernel()
    job = api.CreateJobObjectW(None, None)
    _checked(job)
    process = thread = None
    assigned = False
    completed = False
    try:
        limits = ExtendedLimits()
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and ACTIVE_PROCESS. No breakaway.
        limits.basic.flags = 0x2000 | 0x8
        limits.basic.active_limit = 4
        _checked(api.SetInformationJobObject(job, 9, byref(limits), sizeof(limits)))
        argv = (str(python), "-I", "-S", "-B", str(launcher), "worker", mode, str(root))
        process, thread, _, _ = _winapi.CreateProcess(
            str(python), list2cmdline(argv), None, None, False,
            0x4 | _winapi.CREATE_NO_WINDOW, env, str(root), STARTUPINFO(),
        )
        _checked(api.AssignProcessToJobObject(job, process))
        assigned = True
        status = W.BOOL()
        _checked(api.IsProcessInJob(process, job, byref(status)))
        if not status.value or api.ResumeThread(thread) != 1:
            raise RuntimeError("Suspended worker custody unconfirmed")
        result = _winapi.WaitForSingleObject(process, deadline_ms)
        if result == _winapi.WAIT_TIMEOUT:
            raise TimeoutError("B5 worker deadline")
        if result != _winapi.WAIT_OBJECT_0:
            raise RuntimeError("B5 worker wait failed")
        completed = True
        return _winapi.GetExitCodeProcess(process)
    finally:
        try:
            if assigned:
                if not _wait_empty(api, job, .5 if completed else 0):
                    _checked(api.TerminateJobObject(job, 1))
                    if not _wait_empty(api, job, 3):
                        raise RuntimeError("B5 Job cleanup unconfirmed")
                    if completed:
                        raise RuntimeError("B5 worker left Job processes running")
            elif process is not None:
                _winapi.TerminateProcess(process, 1)
                if _winapi.WaitForSingleObject(process, 3000) != _winapi.WAIT_OBJECT_0:
                    raise RuntimeError("Suspended worker cleanup unconfirmed")
        finally:
            try:
                _winapi.CloseHandle(job)  # independent KILL_ON_JOB_CLOSE fallback
            finally:
                if thread is not None:
                    _winapi.CloseHandle(thread)
                if process is not None:
                    _winapi.CloseHandle(process)
