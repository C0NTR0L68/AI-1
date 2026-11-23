"""Windows LOCAL enrollment for the fixed Memory V2 SCM authority."""
import ctypes
from ctypes import wintypes as W
import os
import sys

from app.memory_authority_identity import READ_PIPE, WRITE_PIPE, _bind, _service_sid
from app.memory_security import MemoryAccessGuard
from app.memory_service_http import semantic_service_binding
from app.memory_service_pipe import SemanticPipeClient
from app.windows_storage_inspector import _sid_string, _windows_apis


def _client_sid(kernel, advapi):
    current = _bind(kernel, "GetCurrentProcess", W.HANDLE)
    open_token = _bind(advapi, "OpenProcessToken", W.BOOL, W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE))
    query = _bind(advapi, "GetTokenInformation", W.BOOL, W.HANDLE, W.DWORD, ctypes.c_void_p,
                  W.DWORD, ctypes.POINTER(W.DWORD))
    token = W.HANDLE()
    if not open_token(current(), 8, ctypes.byref(token)):
        raise ValueError("LOCAL Windows token unavailable")
    try:
        size, elevated = W.DWORD(), W.DWORD()
        if not query(token, 20, ctypes.byref(elevated), ctypes.sizeof(elevated), ctypes.byref(size)) or elevated.value:
            raise ValueError("Memory V2 requires a non-elevated LOCAL process")
        query(token, 1, None, 0, ctypes.byref(size))
        if not 1 <= size.value <= 4096:
            raise ValueError("LOCAL SID unavailable")
        data = ctypes.create_string_buffer(size.value)
        if not query(token, 1, data, size.value, ctypes.byref(size)):
            raise ValueError("LOCAL SID unavailable")
        return _sid_string(advapi, kernel.LocalFree, ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p)).contents)
    finally:
        kernel.CloseHandle(token)


def make_binding():
    if os.name != "nt" or not (sys.stdin.isatty() and sys.stderr.isatty()):
        raise ValueError("Memory V2 requires a trusted interactive Windows console")
    kernel, advapi = _windows_apis()
    server_sid = _service_sid(kernel, advapi)
    client_sid = _client_sid(kernel, advapi)
    reader = SemanticPipeClient(READ_PIPE, server_sid=server_sid, client_sid=client_sid, timeout=5)
    writer = SemanticPipeClient(WRITE_PIPE, server_sid=server_sid, client_sid=client_sid, timeout=5)
    guard = MemoryAccessGuard(enabled=True)
    binding = semantic_service_binding(guard, reader, writer)
    print("Memory V2 pairing (120 sec): " + guard.issue_pairing_challenge().secret, file=sys.stderr, flush=True)
    return binding
