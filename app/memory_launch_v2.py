"""Windows LOCAL enrollment for the fixed Memory V2 SCM authority."""
import ctypes
from ctypes import wintypes as W
import os
import sys
from uuid import NAMESPACE_URL, uuid5

from app.memory_security import MemoryAccessGuard
from app.memory_service_http import semantic_service_binding
from app.memory_service_pipe import SemanticPipeClient
from app.windows_storage_inspector import _sid_string, _windows_apis


SERVICE_ACCOUNT = r"NT SERVICE\AI1MemoryAuthority"
READ_PIPE, WRITE_PIPE = (
    "AI1-C7-" + uuid5(NAMESPACE_URL, "urn:ai1:memory-v2:" + role).hex
    for role in ("read", "write")
)


def _bind(dll, name, result, *arguments):
    api = getattr(dll, name)
    api.argtypes, api.restype = arguments, result
    return api


def _service_sid(kernel, advapi):
    lookup = _bind(advapi, "LookupAccountNameW", W.BOOL, W.LPCWSTR, W.LPCWSTR, ctypes.c_void_p,
                   ctypes.POINTER(W.DWORD), W.LPWSTR, ctypes.POINTER(W.DWORD), ctypes.POINTER(W.DWORD))
    size, domain_size, use = W.DWORD(), W.DWORD(), W.DWORD()
    lookup(None, SERVICE_ACCOUNT, None, ctypes.byref(size), None, ctypes.byref(domain_size), ctypes.byref(use))
    if ctypes.get_last_error() != 122 or not 1 <= size.value <= 256 or not 1 <= domain_size.value <= 256:
        raise ValueError("Enrolled Memory V2 service account unavailable")
    sid, domain = ctypes.create_string_buffer(size.value), ctypes.create_unicode_buffer(domain_size.value)
    if not lookup(None, SERVICE_ACCOUNT, sid, ctypes.byref(size), domain, ctypes.byref(domain_size), ctypes.byref(use)):
        raise ValueError("Enrolled Memory V2 service account unavailable")
    resolved = _sid_string(advapi, kernel.LocalFree, ctypes.cast(sid, ctypes.c_void_p))
    if domain.value.casefold() != "nt service" or not resolved.startswith("S-1-5-80-"):
        raise ValueError("Unexpected Memory V2 service SID")
    return resolved


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
