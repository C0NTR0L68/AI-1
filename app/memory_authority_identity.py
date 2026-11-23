"""Fixed Win32 identity for the Memory V2 authority."""
import ctypes
from ctypes import wintypes as W
from uuid import NAMESPACE_URL, uuid5

from app.windows_storage_inspector import _sid_string


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
