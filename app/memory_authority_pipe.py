"""Local, read-only Windows authority channel for dormant Memory V2."""
from contextlib import closing, contextmanager
import ctypes
from ctypes import wintypes as W
import logging
import os
import re
import struct
from time import monotonic, sleep
from uuid import UUID

from app.memory_head_v2 import Head, HeadUnavailable
from app.windows_storage_inspector import _free_local, _sid_string, _windows_apis


_NAME = re.compile(r"AI1-C7-[a-f0-9]{32}\Z")
_ACCOUNT_SID = re.compile(r"S-1-5-(?:18|21(?:-[0-9]{1,10}){4}|80(?:-[0-9]{1,10}){5})\Z")
_RESPONSE = struct.Struct(">16sQ32s")
_CLIENT_ACCESS = 0x0012008B  # FILE_GENERIC_READ | FILE_WRITE_DATA, excludes FILE_CREATE_PIPE_INSTANCE
_OVERLAPPED = 0x40000000
_IDENTIFY_ONLY = 0x00110000  # SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
_LOG = logging.getLogger(__name__)


def _configuration(name, server_sid, client_sid, timeout):
    if (not isinstance(name, str) or not _NAME.fullmatch(name)
            or any(not isinstance(sid, str) or not _ACCOUNT_SID.fullmatch(sid)
                   for sid in (server_sid, client_sid))
            or server_sid == client_sid or type(timeout) not in (int, float)
            or not 0.25 <= timeout <= 10):
        raise ValueError("Explicit local authority pipe and distinct principals required")


def _native():
    if os.name != "nt":
        raise HeadUnavailable("authority_platform")
    import _winapi

    return _winapi


def _io_result(api, operation, deadline):
    remaining = max(0, int((deadline - monotonic()) * 1000))
    if api.WaitForSingleObject(operation.event, remaining) != api.WAIT_OBJECT_0:
        operation.cancel()
        operation.GetOverlappedResult(True)
        raise TimeoutError("authority_pipe_deadline")
    count, error = operation.GetOverlappedResult(False)
    if error:
        raise ctypes.WinError(error)
    return count


def _send(api, handle, data, deadline):
    operation, _ = api.WriteFile(handle, data, overlapped=True)
    if _io_result(api, operation, deadline) != len(data):
        raise OSError("authority_partial_write")


def _receive(api, handle, size, deadline):
    result = bytearray()
    while len(result) < size:
        operation, _ = api.ReadFile(handle, size - len(result), overlapped=True)
        count = _io_result(api, operation, deadline)
        if count == 0:
            raise EOFError("authority_disconnected")
        result.extend(operation.getbuffer())
    return bytes(result)


def _owner(kernel, advapi, handle):
    owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    error = advapi.GetSecurityInfo(handle, 1, 1, ctypes.byref(owner), None, None, None,
                                   ctypes.byref(descriptor))  # SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION
    if error:
        raise ctypes.WinError(error)
    try:
        return _sid_string(advapi, kernel.LocalFree, owner)
    finally:
        _free_local(kernel.LocalFree, descriptor)


def _peer_sid(kernel, advapi, pipe):
    def bind(dll, name, result, *args):
        function = getattr(dll, name)
        function.argtypes, function.restype = args, result
        return function

    impersonate = bind(advapi, "ImpersonateNamedPipeClient", W.BOOL, W.HANDLE)
    revert = bind(advapi, "RevertToSelf", W.BOOL)
    current = bind(kernel, "GetCurrentThread", W.HANDLE)
    open_token = bind(advapi, "OpenThreadToken", W.BOOL, W.HANDLE, W.DWORD, W.BOOL,
                      ctypes.POINTER(W.HANDLE))
    query = bind(advapi, "GetTokenInformation", W.BOOL, W.HANDLE, ctypes.c_int,
                 ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD))
    if not impersonate(pipe):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        token = W.HANDLE()
        if not open_token(current(), 0x0008, True, ctypes.byref(token)):  # TOKEN_QUERY
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            size = W.DWORD()
            query(token, 1, None, 0, ctypes.byref(size))  # TokenUser
            if not ctypes.sizeof(ctypes.c_void_p) <= size.value <= 4096:
                raise OSError("authority_invalid_token_size")
            buffer = ctypes.create_string_buffer(size.value)
            if not query(token, 1, buffer, size, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents
            return _sid_string(advapi, kernel.LocalFree, sid)
        finally:
            if not kernel.CloseHandle(token):
                raise OSError("authority_token_close")
    finally:
        if not revert():
            # Do not continue performing authority I/O on a borrowed token.
            raise RuntimeError("authority_revert_failed")


class PipeAuthorityClient:
    """A single read per bounded connection, authenticated before sending."""

    def __init__(self, name, *, server_sid, client_sid, timeout=2.0):
        _configuration(name, server_sid, client_sid, timeout)
        self._address = "\\\\.\\pipe\\" + name
        self._server_sid = server_sid
        self._timeout = timeout

    def read(self):
        return self._exchange(b"R")

    def advance(self, expected, candidate):
        raise HeadUnavailable("authority_read_only")

    def _exchange(self, operation):
        if type(operation) is not bytes or len(operation) != 1:
            raise ValueError("One bounded authority operation required")
        api = _native()
        kernel, advapi = _windows_apis()
        deadline = monotonic() + self._timeout
        try:
            while True:
                try:
                    handle = api.CreateFile(self._address, _CLIENT_ACCESS, 0, api.NULL,
                                            api.OPEN_EXISTING, _OVERLAPPED | _IDENTIFY_ONLY, api.NULL)
                    break
                except OSError as error:
                    if error.winerror != api.ERROR_PIPE_BUSY or monotonic() >= deadline:
                        raise
                    sleep(0.01)
            try:
                if _owner(kernel, advapi, handle) != self._server_sid:
                    raise HeadUnavailable("authority_wrong_owner")
                _send(api, handle, operation, deadline)
                status = _receive(api, handle, 1, deadline)
                if status == b"!":
                    _send(api, handle, b"A", deadline)
                    raise HeadUnavailable("authority_operation_refused")
                if status != b"H":
                    raise HeadUnavailable("authority_invalid_response")
                generation, revision, digest = _RESPONSE.unpack(_receive(api, handle, _RESPONSE.size, deadline))
                head = Head(UUID(bytes=generation), revision, digest)
                _send(api, handle, b"A", deadline)
                return head
            finally:
                api.CloseHandle(handle)
        except (OSError, EOFError, ValueError) as error:
            raise HeadUnavailable("authority_pipe_unavailable") from error


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", W.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", W.BOOL)]


@contextmanager
def authority_listener(name, *, server_sid, client_sid, registry, generation, timeout=2.0):
    """Serve only reads of one generation on an OS-restricted pipe."""
    _configuration(name, server_sid, client_sid, timeout)
    if type(generation) is not UUID or generation.int == 0:
        raise ValueError("Explicit enrolled generation required")
    api = _native()
    kernel, advapi = _windows_apis()
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [W.LPCWSTR, W.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = W.BOOL
    descriptor = ctypes.c_void_p()
    # The guest's enrolled high-integrity account may write protocol bytes
    # without acquiring server rights. Low/medium tokens remain blocked.
    sddl = f"O:{server_sid}D:P(A;;GA;;;{server_sid})(A;;0x{_CLIENT_ACCESS:x};;;{client_sid})S:(ML;;NW;;;HI)"
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        create = kernel.CreateNamedPipeW
        create.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD,
                           ctypes.POINTER(_SecurityAttributes)]
        create.restype = W.HANDLE
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        handle = create("\\\\.\\pipe\\" + name, 0x00080003 | _OVERLAPPED, 0x8,
                        1, 4096, 4096, 1000, ctypes.byref(attributes))
        if handle in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        _free_local(kernel.LocalFree, descriptor)

    def serve_one(accept_timeout):
        if type(accept_timeout) not in (float, int) or not 0.25 <= accept_timeout <= 10:
            raise ValueError("Finite accept deadline required")
        try:
            connection = api.ConnectNamedPipe(handle, overlapped=True)
            _io_result(api, connection, monotonic() + accept_timeout)
        except TimeoutError:
            return "idle"
        except OSError as error:
            if error.winerror != api.ERROR_NO_DATA:
                raise
            kernel.DisconnectNamedPipe.argtypes = [W.HANDLE]
            kernel.DisconnectNamedPipe.restype = W.BOOL
            if not kernel.DisconnectNamedPipe(handle):
                raise ctypes.WinError(ctypes.get_last_error())
            return "disconnected"
        try:
            deadline = monotonic() + timeout
            operation = _receive(api, handle, 1, deadline)
            if _peer_sid(kernel, advapi, handle) != client_sid or operation != b"R":
                _send(api, handle, b"!", deadline)
                return "denied" if _receive(api, handle, 1, deadline) == b"A" else "disconnected"
            head = registry.read()
            if type(head) is not Head or head.generation != generation:
                raise HeadUnavailable("authority_generation_mismatch")
            _send(api, handle, b"H" + _RESPONSE.pack(head.generation.bytes, head.revision, head.digest), deadline)
            return "read" if _receive(api, handle, 1, deadline) == b"A" else "disconnected"
        except (OSError, EOFError, HeadUnavailable) as error:
            _LOG.debug("Authority pipe closed: %s / %s", type(error).__name__, getattr(error, "winerror", None))
            return "disconnected"
        finally:
            kernel.DisconnectNamedPipe.argtypes = [W.HANDLE]
            kernel.DisconnectNamedPipe.restype = W.BOOL
            if not kernel.DisconnectNamedPipe(handle):
                raise ctypes.WinError(ctypes.get_last_error())

    try:
        if _owner(kernel, advapi, handle) != server_sid:
            raise HeadUnavailable("authority_wrong_listener_owner")
        yield serve_one
    finally:
        api.CloseHandle(handle)
