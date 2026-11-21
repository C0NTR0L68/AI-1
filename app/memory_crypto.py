"""Current-user Windows DPAPI helpers for Memory V2.

This module is deliberately not connected to storage or application startup.
"""
import ctypes
import os
from ctypes import wintypes


CRYPTPROTECT_UI_FORBIDDEN = 0x1
_MAX_PLAINTEXT_BYTES = 16 * 1024 * 1024
_MAX_CIPHERTEXT_BYTES = _MAX_PLAINTEXT_BYTES + 64 * 1024


class MemoryCryptoError(RuntimeError):
    """Redacted DPAPI failure with an operation category and optional Win32 code."""

    def __init__(self, operation: str, winerror: int | None = None):
        self.operation = operation
        self.winerror = winerror
        message = f"DPAPI {operation} failed"
        if winerror is not None:
            message += f" (Windows error {winerror})"
        super().__init__(message)


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    return int(getter()) if getter is not None else 0


def _load_apis():
    if os.name != "nt":
        raise MemoryCryptoError("unsupported_platform")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.POINTER(_DataBlob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return crypt32, kernel32


def _input_blob(data: bytes | bytearray | memoryview, limit: int):
    if type(data) not in (bytes, bytearray, memoryview):
        raise TypeError("DPAPI input must be bytes-like")
    if isinstance(data, memoryview) and not data.c_contiguous:
        raise ValueError("DPAPI input must be contiguous")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if size > limit:
        raise ValueError("DPAPI input exceeds the size limit")
    if isinstance(data, bytes):
        source = ctypes.c_char_p(data)
        pointer = ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte))
        return _DataBlob(size, pointer), (data, source)
    if size == 0:
        buffer = (ctypes.c_ubyte * 1)()
    else:
        buffer = (ctypes.c_ubyte * size).from_buffer_copy(data)
    blob = _DataBlob(size, ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    return blob, buffer


def _validated_output(blob: _DataBlob, limit: int) -> tuple[int | None, int]:
    size = blob.cbData
    address = ctypes.cast(blob.pbData, ctypes.c_void_p).value
    if (type(size) is not int or size < 0 or size > limit
            or (size and not address)):
        raise MemoryCryptoError("invalid_output")
    return address, size


def _copy_validated_output(address, size) -> bytes:
    if not size:
        return b""
    try:
        return ctypes.string_at(address, size)
    except (ValueError, OSError):
        raise MemoryCryptoError("invalid_output") from None


def _copy_output(blob: _DataBlob, limit: int) -> bytes:
    return _copy_validated_output(*_validated_output(blob, limit))


def _release_local(kernel32, pointer) -> None:
    if pointer:
        try:
            result = kernel32.LocalFree(pointer)
        except Exception:
            raise MemoryCryptoError("release") from None
        if result:
            raise MemoryCryptoError("release")


def _release_blob(kernel32, blob: _DataBlob) -> None:
    if type(blob) is not _DataBlob:
        raise MemoryCryptoError("invalid_output")
    pointer = ctypes.cast(blob.pbData, ctypes.c_void_p).value if blob.pbData else None
    blob.pbData = ctypes.POINTER(ctypes.c_ubyte)()
    blob.cbData = 0
    if pointer:
        _release_local(kernel32, pointer)


def _release_outputs(kernel32, output_blob: _DataBlob, description=None) -> None:
    release_error = False
    try:
        _release_blob(kernel32, output_blob)
    except MemoryCryptoError:
        release_error = True
    if description:
        try:
            _release_local(kernel32, ctypes.cast(description, ctypes.c_void_p))
        except MemoryCryptoError:
            release_error = True
    if release_error:
        raise MemoryCryptoError("release")


def _cleanup(kernel32, output_blob: _DataBlob, input_buffer, *, primary_error, description=None, plaintext=None) -> None:
    error = None
    for zero in (
        lambda: _wipe_input(input_buffer),
        lambda: ctypes.memset(plaintext[0], 0, plaintext[1]) if plaintext and plaintext[1] else None,
    ):
        try:
            zero()
        except Exception:
            if error is None:
                error = MemoryCryptoError("wipe")
    if kernel32 is not None:
        try:
            _release_outputs(kernel32, output_blob, description)
        except MemoryCryptoError as release:
            if error is None:
                error = release
    if error is not None and not primary_error:
        raise error from None


def _wipe_input(buffer) -> None:
    if isinstance(buffer, ctypes.Array):
        ctypes.memset(ctypes.addressof(buffer), 0, ctypes.sizeof(buffer))


def protect_for_current_user(data: bytes | bytearray | memoryview) -> bytes:
    """Encrypt bytes with the current user's DPAPI profile; never returns plaintext."""
    input_blob, input_buffer = _input_blob(data, _MAX_PLAINTEXT_BYTES)
    output_blob = _DataBlob()
    kernel32 = None
    primary_error = False
    try:
        crypt32, kernel32 = _load_apis()
        succeeded = crypt32.CryptProtectData(
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
        if not succeeded:
            raise MemoryCryptoError("protect", _last_error())
        return _copy_output(output_blob, _MAX_CIPHERTEXT_BYTES)
    except BaseException:
        primary_error = True
        raise
    finally:
        _cleanup(kernel32, output_blob, input_buffer, primary_error=primary_error)


def unprotect_for_current_user(data: bytes | bytearray | memoryview) -> bytes:
    """Decrypt with DPAPI; clear validated native output, not Python bytes."""
    input_blob, input_buffer = _input_blob(data, _MAX_CIPHERTEXT_BYTES)
    output_blob = _DataBlob()
    description = wintypes.LPWSTR()
    kernel32 = None
    plaintext = None
    primary_error = False
    try:
        crypt32, kernel32 = _load_apis()
        succeeded = crypt32.CryptUnprotectData(
            ctypes.byref(input_blob),
            ctypes.byref(description),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
        if not succeeded:
            raise MemoryCryptoError("unprotect", _last_error())
        # Successful DPAPI owns this byte buffer by the DATA_BLOB contract.
        # Snapshot once after validation; failed/malformed output is never
        # dereferenced for copying or wiping. LocalFree is still attempted.
        plaintext = _validated_output(output_blob, _MAX_PLAINTEXT_BYTES)
        return _copy_validated_output(*plaintext)
    except BaseException:
        primary_error = True
        raise
    finally:
        _cleanup(kernel32, output_blob, input_buffer, primary_error=primary_error,
                 description=description, plaintext=plaintext)
