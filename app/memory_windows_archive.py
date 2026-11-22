"""C7-v1 archive I/O in an explicitly pinned, private Windows namespace.

The owner/System are trusted for this namespace and the separate head registry.
The application does not provision or activate this boundary.
"""
from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes
import ntpath
from pathlib import Path

from app.memory_archive_publish_v2 import publish_archive, read_published_archive
from app.memory_storage_policy import FileIdentity
from app.windows_storage_inspector import (
    WindowsStorageInspectionError,
    _INVALID_HANDLE_VALUE,
    _FILE_FLAG_OPEN_REPARSE_POINT,
    _GENERIC_WRITE,
    _SID,
    _release_after,
    _validate_local_path,
    _windows_apis,
    hold_archive_directory,
    hold_component_evidence,
    inspect_component,
    read_pinned_artifact,
)


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                ("inherit_handle", wintypes.BOOL)]


@contextmanager
def _creation_security(kernel, advapi, owner_sid, *, directory=False):
    """Build an explicit protected DACL for a newly created object only."""
    if not _SID.fullmatch(owner_sid):
        raise ValueError("Explicit owner SID required")
    flags = "OICI" if directory else ""
    sddl = f"O:{owner_sid}D:P(A;{flags};FA;;;SY)(A;{flags};FA;;;{owner_sid})"
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise WindowsStorageInspectionError("private_descriptor")
    attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
    def release():
        if kernel.LocalFree(descriptor):
            raise WindowsStorageInspectionError("private_descriptor_release")
    with _release_after(release):
        yield ctypes.byref(attributes)


def _require_fixed_ntfs(drive):
    kernel, _ = _windows_apis()
    drive_type = kernel.GetDriveTypeW
    drive_type.argtypes = [wintypes.LPCWSTR]
    drive_type.restype = wintypes.UINT
    volume = kernel.GetVolumeInformationW
    volume.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                       wintypes.LPWSTR, wintypes.DWORD]
    volume.restype = wintypes.BOOL
    filesystem = ctypes.create_unicode_buffer(32)
    if (drive_type(drive) != 3  # DRIVE_FIXED
            or not volume(drive, None, 0, None, None, None, filesystem, len(filesystem))
            or filesystem.value != "NTFS"):
        raise WindowsStorageInspectionError("archive_volume")


def _create_private_file(path, data, owner_sid):
    kernel, advapi = _windows_apis()
    write = kernel.WriteFile
    write.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                      ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    write.restype = wintypes.BOOL
    flush = kernel.FlushFileBuffers
    flush.argtypes = [wintypes.HANDLE]
    flush.restype = wintypes.BOOL
    with _creation_security(kernel, advapi, owner_sid) as attributes:
        # No sharing and CREATE_NEW. Existing targets never get a write handle.
        handle = kernel.CreateFileW(str(path), _GENERIC_WRITE, 0, attributes, 1,
                                    _FILE_FLAG_OPEN_REPARSE_POINT, None)
        if handle in (None, _INVALID_HANDLE_VALUE):
            raise WindowsStorageInspectionError("archive_create")
        def release():
            if not kernel.CloseHandle(handle):
                raise WindowsStorageInspectionError("archive_close")
        with _release_after(release):
            written = wintypes.DWORD()
            if (not write(handle, data, len(data), ctypes.byref(written), None)
                    or written.value != len(data) or not flush(handle)):
                raise WindowsStorageInspectionError("archive_write")


class PrivateArchiveDirectory:
    """Use independently enrolled ancestor identities, and inspect each open."""

    def __init__(self, path, *, owner_sid, ancestors):
        _validate_local_path(path)
        drive, tail = ntpath.splitdrive(path)
        parts = tail[1:].split("\\")
        if (not tail[1:] or not isinstance(owner_sid, str) or not _SID.fullmatch(owner_sid)
                or type(ancestors) is not tuple or len(ancestors) != len(parts) + 1
                or any(type(item) is not FileIdentity or type(item.native_id) is not bytes
                       or len(item.native_id) != 16 or not any(item.native_id) for item in ancestors)
                or len(set(ancestors)) != len(ancestors)
                or len({item.volume for item in ancestors}) != 1):
            raise WindowsStorageInspectionError("archive_pins")
        names = [drive + "\\"]
        for part in parts:
            names.append(ntpath.join(names[-1], part))
        self._names = tuple(names)
        self._directory = Path(path)
        self._owner_sid = owner_sid
        self._ancestors = ancestors

    @contextmanager
    def hold(self, path):
        if path != self._directory:
            raise WindowsStorageInspectionError("archive_directory")
        _require_fixed_ntfs(self._names[0])
        with ExitStack() as stack:
            for name, expected in zip(self._names[:-1], self._ancestors[:-1]):
                held = stack.enter_context(hold_component_evidence(name, expected_kind="directory"))
                if held.identity != expected:
                    raise WindowsStorageInspectionError("archive_ancestor_identity")
            held = stack.enter_context(hold_archive_directory(
                self._names[-1], owner_sid=self._owner_sid, require_private_acl=True))
            if held.identity != self._ancestors[-1] or held.untrusted_mutation is not False:
                raise WindowsStorageInspectionError("archive_directory_identity")
            yield

    def _read_bound(self, path, limit):
        if path.parent != self._directory:
            raise WindowsStorageInspectionError("archive_directory")
        evidence = inspect_component(str(path), expected_kind="file",
                                     owner_sid=self._owner_sid, require_private_acl=True)
        if evidence.identity.volume != self._ancestors[-1].volume:
            raise WindowsStorageInspectionError("archive_volume")
        return read_pinned_artifact(str(path), expected=evidence, max_bytes=limit)

    def read(self, fingerprint):
        return read_published_archive(self._directory, fingerprint=fingerprint,
                                      hold_directory=self.hold, read_bound=self._read_bound)

    def publish(self, archive):
        return publish_archive(archive, self._directory, hold_directory=self.hold,
                               read_bound=self._read_bound,
                               write_pending=lambda path, data: _create_private_file(path, data, self._owner_sid))
