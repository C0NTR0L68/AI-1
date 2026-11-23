"""Read-only Windows handle inspection for the disabled Memory V2 storage path.

Evidence is a snapshot, not an authorization token: callers must still evaluate
it with the C7 policy and must not open the database through this module.
"""
import ctypes
from contextlib import ExitStack, contextmanager
import ntpath
import os
import re
from ctypes import wintypes

from app.memory_storage_policy import FileIdentity, HandleEvidence, MEMORY_PATH, evaluate_existing_notes


_SID = re.compile(r"S-1-5-21(?:-(?:0|[1-9][0-9]{0,9})){4}\Z")
_SERVICE_OWNER_SID = re.compile(r"S-1-5-80(?:-(?:0|[1-9][0-9]{0,9})){5}\Z")


def _valid_storage_owner(owner_sid, allow_service_owner=False):
    return (type(owner_sid) is str and
            (_SID.fullmatch(owner_sid) is not None or (allow_service_owner is True
             and _SERVICE_OWNER_SID.fullmatch(owner_sid) is not None)))
_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³])\Z", re.IGNORECASE)
_SYSTEM_SID = "S-1-5-18"

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_GENERIC_EXECUTE = 0x20000000
_GENERIC_ALL = 0x10000000
_STANDARD_RIGHTS_REQUIRED = 0x000F0000
_SYNCHRONIZE = 0x00100000
_FILE_ALL_ACCESS = _STANDARD_RIGHTS_REQUIRED | _SYNCHRONIZE | 0x1FF
_FILE_GENERIC_READ = 0x00020000 | 0x00000001 | 0x00000008 | 0x00000080 | _SYNCHRONIZE
_FILE_GENERIC_WRITE = 0x00020000 | 0x00000002 | 0x00000004 | 0x00000010 | 0x00000100 | _SYNCHRONIZE
_FILE_GENERIC_EXECUTE = 0x00020000 | 0x00000020 | 0x00000080 | _SYNCHRONIZE
_MUTATING_RIGHTS = (
    0x00000002 | 0x00000004 | 0x00000010 | 0x00000040 | 0x00000100
    | 0x00010000 | 0x00040000 | 0x00080000
)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_READ_DATA_OR_LIST_DIRECTORY = 0x00000001
_READ_CONTROL = 0x00020000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_FILE_STANDARD_INFO_CLASS = 1
_FILE_ID_INFO_CLASS = 18
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_SE_DACL_PROTECTED = 0x1000
_ACCESS_ALLOWED_ACE_TYPE = 0
_INHERITED_ACE = 0x10
_OBJECT_AND_CONTAINER_INHERIT = 0x03
_ACL_SIZE_INFORMATION = 2
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class WindowsStorageInspectionError(PermissionError):
    """Stable failure reason without exposing paths, SIDs, or ACL contents."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]


class _FileId128(ctypes.Structure):
    _fields_ = [("Identifier", ctypes.c_ubyte * 16)]


class _FileIdInfo(ctypes.Structure):
    _fields_ = [("VolumeSerialNumber", ctypes.c_ulonglong), ("FileId", _FileId128)]


class _FileStandardInfo(ctypes.Structure):
    _fields_ = [
        ("AllocationSize", ctypes.c_longlong),
        ("EndOfFile", ctypes.c_longlong),
        ("NumberOfLinks", wintypes.DWORD),
        ("DeletePending", ctypes.c_ubyte),
        ("Directory", ctypes.c_ubyte),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", ctypes.c_ubyte),
        ("AceFlags", ctypes.c_ubyte),
        ("AceSize", wintypes.WORD),
    ]


class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [("Header", _AceHeader), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


class _GenericMapping(ctypes.Structure):
    _fields_ = [
        ("GenericRead", wintypes.DWORD),
        ("GenericWrite", wintypes.DWORD),
        ("GenericExecute", wintypes.DWORD),
        ("GenericAll", wintypes.DWORD),
    ]


def _validate_local_path(path: str) -> None:
    if (type(path) is not str or not path or len(path) > 32760 or "\x00" in path
            or "/" in path or any(ord(char) < 32 for char in path)):
        raise WindowsStorageInspectionError("path")
    drive, tail = ntpath.splitdrive(path)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith("\\"):
        raise WindowsStorageInspectionError("path")
    if tail == "\\":
        return
    for component in tail[1:].split("\\"):
        stem = component.split(".", 1)[0].rstrip(" ")
        if (not component or component.endswith((" ", "."))
                or any(char in '<>:"|?*' for char in component) or _DEVICE.fullmatch(stem)):
            raise WindowsStorageInspectionError("path")


def _windows_apis():
    if os.name != "nt":
        raise WindowsStorageInspectionError("platform")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ]
    kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.MapGenericMask.argtypes = [
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(_GenericMapping),
    ]
    advapi32.MapGenericMask.restype = None
    return kernel32, advapi32


def _final_path(kernel32, handle, volume_name_flag: int) -> str:
    capacity = 260
    while capacity <= 32760:
        buffer = ctypes.create_unicode_buffer(capacity)
        length = kernel32.GetFinalPathNameByHandleW(handle, buffer, capacity, volume_name_flag)
        if length == 0:
            raise WindowsStorageInspectionError("final_path")
        if length < capacity:
            return buffer.value
        capacity = length + 1
    raise WindowsStorageInspectionError("final_path")


def _strip_extended_prefix(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    raise WindowsStorageInspectionError("final_path")


def _sid_string(advapi32, local_free, sid) -> str:
    value = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(value)):
        raise WindowsStorageInspectionError("sid")
    with _release_after(lambda: _free_local(local_free, ctypes.cast(value, ctypes.c_void_p))):
        return value.value or ""


def _free_local(local_free, allocation) -> None:
    if allocation and local_free(allocation):
        raise WindowsStorageInspectionError("release")


@contextmanager
def _release_after(release):
    primary_error = False
    try:
        yield
    except BaseException:
        primary_error = True
        raise
    finally:
        try:
            release()
        except Exception:
            if not primary_error:
                raise WindowsStorageInspectionError("release") from None


def _map_access_mask(advapi32, raw_mask: int) -> int | None:
    mask = wintypes.DWORD(raw_mask)
    mapping = _GenericMapping(
        _FILE_GENERIC_READ,
        _FILE_GENERIC_WRITE,
        _FILE_GENERIC_EXECUTE,
        _FILE_ALL_ACCESS,
    )
    advapi32.MapGenericMask(ctypes.byref(mask), ctypes.byref(mapping))
    if mask.value & ~_FILE_ALL_ACCESS:
        return None
    return mask.value


def _read_acl(kernel32, advapi32, handle, expected_owner_sid: str | None, kind: str):
    owner_ptr = ctypes.c_void_p()
    dacl_ptr = ctypes.c_void_p()
    descriptor_ptr = ctypes.c_void_p()
    result = advapi32.GetSecurityInfo(
        handle,
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner_ptr),
        None,
        ctypes.byref(dacl_ptr),
        None,
        ctypes.byref(descriptor_ptr),
    )
    with _release_after(lambda: _free_local(kernel32.LocalFree, descriptor_ptr.value)):
        if result != 0:
            raise WindowsStorageInspectionError("acl")
        owner = _sid_string(advapi32, kernel32.LocalFree, owner_ptr) if owner_ptr.value else None
        if not descriptor_ptr.value:
            return owner, None, None, False

        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor_ptr, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            return owner, None, None, False
        if not present.value or not dacl.value:
            return owner, None, True, False

        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor_ptr, ctypes.byref(control), ctypes.byref(revision)
        ):
            return owner, None, None, False
        protected = bool(control.value & _SE_DACL_PROTECTED)

        acl_info = _AclSizeInformation()
        if not advapi32.GetAclInformation(
            dacl, ctypes.byref(acl_info), ctypes.sizeof(acl_info), _ACL_SIZE_INFORMATION
        ):
            return owner, None, None, False

        principals = set()
        entries = []
        detected_untrusted_mutation = False
        for index in range(acl_info.AceCount):
            ace_ptr = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace_ptr)) or not ace_ptr.value:
                return owner, None, None, False
            header = ctypes.cast(ace_ptr, ctypes.POINTER(_AceHeader)).contents
            if header.AceType != _ACCESS_ALLOWED_ACE_TYPE or header.AceSize < ctypes.sizeof(_AccessAllowedAce):
                return owner, None, None, False
            ace = ctypes.cast(ace_ptr, ctypes.POINTER(_AccessAllowedAce)).contents
            sid_ptr = ctypes.c_void_p(ace_ptr.value + _AccessAllowedAce.SidStart.offset)
            principal = _sid_string(advapi32, kernel32.LocalFree, sid_ptr)
            mask = _map_access_mask(advapi32, ace.Mask)
            if mask is None:
                return owner, None, None, False
            principals.add(principal)
            entries.append((principal, mask, header.AceFlags))
            if principal not in (expected_owner_sid, _SYSTEM_SID) and mask & _MUTATING_RIGHTS:
                detected_untrusted_mutation = True

        private_principals = frozenset(principals)
        owner_can_change_acl = (
            owner is not None and owner not in (expected_owner_sid, _SYSTEM_SID)
        )
        if detected_untrusted_mutation or owner_can_change_acl:
            untrusted_mutation = True
        elif expected_owner_sid is None or owner is None:
            untrusted_mutation = None
        else:
            untrusted_mutation = False
        strict_private_acl = (
            owner is not None
            and expected_owner_sid == owner
            and protected
            and len(entries) == 2
            and private_principals == frozenset((owner, _SYSTEM_SID))
            and all(
                principal in (owner, _SYSTEM_SID)
                and mask == _FILE_ALL_ACCESS
                and not (flags & _INHERITED_ACE)
                and flags == (_OBJECT_AND_CONTAINER_INHERIT if kind == "directory" else 0)
                for principal, mask, flags in entries
            )
        )
        return owner, private_principals, untrusted_mutation, strict_private_acl


def inspect_component(
    path: str,
    *,
    expected_kind: str,
    owner_sid: str | None = None,
    require_private_acl: bool = False,
    allow_service_owner: bool = False,
) -> HandleEvidence:
    """Return a snapshot; no handle or authorization survives this call."""
    with _component(path, expected_kind=expected_kind, owner_sid=owner_sid,
                    require_private_acl=require_private_acl, pinned=False,
                    allow_service_owner=allow_service_owner) as evidence:
        return evidence


def hold_component_evidence(path, *, expected_kind, owner_sid=None, require_private_acl=False):
    """Read-only evidence with the component open without delete sharing."""
    return _component(path, expected_kind=expected_kind, owner_sid=owner_sid,
                      require_private_acl=require_private_acl, pinned=True)


def hold_archive_directory(path, *, owner_sid=None, require_private_acl=True, allow_service_owner=False):
    """Pin the directory against deletion while permitting child publication.

    Windows needs write sharing on this directory for rename of its children.
    The caller must independently exclude other writers for that duration.
    The ordinary C7 inspection keeps its more restrictive share mode.
    """
    return _component(path, expected_kind="directory", owner_sid=owner_sid,
                      require_private_acl=require_private_acl, pinned=True, publish_children=True,
                      allow_service_owner=allow_service_owner)


@contextmanager
def _component(path, *, expected_kind, owner_sid, require_private_acl, pinned,
               include_handle=False, publish_children=False, allow_service_owner=False):
    _validate_local_path(path)
    if expected_kind not in ("file", "directory"):
        raise WindowsStorageInspectionError("kind")
    if type(require_private_acl) is not bool:
        raise WindowsStorageInspectionError("acl")
    if owner_sid is not None and not _valid_storage_owner(owner_sid, allow_service_owner):
        raise WindowsStorageInspectionError("owner")
    if require_private_acl and owner_sid is None:
        raise WindowsStorageInspectionError("owner")

    kernel32, advapi32 = _windows_apis()
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if expected_kind == "directory":
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    share = _FILE_SHARE_READ
    if not pinned:
        share |= _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
    elif publish_children:
        share |= _FILE_SHARE_WRITE
    handle = kernel32.CreateFileW(
        path,
        _FILE_READ_ATTRIBUTES | _READ_CONTROL | (_FILE_READ_DATA_OR_LIST_DIRECTORY if pinned else 0),
        share,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE or handle is None:
        raise WindowsStorageInspectionError("open")
    def close():
        if not kernel32.CloseHandle(handle):
            raise WindowsStorageInspectionError("release")

    with _release_after(close):
        attributes = _FileAttributeTagInfo()
        if not kernel32.GetFileInformationByHandleEx(
            handle, _FILE_ATTRIBUTE_TAG_INFO_CLASS, ctypes.byref(attributes), ctypes.sizeof(attributes)
        ):
            raise WindowsStorageInspectionError("attributes")
        is_reparse = bool(attributes.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT)
        if is_reparse:
            raise WindowsStorageInspectionError("reparse")

        standard = _FileStandardInfo()
        identity_info = _FileIdInfo()
        if not kernel32.GetFileInformationByHandleEx(
            handle, _FILE_STANDARD_INFO_CLASS, ctypes.byref(standard), ctypes.sizeof(standard)
        ):
            raise WindowsStorageInspectionError("links")
        if not kernel32.GetFileInformationByHandleEx(
            handle, _FILE_ID_INFO_CLASS, ctypes.byref(identity_info), ctypes.sizeof(identity_info)
        ):
            raise WindowsStorageInspectionError("identity")
        if standard.DeletePending:
            raise WindowsStorageInspectionError("delete_pending")
        actual_kind = "directory" if standard.Directory else "file"
        if actual_kind != expected_kind:
            raise WindowsStorageInspectionError("kind")

        final_path_raw = _final_path(kernel32, handle, 0)
        volume_path_raw = _final_path(kernel32, handle, 1)
        final_path = _strip_extended_prefix(final_path_raw)
        volume_end = volume_path_raw.find("}\\")
        if not volume_path_raw.startswith("\\\\?\\Volume{") or volume_end < 0:
            raise WindowsStorageInspectionError("volume")
        volume = volume_path_raw[:volume_end + 1]
        if (ntpath.normcase(ntpath.normpath(final_path))
                != ntpath.normcase(ntpath.normpath(path))):
            raise WindowsStorageInspectionError("final_path")

        native_id = bytes(identity_info.FileId.Identifier)
        if not any(native_id):
            raise WindowsStorageInspectionError("identity")
        identity = FileIdentity(volume, native_id)
        owner, principals, untrusted_mutation, strict_private_acl = _read_acl(
            kernel32, advapi32, handle, owner_sid, actual_kind
        )
        if require_private_acl and not strict_private_acl:
            raise WindowsStorageInspectionError("private_acl")
        evidence = HandleEvidence(
            final_path=path,
            kind=actual_kind,
            identity=identity,
            reparse=False,
            untrusted_mutation=untrusted_mutation,
            owner=owner,
            # A list of principals alone is not proof of a private ACL.
            private_acl_principals=principals if strict_private_acl else None,
            links=int(standard.NumberOfLinks),
        )
        yield (evidence, kernel32, handle, standard.EndOfFile) if include_handle else evidence


def read_pinned_artifact(path, *, expected, max_bytes, require_private_acl=True, allow_service_owner=False):
    """Read an existing artifact through the exact native handle inspected.

    The caller supplies an independently admitted file identity and must hold a
    trusted namespace. This does not authorize a SQLite filename or publication.
    The false ACL option exists for a synthetic Windows fixture only.
    """
    if (type(expected) is not HandleEvidence or expected.kind != "file"
            or expected.final_path != path or expected.links != 1 or expected.reparse is not False
            or type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024
            or type(require_private_acl) is not bool):
        raise WindowsStorageInspectionError("artifact_input")
    with _component(path, expected_kind="file", owner_sid=expected.owner if require_private_acl else None,
                    require_private_acl=require_private_acl, pinned=True, include_handle=True,
                    allow_service_owner=allow_service_owner) as opened:
        evidence, kernel, handle, size = opened
        if (evidence.identity != expected.identity or evidence.links != 1
                or require_private_acl and (evidence.owner != expected.owner or evidence.untrusted_mutation is not False)):
            raise WindowsStorageInspectionError("artifact_identity")
        if not 0 < size <= max_bytes:
            raise WindowsStorageInspectionError("artifact_size")
        read = kernel.ReadFile
        read.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        read.restype = wintypes.BOOL
        output = (ctypes.c_ubyte * size)()
        received = wintypes.DWORD()
        if not read(handle, output, size, ctypes.byref(received), None) or received.value != size:
            raise WindowsStorageInspectionError("artifact_read")
        extra = ctypes.c_ubyte()
        if not read(handle, ctypes.byref(extra), 1, ctypes.byref(received), None) or received.value:
            raise WindowsStorageInspectionError("artifact_read")
        return bytes(output)


def _sidecars_absent(path):
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            os.lstat(path + suffix)
        except FileNotFoundError:
            continue
        return False
    return True


def inspect_memory_chain(*, owner_sid, observed_volume, pinned_volume, fixed_local_ntfs, protected_identities):
    """Read-only C7 diagnostic, intentionally returns no storage authority.

    Volume/SID and protected identities must independently come from deployment
    inventory. This does not prove SQLite subsequently opens these handles.
    """
    if (fixed_local_ntfs is not True or type(pinned_volume) is not str or not pinned_volume
            or observed_volume != pinned_volume or type(owner_sid) is not str or not _SID.fullmatch(owner_sid)
            or type(protected_identities) is not frozenset or not protected_identities):
        raise WindowsStorageInspectionError("chain_prerequisite")
    drive, tail = ntpath.splitdrive(MEMORY_PATH)
    path = drive + "\\"
    paths = [path]
    for part in tail[1:].split("\\"):
        path = ntpath.join(path, part)
        paths.append(path)
    with ExitStack() as stack:
        evidence = []
        for i, name in enumerate(paths):
            item = stack.enter_context(hold_component_evidence(
                name, expected_kind="file" if i == len(paths) - 1 else "directory",
                owner_sid=owner_sid, require_private_acl=i >= len(paths) - 2,
            ))
            if (item.reparse is not False or item.untrusted_mutation is not False
                    or item.identity.volume != observed_volume or item.final_path != name):
                raise WindowsStorageInspectionError("chain_component")
            evidence.append(item)
        try:
            absent = _sidecars_absent(MEMORY_PATH)
        except OSError as error:
            raise WindowsStorageInspectionError("sidecars") from error
        evaluate_existing_notes(path=MEMORY_PATH, owner_sid=owner_sid, observed_volume=observed_volume,
                                pinned_volume=pinned_volume, fixed_local_ntfs=fixed_local_ntfs,
                                chain=tuple(evidence), protected_identities=protected_identities, sidecars_absent=absent)
