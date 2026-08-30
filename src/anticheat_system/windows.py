"""Read-only Windows backend for the portable observation contract.

This module is separate from ``scripts/live_capture.py``. It never sends device
IOCTLs, reads or writes target bytes, allocates target memory, injects code,
changes privileges, or modifies process/kernel state.
"""

from __future__ import annotations

import collections
import ctypes
import ctypes.wintypes as wt
import datetime as dt
import hashlib
import importlib
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

from .contract import validate_snapshot_contract
from .errors import (
    AmbiguousTargetError,
    InconsistentSnapshotError,
    TargetAccessDeniedError,
    TargetNotFoundError,
    UnsupportedPlatformError,
    classify_os_error,
    unavailable,
)
from .signals import derive_signals, summarize_signals

PROCESS_QUERY_INFORMATION = 0x00000400
PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
SYNCHRONIZE = 0x00100000
TOKEN_QUERY = 0x0008
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
ERROR_ACCESS_DENIED = 5
ERROR_NO_MORE_FILES = 18
ERROR_BAD_LENGTH = 24
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_PARTIAL_COPY = 299
ERROR_CALL_NOT_IMPLEMENTED = 120
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MAX_PATH = 260
MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
MAX_MEMORY_REGIONS = 1_000_000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
SYSTEM_CODEINTEGRITY_INFORMATION_CLASS = 103

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_FREE = 0x00010000
MEM_PRIVATE = 0x00020000
MEM_MAPPED = 0x00040000
MEM_IMAGE = 0x01000000
PAGE_GUARD = 0x00000100
PAGE_NOCACHE = 0x00000200
PAGE_WRITECOMBINE = 0x00000400

_EXECUTABLE_PROTECTIONS = {0x10, 0x20, 0x40, 0x80}
_WRITABLE_EXECUTABLE_PROTECTIONS = {0x40, 0x80}

_MACHINE_NAMES = {
    0x0000: "unknown",
    0x014C: "x86",
    0x01C0: "arm",
    0x01C4: "armv7-thumb2",
    0x8664: "x86_64",
    0xAA64: "arm64",
}

_PROTECTION_LEVEL_NAMES = {
    0x00000000: "wintcb-light",
    0x00000001: "windows",
    0x00000002: "windows-light",
    0x00000003: "antimalware-light",
    0x00000004: "lsa-light",
    0x00000005: "wintcb",
    0x00000006: "codegen-light",
    0x00000007: "authenticode",
    0x00000008: "ppl-app",
    0xFFFFFFFE: "none",
}

_CODE_INTEGRITY_FLAGS = {
    0x0001: "kernel_mode_enabled",
    0x0002: "test_signing_allowed",
    0x0004: "user_mode_enabled",
    0x0008: "user_mode_audit",
    0x0010: "user_mode_exclusion_paths",
    0x0020: "test_build",
    0x0040: "preproduction_build",
    0x0080: "debug_mode",
    0x0100: "flight_build",
    0x0200: "flighting_enabled",
    0x0400: "hvci_kernel_mode_enabled",
    0x0800: "hvci_kernel_mode_audit",
    0x1000: "hvci_kernel_mode_strict",
    0x2000: "hvci_isolated_user_mode",
}


class FILETIME(ctypes.Structure):
    _fields_ = [("low", wt.DWORD), ("high", wt.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", wt.WCHAR * 256),
        ("szExePath", wt.WCHAR * MAX_PATH),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


class PROCESS_PROTECTION_LEVEL_INFORMATION(ctypes.Structure):
    _fields_ = [("ProtectionLevel", wt.DWORD)]


class PROCESS_MACHINE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ProcessMachine", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("MachineAttributes", wt.DWORD),
    ]


class SYSTEM_CODEINTEGRITY_INFORMATION(ctypes.Structure):
    _fields_ = [("Length", wt.ULONG), ("CodeIntegrityOptions", wt.ULONG)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]


class DEP_POLICY(ctypes.Structure):
    _fields_ = [("Flags", wt.DWORD), ("Permanent", wt.BOOL)]


class DWORD_POLICY(ctypes.Structure):
    _fields_ = [("Flags", wt.DWORD)]


def _load_dll(name: str) -> Any | None:
    factory = getattr(ctypes, "WinDLL", None)
    return factory(name, use_last_error=True) if factory is not None else None


_kernel32 = _load_dll("kernel32")
_advapi32 = _load_dll("advapi32")
_ntdll = _load_dll("ntdll")


def _bind(dll: Any | None, name: str, argtypes: list[Any], restype: Any) -> Any | None:
    if dll is None:
        return None
    function = getattr(dll, name, None)
    if function is None:
        return None
    function.argtypes = argtypes
    function.restype = restype
    return function


_OpenProcess = _bind(
    _kernel32, "OpenProcess", [wt.DWORD, wt.BOOL, wt.DWORD], ctypes.c_void_p
)
_CloseHandle = _bind(_kernel32, "CloseHandle", [ctypes.c_void_p], wt.BOOL)
_GetProcessId = _bind(_kernel32, "GetProcessId", [ctypes.c_void_p], wt.DWORD)
_WaitForSingleObject = _bind(
    _kernel32, "WaitForSingleObject", [ctypes.c_void_p, wt.DWORD], wt.DWORD
)
_GetProcessTimes = _bind(
    _kernel32,
    "GetProcessTimes",
    [
        ctypes.c_void_p,
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
    ],
    wt.BOOL,
)
_QueryFullProcessImageNameW = _bind(
    _kernel32,
    "QueryFullProcessImageNameW",
    [ctypes.c_void_p, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)],
    wt.BOOL,
)
_GetProcessHandleCount = _bind(
    _kernel32,
    "GetProcessHandleCount",
    [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)],
    wt.BOOL,
)
_CheckRemoteDebuggerPresent = _bind(
    _kernel32,
    "CheckRemoteDebuggerPresent",
    [ctypes.c_void_p, ctypes.POINTER(wt.BOOL)],
    wt.BOOL,
)
_IsWow64Process2 = _bind(
    _kernel32,
    "IsWow64Process2",
    [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ushort),
        ctypes.POINTER(ctypes.c_ushort),
    ],
    wt.BOOL,
)
_GetProcessInformation = _bind(
    _kernel32,
    "GetProcessInformation",
    [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wt.DWORD],
    wt.BOOL,
)
_GetProcessMitigationPolicy = _bind(
    _kernel32,
    "GetProcessMitigationPolicy",
    [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t],
    wt.BOOL,
)
_VirtualQueryEx = _bind(
    _kernel32,
    "VirtualQueryEx",
    [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ],
    ctypes.c_size_t,
)
_CreateToolhelp32Snapshot = _bind(
    _kernel32,
    "CreateToolhelp32Snapshot",
    [wt.DWORD, wt.DWORD],
    ctypes.c_void_p,
)
_Process32FirstW = _bind(
    _kernel32,
    "Process32FirstW",
    [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)],
    wt.BOOL,
)
_Process32NextW = _bind(
    _kernel32,
    "Process32NextW",
    [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)],
    wt.BOOL,
)
_Module32FirstW = _bind(
    _kernel32,
    "Module32FirstW",
    [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32W)],
    wt.BOOL,
)
_Module32NextW = _bind(
    _kernel32,
    "Module32NextW",
    [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32W)],
    wt.BOOL,
)
_GetFirmwareType = _bind(
    _kernel32, "GetFirmwareType", [ctypes.POINTER(wt.DWORD)], wt.BOOL
)
_GetSystemDEPPolicy = _bind(_kernel32, "GetSystemDEPPolicy", [], wt.DWORD)
_OpenProcessToken = _bind(
    _advapi32,
    "OpenProcessToken",
    [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(ctypes.c_void_p)],
    wt.BOOL,
)
_GetTokenInformation = _bind(
    _advapi32,
    "GetTokenInformation",
    [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        wt.DWORD,
        ctypes.POINTER(wt.DWORD),
    ],
    wt.BOOL,
)
_IsValidSid = _bind(_advapi32, "IsValidSid", [ctypes.c_void_p], wt.BOOL)
_GetSidSubAuthorityCount = _bind(
    _advapi32,
    "GetSidSubAuthorityCount",
    [ctypes.c_void_p],
    ctypes.POINTER(ctypes.c_ubyte),
)
_GetSidSubAuthority = _bind(
    _advapi32,
    "GetSidSubAuthority",
    [ctypes.c_void_p, wt.DWORD],
    ctypes.POINTER(wt.DWORD),
)
_NtQuerySystemInformation = _bind(
    _ntdll,
    "NtQuerySystemInformation",
    [ctypes.c_int, ctypes.c_void_p, wt.ULONG, ctypes.POINTER(wt.ULONG)],
    ctypes.c_long,
)


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    return int(getter()) if getter is not None else 0


def _clear_last_error() -> None:
    setter = getattr(ctypes, "set_last_error", None)
    if setter is not None:
        setter(0)


def classify_windows_error(code: int) -> str:
    if code == ERROR_ACCESS_DENIED:
        return "permission_denied"
    if code in {ERROR_INVALID_PARAMETER, 87, 1168}:
        return "not_found_or_process_exited"
    if code == ERROR_PARTIAL_COPY:
        return "architecture_or_access_restricted"
    if code == ERROR_BAD_LENGTH:
        return "transient_snapshot_error"
    if code == ERROR_CALL_NOT_IMPLEMENTED:
        return "not_supported"
    return "win32_error"


def _require_windows() -> None:
    if os.name != "nt" or _kernel32 is None:
        raise UnsupportedPlatformError(platform.system())


def _close_handle(handle: int | None) -> None:
    if handle and _CloseHandle is not None:
        _CloseHandle(ctypes.c_void_p(handle))


def _open_process_raw(access: int, pid: int) -> int:
    if _OpenProcess is None:
        raise OSError(ERROR_CALL_NOT_IMPLEMENTED, "OpenProcess is unavailable")
    _clear_last_error()
    handle = _OpenProcess(access, False, pid)
    if not handle:
        code = _last_error()
        raise OSError(code, "OpenProcess failed")
    return int(handle)


def _filetime_value(value: FILETIME) -> int:
    return (int(value.high) << 32) | int(value.low)


@dataclass(slots=True)
class WindowsProcessHandle:
    pid: int
    handle: int
    synchronize_access: bool
    requested_access: int

    @classmethod
    def open(cls, pid: int) -> WindowsProcessHandle:
        _require_windows()
        last_error: OSError | None = None
        for access, synchronize_access in (
            (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, True),
            (PROCESS_QUERY_LIMITED_INFORMATION, False),
        ):
            try:
                handle = _open_process_raw(access, pid)
                process_id = int(_GetProcessId(handle)) if _GetProcessId else pid
                if process_id != pid:
                    _close_handle(handle)
                    raise InconsistentSnapshotError(
                        "Windows process handle did not match the requested PID"
                    )
                return cls(pid, handle, synchronize_access, access)
            except OSError as error:
                last_error = error
        assert last_error is not None
        raise last_error

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self.handle:
            _close_handle(self.handle)
            self.handle = 0

    def creation_time_100ns(self) -> int:
        if _GetProcessTimes is None:
            raise OSError(ERROR_CALL_NOT_IMPLEMENTED, "GetProcessTimes unavailable")
        creation, exit_time, kernel, user = (
            FILETIME(),
            FILETIME(),
            FILETIME(),
            FILETIME(),
        )
        _clear_last_error()
        if not _GetProcessTimes(
            self.handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise OSError(_last_error(), "GetProcessTimes failed")
        return _filetime_value(creation)

    def process_times(self) -> dict[str, int]:
        if _GetProcessTimes is None:
            raise OSError(ERROR_CALL_NOT_IMPLEMENTED, "GetProcessTimes unavailable")
        creation, exit_time, kernel, user = (
            FILETIME(),
            FILETIME(),
            FILETIME(),
            FILETIME(),
        )
        _clear_last_error()
        if not _GetProcessTimes(
            self.handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise OSError(_last_error(), "GetProcessTimes failed")
        return {
            "creation_time_100ns": _filetime_value(creation),
            "kernel_time_100ns": _filetime_value(kernel),
            "user_time_100ns": _filetime_value(user),
        }

    def image_path(self) -> str:
        if _QueryFullProcessImageNameW is None:
            raise OSError(
                ERROR_CALL_NOT_IMPLEMENTED, "QueryFullProcessImageNameW unavailable"
            )
        buffer = ctypes.create_unicode_buffer(32768)
        size = wt.DWORD(len(buffer))
        _clear_last_error()
        if not _QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(size)):
            raise OSError(_last_error(), "QueryFullProcessImageNameW failed")
        return buffer.value[: size.value]

    def alive(self) -> bool | None:
        if not self.synchronize_access or _WaitForSingleObject is None:
            return None
        result = int(_WaitForSingleObject(self.handle, 0))
        if result == WAIT_TIMEOUT:
            return True
        if result == WAIT_OBJECT_0:
            return False
        raise OSError(_last_error(), "WaitForSingleObject failed")


def _process_entries() -> list[dict[str, Any]]:
    if (
        _CreateToolhelp32Snapshot is None
        or _Process32FirstW is None
        or _Process32NextW is None
    ):
        raise OSError(ERROR_CALL_NOT_IMPLEMENTED, "Tool Help process APIs unavailable")
    _clear_last_error()
    raw = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    handle = int(raw) if raw else 0
    if not handle or handle == INVALID_HANDLE_VALUE:
        raise OSError(_last_error(), "process snapshot failed")
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not _Process32FirstW(handle, ctypes.byref(entry)):
            raise OSError(_last_error(), "Process32FirstW failed")
        values: list[dict[str, Any]] = []
        while True:
            values.append(
                {
                    "pid": int(entry.th32ProcessID),
                    "parent_pid": int(entry.th32ParentProcessID),
                    "thread_count": int(entry.cntThreads),
                    "name": str(entry.szExeFile),
                }
            )
            entry.dwSize = ctypes.sizeof(entry)
            if not _Process32NextW(handle, ctypes.byref(entry)):
                code = _last_error()
                if code not in {0, ERROR_NO_MORE_FILES}:
                    raise OSError(code, "Process32NextW failed")
                break
        return values
    finally:
        _close_handle(handle)


def _entry_for_pid(pid: int) -> dict[str, Any] | None:
    return next((entry for entry in _process_entries() if entry["pid"] == pid), None)


def _hash_path(path: str, *, limit: int = MAX_EXECUTABLE_BYTES) -> dict[str, Any]:
    try:
        with Path(path).open("rb", buffering=0) as stream:
            size = os.fstat(stream.fileno()).st_size
            if size > limit:
                return unavailable("size_limit_exceeded")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    return unavailable("size_limit_exceeded")
                digest.update(chunk)
            return {
                "status": "observed",
                "sha256": digest.hexdigest(),
                "size_bytes": total,
                "identity_basis": "path-opened-file",
            }
    except OSError as error:
        return unavailable(classify_os_error(error))


def _query_debugger(handle: int) -> dict[str, Any]:
    if _CheckRemoteDebuggerPresent is None:
        return unavailable("not_supported")
    present = wt.BOOL()
    _clear_last_error()
    if not _CheckRemoteDebuggerPresent(handle, ctypes.byref(present)):
        return unavailable(classify_windows_error(_last_error()))
    return {"status": "observed", "present": bool(present.value)}


def _query_handle_count(handle: int) -> dict[str, Any]:
    if _GetProcessHandleCount is None:
        return unavailable("not_supported")
    count = wt.DWORD()
    _clear_last_error()
    if not _GetProcessHandleCount(handle, ctypes.byref(count)):
        return unavailable(classify_windows_error(_last_error()))
    return {"status": "observed", "count": int(count.value)}


def _query_architecture(handle: int) -> dict[str, Any]:
    machine_info: dict[str, Any] | None = None
    if _GetProcessInformation is not None:
        value = PROCESS_MACHINE_INFORMATION()
        _clear_last_error()
        if _GetProcessInformation(handle, 9, ctypes.byref(value), ctypes.sizeof(value)):
            machine_info = {
                "machine": int(value.ProcessMachine),
                "attributes_mask": f"0x{int(value.MachineAttributes):08x}",
            }

    if _IsWow64Process2 is None:
        if machine_info is None:
            return unavailable("not_supported")
        machine = machine_info["machine"]
        return {
            "status": "observed",
            "process_machine": _MACHINE_NAMES.get(machine, f"0x{machine:04x}"),
            "process_machine_raw": f"0x{machine:04x}",
            "machine_attributes_mask": machine_info["attributes_mask"],
            "wow64": None,
        }

    process_machine = ctypes.c_ushort()
    native_machine = ctypes.c_ushort()
    _clear_last_error()
    if not _IsWow64Process2(
        handle, ctypes.byref(process_machine), ctypes.byref(native_machine)
    ):
        return unavailable(classify_windows_error(_last_error()))
    actual_machine = (
        machine_info["machine"]
        if machine_info is not None and machine_info["machine"]
        else process_machine.value or native_machine.value
    )
    result = {
        "status": "observed",
        "process_machine": _MACHINE_NAMES.get(
            actual_machine, f"0x{actual_machine:04x}"
        ),
        "process_machine_raw": f"0x{actual_machine:04x}",
        "native_machine": _MACHINE_NAMES.get(
            native_machine.value, f"0x{native_machine.value:04x}"
        ),
        "native_machine_raw": f"0x{native_machine.value:04x}",
        "wow64": process_machine.value != 0,
    }
    if machine_info is not None:
        result["machine_attributes_mask"] = machine_info["attributes_mask"]
    return result


def _query_protection_level(handle: int) -> dict[str, Any]:
    if _GetProcessInformation is None:
        return unavailable("not_supported")
    value = PROCESS_PROTECTION_LEVEL_INFORMATION()
    _clear_last_error()
    if not _GetProcessInformation(handle, 7, ctypes.byref(value), ctypes.sizeof(value)):
        return unavailable(classify_windows_error(_last_error()))
    level = int(value.ProtectionLevel)
    return {
        "status": "observed",
        "level": _PROTECTION_LEVEL_NAMES.get(level, "unknown"),
        "raw": f"0x{level:08x}",
        "protected": level != 0xFFFFFFFE,
    }


def _token_dword(token: int, information_class: int) -> dict[str, Any]:
    if _GetTokenInformation is None:
        return unavailable("not_supported")
    value = wt.DWORD()
    returned = wt.DWORD()
    _clear_last_error()
    if not _GetTokenInformation(
        token,
        information_class,
        ctypes.byref(value),
        ctypes.sizeof(value),
        ctypes.byref(returned),
    ):
        return unavailable(classify_windows_error(_last_error()))
    return {"status": "observed", "value": int(value.value)}


def _query_integrity_level(token: int) -> dict[str, Any]:
    if (
        _GetTokenInformation is None
        or _IsValidSid is None
        or _GetSidSubAuthorityCount is None
        or _GetSidSubAuthority is None
    ):
        return unavailable("not_supported")
    needed = wt.DWORD()
    _clear_last_error()
    _GetTokenInformation(token, 25, None, 0, ctypes.byref(needed))
    if needed.value == 0 or _last_error() != ERROR_INSUFFICIENT_BUFFER:
        return unavailable(classify_windows_error(_last_error()))
    buffer = ctypes.create_string_buffer(needed.value)
    if not _GetTokenInformation(token, 25, buffer, needed.value, ctypes.byref(needed)):
        return unavailable(classify_windows_error(_last_error()))
    label = TOKEN_MANDATORY_LABEL.from_buffer(buffer)
    if not label.Sid or not _IsValidSid(label.Sid):
        return unavailable("invalid_sid")
    count_pointer = _GetSidSubAuthorityCount(label.Sid)
    if not count_pointer or count_pointer[0] == 0:
        return unavailable("invalid_sid")
    rid_pointer = _GetSidSubAuthority(label.Sid, int(count_pointer[0]) - 1)
    if not rid_pointer:
        return unavailable("invalid_sid")
    rid = int(rid_pointer[0])
    if rid < 0x1000:
        name = "untrusted"
    elif rid < 0x2000:
        name = "low"
    elif rid < 0x3000:
        name = "medium"
    elif rid < 0x4000:
        name = "high"
    elif rid < 0x5000:
        name = "system"
    else:
        name = "protected"
    return {"status": "observed", "level": name, "rid": f"0x{rid:08x}"}


def _query_token(handle: int) -> dict[str, Any]:
    if _OpenProcessToken is None:
        return unavailable("not_supported")
    raw = ctypes.c_void_p()
    _clear_last_error()
    if not _OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(raw)):
        return unavailable(classify_windows_error(_last_error()))
    token = int(raw.value or 0)
    try:
        elevation = _token_dword(token, 20)
        elevation_type = _token_dword(token, 18)
        virtualization = _token_dword(token, 24)
        ui_access = _token_dword(token, 26)
        app_container = _token_dword(token, 29)
        return {
            "status": "observed",
            "elevated": _dword_bool(elevation),
            "elevation_type": _dword_value(elevation_type),
            "virtualization_enabled": _dword_bool(virtualization),
            "ui_access": _dword_bool(ui_access),
            "app_container": _dword_bool(app_container),
            "integrity": _query_integrity_level(token),
            "user_sid_included": False,
        }
    finally:
        _close_handle(token)


def _dword_bool(observation: dict[str, Any]) -> bool | dict[str, Any]:
    return (
        bool(observation["value"])
        if observation.get("status") == "observed"
        else observation
    )


def _dword_value(observation: dict[str, Any]) -> int | dict[str, Any]:
    return (
        int(observation["value"])
        if observation.get("status") == "observed"
        else observation
    )


def _verified_information_handle(
    pid: int, expected_creation_time: int
) -> tuple[int | None, str | None]:
    try:
        handle = _open_process_raw(PROCESS_QUERY_INFORMATION, pid)
    except OSError as error:
        return None, classify_windows_error(error.errno or 0)
    temporary = WindowsProcessHandle(pid, handle, False, PROCESS_QUERY_INFORMATION)
    keep_handle = False
    try:
        if temporary.creation_time_100ns() != expected_creation_time:
            return None, "identity_changed"
        keep_handle = True
        return handle, None
    except OSError as error:
        return None, classify_windows_error(error.errno or 0)
    finally:
        if not keep_handle:
            temporary.close()


def _query_mitigations(
    handle: int | None, unavailable_reason: str | None
) -> dict[str, Any]:
    if handle is None:
        return unavailable(unavailable_reason or "permission_denied")
    if _GetProcessMitigationPolicy is None:
        return unavailable("not_supported")
    policies = {
        "dep": (0, DEP_POLICY),
        "aslr": (1, DWORD_POLICY),
        "dynamic_code": (2, DWORD_POLICY),
        "strict_handle": (3, DWORD_POLICY),
        "system_call_disable": (4, DWORD_POLICY),
        "extension_point_disable": (6, DWORD_POLICY),
        "control_flow_guard": (7, DWORD_POLICY),
        "binary_signature": (8, DWORD_POLICY),
        "font_disable": (9, DWORD_POLICY),
        "image_load": (10, DWORD_POLICY),
        "child_process": (12, DWORD_POLICY),
        "side_channel_isolation": (13, DWORD_POLICY),
        "user_shadow_stack": (14, DWORD_POLICY),
    }
    details: dict[str, Any] = {}
    observed = 0
    for name, (policy_id, structure_type) in policies.items():
        value = structure_type()
        _clear_last_error()
        if _GetProcessMitigationPolicy(
            handle, policy_id, ctypes.byref(value), ctypes.sizeof(value)
        ):
            flags = int(value.Flags)
            item: dict[str, Any] = {
                "status": "observed",
                "flags": f"0x{flags:08x}",
                "enabled_bit_indices": [bit for bit in range(32) if flags & (1 << bit)],
            }
            if isinstance(value, DEP_POLICY):
                item["permanent"] = bool(value.Permanent)
            details[name] = item
            observed += 1
        else:
            details[name] = unavailable(classify_windows_error(_last_error()))
    return {"status": "observed" if observed else "unavailable", "details": details}


def _protection_name(protect: int) -> str:
    base = protect & 0xFF
    names = {
        0x01: "no-access",
        0x02: "read-only",
        0x04: "read-write",
        0x08: "write-copy",
        0x10: "execute",
        0x20: "execute-read",
        0x40: "execute-read-write",
        0x80: "execute-write-copy",
    }
    modifiers: list[str] = []
    if protect & PAGE_GUARD:
        modifiers.append("guard")
    if protect & PAGE_NOCACHE:
        modifiers.append("no-cache")
    if protect & PAGE_WRITECOMBINE:
        modifiers.append("write-combine")
    root = names.get(base, f"0x{base:02x}")
    return "+".join([root, *modifiers])


def _query_memory_regions(
    handle: int | None, unavailable_reason: str | None
) -> dict[str, Any]:
    if handle is None:
        return unavailable(unavailable_reason or "permission_denied")
    if _VirtualQueryEx is None:
        return unavailable("not_supported")
    state_counts: collections.Counter[str] = collections.Counter()
    type_counts: collections.Counter[str] = collections.Counter()
    protection_counts: collections.Counter[str] = collections.Counter()
    total_virtual_bytes = 0
    committed_bytes = 0
    executable_count = 0
    writable_executable_count = 0
    address = 0
    pointer_bits = ctypes.sizeof(ctypes.c_void_p) * 8
    maximum_address = (1 << pointer_bits) - 1
    complete = False
    error_reason: str | None = None
    for _ in range(MAX_MEMORY_REGIONS):
        value = MEMORY_BASIC_INFORMATION()
        _clear_last_error()
        returned = _VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(value), ctypes.sizeof(value)
        )
        if not returned:
            code = _last_error()
            if code == ERROR_INVALID_PARAMETER:
                complete = True
            else:
                error_reason = classify_windows_error(code)
            break
        base = int(value.BaseAddress or 0)
        size = int(value.RegionSize)
        next_address = base + size
        if size <= 0 or next_address <= address:
            error_reason = "non_progressing_region"
            break
        state_name = {
            MEM_COMMIT: "commit",
            MEM_RESERVE: "reserve",
            MEM_FREE: "free",
        }.get(int(value.State), f"0x{int(value.State):08x}")
        type_name = {
            0: "none",
            MEM_PRIVATE: "private",
            MEM_MAPPED: "mapped",
            MEM_IMAGE: "image",
        }.get(int(value.Type), f"0x{int(value.Type):08x}")
        protection = int(value.Protect)
        state_counts[state_name] += 1
        type_counts[type_name] += 1
        protection_counts[_protection_name(protection)] += 1
        total_virtual_bytes += size
        if value.State == MEM_COMMIT:
            committed_bytes += size
            base_protection = protection & 0xFF
            executable_count += int(base_protection in _EXECUTABLE_PROTECTIONS)
            writable_executable_count += int(
                base_protection in _WRITABLE_EXECUTABLE_PROTECTIONS
            )
        if next_address > maximum_address:
            complete = True
            break
        address = next_address
    else:
        error_reason = "region_limit_exceeded"

    status = "observed" if complete else ("partial" if state_counts else "unavailable")
    result: dict[str, Any] = {
        "status": status,
        "complete": complete,
        "mapping_count": sum(state_counts.values()),
        "total_virtual_bytes": total_virtual_bytes,
        "committed_bytes": committed_bytes,
        "state_counts": dict(sorted(state_counts.items())),
        "type_counts": dict(sorted(type_counts.items())),
        "permission_counts": dict(sorted(protection_counts.items())),
        "executable_mapping_count": executable_count,
        "writable_executable_mapping_count": writable_executable_count,
        "deleted_mapping_count": None,
        "deleted_executable_mapping_count": None,
        "addresses_included": False,
        "raw_paths_included": False,
    }
    if error_reason:
        result["reason"] = error_reason
    return result


def _module_snapshot(pid: int, *, include_basenames: bool) -> dict[str, Any]:
    if (
        _CreateToolhelp32Snapshot is None
        or _Module32FirstW is None
        or _Module32NextW is None
    ):
        return unavailable("not_supported")
    handle = 0
    error = 0
    for _ in range(4):
        _clear_last_error()
        raw = _CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        handle = int(raw) if raw else 0
        if handle and handle != INVALID_HANDLE_VALUE:
            break
        error = _last_error()
        if error != ERROR_BAD_LENGTH:
            break
    if not handle or handle == INVALID_HANDLE_VALUE:
        return unavailable(classify_windows_error(error or _last_error()))
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        _clear_last_error()
        if not _Module32FirstW(handle, ctypes.byref(entry)):
            return unavailable(classify_windows_error(_last_error()))
        count = 0
        total_image_bytes = 0
        basenames: set[str] = set()
        while True:
            count += 1
            total_image_bytes += int(entry.modBaseSize)
            if include_basenames and entry.szModule:
                basenames.add(str(entry.szModule))
            entry.dwSize = ctypes.sizeof(entry)
            if not _Module32NextW(handle, ctypes.byref(entry)):
                code = _last_error()
                if code not in {0, ERROR_NO_MORE_FILES}:
                    return {
                        "status": "partial",
                        "reason": classify_windows_error(code),
                        "module_count": count,
                        "unique_executable_file_count": count,
                        "total_image_bytes": total_image_bytes,
                        "raw_addresses_included": False,
                        "raw_paths_included": False,
                        "snapshot_semantics": "toolhelp-best-effort",
                    }
                break
        result: dict[str, Any] = {
            "status": "observed",
            "module_count": count,
            "unique_executable_file_count": count,
            "total_image_bytes": total_image_bytes,
            "raw_addresses_included": False,
            "raw_paths_included": False,
            "snapshot_semantics": "toolhelp-best-effort",
        }
        if include_basenames:
            result["executable_file_basenames"] = sorted(basenames)
        return result
    finally:
        _close_handle(handle)


def _query_code_integrity() -> dict[str, Any]:
    if _NtQuerySystemInformation is None:
        return unavailable("not_supported")
    value = SYSTEM_CODEINTEGRITY_INFORMATION()
    value.Length = ctypes.sizeof(value)
    _clear_last_error()
    status = int(
        _NtQuerySystemInformation(
            SYSTEM_CODEINTEGRITY_INFORMATION_CLASS,
            ctypes.byref(value),
            ctypes.sizeof(value),
            None,
        )
    )
    if status != 0:
        return {
            "status": "unavailable",
            "reason": "ntstatus_error",
            "ntstatus": f"0x{status & 0xFFFFFFFF:08x}",
        }
    options = int(value.CodeIntegrityOptions)
    return {
        "status": "observed",
        "options_mask": f"0x{options:08x}",
        "enabled_options": [
            name for flag, name in _CODE_INTEGRITY_FLAGS.items() if options & flag
        ],
    }


def _query_secure_boot() -> dict[str, Any]:
    try:
        registry: Any = importlib.import_module("winreg")

        with registry.OpenKey(
            registry.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        ) as key:
            value, _ = registry.QueryValueEx(key, "UEFISecureBootEnabled")
        return {"status": "observed", "enabled": bool(int(value))}
    except FileNotFoundError:
        return unavailable("not_supported_or_legacy_firmware")
    except PermissionError:
        return unavailable("permission_denied")
    except OSError:
        return unavailable("registry_error")


def _query_firmware_type() -> dict[str, Any]:
    if _GetFirmwareType is None:
        return unavailable("not_supported")
    value = wt.DWORD()
    _clear_last_error()
    if not _GetFirmwareType(ctypes.byref(value)):
        return unavailable(classify_windows_error(_last_error()))
    return {
        "status": "observed",
        "type": {1: "bios", 2: "uefi"}.get(int(value.value), "unknown"),
        "raw": int(value.value),
    }


class WindowsPassiveBackend:
    """Passive Windows implementation of the portable process snapshot schema."""

    backend_name = "windows-passive-v1"

    def __init__(self, *, require_windows: bool = True) -> None:
        if require_windows:
            _require_windows()

    def find_processes(self, name: str) -> list[int]:
        wanted = name.casefold()
        return sorted(
            int(entry["pid"])
            for entry in _process_entries()
            if str(entry["name"]).casefold() == wanted
        )

    def resolve_pid(
        self,
        *,
        pid: int | None = None,
        name: str | None = None,
        self_process: bool = False,
    ) -> int:
        selector_count = sum((pid is not None, name is not None, self_process))
        if selector_count != 1:
            raise ValueError("select exactly one of pid, name, or self_process")
        if self_process:
            return os.getpid()
        if pid is not None:
            if pid <= 0:
                raise ValueError("pid must be positive")
            try:
                with WindowsProcessHandle.open(pid):
                    return pid
            except OSError as error:
                reason = classify_windows_error(error.errno or 0)
                if reason == "not_found_or_process_exited":
                    raise TargetNotFoundError(f"PID {pid}") from error
                if reason == "permission_denied":
                    raise TargetAccessDeniedError(f"PID {pid}") from error
                raise
        assert name is not None
        matches = self.find_processes(name)
        if not matches:
            raise TargetNotFoundError(f"name {name!r}")
        if len(matches) > 1:
            raise AmbiguousTargetError(f"name {name!r}", len(matches))
        return matches[0]

    def capture(
        self,
        pid: int,
        *,
        privacy_mode: str = "aggregate",
        hash_executable: bool = True,
    ) -> dict[str, Any]:
        if privacy_mode not in {"aggregate", "local"}:
            raise ValueError("privacy_mode must be 'aggregate' or 'local'")
        section_errors: list[dict[str, str]] = []
        with WindowsProcessHandle.open(pid) as process:
            try:
                creation_before = process.creation_time_100ns()
            except OSError as error:
                raise InconsistentSnapshotError(
                    "could not establish the Windows process creation identity"
                ) from error
            try:
                entry = _entry_for_pid(pid)
            except OSError as error:
                entry = None
                reason = classify_windows_error(error.errno or 0)
                section_errors.append({"section": "process_snapshot", "reason": reason})
            try:
                image_path = process.image_path()
                executable_link: dict[str, Any] = {"status": "observed"}
            except OSError as error:
                image_path = ""
                reason = classify_windows_error(error.errno or 0)
                executable_link = unavailable(reason)
                section_errors.append({"section": "executable_link", "reason": reason})

            information_handle, information_reason = _verified_information_handle(
                pid, creation_before
            )
            try:
                memory_maps = _query_memory_regions(
                    information_handle, information_reason
                )
                mitigations = _query_mitigations(information_handle, information_reason)
                debugger = _query_debugger(
                    information_handle
                    if information_handle is not None
                    else process.handle
                )
            finally:
                _close_handle(information_handle)

            modules = _module_snapshot(pid, include_basenames=privacy_mode == "local")
            handle_count = _query_handle_count(process.handle)
            architecture = _query_architecture(process.handle)
            token = _query_token(process.handle)
            protection = _query_protection_level(process.handle)
            try:
                observed_times = process.process_times()
                times: dict[str, Any] = {
                    "status": "observed",
                    "kernel_time_100ns": observed_times["kernel_time_100ns"],
                    "user_time_100ns": observed_times["user_time_100ns"],
                }
            except OSError as error:
                reason = classify_windows_error(error.errno or 0)
                times = unavailable(reason)
                section_errors.append({"section": "process_times", "reason": reason})

            creation_after = process.creation_time_100ns()
            if creation_before != creation_after:
                raise InconsistentSnapshotError(
                    "Windows process creation identity changed during capture"
                )
            alive = process.alive()
            if alive is False:
                raise InconsistentSnapshotError("target exited during capture")

            basename = Path(image_path).name if image_path else None
            identity: dict[str, Any] = {
                "comm": entry["name"] if entry else basename,
                "executable_basename": basename,
            }
            if privacy_mode == "local":
                identity.update(
                    {
                        "pid": pid,
                        "parent_pid": entry["parent_pid"] if entry else None,
                        "creation_time_100ns": creation_before,
                    }
                )

            executable: dict[str, Any] = {
                "status": executable_link["status"],
                "basename": basename,
                "path_basis": "QueryFullProcessImageNameW",
                "hash_requested": hash_executable,
            }
            if executable_link["status"] != "observed":
                executable["reason"] = executable_link["reason"]
            if privacy_mode == "local" and image_path:
                executable["path"] = image_path
            executable["integrity"] = (
                _hash_path(image_path)
                if hash_executable and image_path
                else {
                    "status": "not_requested" if not hash_executable else "unavailable",
                    "reason": "path_unavailable",
                }
            )

            status: dict[str, Any] = {
                "status": "observed",
                "thread_count": entry["thread_count"] if entry else None,
                "debugger_present": debugger,
                "architecture": architecture,
                "token": token,
                "protection": protection,
                "mitigations": mitigations,
                "times": times,
            }
            file_descriptors = {
                "status": handle_count["status"],
                "descriptor_model": "windows-object-handles",
                "descriptor_count": handle_count.get("count"),
                "category_counts": None,
                "raw_targets_included": False,
            }
            if handle_count["status"] != "observed":
                file_descriptors["reason"] = handle_count["reason"]

            consistency = {
                "process_handle_anchored": True,
                "synchronize_access_granted": process.synchronize_access,
                "creation_time_stable": True,
                "process_alive_after_capture": alive,
                "information_handle_identity_verified": information_handle is not None,
                "module_snapshot_atomic": False,
            }

        snapshot: dict[str, Any] = {
            "schema_version": 1,
            "capture": {
                "kind": "passive_process_snapshot",
                "captured_utc": _utc_now(),
                "backend": self.backend_name,
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "machine": platform.machine(),
                },
                "read_only": True,
                "privacy_mode": privacy_mode,
                "consistency": consistency,
            },
            "privacy": {
                "host_or_user_identity_included": False,
                "command_line_or_environment_included": False,
                "raw_memory_addresses_included": False,
                "raw_file_descriptor_targets_included": False,
                "raw_module_paths_included": False,
                "raw_namespace_identifiers_included": False,
                "raw_cgroup_paths_included": False,
                "process_ids_included": privacy_mode == "local",
                "executable_path_included": privacy_mode == "local",
                "user_sid_included": False,
            },
            "host_security": self.capture_host_security(),
            "target": {
                "identity": identity,
                "status": status,
                "executable": executable,
                "memory_maps": memory_maps,
                "modules": modules,
                "file_descriptors": file_descriptors,
                "namespaces": {
                    "status": "not_applicable",
                    "reason": "windows_process_model",
                },
                "cgroups": {
                    "status": "not_applicable",
                    "reason": "windows_process_model",
                },
            },
            "section_errors": section_errors,
        }
        signals = derive_signals(snapshot)
        snapshot["signals"] = signals
        snapshot["summary"] = summarize_signals(signals)
        validate_snapshot_contract(snapshot)
        return snapshot

    def capture_host_security(self) -> dict[str, Any]:
        firmware = _query_firmware_type()
        dep_policy = (
            {"status": "observed", "policy": int(_GetSystemDEPPolicy())}
            if _GetSystemDEPPolicy is not None
            else unavailable("not_supported")
        )
        return {
            "status": "observed",
            "code_integrity": _query_code_integrity(),
            "secure_boot": _query_secure_boot(),
            "firmware": firmware,
            "system_dep_policy": dep_policy,
            "writes_performed": False,
        }
