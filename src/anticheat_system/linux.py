"""Race-aware, read-only Linux process and host observation.

The backend intentionally does not use ptrace, process_vm_readv, /proc/PID/mem,
eBPF, perf events, fanotify, or any write-capable proc/sys interface. It reads
bounded metadata and keeps failure distinct from a valid zero observation.
"""

from __future__ import annotations

import collections
import contextlib
import ctypes
import datetime as dt
import errno
import hashlib
import os
import platform
import re
import select
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

from .contract import validate_snapshot_contract
from .errors import (
    AmbiguousTargetError,
    InconsistentSnapshotError,
    TargetNotFoundError,
    UnsupportedPlatformError,
    classify_os_error,
    unavailable,
)
from .signals import derive_signals, summarize_signals

MAX_SMALL_TEXT = 256 * 1024
MAX_MAPS_TEXT = 32 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
NAMESPACE_NAMES = (
    "cgroup",
    "ipc",
    "mnt",
    "net",
    "pid",
    "pid_for_children",
    "time",
    "time_for_children",
    "user",
    "uts",
)
_PIDFD_OPEN_SYSCALL_BY_MACHINE = {
    "aarch64": 434,
    "amd64": 434,
    "arm64": 434,
    "riscv64": 434,
    "x86_64": 434,
}

_MAP_LINE = re.compile(
    r"^(?P<start>[0-9a-fA-F]+)-(?P<end>[0-9a-fA-F]+)\s+"
    r"(?P<perms>[rwxps-]{4})\s+"
    r"(?P<offset>[0-9a-fA-F]+)\s+"
    r"(?P<device>\S+)\s+(?P<inode>\d+)"
    r"(?:\s+(?P<pathname>.*))?$"
)


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _open_pidfd(pid: int) -> int:
    """Open a pidfd even when a Linux Python build omitted os.pidfd_open."""

    native = getattr(os, "pidfd_open", None)
    if native is not None:
        return native(pid, 0)

    syscall_number = _PIDFD_OPEN_SYSCALL_BY_MACHINE.get(platform.machine().lower())
    if syscall_number is None:
        raise OSError(errno.ENOSYS, "pidfd_open syscall number is not known")
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_uint]
    syscall.restype = ctypes.c_long
    descriptor = syscall(syscall_number, pid, 0)
    if descriptor < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return int(descriptor)


def parse_proc_stat(text: str) -> dict[str, int | str]:
    """Parse identity fields from /proc/PID/stat without trusting spaces in comm."""

    line = text.strip()
    open_paren = line.find("(")
    close_paren = line.rfind(") ")
    if open_paren <= 0 or close_paren <= open_paren:
        raise ValueError("malformed proc stat record")
    try:
        pid = int(line[:open_paren].strip())
        comm = line[open_paren + 1 : close_paren]
        fields = line[close_paren + 2 :].split()
        # fields[0] is field 3 (state); starttime is field 22.
        if len(fields) < 20:
            raise ValueError("truncated proc stat record")
        return {
            "pid": pid,
            "comm": comm,
            "state_code": fields[0],
            "parent_pid": int(fields[1]),
            "thread_count": int(fields[17]),
            "start_time_ticks": int(fields[19]),
        }
    except (IndexError, ValueError) as error:
        if isinstance(error, ValueError) and str(error).startswith("malformed"):
            raise
        raise ValueError("malformed proc stat fields") from error


def parse_proc_status(text: str) -> dict[str, Any]:
    fields: dict[str, str] = {}
    for raw_line in text.splitlines():
        key, separator, value = raw_line.partition(":")
        if separator:
            fields[key] = value.strip()

    def first_int(key: str) -> int | None:
        value = fields.get(key)
        if value is None:
            return None
        try:
            return int(value.split()[0], 10)
        except (IndexError, ValueError):
            return None

    def hex_mask(key: str) -> str | None:
        value = fields.get(key)
        if value is None:
            return None
        try:
            return f"0x{int(value, 16):016x}"
        except ValueError:
            return None

    state_value = fields.get("State", "")
    state_code = state_value[:1] or None
    state_name_match = re.search(r"\(([^)]+)\)", state_value)
    uid_values = _parse_decimal_list(fields.get("Uid"))
    gid_values = _parse_decimal_list(fields.get("Gid"))
    namespace_pids = _parse_decimal_list(fields.get("NSpid"))
    tracer_pid = first_int("TracerPid")
    return {
        "name": fields.get("Name"),
        "state_code": state_code,
        "state_name": state_name_match.group(1) if state_name_match else None,
        "parent_pid": first_int("PPid"),
        "thread_count": first_int("Threads"),
        "tracer_present": tracer_pid != 0 if tracer_pid is not None else None,
        "no_new_privileges": _int_to_bool(first_int("NoNewPrivs")),
        "seccomp_mode": first_int("Seccomp"),
        "seccomp_filter_count": first_int("Seccomp_filters"),
        "core_dumping": _int_to_bool(first_int("CoreDumping")),
        "memory_kib": {
            key: value
            for key, value in {
                "virtual": first_int("VmSize"),
                "resident": first_int("VmRSS"),
                "locked": first_int("VmLck"),
                "pinned": first_int("VmPin"),
                "swap": first_int("VmSwap"),
            }.items()
            if value is not None
        },
        "capabilities": {
            key: value
            for key, value in {
                "inheritable": hex_mask("CapInh"),
                "permitted": hex_mask("CapPrm"),
                "effective": hex_mask("CapEff"),
                "bounding": hex_mask("CapBnd"),
                "ambient": hex_mask("CapAmb"),
            }.items()
            if value is not None
        },
        "uid_values": uid_values,
        "gid_values": gid_values,
        "pid_namespace_depth": len(namespace_pids)
        if namespace_pids is not None
        else None,
    }


def _parse_decimal_list(value: str | None) -> list[int] | None:
    if value is None:
        return None
    try:
        return [int(part, 10) for part in value.split()]
    except ValueError:
        return None


def _int_to_bool(value: int | None) -> bool | None:
    if value is None:
        return None
    return value != 0


def parse_proc_maps(text: str, *, include_basenames: bool = False) -> dict[str, Any]:
    permission_counts: collections.Counter[str] = collections.Counter()
    category_counts: collections.Counter[str] = collections.Counter()
    unique_files: set[tuple[str, int]] = set()
    executable_files: set[tuple[str, int]] = set()
    executable_basenames: set[str] = set()
    total_virtual_bytes = 0
    writable_executable_count = 0
    deleted_count = 0
    deleted_executable_count = 0
    malformed_count = 0

    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        match = _MAP_LINE.match(raw_line)
        if match is None:
            malformed_count += 1
            continue
        start = int(match.group("start"), 16)
        end = int(match.group("end"), 16)
        if end < start:
            malformed_count += 1
            continue
        total_virtual_bytes += end - start
        permissions = match.group("perms")
        permission_counts[permissions] += 1
        writable_executable = permissions.startswith("rwx") or (
            permissions[1] == "w" and permissions[2] == "x"
        )
        writable_executable_count += int(writable_executable)

        pathname = (match.group("pathname") or "").strip()
        inode = int(match.group("inode"), 10)
        device = match.group("device")
        is_deleted = pathname.endswith(" (deleted)")
        is_executable = permissions[2] == "x"
        if is_deleted:
            deleted_count += 1
            deleted_executable_count += int(is_executable)

        if not pathname:
            category = "anonymous"
        elif pathname.startswith("["):
            category = "special"
        elif pathname.startswith(("/memfd:", "memfd:")):
            category = "memfd"
        elif inode > 0:
            category = "file"
            stable_path = pathname.removesuffix(" (deleted)")
            identity = (device, inode)
            unique_files.add(identity)
            if is_executable:
                executable_files.add(identity)
                basename = Path(stable_path).name
                if basename:
                    executable_basenames.add(basename)
        else:
            category = "other"
        category_counts[category] += 1

    result: dict[str, Any] = {
        "status": "observed",
        "mapping_count": sum(permission_counts.values()),
        "total_virtual_bytes": total_virtual_bytes,
        "permission_counts": dict(sorted(permission_counts.items())),
        "category_counts": dict(sorted(category_counts.items())),
        "unique_file_count": len(unique_files),
        "unique_executable_file_count": len(executable_files),
        "writable_executable_mapping_count": writable_executable_count,
        "deleted_mapping_count": deleted_count,
        "deleted_executable_mapping_count": deleted_executable_count,
        "malformed_line_count": malformed_count,
        "addresses_included": False,
        "raw_paths_included": False,
    }
    if include_basenames:
        result["executable_file_basenames"] = sorted(executable_basenames)
    return result


def categorize_fd_target(target: str) -> str:
    if target.startswith("socket:["):
        return "socket"
    if target.startswith("pipe:["):
        return "pipe"
    if target.startswith("anon_inode:"):
        return "anonymous_inode"
    if target.startswith("memfd:") or "/memfd:" in target:
        return "memory_file"
    if target.endswith(" (deleted)"):
        return "deleted_file"
    if target.startswith("/"):
        return "filesystem"
    return "other"


def parse_proc_cgroup(text: str) -> dict[str, Any]:
    controllers: set[str] = set()
    membership_count = 0
    non_root_membership_count = 0
    unified = False
    malformed_count = 0
    for line in text.splitlines():
        if not line:
            continue
        parts = line.split(":", 2)
        if len(parts) != 3:
            malformed_count += 1
            continue
        hierarchy, controller_text, path = parts
        membership_count += 1
        non_root_membership_count += int(path != "/")
        if hierarchy == "0" and not controller_text:
            unified = True
        controllers.update(part for part in controller_text.split(",") if part)
    return {
        "status": "observed",
        "version": 2 if unified else (1 if membership_count else None),
        "membership_count": membership_count,
        "non_root_membership_count": non_root_membership_count,
        "controllers": sorted(controllers),
        "raw_paths_included": False,
        "malformed_line_count": malformed_count,
    }


@dataclass(slots=True)
class LinuxProcessHandle:
    pid: int
    directory_fd: int
    pid_fd: int | None
    pidfd_unavailable_reason: str | None

    @classmethod
    def open(
        cls, pid: int, *, proc_root: Path = Path("/proc"), enable_pidfd: bool = True
    ) -> LinuxProcessHandle:
        pid_fd: int | None = None
        pidfd_reason: str | None = None
        use_pidfd = enable_pidfd and proc_root == Path("/proc")
        if use_pidfd:
            try:
                pid_fd = _open_pidfd(pid)
            except OSError as error:
                pidfd_reason = classify_os_error(error)
        else:
            pidfd_reason = "not_supported"

        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            directory_fd = os.open(str(proc_root / str(pid)), flags)
        except BaseException:
            if pid_fd is not None:
                os.close(pid_fd)
            raise

        handle = cls(pid, directory_fd, pid_fd, pidfd_reason)
        if handle.pidfd_exited():
            handle.close()
            raise InconsistentSnapshotError(
                "target exited while its procfs handle was opened"
            )
        return handle

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        for descriptor_name in ("directory_fd", "pid_fd"):
            descriptor = getattr(self, descriptor_name)
            if descriptor is not None and descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
                setattr(
                    self,
                    descriptor_name,
                    -1 if descriptor_name == "directory_fd" else None,
                )

    def pidfd_exited(self) -> bool | None:
        if self.pid_fd is None:
            return None
        readable, _, exceptional = select.select([self.pid_fd], [], [self.pid_fd], 0)
        return bool(readable or exceptional)

    def read_text(self, relative_path: str, *, limit: int = MAX_SMALL_TEXT) -> str:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(relative_path, flags, dir_fd=self.directory_fd)
        try:
            data = os.read(descriptor, limit + 1)
        finally:
            os.close(descriptor)
        if len(data) > limit:
            raise OSError(errno.EOVERFLOW, "procfs record exceeded the bounded read")
        return data.decode("utf-8", "replace")

    def readlink(self, relative_path: str) -> str:
        return os.readlink(relative_path, dir_fd=self.directory_fd)

    def listdir(self, relative_path: str) -> list[str]:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(relative_path, flags, dir_fd=self.directory_fd)
        try:
            return os.listdir(descriptor)
        finally:
            os.close(descriptor)

    def hash_executable(self, *, limit: int = MAX_EXECUTABLE_BYTES) -> dict[str, Any]:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open("exe", flags, dir_fd=self.directory_fd)
        try:
            stat_result = os.fstat(descriptor)
            if stat_result.st_size > limit:
                return unavailable("size_limit_exceeded")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
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
            }
        finally:
            os.close(descriptor)


class LinuxProcfsBackend:
    """Passive Linux backend with explicit privacy and consistency contracts."""

    backend_name = "linux-procfs-v1"

    def __init__(
        self,
        *,
        proc_root: Path | str = Path("/proc"),
        sys_root: Path | str = Path("/sys"),
        require_linux: bool = True,
    ) -> None:
        if require_linux and platform.system() != "Linux":
            raise UnsupportedPlatformError(platform.system())
        self.proc_root = Path(proc_root)
        self.sys_root = Path(sys_root)

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
            if not (self.proc_root / str(pid)).is_dir():
                raise TargetNotFoundError(f"PID {pid}")
            return pid

        assert name is not None
        matches = self.find_processes(name)
        if not matches:
            raise TargetNotFoundError(f"name {name!r}")
        if len(matches) > 1:
            raise AmbiguousTargetError(f"name {name!r}", len(matches))
        return matches[0]

    def find_processes(self, name: str) -> list[int]:
        matches: list[int] = []
        try:
            entries: Iterable[Path] = self.proc_root.iterdir()
        except OSError:
            return matches
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            try:
                comm = _read_path_once(entry / "comm", MAX_SMALL_TEXT).strip()
                executable_name = Path(os.readlink(entry / "exe")).name
            except OSError:
                executable_name = ""
                try:
                    comm = _read_path_once(entry / "comm", MAX_SMALL_TEXT).strip()
                except OSError:
                    continue
            if name in {comm, executable_name}:
                matches.append(int(entry.name))
        return sorted(matches)

    def capture(
        self,
        pid: int,
        *,
        privacy_mode: str = "aggregate",
        hash_executable: bool = True,
    ) -> dict[str, Any]:
        if privacy_mode not in {"aggregate", "local"}:
            raise ValueError("privacy_mode must be 'aggregate' or 'local'")

        with LinuxProcessHandle.open(
            pid,
            proc_root=self.proc_root,
            enable_pidfd=self.proc_root == Path("/proc"),
        ) as process:
            try:
                stat_before = parse_proc_stat(process.read_text("stat"))
            except (OSError, ValueError) as error:
                raise InconsistentSnapshotError(
                    "could not establish the target process identity"
                ) from error
            if stat_before["pid"] != pid:
                raise InconsistentSnapshotError(
                    "procfs PID did not match the requested target"
                )

            target: dict[str, Any] = {}
            section_errors: list[dict[str, str]] = []
            status = self._capture_status(process, section_errors)
            executable = self._capture_executable(
                process,
                privacy_mode=privacy_mode,
                hash_executable=hash_executable,
                errors=section_errors,
            )
            memory_maps = self._capture_maps(
                process, privacy_mode=privacy_mode, errors=section_errors
            )
            file_descriptors = self._capture_file_descriptors(process, section_errors)
            namespaces = self._capture_namespaces(process)
            cgroups = self._capture_cgroups(process, section_errors)
            modules = self._modules_from_maps(memory_maps, privacy_mode=privacy_mode)

            try:
                stat_after = parse_proc_stat(process.read_text("stat"))
            except (OSError, ValueError) as error:
                raise InconsistentSnapshotError(
                    "target exited before the snapshot could be committed"
                ) from error
            if stat_before["start_time_ticks"] != stat_after["start_time_ticks"]:
                raise InconsistentSnapshotError(
                    "target identity changed during capture"
                )
            pidfd_exited = process.pidfd_exited()
            if pidfd_exited:
                raise InconsistentSnapshotError("target exited during capture")

            identity: dict[str, Any] = {
                "comm": (
                    status.get("name") or stat_before["comm"]
                    if status.get("status") == "observed"
                    else stat_before["comm"]
                ),
                "executable_basename": executable.get("basename"),
            }
            if privacy_mode == "local":
                identity.update(
                    {
                        "pid": pid,
                        "parent_pid": stat_before["parent_pid"],
                        "start_time_ticks": stat_before["start_time_ticks"],
                    }
                )
                if status.get("status") == "observed":
                    identity["uid_values"] = status.pop("uid_values", None)
                    identity["gid_values"] = status.pop("gid_values", None)
            else:
                status.pop("uid_values", None)
                status.pop("gid_values", None)
                status.pop("parent_pid", None)

            target.update(
                {
                    "identity": identity,
                    "status": status,
                    "executable": executable,
                    "memory_maps": memory_maps,
                    "modules": modules,
                    "file_descriptors": file_descriptors,
                    "namespaces": namespaces,
                    "cgroups": cgroups,
                }
            )
            consistency = {
                "process_directory_anchored": True,
                "pidfd_anchored": process.pid_fd is not None,
                "pidfd_unavailable_reason": process.pidfd_unavailable_reason,
                "start_time_stable": True,
                "process_alive_after_capture": None
                if pidfd_exited is None
                else not pidfd_exited,
                "maps_single_read_bounded": memory_maps.get("status") == "observed",
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
            "target": target,
            "section_errors": section_errors,
        }
        signals = derive_signals(snapshot)
        snapshot["signals"] = signals
        snapshot["summary"] = summarize_signals(signals)
        validate_snapshot_contract(snapshot)
        return snapshot

    @staticmethod
    def _modules_from_maps(
        memory_maps: dict[str, Any], *, privacy_mode: str
    ) -> dict[str, Any]:
        if memory_maps.get("status") != "observed":
            return unavailable(memory_maps.get("reason", "maps_unavailable"))
        result: dict[str, Any] = {
            "status": "observed",
            "module_count": memory_maps["unique_executable_file_count"],
            "unique_executable_file_count": memory_maps["unique_executable_file_count"],
            "raw_addresses_included": False,
            "raw_paths_included": False,
            "snapshot_semantics": "proc-maps-aggregate",
        }
        if privacy_mode == "local":
            result["executable_file_basenames"] = memory_maps.get(
                "executable_file_basenames", []
            )
        return result

    def _capture_status(
        self, process: LinuxProcessHandle, errors: list[dict[str, str]]
    ) -> dict[str, Any]:
        try:
            return {
                "status": "observed",
                **parse_proc_status(process.read_text("status")),
            }
        except (OSError, ValueError) as error:
            reason = (
                classify_os_error(error)
                if isinstance(error, OSError)
                else "parse_error"
            )
            errors.append({"section": "status", "reason": reason})
            return unavailable(reason)

    def _capture_executable(
        self,
        process: LinuxProcessHandle,
        *,
        privacy_mode: str,
        hash_executable: bool,
        errors: list[dict[str, str]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "observed",
            "hash_requested": hash_executable,
        }
        try:
            path = process.readlink("exe")
            clean_path = path.removesuffix(" (deleted)")
            result["basename"] = Path(clean_path).name
            result["deleted"] = path.endswith(" (deleted)")
            if privacy_mode == "local":
                result["path"] = path
        except OSError as error:
            reason = classify_os_error(error)
            errors.append({"section": "executable_link", "reason": reason})
            result.update(
                {"basename": None, "deleted": None, "link": unavailable(reason)}
            )
        if hash_executable:
            try:
                result["integrity"] = process.hash_executable()
            except OSError as error:
                reason = classify_os_error(error)
                errors.append({"section": "executable_hash", "reason": reason})
                result["integrity"] = unavailable(reason)
        else:
            result["integrity"] = {"status": "not_requested"}
        return result

    def _capture_maps(
        self,
        process: LinuxProcessHandle,
        *,
        privacy_mode: str,
        errors: list[dict[str, str]],
    ) -> dict[str, Any]:
        try:
            text = process.read_text("maps", limit=MAX_MAPS_TEXT)
            return parse_proc_maps(text, include_basenames=privacy_mode == "local")
        except (OSError, ValueError) as error:
            reason = (
                classify_os_error(error)
                if isinstance(error, OSError)
                else "parse_error"
            )
            errors.append({"section": "memory_maps", "reason": reason})
            return unavailable(reason)

    def _capture_file_descriptors(
        self, process: LinuxProcessHandle, errors: list[dict[str, str]]
    ) -> dict[str, Any]:
        try:
            entries = sorted(
                entry for entry in process.listdir("fd") if entry.isdecimal()
            )
        except OSError as error:
            reason = classify_os_error(error)
            errors.append({"section": "file_descriptors", "reason": reason})
            return unavailable(reason)
        categories: collections.Counter[str] = collections.Counter()
        inaccessible_count = 0
        for entry in entries:
            try:
                categories[categorize_fd_target(process.readlink(f"fd/{entry}"))] += 1
            except OSError:
                inaccessible_count += 1
        return {
            "status": "observed",
            "descriptor_count": len(entries),
            "category_counts": dict(sorted(categories.items())),
            "inaccessible_target_count": inaccessible_count,
            "raw_targets_included": False,
        }

    def _capture_namespaces(self, process: LinuxProcessHandle) -> dict[str, Any]:
        details: dict[str, dict[str, Any]] = {}
        for name in NAMESPACE_NAMES:
            try:
                target_identity = process.readlink(f"ns/{name}")
            except OSError as error:
                details[name] = unavailable(classify_os_error(error))
                continue
            try:
                observer_identity = os.readlink(self.proc_root / "self" / "ns" / name)
                details[name] = {
                    "status": "observed",
                    "same_as_observer": target_identity == observer_identity,
                }
            except OSError as error:
                details[name] = {
                    "status": "observed",
                    "same_as_observer": None,
                    "observer_reason": classify_os_error(error),
                }
        observed = [item for item in details.values() if item["status"] == "observed"]
        return {
            "status": "observed" if observed else "unavailable",
            "details": details,
            "observed_count": len(observed),
            "different_from_observer_count": sum(
                item.get("same_as_observer") is False for item in observed
            ),
            "raw_identifiers_included": False,
        }

    def _capture_cgroups(
        self, process: LinuxProcessHandle, errors: list[dict[str, str]]
    ) -> dict[str, Any]:
        try:
            return parse_proc_cgroup(process.read_text("cgroup"))
        except (OSError, ValueError) as error:
            reason = (
                classify_os_error(error)
                if isinstance(error, OSError)
                else "parse_error"
            )
            errors.append({"section": "cgroups", "reason": reason})
            return unavailable(reason)

    def capture_host_security(self) -> dict[str, Any]:
        sysctls = {
            "yama_ptrace_scope": self.proc_root / "sys/kernel/yama/ptrace_scope",
            "unprivileged_bpf_disabled": self.proc_root
            / "sys/kernel/unprivileged_bpf_disabled",
            "perf_event_paranoid": self.proc_root / "sys/kernel/perf_event_paranoid",
            "kptr_restrict": self.proc_root / "sys/kernel/kptr_restrict",
            "dmesg_restrict": self.proc_root / "sys/kernel/dmesg_restrict",
            "modules_disabled": self.proc_root / "sys/kernel/modules_disabled",
            "randomize_va_space": self.proc_root / "sys/kernel/randomize_va_space",
            "kernel_taint_mask": self.proc_root / "sys/kernel/tainted",
        }
        observations = {
            name: _read_int_observation(path) for name, path in sysctls.items()
        }

        lsm_path = self.sys_root / "kernel/security/lsm"
        try:
            active_lsms: dict[str, Any] = {
                "status": "observed",
                "names": [
                    value
                    for value in _read_path_once(lsm_path, MAX_SMALL_TEXT)
                    .strip()
                    .split(",")
                    if value
                ],
            }
        except OSError as error:
            active_lsms = unavailable(classify_os_error(error))

        lockdown_path = self.sys_root / "kernel/security/lockdown"
        try:
            lockdown_text = _read_path_once(lockdown_path, MAX_SMALL_TEXT).strip()
            active_match = re.search(r"\[([^]]+)\]", lockdown_text)
            lockdown: dict[str, Any] = {
                "status": "observed",
                "mode": active_match.group(1)
                if active_match
                else lockdown_text or "unknown",
            }
        except OSError as error:
            lockdown = unavailable(classify_os_error(error))

        module_sig_path = self.sys_root / "module/module/parameters/sig_enforce"
        try:
            value = _read_path_once(module_sig_path, MAX_SMALL_TEXT).strip().lower()
            module_signatures: dict[str, Any] = {
                "status": "observed",
                "enforced": value in {"1", "y", "yes", "true"},
            }
        except OSError as error:
            module_signatures = unavailable(classify_os_error(error))

        return {
            "status": "observed",
            "sysctls": observations,
            "active_linux_security_modules": active_lsms,
            "lockdown": lockdown,
            "module_signature_enforcement": module_signatures,
            "writes_performed": False,
        }


def _read_path_once(path: Path, limit: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        data = os.read(descriptor, limit + 1)
    finally:
        os.close(descriptor)
    if len(data) > limit:
        raise OSError(errno.EOVERFLOW, "record exceeded bounded read")
    return data.decode("utf-8", "replace")


def _read_int_observation(path: Path) -> dict[str, Any]:
    try:
        value = int(_read_path_once(path, MAX_SMALL_TEXT).strip(), 10)
        return {"status": "observed", "value": value}
    except OSError as error:
        return unavailable(classify_os_error(error))
    except ValueError:
        return unavailable("parse_error")
