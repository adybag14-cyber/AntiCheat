"""Capture read-only process-handle table snapshots on Windows.

The collector opens one query-only handle to its own process solely to discover
the runtime ObjectTypeIndex used for process objects. It never opens, duplicates,
reads, writes, suspends, terminates, or debugs another process. Subsequent data
comes from NtQuerySystemInformation(SystemExtendedHandleInformation).

Output is local-only JSON Lines because it contains transient kernel object
addresses and system-wide handle metadata. Do not publish the raw file.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MAX_BUFFER_BYTES = 512 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def require_windows() -> None:
    if os.name != "nt":
        raise SystemExit("process-handle snapshots are supported only on Windows")


class SystemHandleTableEntryInfoEx(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_size_t),
        ("HandleValue", ctypes.c_size_t),
        ("GrantedAccess", ctypes.c_ulong),
        ("CreatorBackTraceIndex", ctypes.c_ushort),
        ("ObjectTypeIndex", ctypes.c_ushort),
        ("HandleAttributes", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
    ]


def ntstatus(value: int) -> int:
    return value & 0xFFFFFFFF


def query_handle_entries() -> list[SystemHandleTableEntryInfoEx]:
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    query = ntdll.NtQuerySystemInformation
    query.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    query.restype = ctypes.c_long

    size = 4 * 1024 * 1024
    while size <= MAX_BUFFER_BYTES:
        buffer = ctypes.create_string_buffer(size)
        required = ctypes.c_ulong()
        status = ntstatus(
            query(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                ctypes.byref(buffer),
                size,
                ctypes.byref(required),
            )
        )
        if status == 0:
            count = ctypes.c_size_t.from_buffer(buffer, 0).value
            header_size = ctypes.sizeof(ctypes.c_size_t) * 2
            entry_size = ctypes.sizeof(SystemHandleTableEntryInfoEx)
            available = max(0, (size - header_size) // entry_size)
            if count > available:
                raise RuntimeError(
                    f"handle count {count} exceeds decoded buffer capacity {available}"
                )
            return [
                SystemHandleTableEntryInfoEx.from_buffer_copy(
                    buffer, header_size + index * entry_size
                )
                for index in range(count)
            ]
        if status != STATUS_INFO_LENGTH_MISMATCH:
            raise OSError(f"NtQuerySystemInformation failed with NTSTATUS 0x{status:08X}")
        size = max(size * 2, int(required.value) + 1024 * 1024)
    raise MemoryError(f"handle table exceeded the {MAX_BUFFER_BYTES}-byte safety limit")


def open_self_process_handle() -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    open_process.restype = ctypes.c_void_p
    handle = open_process(PROCESS_QUERY_LIMITED_INFORMATION, 0, os.getpid())
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(handle)


def close_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close = kernel32.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = ctypes.c_int
    if not close(ctypes.c_void_p(handle)):
        raise ctypes.WinError(ctypes.get_last_error())


def discover_process_type_index() -> int:
    handle = open_self_process_handle()
    try:
        for entry in query_handle_entries():
            if int(entry.UniqueProcessId) == os.getpid() and int(entry.HandleValue) == handle:
                return int(entry.ObjectTypeIndex)
    finally:
        close_handle(handle)
    raise RuntimeError("could not locate the collector's self-process handle")


def normalized_process_handles(type_index: int) -> dict[tuple[int, int], dict[str, Any]]:
    rows: dict[tuple[int, int], dict[str, Any]] = {}
    for entry in query_handle_entries():
        if int(entry.ObjectTypeIndex) != type_index:
            continue
        owner_pid = int(entry.UniqueProcessId)
        handle_value = int(entry.HandleValue)
        rows[(owner_pid, handle_value)] = {
            "owner_pid": owner_pid,
            "handle": f"0x{handle_value:X}",
            "object": f"0x{int(entry.Object or 0):X}",
            "granted_access": f"0x{int(entry.GrantedAccess):08X}",
            "attributes": f"0x{int(entry.HandleAttributes):X}",
        }
    return rows


def write_record(handle, payload: dict[str, Any]) -> None:
    handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    handle.flush()


def capture(output: Path, duration: float, interval: float) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    process_type_index = discover_process_type_index()
    deadline = time.monotonic() + duration
    previous = normalized_process_handles(process_type_index)
    snapshot_count = 1
    added_count = 0
    removed_count = 0
    changed_count = 0

    with output.open("w", encoding="utf-8", newline="\n") as handle:
        write_record(
            handle,
            {
                "type": "metadata",
                "schema_version": 1,
                "started_utc": utc_now(),
                "collector_pid": os.getpid(),
                "process_object_type_index": process_type_index,
                "duration_seconds": duration,
                "interval_seconds": interval,
                "privacy": "local-only; contains transient kernel object addresses",
                "safety": "opens only a query-limited handle to the collector itself",
            },
        )
        write_record(
            handle,
            {
                "type": "baseline",
                "captured_utc": utc_now(),
                "entries": list(previous.values()),
            },
        )

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(interval, remaining))
            current = normalized_process_handles(process_type_index)
            added_keys = sorted(current.keys() - previous.keys())
            removed_keys = sorted(previous.keys() - current.keys())
            common_keys = current.keys() & previous.keys()
            changed_keys = sorted(
                key for key in common_keys if current[key] != previous[key]
            )
            added = [current[key] for key in added_keys]
            removed = [previous[key] for key in removed_keys]
            changed = [
                {"before": previous[key], "after": current[key]} for key in changed_keys
            ]
            added_count += len(added)
            removed_count += len(removed)
            changed_count += len(changed)
            snapshot_count += 1
            if added or removed or changed:
                write_record(
                    handle,
                    {
                        "type": "delta",
                        "captured_utc": utc_now(),
                        "added": added,
                        "removed": removed,
                        "changed": changed,
                    },
                )
            previous = current

        write_record(
            handle,
            {
                "type": "summary",
                "completed_utc": utc_now(),
                "snapshot_count": snapshot_count,
                "final_process_handle_count": len(previous),
                "added_entries": added_count,
                "removed_entries": removed_count,
                "changed_entries": changed_count,
            },
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()
    if not 1.0 <= args.duration <= 300.0:
        parser.error("--duration must be between 1 and 300 seconds")
    if not 0.1 <= args.interval <= 10.0:
        parser.error("--interval must be between 0.1 and 10 seconds")
    return args


def main() -> None:
    require_windows()
    args = parse_args()
    capture(args.output, args.duration, args.interval)
    print(args.output)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"snapshot_process_handles: {error}", file=sys.stderr)
        raise
