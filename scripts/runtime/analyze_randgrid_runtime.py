"""Reduce local Randgrid runtime traces into a reviewable evidence summary.

The input files are deliberately Git-ignored because ETL decodes and handle
snapshots contain transient process IDs, paths, and kernel object addresses.
This analyzer streams the large Xperf audit dump, keeps only aggregate counts,
and aliases (rather than publishes) any object-pointer correlation candidates.

Correlation is intentionally conservative.  A process-handle entry observed in
the first snapshot after an ETW PsOpenProcess event is only a temporal candidate:
the ETW event does not expose the returned handle value, and a 500 ms snapshot
can contain unrelated handle activity.  The output never labels such a match as
proof of callback access stripping.
"""

from __future__ import annotations

import argparse
import bisect
import json
import re
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

AUDIT_PREFIX = "Microsoft-Windows-Kernel-Audit-API-Calls//win:Info,"
PROCESS_OPEN_EVENT_ID = 5
THREAD_OPEN_EVENT_ID = 6
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

CALLER_RE = re.compile(
    r'^Microsoft-Windows-Kernel-Audit-API-Calls//win:Info,\s*'
    r'(?P<timestamp_us>\d+),\s*"(?P<name>[^"]+)"\s*'
    r'\(\s*(?P<pid>\d+)\),\s*(?P<thread_id>\d+),\s*(?P<cpu>\d+),'
)
TARGET_PROCESS_RE = re.compile(r'"TargetProcessId\s*:\s*(\d+)"')
TARGET_THREAD_RE = re.compile(r'"Target(?:Thread|Threat)Id\s*:\s*(\d+)"')
DESIRED_ACCESS_RE = re.compile(r'"DesiredAccess\s*:\s*(0x[0-9A-Fa-f]+|-?\d+)"')
RETURN_CODE_RE = re.compile(r'"ReturnCode\s*:\s*(0x[0-9A-Fa-f]+|-?\d+)"')
TRACE_START_RE = re.compile(r"Trace Start:\s*(\d+)")
TRACE_LENGTH_RE = re.compile(r"Trace Length:\s*(\d+)\s+sec")
SUMMARY_TOTAL_RE = re.compile(r"Total Events\s+Processed\s+(\d+)")
SUMMARY_LOST_RE = re.compile(r"Total Events\s+Lost\s+(\d+)")
SUMMARY_EVENT_RE = re.compile(
    r"\|\s*(\d+)\s+Microsoft-Windows-Kernel-Audit-API-Calls\s+"
    r"(\d+)\s+(\d+)\s+\{e02a841c-75a3-4fa7-afc8-ae09cf9b7f23\}\|",
    re.IGNORECASE,
)
PROCESS_EVENT_RE = re.compile(
    r'^Microsoft-Windows-Kernel-Process/Process(?P<kind>Start|Stop)/'
)
PROCESS_ID_RE = re.compile(r'"ProcessID\s*:[^\r\n]*?\((\d+)\)"')
OB_HANDLE_RE = re.compile(
    r'^\s*Handle(?P<action>Create|Close),\s*(?P<timestamp_us>\d+),\s*'
    r'(?P<name>.*?)\s+\(\s*(?P<pid>\d+)\),\s*(?P<thread_id>\d+),\s*'
    r'(?P<object>0x[0-9A-Fa-f]+),\s*(?P<handle>0x[0-9A-Fa-f]+),\s*Process,'
)
OB_RUNDOWN_RE = re.compile(
    r'^\s*Handle-DCEnd,\s*(?P<timestamp_us>\d+),\s*'
    r'(?P<name>.*?)\s+\(\s*(?P<pid>\d+)\),\s*'
    r'(?P<object>0x[0-9A-Fa-f]+),\s*(?P<handle>0x[0-9A-Fa-f]+),\s*Process,'
)
OB_SUMMARY_EVENT_RE = re.compile(
    r"\|\s*(\d+)\s+Object\s+0\s+"
    r"(TypeDCEnd|HandleDCEnd|CloseHandle|CreateHandle|34)\s+"
    r"\d+\s+\{89497f50-effe-4440-8cf2-ce6b1cdcaca7\}\|",
    re.IGNORECASE,
)
PROCESS_ACCESS_RIGHTS = (
    (0x00000001, "terminate"),
    (0x00000002, "create_thread"),
    (0x00000004, "set_session_id"),
    (0x00000008, "vm_operation"),
    (0x00000010, "vm_read"),
    (0x00000020, "vm_write"),
    (0x00000040, "duplicate_handle"),
    (0x00000080, "create_process"),
    (0x00000100, "set_quota"),
    (0x00000200, "set_information"),
    (0x00000400, "query_information"),
    (0x00000800, "suspend_resume"),
    (0x00001000, "query_limited_information"),
    (0x00002000, "set_limited_information"),
    (0x00010000, "delete"),
    (0x00020000, "read_control"),
    (0x00040000, "write_dac"),
    (0x00080000, "write_owner"),
    (0x00100000, "synchronize"),
    (0x02000000, "maximum_allowed"),
)

THREAD_ACCESS_RIGHTS = (
    (0x00000001, "terminate"),
    (0x00000002, "suspend_resume"),
    (0x00000008, "get_context"),
    (0x00000010, "set_context"),
    (0x00000020, "set_information"),
    (0x00000040, "query_information"),
    (0x00000080, "set_thread_token"),
    (0x00000100, "impersonate"),
    (0x00000200, "direct_impersonation"),
    (0x00000400, "set_limited_information"),
    (0x00000800, "query_limited_information"),
    (0x00001000, "resume"),
    (0x00010000, "delete"),
    (0x00020000, "read_control"),
    (0x00040000, "write_dac"),
    (0x00080000, "write_owner"),
    (0x00100000, "synchronize"),
    (0x02000000, "maximum_allowed"),
)


@dataclass(frozen=True)
class AuditEvent:
    timestamp_us: int
    caller_pid: int
    caller_name: str
    caller_thread_id: int
    target_pid: int
    target_thread_id: int | None
    desired_access: int
    return_code: int

    @property
    def event_id(self) -> int:
        return THREAD_OPEN_EVENT_ID if self.target_thread_id is not None else PROCESS_OPEN_EVENT_ID


@dataclass(frozen=True)
class ObHandleEvent:
    action: str
    timestamp_us: int
    owner_pid: int
    owner_name: str
    thread_id: int | None
    object_pointer: str
    handle: int


def parse_integer(value: str) -> int:
    return int(value, 0)


def decode_access(mask: int, kind: str = "process") -> list[str]:
    rights = PROCESS_ACCESS_RIGHTS if kind == "process" else THREAD_ACCESS_RIGHTS
    return [name for bit, name in rights if mask & bit]


def mask_row(mask: int, count: int, kind: str = "process") -> dict[str, Any]:
    return {
        "mask": f"0x{mask:08X}",
        "decimal": mask,
        "rights": decode_access(mask, kind),
        "count": count,
    }


def parse_audit_line(line: str) -> AuditEvent | None:
    if not line.startswith(AUDIT_PREFIX):
        return None
    caller = CALLER_RE.match(line)
    target = TARGET_PROCESS_RE.search(line)
    desired = DESIRED_ACCESS_RE.search(line)
    result = RETURN_CODE_RE.search(line)
    if not (caller and target and desired and result):
        return None
    thread = TARGET_THREAD_RE.search(line)
    return AuditEvent(
        timestamp_us=int(caller.group("timestamp_us")),
        caller_pid=int(caller.group("pid")),
        caller_name=caller.group("name"),
        caller_thread_id=int(caller.group("thread_id")),
        target_pid=int(target.group(1)),
        target_thread_id=int(thread.group(1)) if thread else None,
        desired_access=parse_integer(desired.group(1)),
        return_code=parse_integer(result.group(1)),
    )


def parse_trace_header(path: Path) -> tuple[datetime, int | None]:
    trace_start: datetime | None = None
    trace_length: int | None = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle):
            if match := TRACE_START_RE.search(line):
                ticks = int(match.group(1))
                trace_start = FILETIME_EPOCH + timedelta(microseconds=ticks / 10)
            if match := TRACE_LENGTH_RE.search(line):
                trace_length = int(match.group(1))
            if trace_start is not None and line_number > 100:
                break
    if trace_start is None:
        raise ValueError(f"could not find Trace Start FILETIME in {path}")
    return trace_start, trace_length


def parse_audit_summary(path: Path) -> dict[str, Any]:
    total = None
    lost = None
    event_ids: dict[str, dict[str, int]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if match := SUMMARY_TOTAL_RE.search(line):
            total = int(match.group(1))
        if match := SUMMARY_LOST_RE.search(line):
            lost = int(match.group(1))
        if match := SUMMARY_EVENT_RE.search(line):
            count, event_id, version = map(int, match.groups())
            event_ids[str(event_id)] = {"count": count, "version": version}
    return {"total_events": total, "events_lost": lost, "event_ids": event_ids}


def parse_ob_summary(path: Path) -> dict[str, Any]:
    total = None
    lost = None
    events: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if match := SUMMARY_TOTAL_RE.search(line):
            total = int(match.group(1))
        if match := SUMMARY_LOST_RE.search(line):
            lost = int(match.group(1))
        if match := OB_SUMMARY_EVENT_RE.search(line):
            count, opcode = match.groups()
            events[opcode] = int(count)
    return {"total_events": total, "events_lost": lost, "object_events": events}


def iter_target_events(path: Path, target_pid: int) -> Iterable[AuditEvent]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if f'"TargetProcessId : {target_pid}"' not in line:
                continue
            event = parse_audit_line(line)
            if event is not None and event.target_pid == target_pid:
                yield event


def parse_ob_process_handles(path: Path) -> list[ObHandleEvent]:
    events: list[ObHandleEvent] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if ", Process," not in line:
                continue
            match = OB_HANDLE_RE.match(line)
            if match:
                events.append(
                    ObHandleEvent(
                        action=match.group("action").lower(),
                        timestamp_us=int(match.group("timestamp_us")),
                        owner_pid=int(match.group("pid")),
                        owner_name=match.group("name").strip(),
                        thread_id=int(match.group("thread_id")),
                        object_pointer=match.group("object").upper(),
                        handle=int(match.group("handle"), 16),
                    )
                )
                continue
            match = OB_RUNDOWN_RE.match(line)
            if match:
                events.append(
                    ObHandleEvent(
                        action="rundown",
                        timestamp_us=int(match.group("timestamp_us")),
                        owner_pid=int(match.group("pid")),
                        owner_name=match.group("name").strip(),
                        thread_id=None,
                        object_pointer=match.group("object").upper(),
                        handle=int(match.group("handle"), 16),
                    )
                )
    return events


def basename_nt_path(value: str) -> str:
    return value.replace("/", "\\").rsplit("\\", 1)[-1]


def parse_process_names(path: Path) -> dict[int, str]:
    names: dict[int, str] = {}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not PROCESS_EVENT_RE.match(line):
                continue
            pid_match = PROCESS_ID_RE.search(line)
            marker = '"ImageName : \\"'
            marker_index = line.rfind(marker)
            if not pid_match or marker_index < 0:
                continue
            image_start = marker_index + len(marker)
            image_end = line.find('\\""', image_start)
            if image_end < 0:
                continue
            names[int(pid_match.group(1))] = basename_nt_path(line[image_start:image_end])
    return names


def parse_preflight_names(path: Path) -> dict[int, str]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    rows = list(payload.get("process_inventory", [])) + list(payload.get("processes", []))
    return {
        int(row["ProcessId"]): str(row["Name"])
        for row in rows
        if row.get("ProcessId") is not None and row.get("Name")
    }


def parse_pid_names(values: Iterable[str]) -> dict[int, str]:
    result: dict[int, str] = {}
    for value in values:
        pid, separator, name = value.partition("=")
        if not separator or not pid.isdecimal() or not name:
            raise ValueError(f"invalid --pid-name value {value!r}; expected PID=name")
        result[int(pid)] = basename_nt_path(name)
    return result


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_handle_snapshots(path: Path) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    metadata = None
    baseline = None
    deltas: list[dict[str, Any]] = []
    summary = None
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            kind = record.get("type")
            if kind == "metadata":
                metadata = record
            elif kind == "baseline":
                baseline = record
            elif kind == "delta":
                deltas.append(record)
            elif kind == "summary":
                summary = record
    if metadata is None or baseline is None or summary is None:
        raise ValueError(f"incomplete handle snapshot stream: {path}")
    return metadata, baseline, deltas, summary


def normalize_handle(value: int) -> int:
    # Kernel handles appear in OB events with bit 31 set, while
    # SystemExtendedHandleInformation reports the table-local value.
    return value & 0x7FFFFFFF if value & 0x80000000 else value


def final_snapshot_rows(
    baseline: dict[str, Any], deltas: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    state = {
        (int(row["owner_pid"]), int(row["handle"], 16)): row
        for row in baseline["entries"]
    }
    for delta in deltas:
        for row in delta.get("removed", []):
            state.pop((int(row["owner_pid"]), int(row["handle"], 16)), None)
        for change in delta.get("changed", []):
            before = change["before"]
            after = change["after"]
            state.pop((int(before["owner_pid"]), int(before["handle"], 16)), None)
            state[(int(after["owner_pid"]), int(after["handle"], 16))] = after
        for row in delta.get("added", []):
            state[(int(row["owner_pid"]), int(row["handle"], 16))] = row
    return list(state.values())


def summarize_masks(counter: Counter[int], kind: str = "process") -> list[dict[str, Any]]:
    return [
        mask_row(mask, count, kind)
        for mask, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    ]


def caller_rows(
    events: list[AuditEvent], names: dict[int, str], kind: str
) -> list[dict[str, Any]]:
    grouped: dict[int, list[AuditEvent]] = defaultdict(list)
    for event in events:
        grouped[event.caller_pid].append(event)
    rows = []
    for pid, values in grouped.items():
        masks = Counter(event.desired_access for event in values)
        results = Counter(event.return_code for event in values)
        rows.append(
            {
                "caller_pid": pid,
                "caller_name": names.get(pid, values[0].caller_name),
                "event_count": len(values),
                "successful_events": results.get(0, 0),
                "desired_access": summarize_masks(masks, kind),
                "return_codes": [
                    {"code": f"0x{code & 0xFFFFFFFF:08X}", "decimal": code, "count": count}
                    for code, count in sorted(results.items(), key=lambda item: (-item[1], item[0]))
                ],
            }
        )
    return sorted(rows, key=lambda row: (-row["event_count"], row["caller_pid"]))


def summarize_handle_activity(
    metadata: dict[str, Any],
    baseline: dict[str, Any],
    deltas: list[dict[str, Any]],
    summary: dict[str, Any],
    opener_pids: set[int],
    target_pid: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    state: dict[tuple[int, str], dict[str, Any]] = {
        (int(row["owner_pid"]), row["handle"]): row for row in baseline["entries"]
    }
    baseline_rows = list(state.values())
    opener_added = Counter()
    opener_removed = Counter()
    timeline: list[dict[str, Any]] = []
    for delta in deltas:
        for row in delta.get("removed", []):
            owner = int(row["owner_pid"])
            state.pop((owner, row["handle"]), None)
            if owner in opener_pids:
                opener_removed[owner] += 1
        for change in delta.get("changed", []):
            before = change["before"]
            after = change["after"]
            state.pop((int(before["owner_pid"]), before["handle"]), None)
            state[(int(after["owner_pid"]), after["handle"])] = after
        additions = []
        for row in delta.get("added", []):
            owner = int(row["owner_pid"])
            state[(owner, row["handle"])] = row
            if owner in opener_pids:
                opener_added[owner] += 1
                additions.append(row)
        if additions:
            timeline.append({"captured_utc": delta["captured_utc"], "added": additions})

    pointer_rows = baseline_rows + [row for delta in deltas for row in delta.get("added", [])]
    nonzero_pointers = sum(int(row["object"], 16) != 0 for row in pointer_rows)
    target_baseline = [row for row in baseline_rows if int(row["owner_pid"]) == target_pid]
    target_final = [row for row in state.values() if int(row["owner_pid"]) == target_pid]
    opener_activity = [
        {
            "caller_pid": pid,
            "added_process_handles": opener_added[pid],
            "removed_process_handles": opener_removed[pid],
        }
        for pid in sorted(opener_pids)
        if opener_added[pid] or opener_removed[pid]
    ]
    return (
        {
            "process_object_type_index": metadata["process_object_type_index"],
            "interval_seconds": metadata["interval_seconds"],
            "snapshot_count": summary["snapshot_count"],
            "baseline_process_handle_count": len(baseline_rows),
            "final_process_handle_count": summary["final_process_handle_count"],
            "added_entries": summary["added_entries"],
            "removed_entries": summary["removed_entries"],
            "changed_entries": summary["changed_entries"],
            "observed_pointer_rows": len(pointer_rows),
            "nonzero_pointer_rows": nonzero_pointers,
            "target_owned_process_handles_at_baseline": len(target_baseline),
            "target_owned_process_handles_at_end": len(target_final),
            "target_owned_note": (
                "These are process-object handles owned by the target process; "
                "they are not necessarily handles referring to the target itself."
            ),
            "target_opener_handle_activity": opener_activity,
        },
        timeline,
        baseline_rows,
    )


def correlate_temporally(
    process_events: list[AuditEvent],
    trace_start: datetime,
    timeline: list[dict[str, Any]],
    interval_seconds: float,
    names: dict[int, str],
    baseline_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    events_by_pid: dict[int, list[AuditEvent]] = defaultdict(list)
    for event in process_events:
        if event.return_code == 0:
            events_by_pid[event.caller_pid].append(event)

    object_support: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "windows": 0,
            "owners": set(),
            "granted_access": Counter(),
            "event_candidates": 0,
        }
    )
    candidate_additions = 0
    uniquely_paired_additions = 0
    exact_mask_single_event_candidates = []
    excluded_system_additions = 0
    window_us = int(interval_seconds * 1_000_000)
    for delta in timeline:
        delta_us = int((parse_datetime(delta["captured_utc"]) - trace_start).total_seconds() * 1_000_000)
        lower = delta_us - window_us
        for row in delta["added"]:
            owner = int(row["owner_pid"])
            candidates = [
                event
                for event in events_by_pid.get(owner, [])
                if lower <= event.timestamp_us <= delta_us
            ]
            if not candidates:
                continue
            candidate_additions += 1
            if len(candidates) == 1:
                uniquely_paired_additions += 1
            granted_access = int(row["granted_access"], 16)
            same_mask = [event for event in candidates if event.desired_access == granted_access]
            if len(same_mask) == 1:
                match = same_mask[0]
                exact_mask_single_event_candidates.append(
                    {
                        "_object": row["object"],
                        "caller_pid": owner,
                        "caller_name": names.get(owner, match.caller_name),
                        "requested_and_sampled_mask": f"0x{granted_access:08X}",
                        "rights": decode_access(granted_access),
                        "candidate_events_in_window": len(candidates),
                        "matching_mask_events_in_window": 1,
                        "sample_lag_ms": round((delta_us - match.timestamp_us) / 1000, 3),
                    }
                )
            if owner == 4:
                excluded_system_additions += 1
                continue
            object_key = row["object"]
            support = object_support[object_key]
            support["windows"] += 1
            support["owners"].add(owner)
            support["granted_access"][int(row["granted_access"], 16)] += 1
            support["event_candidates"] += len(candidates)

    ranked = sorted(
        object_support.items(),
        key=lambda item: (-item[1]["windows"], -len(item[1]["owners"]), item[0]),
    )
    aliases = []
    for index, (pointer, support) in enumerate(ranked[:10], start=1):
        aliases.append(
            {
                "alias": f"candidate-object-{index}",
                "supporting_snapshot_windows": support["windows"],
                "distinct_owner_pids": len(support["owners"]),
                "owner_names": sorted({names.get(pid, "Unknown") for pid in support["owners"]}),
                "candidate_audit_events_in_windows": support["event_candidates"],
                "sampled_granted_access": summarize_masks(support["granted_access"]),
            }
        )
    selected_pointer = None
    if len(exact_mask_single_event_candidates) == 1:
        selected_pointer = exact_mask_single_event_candidates[0]["_object"]
    selected_summary: dict[str, Any]
    if selected_pointer is None:
        selected_summary = {
            "status": "unresolved",
            "reason": "No unique single-matching-mask temporal candidate was available.",
        }
    else:
        selected_rows = [row for row in baseline_rows if row["object"] == selected_pointer]
        owners: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for row in selected_rows:
            owners[int(row["owner_pid"])].append(row)
        selected_summary = {
            "status": "high-confidence-temporal-inference",
            "basis": (
                "One target-opening caller had exactly one requested-access event matching "
                "one newly sampled granted-access mask in the snapshot window."
            ),
            "baseline_handle_count": len(selected_rows),
            "baseline_distinct_owners": len(owners),
            "baseline_owners": [
                {
                    "owner_pid": owner,
                    "owner_name": names.get(owner, "Unknown"),
                    "handle_count": len(rows),
                    "granted_access": summarize_masks(
                        Counter(int(row["granted_access"], 16) for row in rows)
                    ),
                }
                for owner, rows in sorted(owners.items())
            ],
            "literal_hiding_observation": (
                "The inferred target object and external handles to it were visible in the "
                "elevated system handle table. This contradicts universal literal hiding, "
                "but does not resolve selective callback allowlisting or access stripping."
            ),
            "identity_limit": (
                "The provider records NTSTATUS but not the returned handle value. Object identity "
                "is therefore a high-confidence temporal inference, not an exact join."
            ),
        }
    public_exact_candidates = [
        {key: value for key, value in row.items() if key != "_object"}
        for row in exact_mask_single_event_candidates
    ]

    return {
        "method": (
            "For each newly sampled process handle owned by a target-opening caller, "
            "look backward one snapshot interval for successful PsOpenProcess events "
            "from that caller to the target."
        ),
        "candidate_added_handles": candidate_additions,
        "single_event_window_additions": uniquely_paired_additions,
        "system_pid_4_candidate_additions_excluded_from_object_ranking": excluded_system_additions,
        "single_matching_mask_candidates": public_exact_candidates,
        "candidate_objects": aliases,
        "target_object_inference": selected_summary,
        "evidentiary_limit": (
            "Temporal candidates are not exact handle-event joins: the audit event has "
            "no returned handle value and snapshots are periodic. Requested-versus-granted "
            "differences therefore do not by themselves prove an Ob callback rewrite."
        ),
    }


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * quantile)))
    return ordered[index]


def exact_ob_correlation(
    process_events: list[AuditEvent],
    audit_start: datetime,
    ob_events: list[ObHandleEvent],
    ob_start: datetime,
    baseline: dict[str, Any],
    deltas: list[dict[str, Any]],
    names: dict[int, str],
) -> dict[str, Any]:
    """Join target audit requests to OB handle events by PID, TID, and time.

    The two traces use independent clocks with QPC timestamps, so Xperf exposes
    each event relative to its own FILETIME trace start.  Converting the OB
    timestamp into the audit trace's timeline makes the corresponding
    HandleCreate event land within a few microseconds of event 5.
    """

    offset_us = round((ob_start - audit_start).total_seconds() * 1_000_000)
    creates_by_key: dict[tuple[int, int], list[tuple[int, int, ObHandleEvent]]] = defaultdict(list)
    all_creates = [event for event in ob_events if event.action == "create"]
    for index, event in enumerate(all_creates):
        if event.thread_id is None:
            continue
        aligned = event.timestamp_us + offset_us
        creates_by_key[(event.owner_pid, event.thread_id)].append((aligned, index, event))
    for rows in creates_by_key.values():
        rows.sort(key=lambda row: row[0])

    used: set[int] = set()
    matched: list[tuple[AuditEvent, ObHandleEvent, int]] = []
    unmatched = 0
    match_window_us = 25
    for audit in sorted(process_events, key=lambda event: event.timestamp_us):
        rows = creates_by_key.get((audit.caller_pid, audit.caller_thread_id), [])
        timestamps = [row[0] for row in rows]
        position = bisect.bisect_left(timestamps, audit.timestamp_us)
        candidates = []
        for candidate_index in range(max(0, position - 4), min(len(rows), position + 5)):
            aligned, global_index, event = rows[candidate_index]
            if global_index in used:
                continue
            delta = aligned - audit.timestamp_us
            if abs(delta) <= match_window_us:
                candidates.append((abs(delta), delta, global_index, event))
        if not candidates:
            unmatched += 1
            continue
        _, delta, global_index, event = min(candidates, key=lambda row: (row[0], row[2]))
        used.add(global_index)
        matched.append((audit, event, delta))

    object_counts = Counter(event.object_pointer for _, event, _ in matched)
    if not object_counts:
        return {
            "status": "unresolved",
            "matched_audit_events": 0,
            "unmatched_audit_events": unmatched,
            "reason": "No same-PID/thread HandleCreate event fell within 25 microseconds.",
        }
    target_object, target_object_matches = object_counts.most_common(1)[0]
    target_matches = [row for row in matched if row[1].object_pointer == target_object]
    deltas_us = [float(delta) for _, _, delta in target_matches]
    dominant_ratio = target_object_matches / len(matched)

    target_creates = [
        event
        for event in ob_events
        if event.action == "create" and event.object_pointer == target_object
    ]
    target_closes = [
        event
        for event in ob_events
        if event.action == "close" and event.object_pointer == target_object
    ]
    close_queues: dict[tuple[int, int], list[ObHandleEvent]] = defaultdict(list)
    for event in target_closes:
        close_queues[(event.owner_pid, normalize_handle(event.handle))].append(event)
    for queue in close_queues.values():
        queue.sort(key=lambda event: event.timestamp_us)
    lifetimes: list[float] = []
    for create in sorted(target_creates, key=lambda event: event.timestamp_us):
        key = (create.owner_pid, normalize_handle(create.handle))
        queue = close_queues.get(key, [])
        while queue and queue[0].timestamp_us < create.timestamp_us:
            queue.pop(0)
        if queue:
            close = queue.pop(0)
            lifetimes.append(float(close.timestamp_us - create.timestamp_us))

    baseline_rows = [
        row for row in baseline["entries"] if row["object"].upper() == target_object
    ]
    final_rows = [
        row for row in final_snapshot_rows(baseline, deltas) if row["object"].upper() == target_object
    ]
    rundown_events = [
        event
        for event in ob_events
        if event.action == "rundown" and event.object_pointer == target_object
    ]
    final_keys = {
        (int(row["owner_pid"]), int(row["handle"], 16)) for row in final_rows
    }
    rundown_keys = {
        (event.owner_pid, normalize_handle(event.handle)) for event in rundown_events
    }

    access_index: dict[tuple[int, int, str], Counter[int]] = defaultdict(Counter)
    observed_rows = list(baseline["entries"])
    for delta in deltas:
        observed_rows.extend(delta.get("added", []))
        observed_rows.extend(delta.get("removed", []))
        for change in delta.get("changed", []):
            observed_rows.extend((change["before"], change["after"]))
    for row in observed_rows:
        access_index[
            (
                int(row["owner_pid"]),
                int(row["handle"], 16),
                row["object"].upper(),
            )
        ][int(row["granted_access"], 16)] += 1

    exact_pairs = Counter()
    pair_callers: dict[tuple[int, int, int], Counter[str]] = defaultdict(Counter)
    for audit, event, _ in target_matches:
        key = (event.owner_pid, normalize_handle(event.handle), target_object)
        for granted, observations in access_index.get(key, {}).items():
            pair = (audit.desired_access, granted)
            exact_pairs[pair] += 1
            pair_callers[pair][names.get(event.owner_pid, event.owner_name)] += observations

    owner_rows: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in baseline_rows:
        owner_rows[int(row["owner_pid"])].append(row)
    baseline_owners = [
        {
            "owner_pid": owner,
            "owner_name": names.get(owner, "Unknown"),
            "handle_count": len(rows),
            "granted_access": summarize_masks(
                Counter(int(row["granted_access"], 16) for row in rows)
            ),
        }
        for owner, rows in sorted(owner_rows.items())
    ]

    exact_pair_rows = []
    for (requested, granted), count in sorted(
        exact_pairs.items(), key=lambda item: (-item[1], item[0])
    ):
        exact_pair_rows.append(
            {
                "requested": mask_row(requested, count),
                "granted": mask_row(granted, count),
                "same_mask": requested == granted,
                "caller_names": sorted(pair_callers[(requested, granted)]),
            }
        )

    status = (
        "exact-event-correlation"
        if target_object_matches >= 10 and dominant_ratio >= 0.99
        else "partial-event-correlation"
    )
    return {
        "status": status,
        "method": (
            "Event 5 and HandleCreate were matched on caller PID, caller thread ID, "
            "and an aligned timestamp within 25 microseconds. The dominant Object "
            "value is then joined directly to SystemExtendedHandleInformation rows."
        ),
        "audit_trace_to_ob_trace_offset_us": offset_us,
        "matched_audit_events": len(matched),
        "unmatched_audit_events": unmatched,
        "dominant_target_object_matches": target_object_matches,
        "dominant_target_object_ratio": dominant_ratio,
        "match_delta_us": {
            "min": min(deltas_us),
            "median": statistics.median(deltas_us),
            "p95_absolute": percentile([abs(value) for value in deltas_us], 0.95),
            "max": max(deltas_us),
        },
        "target_object_alias": "cod-process-object",
        "target_object_pointer_published": False,
        "target_handle_events": {
            "create_count": len(target_creates),
            "close_count": len(target_closes),
            "paired_lifetime_count": len(lifetimes),
            "lifetime_us": {
                "median": statistics.median(lifetimes) if lifetimes else None,
                "p95": percentile(lifetimes, 0.95),
                "max": max(lifetimes) if lifetimes else None,
            },
        },
        "persistent_handles": {
            "snapshot_baseline_count": len(baseline_rows),
            "snapshot_final_count": len(final_rows),
            "ob_rundown_count": len(rundown_events),
            "final_snapshot_rundown_tuple_overlap": len(final_keys & rundown_keys),
            "baseline_distinct_owners": len(owner_rows),
            "baseline_owners": baseline_owners,
        },
        "exact_requested_granted_pairs": exact_pair_rows,
        "exact_requested_granted_pair_count": sum(exact_pairs.values()),
        "selective_filtering_assessment": (
            "The target object and its persistent handles are now identified directly. "
            "An exact requested-to-granted claim is made only for rows listed in "
            "exact_requested_granted_pairs; owner-level request/persistent-mask patterns "
            "remain corroboration, not a handle-specific causal join."
        ),
    }


def aggregate_named_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "event_count": 0,
            "successful_events": 0,
            "desired_access": Counter(),
            "return_codes": Counter(),
        }
    )
    for row in rows:
        target = grouped[row["caller_name"]]
        target["event_count"] += row["event_count"]
        target["successful_events"] += row["successful_events"]
        for access in row["desired_access"]:
            target["desired_access"][int(access["decimal"])] += int(access["count"])
        for result in row["return_codes"]:
            target["return_codes"][int(result["decimal"])] += int(result["count"])
    return sorted(
        [
            {
                "caller_name": name,
                "event_count": values["event_count"],
                "successful_events": values["successful_events"],
                "desired_access": summarize_masks(values["desired_access"]),
                "return_codes": [
                    {
                        "code": f"0x{code & 0xFFFFFFFF:08X}",
                        "decimal": code,
                        "count": count,
                    }
                    for code, count in sorted(
                        values["return_codes"].items(),
                        key=lambda item: (-item[1], item[0]),
                    )
                ],
            }
            for name, values in grouped.items()
        ],
        key=lambda row: (-row["event_count"], row["caller_name"].lower()),
    )


def aggregate_named_owners(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"handle_count": 0, "granted_access": Counter()}
    )
    for row in rows:
        target = grouped[row["owner_name"]]
        target["handle_count"] += row["handle_count"]
        for access in row["granted_access"]:
            target["granted_access"][int(access["decimal"])] += int(access["count"])
    return sorted(
        [
            {
                "owner_name": name,
                "handle_count": values["handle_count"],
                "granted_access": summarize_masks(values["granted_access"]),
            }
            for name, values in grouped.items()
        ],
        key=lambda row: (-row["handle_count"], row["owner_name"].lower()),
    )


def public_summary(payload: dict[str, Any]) -> dict[str, Any]:
    target_events = payload["target_events"]
    exact_ob = payload.get("exact_ob_correlation")
    public_exact_ob = None
    if exact_ob is not None:
        public_exact_ob = dict(exact_ob)
        persistent = dict(public_exact_ob.get("persistent_handles", {}))
        if "baseline_owners" in persistent:
            persistent["baseline_owners"] = aggregate_named_owners(
                persistent["baseline_owners"]
            )
        public_exact_ob["persistent_handles"] = persistent
    return {
        "schema_version": 1,
        "capture": {
            "date": payload["trace"]["start_utc"][:10],
            "administrator": True,
            "requested_duration_seconds": payload["capture"]["requested_duration_seconds"],
            "trace_length_seconds": payload["trace"]["length_seconds"],
            "capture_phase": payload["capture"]["phase"],
            "decoder_exit_codes": payload["capture"]["decoder_exit_codes"],
            "method": (
                "Two uniquely named user ETW sessions for Kernel Audit API Calls and "
                "Kernel Process, plus elevated SystemExtendedHandleInformation snapshots."
            ),
            "safety": (
                "No handle was opened to cod.exe; no IOCTL, driver/service mutation, "
                "debugger, injection, or process termination was performed."
            ),
            "raw_artifacts_published": False,
        },
        "driver": payload["driver"],
        "trace": payload["trace"],
        "target_process": {
            "name": "cod.exe",
            "process_open_event_id": target_events["process_open_event_id"],
            "thread_open_event_id": target_events["thread_open_event_id"],
            "process_open_count": target_events["process_open_count"],
            "external_process_open_count": target_events["external_process_open_count"],
            "process_open_success_count": target_events["process_open_success_count"],
            "process_open_failure_count": target_events["process_open_failure_count"],
            "thread_open_count": target_events["thread_open_count"],
            "external_thread_open_count": target_events["external_thread_open_count"],
            "thread_open_success_count": target_events["thread_open_success_count"],
            "thread_open_failure_count": target_events["thread_open_failure_count"],
            "process_desired_access": target_events["process_desired_access"],
            "thread_desired_access": target_events["thread_desired_access"],
            "process_open_callers": aggregate_named_rows(
                target_events["process_open_callers"]
            ),
            "thread_open_callers": [
                {key: value for key, value in row.items() if key != "caller_pid"}
                for row in target_events["thread_open_callers"]
            ],
        },
        "process_handle_table": {
            **payload["handle_snapshots"],
            "target_opener_handle_activity": "omitted: transient PIDs are local-only",
            "kernel_object_pointers_visible": True,
            "raw_metadata_published": False,
        },
        "ob_handle_trace": payload.get("ob_handle_trace"),
        "exact_ob_correlation": public_exact_ob,
        "conclusion": payload["conclusion"],
    }


def analyze(args: argparse.Namespace) -> dict[str, Any]:
    trace_start, trace_length = parse_trace_header(args.audit_dump)
    summary = parse_audit_summary(args.audit_summary)
    events = list(iter_target_events(args.audit_dump, args.target_pid))
    process_events = [event for event in events if event.event_id == PROCESS_OPEN_EVENT_ID]
    thread_events = [event for event in events if event.event_id == THREAD_OPEN_EVENT_ID]

    names = parse_process_names(args.process_dump)
    names.update(parse_preflight_names(args.preflight))
    names.update(parse_pid_names(args.pid_name))
    names.setdefault(4, "System")

    preflight = load_json(args.preflight)
    capture_status = load_json(args.capture_status)
    if capture_status.get("phase") != "complete":
        raise ValueError(
            f"capture status is {capture_status.get('phase')!r}, not 'complete'"
        )
    decoder_keys = [
        "audit_xperf_dump_exit_code",
        "audit_tracerpt_exit_code",
        "process_xperf_dump_exit_code",
        "process_tracerpt_exit_code",
    ]
    if "ob_xperf_dump_exit_code" in capture_status:
        decoder_keys.extend(("ob_xperf_dump_exit_code", "ob_tracerpt_exit_code"))
    decoder_exit_codes = {key: int(capture_status[key]) for key in decoder_keys}
    if any(decoder_exit_codes.values()):
        raise ValueError(f"one or more ETL decoders failed: {decoder_exit_codes}")

    metadata, baseline, deltas, handle_summary = load_handle_snapshots(args.handle_snapshots)
    opener_pids = {event.caller_pid for event in process_events}
    handles, timeline, baseline_rows = summarize_handle_activity(
        metadata, baseline, deltas, handle_summary, opener_pids, args.target_pid
    )
    correlation = correlate_temporally(
        process_events,
        trace_start,
        timeline,
        float(metadata["interval_seconds"]),
        names,
        baseline_rows,
    )

    ob_trace = None
    exact_ob = None
    if args.ob_dump is not None or args.ob_summary is not None:
        if args.ob_dump is None or args.ob_summary is None:
            raise ValueError("--ob-dump and --ob-summary must be supplied together")
        ob_start, ob_length = parse_trace_header(args.ob_dump)
        ob_events = parse_ob_process_handles(args.ob_dump)
        ob_trace = {
            "start_utc": ob_start.isoformat(),
            "length_seconds": ob_length,
            **parse_ob_summary(args.ob_summary),
            "parsed_process_handle_events": len(ob_events),
        }
        exact_ob = exact_ob_correlation(
            process_events,
            trace_start,
            ob_events,
            ob_start,
            baseline,
            deltas,
            names,
        )

    process_masks = Counter(event.desired_access for event in process_events)
    process_results = Counter(event.return_code for event in process_events)
    thread_masks = Counter(event.desired_access for event in thread_events)
    thread_results = Counter(event.return_code for event in thread_events)

    exact_identity = bool(
        exact_ob and exact_ob.get("status") == "exact-event-correlation"
    )
    result = {
        "schema_version": 1,
        "analysis": "Randgrid elevated passive runtime correlation",
        "target_pid": args.target_pid,
        "capture": {
            "phase": capture_status["phase"],
            "requested_duration_seconds": int(preflight["trace"]["duration_seconds"]),
            "decoder_exit_codes": decoder_exit_codes,
        },
        "driver": preflight["driver"],
        "trace": {
            "start_utc": trace_start.isoformat(),
            "length_seconds": trace_length,
            **summary,
        },
        "target_events": {
            "process_open_event_id": PROCESS_OPEN_EVENT_ID,
            "thread_open_event_id": THREAD_OPEN_EVENT_ID,
            "process_open_count": len(process_events),
            "thread_open_count": len(thread_events),
            "external_process_open_count": sum(
                event.caller_pid != args.target_pid for event in process_events
            ),
            "external_thread_open_count": sum(
                event.caller_pid != args.target_pid for event in thread_events
            ),
            "process_open_success_count": process_results.get(0, 0),
            "process_open_failure_count": len(process_events) - process_results.get(0, 0),
            "thread_open_success_count": thread_results.get(0, 0),
            "thread_open_failure_count": len(thread_events) - thread_results.get(0, 0),
            "process_desired_access": summarize_masks(process_masks, "process"),
            "thread_desired_access": summarize_masks(thread_masks, "thread"),
            "process_open_callers": caller_rows(process_events, names, "process"),
            "thread_open_callers": caller_rows(thread_events, names, "thread"),
        },
        "handle_snapshots": handles,
        "temporal_correlation": correlation,
        "conclusion": {
            "object_callback_registration_proved_statically": True,
            "naturally_occurring_process_open_requests_observed": bool(process_events),
            "target_process_object_identified_at_runtime": exact_identity,
            "universal_literal_handle_hiding_supported": False if exact_identity else None,
            "runtime_access_stripping_proved": False,
            "runtime_access_stripping_disproved": False,
            "reason": (
                "Exact audit/OB correlation identifies the target process object and exposes external "
                "handles, contradicting universal literal hiding. Selective callback rewriting is "
                "proved only if an exact returned-handle snapshot shows a requested/granted change; "
                "owner-level patterns alone remain corroboration."
                if exact_identity
                else "The trace proves requests and outcomes, while periodic snapshots prove actual "
                "masks, but no exact target-object correlation was completed."
            ),
        },
    }
    if ob_trace is not None:
        result["ob_handle_trace"] = ob_trace
    if exact_ob is not None:
        result["exact_ob_correlation"] = exact_ob
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-dump", type=Path, required=True)
    parser.add_argument("--audit-summary", type=Path, required=True)
    parser.add_argument("--process-dump", type=Path, required=True)
    parser.add_argument("--ob-dump", type=Path)
    parser.add_argument("--ob-summary", type=Path)
    parser.add_argument("--handle-snapshots", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--capture-status", type=Path, required=True)
    parser.add_argument("--target-pid", type=int, required=True)
    parser.add_argument("--pid-name", action="append", default=[], metavar="PID=NAME")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    payload = analyze(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(args.output)
    if args.public_output is not None:
        args.public_output.parent.mkdir(parents=True, exist_ok=True)
        args.public_output.write_text(
            json.dumps(public_summary(payload), indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(args.public_output)


if __name__ == "__main__":
    main()
