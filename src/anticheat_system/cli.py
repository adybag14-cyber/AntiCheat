"""Command-line interface for passive snapshots and bounded monitor runs."""

from __future__ import annotations

import argparse
import errno
import json
import math
import os
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .chain import seal_record, verify_record
from .errors import ProbeError
from .linux import LinuxProcfsBackend

DEFAULT_SNAPSHOT = Path("local-analysis/linux-system-snapshot.json")
DEFAULT_MONITOR = Path("local-analysis/linux-system-monitor.jsonl")
MAX_MONITOR_RECORD_CHARACTERS = 64 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anticheat-system",
        description=(
            "Passive Linux process metadata capture for defensive systems research. "
            "No ptrace, process-memory access, kernel instrumentation, or target-state "
            "writes are used."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser(
        "snapshot", help="capture one consistent process snapshot"
    )
    _add_selector(snapshot)
    _add_capture_options(snapshot)
    snapshot.add_argument("--out", type=Path, default=DEFAULT_SNAPSHOT)
    snapshot.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output file (never implied)",
    )

    monitor = subparsers.add_parser(
        "monitor", help="capture a bounded hash-chained JSON Lines sequence"
    )
    _add_selector(monitor)
    _add_capture_options(monitor)
    monitor.add_argument("--out", type=Path, default=DEFAULT_MONITOR)
    monitor.add_argument("--samples", type=int, default=10)
    monitor.add_argument("--interval", type=float, default=1.0)
    monitor.add_argument(
        "--force",
        action="store_true",
        help="replace an existing monitor file (never implied)",
    )

    verify = subparsers.add_parser(
        "verify-chain", help="verify ordering and hashes in a monitor JSONL file"
    )
    verify.add_argument("path", type=Path)
    return parser


def _add_selector(parser: argparse.ArgumentParser) -> None:
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--pid", type=int)
    selector.add_argument("--name")
    selector.add_argument("--self", action="store_true", dest="self_process")


def _add_capture_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--privacy-mode",
        choices=("aggregate", "local"),
        default="aggregate",
        help="aggregate omits PID, UID/GID, executable path, and mapped-file basenames",
    )
    parser.add_argument(
        "--hash-executable",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="hash the already-open target executable for an identity anchor",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-chain":
            result = verify_chain_file(args.path)
            print(json.dumps(result, sort_keys=True))
            return 0

        backend = LinuxProcfsBackend()
        pid = backend.resolve_pid(
            pid=args.pid,
            name=args.name,
            self_process=args.self_process,
        )
        if args.command == "snapshot":
            payload = backend.capture(
                pid,
                privacy_mode=args.privacy_mode,
                hash_executable=args.hash_executable,
            )
            _write_json_atomic(args.out, payload, force=args.force)
            if args.out != Path("-"):
                print(
                    json.dumps(
                        {
                            "status": "ok",
                            "output": str(args.out),
                            "highest_signal_severity": payload["summary"][
                                "highest_signal_severity"
                            ],
                        },
                        sort_keys=True,
                    )
                )
            return 0

        if args.command == "monitor":
            if args.samples <= 0:
                parser.error("--samples must be positive; monitor runs are bounded")
            if args.interval < 0:
                parser.error("--interval cannot be negative")
            if args.out == Path("-"):
                parser.error(
                    "monitor output must be a file so each record can be fsynced"
                )
            terminal_hash = _run_monitor(
                backend,
                pid,
                output=args.out,
                samples=args.samples,
                interval=args.interval,
                privacy_mode=args.privacy_mode,
                hash_executable=args.hash_executable,
                force=args.force,
            )
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "output": str(args.out),
                        "records": args.samples,
                        "terminal_sha256": terminal_hash,
                    },
                    sort_keys=True,
                )
            )
            return 0
    except ProbeError as error:
        print(
            json.dumps({"status": "error", "code": error.code, "message": str(error)}),
            file=sys.stderr,
        )
        return 2
    except FileExistsError as error:
        print(
            json.dumps(
                {
                    "status": "error",
                    "code": "output_exists",
                    "message": f"output exists: {error.filename}; pass --force to replace it",
                }
            ),
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(
            json.dumps(
                {"status": "error", "code": "capture_failed", "message": str(error)}
            ),
            file=sys.stderr,
        )
        return 3
    return 3


def _write_json_atomic(path: Path, payload: dict[str, Any], *, force: bool) -> None:
    if path == Path("-"):
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise FileExistsError(errno.EEXIST, "output exists", str(path))
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(temporary_path, path)
        else:
            # A hard-link publish is atomic and cannot replace a concurrently
            # created target. The temporary file is in the same directory.
            try:
                os.link(temporary_path, path)
            except FileExistsError as error:
                raise FileExistsError(
                    errno.EEXIST, "output exists", str(path)
                ) from error
            temporary_path.unlink()
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _run_monitor(
    backend: LinuxProcfsBackend,
    pid: int,
    *,
    output: Path,
    samples: int,
    interval: float,
    privacy_mode: str,
    hash_executable: bool,
    force: bool,
) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if force else "x"
    previous_hash: str | None = None
    next_deadline = time.monotonic()
    with output.open(mode, encoding="utf-8", newline="\n") as stream:
        for sequence in range(samples):
            if sequence:
                next_deadline += interval
                delay = next_deadline - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            payload = backend.capture(
                pid,
                privacy_mode=privacy_mode,
                hash_executable=hash_executable,
            )
            payload["monitor"] = {
                "planned_sample_count": samples,
                "sample_sequence": sequence,
                "interval_seconds": interval,
            }
            record = seal_record(
                sequence=sequence,
                previous_sha256=previous_hash,
                payload=payload,
            )
            stream.write(json.dumps(record, sort_keys=True, allow_nan=False))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            previous_hash = record["record_sha256"]
    assert previous_hash is not None
    return previous_hash


def verify_chain_file(path: Path) -> dict[str, Any]:
    previous_hash: str | None = None
    record_count = 0
    planned_sample_count: int | None = None
    planned_interval: float | int | None = None
    with path.open("r", encoding="utf-8") as stream:
        line_number = 0
        while True:
            line = stream.readline(MAX_MONITOR_RECORD_CHARACTERS + 1)
            if not line:
                break
            line_number += 1
            if len(line) > MAX_MONITOR_RECORD_CHARACTERS:
                raise ValueError(f"record exceeds size limit at line {line_number}")
            if not line.endswith("\n"):
                raise ValueError(f"unterminated record at line {line_number}")
            if not line.strip():
                raise ValueError(f"blank record at line {line_number}")
            record = json.loads(line)
            if not isinstance(record, dict) or not verify_record(
                record,
                expected_sequence=record_count,
                previous_sha256=previous_hash,
            ):
                raise ValueError(f"invalid record at line {line_number}")
            payload = record.get("payload")
            monitor = payload.get("monitor") if isinstance(payload, dict) else None
            interval = (
                monitor.get("interval_seconds") if isinstance(monitor, dict) else None
            )
            if (
                not isinstance(monitor, dict)
                or monitor.get("sample_sequence") != record_count
                or type(monitor.get("planned_sample_count")) is not int
                or monitor["planned_sample_count"] <= 0
                or isinstance(interval, bool)
                or not isinstance(interval, (int, float))
                or not math.isfinite(interval)
                or interval < 0
            ):
                raise ValueError(f"invalid monitor metadata at line {line_number}")
            if planned_sample_count is None:
                planned_sample_count = monitor["planned_sample_count"]
                planned_interval = interval
            elif monitor["planned_sample_count"] != planned_sample_count:
                raise ValueError(f"monitor plan changed at line {line_number}")
            elif interval != planned_interval:
                raise ValueError(f"monitor interval changed at line {line_number}")
            previous_hash = record["record_sha256"]
            record_count += 1
    if record_count == 0:
        raise ValueError("monitor file contains no records")
    if record_count != planned_sample_count:
        raise ValueError(
            f"incomplete monitor chain: expected {planned_sample_count}, found {record_count}"
        )
    return {
        "status": "ok",
        "record_count": record_count,
        "planned_record_count": planned_sample_count,
        "terminal_sha256": previous_hash,
    }
