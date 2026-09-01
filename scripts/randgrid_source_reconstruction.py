"""Generate a non-operational, source-like static reconstruction of Randgrid.sys.

The full output is a Git-ignored gzip-compressed C-shaped comment stream. It
covers every linear instruction record and every skipdata byte exactly once,
grouped under one deterministic primary entry owner. It is not original source,
not a decompiler claim, and not executable driver logic.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import heapq
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import randgrid_full_map as full_map

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
ROOT = SCRIPT_DIRECTORY.parent
DEFAULT_OUTPUT_DIRECTORY = ROOT / "analysis" / "randgrid-source-reconstruction"
DEFAULT_EXAMPLE = ROOT / "examples" / "randgrid-source-reconstruction.c"
DEFAULT_SUMMARY = ROOT / "evidence" / "randgrid-source-reconstruction-summary.json"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(16 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.name


def safe_comment(value: Any) -> str:
    return str(value).replace("*/", "* /").replace("\r", " ").replace("\n", " ")


def c_identifier(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"rg_{cleaned}"
    return cleaned


def parse_hex(value: str | int) -> int:
    return int(value, 16) if isinstance(value, str) else int(value)


class PrimaryOwnerIndex:
    """Streaming interval index with Ghidra-body precedence."""

    def __init__(
        self,
        entries: list[dict[str, Any]],
        ghidra_rows: list[dict[str, Any]],
    ) -> None:
        ghidra_by_va = {parse_hex(row["entry"]): row for row in ghidra_rows}
        intervals: list[tuple[int, int, int, int, int]] = []
        for entry in entries:
            va = parse_hex(entry["va"])
            end = parse_hex(entry["end_va"])
            if end > va:
                fallback_priority = 1 if entry["entry_kind"] == "unwind_entry" else 2
                intervals.append((va, end, fallback_priority, end - va, va))
            ghidra = ghidra_by_va.get(va)
            if ghidra is not None:
                body_addresses = int(ghidra.get("body_addresses") or 0)
                for start, end in ghidra["_body_ranges"]:
                    span = body_addresses or (end - start)
                    intervals.append((start, end, 0, span, va))
        self.intervals = sorted(intervals, key=lambda row: (row[0], row[1], row[4]))
        self.index = 0
        self.active: list[tuple[int, int, int, int, int]] = []
        self.serial = 0

    def owner(self, address: int) -> int | None:
        while (
            self.index < len(self.intervals)
            and self.intervals[self.index][0] <= address
        ):
            _start, end, priority, span, owner_va = self.intervals[self.index]
            heapq.heappush(self.active, (priority, span, owner_va, end, self.serial))
            self.serial += 1
            self.index += 1
        while self.active and self.active[0][3] <= address:
            heapq.heappop(self.active)
        return self.active[0][2] if self.active else None


def instruction_rows(path: Path) -> Iterator[dict[str, Any]]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        header = handle.readline().rstrip("\n")
        if header != "va\tsize\tbytes\ttext\tsection":
            raise ValueError(f"unexpected instruction dump header: {header!r}")
        for line in handle:
            va, size, raw, text, section = line.rstrip("\n").split("\t", 4)
            yield {
                "kind": "instruction",
                "va": int(va, 16),
                "size": int(size),
                "bytes": raw,
                "text": text,
                "section": section,
            }


def gap_rows(path: Path) -> Iterator[dict[str, Any]]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        header = handle.readline().rstrip("\n")
        if header != "va\tsize\tbytes\tcoarse\tfine\tsection":
            raise ValueError(f"unexpected gap dump header: {header!r}")
        for line in handle:
            va, size, raw, coarse, fine, section = line.rstrip("\n").split("\t", 5)
            yield {
                "kind": "gap",
                "va": int(va, 16),
                "size": int(size),
                "bytes": raw,
                "text": f"{coarse}:{fine}",
                "section": section,
            }


def merge_rows(*iterables: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    heap: list[tuple[int, int, dict[str, Any], Iterator[dict[str, Any]]]] = []
    for ordinal, iterator in enumerate(iterables):
        try:
            row = next(iterator)
        except StopIteration:
            continue
        heapq.heappush(heap, (row["va"], ordinal, row, iterator))
    while heap:
        _, ordinal, row, iterator = heapq.heappop(heap)
        yield row
        try:
            following = next(iterator)
        except StopIteration:
            continue
        heapq.heappush(heap, (following["va"], ordinal, following, iterator))


def write_full_reconstruction(
    *,
    evidence: dict[str, Any],
    ghidra_rows: list[dict[str, Any]],
    instructions: Path,
    gaps: Path,
    output: Path,
) -> dict[str, Any]:
    entries = evidence["entries"]
    entries_by_va = {parse_hex(row["va"]): row for row in entries}
    call_sites_by_va = {parse_hex(row["va"]): row for row in evidence["call_sites"]}
    owner_index = PrimaryOwnerIndex(entries, ghidra_rows)
    part_counts: Counter[int | None] = Counter()
    owner_record_counts: Counter[int | None] = Counter()
    kind_counts: Counter[str] = Counter()
    section_counts: Counter[str] = Counter()
    total_bytes = 0
    total_records = 0
    expected_ranges = sorted(
        (
            parse_hex(section["va"]),
            parse_hex(section["va"]) + int(section["virtual_size"]),
            str(section["name"]),
        )
        for section in evidence["coverage"]["sections"]
    )
    if not expected_ranges:
        raise ValueError("full-map evidence has no executable section ranges")
    range_index = 0
    next_expected_va = expected_ranges[0][0]
    current_key: tuple[int | None, str] | None = None
    block_open = False

    output.parent.mkdir(parents=True, exist_ok=True)
    with full_map.open_deterministic_gzip_text(output) as handle:
        handle.write("/*\n")
        handle.write(" * Randgrid.sys source-like static reconstruction.\n")
        handle.write(" * NOT ORIGINAL SOURCE. NOT EXECUTABLE DRIVER LOGIC.\n")
        handle.write(f" * Input SHA-256: {evidence['input']['sha256']}\n")
        handle.write(f" * Entry candidates: {len(entries)}\n")
        handle.write(f" * Exact IAT call sites: {len(evidence['call_sites'])}\n")
        handle.write(
            " * Each instruction/gap record appears exactly once below as a comment.\n"
        )
        handle.write(" */\n\n")
        for entry in entries:
            handle.write(
                "/* ENTRY "
                f"{entry['va']} {safe_comment(entry['entry_kind'])} "
                f"{safe_comment(entry['entry_confidence'])} {safe_comment(entry['name'])} */\n"
            )
        handle.write("\n")

        for row in merge_rows(instruction_rows(instructions), gap_rows(gaps)):
            while (
                range_index < len(expected_ranges)
                and next_expected_va == expected_ranges[range_index][1]
            ):
                range_index += 1
                if range_index < len(expected_ranges):
                    next_expected_va = expected_ranges[range_index][0]
            if range_index >= len(expected_ranges):
                raise ValueError(
                    f"record {row['va']:#x} is outside the executable section ranges"
                )
            expected_start, expected_end, expected_section = expected_ranges[
                range_index
            ]
            if row["va"] != next_expected_va:
                raise ValueError(
                    "non-contiguous reconstruction: "
                    f"expected {next_expected_va:#x}, got {row['va']:#x}"
                )
            if row["section"] != expected_section:
                raise ValueError(
                    f"record {row['va']:#x} names section {row['section']!r}, "
                    f"expected {expected_section!r}"
                )
            if row["size"] <= 0 or row["va"] + row["size"] > expected_end:
                raise ValueError(
                    f"record {row['va']:#x} crosses executable range "
                    f"{expected_start:#x}-{expected_end:#x}"
                )
            try:
                raw_size = len(bytes.fromhex(row["bytes"]))
            except ValueError as error:
                raise ValueError(f"invalid hex bytes at {row['va']:#x}") from error
            if raw_size != row["size"]:
                raise ValueError(
                    f"record {row['va']:#x} declares {row['size']} bytes, has {raw_size}"
                )
            next_expected_va += row["size"]
            owner_va = owner_index.owner(row["va"])
            key = (owner_va, row["section"])
            if key != current_key:
                if block_open:
                    handle.write("}\n\n")
                part = part_counts[owner_va]
                part_counts[owner_va] += 1
                owner = entries_by_va.get(owner_va) if owner_va is not None else None
                owner_name = owner["name"] if owner else "unowned_executable_bytes"
                function_name = c_identifier(
                    f"rg_{owner_va:X}_{owner_name}_part_{part}"
                    if owner_va is not None
                    else f"rg_unowned_part_{part}"
                )
                handle.write(
                    f"static void {function_name}(void) {{ "
                    f"/* owner={hex(owner_va) if owner_va is not None else 'unresolved'} "
                    f"section={safe_comment(row['section'])} */\n"
                )
                current_key = key
                block_open = True
            if row["kind"] == "instruction":
                call_site = call_sites_by_va.get(row["va"])
                call_annotation = (
                    f" | IAT_CALL {call_site['import']} via {call_site['route']}"
                    if call_site is not None
                    else ""
                )
                handle.write(
                    f"    /* {row['va']:#x} {row['bytes']} | {safe_comment(row['text'])}"
                    f"{safe_comment(call_annotation)} */\n"
                )
            else:
                handle.write(
                    f"    /* {row['va']:#x} {row['bytes']} | SKIPDATA {safe_comment(row['text'])} */\n"
                )
            total_records += 1
            total_bytes += row["size"]
            owner_record_counts[owner_va] += 1
            kind_counts[row["kind"]] += 1
            section_counts[row["section"]] += row["size"]
        if block_open:
            handle.write("}\n")

    while (
        range_index < len(expected_ranges)
        and next_expected_va == expected_ranges[range_index][1]
    ):
        range_index += 1
        if range_index < len(expected_ranges):
            next_expected_va = expected_ranges[range_index][0]
    if range_index != len(expected_ranges):
        raise ValueError(
            f"reconstruction ended at {next_expected_va:#x} before all executable ranges"
        )
    expected_bytes = int(evidence["coverage"]["executable_virtual_bytes"])
    if total_bytes != expected_bytes:
        raise ValueError(
            f"reconstruction covered {total_bytes} bytes, expected {expected_bytes}"
        )
    return {
        "path": repository_path(output),
        "size": output.stat().st_size,
        "sha256": file_sha256(output),
        "record_count": total_records,
        "covered_bytes": total_bytes,
        "instruction_records": kind_counts["instruction"],
        "gap_records": kind_counts["gap"],
        "entry_owners_with_records": sum(
            owner is not None for owner in owner_record_counts
        ),
        "unowned_records": owner_record_counts[None],
        "function_parts": sum(part_counts.values()),
        "section_bytes": dict(sorted(section_counts.items())),
    }


def write_public_example(evidence: dict[str, Any], output: Path) -> dict[str, Any]:
    named_call_owner_vas = {
        site["owner_va"]
        for site in evidence["call_sites"]
        if site["name"].endswith("_CallSite") and site["owner_va"]
    }
    entries = [
        row
        for row in evidence["entries"]
        if "known" in row["source"].split("+")
        or "pe_entry" in row["source"].split("+")
        or row["va"] in named_call_owner_vas
    ]
    calls_by_owner: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for site in evidence["call_sites"]:
        if site["owner_va"]:
            calls_by_owner[site["owner_va"]].append(site)
    lines = [
        "/*",
        " * Best-effort source-like examples for the pinned Randgrid.sys static map.",
        " * This is NOT original source and deliberately contains no operational driver logic.",
        f" * Input SHA-256: {evidence['input']['sha256']}",
        " */",
        "",
        "#include <stdint.h>",
        "",
        "#if defined(__GNUC__) || defined(__clang__)",
        "#define RG_UNUSED __attribute__((unused))",
        "#else",
        "#define RG_UNUSED",
        "#endif",
        "",
    ]
    for entry in sorted(entries, key=lambda row: parse_hex(row["va"])):
        identifier = c_identifier(f"example_{entry['name']}_{entry['va']}")
        lines.append(
            f"static RG_UNUSED void {identifier}(void) {{ /* {entry['va']} {entry['entry_kind']} "
            f"confidence={entry['entry_confidence']} */"
        )
        for instruction in entry.get("head") or []:
            lines.append(
                f"    /* {instruction['va']} {instruction['bytes']} | "
                f"{safe_comment(instruction['text'])} */"
            )
        for site in calls_by_owner.get(entry["va"], []):
            lines.append(
                f"    /* exact IAT call {site['va']}: {safe_comment(site['import'])} "
                f"via {site['route']} */"
            )
        lines.append("    /* Opaque MBA/control flow remains unresolved. */")
        lines.append("}")
        lines.append("")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return {
        "path": repository_path(output),
        "size": output.stat().st_size,
        "sha256": file_sha256(output),
        "entry_examples": len(entries),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--ghidra-catalog", type=Path, required=True)
    parser.add_argument("--instructions", type=Path, required=True)
    parser.add_argument("--gaps", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIRECTORY)
    parser.add_argument("--example", type=Path, default=DEFAULT_EXAMPLE)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    evidence_raw = args.evidence.read_bytes()
    evidence = json.loads(evidence_raw)
    if evidence.get("schema_version") != 2:
        raise SystemExit("source reconstruction requires full-map schema version 2")
    if evidence["input"]["sha256"] != full_map.EXPECTED_SHA256:
        raise SystemExit("source reconstruction evidence is not pinned to Randgrid.sys")
    ghidra_rows, ghidra_provenance = full_map.load_ghidra_catalog(
        args.ghidra_catalog,
        image_base=int(evidence["input"]["image_base"]),
        input_sha256=evidence["input"]["sha256"],
    )
    if ghidra_provenance["sha256"] != evidence["authority"]["ghidra_catalog"]["sha256"]:
        raise SystemExit(
            "Ghidra catalog does not match the full-map evidence authority"
        )

    full_output = args.output_dir / "randgrid-source-like-reconstruction.c.gz"
    full_result = write_full_reconstruction(
        evidence=evidence,
        ghidra_rows=ghidra_rows,
        instructions=args.instructions,
        gaps=args.gaps,
        output=full_output,
    )
    example_result = write_public_example(evidence, args.example)
    summary = {
        "schema_version": 1,
        "input": evidence["input"],
        "authority": {
            "full_map_sha256": hashlib.sha256(evidence_raw).hexdigest(),
            "ghidra_catalog": ghidra_provenance,
            "instruction_dump_sha256": file_sha256(args.instructions),
            "gap_dump_sha256": file_sha256(args.gaps),
        },
        "coverage": {
            "entry_candidates": len(evidence["entries"]),
            "exact_iat_call_sites": len(evidence["call_sites"]),
            "executable_virtual_bytes": evidence["coverage"][
                "executable_virtual_bytes"
            ],
            "linear_instructions": evidence["coverage"]["instruction_count"],
            "gap_bytes": evidence["coverage"]["gap_bytes"],
        },
        "full_local_reconstruction": full_result,
        "public_example": example_result,
        "limitations": [
            "This is not original source code.",
            "Types, variables, macros, comments, and compiler structure are not recoverable.",
            "MBA and flattened control flow remain opaque unless separately simplified.",
            "The full reconstruction is local-only because it contains derived proprietary bytes.",
            "No runtime policy, IOCTL protocol, bypass, or evasion behavior is inferred.",
        ],
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(
        json.dumps(summary, indent=2), encoding="utf-8", newline="\n"
    )
    print(f"full reconstruction: {full_result['path']}")
    print(f"covered bytes: {full_result['covered_bytes']}")
    print(f"records: {full_result['record_count']}")
    print(f"unowned records: {full_result['unowned_records']}")
    print(f"public example: {example_result['path']}")
    print(f"summary: {args.summary}")


if __name__ == "__main__":
    main()
