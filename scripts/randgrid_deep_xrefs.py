"""Deterministic deep static xref census for Randgrid.sys.

This script reads the PE on disk. It does not load the driver, open its device,
connect to a service, or interact with a running game. It combines four sources
of evidence:

1. the PE import address table (IAT),
2. exact x86-64 RIP-relative direct-call/jump encodings,
3. a conservative linear Capstone reference pass, and
4. x64 exception-directory (``.pdata``) runtime-function boundaries.

The exception boundaries are particularly useful for protected binaries: they
provide loader-consumed unwind ranges independent of Ghidra's heuristic function
splitting. A decoded instruction is still only a static reference; this script
does not infer callback semantics or runtime policy from an import name.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import math
import re
import statistics
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if SCRIPT_DIRECTORY.name == "scripts" and (SCRIPT_DIRECTORY.parent / "evidence").is_dir():
    DEFAULT_OUTPUT_DIRECTORY = SCRIPT_DIRECTORY.parent / "evidence"
else:
    DEFAULT_OUTPUT_DIRECTORY = SCRIPT_DIRECTORY / "analysis"
DEFAULT_JSON = DEFAULT_OUTPUT_DIRECTORY / "randgrid-deep-xrefs.json"
DEFAULT_MARKDOWN = DEFAULT_OUTPUT_DIRECTORY / "randgrid-deep-xrefs.md"

EXECUTE = 0x20000000
KERNEL_NAME_TOKEN = re.compile(
    r"\b(?:Zw|Nt|Mm|Ob|Ps|Ke|Ex|Rtl|Io|Se|Cm|FsRtl|Flt)[A-Z][A-Za-z0-9_]{4,127}\b"
)

FOCUS_GROUPS: dict[str, tuple[str, ...]] = {
    "object_callbacks": (
        "ObRegisterCallbacks",
        "ObUnRegisterCallbacks",
    ),
    "process_thread_image_callbacks": (
        "PsSetCreateProcessNotifyRoutine",
        "PsSetCreateProcessNotifyRoutineEx",
        "PsSetCreateThreadNotifyRoutine",
        "PsRemoveCreateThreadNotifyRoutine",
        "PsSetLoadImageNotifyRoutine",
    ),
    "other_callback_surfaces": (
        "KeRegisterBugCheckCallback",
        "KeDeregisterBugCheckCallback",
        "IoRegisterBootDriverCallback",
        "IoUnregisterBootDriverCallback",
        "PoRegisterPowerSettingCallback",
        "PoUnregisterPowerSettingCallback",
        "ExCreateCallback",
        "ExRegisterCallback",
        "ExUnregisterCallback",
        "ExNotifyCallback",
    ),
    "device_surface": (
        "IoCreateDevice",
        "IoDeleteDevice",
        "IoCreateSymbolicLink",
        "IoCreateUnprotectedSymbolicLink",
        "IoDeleteSymbolicLink",
        "IoCreateFile",
        "IoCreateFileEx",
    ),
    "memory_surface": (
        "MmCopyMemory",
        "MmGetPhysicalAddress",
        "MmMapIoSpace",
        "MmProbeAndLockPages",
        "MmProbeAndLockSelectedPages",
        "MmGetSystemRoutineAddress",
    ),
    "process_inspection_surface": (
        "ZwOpenProcess",
        "ZwQueryVirtualMemory",
        "ZwQueryInformationThread",
        "ZwQuerySystemInformation",
        "ZwTerminateProcess",
        "ZwAlertThread",
        "PsGetProcessPeb",
        "PsGetCurrentProcessId",
        "SeLocateProcessImageName",
        "ObOpenObjectByPointer",
        "ObReferenceObjectByHandle",
        "ObReferenceObjectByName",
    ),
    "debugger_surface": (
        "KdDisableDebugger",
        "KdEnableDebugger",
        "KdDebuggerNotPresent",
    ),
    "firmware_image_ci_surface": (
        "ExGetFirmwareEnvironmentVariable",
        "RtlImageNtHeader",
        "RtlImageDirectoryEntryToData",
        "CiCheckSignatureMandatory",
        "CiGetCertificateStoreOptions",
        "CiFreePolicyInfo",
        "CiValidateFileObject",
    ),
    "cng_signature_surface": (
        "BCryptOpenAlgorithmProvider",
        "BCryptGetProperty",
        "BCryptCloseAlgorithmProvider",
        "BCryptImportKeyPair",
        "BCryptDestroyKey",
        "BCryptVerifySignature",
        "BCryptCreateHash",
        "BCryptHashData",
        "BCryptFinishHash",
        "BCryptDestroyHash",
    ),
}

STRING_TARGETS = (
    r"\Device\Randgrid",
    r"\DosDevices\Randgrid",
    "Randgrid Driver",
    "Randgrid.pdb",
    "ECDSA_P256",
    "ECCPUBLICBLOB",
    "SHA256",
    "HashDigestLength",
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def section_name(section: Any) -> str:
    return section.Name.rstrip(b"\0").decode("ascii", errors="replace")


def runtime_functions(pe: pefile.PE) -> list[dict[str, int]]:
    entries = []
    for item in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []):
        begin = int(item.struct.BeginAddress)
        end = int(item.struct.EndAddress)
        if end <= begin:
            continue
        entries.append(
            {
                "begin_rva": begin,
                "end_rva": end,
                "size": end - begin,
                "unwind_rva": int(item.struct.UnwindData),
            }
        )
    return sorted(entries, key=lambda row: (row["begin_rva"], row["end_rva"]))


class RuntimeLookup:
    def __init__(self, entries: list[dict[str, int]]) -> None:
        self.entries = entries
        self.starts = [row["begin_rva"] for row in entries]

    def containing(self, rva: int) -> dict[str, int] | None:
        index = bisect.bisect_right(self.starts, rva) - 1
        if index < 0:
            return None
        row = self.entries[index]
        if row["begin_rva"] <= rva < row["end_rva"]:
            return dict(row)
        return None


def import_slots(pe: pefile.PE) -> dict[int, dict[str, Any]]:
    slots: dict[int, dict[str, Any]] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("ascii", errors="replace")
        for item in entry.imports:
            name = (
                item.name.decode("ascii", errors="replace")
                if item.name
                else f"ordinal:{item.ordinal}"
            )
            slots[int(item.address)] = {
                "dll": dll,
                "name": name,
                "iat_va": int(item.address),
            }
    return slots


def executable_sections(pe: pefile.PE) -> Iterable[Any]:
    for section in pe.sections:
        if int(section.Characteristics) & EXECUTE:
            yield section


def decoded_direct_transfers(
    pe: pefile.PE,
    slots: dict[int, dict[str, Any]],
    runtime: RuntimeLookup,
) -> list[dict[str, Any]]:
    """Decode every exact ``FF /2`` or ``FF /4`` RIP-relative IAT transfer.

    Each byte-pattern candidate is decoded at its own address. This avoids
    losing a real transfer when a protected section disrupts one global linear
    sweep. It can still encounter executable-section data, so the runtime
    boundary and the separate linear pass are retained as corroboration.
    """

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    rows: list[dict[str, Any]] = []
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)

    for section in executable_sections(pe):
        data = bytes(section.get_data())
        section_va = image_base + int(section.VirtualAddress)
        for offset in range(0, max(0, len(data) - 6)):
            if data[offset] != 0xFF or data[offset + 1] not in (0x15, 0x25):
                continue
            address = section_va + offset
            displacement = struct.unpack_from("<i", data, offset + 2)[0]
            target = address + 6 + displacement
            imported = slots.get(target)
            if imported is None:
                continue
            decoded = list(md.disasm(data[offset : offset + 15], address, count=1))
            if not decoded:
                continue
            instruction = decoded[0]
            expected = "call" if data[offset + 1] == 0x15 else "jmp"
            if instruction.address != address or instruction.size != 6 or instruction.mnemonic != expected:
                continue
            function = runtime.containing(address - image_base)
            rows.append(
                {
                    **imported,
                    "instruction_va": address,
                    "instruction_rva": address - image_base,
                    "kind": expected,
                    "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                    "bytes": bytes(instruction.bytes).hex(),
                    "section": section_name(section),
                    "runtime_function": function,
                }
            )
    return sorted(rows, key=lambda row: (row["instruction_va"], row["name"]))


def decoded_transfers_to_iat_stubs(
    pe: pefile.PE,
    direct_rows: list[dict[str, Any]],
    runtime: RuntimeLookup,
) -> list[dict[str, Any]]:
    """Find exact relative calls/jumps whose target is an IAT jump stub.

    Windows binaries may reach an import either with ``call [rip+IAT]`` or by
    calling a local six-byte ``jmp [rip+IAT]`` stub. The latter must be traced
    one level back; the mere presence of the stub is not use evidence.
    """

    stubs: dict[int, dict[str, Any]] = {
        row["instruction_va"]: row for row in direct_rows if row["kind"] == "jmp"
    }
    if not stubs:
        return []

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    rows: list[dict[str, Any]] = []
    for section in executable_sections(pe):
        data = bytes(section.get_data())
        section_va = image_base + int(section.VirtualAddress)
        for offset in range(0, max(0, len(data) - 5)):
            opcode = data[offset]
            if opcode not in (0xE8, 0xE9):
                continue
            address = section_va + offset
            displacement = struct.unpack_from("<i", data, offset + 1)[0]
            target = address + 5 + displacement
            stub = stubs.get(target)
            if stub is None:
                continue
            decoded = list(md.disasm(data[offset : offset + 15], address, count=1))
            if not decoded:
                continue
            instruction = decoded[0]
            expected = "call" if opcode == 0xE8 else "jmp"
            if instruction.address != address or instruction.size != 5 or instruction.mnemonic != expected:
                continue
            rows.append(
                {
                    "dll": stub["dll"],
                    "name": stub["name"],
                    "iat_va": stub["iat_va"],
                    "stub_va": target,
                    "instruction_va": address,
                    "instruction_rva": address - image_base,
                    "kind": expected,
                    "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                    "bytes": bytes(instruction.bytes).hex(),
                    "section": section_name(section),
                    "runtime_function": runtime.containing(address - image_base),
                }
            )
    return sorted(rows, key=lambda row: (row["instruction_va"], row["name"]))


def linear_rip_references(
    pe: pefile.PE,
    slots: dict[int, dict[str, Any]],
    string_addresses: dict[int, list[dict[str, Any]]],
    runtime: RuntimeLookup,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    import_rows: list[dict[str, Any]] = []
    string_rows: list[dict[str, Any]] = []

    for section in executable_sections(pe):
        section_va = image_base + int(section.VirtualAddress)
        for instruction in md.disasm(bytes(section.get_data()), section_va):
            # Capstone emits a synthetic data record (id == 0) when skipdata
            # resynchronizes after an undecodable byte sequence. Such records
            # intentionally have no operand-detail structure.
            if instruction.id == 0:
                continue
            targets: set[int] = set()
            for operand in instruction.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    targets.add(instruction.address + instruction.size + operand.mem.disp)
            for target in sorted(targets):
                function = runtime.containing(instruction.address - image_base)
                if target in slots:
                    import_rows.append(
                        {
                            **slots[target],
                            "instruction_va": instruction.address,
                            "instruction_rva": instruction.address - image_base,
                            "mnemonic": instruction.mnemonic,
                            "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                            "bytes": bytes(instruction.bytes).hex(),
                            "section": section_name(section),
                            "runtime_function": function,
                        }
                    )
                for string_row in string_addresses.get(target, []):
                    string_rows.append(
                        {
                            "text": string_row["text"],
                            "encoding": string_row["encoding"],
                            "string_va": target,
                            "string_rva": target - image_base,
                            "instruction_va": instruction.address,
                            "instruction_rva": instruction.address - image_base,
                            "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                            "bytes": bytes(instruction.bytes).hex(),
                            "section": section_name(section),
                            "runtime_function": function,
                        }
                    )

    import_rows.sort(key=lambda row: (row["instruction_va"], row["name"]))
    string_rows.sort(key=lambda row: (row["instruction_va"], row["text"]))
    return import_rows, string_rows


def locate_strings(pe: pefile.PE) -> tuple[list[dict[str, Any]], dict[int, list[dict[str, Any]]]]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    rows: list[dict[str, Any]] = []
    by_address: dict[int, list[dict[str, Any]]] = defaultdict(list)

    for section in pe.sections:
        data = bytes(section.get_data())
        for text in STRING_TARGETS:
            for encoding, needle in (
                ("ascii", text.encode("ascii", errors="strict")),
                ("utf16le", text.encode("utf-16-le")),
            ):
                start = 0
                while True:
                    offset = data.find(needle, start)
                    if offset < 0:
                        break
                    rva = int(section.VirtualAddress) + offset
                    row = {
                        "text": text,
                        "encoding": encoding,
                        "section": section_name(section),
                        "rva": rva,
                        "va": image_base + rva,
                        "file_offset": int(section.PointerToRawData) + offset,
                    }
                    rows.append(row)
                    by_address[row["va"]].append(row)
                    start = offset + 1

    rows.sort(key=lambda row: (row["va"], row["encoding"], row["text"]))
    return rows, by_address


def section_for_file_offset(pe: pefile.PE, offset: int) -> tuple[str | None, int | None]:
    for section in pe.sections:
        start = int(section.PointerToRawData)
        end = start + int(section.SizeOfRawData)
        if start <= offset < end:
            return section_name(section), int(section.VirtualAddress) + (offset - start)
    return None, None


def dynamic_kernel_name_scan(
    pe: pefile.PE, imported_names: set[str]
) -> dict[str, Any]:
    candidates: dict[str, list[dict[str, Any]]] = defaultdict(list)
    data = bytes(pe.__data__)
    extractors = (
        ("ascii", re.compile(rb"[\x20-\x7e]{6,}"), "ascii"),
        ("utf16le", re.compile(rb"(?:[\x20-\x7e]\x00){6,}"), "utf-16-le"),
    )
    for encoding, pattern, codec in extractors:
        for match in pattern.finditer(data):
            text = match.group().decode(codec, errors="replace")
            for name_match in KERNEL_NAME_TOKEN.finditer(text):
                name = name_match.group(0)
                if name in imported_names:
                    continue
                section, rva = section_for_file_offset(pe, match.start())
                candidates[name].append(
                    {
                        "file_offset": match.start(),
                        "encoding": encoding,
                        "section": section,
                        "rva": rva,
                        "container_preview": text[:300],
                    }
                )
    return {
        "candidate_count": len(candidates),
        "candidates": {name: rows for name, rows in sorted(candidates.items())},
        "interpretation": (
            "Non-import plaintext names are only candidates for dynamic lookup. "
            "A call-site/string data-flow xref is still required to prove use."
        ),
    }


def p95(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]


def summarize_focus(
    slots: dict[int, dict[str, Any]],
    direct_rows: list[dict[str, Any]],
    stub_rows: list[dict[str, Any]],
    linear_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    imported_names = {row["name"] for row in slots.values()}
    direct_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    stub_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    linear_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in direct_rows:
        direct_by_name[row["name"]].append(row)
    for row in stub_rows:
        stub_by_name[row["name"]].append(row)
    for row in linear_rows:
        linear_by_name[row["name"]].append(row)

    groups: dict[str, list[dict[str, Any]]] = {}
    for group, names in FOCUS_GROUPS.items():
        rows = []
        for name in names:
            calls = [item for item in direct_by_name[name] if item["kind"] == "call"]
            jumps = [item for item in direct_by_name[name] if item["kind"] == "jmp"]
            stub_calls = [item for item in stub_by_name[name] if item["kind"] == "call"]
            stub_jumps = [item for item in stub_by_name[name] if item["kind"] == "jmp"]
            linear_calls = [item for item in linear_by_name[name] if item["mnemonic"] == "call"]
            linear_jumps = [item for item in linear_by_name[name] if item["mnemonic"] == "jmp"]
            linear_other = [
                item for item in linear_by_name[name] if item["mnemonic"] not in ("call", "jmp")
            ]
            rows.append(
                {
                    "name": name,
                    "imported": name in imported_names,
                    "direct_transfer_count": len(direct_by_name[name]),
                    "direct_call_count": len(calls),
                    "iat_jump_count": len(jumps),
                    "stub_call_count": len(stub_calls),
                    "stub_jump_count": len(stub_jumps),
                    "effective_call_count": len(calls) + len(stub_calls),
                    "linear_rip_reference_count": len(linear_by_name[name]),
                    "linear_call_count": len(linear_calls),
                    "linear_jump_count": len(linear_jumps),
                    "linear_other_reference_count": len(linear_other),
                    "direct_calls": calls,
                    "iat_jumps": jumps,
                    "stub_calls": stub_calls,
                    "stub_jumps": stub_jumps,
                    "direct_transfers": direct_by_name[name],
                    "linear_rip_references": linear_by_name[name],
                }
            )
        groups[group] = rows
    return groups


def build_payload(target: Path) -> dict[str, Any]:
    pe = pefile.PE(str(target), fast_load=False)
    pe.parse_data_directories()
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    slots = import_slots(pe)
    imported_names = {row["name"] for row in slots.values()}
    functions = runtime_functions(pe)
    runtime = RuntimeLookup(functions)
    strings, strings_by_address = locate_strings(pe)
    direct = decoded_direct_transfers(pe, slots, runtime)
    stub_transfers = decoded_transfers_to_iat_stubs(pe, direct, runtime)
    linear, string_xrefs = linear_rip_references(pe, slots, strings_by_address, runtime)
    sizes = [row["size"] for row in functions]

    direct_counts = Counter(row["name"] for row in direct)
    direct_calls = [row for row in direct if row["kind"] == "call"]
    direct_jumps = [row for row in direct if row["kind"] == "jmp"]
    direct_call_counts = Counter(row["name"] for row in direct_calls)
    direct_jump_counts = Counter(row["name"] for row in direct_jumps)
    stub_calls = [row for row in stub_transfers if row["kind"] == "call"]
    stub_jumps = [row for row in stub_transfers if row["kind"] == "jmp"]
    stub_call_counts = Counter(row["name"] for row in stub_calls)
    stub_jump_counts = Counter(row["name"] for row in stub_jumps)
    effectively_called_names = set(direct_call_counts) | set(stub_call_counts)
    linear_counts = Counter(row["name"] for row in linear)
    return {
        "schema_version": 1,
        "input": {
            "name": target.name,
            "size": target.stat().st_size,
            "sha256": file_sha256(target),
            "image_base": image_base,
            "entry_rva": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        },
        "sections": [
            {
                "name": section_name(section),
                "rva": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "characteristics": int(section.Characteristics),
                "executable": bool(int(section.Characteristics) & EXECUTE),
            }
            for section in pe.sections
        ],
        "imports": {
            "slot_count": len(slots),
            "dll_counts": dict(sorted(Counter(row["dll"] for row in slots.values()).items())),
            "direct_transfer_count": len(direct),
            "direct_call_count": len(direct_calls),
            "iat_jump_count": len(direct_jumps),
            "stub_call_count": len(stub_calls),
            "stub_jump_count": len(stub_jumps),
            "linear_rip_reference_count": len(linear),
            "directly_transferred_import_count": len(direct_counts),
            "directly_called_import_count": len(direct_call_counts),
            "iat_jump_import_count": len(direct_jump_counts),
            "stub_called_import_count": len(stub_call_counts),
            "stub_jump_import_count": len(stub_jump_counts),
            "effectively_called_import_count": len(effectively_called_names),
            "linearly_referenced_import_count": len(linear_counts),
            "direct_transfer_counts": dict(sorted(direct_counts.items())),
            "direct_call_counts": dict(sorted(direct_call_counts.items())),
            "iat_jump_counts": dict(sorted(direct_jump_counts.items())),
            "stub_call_counts": dict(sorted(stub_call_counts.items())),
            "stub_jump_counts": dict(sorted(stub_jump_counts.items())),
            "linear_rip_reference_counts": dict(sorted(linear_counts.items())),
        },
        "runtime_functions": {
            "count": len(functions),
            "median_size": statistics.median(sizes) if sizes else 0,
            "p95_size": p95(sizes),
            "max_size": max(sizes, default=0),
            "over_4k": sum(size > 4096 for size in sizes),
            "over_64k": sum(size > 65536 for size in sizes),
            "over_1m": sum(size > 1024 * 1024 for size in sizes),
            "largest": sorted(functions, key=lambda row: (-row["size"], row["begin_rva"]))[:25],
            "entry_containing_range": runtime.containing(int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)),
        },
        "focus_groups": summarize_focus(slots, direct, stub_transfers, linear),
        "located_strings": strings,
        "string_xrefs": string_xrefs,
        "dynamic_kernel_name_scan": dynamic_kernel_name_scan(pe, imported_names),
        "direct_transfers": direct,
        "stub_transfers": stub_transfers,
        "linear_rip_references": linear,
        "interpretation": {
            "direct_transfer": (
                "Exact x86-64 RIP-relative call/jump to an IAT slot, decoded at the candidate address. "
                "Executable-section data can still resemble code; runtime boundaries and the linear/Ghidra passes are corroboration."
            ),
            "linear_rip_reference": (
                "RIP-relative reference recovered by a section-wide Capstone sweep. Protected control flow or embedded data may cause misses."
            ),
            "runtime_function": (
                "PE x64 exception-directory unwind range consumed by the Windows loader; independent of decompiler function heuristics."
            ),
            "non_claim": (
                "An imported or referenced API proves a static dependency/call site, not callback semantics, target policy, or runtime success."
            ),
        },
    }


def hex_value(value: int | float) -> str:
    return f"0x{int(value):X}"


def write_markdown(payload: dict[str, Any], output: Path) -> None:
    source = payload["input"]
    runtime = payload["runtime_functions"]
    imports = payload["imports"]
    lines = [
        "# Randgrid.sys — deep PE/IAT/unwind evidence",
        "",
        f"- SHA-256: `{source['sha256']}`",
        f"- Size: `{source['size']}` bytes",
        f"- Image base: `{hex_value(source['image_base'])}`",
        f"- Entry RVA: `{hex_value(source['entry_rva'])}`",
        f"- Import slots: `{imports['slot_count']}`",
        f"- Exact direct IAT calls: `{imports['direct_call_count']}` across `{imports['directly_called_import_count']}` imports",
        f"- IAT jump stubs/candidates: `{imports['iat_jump_count']}` across `{imports['iat_jump_import_count']}` imports",
        f"- Exact calls through IAT jump stubs: `{imports['stub_call_count']}` across `{imports['stub_called_import_count']}` imports",
        f"- Imports reached by either exact call form: `{imports['effectively_called_import_count']}`",
        f"- Linear RIP-relative IAT references: `{imports['linear_rip_reference_count']}` across `{imports['linearly_referenced_import_count']}` imports",
        "",
        "## Exception-directory runtime functions",
        "",
        f"- Count: `{runtime['count']}`",
        f"- Median span: `{runtime['median_size']}` bytes",
        f"- 95th-percentile span: `{runtime['p95_size']}` bytes",
        f"- Maximum span: `{runtime['max_size']}` bytes",
        f"- Spans over 4 KiB / 64 KiB / 1 MiB: `{runtime['over_4k']}` / `{runtime['over_64k']}` / `{runtime['over_1m']}`",
        "",
        "| Begin RVA | End RVA | Size | Unwind RVA |",
        "|---:|---:|---:|---:|",
    ]
    for row in runtime["largest"][:15]:
        lines.append(
            f"| `{hex_value(row['begin_rva'])}` | `{hex_value(row['end_rva'])}` | "
            f"`{hex_value(row['size'])}` | `{hex_value(row['unwind_rva'])}` |"
        )

    lines.extend(["", "## Focused import evidence", ""])
    for group, rows in payload["focus_groups"].items():
        lines.extend(
            [
                f"### `{group}`",
                "",
                "| Import | Present | Direct-IAT calls | Calls via stub | IAT stub | Other RIP refs |",
                "|---|---:|---:|---:|---:|---:|",
            ]
        )
        for row in rows:
            lines.append(
                f"| `{row['name']}` | {'yes' if row['imported'] else 'no'} | "
                f"{row['direct_call_count']} | {row['stub_call_count']} | {row['iat_jump_count']} | "
                f"{row['linear_other_reference_count']} |"
            )
        lines.append("")

    lines.extend(
        [
            "## Exact focused calls",
            "",
            "IAT jump stubs are excluded: a stub's existence is not evidence that a higher-level caller reaches its import.",
            "",
        ]
    )
    for group, rows in payload["focus_groups"].items():
        for row in rows:
            for reference in row["direct_calls"]:
                function = reference.get("runtime_function")
                containing = (
                    f"RVA {hex_value(function['begin_rva'])}–{hex_value(function['end_rva'])}"
                    if function
                    else "no .pdata range"
                )
                lines.append(
                    f"- `{row['name']}`: `{hex_value(reference['instruction_va'])}` "
                    f"direct to IAT (`{reference['instruction']}`), {containing}"
                )
            for reference in row["stub_calls"]:
                function = reference.get("runtime_function")
                containing = (
                    f"RVA {hex_value(function['begin_rva'])}–{hex_value(function['end_rva'])}"
                    if function
                    else "no .pdata range"
                )
                lines.append(
                    f"- `{row['name']}`: `{hex_value(reference['instruction_va'])}` calls stub "
                    f"`{hex_value(reference['stub_va'])}` (`{reference['instruction']}`), {containing}"
                )
    lines.extend(["", "## Located Randgrid strings and static xrefs", ""])
    for row in payload["located_strings"]:
        lines.append(
            f"- `{row['text']}` ({row['encoding']}) at RVA `{hex_value(row['rva'])}` in `{row['section']}`"
        )
    if payload["string_xrefs"]:
        lines.append("")
        for row in payload["string_xrefs"]:
            lines.append(
                f"  - `{row['text']}` referenced by `{hex_value(row['instruction_va'])}`: `{row['instruction']}`"
            )
    else:
        lines.extend(
            [
                "",
                "No section-wide linear RIP-relative code reference to these exact string starts was recovered.",
            ]
        )

    dynamic_names = payload["dynamic_kernel_name_scan"]
    lines.extend(
        [
            "",
            "## Non-import kernel-routine plaintext names",
            "",
            f"- Candidate count: `{dynamic_names['candidate_count']}`",
            "",
            dynamic_names["interpretation"],
        ]
    )
    for name, rows in dynamic_names["candidates"].items():
        lines.append(f"- `{name}`: {len(rows)} occurrence(s)")

    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            payload["interpretation"]["non_claim"],
            "An IAT jump stub is normal linkage machinery and is not treated as proof that a higher-level caller reaches that API.",
            "The JSON companion preserves every decoded transfer and linear reference for independent review.",
            "",
        ]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.target.is_file():
        raise SystemExit(f"target does not exist: {args.target}")
    payload = build_payload(args.target)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8", newline="\n"
    )
    write_markdown(payload, args.markdown)
    print(f"input sha256: {payload['input']['sha256']}")
    print(f"import slots: {payload['imports']['slot_count']}")
    print(f"direct calls: {payload['imports']['direct_call_count']}")
    print(f"IAT jumps: {payload['imports']['iat_jump_count']}")
    print(f"calls through IAT stubs: {payload['imports']['stub_call_count']}")
    print(f"linear RIP references: {payload['imports']['linear_rip_reference_count']}")
    print(f"runtime functions: {payload['runtime_functions']['count']}")
    print(f"wrote {args.json}")
    print(f"wrote {args.markdown}")


if __name__ == "__main__":
    main()
