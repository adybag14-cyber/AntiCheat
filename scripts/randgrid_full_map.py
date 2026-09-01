"""Complete static function and instruction map for Randgrid.sys.

This is a read-only PE parser. It does not load the driver, talk to its
device, or interact with a running game. It maps every executable byte with
Capstone, catalogs every ``.pdata`` unwind range plus recovered extra entry
points (IAT stubs, relative-call targets, known thunks, clear wrappers),
classifies obfuscation shape, and names functions from exact IAT evidence.

Bulk instruction listings stay in the Git-ignored analysis directory. The
published JSON/Markdown evidence is compact derived metadata.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.metadata
import io
import json
import platform
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import capstone as capstone_module
import pefile
import randgrid_deep_xrefs as xref
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_IMM

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
ROOT = SCRIPT_DIRECTORY.parent
DEFAULT_JSON = ROOT / "evidence" / "randgrid-full-map.json"
DEFAULT_MARKDOWN = ROOT / "evidence" / "randgrid-full-map.md"
DEFAULT_DUMP = ROOT / "analysis" / "randgrid-full-map"
EXPECTED_SHA256 = "4150290a810ebebe9f9e6b5bd32c60299f9f34c3d2b6f02b89590ed49a6b895e"
EXPECTED_SIZE = 13_130_616

# Previously recovered high-confidence labels. Addresses are VAs at image base
# 0x140000000. These are names, not new behavior claims.
KNOWN_NAMES: dict[int, str] = {
    0x140C61000: "DriverEntry",
    0x14059A14C: "DriverEntry_ObfuscatedBody",
    0x14015CF58: "MbaBlock_14015CF58",
    0x140A294E0: "ProcessNotifyThunk",
    0x140A8DB26: "ProcessNotifyBody",
    0x140A2AC70: "ThreadNotifyThunk",
    0x140A8EDB5: "ThreadNotifyBody",
    0x140AB2C18: "ObRegisterCallbacks_Setup",
    0x140AA11D6: "ProcessNotify_RegisterPath",
    0x140A8CD84: "_guard_dispatch_icall",
    0x140AB7BF0: "_guard_check_icall",
}

KNOWN_CALLSITE_NAMES: dict[int, str] = {
    0x140AB309D: "ObRegisterCallbacks_CallSite",
    0x140AA12F2: "PsSetCreateProcessNotifyRoutineEx_CallSite",
    0x140AA130F: "PsSetCreateThreadNotifyRoutine_CallSite",
}

MBA_MNEMONICS = frozenset(
    {"push", "pop", "pushfq", "popfq", "add", "sub", "xor", "and", "or", "not", "neg"}
)
CLEAR_MNEMONICS = frozenset(
    {
        "mov",
        "lea",
        "cmp",
        "test",
        "call",
        "ret",
        "je",
        "jne",
        "ja",
        "jb",
        "jae",
        "jbe",
        "jmp",
    }
)
PROLOGUE_PREFIXES: tuple[bytes, ...] = (
    b"\x40\x53",
    b"\x40\x55",
    b"\x40\x56",
    b"\x40\x57",
    b"\x41\x54",
    b"\x41\x55",
    b"\x41\x56",
    b"\x41\x57",
    b"\x48\x83\xec",
    b"\x48\x81\xec",
    b"\x48\x89",
    b"\x4c\x89",
    b"\x48\x8b\xc4",
    b"\x9c",
    b"\xff\x25",
    b"\xff\x15",
    b"\xe9",
    b"\x55",
    b"\x53",
    b"\x56",
    b"\x57",
    b"\x51",
    b"\x52",
    b"\x41\x50",
    b"\x41\x51",
    b"\x41\x52",
    b"\x41\x53",
)


def looks_like_entry(raw: bytes) -> bool:
    if not raw:
        return False
    return any(raw.startswith(prefix) for prefix in PROLOGUE_PREFIXES)


# Single-byte encodings that #UD in 64-bit mode (Intel SDM). These dominate the
# linear skipdata remainder: MBA junk inserted as legacy 16/32-bit opcodes.
LEGACY_UD: dict[int, str] = {
    0x06: "PUSH_ES",
    0x07: "POP_ES",
    0x0E: "PUSH_CS",
    0x16: "PUSH_SS",
    0x17: "POP_SS",
    0x1E: "PUSH_DS",
    0x1F: "POP_DS",
    0x27: "DAA",
    0x2F: "DAS",
    0x37: "AAA",
    0x3F: "AAS",
    0x60: "PUSHA",
    0x61: "POPA",
    0x62: "BOUND_or_EVEX",
    0x82: "ALU_imm8_alias",
    0x9A: "CALLF",
    0xEA: "JMPF",
    0xCE: "INTO",
    0xD4: "AAM",
    0xD5: "AAD",
    0xD6: "SALC",
}

SEG_PREFIX: dict[int, str] = {
    0x26: "ES",
    0x2E: "CS",
    0x36: "SS",
    0x3E: "DS",
    0x64: "FS",
    0x65: "GS",
}


def classify_gap_byte(value: int, following: bytes) -> tuple[str, str, bool]:
    """Name one linear-skipdata byte from its value and the bytes after it.

    A skipdata byte is not missing file content. Capstone refused to start an
    x64 instruction here; the next linear instruction begins immediately after
    the skipped run. The job is to say *why* this byte is not a 64-bit insn.
    """

    if value in LEGACY_UD:
        return "legacy_ud", LEGACY_UD[value], True
    if value == 0xFF:
        if not following:
            return "truncated_instruction", "FF_ModRM", True
        digit = (following[0] >> 3) & 7
        if digit in (3, 5, 7):
            return "invalid_ff", f"group5_/{digit}", True
        return "invalid_ff", f"rejected_/{digit}", True
    if value == 0xFE:
        if not following:
            return "truncated_instruction", "FE_ModRM", True
        digit = (following[0] >> 3) & 7
        if digit >= 2:
            return "invalid_fe", f"group4_/{digit}", True
        return "invalid_fe", f"rejected_/{digit}", True
    if value in (0xC4, 0xC5):
        return "invalid_vex", "C4" if value == 0xC4 else "C5", True
    if 0x40 <= value <= 0x4F:
        return "orphan_rex", f"REX_{value:02X}", True
    if value == 0xF0:
        return "invalid_prefix", "LOCK", True
    if value == 0xF2:
        return "invalid_prefix", "REPNE", True
    if value == 0xF3:
        return "invalid_prefix", "REP", True
    if value in SEG_PREFIX:
        return "invalid_prefix", f"SEG_{SEG_PREFIX[value]}", True
    if value == 0x66:
        return "invalid_prefix", "OSIZE", True
    if value == 0x67:
        return "invalid_prefix", "ASIZE", True
    if value == 0x0F:
        if not following:
            return "truncated_instruction", "0F_escape", True
        return "invalid_escape", f"0F_{following[0]:02X}", True
    if value in (0xC6, 0xC7):
        return "invalid_modrm", "MOV_imm", True
    if value == 0x8F:
        return "invalid_modrm", "POP_or_XOP", True
    if value in (0x8C, 0x8E):
        return "invalid_modrm", "MOV_Sreg", True
    if value == 0x8D:
        return "invalid_modrm", "LEA", True
    if value in (0x80, 0x81, 0x83):
        return "invalid_modrm", "ALU_group", True
    if value in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
        return "invalid_modrm", "SHIFT_group", True
    if value in (0xF6, 0xF7):
        return "invalid_modrm", "UNARY_group", True
    if 0xD8 <= value <= 0xDF:
        return "invalid_x87", f"x87_{value:02X}", True
    if value in (0xC2, 0xC3, 0xCA, 0xCB, 0xCF):
        return "invalid_encoding", f"RET_like_{value:02X}", True
    if value in (0xE0, 0xE1, 0xE2, 0xE3) and len(following) < 1:
        return "truncated_instruction", f"LOOP_family_{value:02X}_rel8", True
    if value == 0xA9 and len(following) < 4:
        return "truncated_instruction", "TEST_EAX_imm32", True
    return "unknown", f"op_{value:02X}", False


def record_gap_run(
    data: bytes,
    section_name: str,
    run_va: int | None,
    run_off: int,
    run_len: int,
    *,
    run_len_hist: Counter[int],
    coarse_counts: Counter[str],
    fine_counts: Counter[str],
    gap_handle: io.TextIOWrapper | None,
) -> tuple[int, int]:
    """Write and classify one completed linear-decode gap run.

    The helper takes the current values explicitly so a per-section callback
    cannot accidentally retain values from a later loop iteration.
    """

    if run_va is None or run_len <= 0:
        return 0, 0
    raw = data[run_off : run_off + run_len]
    run_len_hist[run_len] += 1
    classified_bytes = 0
    for index, value in enumerate(raw):
        follow_at = run_off + index + 1
        following = data[follow_at : follow_at + 16]
        coarse, fine, recognized = classify_gap_byte(value, following)
        coarse_counts[coarse] += 1
        fine_counts[fine] += 1
        if recognized:
            classified_bytes += 1
        if gap_handle is not None:
            gap_handle.write(
                f"{run_va + index:x}\t1\t{value:02x}\t{coarse}\t{fine}\t{section_name}\n"
            )
    return 1, classified_bytes


def hex_value(value: int) -> str:
    return f"0x{value:X}"


def open_deterministic_gzip_text(path: Path) -> io.TextIOWrapper:
    compressed = gzip.GzipFile(filename=str(path), mode="wb", mtime=0)
    return io.TextIOWrapper(compressed, encoding="utf-8", newline="\n")


def verify_target(path: Path) -> dict[str, Any]:
    """Fail closed unless *path* is the exact pinned Randgrid.sys input."""

    size = path.stat().st_size
    if size != EXPECTED_SIZE:
        raise ValueError(
            f"unexpected Randgrid.sys size: {size} (expected {EXPECTED_SIZE})"
        )
    sha256 = xref.file_sha256(path)
    if sha256 != EXPECTED_SHA256:
        raise ValueError(
            f"unexpected Randgrid.sys SHA-256: {sha256} (expected {EXPECTED_SHA256})"
        )
    return {"name": path.name, "size": size, "sha256": sha256}


def make_disassembler(*, skipdata: bool = False) -> Cs:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = skipdata
    return md


def classify_from_head(insns: list[dict[str, Any]], size: int, raw_head: bytes) -> str:
    """Classify a recovered body from its decoded head and raw prefix."""

    if size <= 0:
        return "empty"
    if not insns:
        if raw_head.startswith(b"\x00\x00"):
            return "padding"
        return "undecodable"
    mnemonics = [row["mnemonic"] for row in insns]
    first = mnemonics[0]
    if raw_head[:2] == b"\xff\x25":
        return "iat_stub"
    if raw_head[:2] == b"\xff\x15":
        return "iat_call_wrapper"
    if size <= 8 and first == "pop" and "popfq" in mnemonics[:3]:
        return "mba_epilogue"
    if first == "jmp" and raw_head[:2] != b"\xff\x25":
        return "thunk"
    texts = [row["text"] for row in insns[:10]]
    joined = " ; ".join(texts)
    home = any(
        marker in joined
        for marker in (
            "mov qword ptr [rsp + 8], rcx",
            "mov qword ptr [rsp+8], rcx",
            "mov qword ptr [rsp + 0x8], rcx",
            "mov qword ptr [rsp + 0x10], rdx",
            "mov qword ptr [rsp + 10h], rdx",
        )
    )
    if home:
        if any(row["mnemonic"] == "jmp" for row in insns[:8]):
            return "clear_wrapper_to_obfuscated"
        if any(row["mnemonic"] == "ret" for row in insns):
            return "clear_msvc"
        return "clear_msvc"
    if first in ("pushfq",) or (first == "push" and size > 16):
        junk = sum(1 for name in mnemonics if name in MBA_MNEMONICS)
        if mnemonics and junk / len(mnemonics) >= 0.45:
            return "mba_obfuscated"
    junk = sum(1 for name in mnemonics if name in MBA_MNEMONICS)
    if mnemonics and junk / len(mnemonics) >= 0.60:
        return "mba_obfuscated"
    if "ret" in mnemonics and junk / max(len(mnemonics), 1) < 0.40:
        return "clear"
    if first in ("int3", "nop") and size <= 16:
        return "padding"
    if size > 1024 * 1024:
        return "obfuscated_blob"
    return "unknown"


def name_function(
    va: int,
    classification: str,
    iat_names: list[str],
    thunk_target: int | None = None,
    iat_stub_name: str | None = None,
) -> str:
    if va in KNOWN_NAMES:
        return KNOWN_NAMES[va]
    if classification == "iat_call_wrapper" and iat_names:
        return f"iat_wrapper_{iat_names[0]}"
    if classification == "iat_stub" and iat_stub_name:
        return f"iat_stub_{iat_stub_name}"
    unique = list(dict.fromkeys(iat_names))
    if len(unique) == 1:
        prefix = "wrapper" if classification.startswith("clear") else "uses"
        return f"{prefix}_{unique[0]}"
    if 1 < len(unique) <= 3:
        return "uses_" + "_".join(unique[:3])
    if classification == "thunk" and thunk_target is not None:
        if thunk_target in KNOWN_NAMES:
            return f"thunk_to_{KNOWN_NAMES[thunk_target]}"
        return f"thunk_{hex_value(thunk_target)}"
    if classification == "mba_epilogue":
        return f"mba_epilogue_{hex_value(va)}"
    if classification == "mba_obfuscated":
        return f"mba_{hex_value(va)}"
    if classification == "clear_wrapper_to_obfuscated":
        return f"wrapper_{hex_value(va)}"
    if classification == "DriverEntry" or va == 0x140C61000:
        return "DriverEntry"
    return f"{classification}_{hex_value(va)}"


def decode_range(
    pe: pefile.PE,
    va: int,
    size: int,
    *,
    limit_insns: int | None = None,
) -> list[dict[str, Any]]:
    if size <= 0:
        return []
    rva = va - int(pe.OPTIONAL_HEADER.ImageBase)
    try:
        offset = pe.get_offset_from_rva(rva)
    except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return []
    data = bytes(pe.__data__[offset : offset + size])
    md = make_disassembler(skipdata=False)
    rows: list[dict[str, Any]] = []
    consumed = 0
    for insn in md.disasm(data, va):
        rows.append(
            {
                "va": insn.address,
                "size": insn.size,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "text": f"{insn.mnemonic} {insn.op_str}".strip(),
                "bytes": bytes(insn.bytes).hex(),
            }
        )
        consumed += insn.size
        if limit_insns is not None and len(rows) >= limit_insns:
            break
        if consumed >= size:
            break
    return rows


def first_imm_target(insns: list[dict[str, Any]], mnemonic: str) -> int | None:
    md = make_disassembler()
    for row in insns[:12]:
        if row["mnemonic"] != mnemonic:
            continue
        decoded = list(md.disasm(bytes.fromhex(row["bytes"]), row["va"], count=1))
        if not decoded:
            continue
        insn = decoded[0]
        if insn.operands and insn.operands[0].type == X86_OP_IMM:
            return int(insn.operands[0].imm)
    return None


def collect_rel_targets(insns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    md = make_disassembler()
    rows: list[dict[str, Any]] = []
    for row in insns:
        if row["mnemonic"] not in (
            "call",
            "jmp",
            "je",
            "jne",
            "ja",
            "jb",
            "jae",
            "jbe",
            "jg",
            "jl",
        ):
            continue
        raw = bytes.fromhex(row["bytes"])
        if not raw:
            continue
        decoded = list(md.disasm(raw, row["va"], count=1))
        if not decoded or not decoded[0].operands:
            continue
        op = decoded[0].operands[0]
        if op.type == X86_OP_IMM:
            rows.append(
                {"from": row["va"], "to": int(op.imm), "mnemonic": row["mnemonic"]}
            )
    return rows


def linear_coverage(
    pe: pefile.PE,
    slots: dict[int, dict[str, Any]],
    dump_dir: Path | None,
) -> dict[str, Any]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    md = make_disassembler(skipdata=True)
    section_rows: list[dict[str, Any]] = []
    rel_call_targets: set[int] = set()
    rel_jmp_targets: set[int] = set()
    iat_stubs: dict[int, str] = {}
    total_insns = 0
    total_decoded = 0
    total_gaps = 0
    total_classified_gaps = 0
    total_virtual = 0
    mnemonic_counts: Counter[str] = Counter()
    coarse_counts: Counter[str] = Counter()
    fine_counts: Counter[str] = Counter()
    run_count = 0
    run_len_hist = Counter()
    insn_dump_path = None if dump_dir is None else dump_dir / "instructions.tsv.gz"
    gap_dump_path = None if dump_dir is None else dump_dir / "gaps.tsv.gz"
    dump_handle = None
    gap_handle = None
    if dump_dir is not None:
        dump_dir.mkdir(parents=True, exist_ok=True)
        dump_handle = open_deterministic_gzip_text(insn_dump_path)
        dump_handle.write("va\tsize\tbytes\ttext\tsection\n")
        gap_handle = open_deterministic_gzip_text(gap_dump_path)
        gap_handle.write("va\tsize\tbytes\tcoarse\tfine\tsection\n")
    try:
        for section in xref.executable_sections(pe):
            name = xref.section_name(section)
            virtual_size = int(section.Misc_VirtualSize)
            section_va = image_base + int(section.VirtualAddress)
            data = bytes(section.get_data())[:virtual_size]
            total_virtual += virtual_size
            decoded = 0
            gaps = 0
            classified_gaps = 0
            insns = 0
            run_va: int | None = None
            run_off = 0
            run_len = 0

            for insn in md.disasm(data, section_va):
                offset = insn.address - section_va
                if insn.id == 0:
                    size = insn.size or 1
                    gaps += size
                    if run_va is not None and offset == run_off + run_len:
                        run_len += size
                    else:
                        added_runs, added_classified = record_gap_run(
                            data,
                            name,
                            run_va,
                            run_off,
                            run_len,
                            run_len_hist=run_len_hist,
                            coarse_counts=coarse_counts,
                            fine_counts=fine_counts,
                            gap_handle=gap_handle,
                        )
                        run_count += added_runs
                        classified_gaps += added_classified
                        run_va = insn.address
                        run_off = offset
                        run_len = size
                    continue
                added_runs, added_classified = record_gap_run(
                    data,
                    name,
                    run_va,
                    run_off,
                    run_len,
                    run_len_hist=run_len_hist,
                    coarse_counts=coarse_counts,
                    fine_counts=fine_counts,
                    gap_handle=gap_handle,
                )
                run_count += added_runs
                classified_gaps += added_classified
                run_va = None
                run_len = 0
                insns += 1
                decoded += insn.size
                mnemonic_counts[insn.mnemonic] += 1
                raw = bytes(insn.bytes)
                if dump_handle is not None:
                    dump_handle.write(
                        f"{insn.address:x}\t{insn.size}\t{raw.hex()}\t"
                        f"{insn.mnemonic} {insn.op_str}\t{name}\n"
                    )
                if raw[:2] == b"\xff\x25" and insn.size == 6:
                    disp = struct.unpack_from("<i", raw, 2)[0]
                    target = insn.address + insn.size + disp
                    imported = slots.get(target)
                    if imported is not None:
                        iat_stubs[insn.address] = imported["name"]
                if insn.mnemonic == "call" and raw[:1] == b"\xe8" and insn.size == 5:
                    disp = struct.unpack_from("<i", raw, 1)[0]
                    rel_call_targets.add(insn.address + insn.size + disp)
                elif insn.mnemonic == "jmp" and raw[:1] == b"\xe9" and insn.size == 5:
                    disp = struct.unpack_from("<i", raw, 1)[0]
                    rel_jmp_targets.add(insn.address + insn.size + disp)
            added_runs, added_classified = record_gap_run(
                data,
                name,
                run_va,
                run_off,
                run_len,
                run_len_hist=run_len_hist,
                coarse_counts=coarse_counts,
                fine_counts=fine_counts,
                gap_handle=gap_handle,
            )
            run_count += added_runs
            classified_gaps += added_classified
            run_va = None
            run_len = 0
            covered = decoded + gaps
            if covered < virtual_size:
                run_va = section_va + covered
                run_off = covered
                run_len = virtual_size - covered
                gaps += run_len
                added_runs, added_classified = record_gap_run(
                    data,
                    name,
                    run_va,
                    run_off,
                    run_len,
                    run_len_hist=run_len_hist,
                    coarse_counts=coarse_counts,
                    fine_counts=fine_counts,
                    gap_handle=gap_handle,
                )
                run_count += added_runs
                classified_gaps += added_classified
                run_va = None
                run_len = 0
            total_insns += insns
            total_decoded += decoded
            total_gaps += gaps
            total_classified_gaps += classified_gaps
            classified_here = decoded + classified_gaps
            labeled_here = decoded + gaps
            section_rows.append(
                {
                    "name": name,
                    "va": section_va,
                    "rva": int(section.VirtualAddress),
                    "virtual_size": virtual_size,
                    "instruction_count": insns,
                    "decoded_bytes": decoded,
                    "gap_bytes": gaps,
                    "classified_bytes": classified_here,
                    "labeled_bytes": labeled_here,
                    "coverage": round(decoded / virtual_size, 6)
                    if virtual_size
                    else 0.0,
                    "classified_coverage": round(classified_here / virtual_size, 6)
                    if virtual_size
                    else 0.0,
                    "labeled_coverage": round(labeled_here / virtual_size, 6)
                    if virtual_size
                    else 0.0,
                }
            )
    finally:
        if dump_handle is not None:
            dump_handle.close()
        if gap_handle is not None:
            gap_handle.close()

    labeled_gap = sum(coarse_counts.values())
    classified_gap = total_classified_gaps
    unclassified = max(0, total_gaps - classified_gap)
    classified_all = total_decoded + classified_gap
    labeled_all = total_decoded + labeled_gap
    return {
        "executable_virtual_bytes": total_virtual,
        "instruction_count": total_insns,
        "decoded_bytes": total_decoded,
        "gap_bytes": total_gaps,
        "coverage": round(total_decoded / total_virtual, 6) if total_virtual else 0.0,
        "classified_coverage": round(classified_all / total_virtual, 6)
        if total_virtual
        else 0.0,
        "labeled_coverage": round(labeled_all / total_virtual, 6)
        if total_virtual
        else 0.0,
        "sections": section_rows,
        "mnemonic_top": mnemonic_counts.most_common(40),
        "rel_call_targets": sorted(rel_call_targets),
        "rel_jmp_targets": sorted(rel_jmp_targets),
        "iat_stubs": iat_stubs,
        "instruction_dump": str(insn_dump_path) if insn_dump_path is not None else None,
        "gap_dump": str(gap_dump_path) if gap_dump_path is not None else None,
        "gaps": {
            "bytes": total_gaps,
            "runs": run_count,
            "labeled_bytes": labeled_gap,
            "classified_bytes": classified_gap,
            "unclassified_bytes": unclassified,
            "run_len_buckets": {
                "1": run_len_hist.get(1, 0),
                "2-4": sum(c for n, c in run_len_hist.items() if 2 <= n <= 4),
                "5-16": sum(c for n, c in run_len_hist.items() if 5 <= n <= 16),
                "17+": sum(c for n, c in run_len_hist.items() if n >= 17),
            },
            "classes": dict(sorted(coarse_counts.items())),
            "fine_top": fine_counts.most_common(25),
        },
    }


def in_image(pe: pefile.PE, va: int) -> bool:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    rva = va - image_base
    if rva < 0:
        return False
    for section in xref.executable_sections(pe):
        start = int(section.VirtualAddress)
        end = start + int(section.Misc_VirtualSize)
        if start <= rva < end:
            return True
    return False


def raw_at(pe: pefile.PE, va: int, size: int) -> bytes:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    try:
        offset = pe.get_offset_from_rva(va - image_base)
    except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return b""
    return bytes(pe.__data__[offset : offset + size])


def entry_authority(source: str) -> tuple[str, str]:
    sources = set(source.split("+"))
    if "pe_entry" in sources:
        return "pe_entry", "high"
    if "known" in sources:
        return "known_static_label", "high"
    if "iat_stub" in sources:
        return "iat_jump_stub", "high"
    if "pdata" in sources:
        return "unwind_entry", "high"
    if "ghidra" in sources:
        return "ghidra_function", "medium"
    if "rel_call_target" in sources:
        return "heuristic_call_target", "heuristic"
    return "entry_candidate", "heuristic"


def build_function_entry(
    pe: pefile.PE,
    va: int,
    end_va: int,
    *,
    source: str,
    pdata: dict[str, int] | None,
    stub_name: str | None = None,
    ghidra_name: str | None = None,
    ghidra_body_ranges: list[tuple[int, int]] | None = None,
    ghidra_body_addresses: int | None = None,
    head_limit: int = 16,
    body_insn_limit: int | None = None,
) -> dict[str, Any]:
    size = max(0, end_va - va)
    giant = size > 1024 * 1024
    limit = 48 if giant else body_insn_limit
    insns = decode_range(pe, va, size, limit_insns=limit)
    raw_head = raw_at(pe, va, min(16, size or 16))
    classification = classify_from_head(insns, size, raw_head)
    if giant:
        classification = "obfuscated_blob"
    iat_names: list[str] = []
    thunk_target = first_imm_target(insns, "jmp")
    transfers = collect_rel_targets(insns[:64])
    name = name_function(va, classification, iat_names, thunk_target, stub_name)
    if va not in KNOWN_NAMES and ghidra_name and not ghidra_name.startswith("FUN_"):
        name = ghidra_name
    mnemonic_counts = Counter(row["mnemonic"] for row in insns)
    entry_kind, confidence = entry_authority(source)
    return {
        "name": name,
        "va": va,
        "rva": va - int(pe.OPTIONAL_HEADER.ImageBase),
        "end_va": end_va,
        "size": size,
        "source": source,
        "entry_kind": entry_kind,
        "entry_confidence": confidence,
        "classification": classification,
        "instruction_count_sampled": len(insns),
        "instruction_count_is_sample": giant
        or (body_insn_limit is not None and len(insns) >= (body_insn_limit or 0)),
        "iat_imports": iat_names,
        "iat_call_site_count": 0,
        "iat_call_sites": [],
        "thunk_target": thunk_target,
        "transfers": transfers[:32],
        "head": [
            {"va": hex_value(row["va"]), "text": row["text"], "bytes": row["bytes"]}
            for row in insns[:head_limit]
        ],
        "mnemonic_top": mnemonic_counts.most_common(8),
        "pdata": pdata,
        "ghidra_name": ghidra_name,
        "ghidra_body_ranges": ghidra_body_ranges or [],
        "ghidra_body_addresses": ghidra_body_addresses,
        "raw_head": raw_head.hex(),
    }


def resolve_call_owner(
    call_va: int,
    entries: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, str | None, int]:
    """Choose one evidence-backed owner for a static IAT call site."""

    ghidra_candidates = [
        row
        for row in entries
        if any(start <= call_va < end for start, end in row["ghidra_body_ranges"])
    ]
    if ghidra_candidates:
        ghidra_candidates.sort(
            key=lambda row: (
                row.get("ghidra_body_addresses")
                or sum(end - start for start, end in row["ghidra_body_ranges"]),
                sum(end - start for start, end in row["ghidra_body_ranges"]),
                row["va"],
            )
        )
        return ghidra_candidates[0], "ghidra_body", len(ghidra_candidates)

    pdata_candidates = []
    for row in entries:
        pdata = row.get("pdata")
        if pdata is None:
            continue
        image_base = row["va"] - row["rva"]
        start = image_base + int(pdata["begin_rva"])
        end = image_base + int(pdata["end_rva"])
        if start <= call_va < end:
            pdata_candidates.append(row)
    if pdata_candidates:
        pdata_candidates.sort(key=lambda row: (row["pdata"]["size"], row["va"]))
        return pdata_candidates[0], "pdata_smallest_range", len(pdata_candidates)
    return None, None, 0


def build_call_sites(
    direct_calls: list[dict[str, Any]],
    stub_calls: list[dict[str, Any]],
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    call_sites: list[dict[str, Any]] = []
    for route, rows in (("direct_iat", direct_calls), ("iat_stub", stub_calls)):
        for row in rows:
            va = int(row["instruction_va"])
            owner, basis, candidate_count = resolve_call_owner(va, entries)
            call_sites.append(
                {
                    "name": KNOWN_CALLSITE_NAMES.get(
                        va, f"{route}_call_{row['name']}_{hex_value(va)}"
                    ),
                    "va": va,
                    "rva": int(row["instruction_rva"]),
                    "route": route,
                    "import": row["name"],
                    "dll": row["dll"],
                    "instruction": row["instruction"],
                    "bytes": row["bytes"],
                    "owner_va": owner["va"] if owner else None,
                    "owner_name": owner["name"] if owner else None,
                    "owner_basis": basis,
                    "owner_candidate_count": candidate_count,
                }
            )
    return sorted(call_sites, key=lambda row: (row["va"], row["import"], row["route"]))


def next_boundary(sorted_starts: list[int], va: int, fallback: int) -> int:
    index = 0
    # sorted_starts includes va; the next start after va is the exclusive end.
    high = len(sorted_starts)
    while index < high:
        mid = (index + high) // 2
        if sorted_starts[mid] <= va:
            index = mid + 1
        else:
            high = mid
    if index < len(sorted_starts):
        return sorted_starts[index]
    return fallback


def load_ghidra_catalog(
    path: Path,
    *,
    image_base: int,
    input_sha256: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load and validate the complete private Ghidra authority catalog."""

    if not path.is_file():
        raise ValueError(f"required Ghidra catalog does not exist: {path}")
    raw = path.read_bytes()
    catalog_sha256 = hashlib.sha256(raw).hexdigest()
    items = [
        json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()
    ]
    if len(items) < 3:
        raise ValueError("Ghidra catalog is missing its header, functions, or footer")
    header = items[0]
    footer = items[-1]
    if header.get("type") != "header" or footer.get("type") != "footer":
        raise ValueError(
            "Ghidra catalog must start with a header and end with a footer"
        )
    if header.get("program") != "Randgrid.sys":
        raise ValueError(f"unexpected Ghidra program: {header.get('program')!r}")
    header_base = int(str(header.get("image_base")), 16)
    if header_base != image_base:
        raise ValueError(
            f"Ghidra image base {header_base:#x} does not match PE {image_base:#x}"
        )
    header_sha = str(header.get("program_sha256") or "").lower()
    if header_sha != input_sha256:
        raise ValueError(
            f"Ghidra program SHA-256 {header_sha!r} does not match the pinned PE"
        )
    if footer.get("cancelled"):
        raise ValueError("Ghidra catalog export was cancelled")

    rows = [item for item in items[1:-1] if item.get("type") == "function"]
    if len(rows) != len(items) - 2:
        raise ValueError("Ghidra catalog contains unexpected record types")
    written = int(footer.get("written_functions", -1))
    if written != len(rows):
        raise ValueError(
            f"Ghidra footer says {written} functions but {len(rows)} records exist"
        )
    manager_count = int(header.get("ghidra_function_count", -1))
    if manager_count < written:
        raise ValueError(
            "Ghidra manager function count is smaller than the exported catalog"
        )

    for item in rows:
        if item.get("external"):
            raise ValueError(
                "external function unexpectedly present in the internal catalog"
            )
        ranges = item.get("body_ranges")
        if not isinstance(ranges, list) or not ranges:
            raise ValueError(f"Ghidra function {item.get('entry')} has no body_ranges")
        normalized: list[tuple[int, int]] = []
        for body_range in ranges:
            start = int(str(body_range["min"]), 16)
            end_inclusive = int(str(body_range["max"]), 16)
            if end_inclusive < start:
                raise ValueError(f"invalid Ghidra body range for {item.get('entry')}")
            normalized.append((start, end_inclusive + 1))
        item["_body_ranges"] = normalized

    provenance = {
        "file": path.name,
        "sha256": catalog_sha256,
        "ghidra_version": header.get("ghidra_version"),
        "program": header.get("program"),
        "program_sha256": header_sha,
        "image_base": header.get("image_base"),
        "language_id": header.get("language_id"),
        "compiler_spec_id": header.get("compiler_spec_id"),
        "manager_function_count": manager_count,
        "written_functions": written,
        "cancelled": False,
    }
    return rows, provenance


def infer_end_va(
    pe: pefile.PE,
    va: int,
    meta: dict[str, Any],
    next_va: int,
) -> int:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    if "iat_stub" in meta["source"] or meta.get("stub_name"):
        return min(va + 6, next_va)
    if meta.get("pdata"):
        return image_base + int(meta["pdata"]["end_rva"])
    head = decode_range(pe, va, 16, limit_insns=1)
    if head and head[0]["mnemonic"] == "jmp":
        return min(va + int(head[0]["size"]), next_va)
    proposed = meta.get("end_va") or (va + 0x1000)
    return min(next_va, int(proposed), va + 0x1000)


def build_payload(
    target: Path,
    dump_dir: Path | None,
    ghidra_catalog: Path,
) -> dict[str, Any]:
    verified_input = verify_target(target)
    pe = pefile.PE(str(target), fast_load=False)
    pe.parse_data_directories()
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    entry_va = image_base + entry_rva
    ghidra_rows, ghidra_provenance = load_ghidra_catalog(
        ghidra_catalog,
        image_base=image_base,
        input_sha256=verified_input["sha256"],
    )
    slots = xref.import_slots(pe)
    pdata_rows = xref.runtime_functions(pe)
    runtime = xref.RuntimeLookup(pdata_rows)
    direct = xref.decoded_direct_transfers(pe, slots, runtime)
    stub_transfers = xref.decoded_transfers_to_iat_stubs(pe, direct, runtime)
    direct_calls = [row for row in direct if row["kind"] == "call"]
    stub_calls = [row for row in stub_transfers if row["kind"] == "call"]

    coverage = linear_coverage(pe, slots, dump_dir)

    exec_end_by_section = []
    for section in xref.executable_sections(pe):
        start = image_base + int(section.VirtualAddress)
        end = start + int(section.Misc_VirtualSize)
        exec_end_by_section.append((start, end))

    def clamp_end(va: int, proposed: int) -> int:
        for start, end in exec_end_by_section:
            if start <= va < end:
                return min(proposed, end)
        return proposed

    seeds: dict[int, dict[str, Any]] = {}

    def add_seed(
        va: int,
        source: str,
        end_va: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if not in_image(pe, va):
            return
        row = seeds.get(va)
        payload = extra or {}
        if row is None:
            seeds[va] = {"va": va, "source": source, "end_va": end_va, **payload}
            return
        if end_va is not None and (row.get("end_va") is None or end_va > row["end_va"]):
            row["end_va"] = end_va
        if source not in row["source"]:
            row["source"] = f"{row['source']}+{source}"
        row.update({k: v for k, v in payload.items() if k not in row})

    for row in pdata_rows:
        begin_va = image_base + row["begin_rva"]
        end_va = image_base + row["end_rva"]
        add_seed(begin_va, "pdata", end_va, {"pdata": row})

    add_seed(entry_va, "pe_entry")
    for va, name in KNOWN_NAMES.items():
        add_seed(va, "known", extra={"known_name": name})
    for va, name in coverage["iat_stubs"].items():
        add_seed(va, "iat_stub", va + 6, {"stub_name": name})
    for va in coverage["rel_call_targets"]:
        if looks_like_entry(raw_at(pe, va, 8)):
            add_seed(va, "rel_call_target")
    for row in ghidra_rows:
        entry = (
            int(str(row["entry"]), 16)
            if isinstance(row["entry"], str)
            else int(row["entry"])
        )
        body_ranges = list(row["_body_ranges"])
        body_end = max(end for _, end in body_ranges)
        add_seed(
            entry,
            "ghidra",
            body_end,
            {
                "ghidra_name": row.get("name"),
                "ghidra_body_ranges": body_ranges,
                "ghidra_body_addresses": int(row.get("body_addresses") or 0),
            },
        )

    starts = sorted(seeds)
    functions: list[dict[str, Any]] = []
    for va in starts:
        meta = seeds[va]
        fallback = clamp_end(va, va + 0x1000)
        next_va = next_boundary(starts, va, fallback)
        end_va = infer_end_va(pe, va, meta, next_va)
        end_va = clamp_end(va, end_va)
        if end_va <= va:
            end_va = clamp_end(va, va + 1)
        functions.append(
            build_function_entry(
                pe,
                va,
                end_va,
                source=meta["source"],
                pdata=meta.get("pdata"),
                stub_name=meta.get("stub_name"),
                ghidra_name=meta.get("ghidra_name"),
                ghidra_body_ranges=meta.get("ghidra_body_ranges"),
                ghidra_body_addresses=meta.get("ghidra_body_addresses"),
            )
        )

    call_sites = build_call_sites(direct_calls, stub_calls, functions)
    calls_by_owner: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for call_site in call_sites:
        if call_site["owner_va"] is not None:
            calls_by_owner[int(call_site["owner_va"])].append(call_site)
    for row in functions:
        owned = calls_by_owner.get(row["va"], [])
        row["iat_call_sites"] = owned
        row["iat_call_site_count"] = len(owned)
        row["iat_imports"] = sorted({site["import"] for site in owned})
        if row["iat_imports"] and row["classification"] in {"unknown", "undecodable"}:
            row["classification"] = "import_bearing"
        generic_prefixes = (
            "unknown_",
            "undecodable_",
            "import_bearing_",
            "clear_",
            "clear_msvc_",
            "iat_call_wrapper_",
        )
        if (
            row["iat_imports"]
            and row["va"] not in KNOWN_NAMES
            and (
                row["ghidra_name"] is None
                or str(row["ghidra_name"]).startswith("FUN_")
                or row["name"].startswith(generic_prefixes)
            )
        ):
            row["name"] = name_function(
                row["va"],
                row["classification"],
                row["iat_imports"],
                row["thunk_target"],
                None,
            )

    class_counts = Counter(row["classification"] for row in functions)
    source_counts = Counter(
        source for row in functions for source in row["source"].split("+")
    )
    named_known = [row for row in functions if row["va"] in KNOWN_NAMES]
    named_iat = [row for row in functions if row["classification"] == "iat_stub"]
    wrappers = [
        row
        for row in functions
        if row["classification"] == "clear_wrapper_to_obfuscated"
    ]
    with_imports = [row for row in functions if row["iat_imports"]]

    entry_follow = first_imm_target(decode_range(pe, entry_va, 16), "jmp")

    def compact_row(row: dict[str, Any], *, include_head: bool) -> dict[str, Any]:
        item = {
            "name": row["name"],
            "va": hex_value(row["va"]),
            "rva": hex_value(row["rva"]),
            "end_va": hex_value(row["end_va"]),
            "size": row["size"],
            "source": row["source"],
            "entry_kind": row["entry_kind"],
            "entry_confidence": row["entry_confidence"],
            "classification": row["classification"],
            "iat_imports": row["iat_imports"],
            "iat_call_site_count": row["iat_call_site_count"],
            "ghidra_name": row["ghidra_name"],
            "thunk_target": hex_value(row["thunk_target"])
            if row["thunk_target"]
            else None,
            "instruction_count_sampled": row["instruction_count_sampled"],
            "instruction_count_is_sample": row["instruction_count_is_sample"],
        }
        if include_head:
            item["head"] = row["head"]
            item["mnemonic_top"] = row["mnemonic_top"]
        return item

    dump_functions = [compact_row(row, include_head=True) for row in functions]
    publish_entries = []
    for row in functions:
        interesting = (
            row["va"] in KNOWN_NAMES
            or row["iat_imports"]
            or row["classification"]
            in {
                "iat_stub",
                "clear_msvc",
                "clear_wrapper_to_obfuscated",
                "thunk",
                "clear",
                "obfuscated_blob",
            }
            or "known" in row["source"]
            or "pe_entry" in row["source"]
        )
        publish_entries.append(compact_row(row, include_head=interesting))

    compact_call_sites = [
        {
            **{
                key: value
                for key, value in row.items()
                if key not in {"va", "rva", "owner_va"}
            },
            "va": hex_value(row["va"]),
            "rva": hex_value(row["rva"]),
            "owner_va": hex_value(row["owner_va"])
            if row["owner_va"] is not None
            else None,
        }
        for row in call_sites
    ]

    if dump_dir is not None:
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / "entries.json").write_text(
            json.dumps(dump_functions, indent=2), encoding="utf-8", newline="\n"
        )

    return {
        "schema_version": 2,
        "authority": {
            "pinned_input_enforced": True,
            "ghidra_catalog": ghidra_provenance,
            "toolchain": {
                "python": platform.python_version(),
                "capstone_distribution": importlib.metadata.version("capstone"),
                "capstone_module": getattr(capstone_module, "__version__", None),
                "capstone_engine": list(capstone_module.cs_version()),
                "pefile_distribution": importlib.metadata.version("pefile"),
                "pefile_module": getattr(pefile, "__version__", None),
            },
        },
        "input": {
            **verified_input,
            "image_base": image_base,
            "entry_rva": entry_rva,
            "entry_va": entry_va,
            "entry_follows": entry_follow,
        },
        "coverage": {
            "executable_virtual_bytes": coverage["executable_virtual_bytes"],
            "instruction_count": coverage["instruction_count"],
            "decoded_bytes": coverage["decoded_bytes"],
            "gap_bytes": coverage["gap_bytes"],
            "coverage": coverage["coverage"],
            "classified_coverage": coverage.get("classified_coverage"),
            "labeled_coverage": coverage.get("labeled_coverage"),
            "sections": coverage["sections"],
            "mnemonic_top": coverage["mnemonic_top"],
            "instruction_dump": coverage["instruction_dump"],
            "gap_dump": coverage.get("gap_dump"),
            "gaps": coverage.get("gaps"),
        },
        "seeds": {
            "pdata": len(pdata_rows),
            "iat_stubs": len(coverage["iat_stubs"]),
            "rel_call_targets": len(coverage["rel_call_targets"]),
            "rel_jmp_targets": len(coverage["rel_jmp_targets"]),
            "known": len(KNOWN_NAMES),
            "ghidra_catalog": len(ghidra_rows),
            "unique_entry_candidates": len(functions),
        },
        "classification_counts": dict(sorted(class_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "imports": {
            "slot_count": len(slots),
            "direct_call_count": len(direct_calls),
            "stub_call_count": len(stub_calls),
            "unique_call_site_count": len(call_sites),
            "owned_call_site_count": sum(
                row["owner_va"] is not None for row in call_sites
            ),
            "unresolved_call_site_count": sum(
                row["owner_va"] is None for row in call_sites
            ),
            "entries_with_owned_iat_calls": len(with_imports),
            "call_sites_with_multiple_owner_candidates": sum(
                row["owner_candidate_count"] > 1 for row in call_sites
            ),
        },
        "call_sites": compact_call_sites,
        "named_known": [
            {
                "name": row["name"],
                "va": hex_value(row["va"]),
                "classification": row["classification"],
                "size": row["size"],
            }
            for row in named_known
        ],
        "iat_stub_count": len(named_iat),
        "clear_wrapper_count": len(wrappers),
        "largest": sorted(
            (
                {
                    "name": row["name"],
                    "va": hex_value(row["va"]),
                    "size": row["size"],
                    "classification": row["classification"],
                    "source": row["source"],
                }
                for row in functions
            ),
            key=lambda row: (-row["size"], row["va"]),
        )[:30],
        "entries": publish_entries,
        "interpretation": {
            "coverage": (
                "Instruction coverage is a linear Capstone sweep of every executable section. "
                "Recognized skipdata bytes are classified individually as 64-bit #UD encodings, "
                "invalid prefixes/VEX/ModR/M, truncated instructions, or other rejected opcodes. "
                "Unknown fallback labels are excluded from semantic classified coverage."
            ),
            "gaps": (
                "A skipdata byte is present in the file. It is not a missing region. Capstone "
                "refused to start a 64-bit instruction there; the next linear instruction begins "
                "immediately after the skipped run. The taxonomy names the reason."
            ),
            "pdata": (
                "Exception-directory ranges are loader-consumed unwind facts. In this binary many "
                "are MBA epilogue fragments or obfuscated blocks, not conventional compiler functions."
            ),
            "ghidra": (
                f"The validated Ghidra catalog contributes {len(ghidra_rows)} internal entry "
                "candidates and is hash-pinned in authority metadata. Entries can overlap because "
                "Ghidra bodies, unwind ranges, and linkage stubs are distinct authority surfaces."
            ),
            "calls": (
                "IAT call instructions are call sites, never function seeds. Each call receives at "
                "most one primary owner: the smallest exact Ghidra body first, otherwise the "
                "smallest containing .pdata range, otherwise unresolved."
            ),
            "non_claim": (
                "A mapped instruction or named wrapper is static recovery, not runtime policy, "
                "bypass guidance, or a complete deobfuscation of MBA control flow."
            ),
        },
    }


def write_markdown(payload: dict[str, Any], output: Path) -> None:
    source = payload["input"]
    coverage = payload["coverage"]
    lines = [
        "# Randgrid.sys — static entry and call-site map",
        "",
        f"- SHA-256: `{source['sha256']}`",
        f"- Size: `{source['size']}` bytes",
        f"- Image base: `{hex_value(source['image_base'])}`",
        f"- PE entry: `{hex_value(source['entry_va'])}`",
        f"- Entry follows: `{hex_value(source['entry_follows']) if source.get('entry_follows') else 'unresolved'}`",
        f"- Unique entry candidates: `{payload['seeds']['unique_entry_candidates']}`",
        f"- `.pdata` ranges: `{payload['seeds']['pdata']}`",
        f"- IAT stubs: `{payload['seeds']['iat_stubs']}`",
        f"- Relative-call targets: `{payload['seeds']['rel_call_targets']}`",
        f"- Linear instructions: `{coverage['instruction_count']}`",
        (
            f"- Decoded executable bytes: `{coverage['decoded_bytes']}` / "
            f"`{coverage['executable_virtual_bytes']}` (`{coverage['coverage']:.4f}`)"
        ),
        (
            "- Recognized executable-byte coverage: "
            f"`{coverage.get('classified_coverage', coverage['coverage']):.4f}`"
        ),
        (
            "- Labeled executable-byte coverage: "
            f"`{coverage.get('labeled_coverage', coverage['coverage']):.4f}`"
        ),
        (
            f"- Exact IAT call sites: `{payload['imports']['unique_call_site_count']}` "
            f"(`{payload['imports']['owned_call_site_count']}` owned, "
            f"`{payload['imports']['unresolved_call_site_count']}` unresolved)"
        ),
        f"- Entries owning exact IAT calls: `{payload['imports']['entries_with_owned_iat_calls']}`",
        "",
        "## Authority inputs",
        "",
        f"- Pinned input enforced: `{payload['authority']['pinned_input_enforced']}`",
        (
            "- Ghidra catalog SHA-256: "
            f"`{payload['authority']['ghidra_catalog']['sha256']}`"
        ),
        f"- Ghidra version: `{payload['authority']['ghidra_catalog']['ghidra_version']}`",
        (
            "- Ghidra internal functions: "
            f"`{payload['authority']['ghidra_catalog']['written_functions']}`"
        ),
        "",
        "## Section coverage",
        "",
        "| Section | RVA | Virtual size | Instructions | Decoded | Gaps | Coverage |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in coverage["sections"]:
        lines.append(
            f"| `{row['name']}` | `{hex_value(row['rva'])}` | `{row['virtual_size']}` | "
            f"{row['instruction_count']} | {row['decoded_bytes']} | {row['gap_bytes']} | "
            f"{row['coverage']:.4f} |"
        )
    gaps = coverage.get("gaps") or {}
    if gaps:
        lines.extend(
            [
                "",
                "## Skipdata remainder (former 3.5%)",
                "",
                f"- Gap bytes: `{gaps.get('bytes', 0)}` in `{gaps.get('runs', 0)}` runs",
                f"- Labeled: `{gaps.get('labeled_bytes', 0)}`",
                f"- Semantically recognized: `{gaps.get('classified_bytes', 0)}`",
                f"- Unknown fallback: `{gaps.get('unclassified_bytes', 0)}`",
                f"- Run lengths: `{gaps.get('run_len_buckets', {})}`",
                "",
                (
                    "These bytes are in the file. They are not missing code. Linear x64 decode "
                    "refuses to start an instruction here (legacy 16/32-bit opcodes, invalid "
                    "VEX/LOCK/REX prefixes, rejected ModR/M groups). The next instruction in "
                    "the sweep begins immediately after each run."
                ),
                "",
                "| Gap class | Bytes |",
                "|---|---:|",
            ]
        )
        for name, count in (gaps.get("classes") or {}).items():
            lines.append(f"| `{name}` | {count} |")
        lines.extend(["", "| Fine name | Bytes |", "|---|---:|"])
        for name, count in gaps.get("fine_top") or []:
            lines.append(f"| `{name}` | {count} |")
    lines.extend(
        [
            "",
            "## Entry classification",
            "",
            "| Class | Count |",
            "|---|---:|",
        ]
    )
    for name, count in payload["classification_counts"].items():
        lines.append(f"| `{name}` | {count} |")
    lines.extend(
        [
            "",
            "## Known labels recovered",
            "",
            "| Name | VA | Class | Size |",
            "|---|---|---|---:|",
        ]
    )
    for row in payload["named_known"]:
        lines.append(
            f"| `{row['name']}` | `{row['va']}` | `{row['classification']}` | {row['size']} |"
        )
    lines.extend(
        [
            "",
            "## Largest mapped ranges",
            "",
            "| Name | VA | Size | Class | Source |",
            "|---|---|---:|---|---|",
        ]
    )
    for row in payload["largest"][:20]:
        lines.append(
            f"| `{row['name']}` | `{row['va']}` | {row['size']} | `{row['classification']}` | `{row['source']}` |"
        )
    lines.extend(
        [
            "",
            "## Top mnemonics (linear sweep)",
            "",
            "| Mnemonic | Count |",
            "|---|---:|",
        ]
    )
    for name, count in coverage["mnemonic_top"][:20]:
        lines.append(f"| `{name}` | {count} |")
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            payload["interpretation"]["coverage"],
            payload["interpretation"].get("gaps", ""),
            payload["interpretation"]["pdata"],
            payload["interpretation"]["ghidra"],
            payload["interpretation"]["calls"],
            payload["interpretation"]["non_claim"],
            "",
            (
                "The JSON companion lists every entry candidate and exact IAT call site with "
                "deterministic primary ownership. The Git-ignored analysis dump contains the "
                "full linear instruction stream."
            ),
            "",
        ]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument(
        "--ghidra-catalog",
        type=Path,
        required=True,
        help="validated GhidraFullFunctionCatalog JSONL authority input",
    )
    parser.add_argument("--json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--dump-dir", type=Path, default=DEFAULT_DUMP)
    parser.add_argument("--no-dump", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.target.is_file():
        raise SystemExit(f"target does not exist: {args.target}")
    if not args.ghidra_catalog.is_file():
        raise SystemExit(f"Ghidra catalog does not exist: {args.ghidra_catalog}")
    try:
        verify_target(args.target)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    dump_dir = None if args.no_dump else args.dump_dir
    payload = build_payload(args.target, dump_dir, args.ghidra_catalog)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    # Published evidence omits the full per-function head list when huge; keep it.
    args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8", newline="\n")
    write_markdown(payload, args.markdown)
    print(f"input sha256: {payload['input']['sha256']}")
    print(f"entry candidates: {payload['seeds']['unique_entry_candidates']}")
    print(f"IAT call sites: {payload['imports']['unique_call_site_count']}")
    print(f"instructions: {payload['coverage']['instruction_count']}")
    print(f"coverage: {payload['coverage']['coverage']}")
    print(f"classified: {payload['coverage'].get('classified_coverage')}")
    gaps = payload["coverage"].get("gaps") or {}
    print(
        f"gaps: {gaps.get('bytes')} unclassified={gaps.get('unclassified_bytes')} classes={gaps.get('classes')}"
    )
    print(f"classes: {payload['classification_counts']}")
    print(f"wrote {args.json}")
    print(f"wrote {args.markdown}")
    if dump_dir is not None:
        print(f"dump dir {dump_dir}")


if __name__ == "__main__":
    main()
