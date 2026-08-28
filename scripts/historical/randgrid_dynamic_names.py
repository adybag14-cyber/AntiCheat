"""Compare Randgrid kernel-looking strings with its static imports.

This is a conservative static check for names that could be passed to
MmGetSystemRoutineAddress. It does not claim a string is used unless a code
xref is available; the output explicitly separates imported names from
non-import candidate strings.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pefile


TARGET = Path(r"D:\SteamLibrary\steamapps\common\Call of Duty HQ\Randgrid.sys")
OUTPUT = Path(__file__).resolve().parent / "analysis" / "randgrid-dynamic-name-candidates.json"
TOKEN = re.compile(
    r"\b(?:Zw|Nt|Mm|Ob|Ps|Ke|Ex|Rtl|Io|Se|Cm|FsRtl|Flt)[A-Z][A-Za-z0-9_]{4,127}\b"
)


def extract_strings(data: bytes, minimum: int = 6):
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
        yield match.start(), match.group().decode("ascii", errors="replace"), "ascii"
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum, data):
        yield match.start(), match.group().decode("utf-16-le", errors="replace"), "utf16le"


def section_for_offset(pe: pefile.PE, offset: int):
    for section in pe.sections:
        start = section.PointerToRawData
        end = start + section.SizeOfRawData
        if start <= offset < end:
            return {
                "name": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                "rva": section.VirtualAddress + (offset - start),
            }
    return {"name": None, "rva": None}


def main() -> None:
    pe = pefile.PE(str(TARGET), fast_load=False)
    pe.parse_data_directories()
    imports = set()
    imports_by_dll = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("ascii", errors="replace")
        names = []
        for item in entry.imports:
            if item.name:
                name = item.name.decode("ascii", errors="replace")
                imports.add(name)
                names.append(name)
        imports_by_dll[dll] = names

    candidates = {}
    counts = Counter()
    for offset, value, encoding in extract_strings(pe.__data__):
        for match in TOKEN.finditer(value):
            name = match.group(0)
            counts[name] += 1
            if name in imports:
                continue
            evidence = {
                "file_offset": offset,
                "encoding": encoding,
                **section_for_offset(pe, offset),
                "container_preview": value[:300],
            }
            candidates.setdefault(name, []).append(evidence)

    payload = {
        "target": str(TARGET),
        "static_import_count": len(imports),
        "imports_by_dll": imports_by_dll,
        "non_import_kernel_name_candidates": candidates,
        "candidate_occurrence_counts": {
            name: counts[name] for name in sorted(candidates)
        },
        "interpretation": (
            "Candidate strings are not proof of MmGetSystemRoutineAddress use. "
            "A caller/string code xref is required for that claim."
        ),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("static imports:", len(imports))
    print("non-import candidates:", len(candidates))
    for name, rows in sorted(candidates.items()):
        print(name, len(rows), rows[0]["name"], hex(rows[0]["rva"] or 0))
    print("wrote", OUTPUT)


if __name__ == "__main__":
    main()
