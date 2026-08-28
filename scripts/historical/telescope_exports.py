"""Static export/runtime fingerprinting for telescope24/25.dll.

Reads PE files only. Produces a deterministic JSON artifact with every export,
MSVC-demangled names (via Windows dbghelp), namespace counts, string
fingerprints, and a version-to-version comparison.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import pefile


GAME = Path(r"D:\SteamLibrary\steamapps\common\Call of Duty HQ")
TARGETS = [GAME / "telescope24.dll", GAME / "telescope25.dll"]
OUTPUT = Path(__file__).resolve().parent / "analysis" / "telescope-export-analysis.json"

NAMESPACES = (
    "JSC",
    "WTF",
    "WebCore",
    "bmalloc",
    "Inspector",
    "WebKit",
    "PAL",
    "IPC",
)
FINGERPRINT_TERMS = (
    "JavaScriptCore",
    "WebCore",
    "WebKit",
    "WTF",
    "bmalloc",
    "Yarr",
    "Activision",
    "telescope",
    "telemetry",
    "datax",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def undecorator():
    dbghelp = ctypes.WinDLL("dbghelp")
    function = dbghelp.UnDecorateSymbolName
    function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]
    function.restype = ctypes.c_uint

    def undecorate(name: str) -> str:
        encoded = name.encode("ascii", errors="replace")
        buffer = ctypes.create_string_buffer(32768)
        if function(encoded, buffer, len(buffer), 0):
            return buffer.value.decode("utf-8", errors="replace")
        return name

    return undecorate


def strings(data: bytes, minimum: int = 6) -> set[str]:
    values: set[str] = set()
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
        values.add(match.group().decode("ascii", errors="replace"))
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum, data):
        values.add(match.group().decode("utf-16-le", errors="replace"))
    return values


def namespace_for(raw: str, demangled: str) -> str:
    for namespace in NAMESPACES:
        if f"{namespace}::" in demangled or f"@{namespace}@@" in raw:
            return namespace
    if raw.startswith("JS") or demangled.startswith("JS"):
        return "JavaScriptCore C API"
    return "other"


def analyze(path: Path, undecorate) -> dict:
    pe = pefile.PE(str(path), fast_load=False)
    pe.parse_data_directories()
    exports = []
    namespace_counts: Counter[str] = Counter()
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            raw = symbol.name.decode("ascii", errors="replace") if symbol.name else ""
            demangled = undecorate(raw) if raw else ""
            namespace = namespace_for(raw, demangled)
            namespace_counts[namespace] += 1
            exports.append(
                {
                    "ordinal": symbol.ordinal,
                    "rva": symbol.address,
                    "name": raw,
                    "demangled": demangled,
                    "namespace": namespace,
                    "forwarder": (
                        symbol.forwarder.decode("ascii", errors="replace")
                        if symbol.forwarder
                        else None
                    ),
                }
            )

    extracted = strings(pe.__data__)
    fingerprints = {
        term: sorted(value for value in extracted if term.lower() in value.lower())[:100]
        for term in FINGERPRINT_TERMS
    }
    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("ascii", errors="replace")
        imports[dll] = [
            item.name.decode("ascii", errors="replace")
            if item.name
            else f"ordinal:{item.ordinal}"
            for item in entry.imports
        ]

    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": sha256(path),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "export_count": len(exports),
        "namespace_counts": dict(namespace_counts.most_common()),
        "imports": imports,
        "fingerprints": fingerprints,
        "exports": exports,
    }


def main() -> None:
    undecorate = undecorator()
    reports = [analyze(path, undecorate) for path in TARGETS if path.exists()]
    comparison = {}
    if len(reports) == 2:
        left, right = reports
        left_exports = {item["name"]: item["rva"] for item in left["exports"]}
        right_exports = {item["name"]: item["rva"] for item in right["exports"]}
        common = set(left_exports) & set(right_exports)
        comparison = {
            "common_export_names": len(common),
            "only_telescope24": sorted(set(left_exports) - set(right_exports)),
            "only_telescope25": sorted(set(right_exports) - set(left_exports)),
            "common_same_rva": sum(left_exports[name] == right_exports[name] for name in common),
            "byte_size_delta": right["size"] - left["size"],
        }
    payload = {"targets": reports, "comparison": comparison}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    for report in reports:
        print(Path(report["path"]).name, report["export_count"], "exports")
        for name, count in report["namespace_counts"].items():
            print(f"  {name}: {count}")
    print("comparison:", comparison)
    print("wrote", OUTPUT)


if __name__ == "__main__":
    main()
