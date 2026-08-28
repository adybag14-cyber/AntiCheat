# RICOCHET / Randgrid Static Research

Evidence-backed, read-only research into the Windows RICOCHET component stack,
with the current deep dive focused on `Randgrid.sys`.

This repository contains original analysis, reproducible static-analysis tools,
and compact derived evidence. It does **not** contain Activision binaries,
extracted application bundles, private symbols, Ghidra databases, or live
anti-cheat captures.

## Latest confirmed Randgrid results

The analyzed driver has SHA-256:

```text
4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E
```

| Finding | Static result |
|---|---|
| Imported functions | 689 |
| Imports with an exact supported call form | 61 |
| Exact direct-IAT calls | 527 |
| Exact calls through local IAT stubs | 23 |
| Exception-directory runtime functions | 2,191 |
| Largest unwind range | `0x2BADC9` bytes (about 2.73 MiB) |
| `MmCopyMemory` calls | 18 |
| Process callback | thunk `0x140A294E0`, registered with `Remove = FALSE` |
| Thread callback | thunk `0x140A2AC70`; create-path system-thread/start-address inspection |
| Object callbacks | one registration record; pre/post policy still protected |
| Code Integrity | `CiValidateFileObject` x4, `CiFreePolicyInfo` x8 |
| CNG | all ten imports reached; ECDSA-P256/SHA-256 verification surface |
| Dynamic routine-name candidates | 0 non-import plaintext candidates |

The authoritative narrative is
[`docs/07-randgrid-deep-dive.md`](docs/07-randgrid-deep-dive.md). It explicitly
separates import presence, linkage stubs, exact call sites, high-confidence
inferences, and unresolved behavior.

## Reproduce the call census

Requirements:

- Python 3.11 or newer
- `pefile 2024.8.26`
- `capstone 5.0.9`
- a legally obtained local copy of the matching driver

PowerShell:

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r .\requirements.txt

& .\.venv\Scripts\python.exe .\scripts\randgrid_deep_xrefs.py `
  --target 'X:\path\to\Randgrid.sys' `
  --json .\evidence\randgrid-deep-xrefs.json `
  --markdown .\evidence\randgrid-deep-xrefs.md

& .\.venv\Scripts\python.exe -m unittest discover `
  -s .\tests -p 'test_*.py' -v
```

The analyzer never loads the driver. It parses the file, hashes it, enumerates
the IAT, decodes exact RIP-relative import calls and calls to local import stubs,
maps call sites to x64 unwind ranges, and scans selected strings and dynamic-name
candidates.

## Evidence model

The reports use the following hierarchy:

1. **Observed:** file hash, PE metadata, imports, strings, signatures, service
   state, or a concrete instruction/xref.
2. **Recovered behavior:** a coherent call/data path supported by decompilation
   and raw instruction evidence.
3. **Inference:** a conclusion supported by a complete API/string set but without
   one fully recovered high-level function.
4. **Unresolved:** protected/indirect behavior that the available evidence cannot
   justify naming.

An imported API is not automatically treated as used. A six-byte IAT jump stub
is also not use evidence until a caller to that stub is recovered.

## Repository map

- [`docs/`](docs/) — the static-analysis report chain, corrections, and current
  Randgrid deep dive.
- [`scripts/randgrid_deep_xrefs.py`](scripts/randgrid_deep_xrefs.py) — tested,
  deterministic PE/IAT/stub/unwind analyzer.
- [`scripts/ghidra/`](scripts/ghidra/) — read-only Ghidra evidence exporters.
- [`scripts/historical/`](scripts/historical/) — provenance scripts from reports
  05–06; not authoritative for behavior claims.
- [`evidence/`](evidence/) — compact generated JSON/Markdown without driver
  bytes.
- [`tests/`](tests/) — helper tests and a published-evidence contract.

## Non-goals and boundaries

This repository does not provide:

- anti-cheat bypasses, disabling, evasion, concealment, or process attachment;
- live driver/device probing or undocumented IOCTL recipes;
- game input automation or cheating functionality;
- redistribution of third-party proprietary binaries or decompiled source;
- claims that a plan or static capability proves observed runtime behavior.

The work is independent research and is not affiliated with or endorsed by
Activision, Microsoft, or the RICOCHET team. See [`NOTICE.md`](NOTICE.md) for the
publication and licensing boundary.
