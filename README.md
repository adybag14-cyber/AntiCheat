# RICOCHET / Randgrid Static Research

Evidence-backed, read-only research into the Windows RICOCHET component stack,
with the current deep dive focused on `Randgrid.sys`.

This repository contains original analysis, reproducible static-analysis tools,
and compact derived evidence. It does **not** contain Activision binaries,
extracted application bundles, private symbols, Ghidra databases, raw ETL,
raw system-handle rows, or raw live anti-cheat captures. Published runtime
artifacts are privacy-reduced aggregates; raw captures stay Git-ignored under
`local-analysis/`.

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
| Linear Capstone instructions | 3,478,904 |
| Executable-byte instruction coverage | 10,983,063 / 11,381,760 (0.9650) |
| Skipdata remainder classified | 398,697 / 398,697 (classified coverage 1.0000) |
| Unique mapped function starts | 9,109 |
| Exception-directory runtime functions | 2,191 |
| Largest unwind range | `0x2BADC9` bytes (about 2.73 MiB) |
| PE entry | `0x140C61000` `jmp 0x14059A14C` (MBA body) |
| `MmCopyMemory` calls | 18 |
| Process callback | thunk `0x140A294E0`, registered with `Remove = FALSE` |
| Thread callback | thunk `0x140A2AC70`; create-path system-thread/start-address inspection |
| Object callbacks | one registration record; pre/post policy still protected |
| Code Integrity | `CiValidateFileObject` x4, `CiFreePolicyInfo` x8 |
| CNG | all ten imports reached; ECDSA-P256/SHA-256 verification surface |
| Dynamic routine-name candidates | 0 non-import plaintext candidates |
| Running driver identity | exact static-input hash, valid Activision signature |
| Live DOS-device link | `Randgrid` → `\Device\Randgrid` |
| Runtime target object | exact audit/OB correlation; 2,208 same-thread matches, 1.0 dominant-object ratio |
| Persistent handles to game | 41 in both elevated snapshot and kernel rundown; 41/41 tuple overlap |
| Universal literal handle hiding | contradicted by direct runtime evidence |
| Selective handle-access reduction | exact `0x410` request → stored `0x1000`, reproduced non-admin and elevated |

The authoritative IAT/unwind narrative is
[`docs/07-randgrid-deep-dive.md`](docs/07-randgrid-deep-dive.md). It explicitly
separates import presence, linkage stubs, exact call sites, high-confidence
inferences, and unresolved behavior.

The complete instruction and function-start map is
[`docs/09-randgrid-full-function-map.md`](docs/09-randgrid-full-function-map.md).
It linearly disassembles every executable byte, merges `.pdata`, Ghidra, IAT
stubs/calls, and recovered prologues into 9,109 named starts, and keeps the
full instruction listing Git-ignored under `analysis/randgrid-full-map/`.

The bounded runtime follow-up is
[`docs/08-randgrid-runtime-behavior.md`](docs/08-randgrid-runtime-behavior.md).
It proves the live driver/device identity and cross-channel collision behavior,
identifies the live game process object, disproves universal literal handle
hiding, and narrows the remaining question to handle-specific access rewriting.

## Live capture (dynamic complement)

[`docs/08-live-analysis.md`](docs/08-live-analysis.md) records the separate
non-admin/UAC verification of the driver service, device namespace, broker
pipe, process-access mask, module API, region metadata, and crash-handler
topology. Its machine-readable authority is the privacy-reduced
[`evidence/live-capture.json`](evidence/live-capture.json).

Headline findings:

- three store-specific services are registered; the Steam `_sr` service was
  running;
- `Randgrid` resolves to `\Device\Randgrid`, while metadata-only and read-only
  opens returned error 5 in both privilege contexts; the device-specific denial
  mechanism remains unresolved;
- `COD.Broker.v1` was read-only openable and peekable without consuming data;
- a `0x410` game-process request produced a handle whose stored granted mask was
  `0x1000`, both non-admin and elevated;
- the game was neither elevated nor PPL;
- module snapshotting returned `Access denied`, while region metadata remained
  enumerable.

`scripts/live_capture.py` retains opt-in active blue-team research tiers. Their
presence is not evidence that they ran in the public capture, and raw output now
defaults to Git-ignored `local-analysis/`.

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

& .\.venv\Scripts\python.exe .\scripts\randgrid_full_map.py `
  --target 'X:\path\to\Randgrid.sys' `
  --json .\evidence\randgrid-full-map.json `
  --markdown .\evidence\randgrid-full-map.md `
  --dump-dir .\analysis\randgrid-full-map

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

- [`docs/`](docs/) — the static-analysis report chain, corrections, current
  Randgrid deep dive, and the live-capture report (doc 08).
- [`scripts/randgrid_deep_xrefs.py`](scripts/randgrid_deep_xrefs.py) — tested,
  deterministic PE/IAT/stub/unwind analyzer.
- [`scripts/randgrid_full_map.py`](scripts/randgrid_full_map.py) — complete
  linear instruction sweep and merged function-start catalog.
- [`scripts/live_capture.py`](scripts/live_capture.py) — tiered live-capture
  research probe (pure `ctypes`): observe / probe / memory-trap / optional
  injection; raw output is local-only by default.
- [`scripts/live_discover.ps1`](scripts/live_discover.ps1) — PowerShell
  live-state discovery helper (services, devices, pipes, game identity).
- [`scripts/ghidra/`](scripts/ghidra/) — read-only Ghidra evidence exporters.
- [`scripts/runtime/`](scripts/runtime/) — bounded passive runtime collectors;
  streaming audit/OB correlator; raw ETL/handle metadata remains Git-ignored.
- [`scripts/historical/`](scripts/historical/) — provenance scripts from reports
  05–06; not authoritative for behavior claims.
- [`evidence/`](evidence/) — compact generated JSON/Markdown without driver
  bytes, plus privacy-reduced live aggregates.
- [`tests/`](tests/) — helper tests and a published-evidence contract.

## Non-goals and boundaries

This repository does not provide:

- anti-cheat bypasses, disabling, evasion, or concealment;
- game input automation or cheating functionality;
- redistribution of third-party proprietary binaries or decompiled source;
- claims that a plan or static capability proves observed runtime behavior.

The published live evidence is a bounded, privacy-reduced observation. The
source tree also retains active blue-team research tiers for explicitly
authorized disposable sessions; those tiers are not represented as read-only,
are not part of the public verification run, and do not broaden the claims made
by the published artifact.

The work is independent research and is not affiliated with or endorsed by
Activision, Microsoft, or the RICOCHET team. See [`NOTICE.md`](NOTICE.md) for the
publication and licensing boundary.
