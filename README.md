# RICOCHET / Randgrid Static Research

Evidence-backed, read-only research into the Windows RICOCHET component stack,
with the current deep dive focused on `Randgrid.sys`.

This repository contains original analysis, reproducible static-analysis tools,
and compact derived evidence. It does **not** contain Activision binaries,
extracted application bundles, private symbols, Ghidra databases, raw ETL,
raw system-handle rows, or raw live anti-cheat captures. Published runtime
artifacts are privacy-reduced aggregates; raw captures stay Git-ignored under
`local-analysis/`.

## Linux passive system port

The first Linux systems slice is now implemented as the installable
`anticheat_system` package. It ports the repository's **passive observation and
evidence layer**; it does not claim to port Activision's proprietary Windows
driver, provide a bypass, or make a cheat verdict.

The Linux backend uses bounded, read-only `/proc` and `/sys` metadata to record:

- process identity anchored by an open procfs directory, a stable start time,
  and `pidfd` when the kernel/Python runtime expose it;
- executable SHA-256 identity, security status, seccomp state, Linux
  capabilities, memory-map aggregates, descriptor categories, namespaces, and
  cgroup shape;
- host hardening posture including active LSMs, Yama, lockdown, module-signature
  enforcement, BPF/perf restrictions, address randomization, and kernel taint;
- conservative, caveated signals for tracers, writable/executable mappings,
  deleted executable mappings, namespaces, and effective capabilities;
- bounded JSON Lines monitoring with a SHA-256 record chain.

Install the project and the existing analysis dependencies:

```bash
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt -e .
```

Capture one privacy-reduced snapshot of the collector itself:

```bash
python -m anticheat_system snapshot --self \
  --out local-analysis/linux-system-snapshot.json
```

Capture ten bounded samples and verify their hash chain:

```bash
python -m anticheat_system monitor --pid 1234 --samples 10 --interval 1 \
  --out local-analysis/linux-system-monitor.jsonl
python -m anticheat_system verify-chain \
  local-analysis/linux-system-monitor.jsonl
```

`--name` requires a unique exact process name; otherwise the collector fails
closed and asks for an explicit PID. Aggregate privacy mode is the default. Use
`--privacy-mode local` only for local investigation when PID, UID/GID,
executable path, and mapped executable basenames are actually required.

The architecture, trust boundary, parity map, and next porting stages are in
[`docs/09-linux-system-port.md`](docs/09-linux-system-port.md).

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
| Running driver identity | exact static-input hash, valid Activision signature |
| Live DOS-device link | `Randgrid` → `\Device\Randgrid` |
| Runtime target object | exact audit/OB correlation; 2,208 same-thread matches, 1.0 dominant-object ratio |
| Persistent handles to game | 41 in both elevated snapshot and kernel rundown; 41/41 tuple overlap |
| Universal literal handle hiding | contradicted by direct runtime evidence |
| Selective handle-access reduction | exact `0x410` request → stored `0x1000`, reproduced non-admin and elevated |

The authoritative narrative is
[`docs/07-randgrid-deep-dive.md`](docs/07-randgrid-deep-dive.md). It explicitly
separates import presence, linkage stubs, exact call sites, high-confidence
inferences, and unresolved behavior.

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
- [`scripts/live_capture.py`](scripts/live_capture.py) — tiered live-capture
  research probe (pure `ctypes`): observe / probe / memory-trap / optional
  injection; raw output is local-only by default.
- [`scripts/live_discover.ps1`](scripts/live_discover.ps1) — PowerShell
  live-state discovery helper (services, devices, pipes, game identity).
- [`scripts/ghidra/`](scripts/ghidra/) — read-only Ghidra evidence exporters.
- [`scripts/runtime/`](scripts/runtime/) — bounded passive runtime collectors;
  streaming audit/OB correlator; raw ETL/handle metadata remains Git-ignored.
- [`src/anticheat_system/`](src/anticheat_system/) — portable passive core,
  Linux procfs/sysfs backend, conservative signals, CLI, and monitor hash chain.
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
- claims that the Linux passive port is a kernel anti-cheat, a proprietary
  RICOCHET port, or a standalone cheating determination.

The published live evidence is a bounded, privacy-reduced observation. The
source tree also retains active blue-team research tiers for explicitly
authorized disposable sessions; those tiers are not represented as read-only,
are not part of the public verification run, and do not broaden the claims made
by the published artifact.

The work is independent research and is not affiliated with or endorsed by
Activision, Microsoft, or the RICOCHET team. See [`NOTICE.md`](NOTICE.md) for the
publication and licensing boundary.
