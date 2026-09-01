# Randgrid.sys — Best-Effort Source-Like Reconstruction

**Date:** 2026-09-01

**Input SHA-256:** `4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E`

**Boundary:** read-only static reconstruction. No driver load, device access,
IOCTL experimentation, runtime tracing, injection, bypass, or evasion work.

## What this is

The original C/C++ source is not recoverable from the shipped PE. Symbol names,
types, local variables, macros, comments, source files, compiler structure, and
most high-level control flow were removed or transformed. Randgrid's MBA and
flattened regions make a compiler-level decompilation especially unreliable.

This repository therefore uses the term **source-like reconstruction**:

- every corrected static entry candidate is indexed;
- every exact IAT call site has one deterministic primary owner;
- every one of the 3,478,904 linear instruction records is retained;
- every one of the 398,697 skipdata bytes is retained;
- all 11,381,760 executable virtual bytes occur exactly once in the full local
  reconstruction stream;
- recoverable high-confidence entry heads are shown as C-shaped, comment-only
  examples;
- opaque and unowned bytes stay explicit rather than being assigned to invented
  functions.

It is an annotated static lift, not the original source and not executable
driver logic.

## Authority inputs

The reconstruction is allowed only when all of these inputs validate:

| Input | Authority |
|---|---|
| `Randgrid.sys` | 13,130,616 bytes; SHA-256 above |
| Ghidra catalog | Ghidra 12.1.3; SHA-256 `57500F54C76753380A820481B4A94FE8B65624A35AA3F0EF322E63EDFC7356CD` |
| Ghidra program | `Randgrid.sys`; program SHA equals the PE SHA; image base `0x140000000` |
| Ghidra records | 8,105 internal functions, 8,775 exact body ranges, non-cancelled footer |
| Capstone | distribution 5.0.9; module 5.0.7; engine tuple `(5, 0, 1280)` |
| pefile | 2024.8.26 |

The full-map schema records this metadata. The analyzer refuses the wrong PE,
missing/truncated Ghidra catalogs, mismatched hashes or image bases, cancelled
exports, record-count disagreement, and functions without body ranges.

## Corrected entry and call model

The former map mixed direct IAT call instructions into the function-start set.
The corrected schema separates them:

| Record class | Count |
|---|---:|
| Static entry candidates | 8,764 |
| Exact direct-IAT call sites | 527 |
| Exact calls through IAT stubs | 23 |
| Total unique exact IAT call sites | 550 |
| Owned call sites | 550 |
| Entries selected as primary call owners | 543 |

A call instruction is never a function seed. Ownership uses this precedence:

1. exact Ghidra body-range membership, choosing the smallest body when ranges
   overlap;
2. otherwise the smallest containing `.pdata` range;
3. otherwise `unresolved`—never a nearest-address guess.

In this artifact 419 calls use exact Ghidra body ownership and 131 use the
smallest `.pdata` range. Although 103 calls have more than one possible body or
unwind candidate, each has exactly one deterministic primary owner and retains
the candidate count for audit.

## Full local reconstruction

`scripts/randgrid_source_reconstruction.py` merges the hash-pinned instruction
and gap dumps in virtual-address order and emits:

```text
analysis/randgrid-source-reconstruction/randgrid-source-like-reconstruction.c.gz
```

The file is valid C-shaped text whose function bodies contain comments only.
It cannot load a driver or perform any system action. Each line preserves the
virtual address, exact bytes, and linear assembly or gap classification. Exact
IAT calls are annotated with import and route. Changes in the primary owner
open a new source-like function part.

Much of the obfuscated linear stream has no defensible function owner. Those
records are emitted under explicit `unowned_executable_bytes` blocks. This is a
result, not missing coverage: the bytes are included, but the tooling refuses to
invent a function boundary.

The full output remains Git-ignored because it contains a bulk, byte-derived
representation of proprietary code. Its size, SHA-256, record count, byte
coverage, input hashes, and ownership totals are published in
`evidence/randgrid-source-reconstruction-summary.json`.

Current certified local artifact:

| Fact | Value |
|---|---:|
| Compressed source-like output | 38,456,067 bytes |
| Full-output SHA-256 | `162B6A88605DE3DBA4F0EA58D89DD44577BADB31CA73586DF144FC0A7314F87B` |
| Source-like records | 3,877,601 |
| Entry owners with records | 8,692 |
| Explicitly unowned records | 2,673,314 |
| Function/opaque parts | 13,419 |
| Instruction-dump SHA-256 | `701CF6C92B9C4B667CCD8B5178D2DF7FEE75832D3263E8D1C65D2551AED5B7E6` |
| Gap-dump SHA-256 | `82B2BFBE32F921EE4EAC81E86C31E64D5ED488C2D200BA4F20D4D0183ED59EB3` |

## Public source example

[`examples/randgrid-source-reconstruction.c`](../examples/randgrid-source-reconstruction.c)
contains compact, non-operational examples for the PE entry, known static
labels, callback thunks/bodies, registration paths, and the three exact named
callback-registration call sites. It uses only instruction comments and opaque
placeholders; it does not guess protected policy logic.

## Reproduction order

The Ghidra catalog is an authority input, so it must be exported **before** the
Python map:

```powershell
# 1. Verify the matching driver yourself.
Get-FileHash 'X:\path\to\Randgrid.sys' -Algorithm SHA256

# 2. Export the existing read-only Ghidra project first.
analyzeHeadless <projectDir> RandgridProject -process Randgrid.sys `
  -noanalysis -readOnly `
  -scriptPath .\scripts\ghidra `
  -postScript GhidraFullFunctionCatalog.java `
  .\analysis\randgrid-full-map\ghidra-functions-v2.jsonl

# 3. Build the authoritative entry/call/instruction evidence.
& .\.venv\Scripts\python.exe .\scripts\randgrid_full_map.py `
  --target 'X:\path\to\Randgrid.sys' `
  --ghidra-catalog .\analysis\randgrid-full-map\ghidra-functions-v2.jsonl `
  --json .\evidence\randgrid-full-map.json `
  --markdown .\evidence\randgrid-full-map.md `
  --dump-dir .\analysis\randgrid-full-map-v2

# 4. Generate the local full reconstruction and public summary/example.
& .\.venv\Scripts\python.exe .\scripts\randgrid_source_reconstruction.py `
  --evidence .\evidence\randgrid-full-map.json `
  --ghidra-catalog .\analysis\randgrid-full-map\ghidra-functions-v2.jsonl `
  --instructions .\analysis\randgrid-full-map-v2\instructions.tsv.gz `
  --gaps .\analysis\randgrid-full-map-v2\gaps.tsv.gz
```

## Explicitly unresolved

- original source-level names beyond corroborated static labels;
- source types, variables, structures, comments, and file layout;
- compiler-level control flow for flattened/MBA bodies;
- object-callback pre/post function pointers and access policy;
- IRP major-function table and IOCTL protocol;
- runtime reachability or frequency for linear decodings;
- any bypass, evasion, or operational interaction behavior.
