# Evidence artifacts

`randgrid-full-map.json` and its Markdown rendering are deterministic outputs of
`scripts/randgrid_full_map.py` for the same driver. They catalog every recovered
function start (`.pdata`, Ghidra, IAT stubs/calls, prologue-like call targets)
and the linear executable-byte coverage, including a named taxonomy of every
Capstone skipdata byte (classified coverage 1.0). They do not embed instruction
bytes for every mapped body; the full instruction listing is the Git-ignored
`analysis/randgrid-full-map/instructions.tsv.gz` and the per-byte skipdata
listing is `analysis/randgrid-full-map/gaps.tsv.gz`.

`randgrid-deep-xrefs.json` and its Markdown rendering are deterministic outputs
of `scripts/randgrid_deep_xrefs.py` for the driver identified by SHA-256
`4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E`.

They contain no embedded driver image and no decompiled function bodies. The JSON
preserves import names, selected static instruction bytes/addresses, runtime-
function ranges, focused call classifications, located public strings, and the
input identity needed for independent comparison.

Call classifications:

- `direct_calls`: exact `call [rip+IAT]` instructions;
- `iat_jumps`: local `jmp [rip+IAT]` linkage stubs, not use evidence alone;
- `stub_calls`: exact relative calls whose target is one of those linkage stubs;
- `linear_rip_references`: a conservative section-wide corroboration pass.

The tests assert the published evidence contract and fail if the central counts
or input identity drift unexpectedly.

`randgrid-runtime-passive-summary.json` is a privacy-reduced aggregate from a
bounded non-elevated observation of the same driver hash while the Steam service
and game were active. It contains no process command lines, launch tokens, kernel
object pointers, raw handle rows, or ETL. It proves live driver/device identity
and the measured cross-channel retry pattern. Its handle-policy result is the
historical non-elevated boundary and is superseded by the elevated artifact for
current runtime conclusions.

`randgrid-runtime-elevated-summary.json` is the privacy-reduced result of the
three-stream elevated pass: Kernel Audit API Calls, an independent
SystemTraceProvider `OB_HANDLE` trace, and 100 ms system handle-table snapshots.
It publishes no transient PID, handle, kernel pointer, command line, or raw ETL.
The aggregate records 2,208 exact same-caller/thread/time object correlations,
41 persistent target handles with a 41/41 independent rundown overlap, and the
strict capture-specific limit: none of that trace's microsecond-lived returned
handles survived to a periodic granted-mask snapshot.

`live-capture.json` is a privacy-reduced schema-v2 aggregate from the original
non-admin PR capture and a subsequent same-host non-admin/UAC verification. It
contains no host/user name, PID, raw handle, kernel pointer, command line, launch
token, local path, memory address, or process bytes. It records the later
handle-specific comparison—requested `0x410`, stored `0x1000` in both privilege
contexts—along with corrected device, pipe, module-error, region-metadata,
token-elevation, process-protection, and parent-topology claim boundaries. Raw
research captures stay under Git-ignored `local-analysis/` and are not public
evidence.
