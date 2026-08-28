# Evidence artifacts

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
and the measured cross-channel retry pattern; it explicitly leaves handle-access
stripping unresolved.
