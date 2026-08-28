# Historical first-pass scripts

These scripts are retained to preserve the provenance of reports 05–06. They
predate the exact IAT/stub/unwind analyzer and use simpler heuristics, hard-coded
local input locations, and—in the disassembler—limited/linear entry-point views.

Do not use them as authority for claims such as “this import is called,” “this is
DriverEntry,” or “this behavior is implemented.” The authoritative Randgrid tool
is `../randgrid_deep_xrefs.py`, and the authoritative interpretation is
`../../docs/07-randgrid-deep-dive.md`.
