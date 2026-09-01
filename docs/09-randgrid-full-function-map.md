# Randgrid.sys — Authoritative Static Entry, Call-Site, and Instruction Map

**Date:** 2026-09-01

**Input SHA-256:** `4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E`

**Scope:** read-only static mapping of every executable byte, evidence-backed
entry candidate, and exact IAT call site in the on-disk driver

**Safety boundary:** no driver loading, device access, service/game interaction,
live tracing, bypass work, or evasion work

**Continues:** `07-randgrid-deep-dive.md` (IAT/unwind census) and the existing
Ghidra project under the private research workspace

---

## 1. Executive result

The previous deep dive recovered a sparse exact-call surface: 61 of 689 imports,
2,191 `.pdata` unwind ranges, and selected callback sites. It did **not** map
the instruction stream. This pass does.

On the official Steam `Randgrid.sys` (13,130,616 bytes, hash above):

| Fact | Result |
|---|---|
| Executable virtual bytes | 11,381,760 |
| Linear Capstone instructions | 3,478,904 |
| Decoded executable bytes | 10,983,063 (instruction coverage **0.9650**) |
| Skipdata remainder | 398,697 bytes, **398,697 / 398,697 classified** |
| Semantically recognized executable bytes | **1.0000** (instruction + recognized skipdata) |
| Labeled executable bytes | **1.0000** (instruction + all skipdata labels) |
| Unique static entry candidates | **8,764** |
| `.pdata` unwind ranges | 2,191 |
| Ghidra-defined functions exported | 8,105 listed / 8,178 including externals |
| IAT jump stubs | 656–657 |
| Exact IAT call sites | 550 (527 direct + 23 through stubs) |
| Entries selected as primary call owners | 543 |
| Single giant obfuscated unwind blob | RVA `0x1000–0x2BBDC9` (2,862,537 bytes) |

Ghidra auto-analysis kept about 164k instructions across 8,105 listed
functions. The linear Capstone sweep recovers **more than twenty times** that
many instructions. Entry candidates merge Ghidra entries, `.pdata` starts, IAT
jump stubs, and recovered relative-call targets that look like real prologues.
IAT call instructions stay in a separate call-site table and are not promoted
to functions.

This is a complete **static linear-instruction, entry-candidate, and exact-IAT-call map**. It is not a
complete semantic deobfuscation of the MBA/control-flow-protected bodies.

---

## 2. How the map is built

`scripts/randgrid_full_map.py` never loads the driver. It:

1. Enforces the exact file size/SHA before creating output and reuses the proven IAT/stub decoder from
   `scripts/randgrid_deep_xrefs.py`.
2. Linear-disassembles every executable section (`.text`, `INIT`, secondary
   `.text`) with Capstone, recording every decoded instruction and every
   skipdata gap.
3. Validates a required, hash-pinned Ghidra catalog including program SHA,
   image base, tool version, exact body ranges, record counts, and footer.
4. Seeds entry candidates from `.pdata`, the PE entry, previously recovered
   function labels, IAT jump stubs, prologue-like relative-call targets, and the
   Ghidra catalog. Exact `call [rip+IAT]` instructions are separate call sites.
5. Caps inferred (non-`.pdata`) bodies so MBA-region false `E8` immediates
   cannot swallow megabytes of unrelated code.
6. Assigns every exact IAT call one primary owner: the smallest exact Ghidra
   body first, otherwise the smallest containing `.pdata` range, otherwise
   unresolved.
7. Classifies each entry (IAT stub, thunk, clear MSVC wrapper, MBA block,
   epilogue fragment, giant blob, and so on) and names it from known labels or
   exact imports.

`scripts/ghidra/GhidraFullFunctionCatalog.java` exports the already-analyzed
Ghidra project as JSONL without re-analysis or bulk decompilation.

Bulk artifacts stay Git-ignored under `analysis/randgrid-full-map/`:

- `instructions.tsv.gz` — every linear instruction (`va`, size, bytes, text,
  section);
- `gaps.tsv.gz` — every skipdata byte with coarse/fine class;
- `entries.json` — the 8,764 entry candidates with sampled heads;
- `ghidra-functions-v2.jsonl` — the 8,105 listed Ghidra functions and 8,775
  exact body ranges.

Published evidence is `evidence/randgrid-full-map.json` and
`evidence/randgrid-full-map.md`.

---

## 3. Entry path, now exact

The PE entry at `0x140C61000` is a **44-byte** `INIT` unwind range whose first
instruction is:

```text
0x140C61000  jmp  0x14059A14C
```

Bytes after that jump in the same unwind range do not execute as fall-through.
The real first body is `DriverEntry_ObfuscatedBody` at `0x14059A14C`, which
opens with `pushfq` and MBA stack-junk (push-imm / `sub rsp` / `mov [rsp]` /
`pop [rsp]` canceling sequences). That body is classified `mba_obfuscated`.

The earlier Ghidra label `FUN_14015CF58` is a real MBA block at
`0x14015CF58` (about 3.4 KiB in the merged catalog, 810 decoded instructions in
the sampled body). It is **not** the PE entry. It sits inside the giant
`.pdata` blob that begins at RVA `0x1000`.

---

## 4. Callback and device labels, re-anchored

The merged map confirms the previously recovered thunks by decoding their first
instruction as an unconditional jump:

| Label | VA | First transfer | Classification |
|---|---|---|---|
| `ProcessNotifyThunk` | `0x140A294E0` | `jmp 0x140A8DB26` (`ProcessNotifyBody`) | thunk |
| `ThreadNotifyThunk` | `0x140A2AC70` | `jmp 0x140A8EDB5` (`ThreadNotifyBody`) | thunk |
| `ObRegisterCallbacks_Setup` | `0x140AB2C18` | `jmp 0x140A9256E` | thunk |
| `ObRegisterCallbacks_CallSite` | `0x140AB309D` | exact `call [rip+IAT]` | call site; Ghidra-body owner at same VA |
| `PsSetCreateProcessNotifyRoutineEx_CallSite` | `0x140AA12F2` | exact IAT call | call site; Ghidra-body owner at same VA |
| `PsSetCreateThreadNotifyRoutine_CallSite` | `0x140AA130F` | exact IAT call | call site; Ghidra-body owner at same VA |

`ProcessNotifyThunk`'s 6,021-byte unwind range still contains the previously
reported CI / pool / mutex / `ZwQuerySystemInformation` call sites. Those sites
are live via additional entries into the same unwind range, not via fall-through
from the opening jump.

`ThreadNotifyThunk` still carries the create-path set
`PsLookupThreadByThreadId`, `PsIsSystemThread`, `ObOpenObjectByPointer`,
`ZwQueryInformationThread`.

Object-callback **pre/post bodies, altitude string, and access-mask policy
remain unresolved**. The map names the registration thunk and the exact
`ObRegisterCallbacks` call; it does not recover the protected policy function.

---

## 5. Classification of the 8,764 entry candidates

| Class | Count | Meaning |
|---|---:|---|
| `unknown` | 3,960 | Mostly short Ghidra fragments inside protected code |
| `mba_obfuscated` | 1,722 | MBA junk (push/pop/xor/`sub rsp` canceling sequences) |
| `thunk` | 980 | First instruction is an unconditional jump |
| `mba_epilogue` | 876 | Typical 2-byte `pop rax; popfq` unwind fragments |
| `iat_stub` | 657 | Six-byte `jmp [rip+IAT]` linkage |
| `iat_call_wrapper` | 192 | Ghidra entry candidate whose head begins with an exact IAT call |
| `import_bearing` | 111 | Primary owner entry containing one or more exact IAT calls |
| `clear` | 73 | Ordinary-looking code with a `ret` |
| `clear_msvc` | 49 | MSVC home-space / `sub rsp` prologue |
| `clear_wrapper_to_obfuscated` | 27 | Clear prologue then `jmp` into protected code |
| `undecodable` | 111 | Capstone could not decode the sampled head |
| `padding` | 5 | Zero / `int3` / `nop` fragments |
| `obfuscated_blob` | 1 | The 2.73 MiB `.pdata` range RVA `0x1000–0x2BBDC9` |

The giant blob is one loader-consumed unwind range, not one conventional
function. Linear disassembly still lists every decodable instruction inside it
in `instructions.tsv.gz`. Ghidra split parts of it into thousands of `FUN_*`
labels; those labels are preserved as additional starts.

---

## 6. Section coverage

| Section | RVA | Virtual size | Instructions | Decoded | Gaps | Coverage |
|---|---|---:|---:|---:|---:|---:|
| `.text` (primary) | `0x1000` | 11,240,448 | 3,432,753 | 10,846,698 | 393,750 | 0.9650 |
| `INIT` | `0xC61000` | 23,552 | 8,808 | 22,747 | 805 | 0.9658 |
| `.text` (secondary) | `0xC69000` | 117,760 | 37,343 | 113,618 | 4,142 | 0.9648 |

`INIT` after the 5-byte entry jump is mostly data (API-name strings and
discardable bytes) that a linear sweep will still try to decode. Those 8,808
“instructions” are not a second DriverEntry.

The linear mnemonic histogram is dominated by `add` (838,315), then `mov`,
`push`, `pop`, `cmp`, `sub`, `xor`. High `in`/`out`/`xchg`/`sbb` counts are the
signature of **misaligned decoding inside MBA/obfuscated bytes**, not a claim
that the driver issues port I/O 40,000 times. Coverage counts those bytes as
decoded because Capstone produced an instruction at that alignment; it does not
mean the CPU would execute that decoding at runtime.

### 6.1 The former 3.5% skipdata remainder

The 398,697 bytes Capstone would not start an x64 instruction on are **not a
hole in the file**. They are 319,626 tiny runs (255,938 of them a single byte;
none longer than 16 bytes) sitting between successfully decoded instructions.

Every one of those bytes is now named. The taxonomy:

| Class | Bytes | What it is |
|---|---:|---|
| `legacy_ud` | 221,038 | Documented 64-bit `#UD`: PUSHA/POPA, AAM/AAD, DAA/DAS/AAA/AAS, PUSH/POP sreg, BOUND, INTO, CALLF/JMPF, `82` |
| `invalid_ff` | 58,091 | `FF` that is not a valid Group-5 r/m form here (56,539 are `/7`, which `#UD`s) |
| `invalid_modrm` | 31,099 | MOV-imm / LEA / POP-or-XOP / ALU group rejected at this alignment |
| `invalid_prefix` | 22,252 | LOCK/REP/segment/66/67 prefix that did not attach to a legal instruction |
| `orphan_rex` | 19,798 | `40–4F` REX prefix not consumed by the next linear instruction |
| `invalid_fe` | 17,826 | `FE` Group-4 form rejected (`/2` and above `#UD`) |
| `invalid_vex` | 17,335 | `C4`/`C5` that did not form a valid VEX instruction |
| `invalid_x87` | 9,754 | `D8–DF` x87 encodings Capstone refused here |
| `invalid_escape` | 1,502 | `0F` two-byte escape not followed by a valid secondary opcode |
| `truncated_instruction` | 2 | final-section `E2` (LOOP rel8) and `A9` (TEST EAX,imm32) missing required operands |

Largest fine names: `FF /7` (56,539), `AAD` (25,397), `MOV_imm` (15,766),
`AAM` (15,293), `FE /7` (12,246), `PUSHA` (10,571). In 32-bit mode many of
these decode as real instructions (`pusha`, `aad`, `daa`, `lcall`). In 64-bit
they are `#UD`. That is MBA/junk insertion: legacy opcodes used as non-executing
noise between real x64 instructions.

Instruction coverage stays 0.9650 because these bytes are not valid complete
64-bit instructions at the linear alignment. **Recognized coverage is 1.0000**
for this input. The classifier now has an explicit `unknown` fallback excluded
from recognized coverage; labeled coverage is reported separately, so 1.0000 is
no longer guaranteed by construction. The per-byte listing is
`analysis/randgrid-full-map-v2/gaps.tsv.gz`.

---

## 7. What is now complete vs still protected

**Complete (static):**

- identity of the analyzed file;
- every executable section’s linear instruction stream;
- every remaining skipdata byte labeled, with unknown fallback excluded from
  semantic recognized coverage;
- union map of `.pdata`, Ghidra, IAT jump stubs, and recovered prologue targets
  (8,764 entry candidates);
- 550 exact IAT call sites separated from entries and assigned to 543 primary
  owners without double counting;
- exact PE-entry transfer `0x140C61000 → 0x14059A14C`;
- named IAT stubs and exact IAT call sites;
- confirmation of process/thread notify thunks and the object-callback
  registration call;
- classification of obfuscation shape (MBA + clear wrappers + one giant unwind
  blob).

**Not complete (and not guessed):**

- MBA simplification to compiler-level control flow for every protected body;
- object-callback pre/post function pointers, altitude, and access-mask policy;
- IRP major-function table and IOCTL protocol;
- which `MmCopyMemory` site walks which buffer at runtime;
- callers of imports that still have only a linkage stub;
- runtime frequency of any mapped instruction.

Answering those requires either a dedicated MBA/CFG simplifier on the already
dumped instruction stream or carefully isolated dynamic work. Neither was done
for this report.

---

## 8. Reproduction

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r .\requirements.txt

# Required: export the Ghidra catalog first from the existing analyzed project.
analyzeHeadless <projectDir> RandgridProject -process Randgrid.sys `
  -noanalysis -readOnly `
  -scriptPath .\scripts\ghidra `
  -postScript GhidraFullFunctionCatalog.java `
  .\analysis\randgrid-full-map\ghidra-functions-v2.jsonl

# Instruction/entry/call map (requires the exact matching driver and catalog).
& .\.venv\Scripts\python.exe .\scripts\randgrid_full_map.py `
  --target 'X:\path\to\Randgrid.sys' `
  --ghidra-catalog .\analysis\randgrid-full-map\ghidra-functions-v2.jsonl `
  --json .\evidence\randgrid-full-map.json `
  --markdown .\evidence\randgrid-full-map.md `
  --dump-dir .\analysis\randgrid-full-map-v2

& .\.venv\Scripts\python.exe .\scripts\randgrid_source_reconstruction.py `
  --evidence .\evidence\randgrid-full-map.json `
  --ghidra-catalog .\analysis\randgrid-full-map\ghidra-functions-v2.jsonl `
  --instructions .\analysis\randgrid-full-map-v2\instructions.tsv.gz `
  --gaps .\analysis\randgrid-full-map-v2\gaps.tsv.gz

& .\.venv\Scripts\python.exe -m unittest discover -s .\tests -p 'test_*.py' -v
```

The generated JSON contains the enforced input hash and compact sampled heads;
it does not contain the complete binary. Raw binaries, Ghidra databases and
catalogs, and the full instruction/source-like listings are not published under
this repository's MIT license.
