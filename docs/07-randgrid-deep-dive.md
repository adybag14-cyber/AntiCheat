# Randgrid.sys — Active Call Surface, Callbacks, and Protection Deep Dive

**Date:** 2026-08-28

**Input SHA-256:** `4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E`

**Scope:** read-only static analysis of the on-disk driver

**Safety boundary:** no driver loading, device access, service/game interaction, live tracing, bypass work, or evasion work

---

## 1. Executive result

The earlier import-only report overstated some capabilities and missed several
real ones. This pass separates four different things that must not be conflated:

1. an import-table slot,
2. a local IAT jump stub,
3. an exact call to the IAT or its stub, and
4. recovered higher-level behavior and data flow.

The corrected high-confidence picture is:

- Randgrid imports 689 functions, but only 61 imported functions have an exact
  decoded static call through either supported call form.
- It registers one process-create callback and one thread-create callback at
  identified thunk addresses.
- It registers one object-manager callback configuration, but the protected
  pre/post callback addresses and their access-mask policy remain unresolved.
- It creates a device and symbolic link and contains matching Randgrid device
  names, although the protected flow prevents a direct string-to-call xref.
- It directly calls process/thread inspection APIs, virtual-memory queries,
  file-object Code Integrity validation, and two process-termination sites.
- It implements a complete BCrypt hashing/signature-verification surface with
  ECDSA-P256, ECC public-key blob, and SHA-256 identifiers.
- `MmCopyMemory` has 18 exact call sites. The physical-memory, IO-space,
  firmware-variable, and `MmGetSystemRoutineAddress` imports have linkage stubs
  but no recovered callers in either exact call form.
- The binary does **not** import the `RtlImage*` or `CiCheckSignatureMandatory`
  APIs claimed by the earlier report.

This report supersedes the Randgrid conclusions in documents 05 and 06 wherever
they conflict.

---

## 2. Evidence hierarchy and validation

The primary machine-generated artifact is `analysis/randgrid-deep-xrefs.json`.
It combines:

- PE import slots from `pefile`;
- exact x86-64 `call [rip+IAT]` decoding at each byte-pattern candidate;
- exact relative calls to local `jmp [rip+IAT]` stubs;
- a conservative section-wide Capstone RIP-reference sweep;
- PE x64 exception-directory (`.pdata`) runtime-function ranges;
- SHA-256 identity for the analyzed input.

Ghidra 12.1.3 provides decompilation, symbol xrefs, and call-graph corroboration.
LLVM `objdump` independently confirms selected raw instruction sequences. The
script has unit coverage for half-open runtime ranges, percentile calculation,
and—most importantly—the distinction between a linkage stub and a call to that
stub.

An exact static call proves that a code path contains the call site. It does not
prove runtime frequency, success, target identity, or policy. A linkage stub by
itself proves none of those things.

---

## 3. Protection and function-boundary shape

### 3.1 PE layout

Randgrid contains three executable regions:

- primary `.text`: RVA `0x1000`, virtual size `0xAB8400`;
- `INIT`: RVA `0xC61000`, virtual size `0x5C00`;
- secondary `.text`: RVA `0xC69000`, virtual size `0x1CC00`.

The entry RVA is `0xC61000`. Its small entry function immediately transfers into
the protected dispatcher rooted at Ghidra label `FUN_14015CF58`.

### 3.2 Loader-consumed runtime functions

The exception directory supplies 2,191 runtime-function ranges:

| Statistic | Value |
|---|---:|
| Median span | 33 bytes |
| 95th percentile | 7,903 bytes |
| Maximum span | 2,862,537 bytes (`0x2BADC9`) |
| Spans over 4 KiB | 148 |
| Spans over 64 KiB | 2 |
| Spans over 1 MiB | 1 |

The largest range is RVA `0x1000–0x2BBDC9`, approximately 2.73 MiB. The object-
callback setup and call occupy one real unwind range, RVA `0xAB2C18–0xAB326F`,
even though Ghidra split the path into multiple artificial labels such as
`FUN_140AB2DF3`, `FUN_140AB309D`, and `FUN_140A931A6`.

The dispatcher initializes/relocates a 0x292-entry function table and transfers
through computed targets. Raw `objdump` loses instruction alignment in several
of these regions; decoding each call candidate at its exact address is therefore
more reliable than one linear disassembly alone.

---

## 4. Imported surface versus reached call surface

The 689 imports break down as follows:

| DLL | Imported names | Exact call sites | Distinct names reached |
|---|---:|---:|---:|
| `ntoskrnl.exe` | 673 | 462 | 48 |
| `HAL.dll` | 4 | 62 | 1 |
| `ci.dll` | 2 | 12 | 2 |
| `cng.sys` | 10 | 14 | 10 |
| **Total** | **689** | **550** | **61** |

There are 527 exact direct-IAT calls and 23 exact calls through local IAT jump
stubs. A further 656 jump stubs exist, but they are linkage machinery and are not
counted as API use without a caller.

The largest exact static call-site counts are:

| Import | Call sites |
|---|---:|
| `ExFreePoolWithTag` | 151 |
| `KeStallExecutionProcessor` | 62 |
| `KeGetCurrentIrql` | 58 |
| `ExAllocatePoolWithTag` | 27 |
| `KeAcquireSpinLockRaiseToDpc` | 24 |
| `KeReleaseSpinLock` | 23 |
| `MmCopyMemory` | 18 |
| `KeReleaseGuardedMutex` | 17 |
| `ZwClose` | 16 |
| `ZwQuerySystemInformation` | 15 |

This sparse reached set is consistent with a deliberately broad or padded import
surface, but static evidence cannot distinguish deliberate decoys from code paths
reached through additional unresolved indirection. The safe conclusion is that
628 imported names currently lack either exact supported call form.

---

## 5. Callback architecture

### 5.1 Object-manager callback

`ObRegisterCallbacks` is called at VA `0x140AB309D`, inside runtime range RVA
`0xAB2C18–0xAB326F`. The setup immediately before the call reconstructs the
header of an `OB_CALLBACK_REGISTRATION`:

- packed dword `0x00010100` corresponds to Version `0x0100` and operation count
  `1`;
- the altitude `UNICODE_STRING` length and maximum length are both `0x14` bytes;
- a stack buffer is assigned as the altitude buffer;
- a stack object is assigned as the single `OB_OPERATION_REGISTRATION` array.

Two exact `ObUnRegisterCallbacks` call sites are present for teardown.

The altitude text, object type, operation mask, pre-operation callback, and post-
operation callback are not defensibly recovered. Therefore:

- callback registration is proved;
- one operation-registration record is proved;
- “handle hiding,” a particular target process, create-versus-duplicate policy,
  and access-mask stripping remain unresolved.

### 5.2 Process callback

Raw instructions at VA `0x140AA11D6` are unambiguous:

```text
xor  edx, edx                         ; Remove = FALSE
lea  rcx, [0x140A294E0]              ; callback thunk
jmp  0x140AA12F2
0x140AA12F2: call [PsSetCreateProcessNotifyRoutineEx]
```

Thus the driver registers process callback thunk `0x140A294E0`, which jumps to
protected body `0x140A8DB26`. There are three exact calls to
`PsSetCreateProcessNotifyRoutineEx`; only this registration site's two arguments
are recovered. The other two sites are not automatically labelled as removal
calls.

The process callback body immediately enters the flattened dispatcher. Its exact
event handling and enforcement decisions remain unresolved.

### 5.3 Thread callback

The thread registration path loads callback thunk `0x140A2AC70` and calls
`PsSetCreateThreadNotifyRoutine` at VA `0x140AA130F`.

The thunk jumps to body `0x140A8EDB5`, whose first branch tests the callback's
`Create` boolean. Only the create path continues. That path:

1. passes the callback's thread ID to `PsLookupThreadByThreadId`;
2. checks the resulting thread object using `PsIsSystemThread`;
3. on the system-thread branch, calls `ObOpenObjectByPointer` with handle
   attributes `0x200` (`OBJ_KERNEL_HANDLE`) and desired access `0x800`;
4. queries thread information class `9` through `ZwQueryInformationThread`, the
   class conventionally named `ThreadQuerySetWin32StartAddress`;
5. continues through protected success/cleanup logic whose final classification
   or enforcement action is not recovered.

The non-system-thread branch enters a different protected path. This establishes
special handling for newly created system threads and inspection of their start
address without claiming what verdict is ultimately produced.

Two exact `PsRemoveCreateThreadNotifyRoutine` call sites exist for teardown.

No reached call was found for the imported legacy
`PsSetCreateProcessNotifyRoutine` or `PsSetLoadImageNotifyRoutine`; each currently
has only its IAT jump stub.

---

## 6. Device lifecycle

Exact calls exist for:

| API | Calls |
|---|---:|
| `IoCreateDevice` | 1 |
| `IoCreateSymbolicLink` | 1 |
| `IoDeleteDevice` | 2 |
| `IoDeleteSymbolicLink` | 2 |
| `IofCompleteRequest` | 1 |

The driver contains UTF-16 strings `\Device\Randgrid` at RVA `0xAB9340` and
`\DosDevices\Randgrid` at RVA `0xAB9310`. The section-wide linear pass did not
recover a direct RIP-relative xref from these exact string starts to the create
calls; the protected dispatcher may construct or reference their descriptors
indirectly. The presence of both lifecycle calls and matching names is strong
component-level evidence, but the exact argument data flow is not claimed.

---

## 7. Code Integrity and cryptographic verification

### 7.1 Correct `ci.dll` imports

The actual imports are:

- `CiValidateFileObject` — 4 exact call sites;
- `CiFreePolicyInfo` — 8 exact call sites.

The previously reported `CiCheckSignatureMandatory` and
`CiGetCertificateStoreOptions` are not imported by this binary. The direct calls
do prove that Randgrid submits file objects to Windows Code Integrity and frees
the resulting policy structures. They do not identify every file being checked
or the policy consequence of a particular result.

### 7.2 CNG pipeline

All ten CNG imports have exact callers through local IAT stubs:

- provider lifecycle: `BCryptOpenAlgorithmProvider`,
  `BCryptCloseAlgorithmProvider`;
- property access: `BCryptGetProperty`;
- public-key lifecycle: `BCryptImportKeyPair`, `BCryptDestroyKey`;
- signature check: `BCryptVerifySignature`;
- hash lifecycle: `BCryptCreateHash`, `BCryptHashData`, `BCryptFinishHash`,
  `BCryptDestroyHash`.

The binary also contains the adjacent UTF-16 identifiers:

- `ECDSA_P256` at RVA `0xAB9270`;
- `ECCPUBLICBLOB` at RVA `0xAB9290`;
- `SHA256` at RVA `0xAB92B0`;
- `HashDigestLength` at RVA `0xAB92E0`.

Taken together, the API set and identifiers support a high-confidence inference
of SHA-256 hashing followed by ECDSA-P256 verification using an imported ECC
public-key blob. Because protection prevents direct xrefs from those exact string
starts, the algorithm-to-call association is an inference from the complete,
coherent API/string set rather than a single recovered high-level function.

---

## 8. Process and thread inspection/enforcement surface

Exact reached calls include:

| API | Calls |
|---|---:|
| `ZwQuerySystemInformation` | 15 |
| `IoGetCurrentProcess` | 14 |
| `ObfDereferenceObject` | 9 |
| `ZwAlertThread` | 6 |
| `ZwQueryVirtualMemory` | 4 |
| `PsGetProcessPeb` | 4 |
| `ObOpenObjectByPointer` | 3 |
| `ObReferenceObjectByHandle` | 3 |
| `ZwTerminateProcess` | 2 |
| `PsGetCurrentProcessId` | 2 |
| `ZwOpenProcess` | 1 |
| `ZwQueryInformationThread` | 1 |
| `SeLocateProcessImageName` | 1 via import stub |
| `ObReferenceObjectByName` | 1 |

This proves process/thread discovery, object-to-handle conversion, PEB access,
virtual-memory querying, and the existence of termination/alert call sites. It
does **not** prove which process is terminated, the termination status, the
triggering condition, or whether either site is reached during normal gameplay.

The recovered system-thread flow uses `ObOpenObjectByPointer` handle attributes
`0x200` and desired access `0x800`, then queries thread information class `9` as
described in §5.3. The exact semantic purpose of the surrounding protected state
machine remains unresolved.

---

## 9. Memory, firmware, image parsing, debugger, and HAL corrections

### 9.1 Memory

- `MmCopyMemory`: 18 exact call sites.
- `MmGetPhysicalAddress`: no exact direct or stub call; linkage stub only.
- `MmMapIoSpace`: no exact direct or stub call; linkage stub only.
- `MmProbeAndLockPages`: no exact direct or stub call; linkage stub only.
- `MmProbeAndLockSelectedPages`: no exact direct or stub call; linkage stub only.
- `MmGetSystemRoutineAddress`: no exact direct or stub call; linkage stub only;
  zero non-import plaintext kernel-routine target candidates.

A physical-memory walker or dynamically resolved routine list is therefore not
supported by the recovered call surface.

### 9.2 Firmware and image helpers

- `ExGetFirmwareEnvironmentVariable` is imported but has only its linkage stub.
- `RtlImageNtHeader`, `RtlImageDirectoryEntryToData`, and `RtlImageFileHeader`
  are not imported.

Concrete TPM/Secure Boot/UEFI readiness behavior remains proved in the separate
user-mode `SecureAttestation.dll`, not in a recovered Randgrid call path.

### 9.3 Debugger and HAL

- `KdDisableDebugger` and `KdEnableDebugger` have linkage stubs but no recovered
  caller in the supported call forms.
- `KdDebuggerNotPresent` has a data reference, not a call.
- Of four HAL imports, only `KeStallExecutionProcessor` has exact callers: 62
  static call sites.
- No exact call was recovered for `HalAllocateHardwareCounters`,
  `HalFreeHardwareCounters`, or `KeQueryPerformanceCounter`.

The earlier DMA/hardware-attestation inference from HAL imports was unsupported.

---

## 10. Remaining static limits

The following are deliberately left unresolved rather than guessed:

- object callback altitude string and pre/post callback bodies;
- object type and create/duplicate operation mask;
- process callback's protected classification/enforcement data flow;
- thread callback's final action after `PsIsSystemThread`;
- IRP major-function table and IOCTL protocol;
- callers and semantics of each `MmCopyMemory` wrapper;
- targets of any encoded or dispatcher-mediated imports not captured by the two
  exact call forms;
- runtime frequency and success of every call site.

Answering those questions would require substantially more control-flow recovery
or carefully isolated dynamic work. No live anti-cheat interaction was performed
for this report.

---

## 11. Reproduction and artifacts

Published artifacts:

- `scripts/randgrid_deep_xrefs.py` — deterministic PE/IAT/stub/unwind analyzer;
- `tests/test_randgrid_deep_xrefs.py` — helper and evidence-contract tests;
- `evidence/randgrid-deep-xrefs.json` — complete structured result;
- `evidence/randgrid-deep-xrefs.md` — generated human-readable call census.

The following corroborating artifacts are retained in the private local research
workspace and deliberately excluded from Git because they contain bulk Ghidra
decompilation output:

- `analysis/randgrid-callback-device-evidence.md` — Ghidra callback/device pass;
- `analysis/randgrid-notify-callback-evidence.md` — callback registration and
  first-level callback bodies;
- `analysis/randgrid-notify-callback-deep-evidence.md` — thread callback follow-up;
- `analysis/randgrid-thread-callback-flow.md` — system-thread handle and start-address path;
- `analysis/randgrid-cng-evidence.md` — CNG import callers;
- `analysis/randgrid-process-ci-evidence.md` — process and CI callers.

```powershell
# From the research repository; the proprietary driver remains outside Git.
python -m pip install -r requirements.txt
python .\scripts\randgrid_deep_xrefs.py --target 'X:\path\to\Randgrid.sys'
python -m unittest discover -s .\tests -p 'test_*.py' -v
```

The generated JSON contains the input hash and no embedded driver bytes. Raw
proprietary binaries, extracted application bundles, Ghidra databases, and bulk
decompiler output are not suitable for publication under this repository's MIT
license.
