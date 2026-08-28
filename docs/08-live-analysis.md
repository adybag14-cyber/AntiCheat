# RICOCHET Live Verification — Driver, Device, Broker, and Game Access

**Original capture:** 2026-08-28T21:55:50.434944Z

**Independent verification:** 2026-08-28 UTC, non-admin and UAC-elevated

**Target:** running Call of Duty HQ Steam process and the active Steam Randgrid
service

**Published evidence:**
[`evidence/live-capture.json`](../evidence/live-capture.json), privacy-reduced
schema v2

**Evidence boundary:** the public artifact contains no host/user identity, PID,
raw handle, kernel pointer, command line, launch token, local path, memory
address, or process bytes

---

## 1. Corrected result

The live work confirms the service, namespace, pipe, process-access, and process
topology surfaces. It also corrects several claims made by the first version of
this report.

| Finding | Result |
|---|---|
| Registered Randgrid services | Three observed |
| Active variant | `atvi-randgrid_sr` (Steam), running/manual |
| DOS-device link | `Randgrid -> \Device\Randgrid` |
| Device open | Denied with error 5, non-admin and administrator |
| Device-denial mechanism | Unresolved; not attributable to `ObRegisterCallbacks` from this result |
| Broker pipe | Read-only open and non-consuming peek succeeded in both contexts |
| Game access request | `0x410` (`QUERY_INFORMATION | VM_READ`) |
| Stored granted access | `0x1000` (`QUERY_LIMITED_INFORMATION`) in both contexts |
| Game token elevation | False |
| Game process protection | `PROTECTION_LEVEL_NONE` |
| Module snapshot | Failed with `Access denied`; no valid module count |
| Region metadata | Enumerable: 14,632 non-admin / 14,644 administrator |
| Game crash-handler topology | One crash handler observed as a direct child |

The principal new result is a handle-specific requested-versus-granted
comparison:

```text
requested: 0x00000410
           PROCESS_QUERY_INFORMATION | PROCESS_VM_READ

granted:   0x00001000
           PROCESS_QUERY_LIMITED_INFORMATION
```

Elevation did not restore the removed rights. Access reduction is therefore
directly observed; it is not inferred from a zero module or region count.
Attribution to a particular callback remains a separate causality claim and
requires callback/event correlation.

---

## 2. Evidence sources

The report combines two bounded sources.

### 2.1 Original PR capture

The original non-admin run recorded:

- three service registrations and the running Steam service;
- device-open denial;
- broker-pipe open and peek;
- one game-process handle open;
- one crash-handler parent relationship.

Its device open failed, it found no candidate writable regions, and tier 3 was
not selected. Therefore the recorded artifact shows zero IOCTL calls reached,
zero process-memory writes reached, and zero injection operations executed.

The raw artifact is no longer published because it included host/user identity,
transient identifiers, command lines, a launch token, local paths, handles, and
addresses. Only the privacy-reduced aggregate remains in `evidence/`.

### 2.2 Independent verification

The same read-only verifier was run once normally and once through UAC. It:

- queried WMI service and parent topology;
- used `QueryDosDeviceW`;
- attempted metadata-only and read-only device opens, then closed immediately;
- opened the broker pipe for read only and called `PeekNamedPipe` without
  consuming bytes;
- requested `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` for the game;
- located the verifier's exact returned handle in
  `SystemExtendedHandleInformation` and recorded its stored access mask;
- queried the image name, token elevation, and public process-protection level;
- attempted a correctly defined Unicode module snapshot;
- enumerated only region metadata with `VirtualQueryEx`;
- performed no process-memory read/write or active driver operation.

No verifier process remained afterward. The original game and driver remained
running.

---

## 3. Service and process topology

Three Randgrid services were observed:

| Service | Store | State | Start mode |
|---|---|---|---|
| `atvi-randgrid` | Battle.net | Stopped | Manual |
| `atvi-randgrid_msstore` | Microsoft Store | Stopped | Manual |
| `atvi-randgrid_sr` | Steam | Running | Manual |

This proves the registered per-store variants and the active Steam selection at
the observation time. A single state snapshot does not by itself prove which
specific user-mode component loaded the driver.

One `codCrashHandler.exe` process had the game as its direct parent. That proves
the parent relationship; it does not by itself prove the handler's complete
runtime attachment semantics.

The public artifact omits all PIDs and command lines.

---

## 4. Device namespace and access

`QueryDosDeviceW("Randgrid")` returned:

```text
\Device\Randgrid
```

Both privilege contexts produced the same open result:

| Context | Metadata-only open | Read-only open |
|---|---|---|
| Non-admin | Error 5, Access denied | Error 5, Access denied |
| Administrator | Error 5, Access denied | Error 5, Access denied |

The namespace publication and denial are observed. Their exact cause is not.

Microsoft documents `ObRegisterCallbacks` for process, thread, and desktop
handle operations, not device-object opens:

- [`ObRegisterCallbacks`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [`OB_OPERATION_REGISTRATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_operation_registration)

Possible device-specific mechanisms include the device DACL, the driver's
create/open dispatch path, or another authorization layer. The former statement
that this device denial proves an object callback fired was incorrect.

No IOCTL was sent during independent verification.

---

## 5. Broker pipe

The broker pipe `COD.Broker.v1` was:

- present;
- openable for read only in both contexts;
- peekable in both contexts;
- empty at the sampled moments;
- closed without consuming or writing data.

This confirms reachability, not protocol semantics or authorization for any
broker operation. The protocol remains undecoded.

---

## 6. Process access reduction

The verifier requested:

```text
PROCESS_QUERY_INFORMATION | PROCESS_VM_READ = 0x410
```

It then located that exact owner/handle entry in the system handle table while
the handle remained open. The stored mask was:

```text
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
```

The comparison reproduced under UAC elevation. The game token itself reported
not elevated, and the public process-protection query reported
`PROTECTION_LEVEL_NONE`.

Therefore:

- the game is not merely inaccessible because it is elevated;
- the game is not PPL;
- the requested process rights are reduced before being stored in the returned
  handle;
- administrator status alone does not bypass the reduction.

The running Randgrid driver and statically proved object-callback registration
make Randgrid policy a strong candidate explanation. The direct evidence in
this capture proves the mask transformation, while exact callback attribution
remains an inference unless joined to callback/ETW execution evidence.

---

## 7. Module and region results

### 7.1 Module snapshot

The first version of this report called `module_count: 0` an empty module list.
That was incorrect.

The original `MODULEENTRY32W` definition omitted `modBaseSize` and `hModule` and
used narrow arrays with Unicode APIs. A correctly defined structure produced:

```text
CreateToolhelp32Snapshot: failed
Win32 error: 5 (Access is denied.)
```

Microsoft's documented structure includes the missing fields and `WCHAR`
arrays:

- [`MODULEENTRY32W`](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32w)

An API failure is not a successfully enumerated empty list. The valid published
module count is therefore `null`, with error 5 preserved.

### 7.2 Region metadata

`VirtualQueryEx` region metadata was enumerable:

| Context | Regions observed |
|---|---:|
| Non-admin | 14,632 |
| Administrator | 14,644 |

No process bytes were read and no region addresses are published. The counts are
a live sample and can vary as allocations change.

The earlier statements that the region list was empty or that the complete
address-space map was opaque are disproved.

---

## 8. Research tiers retained in the source

`scripts/live_capture.py` retains the blue-team research tiers from the original
PR:

- tier 1 includes an undocumented IOCTL sweep if a device open succeeds;
- tier 2 includes process-memory read/write trap experiments;
- tier 3 includes remote allocation and `CreateRemoteThread` injection research.

These paths are not represented as read-only or generally safe. They require
separate authorization and an appropriate disposable research session. Their
presence in the source is not evidence that they executed in the published
capture.

For the original recorded run:

```text
device open succeeded:       false
IOCTL calls reached:         0
candidate write regions:     0
process-memory writes reached: 0
injection selected/executed: false
```

Raw runs now default to Git-ignored `local-analysis/live-capture.json` so active
research output cannot silently overwrite the public privacy-reduced artifact.

---

## 9. Published evidence contract

The schema-v2 public JSON may contain:

- stable component names;
- service state and store mapping;
- privilege context;
- access masks and error codes;
- aggregate counts;
- zero-valued safety counters;
- explicit claim boundaries.

It must not contain:

- host or user identity;
- PIDs, raw handles, or kernel pointers;
- command lines or launch tokens;
- local installation, temporary, or crash paths;
- memory addresses or process bytes.

Generated text is UTF-8 with LF newlines, and manifest hashes are calculated
from the Git-normalized bytes used by fresh clones and Linux CI.

---

## 10. Reproduction boundary

The raw research tool remains Windows-only and uses `ctypes`. Its default output
is local and ignored:

```powershell
python .\scripts\live_capture.py `
  --game-pid <PID> `
  --max-tier 0 `
  --out .\local-analysis\live-capture.json
```

Higher numeric tiers add active research operations. Review the source and use
them only in an explicitly authorized research environment. Do not publish the
raw output; derive a privacy-reduced aggregate instead.

The public evidence in this repository is a bounded observation, not a replay
recipe for the broker protocol, driver IOCTL surface, memory mutation, or
injection path.

---

## 11. Final claim boundary

```text
Three registered store services:             confirmed
Steam service running at capture:            confirmed
Randgrid DOS-device link published:          confirmed
Device open denied in both contexts:         confirmed
Device denial caused by Ob callbacks:        unresolved / not established
Broker pipe read-open + non-consuming peek:  confirmed
Requested 0x410 -> stored 0x1000:             confirmed
Game elevated:                               false
Game PPL:                                    false
Module snapshot:                             denied, not an empty list
Region metadata enumerable:                  confirmed
Crash-handler direct parent relationship:   confirmed
Tier-2/tier-3 code present:                   yes, research-only
Tier-2/tier-3 executed in public capture:     no
```

This is the authoritative factual boundary for the live-capture contribution.
