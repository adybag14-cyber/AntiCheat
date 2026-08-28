# Randgrid.sys — Runtime Handle Behavior

**Date:** 2026-08-28

**Static/runtime SHA-256:**
`4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E`

**Scope:** bounded, elevated, read-only observation of the running Steam driver
and `cod.exe`

**Safety boundary:** no driver/service/device mutation, no IOCTL, no debugger,
no injection, no process-memory operation, no process termination, and no
handle opened to `cod.exe`

---

## 1. Corrected result

The runtime work now separates three claims that earlier drafts blurred:

| Claim | Result | Evidence |
|---|---|---|
| Randgrid registers an object callback | Proved statically | Exact `ObRegisterCallbacks` call at VA `0x140AB309D` |
| All handles to the game are hidden | Contradicted at runtime | The exact game process object had 41 visible persistent handles across 17 owners |
| Randgrid selectively rewrites requested access | Strongly suggested, not causally proved | Request and persistent-mask patterns differ, but no transient returned handle survived long enough for a handle-specific granted-mask snapshot |
| Randgrid outright denies process opens | Not observed in this window | All 2,218 game-target process-open events returned success |

The precise conclusion is:

> Randgrid does not universally hide the game's process object or all handles to
> it. The observed owner/mask distribution is consistent with selective
> allowlisting or access reduction, but this capture does not prove a particular
> callback rewrite for a particular returned handle.

This corrects the earlier provisional Task Manager-only temporal inference. The
final object identity comes from same-caller, same-thread, near-simultaneous
correlation between audit event 5 and kernel `HandleCreate`, then an independent
join to the system handle table and kernel handle rundown.

---

## 2. Evidence authority and privacy boundary

The published aggregate is
[`evidence/randgrid-runtime-elevated-summary.json`](../evidence/randgrid-runtime-elevated-summary.json).
It contains counts, process names, access masks, timing statistics, and explicit
limitations. It contains no:

- raw ETL or decoded CSV/dump;
- kernel object address or raw handle value;
- transient PID;
- command line, launch token, or user path;
- proprietary game or driver bytes.

The raw local corpus remains under Git-ignored `local-analysis/`. Its final
three-stream pass contained:

| Stream | Total events | Lost events |
|---|---:|---:|
| Kernel Audit API Calls | 172,143 | 0 |
| Independent SystemTraceProvider / OB handle | 2,487,109 | 0 |
| Process-handle snapshots | 43 snapshots at 100 ms requested interval | n/a |

The requested active window was 10 seconds. Session startup, shutdown, and
kernel rundown made each ETL span 16 seconds. The short active window was
deliberate: OB tracing emitted about 2.49 million events and already provided
complete target correlation without a wasteful longer duplicate.

All six local decoders—Xperf and Tracerpt for audit, process, and OB streams—
returned exit code `0`.

---

## 3. Live driver and device identity

At capture time, the running service was:

| Property | Value |
|---|---|
| Service | `atvi-randgrid_sr` |
| State | Running |
| Start mode | Manual |
| File size | 13,130,616 bytes |
| SHA-256 | `4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E` |
| Authenticode | Valid |
| Signer | Activision Publishing Inc |

The hash is identical to the input used for documents 06 and 07. This closes the
source-versus-runtime identity boundary: the running driver is the image whose
imports and callback-registration call sites were analyzed.

The earlier passive pass also established:

```text
QueryDosDeviceW("Randgrid") -> \Device\Randgrid
```

That query did not open the device or send an IOCTL.

---

## 4. Exact target-object correlation

The final pass recorded three independent sources:

1. `Microsoft-Windows-Kernel-Audit-API-Calls` event 5, exposing caller PID,
   caller thread, target PID, `DesiredAccess`, and `ReturnCode`;
2. kernel `HandleCreate`/`HandleClose`, exposing caller PID/thread, returned
   handle, object, and object type;
3. elevated `SystemExtendedHandleInformation`, exposing owner, handle, object,
   and stored granted-access mask.

Microsoft documents the object-event fields in
[`ObHandleEvent`](https://learn.microsoft.com/en-us/windows/win32/etw/obhandleevent),
the `PERF_OB_HANDLE` enable path in
[`ObTrace`](https://learn.microsoft.com/en-us/windows/win32/etw/obtrace), and
the custom-name, non-`NT Kernel Logger` design in
[`Configuring and Starting a SystemTraceProvider Session`](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session).

The audit and OB sessions started 94,850 microseconds apart. After shifting OB
timestamps onto the audit timeline, the analyzer matched on:

- caller process;
- caller thread;
- process-object type;
- timestamp within 25 microseconds.

Results:

| Metric | Value |
|---|---:|
| Game-target process-open audit events | 2,218 |
| Matched to `HandleCreate` | 2,208 |
| Unmatched | 10 |
| Matches converging on one object | 2,208 / 2,208 |
| Dominant-object ratio | 1.0000 |
| Median timestamp delta | 0 μs |
| 95th-percentile absolute delta | 1 μs |
| Observed delta range | -3 to 0 μs |

This is no longer the weak statement “a Task Manager handle appeared in the
same 500 ms interval.” The same object is recovered independently from 2,208
same-thread event pairs and is then used as the exact key for handle-table and
rundown joins. The pointer itself is intentionally not published.

---

## 5. What actually opened the game

All 2,218 process-open audit events targeting the game returned `0`. All were
external in this window. The most active callers were:

| Caller | Events | Principal requested masks |
|---|---:|---|
| `Taskmgr.exe` | 1,072 | `0x400` x1,024; `0x1200` x32; `0x1400` x16 |
| `System` | 1,026 | `MAXIMUM_ALLOWED` x1,026 |
| `steam.exe` | 63 | `SYNCHRONIZE` x63 |
| `NahimicSvc32.exe` | 16 | `VM_READ \| QUERY_INFORMATION` x16 |
| `NahimicSvc64.exe` | 16 | `VM_READ \| QUERY_INFORMATION` x16 |
| `WmiPrvSE.exe` | 11 | `VM_READ \| QUERY_INFORMATION` x11 |
| `Discord.exe` | 10 | `QUERY_LIMITED_INFORMATION` x10 |
| `explorer.exe` | 2 | `QUERY_LIMITED_INFORMATION` x2 |
| `MacriumService.exe` | 2 | `QUERY_LIMITED_INFORMATION` x2 |

The trace also contained 133 thread-open events targeting the game. Every one
came from `cod.exe` itself; no external thread-open caller appeared in the
bounded window. Those 133 calls also returned success.

`ReturnCode == 0` proves that the open operation completed successfully. It does
not prove that the returned handle retained every requested bit: an object
pre-operation callback can reduce desired access and still allow handle
creation.

---

## 6. Handle lifetimes explain the earlier sampling failure

For the exactly identified game object, the OB stream recorded:

| Metric | Value |
|---|---:|
| `HandleCreate` | 2,250 |
| `HandleClose` | 2,250 |
| Create/close lifetime pairs | 2,250 |
| Median lifetime | 4 μs |
| 95th-percentile lifetime | 11 μs |
| Maximum lifetime | 127 μs |

The final sampler requested a 100 ms sleep and completed 43 snapshots during
the 10-second active window because each system-wide query adds overhead. Even
the 100 ms lower bound is approximately 787 times longer than the longest
transient handle and 25,000 times longer than the median. Therefore it was
expected to miss all returned transient handles. This is why the analyzer
reports zero exact requested-to-granted pairs: not because the object identity
is unknown, but because the newly returned handles closed long before a system
handle-table snapshot could observe their stored masks.

---

## 7. Persistent handles: literal hiding is false

The elevated handle snapshot found 41 persistent handles whose object field
equalled the exactly correlated game object. The independent kernel
`Handle-DCEnd` rundown also reported 41, and every one of the 41
`(owner, handle)` tuples overlapped.

This dual-source equality is the strongest literal-hiding result:

```text
Snapshot persistent target handles: 41
Kernel rundown target handles:       41
Exact owner/handle overlap:           41
Distinct owners:                      17
```

Selected owner/mask results:

| Owner | Handles | Stored granted masks |
|---|---:|---|
| `System` | 14 | thirteen `0x102A`; one `0x1FFFFF` |
| `audiodg.exe` | 8 | six `0x3000`; two `0x2000` |
| `NahimicSvc64.exe` | 5 | five `0x1000` |
| `svchost.exe` | 4 | `0x1478`, `0x100000`, `0x101000`, `0x103200` |
| `csrss.exe` | 1 | `0x1FFFFF` |
| `lsass.exe` | 1 | `0x1478` |
| `NahimicSvc32.exe` | 1 | `0x1000` |
| `steam.exe` | 1 | `0x101400` |
| `nvcontainer.exe` | 1 | `0x100000` |
| `warp-svc.exe` | 1 | `0x1000` |
| `PresentMon-x64.exe` | 1 | `0x1000` |

The complete privacy-reduced owner table is in the JSON evidence artifact.

The game object is therefore not absent from privileged handle enumeration, and
external processes do hold handles to it. “Randgrid hides all handles” is not a
defensible description of the observed runtime behavior.

---

## 8. Evidence for selective policy—and its limit

The distribution is not random-looking:

- system/security processes retain broad masks, including `0x1FFFFF` and
  `0x1478`;
- Steam retains query and synchronize rights;
- graphics/audio/monitoring services often retain only limited-query,
  limited-set, or synchronize rights;
- Nahimic made 32 successful requests for
  `VM_READ | QUERY_INFORMATION` (`0x410`) during the trace, while all six of its
  persistent handles to the game stored only `QUERY_LIMITED_INFORMATION`
  (`0x1000`).

That pattern is consistent with a selective access policy or allowlist, and it
is materially stronger than the static import alone. It is still not a causal
proof that Randgrid transformed `0x410` into `0x1000`:

- the 32 newly returned Nahimic handles lived for only microseconds and closed
  before a 100 ms snapshot;
- the six persistent Nahimic handles predated the observed transient calls;
- event 5 and `HandleCreate` identify a request and returned handle but do not
  include the stored granted-access mask;
- the handle table includes the stored mask but only for a handle still alive at
  snapshot time.

Accordingly, the evidence supports “selective filtering is plausible and
runtime-corroborated,” not “this callback definitely removed these exact bits
from this exact request.”

---

## 9. Cross-channel collision behavior

The earlier passive pass remains valid:

| Service | State | Size | Relationship |
|---|---|---:|---|
| `atvi-randgrid_sr` | Running | 13,130,616 | Runtime/static authority image |
| `atvi-randgrid_msstore` | Stopped | 13,130,616 | Byte-identical to Steam image |
| `atvi-randgrid` | Stopped | 2,981,352 | Different Battle.net image |

The System event log contained 42 event-7000 failures for the Store service.
Most intervals formed approximately 5.55-second retry bursts, and Windows
reported “Cannot create a file when that file already exists.” The byte-identical
Steam and Store images embed the same device and DOS-link names, so a live object
namespace collision is plausible. The event does not identify the exact object;
that last association remains an inference.

---

## 10. Reproduction and safety properties

From an Administrator PowerShell while the game and Steam driver are already
running:

```powershell
$python = (Get-Command python.exe).Source
$stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss')

& .\scripts\runtime\capture_randgrid_runtime.ps1 `
  -OutputDirectory ".\local-analysis\runtime-elevated-$stamp" `
  -PythonPath $python `
  -DurationSeconds 10 `
  -HandleIntervalSeconds 0.1
```

The collector:

- verifies elevation, the target process, driver state, hash, and signature;
- starts two unique Logman user-provider sessions;
- starts one unique Tracelog `-systemlogger -independent` session for
  `PROC_THREAD+LOADER+OB_HANDLE`;
- leaves every pre-existing ETW session untouched;
- opens only a query-limited handle to the collector itself, solely to discover
  the process-object type index;
- monitors target/driver liveness once per second;
- stops only its three exact session names;
- decodes all three ETLs locally and fails closed if any decoder returns nonzero;
- never opens the game, sends an IOCTL, changes a service, or terminates a
  process.

Two rejected Xperf OB-session attempts failed before recording with
`0x800703EC` and were cleaned up immediately. They left no session or helper
process. The successful path uses Microsoft's documented independent
SystemTraceProvider mechanism via Tracelog.

The raw OB stream is high-volume. A 10-second requested window is the recommended
default; extend it only when the question genuinely requires more events.

---

## 11. Final claim boundary

```text
Object callback registration:                  proved statically
Exact running game process object:             proved by audit/OB correlation
Persistent external handles to that object:   proved by snapshot + rundown
Universal literal handle hiding:              contradicted
Outright process-open denial in this window:  not observed
Selective access filtering/allowlisting:      strongly suggested
One exact requested -> stored-mask rewrite:   not captured
```

The remaining uncertainty is now narrow and explicit. It is no longer “we do
not know which process object is the game” or “Windows redacted every pointer.”
It is specifically the lack of a shared granted-mask field for the extremely
short-lived returned handles.
