# Randgrid.sys — Runtime Behavior and Handle-Policy Evidence

**Date:** 2026-08-28

**Static input SHA-256:** `4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E`

**Scope:** bounded, read-only observation of the running Steam driver and game

**Safety boundary:** no driver/service/device mutation, no IOCTL, no debugger,
no injection, no process-memory operation, and no handle opened to `cod.exe`

---

## 1. Result

The runtime pass proves several important parts of the static model:

- the running `atvi-randgrid_sr` service points to the exact driver previously
  analyzed statically;
- the driver is active while `cod.exe`, the bootstrapper, broker service, and
  crash handlers are active;
- the live DOS-device link `Randgrid` resolves to `\Device\Randgrid`;
- the Steam and Microsoft Store driver images are byte-identical and both embed
  `\Device\Randgrid` and `\DosDevices\Randgrid`;
- the stopped Store service repeatedly fails with `ERROR_ALREADY_EXISTS` while
  the Steam service is running, in approximately 5.55-second retry bursts;
- the observed component topology remained stable through a bounded passive
  metrics/handle-table capture.

The runtime pass does **not** yet prove or disprove object-callback handle-access
stripping. The necessary privileged providers were not active, Windows redacted
kernel object pointers from the non-elevated handle table, and the requested UAC
elevation was cancelled. No privileged trace session started.

The precise statement therefore remains:

> Randgrid's object callback registration is proved statically. Runtime handle
> hiding/access stripping remains unresolved—not absent, and not established.

---

## 2. Method and evidence boundary

The successful non-elevated pass used only:

- `Win32_SystemDriver` and `Win32_Process` read-only queries;
- file size, SHA-256, and Authenticode verification;
- `QueryDosDeviceW("Randgrid")`;
- bounded `Get-Process`/`Win32_Process` metric samples;
- `NtQuerySystemInformation(SystemExtendedHandleInformation)` snapshots;
- read-only System and Code Integrity event-log queries;
- read-only inspection of currently active ETW sessions.

Raw handle metadata, process metrics, and any future ETL remain under the
Git-ignored `local-analysis/` directory. Only the privacy-reduced aggregate in
`evidence/randgrid-runtime-passive-summary.json` is published.

No command line or launch token from the running game is published.

---

## 3. Live driver identity

At capture time:

| Property | Value |
|---|---|
| Service | `atvi-randgrid_sr` |
| State | Running |
| Start mode | Manual |
| File size | 13,130,616 bytes |
| SHA-256 | `4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E` |
| Authenticode | Valid |
| Signer | Activision Publishing Inc |

The hash is identical to the static-analysis input in documents 06 and 07. This
closes the source-versus-runtime identity boundary: the driver being observed is
the driver whose import/callback call sites were mapped.

---

## 4. Live device publication

`QueryDosDeviceW("Randgrid")` returned:

```text
\Device\Randgrid
```

with Win32 last error `0`. This proves that the live DOS-device link exists while
the Steam driver is running. It backs the static combination of:

- embedded `\Device\Randgrid`;
- embedded `\DosDevices\Randgrid`;
- one exact `IoCreateDevice` call;
- one exact `IoCreateSymbolicLink` call;
- corresponding teardown calls.

The runtime query does not open the device and sends no IOCTL.

---

## 5. Cross-channel collision behavior

The driver variants were:

| Service | State | Size | SHA-256 relationship | Embedded Randgrid device names |
|---|---|---:|---|---|
| `atvi-randgrid_sr` | Running | 13,130,616 | Static/runtime authority hash | Yes |
| `atvi-randgrid_msstore` | Stopped | 13,130,616 | Byte-identical to Steam | Yes |
| `atvi-randgrid` | Stopped | 2,981,352 | Different Battle.net image | No exact two-name pair |

The System event log contains 42 event-7000 failures for
`atvi-randgrid_msstore` from 12:17:50 through 12:27:54 local time. The reported
error is:

```text
Cannot create a file when that file already exists.
```

Interval analysis:

| Statistic | Value |
|---|---:|
| Intervals | 41 |
| Median | 5.5499 s |
| 75th percentile | 5.5737 s |
| 90th percentile | 22.4783 s |
| Intervals at or below 7 s | 36 |
| Intervals over 30 s | 4 |
| Longer gaps | 22.4783, 40.9301, 69.2238, 145.3072, 146.5070 s |

The pattern is a burst of roughly 5.55-second retries with longer backoff gaps.
Because the Store and Steam images are byte-identical and publish the same
Randgrid names, the live DOS-device/object namespace is a plausible collision
surface. Event 7000 does not name the exact object, so that final association is
labelled an inference rather than direct proof.

---

## 6. Bounded component and process behavior

The 30 requested process samples spanned 34.16 seconds because each read-only WMI
sample adds overhead. The active component set remained unchanged:

- `CODBrokerService.exe`;
- `bootstrapper.exe`;
- `cod.exe`;
- two `codCrashHandler.exe` instances.

Aggregate `cod.exe` observations:

| Metric | Result |
|---|---:|
| Threads | 133 throughout |
| Handles | 51,540 → 51,613 |
| Working set | 2,484,465,664–2,507,337,728 bytes |
| Private memory | 11,362,131,968–11,395,137,536 bytes |
| CPU time added | 53.296875 s |
| Mean logical cores consumed | 1.5604 |
| Read operations | +6,405 |
| Write operations | +6,272 |
| Read bytes | +196,611,438 |
| Write bytes | +83,632 |

The simultaneous process-handle metadata collector completed 45 snapshots and
observed 164 additions, 204 removals, and two changed entries, ending with 7,004
process-type handles system-wide.

These measurements establish that the live topology was stable and active during
the observation window. They do not identify which calls came from Randgrid or
prove execution of the statically mapped callback/CI/CNG paths.

---

## 7. Why the handle-policy question remains open

Three different evidence layers are required:

1. **Requested access:** the caller's process/thread-open request.
2. **Callback result:** the access mask after any registered object callback.
3. **Granted access:** the mask stored in the resulting handle-table entry.

The non-elevated capture had none of the privileged correlation identifiers:

- Windows returned `0` for kernel object pointers in
  `SystemExtendedHandleInformation`.
- No `Microsoft-Windows-Kernel-Audit-API-Calls` session was active.
- The existing `NT Kernel Logger` had `LOADER` only, not `OB_HANDLE`.
- No handle was deliberately opened to `cod.exe`.

Microsoft's `ObHandleEvent` ETW event exposes the handle, object pointer, object
name, and object type—but not the granted access mask. Therefore OB-handle events
alone cannot prove access stripping. They must be correlated with a handle-table
snapshot and an access-request source. See Microsoft's
[`ObHandleEvent`](https://learn.microsoft.com/en-us/windows/win32/etw/obhandleevent)
and [`ObTrace`](https://learn.microsoft.com/en-us/windows/win32/etw/obtrace)
documentation.

Microsoft's own KrabsETW example uses event 5 from
`Microsoft-Windows-Kernel-Audit-API-Calls` for `PsOpenProcess`, including
`TargetProcessId`, `DesiredAccess`, and `ReturnCode`, and explicitly requires
administrator rights for Microsoft-Windows-Kernel-* providers. See the
[`UserTrace007_StackTrace` example](https://github.com/microsoft/krabsetw/blob/master/examples/ManagedExamples/UserTrace007_StackTrace.cs).

The attempted elevation was cancelled by the user. The launcher remained waiting
at UAC, no elevated child appeared, no `RandgridAudit-*` session existed, and no
trace status was written. The request then returned Windows' explicit
“operation was canceled by the user” result. It was not retried.

---

## 8. Prepared elevated passive capture

The repository now includes a bounded collector that can be run manually from an
Administrator PowerShell while the game and Steam Randgrid service are already
active:

```powershell
$python = (Get-Command python.exe).Source
$stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss')

& .\scripts\runtime\capture_randgrid_runtime.ps1 `
  -OutputDirectory ".\local-analysis\runtime-elevated-$stamp" `
  -PythonPath $python `
  -DurationSeconds 60
```

The collector:

- verifies elevation, the active `cod.exe`, and the running Steam driver;
- verifies the driver hash and signature;
- starts one uniquely named user ETW session for
  `Microsoft-Windows-Kernel-Audit-API-Calls` and
  `Microsoft-Windows-Kernel-Process` with stack capture;
- runs passive process-handle snapshots that open only the collector's own
  query-limited self handle;
- monitors that the target and driver remain active;
- stops only its exact ETW session;
- locally decodes the ETL with Xperf and Tracerpt;
- writes fail-closed status JSON;
- never opens `cod.exe`, never touches the Randgrid device, and never changes a
  service or driver.

The capture can reveal naturally occurring process/thread-open requests and
their call stacks. Definitive requested-versus-granted comparison still depends
on a correlatable persistent handle. Creating a controlled high-access handle to
the live game would cross the current no-process-attachment boundary and was not
performed.

---

## 9. Current conclusion

Runtime evidence now backs these statements:

- the exact statically analyzed Randgrid image is running;
- its live DOS-device link is published;
- the game/broker/bootstrapper/crash-handler topology is active;
- byte-identical Steam and Store images collide during Store start attempts in a
  measurable retry/backoff pattern.

Runtime evidence does not yet back “handle hiding.” The most accurate status is:

```text
Object callback registered: proved.
Live Randgrid device published: proved.
Process/thread access stripping: unresolved.
Reason: privileged requested/object/granted-access correlation was not authorized.
```

That boundary is evidence-driven, not a lack of static depth and not an inference
that the callback is inert.
