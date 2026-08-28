# RICOCHET Anti-Cheat — Disassembly & PE Findings

**Date:** 2026-08-28
**Host:** Windows 11 Pro (build 26200), local x86-64 workstation
**Game:** Call of Duty HQ (Steam), `D:\SteamLibrary\steamapps\common\Call of Duty HQ`
**Companion docs:** `06-completed-deep-static-analysis.md`, `07-randgrid-deep-dive.md`, `08-randgrid-runtime-behavior.md`

---

## 1. Methodology

This pass **breaks the clean-room line** the earlier research held (live behavior + PE
structure only, no disassembly). We now disassemble and string-mine the running
binaries directly.

**Tooling** (installed into `~/PowerTheFutureofAIAIM/.venv`):
- `pefile 2024.8.26` — PE structure, imports, exports, sections, data directories
- `capstone` — x86-64 disassembly of entry points / code regions
- `Get-AuthenticodeSignature` (PowerShell) — Authenticode signature verification
- Custom scripts in this folder: `pe_analyze.py`, `disasm.py`, `deep.py`
  (outputs: `pe_analysis.json`, `disasm_report.json`, `deep_report.json`)

**Scope:** every RICOCHET component that was running or present on disk at analysis
time — the bootstrapper, the game client, the broker service, the crash handler,
the attestation wizard, the kernel driver, and the telemetry DLL.

**Honesty note on disassembly:** this original pass landed inside startup thunks or
protected dispatchers for most targets. Imports and strings are unambiguous evidence
that a dependency or capability is present, but they do not prove how it is used.
The subsequent Ghidra/ILSpy/export-table pass in
`06-completed-deep-static-analysis.md` resolves what can be resolved and corrects
the behavior claims that this first pass inferred too aggressively.

---

## 2. Binary Inventory

| Binary | Path | Size | Machine | Subsystem | Role |
|---|---|---:|---|---|---|
| `bootstrapper.exe` | `…\Call of Duty HQ\` | 379,888 B | x86-64 | windows-gui | RICOCHET launcher / service manager |
| `cod.exe` | `…\Call of Duty HQ\` | 479,249,392 B (~457 MB) | x86-64 | windows-gui | Game client (hosts AC) |
| `CODBrokerService.exe` | `C:\ProgramData\Activision\Call of Duty\` | 165,872 B | x86-64 | windows-cui | Broker Windows service |
| `codCrashHandler.exe` | `C:\ProgramData\Activision\Call of Duty\` | 1,514,480 B | x86-64 | windows-cui | Crash capture + upload |
| `CODSecureAttestationWizard.exe` | `…\Call of Duty HQ\` | 67,301,808 B (~64 MB) | x86-64 | windows-gui | .NET attestation UI |
| `Randgrid.sys` | `…\Call of Duty HQ\` | 13,130,616 B (~12.5 MB) | x86-64 | **native** (kernel) | Kernel-mode driver |
| `telescope25.dll` | `…\Call of Duty HQ\` | 35,474,928 B (~34 MB) | x86-64 | windows-gui | Telemetry / "telescope" DLL |

All seven are **x86-64**. Only `Randgrid.sys` is a **native** (kernel) subsystem;
the rest are user-mode. All seven carry a **valid Authenticode signature** from
**Activision Publishing Inc** (verified via `Get-AuthenticodeSignature`, status
`Valid` on every file).

---

## 3. bootstrapper.exe — RICOCHET launcher / service manager

**Size:** 379,888 B · **Sections:** `.text .rdata .data .pdata .fptable .rsrc .reloc`
**Imports:** KERNEL32 (129), ADVAPI32 (19), USER32 (10), SHELL32 (4), VERSION (3), ole32 (1)
**Exports:** 0 · **TLS:** none · **Delay imports:** none

The bootstrapper is the **service manager** for RICOCHET. Its string pool is
decisive about what it does:

- `Ricochet Anti-Cheat`, `Ricochet Service Manager`, `RicochetServiceManager`
- `COD.Broker.Service` — the Windows service it owns
- `CODBrokerService.exe`, `CODBrokerInstaller.exe` — the service binary + installer
  it launches
- `Broker service update needed: %u.%u.%u.%u > %u.%u.%u.%u` — version-gated
  service (re)install
- `Stopped broker service "%ls"`, `Failed to stop broker service (%u)`,
  `Failed to start broker service (%u)`, `Failed to query broker service config (%u)`
- `Not the last process for broker service (refcount: %ld), leaving service running`
  / `Last process in broker service global refcount, stopping service...`
  → **global reference-counted lifetime** for the broker service
- `BrokerInstallStatus`, `Launching BrokerInstaller to install/update service...`
- Crash-handler wiring: `Failed to initialize crash handler`,
  `bootstrappercrashhandler.exe`, `--folder_crashreport`, `--opt-allow_crash_upload`,
  `--opt-allow_old_crashes_reupload`, `dw_upload_url`, `crashfiles`,
  `old_crashes_reupload`, `Failed to create the crash evidence file (error code %u)`
- Registry: `SOFTWARE\Activision\Call Of Duty`

**PDB path leaked:** `E:\sat_etu\game\pc\bootstrapper.pdb` (build machine path).

**Read:** the bootstrapper is a thin **orchestrator**. It does not itself do
anti-cheat work — it (re)installs and reference-counts the `COD.Broker.Service`
Windows service, launches `CODBrokerService.exe`, and wires up the crash handler
with upload options. The `refcount` strings explain why the broker service keeps
running across multiple game launches.

---

## 4. CODBrokerService.exe — the broker Windows service

**Size:** 165,872 B · **Sections:** `.text .rdata .data .pdata buildinf .rsrc .reloc`
**Imports:** KERNEL32 (65), MSVCP140 (37), ADVAPI32 (17), VCRUNTIME140 (13),
api-ms-win-crt-* (runtime), `tbs.dll` (1), `ncrypt.dll` (5)
**Exports:** 0 · **TLS:** none

The broker is the **long-lived user-mode service** that the bootstrapper manages.
Key strings:

- `\.\pipe\COD.Broker.v1` — **named pipe** the game talks to the broker over
- `broker_service`, `broker_service.log`, `CODBrokerService`, `COD.Broker.Service`
- `"executable_name": "CODBrokerService.exe"` — JSON config describing itself
- `ActivisionAIK` — an **AIK** (Activision Identity Key / attestation key) token
- Crash-handler strings identical to the bootstrapper's (shared crash lib):
  `Failed to initialize crash handler`, `crashfiles`, `--folder_crashreport`,
  `is_bootcrash`, `dw_upload_url`, `CrashHandler_CmdlineSetOptions`
- Registry: `Software\Activision\Call of Duty`
- **PDB path leaked:** `C:\workspace\sat_etu\game\pc\CODBrokerService.pdb`

**Read:** the broker is a small, self-contained service. The `COD.Broker.v1`
named pipe is the IPC channel between the game client and the service. The
`ActivisionAIK` string and `ncrypt`/`tbs` imports point to **cryptographic
attestation** happening in the broker (signing/verifying identity keys). The
`buildinf` section is a build-info section (version/build metadata).

---

## 5. codCrashHandler.exe — crash capture + upload

**Size:** 1,514,480 B · **Sections:** `.text .rdata .data .pdata .rsrc .reloc`
**Imports:** KERNEL32 (71), USER32 (49), MSVCP140 (42), GDI32 (15), WINHTTP (12),
ADVAPI32 (11), gdiplus (5), COMCTL32 (2)
**Exports:** 0 · **TLS:** none

The crash handler is the **largest user-mode binary** and the most revealing.
It is a **protobuf-based** crash reporter (Google protobuf 3.13.0, built via
vcpkg). Key strings:

- **Upload endpoint (the big one):**
  `https://ingest.datax.activision.com/messages?client=%S&env=%S&format=proto&target=%S&project=%S`
  → crash data is POSTed as **protobuf** to Activision's `datax` ingest service
- `iw-cod-crashhandler` — the client identifier sent to the ingest endpoint
- `CrashLogsGenerator`, `CrashLogsGenerator.exe`, `CrashLogsGenerator_Dev.exe`
  — spawns a separate log-generator process
- `CRASHLOGSGEN`, `crash_bundle_version_code`, `crash_title_id`,
  `following_crash_signature`, `CrashReportKVPS`
- `The crash zip generated by the current session has failed the upload...`
  `The crash zip [%ws] is too old to be submitted. Deleted.`
  `old_crashes_reupload`, `--opt-allow_old_crashes_reupload`
- Localized UI strings (FR/ES/DE/IT/PT) — a **GUI** crash-report dialog
  (`Dev configuration`, `Your feedback will be read by our development team`,
  `Please, can you describe what happened before the crash ?`)
- `https://support.activision.com` (localized)
- **PDB path leaked:** `C:\workspace\sat_etu\game\pc\codCrashHandler.pdb`
- **Build paths leaked:** `D:\p\vcpkg\buildtrees\protobuf\...`,
  `C:\workspace\sat_etu\code\toolset\apps\pccrashhandler\internal\network\...`
  (protobuf `.pb.cc` generated files: `dlog_event_crash.pb.cc`,
  `dlog_event_crash_scan_and_repair_success.pb.cc`,
  `dlog_event_extch_crashzip_reupload.pb.cc`, `dlog_common.pb.cc`)

**Read:** the crash handler is a **GUI + protobuf uploader**. It zips crash
evidence, generates logs via a child `CrashLogsGenerator` process, and POSTs
protobuf-encoded events to `ingest.datax.activision.com`. The `datax` ingest
service is Activision's central telemetry/crash pipeline — the same one the
`telescope` DLL likely feeds. The protobuf message names (`dlog_event_crash`,
`dlog_event_extch_crashzip_reupload`) reveal the event schema.

---

## 6. CODSecureAttestationWizard.exe — .NET attestation UI

**Size:** 67,301,808 B (~64 MB) · **Machine:** x86-64 · **Subsystem:** windows-gui
**Sections:** `.text .CLR_UEF .rdata .data .pdata .didat Section .rsrc .reloc`
**Imports:** KERNEL32 (200), OLEAUT32 (27), ADVAPI32 (20), ole32 (18), USER32 (2),
api-ms-win-crt-* (runtime)
**Exports:** 6 · **Delay imports:** VERSION.dll, api-ms-win-core-winrt-l1-1-0.dll

This is a **.NET (CoreCLR) single-file app** — the `.CLR_UEF` section and the
`D:\a\_work\1\s\src\coreclr\...` PDB paths are the giveaway. It is the
**Secure Attestation Wizard** UI.

- **CoreCLR PDB paths leaked:** `D:\a\_work\1\s\src\coreclr\vm\jithelpers.cpp`,
  `...\coreclr\vm\threads.cpp`, `...\coreclr\jit\codegenxarch.cpp`,
  `...\coreclr\vm\amd64\jitinterfaceamd64.cpp`, `...\coreclr\vm\excep.cpp`,
  `...\coreclr\dlls\mscoree\exports.cpp`, `singlefilehost.pdb`
  → confirms **.NET single-file** (Corehost.Static) packaging
- `https://aka.ms/dotnet/info`, `https://aka.ms/dotnet-core-applaunch?`
  → standard .NET app-launcher URLs
- `CODSecureAttestationWizard.dll` — the embedded managed assembly
- GUID `d38cc827-e34f-4453-9df4-1e796e9f1d07`
- The huge "url" string hits are **false positives** — they are the .NET
  runtime's embedded HTML/JS resource blobs (the single-file host bundles a
  large static resource section), not real URLs.

**Read:** the attestation wizard is a **.NET 8 single-file GUI** that walks the
user through hardware/TPM attestation. The 64 MB size is almost entirely the
bundled .NET runtime + resources, not app logic. The real attestation logic is
in the managed `CODSecureAttestationWizard.dll` (IL, not native — so a
`monodis`/`ilspycmd` pass would be the right tool, not capstone).

---

## 7. Randgrid.sys — the kernel-mode driver (the core of RICOCHET)

**Size:** 13,130,616 B (~12.5 MB) · **Machine:** x86-64 · **Subsystem:** native (kernel)
**Sections:** `.text .rdata .data .pdata INIT .rsrc .reloc`
**Imports:** `ntoskrnl.exe` (**673** symbols), `HAL.dll` (4), `ci.dll` (2), `cng.sys` (10)
**Exports:** 0 · **TLS:** none

This is the **kernel driver** — the heart of RICOCHET's anti-cheat. A 12.5 MB
kernel driver with **673 ntoskrnl imports** is a heavyweight. The import table
defines its dependency surface; the later exact-call census in document 07
determines which names have recovered callers.

### 7.1 Object manager callback surface
`ObRegisterCallbacks`, `ObOpenObjectByPointer`, `ObReferenceObjectByHandle`,
`ObReferenceObjectByHandleWithTag`, `ObReferenceObjectByName`,
`ObReferenceObjectByPointer`, `ObReferenceObjectByPointerWithTag`,
`ObGetObjectSecurity`

The follow-up Ghidra pass resolves a direct registration path to
`ObRegisterCallbacks`, so object-manager callback registration is confirmed.
The protected pre/post callback itself was not recovered. The import and
registration call do **not** prove that this build hides handles, strips a
particular access mask, or targets a particular process. The `ObReferenceObjectBy*`
family establishes object-reference capability, not a specific hiding behavior.

The deeper pass additionally recovers a process-create callback registration at
thunk `0x140A294E0` and a thread callback at `0x140A2AC70`. The thread callback
continues only for creation events, calls `PsLookupThreadByThreadId`, and checks
the result with `PsIsSystemThread`. See document 07 for the exact paths and
remaining protected behavior.

### 7.2 Memory manager (physical memory + MDL)
`MmGetPhysicalAddress`, `MmMapIoSpace`, `MmProbeAndLockPages`,
`MmProbeAndLockSelectedPages`, `MmCopyMemory`, `MmProtectMdlSystemAddress`,
`MmAllocateContiguousMemory`, `MmAllocateContiguousMemorySpecifyCache`,
`MmAllocateContiguousNodeMemory`, `MmAllocateNonCachedMemory`,
`MmAllocateMdlForIoSpace`, `MmAllocateNodePagesForMdlEx`,
`MmFreeContiguousMemory`, `MmFreePagesFromMdl`, `MmFreeNonCachedMemory`,
`MmGetSystemRoutineAddress`

These imports establish a broad memory-management surface. The follow-up pass
finds 18 direct `MmCopyMemory` wrappers, but no direct statically resolved caller
for `MmGetPhysicalAddress`, `MmMapIoSpace`, `MmProbeAndLockPages`, or
`MmProbeAndLockSelectedPages`; a physical-memory walker was not identified.
`MmGetSystemRoutineAddress` is also imported, but no direct caller and no
non-import plaintext kernel-routine targets were recovered. It would be incorrect
to claim a particular physical-memory workflow or a list of dynamically resolved
routines from the import table alone.

### 7.3 Executive / pool
`ExAllocatePoolWithTag`, `ExAllocatePoolWithTagPriority`,
`ExAllocatePoolWithQuotaTag`, `ExFreePool`, `ExFreePoolWithTag`,
`ExRegisterCallback`, `ExCreateCallback`, `ExGetFirmwareEnvironmentVariable`,
`ExGetPreviousMode`, `ExAcquireRundownProtection`,
`ExReleaseRundownProtection`, `ExGetExclusiveWaiterCount`,
`ExGetSharedWaiterCount`, plus the lookaside-list family
(`ExDeleteLookasideListEx`, `ExDeleteNPagedLookasideList`,
`ExDeletePagedLookasideList`, `ExDeleteResourceLite`,
`ExReleaseResourceLite`).

`ExGetFirmwareEnvironmentVariable` is capable of reading UEFI variables, and
`ExRegisterCallback`/`ExCreateCallback` support executive callback objects.
However, the follow-up Ghidra pass does not recover a direct caller for the
firmware import in Randgrid, so this list does not prove a particular hardware-
attestation flow. The concrete readiness checks are instead proved in the
separately extracted `SecureAttestation.dll`.

### 7.4 Kernel scheduler / sync
`KeAcquireSpinLockAtDpcLevel`, `KeAcquireSpinLockRaiseToDpc`,
`KeReleaseSpinLock`, `KeReleaseSpinLockForDpc`,
`KeReleaseSpinLockFromDpcLevel`, `KeAcquireGuardedMutex`,
`KeReleaseGuardedMutex`, `KeReleaseInStackQueuedSpinLock` (+ForDpc/FromDpcLevel),
`KeReleaseInterruptSpinLock`, `KeReleaseMutex`, `KeReleaseSemaphore`,
`KeWaitForSingleObject`, `KeWaitForMultipleObjects`, `KeDelayExecutionThread`,
`KeInsertQueueDpc`, `KeRemoveQueueDpc`, `KeInsertDeviceQueue`,
`KeRemoveDeviceQueue`, `KeInsertByKeyDeviceQueue`, `KeRemoveByKeyDeviceQueue`,
`KeRemoveEntryDeviceQueue`, `KeExpandKernelStackAndCalloutEx`,
`KeSaveExtendedProcessorState`, `KeRestoreExtendedProcessorState`,
`KeQuerySystemTimePrecise`, `KeBugCheck`, `KeBugCheckEx`

`KeExpandKernelStackAndCalloutEx` provides an expanded kernel stack for a kernel
callout; its import is not evidence of a call into user mode.
`KeSaveExtendedProcessorState`/`KeRestoreExtendedProcessorState` preserve selected
extended processor state around kernel work, but their presence does not prove
thread-register snapshotting for instrumentation or anti-debugging.
`KeQuerySystemTimePrecise` provides precise time; the purpose of that timing is
not resolved by the import alone.

### 7.5 Rtl (runtime)
The 95 actual `Rtl*` imports cover registry access, Unicode/ANSI conversion,
string comparison/copying, bitmap operations, generic AVL tables, resource
encoding, security descriptors, run-once primitives, and time conversion.
Representative names include `RtlCheckRegistryKey`, `RtlCompareMemory`,
`RtlCompareUnicodeString`, `RtlCopyString`, `RtlHashUnicodeString`,
`RtlInitializeGenericTableAvl`, `RtlTimeToTimeFields`, and
`RtlTimeFieldsToTime`.

Contrary to the first report, `RtlImageNtHeader`,
`RtlImageDirectoryEntryToData`, `RtlImageFileHeader`, and the user-mode-style
critical-section family are **not imported** by this driver. PE module walking
was therefore not established by those names.

### 7.6 Other imports
- `ci.dll` (2): the actual imports are `CiValidateFileObject` and
  `CiFreePolicyInfo`, with four and eight exact call sites respectively. The
  previously named CI functions are not imported.
- `cng.sys` (10): all ten BCrypt imports have recovered callers. Together with
  `ECDSA_P256`, `ECCPUBLICBLOB`, `SHA256`, and `HashDigestLength`, they support a
  high-confidence ECDSA-P256/SHA-256 signature-verification pipeline.
- `HAL.dll` (4): only `KeStallExecutionProcessor` has recovered callers (62
  static sites). No recovered caller was found for the hardware-counter or
  performance-counter imports, so the prior DMA-attestation inference was
  unsupported.

### 7.7 Strings
- Device objects: `\Device\Randgrid`, `\DosDevices\Randgrid` — the driver's
  **device name** (user-mode opens `\\.\Randgrid` to talk to it).
- `Randgrid Driver`, `Randgrid Driver with more comments`, `Randgrid.pdb`
- `(C)2024 Activision Blizzard, Inc.`, `Activision Publishing Inc`
- The "url" hits are **Authenticode cert CRL/OCSP** URLs (DigiCert + Microsoft
  Windows Third Party Component CA 2014) — the embedded signature chain, not
  network endpoints.

**Read:** Randgrid.sys is a large, protected kernel-mode anti-cheat driver with
confirmed object/process/thread callbacks, device lifecycle calls, process and
virtual-memory inspection, Code Integrity validation, CNG signature
verification, and 18 `MmCopyMemory` call sites. Its flattened/indirect dispatcher
still prevents defensible attribution of the object-callback policy, a physical-
memory walker, or firmware-variable behavior. Document 07 is authoritative for
the exact reached-call surface and corrections.

---

## 8. telescope25.dll — the "telescope" telemetry DLL

**Size:** 35,474,928 B (~34 MB) · **Machine:** x86-64 · **Subsystem:** windows-gui
**Image base:** `0x180000000` (note: **not** the usual `0x140000000`)
**Sections:** `.text .rdata .data .pdata .fptable _RDATA .rsrc .reloc`
**Imports:** KERNEL32 (185), USER32 (28), WS2_32 (17), GDI32 (12), SHLWAPI (5),
ole32 (3), ADVAPI32 (5), SHELL32 (3), WINMM (2), IPHLPAPI (2), CRYPT32 (2)
**Exports:** **6,984** · **TLS:** none

The follow-up parser demangled every export. The runtime identity is now exact:
`WebCore` accounts for 3,520 exports, `WTF` for 2,731, `JSC` for 714, with one
JavaScriptCore C API export and 18 other/product-facing symbols. Those symbols
include `CreateTelescopeInstance` and `GetChangelistNumberInterface`.

`telescope24.dll` and `telescope25.dll` have the same 6,984 export names at the
same 6,984 RVAs; `telescope25.dll` is eight bytes smaller. The export/import
surface proves a bundled WebCore/WTF/JavaScriptCore runtime with networking and
cryptographic capability. It does **not** prove that telescope sends to the
`datax` endpoint found in the crash handler. Product-specific behavior beyond
`CreateTelescopeInstance` remains a separate call-site/data-flow question.

---

## 9. cod.exe — the game client (hosts the AC)

**Size:** 479,249,392 B (~457 MB) · **Machine:** x86-64 · **Subsystem:** windows-gui
**Image base:** `0x140000000`
**Sections:** `.text .rdata .data .pdata .fptable .rsrc .reloc`
**Imports:** KERNEL32 (185), USER32 (28), WS2_32 (17), GDI32 (12), SHLWAPI (5),
ole32 (3), ADVAPI32 (5), SHELL32 (3), WINMM (2), IPHLPAPI (2), CRYPT32 (2)
**Exports:** 0 · **TLS:** none

The game client is a **457 MB** monolith. Its import table is the standard
Win32 + Winsock + crypto set (identical shape to telescope25.dll's import
counts — both are large native Windows apps). The anti-cheat logic is **not**
in cod.exe's import table; it is **loaded at runtime** by the bootstrapper/broker
machinery (Randgrid.sys, telescope25.dll, the broker service). cod.exe is the
**host** that the AC instruments.

**Read:** cod.exe is the game itself. The AC attaches to it via the broker
service + kernel driver. A targeted disassembly of cod.exe would be a
needle-in-haystack at 457 MB — the high-value targets are the smaller AC
components (Randgrid.sys, broker, telescope), which is where we focused.

---

## 10. Cross-cutting findings

### 10.1 The RICOCHET stack (from the binaries)
```
bootstrapper.exe          (launcher / service manager, refcounted)
   └─ CODBrokerService.exe  (Windows service, named-pipe IPC, AIK attestation)
        └─ cod.exe           (game client — the host)
             ├─ Randgrid.sys (protected kernel driver; callbacks/memory/CI/CNG surface)
             ├─ telescope25.dll (WebCore/WTF/JSC runtime; 6,984 exports)
             └─ codCrashHandler.exe (protobuf crash uploader → datax)
CODSecureAttestationWizard.exe  (.NET 8 single-file attestation UI)
```

### 10.2 Build-infrastructure leaks (PDB / workspace paths)
Every binary leaks its **build machine path** in its PDB / debug-info strings:
- `E:\sat_etu\game\pc\bootstrapper.pdb`
- `C:\workspace\sat_etu\game\pc\CODBrokerService.pdb`
- `C:\workspace\sat_etu\game\pc\codCrashHandler.pdb`
- `C:\workspace\sat_etu\code\toolset\apps\pccrashhandler\...`
- `D:\p\vcpkg\buildtrees\protobuf\...` (vcpkg protobuf build)
- `D:\a\_work\1\s\src\coreclr\...` (.NET CoreCLR build)

→ All built on a shared `sat_etu` workspace (a build-farm path), with the
crash handler built via **vcpkg** and the wizard via **.NET CoreCLR**.

### 10.3 Network endpoints (from strings)
- `https://ingest.datax.activision.com/messages?client=%S&env=%S&format=proto&target=%S&project=%S`
  — the protobuf ingest endpoint directly evidenced in the crash handler.
  This static pass did not establish a telescope call path to it.
- `https://support.activision.com` — support link (localized).
- `https://aka.ms/dotnet/info`, `https://aka.ms/dotnet-core-applaunch?` —
  .NET runtime URLs (wizard).
- DigiCert + Microsoft CRL/OCSP URLs — Authenticode chain (not app traffic).

### 10.4 Attestation / crypto surface
- **Broker:** `ActivisionAIK` token + `ncrypt`/`tbs` imports → user-mode
  attestation key handling.
- **Randgrid.sys:** all ten CNG functions and both actual CI functions have
  recovered callers, supporting SHA-256/ECDSA-P256 verification plus file-object
  policy validation. The firmware-variable import still has no recovered caller.
- **Wizard + `SecureAttestation.dll`:** the proved readiness path for TPM 2.0,
  AIK/certificate, TCG log, EFI measurement, Secure Boot, UEFI/GPT, and broker
  service checks.

### 10.5 Signatures
All 7 binaries: **Authenticode Valid**, signer **Activision Publishing Inc**.
Randgrid.sys additionally carries the **Microsoft Windows Third Party
Component CA 2014** chain (the attested-signer / WHQL path needed to load a
kernel driver on modern Windows).

---

## 11. What this adds over the prior clean-room pass

The earlier research (docs 01–04) established RICOCHET's **architecture and
behavior** without disassembling. This pass adds:

1. **Concrete import-table evidence** for capability surfaces, with behavior
   claims limited to imports that also have resolved call sites. The later
   Ghidra pass confirms callback registration and `MmCopyMemory` use while
   recording negative results for several previously inferred behaviors.
2. **The real network endpoint** (`ingest.datax.activision.com`, protobuf) and
   the **IPC channel** (`\\.\pipe\COD.Broker.v1`).
3. **Build-infrastructure leaks** (PDB/workspace paths) — useful for
   fingerprinting builds and correlating versions.
4. **Component roles supported** from strings and static structure: bootstrapper =
   refcounted service manager; broker = named-pipe service + AIK; crash handler
   = protobuf GUI uploader; wizard = .NET 8 single-file; Randgrid = kernel
   driver; telescope = a product wrapper around WebCore/WTF/JavaScriptCore.

## 12. Deep-analysis follow-up status

The original next-step list has been completed and reconciled in
`06-completed-deep-static-analysis.md`:

- Randgrid Ghidra analysis: completed to the protected static boundary.
- Managed wizard extraction/decompilation: completed.
- Native `SecureAttestation.dll` readiness analysis: completed.
- Telescope export/runtime analysis: completed.
- Broker protocol architecture: completed statically without touching the live
  pipe.
- `MmGetSystemRoutineAddress` target search: completed with a documented
  negative result (no direct caller and zero non-import plaintext candidates).

The unresolved callback body and physical-memory-walker identity are now
recorded as limitations imposed by the driver's indirect/flattened control flow,
not left as unperformed work and not replaced with speculative labels.

---

## Appendix A — Reproduction

```powershell
# From the public repository root. These reproduce the historical first pass.
python .\scripts\historical\pe_analyze.py
python .\scripts\historical\disasm.py
python .\scripts\historical\deep.py

# Use this tested analyzer for the authoritative Randgrid call census.
python .\scripts\randgrid_deep_xrefs.py --target 'X:\path\to\Randgrid.sys'
```

The historical scripts are preserved for provenance and carry their original
limitations. `randgrid_deep_xrefs.py` plus document 07 supersede their Randgrid
behavior inferences.
