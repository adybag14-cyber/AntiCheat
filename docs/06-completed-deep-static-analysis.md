# RICOCHET Anti-Cheat — Completed Deep Static Analysis

**Date:** 2026-08-28

**Scope:** read-only analysis of the on-disk binaries and extracted managed bundle

**Supersedes:** the open task list in `05-disassembly-findings.md` §12

> **Randgrid update:** `07-randgrid-deep-dive.md` adds an independent IAT/stub/
> unwind census and is authoritative where it corrects this initial Ghidra pass.

---

## 1. Completion status

| Previously open item | Status | Result |
|---|---|---|
| Ghidra/IDA pass on `Randgrid.sys` | **Completed to the static-analysis boundary** | The PE entry path, dispatcher, direct `ObRegisterCallbacks` registration path, selected memory-manager references, and negative call-site results are documented. The protected callback and a physical-memory walker cannot be named defensibly because the driver uses a flattened/indirect dispatcher. |
| Managed decompilation of the attestation wizard | **Completed** | The .NET single-file bundle was extracted; the managed assembly was decompiled; all 13 checks, native boundary, UI flow, AIK-enrollment flow, registry persistence, and logging paths were recovered. |
| `telescope25.dll` export analysis | **Completed** | All 6,984 exports were parsed and demangled. The runtime is conclusively WebCore/WTF/JavaScriptCore. `telescope24.dll` and `telescope25.dll` expose the same names at the same RVAs. |
| Broker named-pipe analysis | **Completed statically** | The pipe server, access descriptor, connection loop, fixed header, bounded payload handling, dispatch table, and reply path were recovered without connecting to the live service. |
| `MmGetSystemRoutineAddress` call-site/name analysis | **Completed with a negative result** | The import is present, but Ghidra found no direct resolved caller and the full plaintext string scan found zero non-import kernel-routine-name candidates. Dynamic targets cannot be enumerated honestly from this binary's static plaintext. |

The originally suggested **live** pipe trace was deliberately not performed. A live connection to an active anti-cheat attestation service is unnecessary for the architecture question and crosses the safe read-only boundary. Static analysis closes the useful part of that task without interacting with the driver, service, game, or attestation state.

---

## 2. Inputs and toolchain

### 2.1 Input identities

| Input | SHA-256 |
|---|---|
| `Randgrid.sys` | `4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E` |
| `CODBrokerService.exe` | `C7399FEC98E2C5A5E15D083A4685F2F1D31E7601550B11AC4ED1F58F367E6169` |
| Extracted `CODSecureAttestationWizard.dll` | `956C5E6C664646E61440A9955955CE0A03E86E081AD724D9F028436E1EE9C9DA` |
| Extracted native `SecureAttestation.dll` | `B7B785A29354A36F4AFFB87BE55339FEB9BF0A3697414D0C81F1EFD2D2C99992` |
| `telescope24.dll` | `B53A47898405456BE7E464E4E4D1B5C3D00178DD656E911B4FAE6308DFA718C5` |
| `telescope25.dll` | `FA39D3EE032B3D897F8C09056D208F5B5DBF3E92B5C34836696085F8473C6C5B` |

### 2.2 Local analysis tools

- Ghidra `12.1.3 PUBLIC`, kept project-local under `.tools/ghidra_12.1.3_PUBLIC`;
  the downloaded release ZIP hashes to
  `93A5D11A9AD510622ACAAF908C556A7B9B764D338E78A7567F3689BF5081FD54`.
- ILSpyCmd / ICSharpCode.Decompiler `11.0.0.9375`, kept under `.tools/ilspy`.
- Single-file extractor `sfextract 2.3.0`, kept under `.tools/sfextract`.
- `pefile`, custom deterministic PE scripts, and LLVM `objdump` for independent address-level confirmation.

No system service, driver, game process, or binary was changed. The Ghidra projects and extracted files are analysis copies inside this research directory.

---

## 3. `Randgrid.sys`: what Ghidra resolved

### 3.1 Entry path and control-flow protection

- Image base: `0x140000000`
- PE entry RVA: `0x00C61000`
- Entry address: `0x140C61000`
- Ghidra-defined functions after analysis: `8,178`
- The entry function calls/jumps into `FUN_14015cf58`.
- `FUN_14015cf58` performs custom table initialization/relocation over `0x292` entries and ultimately dispatches through an indirect function-pointer table.
- Ghidra reports that it cannot recover the jump table because there are too many branches. This is consistent with flattened or virtualized control flow rather than an ordinary compiler startup thunk.

This is why calling the PE entry function “DriverEntry” does not expose a conventional driver initialization body. The entry address is known; the semantic implementation behind the dispatcher is not statically recoverable with confidence.

### 3.2 `ObRegisterCallbacks`

There is direct static evidence that the driver reaches `ObRegisterCallbacks`:

- IAT pointer: `0x140ABAD78`
- Computed-call wrapper: `FUN_140AB309D` at `0x140AB309D`
- Resolved surrounding path:
  `FUN_140A27286 -> FUN_140AB2DF3 -> FUN_140AB309D -> FUN_140A931A6 -> FUN_140AB3249`

The setup around `FUN_140AB2DF3` constructs the registration data before jumping to the wrapper. This supports **callback registration** at high confidence.

It does **not** resolve the protected pre/post-operation callback body or prove that the callback strips handles, hides handles, targets a specific process, or enforces a particular access mask. Those behavior claims require the callback pointer and its data flow; the flattened path prevents that identification here.

### 3.3 Memory-manager calls

- `MmCopyMemory` has 18 direct statically resolved wrappers/call sites in the Ghidra evidence artifact.
- `MmGetPhysicalAddress` has an IAT entry at `0x140ABB1C8`, but no direct statically resolved caller.
- `MmMapIoSpace` has an IAT entry at `0x140ABA7B8`, but no direct statically resolved caller.
- `MmProbeAndLockPages` has an IAT entry at `0x140ABA750`, but no direct statically resolved caller.
- `MmProbeAndLockSelectedPages` has an IAT entry at `0x140ABA748`, but no direct statically resolved caller.

Therefore, the binary clearly includes broad memory-manager capability and directly uses `MmCopyMemory`, but this pass did **not** identify a defensible “physical-memory walker.” Import presence alone cannot establish that behavior.

### 3.4 Other previously over-interpreted imports

The deeper PE/IAT census corrects this section:

- `ExGetFirmwareEnvironmentVariable` is imported, but only its linkage stub was
  found; there is no recovered caller in either exact supported call form.
- `RtlImageNtHeader`, `RtlImageDirectoryEntryToData`, and `RtlImageFileHeader`
  are not imported.
- `CiCheckSignatureMandatory` and `CiGetCertificateStoreOptions` are not
  imported.
- The real CI imports are `CiValidateFileObject` and `CiFreePolicyInfo`, with
  four and eight exact call sites respectively.

Thus firmware-variable and `RtlImage*` behavior remain unsupported, while
file-object Code Integrity validation is directly proved.

### 3.5 `MmGetSystemRoutineAddress`: completed negative result

- IAT entry: `0x140ABB588`
- Direct resolved code caller in Ghidra: **none**
- Static imports parsed: `689`
- Non-import kernel-routine-looking plaintext names in the complete ASCII/UTF-16 string pool: **zero**

The absence of plaintext targets means an honest target list cannot be produced. If this import is reached, its name may be encoded, constructed at runtime, stored as non-string data, or reached through the same indirect dispatcher. The old statement that it “resolves many functions dynamically” was not supported and has been removed.

---

## 4. Attestation wizard: managed logic recovered

The .NET single-file bundle yielded `382` files. ILSpy decompiled the actual managed application assembly into `analysis/attestation-wizard-decompiled`.

### 4.1 Native boundary and check set

`SecureAttestationData` allocates exactly 13 `CheckInfo` entries and calls the C-decl export below from `SecureAttestation.dll`:

```csharp
SecureAttestationReadinessVerify(CheckInfo[] checkInfoBuffer,
                                 nuint checkInfoBufferSize,
                                 out nuint dataSize)
```

The 13 check identifiers are:

1. `TPM2_PRESENT`
2. `AMDFW_NEEDS_UPDATE`
3. `SHOULD_TURN_ON_SECURE_BOOT`
4. `CAN_TURN_ON_SECURE_BOOT`
5. `TCG_LOG_PRESENT`
6. `EFI_MEASUREMENT_PRESENT`
7. `GPT_BOOT_PARTITION`
8. `UEFI_BIOS_MODE`
9. `AIK_KEY_EXISTS`
10. `BAD_KEYSET`
11. `AIK_CERT_PRESENT`
12. `COD_BROKER_INSTALLED`
13. `COD_BROKER_DISABLED`

The UI groups results into TPM, attestation, and Secure Boot categories with required, expected, and informational levels.

### 4.2 AIK enrollment flow

The managed control flow is explicit:

1. Run the 13 checks through the native DLL.
2. If automatic enrollment is enabled, require TPM 2.0 to be present, AMD firmware not to require the flagged update, and the AIK either to be absent or marked as a bad keyset.
3. Launch `enrollaik.exe` with ShellExecute verb `runas`.
4. Wait for the elevated process and collect its exit code.
5. Write the exit code as DWORD `EnrollAIK` under `HKCU\Software\Activision\Call Of Duty`.
6. Re-run the readiness checks after a successful enrollment result.

Application logs and user settings are stored below `%LocalAppData%\Activision\SecureAttestationWizard`. The interface also persists EULA acceptance before enabling the normal workflow.

---

## 5. `SecureAttestation.dll`: native readiness implementation

Ghidra resolved the exported `SecureAttestationReadinessVerify` at `0x180002AD0` and the major helpers it calls.

High-confidence native behavior:

- Reads `EnrollAIK` from `HKLM\SOFTWARE\Activision\Call Of Duty`, then falls back to the HKCU key.
- Opens the Service Control Manager and queries `COD.Broker.Service` for installation and disabled state; it may start the service during readiness processing.
- Uses the `Microsoft Platform Crypto Provider`.
- Opens the `ActivisionAIK` key through NCrypt.
- Queries `SmartCardKeyCertificate` to determine whether the AIK certificate exists.
- Calls `Tbsi_GetDeviceInfo` and treats TPM major version `2` as the TPM 2.0 result.
- Calls `Tbsi_Get_TCG_Log_Ex`/`Tbsi_Get_TCG_Log` and parses the TCG event log.
- Reads `PCP_TPM_MANUFACTURER_ID` and `PCP_TPM_FW_VERSION`, then compares a specific manufacturer/firmware combination used by the AMD-firmware check.
- Dynamically resolves `NtQuerySystemInformation` from `ntdll.dll` and queries information class `0x91` (`SystemSecureBootInformation`) for Secure Boot state/capability.
- Calls `GetFirmwareEnvironmentVariableW` with the zero GUID and interprets the Win32 result to distinguish UEFI firmware support from legacy BIOS mode.
- Reads `HKLM\SYSTEM\Setup\SystemPartition`, opens the associated volume/disk path, and issues storage/volume `DeviceIoControl` queries (`0x560000` and `0x70050`) to correlate system-volume extents with partition metadata. The helper returns the boolean used by the GPT boot-partition check.

This native DLL—not the managed UI and not a proved Randgrid call site—is where the concrete TPM, Secure Boot, firmware-mode, AIK, service, TCG-log, EFI-measurement, and boot-partition readiness logic resides.

---

## 6. `telescope24.dll` / `telescope25.dll`: runtime identified

Both versions export exactly `6,984` named symbols:

| Namespace | Count |
|---|---:|
| `WebCore` | 3,520 |
| `WTF` | 2,731 |
| `JSC` | 714 |
| JavaScriptCore C API | 1 |
| Other | 18 |

The non-runtime-facing exports include `CreateTelescopeInstance`, `GetChangelistNumberInterface`, and a set of allocator/memory-tag symbols for HTTP, ICU, JPEG, JSC, SQLite, FreeType, Fontconfig, HarfBuzz, Pixman, Cairo, XML, WTF, and surfaces.

Version comparison:

- Common names: `6,984 / 6,984`
- Common names with identical RVA: `6,984 / 6,984`
- Names unique to telescope24: `0`
- Names unique to telescope25: `0`
- File-size delta (`25 - 24`): `-8` bytes

This conclusively identifies the embedded runtime as WebCore/WTF/JavaScriptCore. It does **not** prove, from the export table, that telescope sends data to `ingest.datax.activision.com`; that endpoint is directly evidenced in the crash handler, not telescope. Telescope's product-specific behavior begins at `CreateTelescopeInstance`, and resolving that behavior would require a separate call-site/data-flow pass.

---

## 7. Broker pipe: static server and framing

The broker contains the literal pipe name `\\.\pipe\COD.Broker.v1`. LLVM disassembly independently confirms that a small wrapper at `0x14000C630` loads this exact string and jumps into the pipe-server function at `0x14000C3F0`.

### 7.1 Server setup

`FUN_14000C3F0`:

- Builds the SDDL descriptor `D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)`.
- Creates a duplex, message-type/message-read-mode pipe.
- Allows up to `255` instances.
- Uses `0x4000`-byte inbound and outbound buffers.
- Waits for connections and creates one worker thread per accepted handle.

The descriptor grants full access to Local System and built-in Administrators, and generic read/write to authenticated users. That is the static access policy in this build; the analysis did not attempt to exercise it.

### 7.2 Worker and frame validation

`FUN_14000C200` performs bounded synchronous reads and writes:

- Reads a fixed `0x14`-byte header.
- Requires magic `0x424B5045` and version `1`.
- Reads a 16-bit operation identifier from header offset `6`.
- Preserves the 32-bit request/correlation field at offset `8` in replies.
- Rejects payload lengths above `0x3FEC`, keeping header plus payload within the `0x4000` allocation.
- Uses a static operation-to-handler table.
- Writes a `0x14`-byte response header followed by a bounded payload.
- Flushes, disconnects, closes, and frees both buffers on termination.

The static evidence also links handlers to the Microsoft Platform Crypto Provider and `ActivisionAIK` NCrypt properties, including `PCP_TPM12_IDACTIVATION` and `PCP_TPM12_IDBINDING`. This supports the broker's role as an AIK/TPM service boundary.

No static imports/call sites were found for `ImpersonateNamedPipeClient`, `GetNamedPipeClientProcessId`, or `TransactNamedPipe` in this service. No claim is made here about runtime peer identity, live message contents, or traffic frequency.

---

## 8. Corrections to the earlier report

The following distinctions are now authoritative:

1. `ObRegisterCallbacks` is reached, but the callback semantics are unresolved. “Handle hiding” was an unsupported inference.
2. Direct `MmCopyMemory` references exist, but a physical-memory walker was not recovered. Memory-manager imports alone do not prove one.
3. The selected firmware import has no recovered caller, the previously named
   PE-parser/CI functions are not imported, and the actual CI pair is reached.
   Document 07 contains the corrected exact names and counts.
4. `MmGetSystemRoutineAddress` is imported, but there is no direct caller or plaintext target-name list. “Resolves many functions dynamically” was unsupported.
5. Telescope is conclusively a WebCore/WTF/JavaScriptCore runtime. A direct telescope-to-datax path was not established.
6. The concrete readiness/firmware/TPM logic is proved in extracted `SecureAttestation.dll` and its managed caller. It should not be attributed to Randgrid merely because Randgrid imports similarly named APIs.
7. `KeExpandKernelStackAndCalloutEx` expands kernel stack for a kernel callout; its import is not evidence of a user-mode callout. `KeSaveExtendedProcessorState` likewise does not prove thread-register snapshotting for anti-debug logic.

---

## 9. Evidence artifacts

The `analysis/...` paths in this table identify the complete local evidence set.
Bulk decompiler output, extracted assemblies, and Ghidra databases are deliberately
not committed to the public repository. The compact public Randgrid evidence is
under `../evidence/`.

| Artifact | Purpose |
|---|---|
| `analysis/randgrid-ghidra-evidence.md` | Randgrid entry, selected import xrefs, call graph, and decompilations |
| `analysis/randgrid-dynamic-name-candidates.json` | Complete import-vs-string comparison for dynamic routine-name candidates |
| `analysis/randgrid-deep-xrefs.json` | Independent complete IAT/stub/unwind call census |
| `analysis/randgrid-deep-xrefs.md` | Generated focused summary of the call census |
| `analysis/attestation-wizard-bundle/` | Extracted .NET single-file contents |
| `analysis/attestation-wizard-decompiled/` | ILSpy project for the managed wizard |
| `analysis/secure-attestation-native-evidence.md` | Native readiness export/helper decompilations and string xrefs |
| `analysis/telescope-export-analysis.json` | Every export, demangled symbol, namespace classification, fingerprints, and version comparison |
| `analysis/broker-pipe-static-evidence.md` | Pipe APIs, strings, call graph, and decompilations |
| `analysis/ghidra-project/` | Persisted Randgrid Ghidra project |
| `analysis/ghidra-native-project/` | Persisted SecureAttestation Ghidra project |
| `analysis/ghidra-broker-project/` | Persisted broker Ghidra project |

The raw evidence is intentionally preserved. The conclusions above distinguish direct call-site/decompiler evidence from capability-only imports and from unresolved protected code.

---

## Appendix A — Safe reproduction

```powershell
# From the public repository root; the proprietary input remains outside Git.
python -m pip install -r .\requirements.txt
python .\scripts\randgrid_deep_xrefs.py `
  --target 'X:\path\to\Randgrid.sys' `
  --json .\evidence\randgrid-deep-xrefs.json `
  --markdown .\evidence\randgrid-deep-xrefs.md
```

The full local analysis additionally used ILSpy and project-local Ghidra against
analysis copies. The read-only exporters are published in `../scripts/ghidra/`.
None of the published reproduction steps launches a game binary, loads a driver,
connects to the broker pipe, or changes service state.
