# Randgrid.sys — deep PE/IAT/unwind evidence

- SHA-256: `4150290a810ebebe9f9e6b5bd32c60299f9f34c3d2b6f02b89590ed49a6b895e`
- Size: `13130616` bytes
- Image base: `0x140000000`
- Entry RVA: `0xC61000`
- Import slots: `689`
- Exact direct IAT calls: `527` across `47` imports
- IAT jump stubs/candidates: `656` across `656` imports
- Exact calls through IAT jump stubs: `23` across `14` imports
- Imports reached by either exact call form: `61`
- Linear RIP-relative IAT references: `1106` across `686` imports

## Exception-directory runtime functions

- Count: `2191`
- Median span: `33` bytes
- 95th-percentile span: `7903` bytes
- Maximum span: `2862537` bytes
- Spans over 4 KiB / 64 KiB / 1 MiB: `148` / `2` / `1`

| Begin RVA | End RVA | Size | Unwind RVA |
|---:|---:|---:|---:|
| `0x1000` | `0x2BBDC9` | `0x2BADC9` | `0x72F5B4` |
| `0xA7A638` | `0xA8BA5C` | `0x11424` | `0xABD198` |
| `0xA8D670` | `0xA96DD3` | `0x9763` | `0xABD2F0` |
| `0xA5A9C0` | `0xA63B70` | `0x91B0` | `0xABD0DC` |
| `0xA21020` | `0xA294D4` | `0x84B4` | `0xABCD10` |
| `0xAA6E24` | `0xAAE401` | `0x75DD` | `0xABD374` |
| `0xA6AD60` | `0xA717D0` | `0x6A70` | `0xABD104` |
| `0xA63B70` | `0xA6A0F3` | `0x6583` | `0xABD0B8` |
| `0xA717D0` | `0xA777BA` | `0x5FEA` | `0xABD0F4` |
| `0xA3E038` | `0xA43ECC` | `0x5E94` | `0xABCF84` |
| `0xA4A294` | `0xA500CB` | `0x5E37` | `0xABD060` |
| `0xAA1534` | `0xAA6E22` | `0x58EE` | `0xABD3A0` |
| `0xA9BC84` | `0xAA1126` | `0x54A2` | `0xABD2A8` |
| `0xA34BD0` | `0xA39F8D` | `0x53BD` | `0xABCF3C` |
| `0xAAE678` | `0xAB2C18` | `0x45A0` | `0xABD218` |

## Focused import evidence

### `object_callbacks`

| Import | Present | Direct-IAT calls | Calls via stub | IAT stub | Other RIP refs |
|---|---:|---:|---:|---:|---:|
| `ObRegisterCallbacks` | yes | 1 | 0 | 1 | 0 |
| `ObUnRegisterCallbacks` | yes | 2 | 0 | 1 | 0 |

### `process_thread_image_callbacks`

| Import | Present | Direct-IAT calls | Calls via stub | IAT stub | Other RIP refs |
|---|---:|---:|---:|---:|---:|
| `PsSetCreateProcessNotifyRoutine` | yes | 0 | 0 | 1 | 0 |
| `PsSetCreateProcessNotifyRoutineEx` | yes | 3 | 0 | 0 | 0 |
| `PsSetCreateThreadNotifyRoutine` | yes | 1 | 0 | 1 | 0 |
| `PsRemoveCreateThreadNotifyRoutine` | yes | 2 | 0 | 0 | 0 |
| `PsSetLoadImageNotifyRoutine` | yes | 0 | 0 | 1 | 0 |

### `other_callback_surfaces`

| Import | Present | Direct-IAT calls | Calls via stub | IAT stub | Other RIP refs |
|---|---:|---:|---:|---:|---:|
| `KeRegisterBugCheckCallback` | yes | 0 | 0 | 1 | 0 |
| `KeDeregisterBugCheckCallback` | yes | 0 | 0 | 1 | 0 |
| `IoRegisterBootDriverCallback` | yes | 0 | 0 | 1 | 0 |
| `IoUnregisterBootDriverCallback` | yes | 0 | 0 | 1 | 0 |
| `PoRegisterPowerSettingCallback` | yes | 0 | 0 | 1 | 0 |
| `PoUnregisterPowerSettingCallback` | yes | 0 | 0 | 1 | 0 |
| `ExCreateCallback` | yes | 0 | 0 | 1 | 0 |
| `ExRegisterCallback` | yes | 0 | 0 | 1 | 0 |
| `ExUnregisterCallback` | yes | 0 | 0 | 1 | 0 |
| `ExNotifyCallback` | yes | 0 | 0 | 1 | 0 |

### `device_surface`

| Import | Present | Direct-IAT calls | Calls via stub | IAT stub | Other RIP refs |
|---|---:|---:|---:|---:|---:|
| `IoCreateDevice` | yes | 1 | 0 | 0 | 0 |
| `IoDeleteDevice` | yes | 2 | 0 | 1 | 0 |
| `IoCreateSymbolicLink` | yes | 1 | 0 | 1 | 0 |
| `IoCreateUnprotectedSymbolicLink` | yes | 0 | 0 | 1 | 0 |
| `IoDeleteSymbolicLink` | yes | 2 | 0 | 1 | 0 |
| `IoCreateFile` | yes | 0 | 0 | 1 | 0 |
| `IoCreateFileEx` | yes | 0 | 0 | 1 | 0 |

### `memory_surface`

| Import | Present | Direct-IAT calls | Calls via stub | IAT stub | Other RIP refs |
|---|---:|---:|---:|---:|---:|
| `MmCopyMemory` | yes | 18 | 0 | 0 | 0 |
| `MmGetPhysicalAddress` | yes | 0 | 0 | 1 | 0 |
| `MmMapIoSpace` | yes | 0 | 0 | 1 | 0 |
| `MmProbeAndLockPages` | yes | 0 | 0 | 1 | 0 |
| `MmProbeAndLockSelectedPages` | yes | 0 | 0 | 1 | 0 |
| `MmGetSystemRoutineAddress` | yes | 0 | 0 | 1 | 0 |

### `process_inspection_surface`

| Import | Present | Direct-IAT calls | Calls via stub | IAT stub | Other RIP refs |
|---|---:|---:|---:|---:|---:|
| `ZwOpenProcess` | yes | 1 | 0 | 1 | 0 |
| `ZwQueryVirtualMemory` | yes | 4 | 0 | 0 | 0 |
| `ZwQueryInformationThread` | yes | 1 | 0 | 0 | 0 |
| `ZwQuerySystemInformation` | yes | 15 | 0 | 0 | 0 |
| `ZwTerminateProcess` | yes | 2 | 0 | 1 | 0 |
| `ZwAlertThread` | yes | 6 | 0 | 0 | 0 |
| `PsGetProcessPeb` | yes | 4 | 0 | 0 | 0 |
| `PsGetCurrentProcessId` | yes | 2 | 0 | 1 | 0 |
| `SeLocateProcessImageName` | yes | 0 | 1 | 1 | 0 |
| `ObOpenObjectByPointer` | yes | 3 | 0 | 0 | 0 |
| `ObReferenceObjectByHandle` | yes | 3 | 0 | 1 | 0 |
| `ObReferenceObjectByName` | yes | 1 | 0 | 0 | 0 |

### `debugger_surface`

| Import | Present | Direct-IAT calls | Calls via stub | IAT stub | Other RIP refs |
|---|---:|---:|---:|---:|---:|
| `KdDisableDebugger` | yes | 0 | 0 | 1 | 0 |
| `KdEnableDebugger` | yes | 0 | 0 | 1 | 0 |
| `KdDebuggerNotPresent` | yes | 0 | 0 | 0 | 1 |

### `firmware_image_ci_surface`

| Import | Present | Direct-IAT calls | Calls via stub | IAT stub | Other RIP refs |
|---|---:|---:|---:|---:|---:|
| `ExGetFirmwareEnvironmentVariable` | yes | 0 | 0 | 1 | 0 |
| `RtlImageNtHeader` | no | 0 | 0 | 0 | 0 |
| `RtlImageDirectoryEntryToData` | no | 0 | 0 | 0 | 0 |
| `CiCheckSignatureMandatory` | no | 0 | 0 | 0 | 0 |
| `CiGetCertificateStoreOptions` | no | 0 | 0 | 0 | 0 |
| `CiFreePolicyInfo` | yes | 8 | 0 | 0 | 0 |
| `CiValidateFileObject` | yes | 4 | 0 | 0 | 0 |

### `cng_signature_surface`

| Import | Present | Direct-IAT calls | Calls via stub | IAT stub | Other RIP refs |
|---|---:|---:|---:|---:|---:|
| `BCryptOpenAlgorithmProvider` | yes | 0 | 2 | 1 | 0 |
| `BCryptGetProperty` | yes | 0 | 2 | 1 | 0 |
| `BCryptCloseAlgorithmProvider` | yes | 0 | 3 | 1 | 0 |
| `BCryptImportKeyPair` | yes | 0 | 1 | 1 | 0 |
| `BCryptDestroyKey` | yes | 0 | 1 | 1 | 0 |
| `BCryptVerifySignature` | yes | 0 | 1 | 1 | 0 |
| `BCryptCreateHash` | yes | 0 | 1 | 1 | 0 |
| `BCryptHashData` | yes | 0 | 1 | 1 | 0 |
| `BCryptFinishHash` | yes | 0 | 1 | 1 | 0 |
| `BCryptDestroyHash` | yes | 0 | 1 | 1 | 0 |

## Exact focused calls

IAT jump stubs are excluded: a stub's existence is not evidence that a higher-level caller reaches its import.

- `ObRegisterCallbacks`: `0x140AB309D` direct to IAT (`call qword ptr [rip + 0x7cd5]`), RVA 0xAB2C18–0xAB326F
- `ObUnRegisterCallbacks`: `0x140425246` direct to IAT (`call qword ptr [rip + 0x695b34]`), RVA 0x425243–0x425249
- `ObUnRegisterCallbacks`: `0x14052B023` direct to IAT (`call qword ptr [rip + 0x58fd57]`), RVA 0x52B020–0x52B026
- `PsSetCreateProcessNotifyRoutineEx`: `0x1402D7D25` direct to IAT (`call qword ptr [rip + 0x7e37a5]`), RVA 0x2D7D22–0x2D7D28
- `PsSetCreateProcessNotifyRoutineEx`: `0x1402FEA90` direct to IAT (`call qword ptr [rip + 0x7bca3a]`), RVA 0x2FEA8D–0x2FEA93
- `PsSetCreateProcessNotifyRoutineEx`: `0x140AA12F2` direct to IAT (`call qword ptr [rip + 0x1a1d8]`), RVA 0xAA1128–0xAA1327
- `PsSetCreateThreadNotifyRoutine`: `0x140AA130F` direct to IAT (`call qword ptr [rip + 0x19efb]`), RVA 0xAA1128–0xAA1327
- `PsRemoveCreateThreadNotifyRoutine`: `0x1403E12ED` direct to IAT (`call qword ptr [rip + 0x6da1e5]`), RVA 0x3E12EA–0x3E12F0
- `PsRemoveCreateThreadNotifyRoutine`: `0x1405C0CD7` direct to IAT (`call qword ptr [rip + 0x4fa7fb]`), RVA 0x5C0CD4–0x5C0CDA
- `IoCreateDevice`: `0x1402EE05F` direct to IAT (`call qword ptr [rip + 0x7cd463]`), RVA 0x2EE05C–0x2EE062
- `IoDeleteDevice`: `0x1403AEB84` direct to IAT (`call qword ptr [rip + 0x70bd8e]`), RVA 0x3AEB81–0x3AEB9E
- `IoDeleteDevice`: `0x1405D58DE` direct to IAT (`call qword ptr [rip + 0x4e5034]`), RVA 0x5D58DB–0x5D58E1
- `IoCreateSymbolicLink`: `0x1402E3DA8` direct to IAT (`call qword ptr [rip + 0x7d6b52]`), RVA 0x2E3DA5–0x2E3DAB
- `IoDeleteSymbolicLink`: `0x1402ECC09` direct to IAT (`call qword ptr [rip + 0x7cdd11]`), RVA 0x2ECC06–0x2ECC0C
- `IoDeleteSymbolicLink`: `0x14042D49E` direct to IAT (`call qword ptr [rip + 0x68d47c]`), RVA 0x42D49B–0x42D4A1
- `MmCopyMemory`: `0x1402D17CC` direct to IAT (`call qword ptr [rip + 0x7e9cce]`), RVA 0x2D17C9–0x2D17CF
- `MmCopyMemory`: `0x1402E0A2E` direct to IAT (`call qword ptr [rip + 0x7daa6c]`), RVA 0x2E0A2B–0x2E0A31
- `MmCopyMemory`: `0x1402E44C2` direct to IAT (`call qword ptr [rip + 0x7d6fd8]`), RVA 0x2E44BF–0x2E44C5
- `MmCopyMemory`: `0x1402E67BA` direct to IAT (`call qword ptr [rip + 0x7d4ce0]`), RVA 0x2E67B7–0x2E67BD
- `MmCopyMemory`: `0x1402E87D1` direct to IAT (`call qword ptr [rip + 0x7d2cc9]`), RVA 0x2E87CE–0x2E87D4
- `MmCopyMemory`: `0x140350EAC` direct to IAT (`call qword ptr [rip + 0x76a5ee]`), RVA 0x350EA9–0x350EAF
- `MmCopyMemory`: `0x1403529CE` direct to IAT (`call qword ptr [rip + 0x768acc]`), RVA 0x3529CB–0x3529D1
- `MmCopyMemory`: `0x1403A19F9` direct to IAT (`call qword ptr [rip + 0x719aa1]`), RVA 0x3A19F6–0x3A19FC
- `MmCopyMemory`: `0x1403B288F` direct to IAT (`call qword ptr [rip + 0x708c0b]`), RVA 0x3B288C–0x3B2892
- `MmCopyMemory`: `0x1403E36A5` direct to IAT (`call qword ptr [rip + 0x6d7df5]`), RVA 0x3E36A2–0x3E36A8
- `MmCopyMemory`: `0x1404041CF` direct to IAT (`call qword ptr [rip + 0x6b72cb]`), RVA 0x4041CC–0x4041D2
- `MmCopyMemory`: `0x140424154` direct to IAT (`call qword ptr [rip + 0x697346]`), RVA 0x424151–0x424157
- `MmCopyMemory`: `0x14046B5EC` direct to IAT (`call qword ptr [rip + 0x64feae]`), RVA 0x46B5E9–0x46B5EF
- `MmCopyMemory`: `0x14046BA02` direct to IAT (`call qword ptr [rip + 0x64fa98]`), RVA 0x46B9FF–0x46BA05
- `MmCopyMemory`: `0x140470BF6` direct to IAT (`call qword ptr [rip + 0x64a8a4]`), RVA 0x470BF3–0x470BF9
- `MmCopyMemory`: `0x140471532` direct to IAT (`call qword ptr [rip + 0x649f68]`), RVA 0x47152F–0x471535
- `MmCopyMemory`: `0x14050E112` direct to IAT (`call qword ptr [rip + 0x5ad388]`), RVA 0x50E10F–0x50E115
- `MmCopyMemory`: `0x140A8C7BF` direct to IAT (`call qword ptr [rip + 0x2ecdb]`), RVA 0xA8C754–0xA8C7DF
- `ZwOpenProcess`: `0x1402CCBC3` direct to IAT (`call qword ptr [rip + 0x7ee817]`), RVA 0x2CCBA4–0x2CCBC6
- `ZwQueryVirtualMemory`: `0x140A8C826` direct to IAT (`call qword ptr [rip + 0x2ecb4]`), RVA 0xA8C7E0–0xA8D606
- `ZwQueryVirtualMemory`: `0x140A9A7B5` direct to IAT (`call qword ptr [rip + 0x20d25]`), RVA 0xA9A680–0xA9BC81
- `ZwQueryVirtualMemory`: `0x140A9AF56` direct to IAT (`call qword ptr [rip + 0x20584]`), RVA 0xA9A680–0xA9BC81
- `ZwQueryVirtualMemory`: `0x140A9B5CD` direct to IAT (`call qword ptr [rip + 0x1ff0d]`), RVA 0xA9A680–0xA9BC81
- `ZwQueryInformationThread`: `0x140A2AD20` direct to IAT (`call qword ptr [rip + 0x9072a]`), RVA 0xA2AC70–0xA2B436
- `ZwQuerySystemInformation`: `0x1402DCB28` direct to IAT (`call qword ptr [rip + 0x7de92a]`), RVA 0x2DCB25–0x2DCB2B
- `ZwQuerySystemInformation`: `0x1402FDFDF` direct to IAT (`call qword ptr [rip + 0x7bd473]`), RVA 0x2FDFDC–0x2FDFE2
- `ZwQuerySystemInformation`: `0x140319749` direct to IAT (`call qword ptr [rip + 0x7a1d09]`), RVA 0x31972E–0x31974C
- `ZwQuerySystemInformation`: `0x14038FE3F` direct to IAT (`call qword ptr [rip + 0x72b613]`), RVA 0x38FE3C–0x38FE42
- `ZwQuerySystemInformation`: `0x14039559E` direct to IAT (`call qword ptr [rip + 0x725eb4]`), RVA 0x39559B–0x3955A1
- `ZwQuerySystemInformation`: `0x1403DB940` direct to IAT (`call qword ptr [rip + 0x6dfb12]`), RVA 0x3DB925–0x3DB943
- `ZwQuerySystemInformation`: `0x140A2516B` direct to IAT (`call qword ptr [rip + 0x962e7]`), RVA 0xA21020–0xA294D4
- `ZwQuerySystemInformation`: `0x140A29F82` direct to IAT (`call qword ptr [rip + 0x914d0]`), RVA 0xA294E0–0xA2AC65
- `ZwQuerySystemInformation`: `0x140A29FC6` direct to IAT (`call qword ptr [rip + 0x9148c]`), RVA 0xA294E0–0xA2AC65
- `ZwQuerySystemInformation`: `0x140A29FE5` direct to IAT (`call qword ptr [rip + 0x9146d]`), RVA 0xA294E0–0xA2AC65
- `ZwQuerySystemInformation`: `0x140A2A026` direct to IAT (`call qword ptr [rip + 0x9142c]`), RVA 0xA294E0–0xA2AC65
- `ZwQuerySystemInformation`: `0x140A2AD44` direct to IAT (`call qword ptr [rip + 0x9070e]`), RVA 0xA2AC70–0xA2B436
- `ZwQuerySystemInformation`: `0x140A2AD7E` direct to IAT (`call qword ptr [rip + 0x906d4]`), RVA 0xA2AC70–0xA2B436
- `ZwQuerySystemInformation`: `0x140A2B4AD` direct to IAT (`call qword ptr [rip + 0x8ffa5]`), RVA 0xA2B484–0xA2C207
- `ZwQuerySystemInformation`: `0x140A2B4EF` direct to IAT (`call qword ptr [rip + 0x8ff63]`), RVA 0xA2B484–0xA2C207
- `ZwTerminateProcess`: `0x140350A8B` direct to IAT (`call qword ptr [rip + 0x76a947]`), RVA 0x350A88–0x350A8E
- `ZwTerminateProcess`: `0x14062B639` direct to IAT (`call qword ptr [rip + 0x48fd99]`), RVA 0x62B636–0x62B63C
- `ZwAlertThread`: `0x1402E5010` direct to IAT (`call qword ptr [rip + 0x7d64e2]`), RVA 0x2E500D–0x2E5013
- `ZwAlertThread`: `0x1402E6362` direct to IAT (`call qword ptr [rip + 0x7d5190]`), RVA 0x2E635F–0x2E6365
- `ZwAlertThread`: `0x1402F45F8` direct to IAT (`call qword ptr [rip + 0x7c6efa]`), RVA 0x2F45F5–0x2F45FB
- `ZwAlertThread`: `0x1402FEF53` direct to IAT (`call qword ptr [rip + 0x7bc59f]`), RVA 0x2FEF50–0x2FEF56
- `ZwAlertThread`: `0x1403CCD12` direct to IAT (`call qword ptr [rip + 0x6ee7e0]`), RVA 0x3CCD0F–0x3CCD15
- `ZwAlertThread`: `0x1405AAD91` direct to IAT (`call qword ptr [rip + 0x510761]`), RVA 0x5AAD8E–0x5AAD94
- `PsGetProcessPeb`: `0x1402EE532` direct to IAT (`call qword ptr [rip + 0x7ccfb8]`), RVA 0x2EE513–0x2EE535
- `PsGetProcessPeb`: `0x14038FE1E` direct to IAT (`call qword ptr [rip + 0x72b6cc]`), RVA 0x38FE1B–0x38FE21
- `PsGetProcessPeb`: `0x140A8DE59` direct to IAT (`call qword ptr [rip + 0x2d691]`), RVA 0xA8D670–0xA96DD3
- `PsGetProcessPeb`: `0x140A94362` direct to IAT (`call qword ptr [rip + 0x27188]`), RVA 0xA8D670–0xA96DD3
- `PsGetCurrentProcessId`: `0x140A8DE67` direct to IAT (`call qword ptr [rip + 0x2d3b3]`), RVA 0xA8D670–0xA96DD3
- `PsGetCurrentProcessId`: `0x140A94370` direct to IAT (`call qword ptr [rip + 0x26eaa]`), RVA 0xA8D670–0xA96DD3
- `SeLocateProcessImageName`: `0x140A21624` calls stub `0x140AB8AFA` (`call 0x140ab8afa`), RVA 0xA21020–0xA294D4
- `ObOpenObjectByPointer`: `0x1402C4089` direct to IAT (`call qword ptr [rip + 0x7f73b9]`), RVA 0x2C4086–0x2C408C
- `ObOpenObjectByPointer`: `0x1402E6732` direct to IAT (`call qword ptr [rip + 0x7d4d10]`), RVA 0x2E672F–0x2E6735
- `ObOpenObjectByPointer`: `0x140A2ACF5` direct to IAT (`call qword ptr [rip + 0x9074d]`), RVA 0xA2AC70–0xA2B436
- `ObReferenceObjectByHandle`: `0x140A25578` direct to IAT (`call qword ptr [rip + 0x957aa]`), RVA 0xA21020–0xA294D4
- `ObReferenceObjectByHandle`: `0x140A26778` direct to IAT (`call qword ptr [rip + 0x945aa]`), RVA 0xA21020–0xA294D4
- `ObReferenceObjectByHandle`: `0x140A26994` direct to IAT (`call qword ptr [rip + 0x9438e]`), RVA 0xA21020–0xA294D4
- `ObReferenceObjectByName`: `0x1402BD8D9` direct to IAT (`call qword ptr [rip + 0x7fdbd1]`), RVA 0x2BD8D6–0x2BD8DC
- `CiFreePolicyInfo`: `0x140A268C6` direct to IAT (`call qword ptr [rip + 0x93784]`), RVA 0xA21020–0xA294D4
- `CiFreePolicyInfo`: `0x140A268D3` direct to IAT (`call qword ptr [rip + 0x93777]`), RVA 0xA21020–0xA294D4
- `CiFreePolicyInfo`: `0x140A26AE4` direct to IAT (`call qword ptr [rip + 0x93566]`), RVA 0xA21020–0xA294D4
- `CiFreePolicyInfo`: `0x140A26AF1` direct to IAT (`call qword ptr [rip + 0x93559]`), RVA 0xA21020–0xA294D4
- `CiFreePolicyInfo`: `0x140A26CD0` direct to IAT (`call qword ptr [rip + 0x9337a]`), RVA 0xA21020–0xA294D4
- `CiFreePolicyInfo`: `0x140A26CDD` direct to IAT (`call qword ptr [rip + 0x9336d]`), RVA 0xA21020–0xA294D4
- `CiFreePolicyInfo`: `0x140A2A97D` direct to IAT (`call qword ptr [rip + 0x8f6cd]`), RVA 0xA294E0–0xA2AC65
- `CiFreePolicyInfo`: `0x140A2A987` direct to IAT (`call qword ptr [rip + 0x8f6c3]`), RVA 0xA294E0–0xA2AC65
- `CiValidateFileObject`: `0x140A25634` direct to IAT (`call qword ptr [rip + 0x94a1e]`), RVA 0xA21020–0xA294D4
- `CiValidateFileObject`: `0x140A2682C` direct to IAT (`call qword ptr [rip + 0x93826]`), RVA 0xA21020–0xA294D4
- `CiValidateFileObject`: `0x140A26A4A` direct to IAT (`call qword ptr [rip + 0x93608]`), RVA 0xA21020–0xA294D4
- `CiValidateFileObject`: `0x140A2A805` direct to IAT (`call qword ptr [rip + 0x8f84d]`), RVA 0xA294E0–0xA2AC65
- `BCryptOpenAlgorithmProvider`: `0x14046EAF5` calls stub `0x140AB8CED` (`call 0x140ab8ced`), RVA 0x46EAF2–0x46EAF7
- `BCryptOpenAlgorithmProvider`: `0x1405050E6` calls stub `0x140AB8CED` (`call 0x140ab8ced`), RVA 0x5050E3–0x5050E8
- `BCryptGetProperty`: `0x1403F4962` calls stub `0x140AB8CF3` (`call 0x140ab8cf3`), RVA 0x3F495F–0x3F4964
- `BCryptGetProperty`: `0x140595D1A` calls stub `0x140AB8CF3` (`call 0x140ab8cf3`), RVA 0x595D17–0x595D1C
- `BCryptCloseAlgorithmProvider`: `0x1403F588D` calls stub `0x140AB8CF9` (`call 0x140ab8cf9`), RVA 0x3F588A–0x3F588F
- `BCryptCloseAlgorithmProvider`: `0x14051A828` calls stub `0x140AB8CF9` (`call 0x140ab8cf9`), RVA 0x51A825–0x51A82A
- `BCryptCloseAlgorithmProvider`: `0x14059B104` calls stub `0x140AB8CF9` (`call 0x140ab8cf9`), RVA 0x59B101–0x59B106
- `BCryptImportKeyPair`: `0x1402ED23D` calls stub `0x140AB8CFF` (`call 0x140ab8cff`), RVA 0x2ED23A–0x2ED23F
- `BCryptDestroyKey`: `0x14039B782` calls stub `0x140AB8D05` (`call 0x140ab8d05`), RVA 0x39B77F–0x39B784
- `BCryptVerifySignature`: `0x1402BF940` calls stub `0x140AB8D0B` (`call 0x140ab8d0b`), RVA 0x2BF93D–0x2BF942
- `BCryptCreateHash`: `0x140428E51` calls stub `0x140AB8D11` (`call 0x140ab8d11`), RVA 0x428E4E–0x428E53
- `BCryptHashData`: `0x1402C2519` calls stub `0x140AB8D17` (`call 0x140ab8d17`), RVA 0x2C2516–0x2C251B
- `BCryptFinishHash`: `0x1404375D7` calls stub `0x140AB8D1D` (`call 0x140ab8d1d`), RVA 0x4375D4–0x4375D9
- `BCryptDestroyHash`: `0x140428C7E` calls stub `0x140AB8D23` (`call 0x140ab8d23`), RVA 0x428C7B–0x428C80

## Located Randgrid strings and static xrefs

- `ECDSA_P256` (utf16le) at RVA `0xAB9270` in `.text`
- `ECCPUBLICBLOB` (utf16le) at RVA `0xAB9290` in `.text`
- `SHA256` (utf16le) at RVA `0xAB92B0` in `.text`
- `HashDigestLength` (utf16le) at RVA `0xAB92E0` in `.text`
- `\DosDevices\Randgrid` (utf16le) at RVA `0xAB9310` in `.text`
- `\Device\Randgrid` (utf16le) at RVA `0xAB9340` in `.text`
- `Randgrid.pdb` (ascii) at RVA `0xABCB18` in `.rdata`
- `Randgrid Driver` (utf16le) at RVA `0xC67110` in `.rsrc`
- `Randgrid Driver` (utf16le) at RVA `0xC67200` in `.rsrc`
- `Randgrid Driver` (utf16le) at RVA `0xC67320` in `.rsrc`

No section-wide linear RIP-relative code reference to these exact string starts was recovered.

## Non-import kernel-routine plaintext names

- Candidate count: `0`

Non-import plaintext names are only candidates for dynamic lookup. A call-site/string data-flow xref is still required to prove use.

## Interpretation boundary

An imported or referenced API proves a static dependency/call site, not callback semantics, target policy, or runtime success.
An IAT jump stub is normal linkage machinery and is not treated as proof that a higher-level caller reaches that API.
The JSON companion preserves every decoded transfer and linear reference for independent review.
