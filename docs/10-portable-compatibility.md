# Portable Compatibility Contract

**Package:** `anticheat-system-research` 0.2.0

**Schema:** portable passive snapshot v1

**Supported Python:** CPython 3.11, 3.12, 3.13, and 3.14

## 1. Meaning of full compatibility

“Full compatibility” in this repository means that every certified platform:

1. installs the same dependency-free portable wheel;
2. selects a native backend automatically;
3. supports `--pid`, unique `--name`, and `--self` selectors;
4. emits the same required top-level and target sections;
5. enforces the same aggregate/local privacy contract;
6. anchors process identity and rejects cross-process snapshots;
7. supports atomic snapshots, bounded monitoring, and complete-chain
   verification;
8. distinguishes unavailable/partial/not-applicable evidence from valid zeroes;
9. runs without enabling debug privilege, attaching a debugger, instrumenting
   the kernel, reading target bytes, or changing target/kernel state.

It does not mean that Linux and Windows expose identical kernel concepts. A
Linux namespace has no Windows equivalent; a Windows process protection level
has no procfs equivalent. Platform-specific evidence remains in normalized
sections with explicit status values.

It also does not claim compatibility with a proprietary RICOCHET kernel driver
on Linux. The portable package is a defensive observation and evidence system.

## 2. Certification matrix

The pull-request workflow certifies the following matrix from clean GitHub-hosted
virtual machines:

| Operating environment | Architecture | CPython | Portable live snapshot/monitor |
|---|---:|---:|---|
| Ubuntu 22.04 | x86-64 | 3.11 | Required |
| Ubuntu 24.04 | x86-64 | 3.12 | Required |
| Ubuntu 24.04 | x86-64 | 3.13 | Required |
| Ubuntu 24.04 | x86-64 | 3.14 | Required |
| Ubuntu 24.04 | ARM64 | 3.14 | Required |
| Windows Server 2022 | x86-64 | 3.11 | Required |
| Windows Server 2025 | x86-64 | 3.12 | Required |
| Windows Server 2025 | x86-64 | 3.13 | Required |
| Windows Server 2025 | x86-64 | 3.14 | Required |
| Windows Server 2022 | x86 process | 3.11 | Required |
| Windows 11 | ARM64 | 3.14 | Required |

GitHub documents these x64 and ARM64 runner labels and `setup-python` documents
the `x86`, `x64`, and `arm64` architecture selector:

- [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [`actions/setup-python` advanced usage](https://github.com/actions/setup-python/blob/main/docs/advanced-usage.md)

The full historical evidence/analyzer suite is additionally run on Ubuntu 24.04
x86-64 and Windows Server 2025 x86-64. The portable package has no Capstone or
PEfile runtime dependency; those packages remain requirements of the historical
PE analyzer only.

## 3. Backend-neutral v1 schema

Every snapshot contains:

```text
schema_version
capture
privacy
host_security
target
  identity
  status
  executable
  memory_maps
  modules
  file_descriptors
  namespaces
  cgroups
section_errors
signals
summary
```

`validate_snapshot_contract()` runs before either backend returns a snapshot.
It rejects:

- missing normalized sections;
- unknown section-status values;
- missing or non-boolean privacy flags;
- process IDs, creation/start identity, paths, or module basenames in aggregate
  mode;
- contradictory privacy flags;
- malformed signals;
- any verdict other than `observation_only`.

Strict JSON serialization with `allow_nan=False` is part of the matrix. A
backend cannot silently emit a Python-only value that another language cannot
consume as JSON.

## 4. Linux compatibility behavior

### Identity

The collector opens `/proc/PID`, reads the start-time identity before and after
collection, and uses a pidfd when the kernel supports it. Some vendor Python
builds omit `os.pidfd_open`; known x86-64, ARM64, and RISC-V 64-bit Linux
architectures use the stable kernel syscall fallback. If pidfds are unavailable,
the result states that fact and retains the proc-directory/start-time boundary.

### Optional kernel interfaces

The following are optional and must degrade to `unavailable`, not abort or
become zero:

- `pidfd_open` on pre-5.3 kernels;
- newer namespace links;
- `Seccomp_filters` and other version-dependent status fields;
- securityfs and `/sys/kernel/security/lsm`;
- lockdown and module-signature parameters;
- Yama and distribution-specific sysctls;
- maps, descriptors, executable links, and namespaces blocked by `hidepid`,
  ptrace access checks, containers, or LSM policy.

Procfs documents both per-process access checks and `hidepid` behavior. It also
documents that open proc descriptors do not retarget a reused PID:
[Linux procfs documentation](https://docs.kernel.org/filesystems/proc.html).

### Cgroups and containers

Cgroup v1 and unified v2 are both parsed. Paths and namespace inode values are
reduced before serialization. Different namespaces produce a caveated
observation, not a cheating decision.

## 5. Windows compatibility behavior

### Identity and access

The Windows backend opens a real process-object handle with
`PROCESS_QUERY_LIMITED_INFORMATION` and `SYNCHRONIZE` when permitted. Creation
time is checked before and after collection, and a second
`PROCESS_QUERY_INFORMATION` handle must report the same creation identity before
it is used for mitigation or virtual-region metadata.

Microsoft documents that `OpenProcess` access is checked against the process
security descriptor, and that query-limited handles are sufficient for image
name and process-time identity:

- [`OpenProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [`QueryFullProcessImageNameW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew)
- [`GetProcessTimes`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)

The backend never enables `SeDebugPrivilege`. Access-denied results are evidence
capability failures, not a reason to elevate automatically.

### 32-bit, 64-bit, and ARM64

The Tool Help and memory structures use pointer-sized fields and have ABI tests
for both 32-bit and 64-bit layouts. `IsWow64Process2` plus optional
`ProcessMachineTypeInfo` distinguishes native and emulated process
architectures where the running Windows version exposes those APIs. Missing
newer APIs degrade individually.

Microsoft documents `IsWow64Process2` as accepting query-limited handles and
returning both process and native machine types:
[`IsWow64Process2`](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2).

### Metadata surfaces

The backend uses only read-only/query APIs:

- Tool Help process/module snapshots;
- `VirtualQueryEx` region attributes, never target bytes;
- token query information without user SID publication;
- debugger-present query;
- process protection, architecture, handle count, and mitigation policies;
- dynamically resolved Code Integrity options;
- firmware/Secure Boot and system DEP state.

Tool Help module snapshots can be loader-racy or architecture-restricted. Their
section explicitly states `toolhelp-best-effort`; unexpected mid-enumeration
errors create `partial`, not a false complete count. Microsoft documents these
limitations in [`CreateToolhelp32Snapshot`](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot).

`VirtualQueryEx` is used only for page attributes under
`PROCESS_QUERY_INFORMATION`, as documented by Microsoft:
[`VirtualQueryEx`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex).

Code Integrity uses the documented `SYSTEM_CODEINTEGRITY_INFORMATION` layout and
is dynamically resolved so removal or change becomes `unavailable`. Microsoft
explicitly warns that `NtQuerySystemInformation` is version-sensitive:
[`NtQuerySystemInformation`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation).

## 6. Compatibility failure semantics

The stable section statuses are:

| Status | Meaning |
|---|---|
| `observed` | The requested interface completed and the reported value is valid. |
| `partial` | Some valid records were returned, followed by an explicit failure. |
| `unavailable` | The interface is missing, denied, size-limited, or the target exited. |
| `not_applicable` | The operating system does not have this normalized concept. |
| `not_requested` | The caller explicitly disabled an optional operation. |

Counts are authoritative only in `observed` sections or when a `partial` section
is explicitly interpreted as a lower bound. `unavailable` never means zero.

## 7. Deliberate exclusions

The certification claim excludes:

- macOS and non-Linux POSIX systems;
- PyPy, GraalPy, and free-threaded CPython builds;
- kernels without procfs mounted;
- kernel event enforcement or prevention;
- undocumented driver protocols and proprietary driver translation;
- automatic privilege elevation;
- process-memory reads/writes, ptrace/debug attachment, device IOCTLs,
  remote-thread creation, and injection;
- a guarantee that protected third-party processes expose every optional
  section.

An excluded platform fails explicitly as `unsupported_platform`; it is never
silently routed to the wrong backend.

## 8. Release gate

A compatibility change is releasable only when:

1. all architecture/OS/Python matrix jobs pass;
2. both full historical-suite jobs pass;
3. native snapshot and two-record monitor/verification smoke tests pass on every
   matrix runner;
4. Ruff, formatting, mypy, compileall, wheel construction, and strict JSON
   round-trip checks pass;
5. a fresh clone resolves to the published commit and repeats the native local
   gate;
6. the PR remains cleanly mergeable with no unresolved actionable review.
