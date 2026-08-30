# Linux Passive Systems Port

**Status:** phase 1 implemented; normalized with the native Windows backend in
portable package 0.2.0

**Port boundary:** portable passive observation and evidence, not the
proprietary RICOCHET driver or a bypass

## 1. What has actually been ported

The original repository had three distinct Windows-specific surfaces:

1. static PE and `Randgrid.sys` analysis;
2. passive Windows runtime evidence using ETW, system-handle snapshots, service
   state, device namespace, and named pipes;
3. separately authorized active research tiers in `scripts/live_capture.py`.

Only the first surface was naturally runnable on Linux before this work. The
new `anticheat_system` package adds a real Linux implementation for the second
category: passive process and host observation. It does not translate Windows
driver APIs into Linux calls, emulate the broker protocol, load a kernel
module, inspect process memory, or execute the active research tiers.

This distinction matters because there is no factual one-to-one port for a
Windows kernel driver, an ETW provider, an object-manager handle callback, or a
named Windows device. Linux has different authority surfaces: procfs, pidfds,
namespaces, cgroups, Linux Security Modules, audit/perf/eBPF facilities, and
ELF/module-signing policy.

## 2. Phase-1 architecture

```text
selector (--pid / unique --name / --self)
                  |
                  v
      LinuxProcfsBackend.resolve_pid
                  |
                  v
  pidfd (when available) + open /proc/<pid> directory
                  |
       +----------+-----------+-------------+
       |                      |             |
       v                      v             v
 status/stat/maps       fd/ns/cgroup   executable FD
       |                      |             |
       +----------+-----------+-------------+
                  |
       re-read start time + poll pidfd
                  |
                  v
 privacy reduction -> caveated signals -> JSON snapshot
                  |
            optional SHA-256 chain
```

The target process directory is opened before collection. All per-process
metadata is then addressed relative to that directory descriptor. The Linux
kernel documentation notes that an open procfs descriptor does not silently
retarget a newly reused PID after the original process exits. When available,
`pidfd_open()` adds a pollable liveness anchor. The collector also compares the
`/proc/PID/stat` start-time field before and after the snapshot. Any exit or
identity change fails the whole snapshot rather than publishing a mixture from
different processes.

Some vendor-built Python runtimes omit `os.pidfd_open` even on a capable kernel.
For x86-64, AArch64, and RISC-V 64-bit Linux, the backend has a narrow
`pidfd_open` syscall fallback; unsupported architectures degrade explicitly to
the proc-directory/start-time contract instead of pretending a pidfd exists.

References:

- [Linux kernel procfs documentation](https://docs.kernel.org/filesystems/proc.html)
- [`pidfd_open(2)`](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
- [`proc_pid_status(5)`](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)

## 3. Collected evidence and failure semantics

### 3.1 Process status

`/proc/PID/status` supplies state, thread count, tracer presence, memory totals,
`no_new_privs`, seccomp mode/filter count, core-dump state, capability masks,
and PID-namespace depth. Aggregate mode removes parent PID and UID/GID values.

The collector records only `tracer_present`; it never publishes the tracer PID.
It does not read the target command line or environment.

### 3.2 Executable identity

The already-open `/proc/PID/exe` reference is SHA-256 hashed through a read-only
descriptor with a 1 GiB upper bound. The hash and size are retained. Aggregate
mode retains only the executable basename and never its full path.

An inaccessible or oversized executable is `unavailable` with a stable reason;
it is not represented by an empty hash or a zero size.

### 3.3 Memory maps

`/proc/PID/maps` is consumed in one bounded read of at most 32 MiB. The parser
uses addresses only to compute aggregate virtual bytes and discards them before
serialization. It publishes mapping counts, permissions, broad backing
categories, unique file identities, and counts of:

- writable-and-executable mappings;
- deleted mappings;
- deleted executable mappings;
- malformed rows.

The kernel documents that maps are inherently racy and gives the strongest
consistency guarantee to a single read. This collector reports that boundary;
it does not claim an atomic whole-process memory snapshot.

### 3.4 Descriptors, namespaces, and cgroups

Descriptor symlink targets are reduced immediately to categories such as
socket, pipe, anonymous inode, memory file, deleted file, or filesystem. Raw
targets are never serialized.

Namespace symlinks are compared with the observer and reduced to booleans. Raw
namespace inode identifiers are never serialized. Cgroup paths are reduced to
version, controller names, membership counts, and root/non-root counts.

### 3.5 Host hardening

The host posture includes:

- the active LSM list from `/sys/kernel/security/lsm` when securityfs exposes it;
- Yama `ptrace_scope`;
- kernel lockdown mode;
- module-signature enforcement;
- `unprivileged_bpf_disabled`, `perf_event_paranoid`, `kptr_restrict`,
  `dmesg_restrict`, `modules_disabled`, `randomize_va_space`, and kernel taint.

Absent files remain `unavailable`, which is common in containers and kernels
without a mounted securityfs. LSM availability and Yama behavior are defined by
the kernel, not inferred from a distribution name:

- [Linux Security Module usage](https://docs.kernel.org/admin-guide/LSM/index.html)
- [Yama ptrace policy](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [Kernel module-signing facility](https://docs.kernel.org/admin-guide/module-signing.html)

## 4. Privacy modes

`aggregate` is the default and is intended to be structurally safe for review.
It excludes:

- hostname and user identity;
- PID and parent PID;
- UID/GID values;
- command line and environment;
- executable path;
- raw map addresses and paths;
- raw descriptor targets;
- raw namespace identifiers;
- raw cgroup paths.

`local` additionally includes the PID, parent PID, process start time, UID/GID
sets, executable path, and executable mapped-file basenames. Both modes default
to the Git-ignored `local-analysis/` directory. Neither mode reads process
memory.

## 5. Signals are not verdicts

The rules layer currently emits conservative observations for:

- an attached tracer;
- writable-and-executable mappings;
- executable mappings backed by deleted files;
- a deleted main executable;
- namespace differences;
- nonzero effective Linux capabilities.

Every signal carries a benign-alternative caveat. Debuggers, JIT runtimes,
crash handlers, package upgrades, containers, and service capabilities can all
produce these conditions. The summary therefore hard-codes
`verdict: observation_only`.

## 6. Bounded monitoring and chain semantics

`monitor` requires a positive sample count. Each JSON Lines record contains its
sequence number, previous-record hash, payload, and SHA-256 over canonical JSON.
The file is flushed and `fsync`ed after every sample. Each record also commits
to the planned sample count, interval, and its sample sequence, so
`verify-chain` rejects truncated runs instead of validating a well-formed but
incomplete prefix.

This detects modification or reordering when a trusted terminal hash is stored
separately. It is **not a digital signature** and is not an authenticity claim
if an attacker can rewrite both the file and the reported terminal hash.

## 7. Current parity and non-parity

| Capability | Windows authority/equivalent | Linux phase 1 |
|---|---|---|
| Static proprietary binary analysis | PE/driver analyzer | Existing analyzer runs cross-platform; no ELF target supplied |
| Stable process identity | portable process-object handle + creation time | proc directory FD + start time + optional pidfd |
| Process security metadata | portable token/PPL/mitigation/architecture query | tracer, seccomp, capabilities, namespaces, cgroups |
| Loaded code metadata | portable Tool Help + `VirtualQueryEx` aggregates | privacy-reduced `/proc/PID/maps` aggregates |
| Open object metadata | portable handle count; detailed historical system-handle snapshots | privacy-reduced `/proc/PID/fd` categories |
| Host security policy | portable Code Integrity/HVCI/Secure Boot/DEP; historical service/device state | LSM/Yama/lockdown/module/BPF/perf/sysctl posture |
| Kernel event correlation | historical ETW audit + OB stream | Not implemented |
| Active memory/device research | Explicit opt-in retained Windows tiers | Intentionally not ported |

Phase 1 is therefore a substantive Linux systems port, but not feature parity
with the elevated Windows ETW correlation work.

The backend-neutral schema and certified OS/Python/architecture matrix are in
[`10-portable-compatibility.md`](10-portable-compatibility.md).

## 8. Validation gates

The repository now runs the full test suite on both `ubuntu-latest` and
`windows-latest`. Linux additionally performs a live self-snapshot, a two-sample
bounded monitor, chain verification, and assertions for read-only mode,
start-time consistency, observed maps, and aggregate PID omission.

Local validation should include:

```bash
python -m compileall -q src scripts tests
python -m unittest discover -s tests -p 'test_*.py' -v
python -m anticheat_system snapshot --self \
  --out local-analysis/linux-system-snapshot.json
```

## 9. Next systems stages

The remaining port should proceed through explicit trust boundaries:

1. **Signed identity policy:** define a versioned allowlist/measurement format
   for expected ELF executables and libraries, with detached signatures and
   rollback-safe key rotation.
2. **Privilege-separated collector:** keep target selection and JSON handling
   unprivileged; isolate any future elevated event source behind a narrow,
   authenticated local IPC schema.
3. **Linux event correlation:** evaluate Linux audit, fanotify, and CO-RE eBPF
   against a fixed kernel-support matrix. Any implementation must be passive,
   bounded, capability-minimal, drop-accounted, and independently unloadable.
4. **Wine/Proton topology:** model launcher, wineserver, game, crash-handler, and
   container namespace relationships without treating parentage as proof of
   function.
5. **Evidence certification:** add schema fixtures, deterministic redaction,
   event-loss accounting, append-chain terminal-hash anchoring, and fresh-host
   reproducibility checks.

An out-of-tree enforcement kernel module is deliberately not the next step. It
would expand crash, signing, compatibility, and privilege risk before the
userspace observation contract is mature. Kernel-level work should begin only
after the event source, privilege model, supported kernels, and rollback path
are specified and tested.
