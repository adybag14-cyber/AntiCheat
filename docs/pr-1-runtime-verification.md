# PR #1 Post-Rebase Runtime Verification

**Pull request:** [#1 — Add live capture: Randgrid driver, device, broker pipe,
game memory](https://github.com/adybag14-cyber/AntiCheat/pull/1)

**Original PR head:** `076583a567999b452b40b5430000de79d56bfac6`

**Rebase base:** current `main` at
`eb5464729a57483d5edfb9cefebe100e08156385`

**Verification date:** 2026-08-28 UTC

**Final scope decision:** correct public-evidence privacy, factual claims,
LF-stable manifest hashes, and current-main integration; retain tier-2 and tier-3
as explicitly active blue-team research code

---

## 1. Verified result

The non-admin and UAC-elevated verification produced this final claim matrix:

| Claim | Non-admin result | Elevated result | Final status |
|---|---|---|---|
| Three Randgrid services; Steam service running | Confirmed | Confirmed | Observed |
| `Randgrid -> \Device\Randgrid` | Confirmed | Confirmed | Observed |
| Device open denied | Error 5 | Error 5 | Observed in both contexts |
| Device denial caused by `ObRegisterCallbacks` | Not established | Not established | Causal mechanism unresolved |
| Broker pipe read-open + peek | Succeeded | Succeeded | Observed; zero bytes consumed |
| Game process open request | `0x410` | `0x410` | Observed |
| Stored granted access | `0x1000` | `0x1000` | Handle-specific reduction observed |
| Game token elevated | False | False | Disproved |
| Game PPL | `PROTECTION_LEVEL_NONE` | Same property | Disproved |
| Module snapshot | Error 5 | Error 5 | Denied; no valid module count |
| Region metadata | 14,632 regions | 14,644 regions | Enumerable in both contexts |
| Crash-handler direct child | One observed | Same | Parent relationship observed |

The access result is direct rather than inferred:

```text
requested: 0x00000410
           PROCESS_QUERY_INFORMATION | PROCESS_VM_READ

granted:   0x00001000
           PROCESS_QUERY_LIMITED_INFORMATION
```

The verifier located its exact returned handle in
`SystemExtendedHandleInformation` before closing it. Elevation did not restore
the removed rights. The mask transformation is observed; attribution to one
particular callback remains a separate causality claim.

---

## 2. Corrected factual boundaries

### 2.1 Device access

The device namespace and denial are observed, but the original callback
attribution was too strong.

Microsoft documents `ObRegisterCallbacks` for process, thread, and desktop
handle operations, not device-object opens:

- [`ObRegisterCallbacks`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [`OB_OPERATION_REGISTRATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_operation_registration)

The public evidence now records the device-specific mechanism as unresolved.
Possible explanations include the device DACL or the driver's create/open
dispatch path.

### 2.2 Game identity

The game is neither elevated nor PPL. Access reduction must not be explained as
an integrity-level or PPL boundary.

### 2.3 Module result

The module snapshot API returned `Access denied`. The earlier `module_count: 0`
was not a valid empty enumeration and is no longer published.

### 2.4 Region result

`VirtualQueryEx` metadata enumeration succeeded in both contexts. The earlier
zero-region/opaque-map claim is removed. Region counts are explicitly labelled
as a live sample that can change while the process runs.

### 2.5 Crash-handler result

The parent relationship is observed. The stronger word “attached” is not used
as proof of complete functional behavior.

---

## 3. Public evidence privacy

`evidence/live-capture.json` is now privacy-reduced schema v2. It does not
publish:

- host or user names;
- PIDs or parent PIDs;
- raw handle values or kernel pointers;
- command lines or launch tokens;
- local installation, temporary, or crash paths;
- memory addresses or process bytes.

It publishes only:

- stable component names;
- service state and store mapping;
- privilege context;
- requested and granted access masks;
- error codes and aggregate counts;
- zero-valued safety counters for the recorded/verification runs;
- explicit claim and causal boundaries.

Raw future captures default to Git-ignored
`local-analysis/live-capture.json`. The public aggregate must be derived and
reviewed separately.

---

## 4. Research-tier boundary

By team decision, the active blue-team research tiers remain in
`scripts/live_capture.py`:

- tier 1 can exercise undocumented IOCTL research when device access succeeds;
- tier 2 contains process-memory trap experiments;
- tier 3 contains remote allocation and thread/injection experiments.

The factual correction is not to describe those tiers as read-only or generally
safe. Their presence in the source does not prove that they executed in the
published capture.

The privacy-reduced evidence records the original run's actual execution
boundary:

```text
device opened:                 false
IOCTL calls reached:           0
candidate write regions:       0
process-memory writes reached: 0
injection executed:            false
```

The research tiers require separate authorization and an appropriate disposable
test session. They are not reproduction requirements for the public evidence.

---

## 5. Reproducibility repair

The former manifest hashes for `evidence/live-capture.json` and
`scripts/live_capture.py` were calculated from CRLF working-tree bytes even
though `.gitattributes` requires LF. Fresh clones and Linux CI therefore failed.

The repaired branch:

- stores public text with LF newlines;
- hashes the Git-normalized bytes;
- includes a privacy/factual evidence contract;
- runs the complete current test suite inherited from `main`;
- verifies Markdown links/fences and JSON parsing;
- will be fresh-clone tested before merge.

---

## 6. Rebase and history boundary

The PR is rebased onto current `main`, retaining its source contribution while
reconciling the newer runtime report, evidence hierarchy, and tests.

Before force-pushing, the complete PR delta is consolidated into one clean
post-`main` commit. This matters for privacy: the original raw evidence must not
remain as an earlier reachable commit in the branch that is merged.

A local backup ref preserves the pre-rebase PR tip for the repository owner, but
that backup is not pushed or merged.

---

## 7. Final merge boundary

```text
Evidence privacy:                         repaired
CRLF/LF manifest drift:                  repaired
Incorrect elevation/PPL claims:          corrected
Incorrect zero-module characterization: corrected
Incorrect zero-region claim:             corrected
Device callback attribution:             corrected to unresolved
Exact 0x410 -> 0x1000 reduction:         published
Tier-2/tier-3 research source:           retained unchanged
Current-main integration:                rebased
Raw evidence in mergeable history:       removed by clean consolidation
```

This document is the final verification record for the narrowed repair scope.
