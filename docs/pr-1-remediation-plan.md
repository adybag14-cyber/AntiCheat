# PR #1 Privacy, Facts, and Integration Remediation Record

**Companion verification:**
[`pr-1-runtime-verification.md`](pr-1-runtime-verification.md)

**Authorized scope:** evidence privacy, CRLF/LF manifest repair, factual claim
corrections, clean rebase, validation, and merge

**Explicit non-goal for this repair:** removal or redesign of tier-2/tier-3
blue-team research code

---

## 1. Scope decision

The original review proposed removing active research tiers. The repository
owner subsequently narrowed the merge repair:

1. preserve the tier-2 and tier-3 source for the research team;
2. stop representing those paths as read-only or as executed evidence;
3. remove sensitive raw evidence from the public branch history;
4. correct the disproved or unsupported narrative claims;
5. repair LF-normalized manifest hashes;
6. rebase onto current `main`, validate, and merge.

This record supersedes the broader removal proposal in the earlier PR comment.

---

## 2. Completed evidence-privacy repair

### 2.1 Public artifact replaced

The raw schema-v1 `evidence/live-capture.json` was replaced before the rebased
commit was finalized. The schema-v2 artifact contains no:

- host/user identity;
- PID or parent PID;
- raw handle or kernel pointer;
- command line or launch token;
- local installation, temporary, or crash path;
- memory address or process bytes.

### 2.2 Public fields are bounded

The new artifact contains only:

- stable service/process/pipe/device names;
- state and privilege context;
- requested/granted masks;
- error codes and aggregate counts;
- safety counters;
- claim boundaries.

### 2.3 Raw future output defaults to ignored storage

`scripts/live_capture.py` now defaults `--out` to:

```text
local-analysis/live-capture.json
```

The raw research structure remains available locally, but it no longer silently
overwrites a public evidence artifact.

### 2.4 Privacy contract added

`tests/test_live_capture_evidence.py` asserts:

- schema version and source timestamp;
- exact requested/granted masks;
- corrected module-error and region-success semantics;
- zero safety counters for the recorded verification;
- absence of sensitive keys, local drive paths, and kernel pointers;
- all privacy flags false;
- raw default output under `local-analysis/`;
- LF-only public text.

---

## 3. Completed factual corrections

| Previous statement | Corrected statement |
|---|---|
| Game is elevated/PPL | Token is not elevated; protection is `PROTECTION_LEVEL_NONE` |
| Modules enumerate to zero | Snapshot API fails with error 5; valid count is unknown/null |
| Region map is empty/opaque | Metadata enumeration succeeds in both contexts |
| Device denial proves `ObRegisterCallbacks` fired | Device denial is observed; device-specific mechanism is unresolved |
| Access stripping inferred from zero lists | Exact verifier handle requested `0x410` and stored `0x1000` |
| Crash handler is functionally attached | Direct parent relationship is observed; broader behavior is not proved |
| Tier 2 is safe/read-only | Tier 2 is active research code; it did not reach mutation in the recorded run |

The corrected statements are synchronized across:

- `README.md`;
- `docs/08-live-analysis.md`;
- `docs/08-randgrid-runtime-behavior.md`;
- `docs/pr-1-runtime-verification.md`;
- `evidence/README.md`;
- `evidence/live-capture.json`.

---

## 4. Research source intentionally retained

No removal or redesign was performed for:

- the conditional tier-1 IOCTL research path;
- tier-2 process-memory trap research;
- tier-3 remote allocation/thread/injection research.

The merge repair changes their documentation boundary:

- they are explicitly active, opt-in research operations;
- they require separate authorization and a suitable disposable session;
- their presence is not evidence of execution;
- they are not necessary to reproduce the public privacy-reduced findings.

The original recorded run did not reach the device IOCTL loop or a memory write
and did not select injection. Those zero-execution facts are published as safety
counters.

---

## 5. Completed line-ending and manifest repair

The previous manifest stored CRLF-derived SHA-256 values for files that Git
normalizes to LF. The repaired process is:

1. ensure public JSON, Markdown, Python, and tests contain LF only;
2. calculate SHA-256 from the actual working bytes after LF normalization;
3. update `evidence/manifest.json` with those values;
4. run the manifest contract locally;
5. verify it again in a fresh clone and Linux GitHub Actions.

The manifest now includes the privacy-reduced live artifact, corrected live
report, raw-capture source, discovery helper, and live evidence contract in
addition to current-main runtime artifacts.

---

## 6. Clean-rebase procedure

The branch repair follows these steps:

1. preserve the pre-rebase PR tip in a local-only backup ref;
2. fetch and verify the exact remote PR and `main` heads;
3. rebase the PR commits onto current `main`;
4. resolve `README.md` and `evidence/manifest.json` manually;
5. replace raw evidence and correct facts before completing the rewritten
   capture commit;
6. update these review documents to the narrowed owner-approved scope;
7. consolidate the complete PR delta into one clean commit based on `main`;
8. force-push only with `--force-with-lease` against the previously verified PR
   head;
9. wait for green CI;
10. merge and verify remote `main` from a fresh clone.

The clean consolidation prevents the original raw public artifact from being an
earlier reachable commit in the merged branch.

---

## 7. Acceptance checklist

### Privacy

- [x] Raw schema-v1 artifact removed from the rebased commit.
- [x] Public schema-v2 artifact contains no identity, PID, handle, pointer,
  command line, launch token, local path, address, or process bytes.
- [x] Future raw output defaults to ignored `local-analysis/`.
- [x] Privacy regression tests added.

### Facts

- [x] Exact requested/granted masks published.
- [x] Elevation and PPL claims corrected.
- [x] Module API failure distinguished from a zero count.
- [x] Region metadata result corrected.
- [x] Device callback attribution narrowed to unresolved.
- [x] Parent relationship separated from functional attachment.
- [x] Research-tier presence separated from execution evidence.

### Reproducibility

- [x] Public text uses LF.
- [x] Manifest hashes regenerated from LF bytes.
- [x] Local full test suite passes.
- [ ] Fresh-clone full test suite passes after final consolidation.
- [ ] GitHub Actions passes after force-push.

### Integration

- [x] PR commits rebased onto current `main` locally.
- [ ] Complete PR delta consolidated into one clean commit.
- [ ] Force-push completed with lease protection.
- [ ] PR reports mergeable.
- [ ] PR merged.
- [ ] Remote `main` and fresh clone verified.

---

## 8. Post-merge research boundary

The merge does not certify active tiers as safe or production-ready. It certifies
only that:

- the public evidence is privacy-reduced;
- the reported facts match the verified observations;
- the active research code is accurately labelled;
- the manifest is platform-stable;
- the branch integrates and validates against current `main`.

Any later tier-2/tier-3 execution remains a separate research-team decision and
authorization event.
