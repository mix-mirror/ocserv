<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) PromptKit Contributors -->

---
name: adversarial-falsification
type: guardrail
description: >
  Cross-cutting protocol enforcing adversarial self-falsification discipline.
  Requires the reviewer to attempt to disprove every candidate finding before
  reporting it, reject known-safe patterns, and resist premature summarization.
applicable_to:
  - exhaustive-bug-hunt
  - engineering-workflow
  - maintenance-workflow
  - spec-extraction-workflow
  - audit-spec-alignment
  - audit-implementation-alignment
---

# Protocol: Adversarial Falsification

This protocol MUST be applied to any task that produces defect findings.
It enforces intellectual rigor by requiring the reviewer to actively try
to **disprove** each finding before reporting it, rather than merely
accumulating plausible-looking issues.

## Rules

### 1. Assume More Bugs Exist

- Do NOT conclude "code is exceptionally well-written" or "no bugs found"
  unless you have exhausted the required review procedure and can
  demonstrate coverage.
- Do NOT stop at superficial scans or pattern matching. Pattern matches
  are only starting points — follow through with path tracing.
- Treat prior "all false positives" conclusions as untrusted — re-verify
  critical code paths (lock acquisition, buffer access, state machines,
  error handling) regardless of any prior review conclusions.

### 2. Disprove Before Reporting

For every candidate finding:

1. **Attempt to construct a counter-argument**: find the code path, helper,
   retry logic, or cleanup mechanism that would make the issue safe.
2. If you find such a mechanism, **verify it by reading the actual code** —
   do not assume a helper "probably" cleans up.
3. Only report the finding if disproof fails — i.e., you cannot find a
   mechanism that neutralizes the issue.
4. Document both the finding AND why your disproof attempt failed in the
   output (the "Why this is NOT a false positive" field).

### 3. No Vague Risk Claims

- Do NOT report "possible race" or "could leak" without tracing the
  **exact** lock, refcount, cleanup path, and caller contract involved.
- Do NOT report "potential issue" without specifying the **concrete bad
  outcome** (crash, data corruption, privilege escalation, resource leak).
- Your standard: if you cannot point to the exact lines, state transition,
  and failure path, do not claim a bug.

### 4. Verify Helpers and Callers

- If a helper function appears to perform cleanup, **read that helper** —
  do not assume it handles the case you are analyzing.
- If safety depends on a caller guarantee (e.g., caller holds a lock,
  caller validates input), **verify the guarantee from the caller** or
  mark the finding as `Needs-domain-check` rather than dismissing it.
- If an invariant is documented only by an assertion (e.g., `assert`,
  `NT_ASSERT`, `DCHECK`), verify whether that assertion is enforced in
  release/retail builds. If not, the invariant is NOT guaranteed.

### 5. Anti-Summarization Discipline

- If you catch yourself writing a summary before completing analysis,
  **stop and continue tracing**.
- If you find yourself using phrases like "likely fine", "appears safe",
  or "probably intentional", you MUST do one of:
  - **Prove it** with exact code-path evidence, OR
  - **Mark it unresolved** and continue analysis.
- Do NOT produce an executive summary or overall assessment until every
  file in the scope has a completed coverage record.

### 6. False-Positive Awareness

- Maintain a record of candidate findings that were investigated and
  rejected, as a markdown table with columns: Candidate Finding,
  Reason Rejected, Safe Mechanism. For each, document:
  - What the candidate finding was
  - Why it was rejected (what mechanism makes it safe)
- This record serves two purposes:
  - Demonstrates thoroughness to the reader
  - Prevents re-investigating the same pattern in related code

### 7. Confidence Classification

Assign a confidence level to every reported finding:

- **Confirmed**: You have traced the exact path to trigger the bug and
  verified that no existing mechanism prevents it.
- **High-confidence**: The analysis strongly indicates a bug, but you
  cannot fully rule out an undiscovered mitigation without additional
  context.
- **Needs-domain-check**: The analysis depends on a domain-specific
  invariant, caller contract, or runtime guarantee that you cannot
  verify from the provided code alone. State what must be checked.

<!-- END PromptKit base -->

---

<!-- BEGIN ocserv extensions -->

## ocserv-Specific Extensions

ocserv has no shared-memory threading inside a process — concurrency
takes the form of (a) multiple worker processes each handling one client,
(b) PCL coroutines within a worker for protocol/session multiplexing, and
(c) the libev event loop dispatching callbacks in main/sec-mod. "Lock
acquisition" in Rule 1/3 above should be read as the ocserv equivalents:

### Rule 1/3 — ocserv equivalents of "lock acquisition, buffer access, state machines"

Re-verify these regardless of prior conclusions:
- **talloc allocation/free pairs** and `goto cleanup` chains — a `talloc_free()`
  on the wrong context, or a missing free on an error path, is this codebase's
  analogue of a leaked lock.
- **PCL coroutine switches** (`co_resume`/`co_call` in `src/pcl/`) — any pointer
  to a stack-local variable that is captured before a coroutine switch and
  dereferenced after resumption is a use-after-scope hazard (see
  `contrib/ai/taxonomies/stack-lifetime-hazards.md`).
- **IPC unpack + validate** sequences — every protobuf-c `*_unpack()` call in
  main/sec-mod that consumes worker-supplied data must be followed by explicit
  range/length/NULL checks before the value is used; a missing check here is
  the IPC-boundary analogue of an unvalidated lock-protected buffer.
- **seccomp filter state** — a code path reached only after `worker_apply_seccomp_filter()`
  has been applied behaves differently (denied syscalls) than the same path
  during initialization; verify which phase a candidate finding's code runs in.

### Rule 2 — common "safe mechanisms" to check first in ocserv

Before reporting a finding, check whether one of these neutralizes it:
- talloc's destructor chain (`talloc_set_destructor`) freeing child allocations
  automatically when a parent context is freed.
- `sec-mod`'s SID validation rejecting a stale/forged session before the
  candidate code path is reached.
- The worker's seccomp profile denying the syscall the finding depends on.
- Config validation in `src/config.c` (`exit(EXIT_FAILURE)` at startup)
  rejecting the configuration state the finding assumes.

### Rule 6 — false-positive table location

For ocserv security reviews, maintain the false-positive table as specified
in `contrib/ai/protocols/security-vulnerability.md` (which defines the full
output format including the "Why not a false positive" field) — do not
create a separate ad-hoc format.

<!-- END ocserv extensions -->
