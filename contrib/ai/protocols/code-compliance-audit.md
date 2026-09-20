<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) PromptKit Contributors -->

---
name: code-compliance-audit
type: reasoning
description: >
  Systematic protocol for auditing source code against requirements and
  design documents. Maps specification claims to code behavior, detects
  unimplemented requirements, undocumented behavior, and constraint
  violations. Classifies findings using the specification-drift taxonomy
  (D8–D10).
applicable_to:
  - audit-code-compliance
---

# Protocol: Code Compliance Audit

Apply this protocol when auditing source code against requirements and
design documents to determine whether the implementation matches the
specification. The goal is to find every gap between what was specified
and what was built — in both directions.

## Phase 1: Specification Inventory

Extract the audit targets from the specification documents.

1. **Requirements document** — extract:
   - Every REQ-ID with its summary, acceptance criteria, and category
   - Every constraint (performance, security, behavioral)
   - Every assumption that affects implementation
   - Defined terms and their precise meanings

2. **Design document** (if provided) — extract:
   - Components, modules, and interfaces described
   - API contracts (signatures, pre/postconditions, error handling)
   - Data models and state management approach
   - Non-functional strategies (caching, pooling, concurrency model)
   - Explicit mapping of design elements to REQ-IDs

3. **Build a requirements checklist**: a flat list of every testable
   claim from the specification that can be verified against code.
   Each entry has: REQ-ID, the specific behavior or constraint, and
   what evidence in code would confirm implementation.

## Phase 2: Code Inventory

Survey the source code to understand its structure before tracing.

1. **Module/component map**: Identify the major code modules, classes,
   or packages and their responsibilities.
2. **API surface**: Catalog public functions, endpoints, interfaces —
   the externally visible behavior.
3. **Configuration and feature flags**: Identify behavior that is
   conditionally enabled or parameterized.
4. **Error handling paths**: Catalog how errors are handled — these
   often implement (or fail to implement) requirements around
   reliability and graceful degradation.

Do NOT attempt to understand every line of code. Focus on the
**behavioral surface** — what the code does, not how it does it
internally — unless the specification constrains the implementation
approach.

## Phase 3: Forward Traceability (Specification → Code)

For each requirement in the checklist:

1. **Search for implementation**: Identify the code module(s),
   function(s), or path(s) that implement this requirement.
   - Look for explicit references (comments citing REQ-IDs, function
     names matching requirement concepts).
   - Look for behavioral evidence (code that performs the specified
     action under the specified conditions).
   - Check configuration and feature flags that may gate the behavior.

2. **Assess implementation completeness**:
   - Does the code implement the **full** requirement, including edge
     cases described in acceptance criteria?
   - Does the code implement the requirement under all specified
     conditions, or only the common case?
   - Are constraints (performance, resource limits, timing) enforced?

3. **Classify the result**:
   - **IMPLEMENTED**: Code clearly implements the requirement. Record
     the code location(s) as evidence.
   - **PARTIALLY IMPLEMENTED**: Some aspects are present but acceptance
     criteria are not fully met. Flag as D8_UNIMPLEMENTED_REQUIREMENT
     with the finding describing what is present and what is missing.
     Set confidence to Medium.
   - **NOT IMPLEMENTED**: No code implements this requirement. Flag as
     D8_UNIMPLEMENTED_REQUIREMENT with confidence High.

## Phase 4: Backward Traceability (Code → Specification)

Identify code behavior that is not specified.

1. **For each significant code module or feature**: determine whether
   it traces to a requirement or design element.
   - "Significant" means it implements user-facing behavior, data
     processing, access control, external communication, or state
     changes. Infrastructure (logging, metrics, boilerplate) is not
     significant unless the specification constrains it.

2. **Flag undocumented behavior**:
   - Code that implements meaningful behavior with no tracing
     requirement is a candidate D9_UNDOCUMENTED_BEHAVIOR.
   - Distinguish between: (a) genuine scope creep, (b) reasonable
     infrastructure that supports requirements indirectly, and
     (c) requirements gaps (behavior that should have been specified).
     Report all three, but note the distinction.

## Phase 5: Constraint Verification

Check that specified constraints are respected in the implementation.

1. **For each constraint in the requirements**:
   - Identify the code path(s) responsible for satisfying it.
   - Assess whether the implementation approach **can** satisfy the
     constraint (algorithmic feasibility, not just correctness).
   - Check for explicit violations — code that demonstrably contradicts
     the constraint.

2. **Common constraint categories to check**:
   - Performance: response time limits, throughput requirements,
     resource consumption bounds
   - Security: encryption requirements, authentication enforcement,
     input validation, access control
   - Data integrity: validation rules, consistency guarantees,
     atomicity requirements
   - Compatibility: API versioning, backward compatibility,
     interoperability constraints

3. **Flag violations** as D10_CONSTRAINT_VIOLATION_IN_CODE with
   specific evidence (code location, the constraint, and how the
   code violates it).

## Phase 6: Classification and Reporting

Classify every finding using the specification-drift taxonomy
(see `taxonomies/specification-drift.md` for full definitions).

1. Assign exactly one drift label (D8, D9, or D10) to each finding.
2. Assign severity using the taxonomy's severity guidance.
3. For each finding, provide:
   - The drift label and short title
   - The spec location (REQ-ID, section) and code location (file,
     function, line range). For D9 findings, the spec location is
     "None — no matching requirement identified" with a description
     of what was searched.
   - Evidence: what the spec says and what the code does (or doesn't)
   - Impact: what could go wrong
   - Recommended resolution
4. Order findings primarily by severity, then by taxonomy ranking
   within each severity tier.

## Phase 7: Coverage Summary

After reporting individual findings, produce aggregate metrics:

1. **Implementation coverage**: % of REQ-IDs with confirmed
   implementations in code.
2. **Undocumented behavior rate**: count of significant code behaviors
   with no tracing requirement.
3. **Constraint compliance**: count of constraints verified vs.
   violated vs. unverifiable from code analysis alone.
4. **Overall assessment**: a summary judgment of code-to-spec alignment.

<!-- BEGIN ocserv extensions -->

## ocserv-Specific Extensions

The sections below extend the generic protocol with ocserv's requirements
tree, document map, and process/privilege model. Apply these alongside the
base phases above — they do not replace them. This protocol is the audit
engine behind **Protocol: Requirements Compliance** in the core-dev persona,
and is also the tool an external contributor should self-apply before
opening an MR.

### Phase 1 — Specification Inventory (ocserv)

- The "requirements document" is the `doc/requirements/` tree. Consult
  `doc/requirements/README.md` for the document map (which file covers
  which process/subsystem) and the ID scheme: `REQ-<AREA>-<NNN>` entries,
  linked `AC-*` acceptance criteria, and category tags (`AUTH`, `IPC`,
  `CFG`, `SEC`, `NET`, `COMPAT`, `ACCT`, `LOG`).
- ocserv has no separate design document beyond `doc/design.md` (IPC and
  process architecture), `doc/ocserv.8.md`, and `sample.config` (documented
  configuration behavior). Treat these three as the "design document" role
  in Phase 1.
- Build the requirements checklist by finding the `REQ-*`/`AC-*` entries
  that cite the files, functions, or config options actually touched by
  the diff — this is a patch-scoped audit, not a whole-project audit,
  unless a full-tree audit is explicitly requested.

### Phase 1.5 — Update-Before-Code Check (ocserv)

AGENTS.md's Requirements-First Workflow requires: if the patch changes
behavior an existing requirement describes, that requirement must be
updated **before** the implementation change, re-applying the protocol in
`contrib/ai/protocols/` that generated its document (see
`requirements-elicitation.md`, `requirements-from-implementation.md`, or
`requirements-reconciliation.md` as applicable).

Before running Phase 3: for every `REQ-*` whose described behavior the
patch changes, confirm the patch includes a corresponding update to that
requirement (typically a preceding commit in the same MR). If it does not,
this is a hard **BLOCK** — classify as D10_CONSTRAINT_VIOLATION_IN_CODE,
since the code now contradicts requirement text that still stands
unmodified, regardless of whether the new behavior is otherwise correct.
If the requirement is independently wrong for reasons unrelated to this
patch, it must be fixed in its own dedicated MR (per AGENTS.md) — do not
treat that as satisfying this check.

### Phase 3 — Forward Traceability (ocserv)

- "Implemented" evidence for a `CFG` requirement includes the parser
  itself (`src/config.c` / `src/subconfig.c`) plus the `[scope:]`
  annotation in `sample.config` and, for reloadable global options, the
  corresponding `error_on_vhost()` call in `src/config.c`.
- For `SEC`/`AUTH`/`IPC`-tagged requirements, a missing **negative**
  acceptance criterion path (e.g., rejection of a tampered cookie, a
  replayed SID, a bad password) is at most PARTIALLY IMPLEMENTED — per
  REQ-GEN-TEST-002's negative-test-first rule, do not classify such a
  requirement as fully IMPLEMENTED on the strength of the positive path
  alone.

### Phase 4 — Backward Traceability (ocserv)

- Significant, trace-worthy surfaces in ocserv: new or changed config
  options (`common-config.h` / `subconfig.c` / `config.c`), new or
  changed IPC fields (`ipc.proto` / `ctl.proto`), new auth/acct module
  registrations (`sec-mod.c`, `src/auth/`, `src/acct/`), and any code that
  crosses the main/sec-mod/worker privilege boundary. `mslog()` / `oclog()`
  / `seclog()` calls and talloc bookkeeping are infrastructure, not
  significant, unless a requirement specifically constrains logging.
- Classify undocumented behavior touching `SEC`, `AUTH`, or `IPC` category
  areas as High severity per the taxonomy's own guidance, and separately
  flag it under AGENTS.md's "Human-judgment required" list (privilege
  boundary crossing, new auth method) — a maintainer must see this, not
  just the audit output.

### Phase 5 — Constraint Verification (ocserv)

- Treat AGENTS.md's architecture invariant — no credential handling in a
  worker, no direct filesystem/socket access outside seccomp, no silent
  collapse of the main/sec-mod/worker boundary — as a standing,
  project-wide constraint even when no single `REQ-*` states it verbatim.
  A violation is always D10_CONSTRAINT_VIOLATION_IN_CODE, Critical
  severity, and requires explicit maintainer acknowledgment per AGENTS.md
  — a requirements-doc fix alone does not resolve it.
- The canonical technology choices (REQ-GEN-TECH-001 through -005:
  talloc-only allocation, GnuTLS-only cryptography via `tlslib.c`,
  protobuf-c for IPC with regenerated bindings, INI-only configuration,
  approval required for new dependencies) are constraints in this sense
  too. A violation is D10.

### Reporting (ocserv)

- Map findings to the BLOCK/REVIEW verdicts used by **Protocol:
  Requirements Compliance**: D8 and D10 findings are always a BLOCK.
  A High-severity D9 finding (SEC/AUTH/IPC area) is also a BLOCK; other
  D9 findings are a REVIEW item to raise with the maintainer rather than
  an automatic rejection.
- Cite `REQ-*` / `AC-*` / `OC-*` IDs exactly as they appear in
  `doc/requirements/`. Never invent or approximate an ID — if you cannot
  find the citation, say so and report a gap instead of guessing.

<!-- END ocserv extensions -->
