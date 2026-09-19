---
title: test authorship and quality requirements
generator: requirements-elicitation
process: all
id-prefix: REQ-GEN-TEST
sources:
  - AGENTS.md
  - tests/meson.build
  - tests/common.sh
---

# Test Authorship and Quality Requirements

These requirements constrain how tests in `tests/` are written, independent
of which subsystem they cover — they are what make every other document's
"Acceptance" criteria trustworthy rather than decorative. Split out of
`internal/general.md`, which still holds the other cross-cutting policy
categories (`SEC`, `TECH`, `STYLE`, `COMPAT`); IDs stay under the `REQ-GEN`
prefix since these remain project-wide policy, not a new subsystem.

### REQ-GEN-TEST-001 — Every feature or fix MUST have both a positive and a negative test; tests MUST be self-diagnosing and registered in `tests/meson.build`

**Requirement:** No feature addition or bug fix is complete without tests.
The following apply to all tests in `tests/`:

  (a) **Coverage**: every new feature or changed behavior MUST have at least
      one positive test (the correct behavior is exercised and confirmed) and
      at least one negative test (invalid input or error conditions are
      correctly rejected). For `SEC`, `AUTH`, and `IPC` changes, the negative
      test is the more important of the two and MUST be written first.
  (b) **Bug-fix test order**: for a bug fix, the reproducing test MUST be
      written and confirmed to fail against the unmodified code before the fix
      is applied. A test written after the fix cannot demonstrate it is
      meaningful.
  (c) **Self-diagnosing output**: a test failure MUST be explainable from the
      test's own output without local reproduction. Shell tests MUST print what
      they were testing and why it failed (e.g.
      `echo "FAIL: expected exit 0, got $ret"`). C unit tests MUST print the
      failing condition and relevant values before returning non-zero. Tests
      that exit non-zero with no diagnostic output MUST NOT be accepted.
  (d) **Registration**: every new test MUST be registered in
      `tests/meson.build`. An unregistered test is not run by CI and provides
      no coverage guarantee.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Testing New Functionality); `tests/meson.build`;
`tests/common.sh`
**Acceptance:** code-review — confirm for every MR that: (1) `tests/meson.build`
contains an entry for each new test file; (2) at least one test is a negative
case; (3) running the negative test against the pre-fix code produces a
non-zero exit and a human-readable failure message. CI runs all registered
tests on every MR; a passing CI run with no newly registered test for a
behavior change is itself a review finding.
**Links:** REQ-GEN-SEC-001, REQ-GEN-SEC-002

---

### REQ-GEN-TEST-002 — Unit tests MUST couple only to a module's public contract; a test that a behavior-preserving refactor could break MUST NOT be merged

**Requirement:** A module's public contract is its header-declared
functions/vtables/types plus their documented input/output behavior.
Everything else — private constants, struct layout, internal control flow,
in-memory representation — is private surface.

A unit test MUST depend only on the public contract, or on private surface
explicitly promoted into the module's header for that purpose. A unit test
MUST NOT depend on private surface it reconstructs itself (by duplicating,
guessing, or imitating it) rather than references by compiler-checked
symbol.

**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Design Principles — Locality of complexity; Testing
New Functionality)
**Acceptance:** code-review — for any test reaching past a module's header,
apply: *would a refactor that preserves the module's public-contract
behavior break this test?* If yes, it is a finding; resolve by promoting the
needed symbol into the header, or replacing the test with one that drives
the module only through its public contract.
**Links:** REQ-GEN-TEST-001
