---
title: test authorship and quality requirements
generator: requirements-elicitation
process: all
id-prefix: REQ-GEN-TEST
sources:
  - AGENTS.md
  - tests/meson.build
  - tests/common.sh
  - .gitlab-ci.yml
  - meson_options.txt
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

---

### REQ-GEN-TEST-003 — A test needing root privilege, a network identity, system users/groups, or a PAM stack MUST use the project's existing wrapper libraries; it MUST NOT invent a new isolation mechanism

**Requirement:** ocserv's test suite provides `socket_wrapper`,
`uid_wrapper`, `nss_wrapper`, and `pam_wrapper` (via `cwrap`) specifically so
tests can fake a network interface, root privilege, system users/groups, or
a PAM service without touching real system state. A test that needs any of
these MUST use the existing `LD_PRELOAD` wrapper plus the corresponding
`common.sh` helper (`launch_simple_sr_server`, `launch_simple_pam_server`,
etc.), consistent with `REQ-GEN-TECH-005`'s bar on new external
dependencies. It MUST NOT mutate real `/etc/passwd`/`/etc/group`, bind to a
real network interface, or otherwise touch system state outside the
wrapper sandbox to achieve isolation.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/common.sh:130-172` (`launch_simple_pam_server`,
`launch_simple_sr_server`); `tests/meson.build` `have_cwrap`/`have_cwrap_pam`
gating; used by 53 test scripts.
**Acceptance:** code-review, local — confirm any new test requiring
elevated/faked privilege sources one of `common.sh`'s `launch_simple_*`
helpers rather than shelling out to real `sudo`/`useradd`/interface
configuration.
**Links:** REQ-GEN-TECH-005

---

### REQ-GEN-TEST-004 — A test MUST require the least privilege that suffices to exercise its behavior; it MUST NOT default to root or other elevated setup when the unprivileged wrapper path would do

**Requirement:** A test MUST be written to need as little privilege as the
property under test allows. If `NO_NEED_ROOT` plus the `*_wrapper`
libraries (`REQ-GEN-TEST-003`) can exercise the behavior, the test MUST use
that path instead of requiring root. Root, real namespaces, or other
CI-only setup MUST be justified by the property under test itself (e.g. an
actual TUN device or network namespace) — they MUST NOT be reached for as a
default that avoids writing the unprivileged path.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/common.sh:34-40` (root gated by `NO_NEED_ROOT`, not
assumed); 60 of the test scripts in `tests/` run under `NO_NEED_ROOT` with
wrapper libraries rather than requiring real root.
**Acceptance:** code-review — for a new test requiring root, confirm and
record why `NO_NEED_ROOT` + wrapper libraries cannot exercise the same
behavior (e.g. it genuinely needs a TUN device, a real network namespace,
or another capability the wrapper libraries do not fake). Absent that
justification, the test MUST be rewritten to the unprivileged path.
**Links:** REQ-GEN-TEST-003

---

### REQ-GEN-TEST-005 — A test whose precondition is unmet in the current run MUST `exit 77` (SKIP); it MUST NOT report a false pass or fail

**Requirement:** After minimizing its precondition per `REQ-GEN-TEST-004`,
a test may still have one genuinely necessary to its current run — missing
root, a missing optional dependency (`openconnect`, `ss`/`netstat`), or an
LD_PRELOAD mechanism incompatible with the active sanitizer. When that
precondition is unmet, the test MUST `exit 77`. It MUST NOT `exit 0` (a
false pass hiding zero coverage) and MUST NOT run anyway and fail for an
unrelated reason (a false fail indistinguishable from a real regression).
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/common.sh:35-40` (no-root skip), `tests/common.sh:58-63`
(ASAN/ld-preload-incompatible skip); the same `exit 77` pattern recurs in 60
files across `tests/`.
**Acceptance:** code-review, local — grep the new test for its environment
precondition checks; confirm each unmet precondition path is `exit 77`
before any assertion runs. Running the test locally without root (where
`NO_NEED_ROOT` is not set) MUST print the skip reason and exit 77, not hang
or fail.
**Links:** REQ-GEN-TEST-001, REQ-GEN-TEST-004

---

### REQ-GEN-TEST-006 — A precondition that makes a test skip locally MUST be satisfied by the project's primary CI matrix; `exit 77` MUST NOT be a way for a test to skip everywhere

**Requirement:** `exit 77` (`REQ-GEN-TEST-005`) covers an unmet precondition
of *this run*, not a standing exemption from ever being executed. Whatever
precondition remains after `REQ-GEN-TEST-004` MUST be satisfied by at least
one job in the project's primary CI matrix, so the test actually runs
there. A test whose precondition also fails in every CI job is not
exercising anything and MUST be fixed — narrow the precondition, or add/
adjust a CI job that satisfies it — rather than left to skip silently
everywhere. Build configurations that disable a whole precondition class on
purpose (`-Droot-tests=false`, used only for the feature-minimal and
FreeBSD jobs) are the documented, scoped exception; they MUST NOT be read
as license for an individual test to avoid execution.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `meson_options.txt:26` (`root-tests` defaults `true`);
`.gitlab-ci.yml` — every primary platform job (Debian, Ubuntu, Fedora,
CentOS, Alpine, seccomp, asan, ubsan, …) runs root-requiring tests with that
default, executing as root in an otherwise-unprivileged container;
`-Droot-tests=false` appears only in `MINIMAL_OPTIONS` and the `.FreeBSD`
template.
**Acceptance:** CI-config review — confirm at least one job in the primary
matrix in `.gitlab-ci.yml` satisfies the new test's precondition (i.e. the
test is not `-Droot-tests=false`'d, nor excluded by a `--no-suite`/`except`
rule, in every job that would otherwise reach it).
**Links:** REQ-GEN-TEST-005

---

### REQ-GEN-TEST-007 — A test that binds a TCP/UDP port MUST obtain it dynamically; it MUST NOT hardcode a fixed port number

**Requirement:** meson runs tests in parallel by default. A test that binds
ocserv (or any helper) to a hardcoded port number will intermittently
collide with another test's listener. A test that needs a port MUST obtain
one via the existing `GETPORT`/`check_if_port_in_use` mechanism in
`tests/common.sh` (or an equivalent unused-port probe), never a literal
port number.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/common.sh:289-300` (`GETPORT`), `tests/common.sh:264-268`
(`check_if_port_in_use`); used by 120 of the test scripts in `tests/`, with
no counterexample of a hardcoded `PORT=<number>`.
**Acceptance:** code-review, local — confirm the new test sources
`eval "${GETPORT}"` (or calls `check_if_port_in_use` itself) before binding
any port, and that no numeric literal is assigned to `PORT`/`ADDRESS:PORT`.

---

### REQ-GEN-TEST-008 — A test's server config MUST be generated from a `tests/data/` template via `update_config()`; it MUST NOT hardcode absolute paths, usernames, or other build-specific values

**Requirement:** A test that needs an ocserv config file MUST derive it from
a template in `tests/data/` using `update_config()`'s `@PLACEHOLDER@`
substitution (`@SRCDIR@`, `@PORT@`, `@USERNAME@`, etc.), so the same test
config works unmodified across out-of-tree builds, parallel build
directories, and CI runners. A test MUST NOT write a config file containing
a literal absolute path, username, or port baked in by the test author.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/common.sh:66-97` (`update_config()`); used by 119 of the
test scripts in `tests/`; placeholder vocabulary documented in AGENTS.md
(Test Structure).
**Acceptance:** code-review, local — confirm the new test's config template
lives under `tests/data/` and is materialized via `update_config`, not
`cp`'d or hand-written with resolved values.

---

### REQ-GEN-TEST-009 — A test MUST terminate every process it started and remove every resource it created, on both the pass and the fail path

**Requirement:** A test that launches an ocserv process tree (main, its
forked workers, sec-mod) MUST ensure every one of those processes is
terminated, and every resource it created (config file, socket-wrapper
directory, PAM-wrapper directory) is removed, regardless of whether the
test passes or fails. The mechanism is not prescribed — `common.sh`'s
`fail()`/`cleanup()`/`cleanup_client_server()` helpers, or an explicit
`trap` — but the outcome MUST hold on every exit path, including an
unexpected early exit. A leaked server process holds its port and
socket/PAM-wrapper directories open, which can cause unrelated later tests
in the same run to fail for a reason that has nothing to do with what they
test.
**Strength:** MUST
**Status:** DERIVED
**Source:** `tests/common.sh:99-104` (`fail()` kills `$PID` before exiting),
`tests/common.sh:183-190` (`cleanup()`), `tests/common.sh:209-231`
(`cleanup_client_server()`), `tests/common.sh:301` (fallback `trap` on the
launch-failure path); `tests/test-pam-abort` as a representative caller
(`PID=$!` captured at launch, `fail $PID "..."` on the failure branch,
`cleanup` on the success path).
**Acceptance:** code-review, local — trace every exit point in the new
test (including the top-level failure of any command not wrapped in
`|| fail ...`) and confirm the server PID(s) captured at launch are killed
on each one. Running the test and checking `ps`/`pgrep ocserv` afterward
MUST show no surviving process.
