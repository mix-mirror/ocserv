---
title: general and cross-cutting requirements
generator: requirements-elicitation
process: all
id-prefix: REQ-GEN
categories:
  SEC: security and privilege invariants
  TECH: canonical technology stack constraints
  STYLE: code style and structure rules enforced by CI or review
  TEST: test quality requirements
  COMPAT: platform portability policy
sources:
  - AGENTS.md
  - doc/design.md
  - doc/ocserv.8.md
  - doc/sample.config
  - .gitlab-ci.yml
---

# General and Cross-Cutting Requirements

This document captures requirements that span all three processes (main,
sec-mod, worker) or that encode project-wide policy — constraints on how
ocserv may evolve that cannot be attributed to a single subsystem or source
file.

Process-specific behavioral requirements belong in their own documents
(`internal/config.md`, `internal/authentication.md`, etc.), even when they
carry security implications. A requirement belongs here only when it applies
regardless of which subsystem is being changed.

The `AGENTS.md` "Canonical Technology Choices" table cites these IDs as its
authoritative source; the table in that file is a quick-reference summary only.

---

## SEC — security and privilege invariants

### REQ-GEN-SEC-001 — A semantic change to an operator-managed file MUST NOT silently grant more access than the previous semantics allowed

**Requirement:** Any change to the interpreted meaning of a value in an
operator-managed artifact — `ocserv.conf`, a plain-auth password file, an OTP
file, a supplemental per-user/per-group config file, or any other file whose
path appears in `ocserv.conf` and whose content is authored by the
administrator — MUST NOT, on upgrade, cause a client or user to gain access to
groups, VPN tunnels, or network resources that the administrator did not
explicitly grant under the previous version's documented semantics.

If such a meaning change is necessary, exactly one of the following MUST apply:

  (a) **Explicit opt-in.** The administrator must take a deliberate action —
      setting a new configuration option, or editing the affected file with
      awareness of the new semantics — before the new, broader behavior takes
      effect. The default for the new option MUST preserve the old behavior.

  (b) **Startup rejection.** ocserv detects the old value at startup, logs a
      clear error message identifying the affected option and file, and exits
      with `EXIT_FAILURE`, forcing the administrator to migrate before the
      server will accept connections.

Silent reinterpretation that expands access — a value that previously granted
no access or limited access and, after an upgrade, grants broader access
without any administrator action — MUST NOT be introduced, regardless of how
useful the new semantics would be for fresh deployments.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md; `doc/ocserv.8.md`; `doc/sample.config`
**Acceptance:** [SEC] code-review — every proposed change that alters the
interpretation of an existing value in an operator-managed file MUST be
evaluated against this requirement before merging.

Concrete failing example (gitlab#748): changing the `*` entry in a plain-auth
passwd file's group field from "no effective group membership" (current
behavior: `break_group_list` discards single-character entries,
`src/auth/plain.c:119–135`) to "membership in all configured groups" would
violate this requirement — on upgrade, any user with `*` in their passwd entry
would silently gain access to all groups without any administrator action.

Compliant alternative for the same feature: introduce a new per-vhost option
(e.g. `plain-wildcard-group = true`, defaulting to `false`) that the
administrator must explicitly enable; `plain_auth_group()` checks this flag
before treating `*` as a wildcard.
**Links:** REQ-AUTH-AUTH-012, REQ-AUTH-AUTH-016, REQ-CONFIG-SEC-001

---

### REQ-GEN-SEC-002 — The three-process privilege boundary MUST NOT be collapsed by any patch

**Requirement:** The division of responsibilities across main (root, listeners
and IP allocation), sec-mod (root, authentication and private keys), and worker
(unprivileged + seccomp, per-client TLS/DTLS) is a security invariant. No
patch MAY:

  (a) move credential handling, private-key operations, or session-state
      storage into the worker process;
  (b) grant a worker direct filesystem access to paths it resolves itself
      (outside the root-created config snapshot, `REQ-CONFIG-SEC-001`);
  (c) grant a worker a direct socket connection to sec-mod or main outside
      the defined Unix-socket IPC channels (`src/ipc.proto`, `src/ctl.proto`);
  (d) silently remove or bypass the seccomp filter that confines the worker.

If a proposed change requires crossing or relaxing a privilege boundary, it
MUST be flagged explicitly in the merge request for maintainer review and MUST
NOT be merged without explicit maintainer acknowledgment.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md ("Hard rule"); `doc/design.md`; `src/main.c`,
`src/sec-mod.c`, `src/worker.c`
**Acceptance:** [SEC] code-review — confirm by call-graph inspection that no
function reachable from `src/worker-*.c` at runtime: (a) opens or reads a
credential file directly; (b) holds a private key in worker-local memory after
`AUTH_COOKIE_REP`; (c) connects a socket to sec-mod's Unix socket path directly
(all worker↔sec-mod traffic routes through main's forwarding). Any MR touching
the seccomp filter (`src/seccomp.c`) or adding a new IPC channel requires
maintainer sign-off citing this requirement.
**Links:** REQ-CONFIG-SEC-001, REQ-IPC-010, REQ-AUTH-AUTH-007,
REQ-GEN-TECH-003

---

## TECH — canonical technology stack constraints

### REQ-GEN-TECH-001 — talloc is the sole memory allocator; GnuTLS-owned memory is the only exception

**Requirement:** All heap allocations in ocserv source code MUST use talloc
functions (`talloc_zero`, `talloc_strdup`, `talloc_array`, etc.) with an
explicit talloc parent context. The plain C allocators `malloc`, `calloc`,
`realloc`, and `free` MUST NOT appear in new code under `src/` (outside vendored
subtrees: `src/ccan/`, `src/inih/`, `src/llhttp/`, `src/pcl/`,
`src/protobuf/`, `src/gnulib/`).

The sole exception: memory whose lifetime GnuTLS manages internally MUST be
allocated with `gnutls_malloc()` and freed with `gnutls_free()`. The two
allocator domains MUST NOT be mixed for the same logical allocation — a buffer
allocated with `talloc_*` MUST NOT be passed to `gnutls_free()`, and vice versa.

Error paths that must release multiple allocations MUST use a `goto cleanup`
pattern with a single freeing label rather than duplicating free calls on every
error branch.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Canonical Technology Choices — Memory management);
pervasive in `src/*.c`
**Acceptance:** negative, code-review — `grep -rn '\b\(malloc\|calloc\|realloc\|free\)\s*(` src/` excluding vendored subtrees; any hit in non-vendored code is a violation. Confirm every new function that returns an allocated pointer documents its talloc parent in a comment or by convention (e.g. allocated on the passed-in `pool` argument).
**Links:** REQ-GEN-TECH-002

---

### REQ-GEN-TECH-002 — GnuTLS is the sole cryptographic library; no OpenSSL; TLS calls go through `src/tlslib.c`

**Requirement:** All TLS, DTLS, certificate, and cryptographic operations MUST
use GnuTLS (or its companion library nettle for low-level primitives). OpenSSL
and any other TLS/crypto library MUST NOT be introduced as a dependency.

Code in `src/worker-*.c` and `src/main-*.c` MUST NOT call GnuTLS API functions
directly — all GnuTLS interaction from those files MUST go through the wrapper
functions in `src/tlslib.c` and `src/tlslib.h`. Direct GnuTLS calls are
permitted only within `src/tlslib.c` itself and in `src/sec-mod-*.c` for
private-key operations that are inherently sec-mod's responsibility.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Canonical Technology Choices — Cryptography);
`src/tlslib.c`, `src/tlslib.h`
**Acceptance:** negative, code-review — `grep -rn 'SSL_\|EVP_\|openssl\|OPENSSL' src/` (excluding vendored subtrees); any hit is a violation. `grep -rn 'gnutls_' src/worker-*.c src/main-*.c`; any hit that is not a call to a `tlslib.h`-declared wrapper is a violation.
**Links:** REQ-GEN-TECH-001

---

### REQ-GEN-TECH-003 — All cross-process messages MUST be defined in `.proto` files; generated bindings MUST NOT be hand-edited

**Requirement:** Every message that crosses a process boundary (worker ↔ main,
worker ↔ sec-mod, main ↔ sec-mod, `occtl` ↔ main) MUST be defined in
`src/ipc.proto` or `src/ctl.proto` using the protobuf-c schema language. No
ad-hoc binary format, fixed-layout struct, or text protocol MAY be introduced
for inter-process communication.

After any edit to a `.proto` file, the C bindings MUST be regenerated with:

```
protoc-c --c_out=src/ src/ipc.proto
protoc-c --c_out=src/ src/ctl.proto
```

The generated files `src/ipc.pb-c.c`, `src/ipc.pb-c.h`, `src/ctl.pb-c.c`,
and `src/ctl.pb-c.h` MUST NOT be edited by hand. Any manual edit will be
silently overwritten by the next `protoc-c` invocation and invalidates the
requirement that the `.proto` file is the authoritative source of the message
schema.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Canonical Technology Choices — IPC serialization;
Modifying IPC); `src/ipc.proto`, `src/ctl.proto`
**Acceptance:** negative, code-review — confirm that `src/ipc.pb-c.*` and
`src/ctl.pb-c.*` are not modified in any MR that does not also modify the
corresponding `.proto` file. Positive — after a `.proto` edit, run `protoc-c`
and confirm `ninja -C build` succeeds and `git diff src/*.pb-c.*` matches the
`protoc-c` output exactly.
**Links:** REQ-GEN-SEC-002, REQ-IPC-010

---

### REQ-GEN-TECH-004 — Configuration MUST use INI `key = value` format; no structured sub-formats

**Requirement:** All administrator-facing configuration options MUST be
expressible as flat INI `key = value` pairs or as the existing bracketed
sub-section syntax (`auth = module[key=value, ...]`) parsed by `src/inih/` and
`src/subconfig.c`. No new structured format — JSON objects, YAML documents,
TOML tables, XML, or any multi-line structured syntax — MAY be introduced for
options that are expressible as key=value pairs.

A new configuration file format (separate from `ocserv.conf`) MAY only be
introduced for data that is inherently structured and cannot be expressed as
key=value (e.g. the OIDC JSON configuration, which is defined by an external
standard). In that case the new format MUST be documented in `doc/ocserv.8.md`
and `doc/sample.config`, and its introduction requires a design-discussion
issue.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Canonical Technology Choices — Configuration parsing;
Design Principles — Configuration stays in INI); `src/config.c`,
`src/subconfig.c`, `src/inih/`
**Acceptance:** code-review — any MR that adds a new `ini_parse()`-bypassing
config path or introduces a call to a JSON/YAML parser for a new option
(outside the existing OIDC path) is a violation. Positive — every new option
added in an MR appears in `doc/sample.config` as a `key = value` line.
**Links:** REQ-CONFIG-CFG-001, REQ-GEN-SEC-001

---

### REQ-GEN-TECH-005 — A new external library dependency requires a design-discussion issue and explicit maintainer approval

**Requirement:** Before introducing a new external library (i.e. a new
`dependency()` call in `meson.build` that is not already present), the
contributor MUST:

  (a) check `src/ccan/` — if the required functionality exists as a CCAN
      module, copy it in and use it rather than adding an external dependency;
  (b) consider whether a small inline implementation (≤ ~50 lines) would
      suffice — if so, prefer it over a new dependency;
  (c) if neither (a) nor (b) applies, open a design-discussion issue documenting
      the proposed dependency, why existing options are insufficient, and the
      build/packaging/security-audit impact; the MR MUST NOT be merged until a
      maintainer explicitly approves the dependency in that issue.

Every external dependency is a permanent build, packaging, and security-audit
cost. The bar for approval is that no existing in-tree alternative exists and
the dependency is actively maintained and widely packaged.
**Strength:** MUST
**Status:** DERIVED
**Source:** AGENTS.md (Canonical Technology Choices — Utility constructs;
Design Principles — Resist dependency growth)
**Acceptance:** code-review — any MR that adds a `dependency()` call not
present in the base branch MUST cite a design-discussion issue number in the MR
description. The absence of such a citation is grounds for blocking the MR.
**Links:** REQ-GEN-TECH-001, REQ-GEN-TECH-002, REQ-GEN-TECH-003,
REQ-GEN-TECH-004

---

### REQ-GEN-TECH-006 — Modifying vendored code requires a runtime test or compile-time check that fails if the change is lost

**Requirement:** Files under vendored subtrees (`src/ccan/`, `src/inih/`,
`src/llhttp/`, `src/pcl/`, `src/protobuf/`, `src/gnulib/`) MUST track upstream
verbatim except for a narrow, justified deviation — an unfixed upstream
security issue, exposing an existing hardcoded value as an `#ifndef`-guarded
override (as already done for `INI_MAX_LINE`), or a fix for an ocserv-specific
build failure — and any such deviation MUST be guarded by either a dedicated
runtime test in `tests/` (per REQ-GEN-TEST-001) that exercises the
ocserv-specific behavior, or a compile-time check (a `#if`/`#error` or
`_Static_assert` tying the deviation to the value it depends on, as MR !604
does for `INI_MAX_SECTION` vs. `MAX_VHOST_NAME_LEN`) where the deviation is a
numeric/structural invariant rather than a behavior, so that a future vendor
sync which silently drops the deviation fails `ninja -C build` or `ninja -C
build test` instead of going unnoticed; this is not hypothetical — a prior
inih deviation (`e7233819`) was dropped by a vendor sync and had to be
manually rediscovered and reapplied twice (`1a2100f9`, `28252bff`) for lack of
either.
**Strength:** MUST
**Status:** DERIVED
**Source:** AGENTS.md (External Libraries); REQ-GEN-TECH-003 (no hand-editing
generated pb-c files); git history `e7233819`, `1a2100f9`, `28252bff`; MR !604
(`INI_MAX_SECTION` compile-time guard)
**Acceptance:** code-review — an MR modifying a vendored file without an
accompanying `tests/meson.build`-registered runtime test or a compile-time
guard is rejected. Regression — `ninja -C build` or `ninja -C build test`
catches a vendor sync that drops the deviation.
**Links:** REQ-GEN-TECH-003, REQ-GEN-TECH-005, REQ-GEN-TEST-001

---

### REQ-GEN-TECH-007 — Improvements to actively-maintained vendored code MUST be sent upstream first

**Requirement:** When a change to a vendored subtree (`src/ccan/`, `src/inih/`,
`src/llhttp/`, `src/pcl/`, `src/protobuf/`, `src/gnulib/`) is a general
improvement rather than an ocserv-specific deviation covered by
REQ-GEN-TECH-006 (e.g. a bug fix, portability fix, or enhancement that upstream
would plausibly also want), the contributor MUST first propose the change to
the upstream project and reference that submission (issue/PR/patch URL) in the
ocserv MR description, before or alongside carrying the change locally. This
does not apply to subtrees whose upstream is unmaintained or has no accepting
channel — currently `src/pcl/` (PCL upstream does not use a collaboration platform).
In that case the change MAY be applied directly in-tree.
This requirement is about where the fix is authored, not whether
it is guarded once merged: any resulting deviation still MUST satisfy
REQ-GEN-TECH-006.
**Strength:** MUST
**Status:** DERIVED
**Source:** MR !604 (review discussion — suggestion to send bundled library
improvements upstream first)
**Acceptance:** code-review — an MR modifying a vendored file, other than
`src/pcl/`, with a change that is not an ocserv-specific deviation (per
REQ-GEN-TECH-006) MUST cite an upstream issue/PR/patch link in the MR
description, or explain why upstreaming does not apply; absence of either is
grounds for blocking the MR.
**Links:** REQ-GEN-TECH-005, REQ-GEN-TECH-006

---

## STYLE — code style and structure rules

### REQ-GEN-STYLE-001 — Source files MUST conform to C99, Linux kernel style, and pass `clang-format`; header guards MUST use the canonical form

**Requirement:** All source files under `src/` and `tests/` (excluding vendored
subtrees: `src/ccan/`, `src/inih/`, `src/llhttp/`, `src/pcl/`, `src/protobuf/`,
`src/gnulib/`, and generated `*.pb-c.*` files) MUST:

  (a) **C standard**: use C99 features only. C11 or later features (e.g.
      `_Atomic`, `_Generic`, `_Static_assert` without a C99-compatible wrapper,
      anonymous struct/union not as a GCC extension) MUST NOT be used.
  (b) **Coding style**: follow Linux kernel style — tabs for indentation,
      8-space tab width, 80-column line limit.
  (c) **Format tool**: pass `clang-format --dry-run -Werror` without errors.
      CI enforces this on every MR.
  (d) **Header guards**: every `.h` file MUST use the form:
      ```c
      #ifndef FILENAME_H
      #define FILENAME_H
      /* ... */
      #endif /* FILENAME_H */
      ```
      where `FILENAME_H` matches the file's base name uppercased with `.`
      replaced by `_`.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Code Style); `.gitlab-ci.yml` (clang-format CI job)
**Acceptance:** CI — the `clang-format` CI job runs `clang-format --dry-run
-Werror` on all non-vendored, non-generated files under `src/` and `tests/`
and fails the pipeline on any formatting violation. C standard and header-guard
conformance are verified by code review; no automated check currently exists
for C99-only compliance beyond what the compiler warns on with `-std=c99 -Wall`.
**Links:** REQ-GEN-STYLE-002

---

### REQ-GEN-STYLE-002 — `#ifdef` blocks in function bodies MUST be shallow and short; optional features MUST use the stub pattern

**Requirement:** Preprocessor conditionals inside function bodies obscure
control flow and make review difficult. The following rules apply to all source
files under `src/` and `tests/` (excluding vendored subtrees):

  (a) **Depth**: `#ifdef`/`#if` blocks inside a function body MUST NOT be
      nested more than one level deep. A conditional that needs deeper nesting
      MUST be extracted into a separately-named function.
  (b) **Length**: each branch of an in-function `#ifdef` MUST contain at most
      5 lines. Longer branches MUST be extracted into separately-named
      functions.
  (c) **Stub pattern**: when a feature is conditionally compiled, the header
      MUST define a no-op (or safe error-returning) inline stub for the disabled
      case, so call sites require no `#ifdef` at all. Example:
      ```c
      #ifdef HAVE_FEATURE
      int feature_init(worker_st *ws);
      #else
      static inline int feature_init(worker_st *ws) { return 0; }
      #endif
      ```
  (d) **Significant feature code**: any optional feature spanning more than one
      function MUST live in its own `.c` file included or excluded by the build
      system (`meson.build`), following the pattern of `src/auth/` and
      `src/acct/`. It MUST NOT be implemented as a large inline `#ifdef` block
      in an existing file.
  (e) **`#endif` annotation**: every `#endif` MUST be annotated with the
      condition it closes: `#endif /* HAVE_FEATURE */`.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Preprocessor Conditionals); `src/auth/`,
`src/acct/` (model structure)
**Acceptance:** code-review — no automated tool currently enforces (a)–(e);
review is the gate. When an MR is submitted, the reviewer MUST check every
modified function for `#ifdef` depth and length violations and for missing
`#endif` annotations. The `src/auth/pam.c` / `src/auth/gssapi.c` files
illustrate compliant optional-feature structure.
**Links:** REQ-GEN-STYLE-001

---

### REQ-GEN-STYLE-003 — All structs MUST use `_st`/`_t`; `_ctx` is tolerated only in pre-existing names; `_ctx_st` MUST NOT be used

**Requirement:** Every struct tag MUST be named `<name>_st`, and its
typedef (if any) `<name>_t`, applied mechanically regardless of what the
struct represents. `_ctx`-suffixed type names in existing code are
tolerated as legacy and need not be renamed on sight, but `_ctx_st` (and
`_ctx_t`) MUST NOT appear anywhere, new or existing — such names MUST be
renamed to the `_st`/`_t` form. This requirement does not apply to
vendored subtrees (`src/ccan/`, `src/inih/`, `src/llhttp/`, `src/pcl/`,
`src/protobuf/`, `src/gnulib/`) or generated `*.pb-c.*` files, whose
naming follows their respective upstreams.
**Strength:** MUST / MUST NOT
**Status:** REVIEW — records the convention proposed in MR !579's
discussion; not yet fully applied across the codebase.
**Source:** MR !579 (struct naming consistency discussion).
**Acceptance:** code-review — an MR MUST NOT introduce a `_ctx_st`/`_ctx_t`
name, and any newly introduced struct MUST follow `<name>_st`/`<name>_t`.
Candidate automated check: `grep -rnE '_ctx_st\b|_ctx_t\b' src/*.c src/*.h`,
excluding the vendored subtrees and generated files listed above, MUST
return no matches.
**Links:** REQ-GEN-STYLE-001

---

## TEST — test quality requirements

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

## COMPAT — platform portability policy

### REQ-GEN-COMPAT-001 — Linux is the primary target; BSD compatibility is best-effort; Linux-specific code MUST be guarded with `#ifdef __linux__`

**Requirement:** ocserv is a Linux service. Linux-specific features (epoll,
TUN device ioctls, procfs, namespaces, seccomp, `SO_REUSEPORT`, etc.) are
accepted without requiring a BSD equivalent.

BSD (FreeBSD, OpenBSD) compatibility is maintained on a best-effort basis:

  (a) Patches MUST NOT gratuitously break BSD builds. A change that breaks BSD
      solely because the author did not check is a defect; a change that is
      inherently Linux-only is accepted.
  (b) Any code path that invokes a Linux-specific system call, header, or
      kernel interface MUST be guarded with `#ifdef __linux__` (or a more
      specific feature-test macro) so that BSD builds continue to compile,
      even if the BSD path is a no-op stub.
  (c) Features that rely on procfs (e.g. config snapshots, REQ-CONFIG-SEC-001)
      are Linux-only by nature; on BSD, the absence of procfs means the
      corresponding behavior is unavailable and the administrator MUST restart
      the server to apply configuration changes. This difference MUST be noted
      in `doc/ocserv.8.md` for any option where it applies.
  (d) A feature MUST NOT be rejected from merging solely because it does not
      work on BSD, provided (a) and (b) are satisfied.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Project Overview — BSD; Platform Portability);
`src/config.c` (`PROC_FS_SUPPORTED`); `.gitlab-ci.yml`
**Acceptance:** CI — the cross-compilation job (i386/Debian) catches most
Linux-specific implicit assumptions. BSD-specific: code-review confirms that
any new `#include <linux/...>` or Linux-specific `ioctl`/syscall is inside
`#ifdef __linux__`. REQ-CONFIG-SEC-001's `[Divergence]` note documents the
accepted procfs gap as a model for how to document platform differences.
**Links:** REQ-CONFIG-SEC-001, REQ-GEN-STYLE-002
