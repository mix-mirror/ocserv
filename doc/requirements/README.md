# ocserv Requirements

This directory contains structured, testable requirements derived from the
ocserv implementation and from the protocols ocserv must interoperate with
(OpenConnect, Cisco AnyConnect). It complements `doc/design.md`:

- **`doc/design.md`** — narrative description of *how* ocserv works
  (process model, IPC sequences, cookie lifecycle).
- **`doc/requirements/`** — normative description of *what must hold*,
  in atomic, testable statements with RFC 2119 keywords, source citations,
  and acceptance criteria.

Each requirement links back to the `design.md` section that explains the
context, and forward to the test (if any) that verifies it. When code,
design.md, and a requirement disagree, treat it as a `[REVIEW]` item, not
as an automatic override — resolve by reading the cited source and, if
still unclear, ask a maintainer.

## Generation protocols

These documents are generated and maintained using the reasoning protocols
in `contrib/ai/protocols/`:

| Directory | Protocol | Produces |
|-----------|----------|----------|
| `internal/` | `requirements-from-implementation.md` | Requirements derived from current ocserv source: what each process (main, sec-mod, worker) and the IPC layer between them actually guarantee. |
| `protocol/sources/` | `requirements-elicitation.md` | Per-source requirement extractions (OpenConnect protocol draft, observed AnyConnect behavior). Working artifacts, not the final spec. |
| `protocol/unified.md` | `requirements-reconciliation.md` | A single reconciled wire-protocol spec, merging `protocol/sources/*` with the `OCSERV` implementation and relevant TLS/DTLS RFCs, classifying agreement (UNIVERSAL/MAJORITY/DIVERGENT/EXTENSION). |

When adding to or updating a document, re-apply the protocol that generated
it — do not hand-write requirements in a different style than the rest of
the file.

## Document map

| Document | ID prefix | Process(es) | Sources |
|----------|-----------|-------------|---------|
| `internal/general.md` | `REQ-GEN-` | all (policy) | `AGENTS.md`, `doc/ocserv.8.md`, `doc/sample.config` |
| `internal/testing.md` | `REQ-GEN-TEST-` | all (policy) | `AGENTS.md`, `tests/meson.build`, `tests/common.sh` |
| `internal/ipc.md` | `REQ-IPC-` | all (cross-process) | `src/ipc.proto`, `src/ctl.proto`, `doc/design.md#ipc-communication*` |
| `internal/config.md` | `REQ-CONFIG-` | all (cross-process) | `src/config.c`, `src/config-ports.c`, `src/config-kkdcp.c`, `src/subconfig.c`, `src/sup-config/file.c`, `src/cfg.proto`, `src/vpn.h`, `src/vhost.h`, `doc/sample.config`, `tests/check-config-scope.py`, `tests/config-inherit.c` |
| `internal/sec-mod.md` | `REQ-SECMOD-` | sec-mod | `src/sec-mod*.c`, `src/sec-mod-auth.h`, `src/auth/*`, `src/acct/*` |
| `internal/authentication.md` | `REQ-AUTH-` | sec-mod (primary), worker, main | `src/sec-mod-auth.{c,h}`, `src/auth/*`, `src/acct/*`, `src/config.c`, `src/subconfig.c`, `src/worker-auth.c`, `doc/sample.config` |
| `internal/main.md` | `REQ-MAIN-` | main | `src/main.c`, `src/main-*.c` |
| `internal/worker.md` | `REQ-WORKER-` | worker | `src/worker.c`, `src/worker-*.c` |
| `protocol/sources/openconnect.md` | `OC-PROTO-` | n/a (external spec) | `~/projects/openconnect/protocol/draft-openconnect.xml` |
| `protocol/sources/anyconnect.md` | `AC-CLIENT-` | n/a (observed client behavior) | `doc/README-cisco-svc.md`, worker CSTP/HTTSP handling |
| `protocol/unified.md` | `REQ-PROTO-` | worker (mostly) | reconciles `OC-PROTO-*`, `AC-CLIENT-*`, RFC-TLS/RFC-DTLS, `OCSERV` (= `internal/worker.md` + code) |

`internal/ipc.md` is generated first — the other `internal/*` documents cite
its `REQ-IPC-*` entries wherever a behavior crosses a process boundary,
instead of restating the IPC contract.

## ID scheme

```
REQ-<PREFIX><CATEGORY>-<NNN>
```

- `<PREFIX>` identifies the document (table above); `IPC` has no
  further category — IDs are `REQ-IPC-NNN`, grouped by message name in
  the document body.
- `<CATEGORY>` for `internal/general.md` uses: `SEC`, `TECH`, `STYLE`,
  `COMPAT` (cross-cutting policy categories; see that file's frontmatter
  for definitions). `internal/testing.md` uses `TEST`, under the same
  `REQ-GEN` prefix — it is a separate document because it governs test
  authorship for every other document, not because it is a different kind
  of policy.
- `<CATEGORY>` for other `internal/*` documents uses the tags from
  `requirements-from-implementation.md`: `INIT`, `AUTH`, `ACCT`,
  `SESSION`, `CFG`, `NET`, `SEC`, `ERR`, `TEARDOWN`.
- `<CATEGORY>` for `protocol/unified.md` uses the tags from
  `requirements-reconciliation.md`: `CONN`, `AUTH`, `SESSION`, `DATA`,
  `CTRL`, `CFG`, `COMPAT`, `SEC`, `EXT`.
- `<NNN>` is a 3-digit sequence number, unique within
  `<PREFIX><CATEGORY>` and never reused (if a requirement is removed,
  mark it `WITHDRAWN`, do not renumber).

Examples: `REQ-AUTH-AUTH-001`, `REQ-WORKER-NET-003`, `REQ-IPC-014`,
`REQ-PROTO-COMPAT-002`.

`protocol/sources/*.md` use their own non-normative working IDs
(`OC-PROTO-<CAT>-<NNN>`, `AC-CLIENT-<CAT>-<NNN>`) — these are inputs to
`unified.md` and are not cited from `internal/*`.

## Status legend

Every requirement carries a `Status`:

| Status | Meaning |
|--------|---------|
| `DERIVED` | Directly supported by current code/spec; no open questions. |
| `REVIEW` | Behavior observed but contradicts documentation, another requirement, or looks like a possible defect — needs a maintainer decision. |
| `AMBIGUOUS` | Cannot be classified as essential/incidental without domain knowledge; two interpretations given. |
| `UNDOCUMENTED` | Behavior exists in code with no doc, test, or evident purpose. |
| `WITHDRAWN` | Previously published requirement no longer applies; kept for ID stability, with a note explaining why. |

`protocol/unified.md` additionally carries a `Class` per
`requirements-reconciliation.md`: `UNIVERSAL`, `MAJORITY`, `DIVERGENT`,
`EXTENSION`.

## Per-requirement format

```markdown
### REQ-<PREFIX><CAT>-<NNN>
**Requirement:** <system/process> MUST/SHOULD/MAY <behavior> when
<condition>, so that <rationale>.
**Strength:** MUST | SHOULD | MAY | MUST NOT | SHOULD NOT
**Status:** DERIVED | REVIEW | AMBIGUOUS | UNDOCUMENTED | WITHDRAWN
**Source:** <file>:<line> [, ...] ; doc/design.md#<section>
**Acceptance:** <test path or description> — positive|negative|unit ;
  local | CI (root/full stack)
**Links:** <other REQ-IDs this depends on or relates to>
```

For `protocol/unified.md`, add **Class** and, for non-UNIVERSAL entries,
**Divergence:** describing what differs between sources and why.

## Document frontmatter

Each requirements document opens with:

```yaml
---
title: <short title>
generator: requirements-from-implementation | requirements-elicitation | requirements-reconciliation
process: main | sec-mod | worker | ipc | n/a
id-prefix: REQ-<PREFIX>
sources:
  - <file or glob>
  - doc/design.md#<section>
---
```

## Conventions carried over from `contrib/ai/protocols/`

- **Negative requirements are mandatory for `SEC`, `AUTH`, and `IPC`**
  categories — write the MUST NOT before the MUST.
- **Privilege boundary violations are never `[UNDOCUMENTED]` or
  incidental** — they are `SEC` requirements, always essential.
- **IPC acceptance criteria must cite protobuf field names** from
  `src/ipc.proto` / `src/ctl.proto`, not vague descriptions.
- **Normative language uses RFC 2119 keywords only** — MUST, MUST NOT,
  SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY, REQUIRED, RECOMMENDED,
  OPTIONAL. Informal equivalents ("needs to," "has to," "can," "will")
  MUST NOT be used to express a normative obligation in requirement prose.

## Glossary

Canonical definitions for terms that are ambiguous across ocserv's own
documentation and code. A requirement MUST NOT redefine a term listed here;
if a requirement needs a meaning not covered below, add it here first, then
cite it. New entries are added the first time a term is flagged during the
Ambiguity Detection phase of `requirements-elicitation.md` or by
`contrib/ai/protocols/prompt-determinism-analysis.md`.

| Term | Definition |
|------|------------|
| session | Disambiguate per use: a **TLS/DTLS session** (GnuTLS session object, resumable via session tickets); a **VPN session** (the authenticated user's SID and lease, spanning reconnects/roaming); or a **PAM session** (`pam_open_session`/`pam_close_session`). A requirement using "session" unqualified MUST specify which. |
| connection | One TCP/UDP socket-level attachment to a single worker process, bounded by that socket's lifetime. Distinct from a **session** (above): a VPN session can span multiple connections via cookie resumption (`doc/design.md`, "IPC Communication for SID assignment": "client/worker may disconnect and reconnect, using SID cookie to resume the authenticated session"). |
| secure | Not a standalone property. Always state the concrete guarantee meant: encrypted transport, authenticated peer, integrity-protected, or a specific cipher/version floor (e.g. "TLS 1.2 or later"). |
| reload | A `SIGHUP`-triggered live config reload (main/sec-mod only, requires procfs — REQ-GEN-COMPAT-001), distinct from a full process restart. Check `doc/sample.config`'s `[reload]`/`[not-reloadable]` annotation for the specific option before using this term. |
| worker / client | "Worker" is always the ocserv worker process; "client" is always the remote OpenConnect/AnyConnect endpoint. Never use one to mean the other, even informally — they sit on opposite sides of the privilege/trust boundary. |
| security module (sec-mod) | The `sec-mod` process. `doc/design.md` uses "security module" and "sec-mod" interchangeably for the same root process that holds private keys, PAM/RADIUS state, and session/SID state (`src/sec-mod*.c`). Not an external HSM or a generic security concept. |
| cookie | The SID-bound authentication ticket issued by sec-mod on successful auth, forwarded via `AUTH_COOKIE_REQ`/`AUTH_COOKIE_REP`, valid for `cookie-timeout`, and used to resume a session across reconnects. `doc/design.md` also calls this a "ticket." Not a generic HTTP `Set-Cookie` value, even though it travels over HTTPS. |
| SID vs. safe_id | The **SID** is the internal session identifier assigned by sec-mod on `SEC_AUTH_INIT` and used directly in IPC (`src/ipc.proto`, `src/ctl.proto`) and as cookie material; treat it as sensitive. **safe_id** is `base64(SHA1(SID))` (`calc_safe_id()`, `src/common/common.c`), a one-way, non-reversible derivation used wherever a session must be referenced externally without exposing the SID: `occtl` session listing/termination, logs, and RADIUS accounting (`PW_ACCT_SESSION_ID`, `src/acct/radius.c`). A requirement or acceptance criterion MUST say which one it means — they are not interchangeable, and safe_id cannot be reversed to recover the SID. |
| accounting | Post-authentication usage/session data reporting (RADIUS accounting, `src/acct/`) forwarded by sec-mod. Distinct from PAM **account management** (`pam_acct_mgmt`), which is an authorization check performed during login, not usage reporting — `doc/design.md`'s "Gatekeeper for accounting information keeping and reporting" refers to the former. |

## Dependencies

External/optional build dependencies that make some requirements
conditionally inapplicable. Format:

```markdown
### DEP-<NNN>
**Dependency:** <build option / library>
**Required by:** <REQ-ID(s) or document>
**Impact if unavailable:** <what becomes inapplicable or degraded>
```

### DEP-001
**Dependency:** seccomp (`-Dseccomp`, auto-detected)
**Required by:** REQ-GEN-SEC-002(d)
**Impact if unavailable:** the worker runs without syscall confinement;
the privilege-boundary requirement's process-separation intent still
holds, but this specific enforcement mechanism is absent and MUST be
called out in deployment documentation as reduced defense-in-depth.

### DEP-002
**Dependency:** PAM (`-Dpam`, auto-detected)
**Required by:** PAM-backed entries in `internal/authentication.md`
**Impact if unavailable:** those entries are not applicable to the build;
authentication falls back to other configured modules (plain, RADIUS,
GSSAPI, OIDC).

### DEP-003
**Dependency:** RADIUS (`-Dradius`, auto-detected)
**Required by:** RADIUS-backed entries in `internal/authentication.md`
**Impact if unavailable:** those entries are not applicable to the build.
