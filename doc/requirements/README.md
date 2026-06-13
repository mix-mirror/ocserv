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
- `<CATEGORY>` for `internal/*` documents uses the tags from
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
