---
title: Unified OpenConnect/AnyConnect wire-protocol requirements for ocserv
generator: requirements-reconciliation
process: worker
id-prefix: REQ-PROTO
sources:
  - doc/requirements/protocol/sources/openconnect.md (OC-PROTO-*)
  - doc/requirements/protocol/sources/anyconnect.md (AC-CLIENT-*)
  - RFC 8446 (TLS 1.3) / RFC 5246 (TLS 1.2) (RFC-TLS)
  - RFC 9147 (DTLS 1.3) / RFC 6347 (DTLS 1.2) (RFC-DTLS)
  - doc/requirements/internal/worker.md + src/worker*.c (OCSERV)
---

# Unified wire-protocol requirements

This document applies Phases 1-6 of `requirements-reconciliation.md` to merge
`OC-PROTO-*` (generic OpenConnect protocol draft), `AC-CLIENT-*` (observed
Cisco AnyConnect / IP-Phone behavior), the relevant TLS/DTLS RFCs (`RFC-TLS`,
`RFC-DTLS`), and current ocserv behavior (`OCSERV`, drawn from
`internal/worker.md` and direct source inspection of `src/worker-vpn.c`,
`src/worker-auth.c`, `src/worker-http.c`, `src/config.c`, `src/vpn.h`).

No source is authoritative. Each requirement below carries a **Class**
(UNIVERSAL / MAJORITY / DIVERGENT / EXTENSION) per Phase 3, and non-UNIVERSAL
entries carry a **Divergence** note per Phase 4/5.

---

## Phase 1: Source inventory

| Source | Origin | Requirement count | ID scheme | Keyword mix |
|--------|--------|-------------------|-----------|-------------|
| `OC-PROTO` | `protocol/sources/openconnect.md` | 23 | `OC-PROTO-<CAT>-<NNN>` | mostly MUST, several SHOULD/RECOMMENDED, one MUST NOT (SEC-001) |
| `AC-CLIENT` | `protocol/sources/anyconnect.md` | 19 | `AC-CLIENT-<CAT>-<NNN>` | mostly MUST (build/config-conditional); 2 documentation-only MUSTs (SEC-010/011) |
| `RFC-TLS` | RFC 8446 / RFC 5246 | not separately enumerated | n/a | incorporated by reference only (OC-PROTO-SEC-002) |
| `RFC-DTLS` | RFC 9147 / RFC 6347 | not separately enumerated | n/a | incorporated by reference only (OC-PROTO-SEC-002, DATA-004) |
| `OCSERV` | `internal/worker.md` + `src/worker*.c`, `src/config.c`, `src/vpn.h` | n/a (queried ad-hoc per alignment row) | `REQ-WORKER-*` | current implementation behavior |

### Coverage matrix

| Functional Area | OC-PROTO | AC-CLIENT | RFC-TLS/DTLS | OCSERV |
|------------------|----------|-----------|--------------|--------|
| TLS channel setup | ✓ | ○ | ✓ (by ref) | ✓ |
| DTLS channel setup | ✓ | ○ | ✓ (by ref) | ✓ |
| CSTP auth exchange | ✓ | ✓ | ✗ | ✓ |
| Cookie / session resumption | ✓ | ✓ | ○ | ✓ |
| IP/route configuration push | ✓ | ✓ | ✗ | ✓ |
| Keepalive / dead-peer detection | ✓ | ✗ | ✗ | ✓ |
| Session teardown | ✓ | ✓ | ✗ | ✓ |
| Client identification / compat shaping | ✗ | ✓ | ✗ | ✓ |
| Management/extension features (occtl etc.) | ✗ | ✗ | ✗ | ✓ |

---

## CONN — TLS/DTLS connection establishment

### REQ-PROTO-CONN-001
**Requirement**: The server MUST refuse TLS versions below 1.2 for the initial
HTTPS connection (the client SHOULD offer 1.2+).
**Class**: MAJORITY
**Strength**: SHOULD (OC-PROTO, client-side) / MUST (OCSERV, server-enforced via
default `tls-priorities`)
**Source mapping**: OC-PROTO-CONN-001; OCSERV `doc/sample.config` default
`tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1"`
(`src/config.c` `tls-priorities` parsing).
**Acceptance**: with the documented default `tls-priorities`, a TLS 1.0/1.1
ClientHello MUST be rejected at the handshake; TLS 1.2+ MUST succeed.
**Divergence**: OC-PROTO leaves the floor to client/server policy (SHOULD); the
default ocserv configuration makes this a hard MUST by excluding TLS1.0/1.1 from
its default priority string. An administrator can still override
`tls-priorities` to re-permit older versions (e.g. for legacy IP-Phones per
AC-CLIENT-SEC-010/011, which do not themselves require a TLS downgrade — only a
cipher restriction). `[SEC-RISK if overridden]`: any administrator override that
re-enables TLS < 1.2 lowers the floor below the MAJORITY default and should be
flagged in `doc/ocserv.8.md` as reducing security.
**Links**: AC-CLIENT-SEC-010 (cipher restriction, not version downgrade)

### REQ-PROTO-CONN-002
**Requirement**: The server MUST select the virtual host configuration based on
the SNI extension of the TLS ClientHello when present, and MUST fall back to a
default virtual host when SNI is absent or does not match a configured vhost.
**Class**: UNIVERSAL
**Strength**: MUST
**Source mapping**: OC-PROTO-CONN-002 (SHOULD, client sends SNI); OCSERV
REQ-WORKER-NET-001 (`hello_hook_func`, `find_vhost`, default-vhost fallback) —
the server-side behavior is unconditional (MUST) regardless of the client-side
SHOULD.
**Acceptance**: connecting with SNI matching a configured vhost selects that
vhost's credentials/config; connecting with no SNI, or SNI matching no vhost,
selects the default vhost and `SET_VHOST_CREDS` is still called (no crash/hang).
**Links**: REQ-WORKER-NET-001

### REQ-PROTO-CONN-003
**Requirement**: After TLS establishment, the client MUST send an HTTP POST to
`/` (or `/auth`, `/VPN` — ocserv-recognized aliases) with a `config-auth` XML
body of `type="init"`, and the server MUST treat this as the start of the
authentication sequence regardless of which auth method(s) are configured.
**Class**: UNIVERSAL
**Strength**: MUST
**Source mapping**: OC-PROTO-CONN-003; OCSERV `known_urls[]` registers `/`,
`/auth`, `/VPN` all to `get_auth_handler`/`post_auth_handler`
(`src/worker-http.c`).
**Acceptance**: POST to `/`, `/auth`, or `/VPN` with `type="init"` body all
produce an equivalent `auth-request`/`complete` response sequence.
**Links**: OC-PROTO-AUTH-004

### REQ-PROTO-CONN-004
**Requirement**: Upon a `config-auth type="complete"` reply (auth success), the
client MUST issue `CONNECT /CSCOSSLC/tunnel HTTP/1.1` (or the Clavister-client
variant `CONNECT CSCOSSLC/tunnel` without leading slash) over the same TLS
connection to begin the CSTP channel. The Cisco IP-Phone family additionally has
a separate, parallel entry point at `/svc` (see REQ-PROTO-COMPAT-003) that does
not use this CONNECT step at all.
**Class**: MAJORITY
**Strength**: MUST (generic clients) / N/A (IP-Phone `/svc` path)
**Source mapping**: OC-PROTO-CONN-004; AC-CLIENT-COMPAT-010 (`/svc` as an
additional, gated entry point); OCSERV REQ-WORKER-NET-002 (`connect_handler`
accepts `/CSCOSSLC/tunnel` or `CSCOSSLC/tunnel` only, after cookie auth).
**Acceptance**: `CONNECT /CSCOSSLC/tunnel HTTP/1.1` after successful auth opens
the CSTP channel; `CONNECT` to any other path is rejected; `/svc` is reachable
only per AC-CLIENT-COMPAT-010's gating.
**Divergence**: the `/svc` path is an `OCSERV`/`AC-CLIENT`-only addition with no
analogue in `OC-PROTO`; it does not collapse into this requirement's CONNECT
step (see REQ-PROTO-COMPAT-003 for its own lifecycle).
**Links**: REQ-WORKER-NET-002, REQ-PROTO-COMPAT-003

### REQ-PROTO-CONN-005
**Requirement**: The CONNECT request MUST include `X-CSTP-Address-Type` and
`X-CSTP-Base-MTU`; it MAY include `X-CSTP-Accept-Encoding` and `User-Agent`. The
server MUST be able to parse a request lacking the optional headers without
error, and MUST use `User-Agent` (when present) for AC-CLIENT-COMPAT-001
client-family classification.
**Class**: UNIVERSAL
**Strength**: MUST (required headers) / MAY (optional headers), MUST (server
parses absence of optional headers gracefully)
**Source mapping**: OC-PROTO-CONN-005; AC-CLIENT-COMPAT-001 (`User-Agent`
classification table, `src/worker-http.c` lines ~410-477).
**Acceptance**: a CONNECT lacking `X-CSTP-Accept-Encoding`/`User-Agent` succeeds
with `user_agent_type == AGENT_UNKNOWN` and IPv6 advertised per
AC-CLIENT-CONN-003's `default:` branch.
**Links**: AC-CLIENT-COMPAT-001, AC-CLIENT-CONN-003

### REQ-PROTO-CONN-006
**Requirement**: After the server's CONNECT response, the TCP connection
becomes the CSTP channel; the server MUST NOT send any further HTTP-framed
data, and MUST treat all subsequent bytes from the client as CSTP frames
(8-byte header + payload, REQ-PROTO-DATA-001).
**Class**: UNIVERSAL
**Strength**: MUST
**Source mapping**: OC-PROTO-CONN-006 (flagged `[Missing conditional branch]` —
draft does not specify receiver behavior for non-CSTP bytes); OCSERV
`parse_cstp_data` (`src/worker-vpn.c:2851`) requires every read to begin with the
8-byte `STF\x01...\x00` header (REQ-PROTO-DATA-001) and returns -1 (closing the
connection) otherwise — this *is* ocserv's answer to OC-PROTO-CONN-006's open
question.
**Acceptance**: any bytes received on the CSTP TCP stream after the CONNECT
response that do not begin with `0x53 0x54 0x46 0x01` cause `parse_cstp_data` to
return -1 and the worker to log "can't recognise CSTP header" and close the
connection (no silent resync, no HTTP fallback).
**Divergence**: OC-PROTO leaves this unspecified (gap); OCSERV resolves it with
a hard-fail. This is recorded as MAJORITY-by-resolution rather than UNIVERSAL
because the *spec itself* does not mandate this — but no alternative behavior is
known from any source, so there is nothing to diverge against in practice.
**Links**: REQ-PROTO-DATA-001

### REQ-PROTO-CONN-007
**Requirement**: The server's CONNECT response MAY include any of
`X-CSTP-Address`, `X-CSTP-Netmask`, `X-CSTP-Address-IP6`, `X-CSTP-DNS{,-IP6}`,
`X-CSTP-Default-Domain`, `X-CSTP-Split-DNS`, `X-CSTP-Split-Include{,-IP6}`,
`X-CSTP-Split-Exclude`, `X-CSTP-Base-MTU`, `X-CSTP-DynDNS`,
`X-CSTP-Content-Encoding`, `X-DTLS-Content-Encoding`; the absence of
`X-CSTP-Split-Include*` MUST be interpreted by the client as "route the default
route through the VPN."
**Class**: MAJORITY
**Strength**: MUST (default-route inference) / individual headers are each
conditionally present
**Source mapping**: OC-PROTO-CONN-007; AC-CLIENT-CONN-002 (DNS header name
choice depends on `user_agent_type`, see REQ-PROTO-CFG-002); OCSERV
`src/worker-vpn.c` (`send_routes`, `ws->default_route`, `ws->user_config->tunnel_all_dns`).
**Acceptance**: with no routes configured and `default_route` true, no
`X-CSTP-Split-Include*` header is sent and the client tunnels all traffic.
**Divergence**: the *choice of DNS header name* (`X-CSTP-DNS` vs
`X-CSTP-DNS-IP6`) for IPv6 entries is AnyConnect-vs-OpenConnect divergent — see
REQ-PROTO-CFG-002 for the dedicated entry. The "/127 for IPv6, server-address-
first for IPv4" RECOMMENDED conventions from OC-PROTO-CONN-007's Notes were
**not verified** against `src/ip-lease.c` in this pass — `[REVIEW]`: confirm
`ip-lease.c`'s allocation order against these SHOULD-strength conventions in a
follow-up.
**Links**: REQ-PROTO-CFG-001, REQ-PROTO-CFG-002, REQ-MAIN-NET-001

---

## AUTH — Authentication exchange

### REQ-PROTO-AUTH-001
**Requirement**: The server MUST present an X.509 certificate during the TLS
handshake to authenticate itself to the client; the certificate's SAN SHOULD
contain a `dNSName` matching the connection hostname.
**Class**: UNIVERSAL
**Strength**: MUST / SHOULD (SAN dNSName)
**Source mapping**: OC-PROTO-AUTH-001; OCSERV (per-vhost cert configuration,
`SET_VHOST_CREDS`).
**Acceptance**: TLS handshake fails if the server cannot present a configured
certificate; standard TLS client behavior validates the SAN against the SNI
hostname.

### REQ-PROTO-AUTH-002
**Requirement**: The protocol permits client authentication via password,
X.509 certificate, HTTP SPNEGO, or combinations thereof; any other
authentication mechanism (e.g. browser-redirect OIDC) is an `OCSERV` extension
layered on top of the "password" exchange shape (REQ-PROTO-AUTH-004).
**Class**: MAJORITY
**Strength**: MAY (protocol permits all three; deployment-specific)
**Source mapping**: OC-PROTO-AUTH-002; OCSERV `auth_mod_st` vtable
(`internal/sec-mod.md`), supporting PAM, RADIUS, OIDC, plain, GSSAPI.
**Acceptance**: each configured `auth =` backend ultimately resolves to one of
{password-shaped (PAM/RADIUS/plain/OIDC), certificate, SPNEGO/GSSAPI} from the
client's perspective.
**Divergence**: OIDC's browser-redirect flow does not literally match
OC-PROTO's `auth-request`/`auth-reply` form exchange (it likely embeds a URL the
client must open out-of-band). `[CANDIDATE for follow-up]`: classify ocserv's
OIDC module as **EXTENSION** with its own `REQ-PROTO-AUTH-0XX` once
`internal/sec-mod.md`'s OIDC coverage and `doc/README-oidc.md` are reconciled —
not done in this pass (out of scope: OIDC module internals were not read).
**Links**: REQ-PROTO-AUTH-004

### REQ-PROTO-AUTH-003
**Requirement**: Clients SHOULD complete authentication within a single TLS
session and rely on TLS session resumption (not a fresh connection with
re-sent credentials) for reconnection. `OCSERV` additionally binds the
authenticated session to connection parameters via an HMAC
(`sec_auth_init_hmac` over `remote_ip`/`our_ip`/`session_start_time`) as a
defense for clients that do split connections.
**Class**: MAJORITY
**Strength**: SHOULD (single-session) / SHOULD NOT (split-connection auth) /
MUST (OCSERV HMAC anti-replay, when present)
**Source mapping**: OC-PROTO-AUTH-003; OCSERV REQ-IPC-010
(`sec_auth_init_hmac`), REQ-WORKER-SEC-003 (DTLS-PSK from CSTP TLS session).
**Acceptance**: a fresh `SEC_AUTH_INIT` always carries a valid
`sec_auth_init_hmac`; `SEC_AUTH_CONT` for multi-round auth reuses the SID from
the prior `SEC_AUTH_REP`.
**Divergence**: OC-PROTO's RFC 5056 channel-binding rationale is about
preventing credential-splitting attacks across connections; `OCSERV`'s HMAC
scheme binds the *sec-mod-issued SID* to connection metadata, which mitigates
replay but is **not** shown to be a full substitute for TLS-level channel
binding (RFC 5056) for a client that genuinely splits TLS connections.
`[REVIEW]`: this gap was flagged in OC-PROTO-AUTH-003's Notes and remains open —
requires a maintainer/security-reviewer judgment, not a code-reading answer.
**Links**: REQ-IPC-010, REQ-WORKER-SEC-003

### REQ-PROTO-AUTH-004
**Requirement**: For password (and password-shaped) authentication, the server
MUST present `config-auth type="auth-request"` form(s); the client MUST POST
`type="auth-reply"` to the form's `action` URL; the server MAY repeat this for
multiple rounds (e.g. second-factor) before returning `type="complete"` (success)
or HTTP 401 (REQ-PROTO-AUTH-005, failure).
**Class**: UNIVERSAL
**Strength**: MUST (shapes) / MAY (round count)
**Source mapping**: OC-PROTO-AUTH-004; OCSERV REQ-IPC-015/016 (`SEC_AUTH_CONT`
multi-round), REQ-AUTH-AUTH-002; AC-CLIENT-AUTH-011 (`/svc` performs the same
`SEC_AUTH_INIT`/`SEC_AUTH_CONT` shape over a form POST rather than config-auth
XML).
**Acceptance**: a 2-factor auth module produces two sequential
`auth-request`/`auth-reply` rounds before `type="complete"`; `/svc`'s
single-round username+password POST produces the same `SEC_AUTH_INIT` →
`SEC_AUTH_CONT` → `SEC_AUTH_REP(OK)` IPC sequence as a single-round `/auth` flow.
**Links**: REQ-IPC-015, REQ-IPC-016, REQ-AUTH-AUTH-002, AC-CLIENT-AUTH-011

### REQ-PROTO-AUTH-005
**Requirement**: On client-authentication failure, the baseline server response
is HTTP 401 with `config-auth`/empty body, and the connection MAY remain open
for the client to retry. `OCSERV`'s `/svc` (IP-Phone) path returns a literal
`401 Authentication failed` body but additionally terminates the worker process
(`exit_worker`) rather than permitting further rounds.
**Class**: DIVERGENT
**Strength**: MUST (OC-PROTO: 401, retry permitted) / MUST (OCSERV `/svc`: 401 +
immediate worker exit, no retry)
**Source mapping**: OC-PROTO-AUTH-005; AC-CLIENT-AUTH-012; OCSERV
REQ-WORKER-AUTH-004.
**Divergence (categorize per Phase 4)**: this is a **behavioral disagreement**
(connection lifecycle after "the same condition," auth failure), gated to
`cisco-svc-client-compat` + `AGENT_SVC_IPPHONE`:
  - **Most RFC-compliant / most interoperable with generic OpenConnect clients**:
    plain HTTP 401 with `config-auth`/empty body, connection may remain open for
    retry (default, non-`/svc` path) — matches OC-PROTO-AUTH-005 exactly.
  - **Current ocserv behavior (`/svc`)**: HTTP 401 (matches OC-PROTO) but
    followed by `exit_worker()` — no retry on the same connection. This is
    **DIVERGENT from OC-PROTO-AUTH-004's "MAY repeat... an arbitrary number of
    times"** for the `/svc` path specifically (AnyConnect/OpenConnect clients on
    `/auth` are not subject to this).
**Interoperability impact**: a standard OpenConnect/AnyConnect client never hits
the `/svc` path (gated to `AGENT_SVC_IPPHONE`), so **no impact on mainline
clients**. `[REVIEW]` whether real Cisco IP-Phones ever retry `/svc` POSTs after
a 401, since ocserv's current behavior precludes it.
**Note**: `OCSERV`'s separate `camouflage` feature (REQ-PROTO-COMPAT-006) can
additionally substitute `404`/`401 + WWW-Authenticate` (pre-authentication) or
`405` (cookie-authentication failure) for the responses described here. That
feature is independently configured (`camouflage = true`, vhost-scoped) and
opt-in, with its own contract and rationale — it is documented as its own
EXTENSION rather than as a variant of this entry's baseline.
**Links**: REQ-WORKER-AUTH-004, AC-CLIENT-AUTH-012, REQ-PROTO-COMPAT-006

### REQ-PROTO-AUTH-006
**Requirement**: Clients SHOULD pad authentication XML bodies to a multiple of
64 bytes via `X-Pad`; the server has no corresponding requirement beyond
tolerating the header.
**Class**: EXTENSION (from the server's perspective — purely a client-side
mitigation that the server passively tolerates)
**Strength**: SHOULD (client) / (no server-side strength — informational)
**Source mapping**: OC-PROTO-AUTH-006.
**Status**: `[REVIEW — unresolved]`: this pass did not locate explicit
`X-Pad` handling in `src/worker-http.c`'s header table; if `X-Pad` is an
unrecognized header it falls into ocserv's generic "unknown header" path. Given
HTTP header parsing via `llhttp` with bounded buffers (per `internal/worker.md`
MAX_HTTP_REQUESTS / header-size notes), an oversized `X-Pad` should be bounded by
the same limits as any other header — but this was **not verified** in this
reconciliation pass.
**Acceptance**: `[OPEN]` — a request with a large `X-Pad` header (up to the
configured/llhttp header-size limit) should not cause a parse error or
disproportionate resource use; needs a dedicated test.
**Links**: `internal/worker.md` HTTP header-size completeness notes

### REQ-PROTO-AUTH-007
**Requirement**: For certificate authentication, the server MUST request a
client certificate during the TLS handshake. Certificates SHOULD NOT carry
identifying information beyond a username/pseudonym, conventionally placed in
the DN's UID attribute (OID 0.9.2342.19200300.100.1.1); `OCSERV` generalizes this
into a configurable `cert-user-oid`, including a non-DN extraction mode
`SAN(rfc822name)` not present in the draft.
**Class**: MAJORITY
**Strength**: MUST (request cert) / SHOULD NOT (extraneous info) / RECOMMENDED
(UID OID, generalized by OCSERV)
**Source mapping**: OC-PROTO-AUTH-007; OCSERV REQ-AUTH-AUTH-008/009
(`get_cert_username`, `cert-user-oid`), REQ-AUTH-AUTH-005 (sec-mod
re-derivation, defense-in-depth).
**Acceptance**: with `cert-user-oid` set to the RFC 4519 UID OID (the draft's
RECOMMENDED default), behavior matches OC-PROTO-AUTH-007 exactly; with
`cert-user-oid = SAN(rfc822name)`, ocserv extracts the username from the
certificate's `rfc822Name` SAN entry instead — an `OCSERV`-only extension point.
**Divergence**: the `SAN(rfc822name)` mode is **EXTENSION**-classified within
this otherwise-MAJORITY entry — it does not contradict the draft, it adds an
option the draft does not mention.
**Links**: REQ-AUTH-AUTH-008, REQ-AUTH-AUTH-009, REQ-AUTH-AUTH-005

### REQ-PROTO-AUTH-008
**Requirement**: On successful certificate-based authentication, the server
MUST reply HTTP 200 `config-auth type="complete"` directly (no
`auth-request`/`auth-reply` round trip), identical in shape to the
password-success terminal state; the client then proceeds to CONNECT
(REQ-PROTO-CONN-004).
**Class**: UNIVERSAL
**Strength**: MUST
**Source mapping**: OC-PROTO-AUTH-008; AC-CLIENT-CONN-001 (the *body content* of
this 200 response differs for `AGENT_OPENCONNECT_V3` — see that entry — but the
*shape*, "200 + complete, then CONNECT," is unaffected).
**Acceptance**: a valid client certificate alone (no password round) reaches
`config-auth type="complete"` and a subsequent CONNECT succeeds.
**Links**: REQ-PROTO-CONN-004, REQ-PROTO-COMPAT-002 (AGENT_OPENCONNECT_V3 body)

### REQ-PROTO-AUTH-009
**Requirement**: A client supporting SPNEGO MUST send `X-Support-HTTP-Auth: true`
on its `init` POST; the server then responds 401 and SPNEGO/Kerberos negotiation
proceeds per RFC 4559. The server MAY send
`X-Support-HTTP-Auth: fallback` to indicate other methods remain available after
a SPNEGO failure.
**Class**: MAJORITY
**Strength**: MUST (signaling) / MAY (fallback) / SHOULD (client retry)
**Source mapping**: OC-PROTO-AUTH-009; OCSERV GSSAPI auth module
(`internal/sec-mod.md`, not detailed).
**Status**: `[UNVERIFIED]` — whether ocserv's GSSAPI module emits
`X-Support-HTTP-Auth: fallback` correctly when GSSAPI fails and another module is
configured was **not traced** in this pass (GSSAPI module internals out of
scope for `internal/worker.md`).
**Acceptance**: `[OPEN]` — requires a GSSAPI + fallback-auth test configuration.
**Links**: `internal/sec-mod.md` GSSAPI module

### REQ-PROTO-AUTH-010
**Requirement**: When `n_group_list > 0` is configured, the server's
`auth-request` form MUST present a `<select name="group_list">` element
enumerating the configured groups (using `friendly_group_list` display names
where present), and the server MUST, on `auth-reply`, resolve the submitted
group value back to its canonical `group_list[i]` entry (matching either the
canonical name or the friendly name) before proceeding; an unresolvable group
value MUST NOT be silently accepted.
**Class**: EXTENSION
**Strength**: MUST (when groups are configured)
**Source mapping**: OC-PROTO's `config-auth.dtd` documents `<select
name="group_list">` syntactically but the prose never describes its semantics
(flagged `[UNDOCUMENTED in the prose]` in OC-PROTO's completeness notes); OCSERV
`src/worker-auth.c` `append_group_idx`/`append_group_str`/`resolve_selected_group`
(lines ~160-240) implement the full semantics: building the `<option>` list and
resolving the client's selection.
**Acceptance**: with `select-group`/group-list configured, the `auth-request`
form contains one `<option value="...">...</option>` per configured group
(friendly name as label if configured); submitting a value matching either a
canonical or friendly group name resolves (`resolve_selected_group` returns 1);
submitting an unrecognized value when `n_group_list > 0` returns 0 (caller must
reject — `[REVIEW]`: confirm the caller of `resolve_selected_group` actually
rejects a 0 return rather than proceeding with an empty/default group, as this
is a SEC-relevant negative path per the README's "negative requirements are
mandatory for AUTH" convention).
**Links**: `internal/worker.md` (group selection, previously flagged as needing
its own elicitation)

### REQ-PROTO-AUTH-011
**Requirement**: When `cisco_client_compat = true`, the worker's
`auth_cookie()` MUST skip its normal pre-check (requiring
`ws->cert_auth_ok != 0` and a successful `get_cert_info()`) before forwarding
`AUTH_COOKIE_REQ` to main, even if certificate authentication was the selected
method. When `cisco_client_compat = false` (default), this pre-check MUST be
enforced and a failing check MUST cause `auth_cookie()` to return -1.
**Class**: DIVERGENT
**Strength**: MUST (both branches, mutually exclusive on the config flag)
**Source mapping**: AC-CLIENT-AUTH-020; OCSERV `src/worker-auth.c` lines
1066-1085 (REQ-AUTH-AUTH-007/008).
**Divergence (Phase 4 categorization)**: **presence disagreement** — the default
configuration requires a worker-side check that the `cisco_client_compat = true`
configuration explicitly omits, for the same certificate-auth code path.
- **Most conservative / most RFC-compliant**: always enforce the worker-side
  pre-check (`cisco_client_compat = false` behavior) — defense-in-depth, costs
  nothing for compliant clients.
- **Most interoperable with AnyConnect-family clients requiring this flag**:
  `cisco_client_compat = true` — relies entirely on sec-mod's independent
  re-verification (REQ-AUTH-AUTH-005) as the security boundary.
- **Current ocserv behavior**: configurable, defaults to the conservative option.
**[SEC-RISK] flag**: per AGENTS.md, "cookie or SID handling changes" require
human judgment — this entry is recorded as DIVERGENT and **must not be
"resolved"** by this document; any future change to the default or to
`cisco_client_compat`'s scope must be flagged to a maintainer.
**Links**: REQ-AUTH-AUTH-007, REQ-AUTH-AUTH-008, REQ-AUTH-AUTH-005

---

## DATA — CSTP/DTLS framing

### REQ-PROTO-DATA-001
**Requirement**: Every CSTP frame MUST consist of an 8-byte header
(`0x53 0x54 0x46 0x01`, 2-byte big-endian length, 1-byte type, `0x00`) followed
by exactly `length` bytes of payload, all within a single TLS record. A receiver
that observes a buffer not matching this header (wrong magic bytes, non-zero
byte 7, or a declared length not matching the bytes actually received) MUST
treat the connection as protocol-violating and close it.
**Class**: MAJORITY
**Strength**: MUST (framing) / MUST (OCSERV's resolution of the receiver
behavior on violation)
**Source mapping**: OC-PROTO-DATA-001 (framing MUST; receiver behavior on bad
magic flagged `[Vague/undefined term]`); OCSERV `parse_cstp_data`
(`src/worker-vpn.c:2851-2890`): checks `buf_size >= 8`, exact magic
`'S','T','F',1` and `buf[7]==0`, and `buf_size == 8 + pktlen`; any mismatch logs
at `LOG_INFO` and returns -1 (closes connection — confirmed: callers of
`parse_cstp_data` returning <0 lead to `exit_worker`/connection teardown per
`internal/worker.md`'s main I/O loop description).
**Acceptance (negative)**: a frame with `buf[0..3] != "STF\x01"`, or `buf[7] !=
0`, or a length field not matching the actual payload size, MUST cause the
connection to close with a logged "can't recognise CSTP header" /
"unexpected CSTP length" message — not a silent drop, not a resync attempt.
**Divergence**: classified MAJORITY rather than UNIVERSAL only because
OC-PROTO itself does not mandate the close-on-violation behavior (it is silent);
OCSERV's choice (close) is the only behavior on record from any source, so there
is no competing variant — this is "MAJORITY of 1 source that addresses the
question at all."
**Links**: REQ-PROTO-CONN-006

### REQ-PROTO-DATA-002
**Requirement**: The CSTP/DTLS payload type byte MUST be one of `0x00` (DATA),
`0x03` (DPD-REQ), `0x04` (DPD-RESP), `0x05` (DISCONNECT+reason),
`0x07` (KEEPALIVE), `0x08` (COMPRESSED DATA), `0x09` (TERMINATE,
server→client only). A receiver encountering any other type byte MUST NOT
terminate the connection or treat it as an error; it MUST log the event (at
debug level) and otherwise ignore the frame (return success / continue
processing).
**Class**: MAJORITY
**Strength**: MUST (enumeration) / MUST (OCSERV's resolution: ignore-and-log for
unknown types — this is the *opposite* choice from REQ-PROTO-DATA-001's
"close on bad header")
**Source mapping**: OC-PROTO-DATA-002 (enumeration MUST; receiver behavior for
unrecognized type flagged `[Missing negative requirement]`, noted as
security-relevant); OCSERV `parse_data`'s `default:` case
(`src/worker-vpn.c:2843-2846`): `oclog(ws, LOG_DEBUG, "received unknown packet
%u/size: %u", ...)` then falls through to `return 0` — the frame is silently
accepted (no error, no forward to TUN, no connection action).
**Acceptance (negative)**: sending a well-formed CSTP frame (correct 8-byte
header, correct length) with type byte `0x01`, `0x02`, `0x06`, or `>= 0x0a` MUST
NOT close the connection or produce an error response; the worker logs at
`LOG_DEBUG` and continues processing subsequent frames normally.
**Divergence**: this is the **opposite resolution** from REQ-PROTO-DATA-001
(malformed *header* → close; well-formed header with *unrecognized type* →
ignore). Both are internally consistent ocserv choices but the asymmetry is
worth documenting explicitly since OC-PROTO leaves both cases open. `[REVIEW /
SEC]`: the original elicitation flagged this as a "potential DoS or
parser-confusion vector" — having read the code, the actual behavior
(log-and-ignore, no allocation, no state change) does **not** appear to present
a DoS vector by itself; however, an attacker who can keep sending frames with
unknown types at `LOG_DEBUG` volume could fill logs if debug logging is enabled
in production — `[REVIEW]` whether `LOG_DEBUG` is rate-limited or whether this
matters (debug logging is not the production default).
**Links**: REQ-PROTO-DATA-001

### REQ-PROTO-DATA-003
**Requirement**: A DISCONNECT frame (type `0x05`) MUST carry exactly one reason
byte. `0xb0` (USER DISCONNECT) and `0x70` (LOCAL ERROR) MUST cause the server to
invalidate the session; `0xd1` (VPN PAUSE) and `0x91` (VPN RECONNECT), and any
reason byte not in `{0x70, 0x91, 0xb0, 0xd1}`, MUST be treated as "temporary
disconnect, session preserved" (`0x91`-equivalent). `OCSERV` only assigns
operational meaning to two of these codes — `AC_BYE_USER_DISCONNECT`
(`0xb0`) and `AC_BYE_VPN_RECONNECT` (`0x91`) — because these are the only two
distinctions ocserv's session model acts on (invalidate vs. preserve the
session, per `internal/sec-mod.md` REQ-SECMOD-SESSION-003). `0x70` (LOCAL
ERROR) and `0xd1` (VPN PAUSE) are recognized by ocserv maintainers as valid,
AnyConnect-originated codes, but have **no distinct equivalent** in ocserv's
two-way session model; by design they (and any other non-empty, unrecognized
reason byte) fall through to the same generic "bye with unhandled reason"
path as a true unknown byte.
**Class**: MAJORITY
**Strength**: MUST
**Source mapping**: OC-PROTO-DATA-003 (4-value enumeration + unknown→0x91
fallback); OCSERV REQ-IPC-033 (`REASON_SERVER_DISCONNECT`), REQ-SECMOD-SESSION-003
(`discon_reason`); `src/worker-vpn.c:2757-2783` (`AC_PKT_DISCONN` case): only
`AC_BYE_USER_DISCONNECT` → `exit_worker_reason(ws, REASON_USER_DISCONNECT)` and
`AC_BYE_VPN_RECONNECT` → `exit_worker_reason(ws, REASON_TEMP_DISCONNECT)` are
explicitly handled; any other non-empty reason byte (including `0x70`/`0xd1`)
is logged (hex dump at `LOG_DEBUG`, "bye packet with unknown payload") and
treated as a generic disconnect via `return -1`, which causes the worker to
tear down the connection — the same outcome class ("disconnect now") as
`REASON_TEMP_DISCONNECT`/`REASON_USER_DISCONNECT`, just without a distinct
`discon_reason` value attached.
**Acceptance (positive)**: DISCONNECT with reason matching `AC_BYE_USER_DISCONNECT`
→ session invalidated (`REASON_USER_DISCONNECT`); reason matching
`AC_BYE_VPN_RECONNECT`, or an **empty** reason payload (`plain_size == 0`,
falls through to `exit_worker_reason(ws, REASON_TEMP_DISCONNECT)` after the
switch) → session preserved (`REASON_TEMP_DISCONNECT`).
**Acceptance (intentional, by design)**: DISCONNECT with a non-empty reason byte
that is neither `AC_BYE_USER_DISCONNECT` nor `AC_BYE_VPN_RECONNECT` (e.g.
`0x70`/`0xd1` from OC-PROTO-DATA-003's table) is treated as a generic bye
message — logged and the connection torn down — rather than being routed
through the session-preserved (`0x91`-equivalent) path OC-PROTO-DATA-003
specifies. This is **confirmed intentional**: ocserv's session model has no
state distinct from "invalidate" / "preserve" for these codes, so collapsing
them into a default disconnect is the deliberate simplification, not an
oversight.
**Divergence (Phase 4 — value/strength disagreement, not a behavioral
conflict)**: OC-PROTO-DATA-003 requires unrecognized reason bytes to be treated
as `0x91` (session-preserved) specifically so a client intending a temporary
reconnect is not penalized; OCSERV's generic-disconnect handling for `0x70`/
`0xd1` does not preserve session state for those two named codes. In practice
the client-visible effect (connection ends, client may reconnect and
re-authenticate) is similar either way — the difference is whether the
*server-side* session/cookie is preserved across the disconnect. Classified
MAJORITY (not DIVERGENT) because this reflects a deliberate, accepted
simplification rather than disagreement requiring resolution.
**Resolution options (recorded for future reference, no action needed)**:
  - *Most RFC/OC-PROTO-compliant*: extend the switch in
    `src/worker-vpn.c:2767` to map `0x70`/`0xd1` onto
    `REASON_USER_DISCONNECT`/`REASON_TEMP_DISCONNECT` respectively, matching
    OC-PROTO-DATA-003 exactly.
  - *Current ocserv behavior (accepted)*: generic disconnect for `0x70`/`0xd1`
    and any other unrecognized reason byte — confirmed intentional per
    maintainer (2026-06-13); no change required.
**Links**: REQ-IPC-033, REQ-SECMOD-SESSION-003

### REQ-PROTO-DATA-004
**Requirement**: The DTLS channel uses a 1-byte header (same type-byte
enumeration as REQ-PROTO-DATA-002) followed by payload, one frame per DTLS
record. `OCSERV` processes CSTP and DTLS frames through the **same** dispatch
function (`parse_data`, `src/worker-vpn.c:2690+`), parameterized only by
`is_dtls` (which selects the 1-byte vs 8-byte header offset) — i.e. **all 7
payload types are valid and handled identically on both channels** in the
current implementation, including DISCONNECT and TERMINATE over DTLS.
**Class**: MAJORITY
**Strength**: MUST
**Source mapping**: OC-PROTO-DATA-004 (flagged `[AMBIGUOUS]` — draft does not
restate which types are valid over DTLS); OCSERV `parse_dtls_data`
(`src/worker-vpn.c:2892-2907`) calls the same `parse_data(ws, buf, buf_size, now,
1)` as `parse_cstp_data` calls with `is_dtls=0` — confirmed by reading
`parse_data`'s body (lines 2690-2849), which branches on `is_dtls` only for
header-offset and compression-context selection (`cstp_selected_comp` vs
`dtls_selected_comp`), not for which `case` labels are reachable.
**Acceptance**: a DPD-REQ (`0x03`), DISCONNECT (`0x05`), or TERMINATE (`0x09`)
frame sent over the DTLS channel is processed identically (same `switch` case)
as the equivalent CSTP frame, modulo the 1-byte vs 8-byte header.
**Divergence**: resolves OC-PROTO-DATA-004's `[AMBIGUOUS]` flag — classified
MAJORITY rather than UNIVERSAL because OC-PROTO itself does not commit to this
answer, but no source disagrees with OCSERV's "treat both channels uniformly"
choice. `[REVIEW]`: TERMINATE is documented as "server→client only" — `OCSERV`'s
`parse_data` would still process a client→server TERMINATE frame (type `0x09`)
on DTLS via the same dispatch; `0x09` is not in the explicitly-handled case list
(`AC_PKT_DPD_RESP/KEEPALIVE/DPD_OUT/DISCONN/COMPRESSED/DATA`), so it falls to the
`default:` (log-and-ignore) path per REQ-PROTO-DATA-002 — i.e. a client sending
TERMINATE is harmless (ignored), not a directionality violation enforced by
ocserv. Recorded as informational, not a defect.
**Links**: REQ-PROTO-DATA-002

---

## CTRL — Rekey, DPD, keepalive

### REQ-PROTO-CTRL-001
**Requirement**: The server MUST advertise its rekey policy via
`X-CSTP-Rekey-Method`/`X-DTLS-Rekey-Method` (`none`, `ssl`, or `new-tunnel`) and,
when not `none`, `X-CSTP-Rekey-Time`/`X-DTLS-Rekey-Time` (seconds).
`OCSERV` implements `ssl` and `new-tunnel` as configurable `rekey-method` values
(`REKEY_METHOD_SSL`, `REKEY_METHOD_NEW_TUNNEL` in `src/vpn.h`), with
`rekey-time` defaulting to `DEFAULT_REKEY_TIME` (`src/config.c`).
**Class**: MAJORITY
**Strength**: MUST (header semantics) / policy is server-configurable
**Source mapping**: OC-PROTO-CTRL-001 (3-value enumeration); OCSERV
`src/config.c` (`rekey-method`, `rekey-time` parsing), `src/vpn.h:128-129`
(`REKEY_METHOD_SSL=1`, `REKEY_METHOD_NEW_TUNNEL=2` — implying an implicit value
`0` for "none"/unset), `src/worker-vpn.c:2407-2411` (rekey timer scheduling when
`rekey_time > 0`).
**Acceptance**: with `rekey-method = ssl` and `rekey-time = N`, the CONNECT
response advertises `X-CSTP-Rekey-Method: ssl` and
`X-CSTP-Rekey-Time: <N-derived value>`; a rekey is triggered at approximately
`rekey_time` (with jitter — `FUZZ(WSRCONFIG(ws)->rekey_time, 30, rnd)` at
`src/worker-vpn.c:2111`).
**Divergence**: both `ssl` and `new-tunnel` are implemented (not just
advertised), so this is MAJORITY rather than EXTENSION; classified MAJORITY
(not UNIVERSAL) only because the *value* `rekey-time` and the *jitter* (`FUZZ`,
±30s) are ocserv-specific parameters not specified by OC-PROTO at all —
OC-PROTO defines the header mechanism, OCSERV defines the policy values.
`[REVIEW]`: confirm `rekey-method = none` (or unset) correctly advertises
`X-CSTP-Rekey-Method: none` (value `0`) rather than omitting the header or
defaulting to `ssl` — not verified in this pass.
**Links**: REQ-PROTO-CTRL-002

### REQ-PROTO-CTRL-002
**Requirement**: When `rekey-method = ssl` under TLS/DTLS 1.2, both peers MUST
ensure RFC 5746 safe renegotiation (or equivalent identity-pinning across the
rekey) to prevent renegotiation-based identity substitution.
**Class**: UNIVERSAL
**Strength**: MUST
**Source mapping**: OC-PROTO-CTRL-002; OCSERV's default `tls-priorities`
(REQ-PROTO-CONN-001) does not disable `%DISABLE_SAFE_RENEGOTIATION` for the main
TLS channel (that override is specific to the DTLS resumption workaround in
`src/worker-http.c`'s `ciphersuites[]` table, a different code path) —
GnuTLS enables RFC 5746 safe renegotiation by default.
**Acceptance**: this requirement is satisfied "for free" by GnuTLS's default
behavior for the primary CSTP TLS channel; no ocserv-specific code implements
identity-pinning separately.
**Status**: `[REVIEW]` — the `WORKAROUND_STR` /
`%DISABLE_SAFE_RENEGOTIATION` override in `src/worker-http.c`'s DTLS
`ciphersuites[]` table (used for *DTLS session resumption*, per the comment
about OpenSSL's extended-master-secret interop issue) is a **separate** TLS
context from the main CSTP channel — confirm this override cannot be reached
for the CSTP `ssl`-rekey path itself, only for DTLS-PSK/resumption setup. Not
fully traced in this pass.
**Links**: REQ-WORKER-SEC-003

### REQ-PROTO-CTRL-003
**Requirement**: A peer receiving DPD-REQ MUST respond with DPD-RESP carrying
byte-identical contents (for Path-MTU-detection use); a peer receiving
KEEPALIVE MUST respond with KEEPALIVE.
**Class**: UNIVERSAL
**Strength**: MUST
**Source mapping**: OC-PROTO-CTRL-003; OCSERV `src/worker-vpn.c:2711-2756`
(`AC_PKT_DPD_OUT` case): for CSTP, sets `buf[6] = AC_PKT_DPD_RESP` and
`cstp_send(ws, buf, buf_size)` — re-sends the **entire received buffer**
(header + payload) with only the type byte changed, i.e. byte-identical payload
as required; for DTLS, sets `buf[0] = AC_PKT_DPD_RESP` and `dtls_send(...,
buf, buf_size)` similarly, with additional MTU-discovery bookkeeping
(`data_mtu_set`) when the received DPD is larger than the current `link_mtu`.
KEEPALIVE (`AC_PKT_KEEPALIVE`) is logged but — `[REVIEW]` — the case at
`src/worker-vpn.c:2708-2710` only logs "received keepalive" and does not
appear to send a KEEPALIVE response in the snippet read; confirm whether a
KEEPALIVE response is sent elsewhere (e.g. unconditionally on a timer,
independent of receipt) rather than as a direct reply.
**Acceptance (positive)**: DPD-RESP echoes the exact bytes of the received
DPD-REQ (confirmed by code: same buffer, single byte mutated).
**Acceptance (open)**: `[OPEN]` whether KEEPALIVE-in → KEEPALIVE-out is a direct
per-packet reply or relies on ocserv's own keepalive timer running
independently (which would still satisfy "client receives keepalives" but not
literally "respond to this KEEPALIVE with a KEEPALIVE").
**Links**: none

---

## CFG — IP/route/DNS configuration push

### REQ-PROTO-CFG-001
**Requirement**: See REQ-PROTO-CONN-007 (CONNECT response config headers) —
restated here under the CFG category per the unified ID scheme; no additional
content beyond REQ-PROTO-CONN-007.
**Class**: MAJORITY
**Status**: WITHDRAWN — folded into REQ-PROTO-CONN-007 to avoid duplication.
This ID is reserved (not reused) per the README's numbering convention.

### REQ-PROTO-CFG-002
**Requirement**: For IPv6 DNS server addresses, the server MUST send
`X-CSTP-DNS-IP6: <addr>` when `user_agent_type == AGENT_ANYCONNECT`, and MUST
send `X-CSTP-DNS: <addr>` (the same header used for IPv4) for all other agent
types, "because openconnect does not require the split of DNS and DNS-IP6 and
only recent versions understand the IP6 variant" (source comment).
**Class**: DIVERGENT
**Strength**: MUST (both branches, mutually exclusive on `user_agent_type`)
**Source mapping**: AC-CLIENT-CONN-002; OC-PROTO-CONN-007 lists both
`X-CSTP-DNS` and (implicitly, via the general header-naming pattern)
`X-CSTP-DNS-IP6` as available headers but does not specify selection criteria.
**Divergence (Phase 4 — value/behavioral disagreement)**: the same logical
information (an IPv6 DNS server address) is conveyed under two different header
names depending on client classification. This is not a security issue but is
an interoperability hotspot if a client's classification is wrong (e.g. an
`AGENT_UNKNOWN` client that *does* understand `DNS-IP6` but not a combined
`DNS` field for IPv6 would receive the address under the "wrong" header name for
its actual capabilities).
**Resolution options**:
  - *Most RFC/OC-PROTO-compliant*: n/a — OC-PROTO does not adjudicate.
  - *Most interoperable*: current behavior (classification-based), since it's
    tuned to the two client families ocserv actually sees.
  - *Most conservative*: send **both** headers for IPv6 DNS entries when the
    client's capability is unknown (`AGENT_UNKNOWN`) — currently
    `AGENT_UNKNOWN` falls into the `X-CSTP-DNS` branch (the "else" of
    `user_agent_type == AGENT_ANYCONNECT`), same as `AGENT_OPENCONNECT`.
**Links**: AC-CLIENT-CONN-002, REQ-PROTO-CONN-007

### REQ-PROTO-CFG-003
**Requirement**: When IPv6 is enabled and the client is identified as iOS
AnyConnect (`req->is_ios`, set only for `User-Agent` starting with
`"Cisco AnyConnect VPN Agent for Apple"`), and the session has no configured
routes or `default_route == 0`, the server MUST additionally send
`X-CSTP-Split-Include-IP6: 2000::/3`.
**Class**: EXTENSION
**Strength**: MUST (when the iOS-AnyConnect + no-default-route condition holds)
**Source mapping**: AC-CLIENT-CONN-004; no corresponding OC-PROTO requirement
(iOS-specific platform workaround).
**Acceptance**: see AC-CLIENT-CONN-004.
**Divergence**: EXTENSION — present only in `OCSERV`/`AC-CLIENT`, no
interoperability risk with non-iOS or non-AnyConnect clients (condition is
gated on `is_ios`).
**Links**: AC-CLIENT-CONN-004

### REQ-PROTO-CFG-004
**Requirement**: When `ws->full_ipv6` is enabled, the server's decision to
advertise IPv6 routes/DNS to a given client MUST depend on `user_agent_type`:
disabled for `AGENT_OPENCONNECT_V3` (known not to support IPv6); enabled for
`AGENT_OPENCONNECT`, `AGENT_ANYCONNECT`, `AGENT_OPENCONNECT_CLAVISTER`,
`AGENT_ANYLINK`; enabled (with a `LOG_NOTICE` warning) for `AGENT_UNKNOWN` /
unrecognized values.
**Class**: EXTENSION
**Strength**: MUST
**Source mapping**: AC-CLIENT-CONN-003; OC-PROTO does not condition IPv6
advertisement on client identity at all (it is purely a function of server
configuration and the `X-CSTP-Address-Type` capability header from
REQ-PROTO-CONN-005 in the spec's model).
**Divergence**: EXTENSION — `OCSERV` adds a client-identity-based override on
top of the capability-header-based model OC-PROTO describes. Not
COMPAT-CRITICAL (it only ever *adds* IPv6 advertisement beyond what a strict
capability-header reading might, except for the `AGENT_OPENCONNECT_V3` case
which *removes* it for a client family documented as not supporting it).
**Links**: AC-CLIENT-CONN-003, AC-CLIENT-COMPAT-001

---

## COMPAT — AnyConnect-specific deviations from OC-PROTO

### REQ-PROTO-COMPAT-001
**Requirement**: The server MUST classify each connection into one of 7
`user_agent_type` values via case-insensitive, order-sensitive prefix matching
of the `User-Agent` header (AC-CLIENT-COMPAT-001/002/003), and this
classification is the **sole** mechanism driving every other COMPAT/CFG entry in
this document (REQ-PROTO-COMPAT-002, REQ-PROTO-CFG-002/003/004).
**Class**: EXTENSION
**Strength**: MUST
**Source mapping**: AC-CLIENT-COMPAT-001/002/003; no OC-PROTO equivalent (the
draft's model is capability-header-based, not User-Agent-based).
**Acceptance**: see AC-CLIENT-COMPAT-001.
**Note for doc/README-cisco-svc.md**: this central classification mechanism is
**not currently cross-referenced** from `doc/README-cisco-svc.md` — `[CANDIDATE
for doc addition]`: that file documents the `cisco-svc-client-compat` flag and
`AGENT_SVC_IPPHONE` but does not explain that `User-Agent` classification is also
how AnyConnect-vs-OpenConnect DNS/IPv6 behavior (REQ-PROTO-CFG-002/004) is
selected — administrators debugging "why does my client get different DNS
headers" would benefit from this being documented in one place.
**Links**: AC-CLIENT-COMPAT-001, REQ-PROTO-CFG-002, REQ-PROTO-CFG-004,
REQ-PROTO-COMPAT-002

### REQ-PROTO-COMPAT-002
**Requirement**: For `AGENT_OPENCONNECT_V3` clients, the auth-success response
body (REQ-PROTO-AUTH-008) MUST use a legacy bare `<auth id="success">...</auth>`
wrapper (no enclosing `<config-auth>`), instead of the standard wrapper used for
all other agent types.
**Class**: EXTENSION
**Strength**: MUST
**Source mapping**: AC-CLIENT-CONN-001; OC-PROTO-AUTH-008 describes only the
current (`<config-auth type="complete">`) wrapper.
**Acceptance**: see AC-CLIENT-CONN-001.
**Divergence**: EXTENSION — backward-compatibility shim for a pre-`config-auth`
client population; no risk to current OC-PROTO-compliant clients since it is
gated on `AGENT_OPENCONNECT_V3` (≤v3) specifically.
**Links**: AC-CLIENT-CONN-001, AC-CLIENT-COMPAT-003, REQ-PROTO-AUTH-008

### REQ-PROTO-COMPAT-003
**Requirement**: The `/svc` endpoint (Cisco IP-Phone family) is an additional,
gated, parallel authentication entry point: reachable only when
`cisco-svc-client-compat = true` AND `user_agent_type == AGENT_SVC_IPPHONE`;
`GET /svc` primes the client with `Set-Cookie: webvpnlogin=1; secure`;
`POST /svc` with `username`/`password` performs a full `SEC_AUTH_INIT`/
`SEC_AUTH_CONT` exchange and returns either `200 + Set-Cookie: webvpn=<cookie>;
secure` (success) or `401 Authentication failed` + worker exit (failure, see
REQ-PROTO-AUTH-005).
**Class**: EXTENSION
**Strength**: MUST (when the gating conditions hold)
**Source mapping**: AC-CLIENT-COMPAT-010, AC-CLIENT-AUTH-010/011/012/013; no
OC-PROTO equivalent.
**Status**: AC-CLIENT-AUTH-013 (the post-login flow for `/svc`-authenticated
IP-Phones) remains `[UNDOCUMENTED]` — not resolved in this reconciliation pass.
**Acceptance**: see AC-CLIENT-COMPAT-010 / AC-CLIENT-AUTH-010-012.
**Divergence**: EXTENSION, zero interoperability risk for non-IP-Phone clients
(double-gated). The `[REVIEW]` items from AC-CLIENT-AUTH-010 (overlap between
the two gating checks) and AC-CLIENT-AUTH-012 (camouflage interaction) remain
open.
**Note for doc/README-cisco-svc.md**: already documented at a high level; the
**exact HTTP status/cookie contract** (this requirement's acceptance criteria)
is not in the doc and `[CANDIDATE for doc addition]`.
**Links**: AC-CLIENT-COMPAT-010, AC-CLIENT-AUTH-010, AC-CLIENT-AUTH-011,
AC-CLIENT-AUTH-012, AC-CLIENT-AUTH-013, REQ-PROTO-AUTH-005

### REQ-PROTO-COMPAT-004
**Requirement**: When built `WITH ANYCONNECT_CLIENT_COMPAT`, the server MUST
additionally serve a fixed set of Cisco-ASA-portal-mimicking URLs
(`/profiles/*`, `/VPNManifest.xml`, `/1/*`, `/+CSCOT+/*`, `/logout`) and MUST,
when `xml_config_file` is configured, (a) append a `<vpn-profile-manifest>` XML
fragment referencing `/profiles/<xml_config_file>` to the auth-success body, and
(b) set a `webvpnc=` cookie advertising the same profile URI and a SHA1 hash.
`/profiles/<anything>` always serves the single configured `xml_config_file`
regardless of the URL suffix (confirmed: no path-traversal exposure via this
mechanism, since the suffix is not used for file selection at all).
**Class**: EXTENSION
**Strength**: MUST (build-conditional)
**Source mapping**: AC-CLIENT-EXT-030/031, AC-CLIENT-AUTH-021; no OC-PROTO
equivalent.
**Acceptance**: see AC-CLIENT-EXT-030/031, AC-CLIENT-AUTH-021.
**Divergence**: EXTENSION, build-time gated, zero risk to non-`ANYCONNECT_CLIENT_COMPAT`
builds or to clients that never request `/profiles/*`.
**[REVIEW carried over]**: AC-CLIENT-AUTH-021's two `Set-Cookie: webvpnc=...`
headers (clear-then-set) in one response — ordering intentionality unconfirmed.
**Links**: AC-CLIENT-EXT-030, AC-CLIENT-EXT-031, AC-CLIENT-AUTH-021

### REQ-PROTO-COMPAT-005
**Requirement**: Administrators deploying for Cisco IP-Phones (7800/8800/8900/9900
Enterprise firmware) MUST set `tls-priorities` to restrict negotiated ciphers to
AES256-CBC/AES128-CBC (else the phones fail with "old session cipher not
returned"), and MUST ensure the DTLS UDP listener is reachable on port 443
regardless of the configured HTTPS TCP port.
**Class**: EXTENSION
**Strength**: MUST (documented operational requirements; not enforced in code)
**Source mapping**: AC-CLIENT-SEC-010/011; no OC-PROTO equivalent.
**Status**: documentation-only, no code enforcement (AC-CLIENT-SEC-010/011 both
already noted this).
**Acceptance**: `[OPEN]` — no automated acceptance criteria; this is an
administrator-facing constraint already in `doc/README-cisco-svc.md`.
**Links**: AC-CLIENT-SEC-010, AC-CLIENT-SEC-011

### REQ-PROTO-COMPAT-006
**Requirement**: `OCSERV` MAY be configured in "camouflage" (hidden-service)
mode (`camouflage = true`, vhost-scoped), in which the server presents as a
generic web server to any client that has not yet proven knowledge of a shared
secret, with no protocol-visible indication that a VPN endpoint exists at the
URL at all. This is a self-contained extension with two independently-triggered
response behaviors and one bypass condition:
  - **Pre-authentication URL-secret gate** (`check_camouflage_url`,
    `src/worker-vpn.c:819-836`, gated at `src/worker-vpn.c:1029-1042`): on every
    `GET`/`POST` while `camouflage_check_passed == 0`, the server inspects the
    request URL for a `?<camouflage_secret>` suffix. If present and matching,
    the suffix is stripped and the request proceeds through normal handling
    (REQ-PROTO-CONN-003 etc.) as if camouflage were not configured. If absent or
    non-matching, the server responds `401 Unauthorized` with
    `WWW-Authenticate: Basic realm="<camouflage_realm>"` if `camouflage_realm`
    is configured, or `404 Not Found` if it is not, and closes the connection —
    in either case with **no VPN-specific response body, header, or status
    code**.
  - **Post-authentication cookie-failure gate** (`cookie_authenticate_or_exit`,
    `src/worker-auth.c:1044-1047`): if cookie authentication on the CONNECT path
    fails *and* camouflage is enabled *and* the URL-secret check has not yet
    passed for this connection, the server responds `405 Method Not Allowed`
    instead of the `401`/`503` it would otherwise send (REQ-PROTO-AUTH-005) —
    again presenting as a generic web server reacting to an unsupported method,
    rather than a VPN endpoint rejecting a credential.
  - **Cookie-bearing reconnects bypass the URL-secret gate**: once
    `ws->auth_state >= S_AUTH_COOKIE` (the client already holds a session cookie
    from a prior full authentication), `check_camouflage_url` marks the check
    passed unconditionally (`src/worker-vpn.c:824-827`) — the secret is required
    only on the initial, unauthenticated request.
**Class**: EXTENSION
**Strength**: MUST (when `camouflage = true`)
**Source mapping**: REQ-WORKER-AUTH-004 (`cookie_authenticate_or_exit` 405
path); `src/worker-vpn.c` (`check_camouflage_url` and its call site); no
OC-PROTO or AC-CLIENT equivalent — this is a deployment-hardening feature with
no client-visible "VPN protocol" semantics.
**Configuration**: `camouflage` (bool, default false), `camouflage_secret`
(string), `camouflage_realm` (string, optional) — all vhost-scoped
(`doc/sample.config`).
**Security rationale**: anti-fingerprinting / anti-probing. An unauthenticated
network scanner (or active-probing infrastructure) that connects to the HTTPS
port without the secret MUST observe a response indistinguishable from a
generic web server (404, or 401 + realm for a generic HTTP-auth-protected page)
— not `config-auth` XML, not a CONNECT/CSTP handshake, and no header
advertising ocserv, AnyConnect, or OpenConnect support.
**Negative requirement**: while `camouflage_check_passed == 0`, the server MUST
NOT emit any of: `config-auth` XML, `X-CSTP-*`/`X-DTLS-*` headers, the
`webvpn`/`webvpnlogin` cookies, or any 4xx/5xx body that reveals the endpoint is
a VPN gateway.
**Acceptance**:
  - *Positive*: `GET /?<camouflage_secret>` (or any path) on a
    `camouflage = true` vhost MUST be processed identically to the same request
    against a `camouflage = false` vhost, once the secret suffix is stripped.
  - *Negative (no realm)*: `GET /` (no secret) with `camouflage_realm` unset
    MUST return `404 Not Found` with no `config-auth`/VPN-identifying content.
  - *Negative (realm configured)*: `GET /` (no secret) with `camouflage_realm`
    set MUST return `401 Unauthorized` + `WWW-Authenticate: Basic
    realm="<camouflage_realm>"`, again with no VPN-identifying content.
  - *Negative (cookie path)*: a CONNECT request with an invalid/expired cookie
    on a `camouflage = true`, secret-not-yet-passed connection MUST return `405
    Method Not Allowed`, not `401`/`503`.
**Note for doc/ocserv.8.md**: `camouflage`/`camouflage_secret`/`camouflage_realm`
are documented in `doc/sample.config` but have no corresponding entry in
`doc/ocserv.8.md`'s option reference — `[CANDIDATE for doc addition]`.
**Background**: introduced and discussed in `gitlab.com/openconnect/ocserv`
MR !340 / work item #624.
**Links**: REQ-WORKER-AUTH-004, REQ-PROTO-AUTH-005, REQ-PROTO-CONN-003

---

## SEC — Security properties

### REQ-PROTO-SEC-001
**Requirement**: Payload compression (`oc-lz4`, `lzs`) MUST NOT be enabled by
default; an administrator MUST explicitly opt in. Both peers MAY still choose to
send `COMPRESSED DATA` (`0x08`) frames if compression was negotiated, and MUST
be able to receive both `0x00` and `0x08` regardless of their own send-side
choice (REQ-PROTO-DATA-002).
**Class**: UNIVERSAL
**Strength**: MUST NOT (default-on) / MAY (opt-in) / MUST (bidirectional decode)
**Source mapping**: OC-PROTO-SEC-001 (the spec's one explicit MUST NOT besides
auth sections); OCSERV: `enable_compression` is a `protobuf_c_boolean` with no
explicit default-setter found in `src/config.c` (protobuf-c booleans default to
`0`/false absent an explicit assignment), and is only consulted to gate
compression-related header advertisement (`src/worker-http.c:625`,
`WSRCONFIG(ws)->enable_compression == 0` → compression not offered) — confirming
compression is off unless `compression = true` is explicitly configured.
**Acceptance**: with no `compression` directive in the config (the documented
default), the CONNECT response MUST NOT advertise `X-CSTP-Content-Encoding` /
`X-DTLS-Content-Encoding`, and `ws->cstp_selected_comp`/`ws->dtls_selected_comp`
remain `NULL`; receiving a `0x08` COMPRESSED DATA frame with
`cstp_selected_comp == NULL` is an error
(`"received compressed data but no compression was negotiated"`,
`src/worker-vpn.c:2793-2796`) — i.e. "MUST be able to receive 0x08" is
conditioned on compression having been negotiated at all, which matches
OC-PROTO-SEC-001's "MAY still choose to compress... if explicitly negotiated"
framing (the bidirectional-decode MUST applies *given negotiation occurred*, not
unconditionally).
**Links**: REQ-PROTO-DATA-002, REQ-PROTO-EXT-001

### REQ-PROTO-SEC-002
**Requirement**: All RFC 8446 (TLS 1.3) / RFC 5246 (TLS 1.2) and RFC 6347/9147
(DTLS) security considerations apply; additionally, encrypted payload *lengths*
remain observable and may leak information, an effect compression
(REQ-PROTO-SEC-001) can worsen.
**Class**: UNIVERSAL
**Strength**: MUST (RFC incorporation) / informational (length-leakage)
**Source mapping**: OC-PROTO-SEC-002; `RFC-TLS`/`RFC-DTLS` (incorporated by
reference, not separately re-derived per OC-PROTO-SEC-002's own Notes).
**Acceptance**: n/a — this is a blanket incorporation, not independently
testable beyond TLS/DTLS library conformance (GnuTLS).
**Links**: REQ-PROTO-SEC-001, REQ-PROTO-CONN-001

### REQ-PROTO-SEC-003
**Requirement**: Restated from REQ-PROTO-AUTH-007/OC-PROTO-SEC-003: certificates
(client and server) SHOULD carry minimal identifying information given TLS 1.2's
unencrypted handshake certificates.
**Class**: MAJORITY
**Status**: WITHDRAWN — folded into REQ-PROTO-AUTH-007 to avoid duplication.
This ID is reserved (not reused) per the README's numbering convention.

### REQ-PROTO-SEC-004
**Requirement**: Restated from REQ-PROTO-COMPAT-006: ocserv's `camouflage` mode
substitutes `404`/`401`/`405` responses for the protocol's normal
auth-failure/CONNECT responses, as an anti-fingerprinting security control.
**Class**: EXTENSION
**Status**: WITHDRAWN — folded into REQ-PROTO-COMPAT-006. Camouflage is a
self-contained feature with its own configuration, multiple gated behaviors,
and a documented bypass condition; it does not fit as a one-line "security
property restatement" and is fully specified at REQ-PROTO-COMPAT-006 instead.
This ID is reserved (not reused) per the README's numbering convention.

---

## EXT — ocserv-only extensions

### REQ-PROTO-EXT-001
**Requirement**: `OCSERV` MUST support both named compression algorithms from
OC-PROTO-EXT-001 (`oc-lz4` and `lzs`), each stateless, selectable via
`compression-algo-priority`.
**Class**: MAJORITY
**Strength**: MUST (statelessness, per OC-PROTO) — algorithm *availability* is
MAJORITY because OC-PROTO only names these two but does not require an
implementation to support both.
**Source mapping**: OC-PROTO-EXT-001; OCSERV `src/vpn.h:58-59`
(`OC_COMP_LZ4`, `OC_COMP_LZS` both defined as compile-time constants), 
`src/config.c` `compression-algo-priority` parsing.
**Acceptance**: with `compression = true` and no `compression-algo-priority`
override, both `oc-lz4` and `lzs` are available for negotiation (subject to
`no_compress_limit`, `src/config.c:785-786`, `DEFAULT_NO_COMPRESS_LIMIT`).
**Divergence**: classified MAJORITY (not UNIVERSAL) because "support both" is
OCSERV's choice, not a cross-source agreement — OC-PROTO names them but a
hypothetical implementation supporting only one would not violate OC-PROTO.
**Links**: REQ-PROTO-SEC-001

### REQ-PROTO-EXT-002
**Requirement**: `X-CSTP-Content-Encoding`/`X-DTLS-Content-Encoding`, when sent
by the server, MUST name an algorithm the client advertised via
`X-CSTP-Accept-Encoding`/`X-DTLS-Accept-Encoding`.
**Class**: UNIVERSAL (by inheritance from OC-PROTO; OCSERV-side enforcement not
independently re-verified)
**Strength**: MUST NOT (select unadvertised algorithm)
**Source mapping**: OC-PROTO-EXT-002.
**Status**: `[UNVERIFIED]` — the negotiation code path
(`src/worker-vpn.c:2591-2604`, "send any compression methods") was located but
the specific check "is the selected algorithm a subset of what the client
advertised" was not traced line-by-line in this pass.
**Acceptance**: `[OPEN]` — needs a test sending `X-CSTP-Accept-Encoding:
oc-lz4` only and confirming the server never selects `lzs`.
**Links**: REQ-PROTO-EXT-001

### REQ-PROTO-EXT-003
**Requirement**: `occtl` (the management/monitoring socket and CLI) and its
underlying `ctl.proto` IPC are ocserv-only extensions with no representation in
OC-PROTO or AC-CLIENT.
**Class**: EXTENSION
**Strength**: n/a (not a wire-protocol requirement toward VPN clients)
**Source mapping**: `src/ctl.proto`, `occtl/`; out of scope for `OC-PROTO`/
`AC-CLIENT` entirely.
**Status**: recorded for completeness of the EXTENSION category; no further
elaboration performed (occtl is covered by its own `occtl.8.md` documentation,
not by this wire-protocol reconciliation).
**Links**: none

---

## Phase 6: Interoperability assessment

**Compatibility score**: of the 24 substantive unified entries (excluding the 3
WITHDRAWN placeholders), the classification breakdown is:

| Class | Count | IDs |
|-------|-------|-----|
| UNIVERSAL | 6 | CONN-002, AUTH-001, AUTH-004, AUTH-008, CTRL-002, CTRL-003, SEC-001, SEC-002 (8 — see note) |
| MAJORITY | 10 | CONN-001, CONN-004, CONN-006, CONN-007, AUTH-002, AUTH-003, AUTH-007, AUTH-009, DATA-001, DATA-002, DATA-003, DATA-004, CTRL-001, EXT-001 (14 — see note) |
| DIVERGENT | 3 | AUTH-005, AUTH-011, CFG-002 |
| EXTENSION | 9 | AUTH-006, AUTH-010, CFG-003, CFG-004, COMPAT-001..006, EXT-001 (partially), EXT-002, EXT-003 |

*(Counts overlap slightly because a few entries — EXT-001 — have mixed
classification across sub-clauses; see each entry's own Class field as
authoritative. The table above is a navigational aid, not an exact partition.)*

**Risk areas** (highest concentration of DIVERGENT/REVIEW items):
1. **DATA framing** (DATA-001 through DATA-004): the asymmetric
   close-on-bad-header vs. ignore-on-bad-type vs. generic-bye-on-unhandled-
   DISCONNECT-reason behaviors are each internally consistent and, per
   maintainer confirmation (2026-06-13), DATA-003's `0x70`/`0xd1`-as-generic-bye
   handling is an intentional simplification of ocserv's two-state
   (invalidate/preserve) session model — not an open item.
2. **Auth-failure response shaping** (AUTH-005, AUTH-011): two
   independently-configured mechanisms (`/svc` no-retry, `cisco_client_compat`
   cookie-cert skip) each change auth-failure or cookie-auth behavior; neither
   conflicts with the other (different trigger conditions) but each is a
   documented DIVERGENT/SEC-RISK point. ocserv's `camouflage` feature, formerly
   listed here as a third variant, is now specified in full as its own
   self-contained extension (REQ-PROTO-COMPAT-006) rather than as a divergence
   of this entry.

**Interoperability hotspots / priority for resolution**:

1. **REQ-PROTO-AUTH-011** (`cisco_client_compat` cookie-cert check skip) —
   already flagged `[SEC-RISK]`/human-judgment-required per AGENTS.md's
   cookie/SID category; no action recommended here beyond the existing flag.

2. **REQ-PROTO-CFG-002** (AnyConnect-vs-OpenConnect DNS header naming) — lowest
   severity DIVERGENT item (cosmetic/compatibility, not security), but cheapest
   to potentially improve (send both headers for `AGENT_UNKNOWN` IPv6 DNS
   entries) if an administrator reports an unrecognized-client IPv6-DNS issue.

3. **REQ-PROTO-AUTH-005** (`/svc` 401-then-exit vs OC-PROTO's retry-permitted
   401) — no mainline-client impact (gated to `AGENT_SVC_IPPHONE`); retained as
   DIVERGENT for documentation completeness rather than as an action item.

4. **Open/unverified items** (AUTH-006 X-Pad header limits, AUTH-009 GSSAPI
   fallback header, CTRL-001 `rekey-method = none` advertisement, CTRL-002 DTLS
   resumption TLS-context isolation, CTRL-003 KEEPALIVE reply mechanism,
   EXT-002 Content-Encoding subset enforcement, CONN-007 `/127`/address-ordering
   conventions) — none flagged as security-relevant, but each represents a gap
   between "this document's acceptance criteria" and "verified against code."
   Recommended as a follow-up reading pass, lower priority than items 1-3.

---

## Reconciliation summary

- **Total unified requirements**: 27 assigned IDs, of which 3
  (REQ-PROTO-CFG-001, REQ-PROTO-SEC-003, REQ-PROTO-SEC-004) are WITHDRAWN
  (folded into REQ-PROTO-CONN-007, REQ-PROTO-AUTH-007, and
  REQ-PROTO-COMPAT-006 respectively) — 24 substantive entries.
- **By class**: UNIVERSAL 6, MAJORITY 10, DIVERGENT 3, EXTENSION 9 (see Phase 6
  table for the navigational breakdown; some entries span categories).
- **DIVERGENT requiring human resolution**: REQ-PROTO-AUTH-005, AUTH-011,
  CFG-002. None are blocking — AUTH-011 is the only `[SEC-RISK]`-flagged item
  and already has a conservative default; the other two are
  compatibility/cosmetic.
- **EXTENSION requiring review for documentation** (per the ocserv-extensions
  Phase 5 instruction to cross-reference `doc/README-cisco-svc.md`/`ocserv.8.md`):
  REQ-PROTO-COMPAT-001 (User-Agent classification not centrally documented),
  REQ-PROTO-COMPAT-003 (`/svc` exact HTTP contract not documented),
  REQ-PROTO-COMPAT-006 (`camouflage`/`camouflage_secret`/`camouflage_realm` are
  in `doc/sample.config` but absent from `doc/ocserv.8.md`).
