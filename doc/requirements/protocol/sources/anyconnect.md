---
title: AnyConnect / Cisco-compatibility client protocol requirements (working set)
generator: requirements-elicitation
process: n/a
id-prefix: AC-CLIENT
sources:
  - doc/README-cisco-svc.md
  - src/worker-svc.c
  - src/worker-http.c (user-agent detection, known_urls table)
  - src/worker-auth.c (cisco_client_compat, ANYCONNECT_CLIENT_COMPAT, webvpnc cookie, profile delivery)
  - src/worker-vpn.c (per-agent IPv6/DNS/route behavior)
  - src/worker.h (user_agent_type enum, ws->req.is_ios)
---

# Scope

This document captures requirements that are specific to **Cisco AnyConnect** and
the broader family of clients/devices that identify themselves via a
Cisco-compatible `User-Agent` string, as distinct from the generic OpenConnect
protocol covered in `protocol/sources/openconnect.md` (OC-PROTO-*).

**Core objective** [from doc/README-cisco-svc.md and code]: allow ocserv to
interoperate with clients and devices that were built against Cisco's AnyConnect
server (ASA) rather than against the OpenConnect protocol draft, by recognizing
their identifying strings and adjusting behavior (URL routing, cookie format,
config delivery, IPv6/DNS handling, TLS cipher selection) to match what those
clients expect.

**Explicit constraints**:
- The `/svc` endpoint and its behavior are gated by `cisco-svc-client-compat = true`
  (per-vhost config option) — `[PROC: worker]`.
- The `ANYCONNECT_CLIENT_COMPAT` build-time option gates an entire family of
  URL routes and cookie/profile-delivery extensions (`/profiles/*`,
  `/VPNManifest.xml`, `/1/*`, `/+CSCOT+/*`, `/logout`, `webvpnc` cookie,
  `<vpn-profile-manifest>` XML fragment) — `[PROC: worker]`.
- `cisco_client_compat` (a separate, runtime per-vhost config flag) changes the
  certificate-presence requirement at cookie-auth time — `[PROC: worker, IPC]`
  (affects what is sent to main in `AUTH_COOKIE_REQ`).

**Implicit constraints** `[IMPLICIT]`:
- `[IMPLICIT]` All AnyConnect-compatibility behavior must remain additive: it must
  not change the wire behavior observed by clients that identify as
  `AGENT_OPENCONNECT` / `AGENT_OPENCONNECT_V3`, except where the code explicitly
  branches on `user_agent_type`.
- `[IMPLICIT]` User-Agent string matching is the *only* signal used to select
  per-client behavior; there is no protocol-level capability negotiation for these
  extensions (cross-ref OC-PROTO note on "no real version negotiation").

**Out of scope**: the generic config-auth XML handshake, CSTP/DTLS framing, and
DPD/keepalive/rekey semantics, which are common to all agent types and already
covered by `openconnect.md`.

---

# COMPAT — Client identification

## AC-CLIENT-COMPAT-001
**Requirement**: The worker MUST classify each connecting client into one of the
`user_agent_type` values (`AGENT_UNKNOWN`, `AGENT_OPENCONNECT_V3`,
`AGENT_OPENCONNECT`, `AGENT_ANYCONNECT`, `AGENT_OPENCONNECT_CLAVISTER`,
`AGENT_ANYLINK`, `AGENT_SVC_IPPHONE`) based on a case-insensitive prefix match of
the `User-Agent` HTTP header against a fixed, ordered list of strings.
- Strength: MUST (this is the sole dispatch mechanism for all AC-CLIENT-* behavior)
- Source: `src/worker-http.c` (`HEADER_USER_AGENT` case, ~lines 410-477)
- Acceptance: connecting with each of the recognized `User-Agent` strings (e.g.
  `"Cisco AnyConnect VPN Agent for Apple..."`, `"Cisco AnyConnect..."`,
  `"AnyConnect-compatible OpenConnect..."`, `"AnyConnect..."`,
  `"Clavister OneConnect VPN..."`, `"AnyLink Secure Client..."`,
  `"Cisco SVC IPPhone Client..."`, `"Open AnyConnect VPN Agent v<N>"`,
  `"OpenConnect VPN Agent..."`) results in the expected `user_agent_type`; an
  unrecognized string results in `AGENT_UNKNOWN` and is logged at `LOG_DEBUG`
  without rejecting the connection.
- Links: REQ-WORKER-NET-* (worker.md), OC-PROTO-CONN-005 (capability headers)

## AC-CLIENT-COMPAT-002 `[AMBIGUOUS]`
**Requirement**: The order of the `User-Agent` prefix checks SHALL be significant:
`"AnyConnect-compatible OpenConnect"` (33 chars) is checked before the shorter
`"AnyConnect"` (10 chars) prefix, so OpenConnect builds that self-identify with
the compatibility string are classified as `AGENT_OPENCONNECT`, not
`AGENT_ANYCONNECT`.
- Strength: MUST (de facto — reordering would silently reclassify a whole class of
  OpenConnect clients as AnyConnect, changing DNS/IPv6 header formatting per
  AC-CLIENT-CONN-002)
- Status: `[UNDOCUMENTED]` — this ordering dependency is not commented in the code
  and is easy to break with future additions to the table.
- Source: `src/worker-http.c` lines 434-459
- Acceptance: a `User-Agent` of `"AnyConnect-compatible OpenConnect vX"` MUST yield
  `AGENT_OPENCONNECT`, not `AGENT_ANYCONNECT`.
- `[CANDIDATE for unified.md]`: recommend adding a comment documenting the ordering
  invariant, and/or a unit test enumerating one representative string per branch
  with its expected `user_agent_type`, to guard against future reordering.

## AC-CLIENT-COMPAT-003
**Requirement**: Detection of `"Open AnyConnect VPN Agent v<N>"` (the historical
OpenConnect self-identification string) MUST further branch on the numeric
version `N`: `N <= 3` yields `AGENT_OPENCONNECT_V3` (legacy XML reply format, see
AC-CLIENT-CONN-001), `N > 3` yields `AGENT_OPENCONNECT`.
- Strength: MUST
- Source: `src/worker-http.c` lines 421-433 (`atoi(&req->user_agent[27])`)
- Acceptance: `"Open AnyConnect VPN Agent v3"` -> `AGENT_OPENCONNECT_V3`;
  `"Open AnyConnect VPN Agent v4"` -> `AGENT_OPENCONNECT`.
- `[REVIEW]`: `atoi` on attacker-controlled input is bounds-safe here (result only
  drives an enum branch, no allocation/indexing), but a non-numeric suffix (e.g.
  `"Open AnyConnect VPN Agent vX"`) yields `atoi() == 0 <= 3`, i.e.
  `AGENT_OPENCONNECT_V3`. This degrades gracefully (more conservative feature set)
  and is not flagged as a defect, but is worth a one-line comment.

---

# CONN — AnyConnect-specific connection/response shaping

## AC-CLIENT-CONN-001
**Requirement**: For `AGENT_OPENCONNECT_V3` clients, the successful-authentication
response body MUST use the legacy XML wrapper (`ocv3_success_msg_head` /
`ocv3_success_msg_foot`, i.e. a bare `<auth id="success">...</auth>` without the
enclosing `<config-auth>` element), instead of the standard
`oc_success_msg_head` / `*_FOOT` wrapper used for all other agent types.
- Strength: MUST
- Source: `src/worker-auth.c` lines 50-76, 1124-1151 (`post_common_handler`)
- Acceptance: a client identifying as `"Open AnyConnect VPN Agent v3"` and
  successfully authenticating receives a response body beginning with
  `<auth id="success">` (no `<?xml...?><config-auth...>` wrapper element around
  it) and ending with `</auth>`.
- Links: OC-PROTO-AUTH-008 (cert auth success -> complete flow), `[CANDIDATE for
  unified.md]`: classify as **EXTENSION** (backward-compatibility shim for a
  client population predating the `config-auth` XML schema described in
  draft-openconnect).

## AC-CLIENT-CONN-002
**Requirement**: For DNS server delivery, when `user_agent_type == AGENT_ANYCONNECT`
and a DNS entry is IPv6, the worker MUST send `X-CSTP-DNS-IP6: <addr>`; for an IPv4
DNS entry (any agent) or for any DNS entry from a non-AnyConnect agent, it MUST
send `X-CSTP-DNS: <addr>` (the comment in the source states "openconnect does not
require the split of DNS and DNS-IP6 and only recent versions understand the IP6
variant").
- Strength: MUST
- Source: `src/worker-vpn.c` lines 2291-2314
- Acceptance: with `full_ipv6` enabled and an IPv6 DNS server configured, an
  `AGENT_ANYCONNECT` session receives `X-CSTP-DNS-IP6: <addr>`; an
  `AGENT_OPENCONNECT` session receives `X-CSTP-DNS: <addr>` for the same address.
- `[CANDIDATE for unified.md]`: classify as **DIVERGENT** — same logical
  information (DNS server address), different header name depending on detected
  client family. Not a security concern but a compatibility-surface item worth
  tracking if `X-CSTP-DNS-IP6` is ever standardized.

## AC-CLIENT-CONN-003
**Requirement**: IPv6 route/DNS advertisement MUST be gated per `user_agent_type`
when `ws->full_ipv6` is set: `AGENT_OPENCONNECT_V3` -> disabled (logged as "agent
known not to support them"); `AGENT_OPENCONNECT`, `AGENT_ANYCONNECT`,
`AGENT_OPENCONNECT_CLAVISTER`, `AGENT_ANYLINK` -> enabled; `AGENT_UNKNOWN` (and any
future/unhandled value via `default`) -> enabled, with a `LOG_NOTICE` warning
("Enabling IPv6 routes/DNS although the agent is unknown").
- Strength: MUST
- Source: `src/worker-vpn.c` lines 2265-2289
- Acceptance: with IPv6 enabled server-side, a session whose `User-Agent` matches
  none of the known strings still receives IPv6 routes/DNS, and the server log
  contains the `LOG_NOTICE` line.
- `[REVIEW]`: the `default:` branch silently enabling IPv6 for unknown agents is a
  permissive default; flagged for maintainer awareness but not classified as a
  defect since failing to advertise IPv6 to a capable-but-unrecognized client would
  be a worse failure mode (broken connectivity vs. unused advertised routes).

## AC-CLIENT-CONN-004
**Requirement**: When `ws->full_ipv6` is set and `req->is_ios` is set (set only
when the `User-Agent` matches `"Cisco AnyConnect VPN Agent for Apple..."`, see
AC-CLIENT-COMPAT-001) and the session has no configured routes or
`ws->default_route == 0`, the worker MUST additionally send
`X-CSTP-Split-Include-IP6: 2000::/3`.
- Strength: MUST
- Source: `src/worker-vpn.c` lines 2351-2357 (comment: "Anyconnect on IOS requires
  this route in order to use IPv6")
- Acceptance: an iOS AnyConnect session (`User-Agent` starting with
  `"Cisco AnyConnect VPN Agent for Apple"`) with IPv6 enabled and no
  split-tunnel/default route receives `X-CSTP-Split-Include-IP6: 2000::/3` in the
  config-auth response headers.
- `[CANDIDATE for unified.md]`: classify as **EXTENSION** — a platform-specific
  (iOS) workaround with no analogue in `openconnect.md`.

---

# COMPAT — `/svc` endpoint (Cisco IP-Phone clients)

## AC-CLIENT-COMPAT-010
**Requirement**: The `/svc` URL (GET and POST) MUST be registered and reachable
regardless of `ANYCONNECT_CLIENT_COMPAT` build configuration (it is the one entry
in `known_urls[]` outside the `#ifdef ANYCONNECT_CLIENT_COMPAT` block), but both
`get_svc_handler` and `post_svc_handler` MUST reject the request unless
**both** of the following hold: (a) `WSRCONFIG(ws)->cisco_svc_client_compat` is
true, AND (b) `ws->req.user_agent_type == AGENT_SVC_IPPHONE`.
- Strength: MUST
- Source: `src/worker-http.c` line 81 (`LL("/svc", get_svc_handler, post_svc_handler)`);
  `src/worker-svc.c` lines 40-44 and 216-220
- Acceptance (negative): a request to `/svc` (GET or POST) when
  `cisco-svc-client-compat = false` (the documented default per
  `doc/README-cisco-svc.md`), or when `cisco-svc-client-compat = true` but the
  `User-Agent` is not `"Cisco SVC IPPhone Client..."`, MUST be rejected (the
  handler does not proceed to the IP-Phone-specific logic).
- `[REVIEW]`: confirm the exact rejection response (404 vs. falling through to
  default handler behavior) — `get_svc_handler`/`post_svc_handler` early-return,
  but the precise HTTP status returned to a non-IP-Phone client hitting `/svc`
  should be verified against `response_404`/`response_401` call sites for a
  complete negative-test specification.
- Links: REQ-WORKER-AUTH-004 (camouflage), `[CANDIDATE for unified.md]`: classify
  as **EXTENSION** (additional entry point beyond OC-PROTO-CONN-003/004's
  `/` and `/CSCOSSLC/tunnel`).

## AC-CLIENT-AUTH-010
**Requirement**: `get_svc_handler` (the initial GET to `/svc`) MUST respond with
HTTP 200 and a `Set-Cookie: webvpnlogin=1; secure` header, with no body, to signal
the IP-Phone client to proceed with a credential POST. It MUST also log a warning
(but still proceed) if `cisco_svc_client_compat` is false or the `User-Agent` does
not match `AGENT_SVC_IPPHONE` — `[AMBIGUOUS]` this appears to overlap with
AC-CLIENT-COMPAT-010's hard gate; the relationship between the warning-and-proceed
path and the reject path needs clarification from source re-inspection.
- Strength: MUST
- Status: `[REVIEW]` — possible duplication/overlap between the gating check (which
  appears twice, at lines 40-44 and again implicitly) and a separate
  warn-but-continue check; needs a side-by-side reading of `get_svc_handler` and
  `post_svc_handler` to resolve which check is authoritative.
- Source: `src/worker-svc.c` (`get_svc_handler`)
- Acceptance: a `Cisco SVC IPPhone Client` issuing `GET /svc` with
  `cisco-svc-client-compat = true` receives `HTTP/1.1 200` with header
  `Set-Cookie: webvpnlogin=1; secure` and an empty body.
- Links: AC-CLIENT-COMPAT-010

## AC-CLIENT-AUTH-011
**Requirement**: `post_svc_handler` MUST parse `username` and `password` fields
from the POST body (via `parse_reply`), then perform a full
`SEC_AUTH_INIT` / `SEC_AUTH_CONT` exchange with sec-mod via `client_auth()`
(populating `SecAuthInitMsg`/`SecAuthContMsg` with `hmac`, `remote_ip`,
`orig_remote_ip`, `our_ip`, `session_start_time`, `user_agent`, `device_type`,
`device_platform`), identical in IPC shape to the worker-driven password
authentication path used by `post_auth_handler`.
- Strength: MUST
- Source: `src/worker-svc.c` (`post_svc_handler`, `client_auth`)
- Acceptance: posting valid `username`/`password` form fields to `/svc` as a
  `Cisco SVC IPPhone Client` results in the same `SEC_AUTH_INIT`/`SEC_AUTH_CONT`
  IPC traffic to sec-mod as an equivalent password login via `/auth`.
- Links: REQ-IPC-015/016 (per internal/ipc.md), REQ-AUTH-AUTH-002,
  OC-PROTO-AUTH-004 (password auth-request/auth-reply flow)
- `[CANDIDATE for unified.md]`: classify as **MAJORITY** for the underlying
  auth-exchange shape (shared with OC-PROTO-AUTH-004), **EXTENSION** for the
  `/svc`-specific transport (form POST instead of config-auth XML).

## AC-CLIENT-AUTH-012
**Requirement**: On successful authentication, `post_svc_handler` MUST set
`ws->auth_state = S_AUTH_COOKIE` and respond HTTP 200 with
`Set-Cookie: webvpn=<base64 cookie>; secure`. On authentication failure, it MUST
respond `HTTP/1.1 401 Authentication failed`, then call `cstp_fatal_close` and
`exit_worker` — i.e. the worker process MUST terminate on a failed `/svc` login,
unlike the `/auth` path which may permit further auth rounds.
- Strength: MUST
- Source: `src/worker-svc.c` (`post_svc_handler`)
- Acceptance (positive): successful `/svc` POST with valid credentials yields
  `HTTP/1.1 200` + `Set-Cookie: webvpn=<cookie>; secure`, and the worker remains
  alive in `S_AUTH_COOKIE` state for a subsequent `CONNECT` (or `/svc`
  cookie-validated request, see AC-CLIENT-AUTH-013).
- Acceptance (negative): `/svc` POST with invalid credentials yields
  `HTTP/1.1 401 Authentication failed`, and the worker process exits — a
  subsequent request on the same TCP connection MUST fail (connection closed).
- Links: OC-PROTO-AUTH-005 (401 on auth failure — note OC-PROTO-AUTH-005 already
  flags ocserv's camouflage-405 behavior as a DIVERGENT/EXTENSION candidate;
  `/svc`'s unconditional-401-then-exit is a *third* variant worth folding into
  that same unified entry), REQ-WORKER-AUTH-004 (camouflage 405 gate — note
  `cookie_authenticate_or_exit`'s camouflage branch is NOT shown to apply inside
  `post_svc_handler`'s own 401 path; `[REVIEW]` whether `/svc` login failures are
  exempt from camouflage masking by design or by oversight).
- `[CANDIDATE for unified.md]`: the immediate `exit_worker()` on `/svc` auth
  failure (vs. allowing retries on `/auth`) should be evaluated as a
  **negative-test requirement**: confirm no information beyond "401
  Authentication failed" is leaked, and that the worker exit does not leave
  sec-mod-side session/ban-score state inconsistent (cross-ref REQ-MAIN-SEC-005,
  REQ-AUTH-AUTH-* ban accounting).

## AC-CLIENT-AUTH-013 `[UNDOCUMENTED]`
**Requirement**: After a successful `/svc` login (`S_AUTH_COOKIE`), the IP-Phone
client is expected to use the returned `webvpn` cookie for subsequent requests —
the exact follow-on flow (does the phone then issue `CONNECT /CSCOSSLC/tunnel`
like a standard OpenConnect client, or does it use `/svc` again, or a different
endpoint?) is not stated in `doc/README-cisco-svc.md` and was not traced in
`worker-svc.c` beyond `post_svc_handler`.
- Strength: SHOULD (informational gap, not a normative gap in ocserv's own
  behavior — ocserv's obligations end at issuing the cookie)
- Status: `[UNDOCUMENTED]`
- Source: `doc/README-cisco-svc.md` (56 lines, does not describe post-login flow)
- `[CANDIDATE for unified.md]`: if the IP-Phone reuses `CONNECT /CSCOSSLC/tunnel`
  with the `webvpn` cookie, AC-CLIENT-AUTH-013 collapses into OC-PROTO-CONN-004
  (classify **MAJORITY**); if it uses a distinct mechanism, this needs its own
  unified entry. Recommend tracing an actual IP-Phone packet capture or asking
  maintainers before reconciliation.

---

# COMPAT — TLS cipher / transport requirements for IP-Phones

## AC-CLIENT-SEC-010
**Requirement**: Per `doc/README-cisco-svc.md`, when serving Cisco IP-Phone
(7800/8800/8900/9900 Enterprise-firmware) clients, the administrator MUST
configure `tls-priorities` to force AES256-CBC or AES128-CBC, because these
phones fail with an "old session cipher not returned" error if the negotiated
cipher is outside this set.
- Strength: MUST (documented operational requirement; not enforced by ocserv code
  — it is a configuration constraint on the administrator)
- Source: `doc/README-cisco-svc.md`
- Status: this is a **documentation-only** requirement — no corresponding code
  enforces or validates it. `[CANDIDATE for unified.md]`: classify as
  **EXTENSION**, and consider whether ocserv should emit a configuration-time
  warning when `cisco-svc-client-compat = true` is set without a compatible
  `tls-priorities` override (a `[CANDIDATE]` for a future config-validation
  requirement, not in scope for this elicitation pass).

## AC-CLIENT-SEC-011
**Requirement**: Per `doc/README-cisco-svc.md`, DTLS for these IP-Phones requires
the server to listen on **port 443** for UDP, regardless of the configured HTTPS
TCP port.
- Strength: MUST (documented operational requirement)
- Source: `doc/README-cisco-svc.md`
- Status: documentation-only, as AC-CLIENT-SEC-010.
- `[CANDIDATE for unified.md]`: classify as **EXTENSION**; cross-ref
  REQ-WORKER-NET-003 (DTLS enablement conditions) — confirm whether ocserv's UDP
  listener port is independently configurable from the TCP port, or whether this
  is purely an administrator-side firewall/NAT requirement.

---

# AUTH — `cisco_client_compat` cookie-authentication relaxation

## AC-CLIENT-AUTH-020
**Requirement**: In `auth_cookie()`, when the selected auth type includes
`AUTH_TYPE_CERTIFICATE` AND `WSRCONFIG(ws)->cisco_client_compat == 0` (the
default), the worker MUST require `ws->cert_auth_ok != 0` and MUST call
`get_cert_info(ws)` before sending `AUTH_COOKIE_REQ` to main, failing the cookie
auth (`return -1`) if either check fails. When `cisco_client_compat == 1`, this
entire certificate-presence check is **skipped** — `AUTH_COOKIE_REQ` is sent
without re-validating `cert_auth_ok`/`get_cert_info`, even if certificate auth was
the selected method.
- Strength: MUST (both branches are unconditional given the flag's value)
- Source: `src/worker-auth.c` lines 1066-1085
- Acceptance (negative, default config): with `cisco_client_compat = false`
  (default) and certificate-based auth selected, a cookie-auth attempt where
  `ws->cert_auth_ok == 0` MUST fail (`auth_cookie` returns -1, leading to the
  401/405/503 handling in `cookie_authenticate_or_exit`, REQ-WORKER-AUTH-004).
- Acceptance (positive, compat config): with `cisco_client_compat = true` and
  certificate-based auth selected, a cookie-auth attempt proceeds to
  `AUTH_COOKIE_REQ` even when `ws->cert_auth_ok == 0` — relying entirely on
  sec-mod's independent verification (REQ-AUTH-AUTH-005) for the actual
  security decision.
- `[SEC-RISK / REVIEW]`: this flag removes a worker-side defense-in-depth check
  (cross-ref REQ-AUTH-AUTH-008, which already notes sec-mod independently
  re-derives cert identity). Because sec-mod's check is authoritative, this is
  *not* a privilege-boundary violation per se, but it widens the set of requests
  that reach sec-mod without a worker-side pre-filter. Flag explicitly for
  maintainer review per AGENTS.md's "Human-judgment required" list (cookie/SID
  handling changes) if this flag is ever touched.
- Links: REQ-AUTH-AUTH-007, REQ-AUTH-AUTH-008, REQ-AUTH-AUTH-005,
  `[CANDIDATE for unified.md]`: classify as **DIVERGENT** (config-gated relaxation
  of a check present in the default/MAJORITY path).

---

# EXT — `ANYCONNECT_CLIENT_COMPAT` build-time extensions

## AC-CLIENT-EXT-030
**Requirement**: When built `WITH ANYCONNECT_CLIENT_COMPAT`, the `known_urls[]`
table MUST additionally register: `/profiles/*` (directory handler ->
`get_config_handler`), `/VPNManifest.xml`, `/1/index.html`, `/1/Linux`,
`/1/Linux_64`, `/1/Windows`, `/1/Windows_ARM64`, `/1/Darwin_i386`,
`/1/binaries/vpndownloader.sh`, `/1/VPNManifest.xml`,
`/1/binaries/update.txt`, `/+CSCOT+/translation-table`,
`/+CSCOT+/oem-customization`, and `/logout`.
- Strength: MUST (build-conditional, but unconditional within that build)
- Source: `src/worker-http.c` lines 64-80
- Acceptance: a build with `ANYCONNECT_CLIENT_COMPAT` defined serves a non-404
  response for `GET /profiles/<file>` (subject to AC-CLIENT-EXT-031) and for each
  literal path above; a build without it returns 404 (the default
  GET-URL-not-found handling) for all of these paths.
- `[CANDIDATE for unified.md]`: classify as **EXTENSION**. Several of these paths
  (`/1/binaries/vpndownloader.sh`, `/1/Linux*`, `/1/Windows*`, `/1/Darwin_i386`)
  appear to mimic Cisco ASA's webvpn client-download portal; `[UNDOCUMENTED]`
  whether ocserv actually serves meaningful content for these vs. stub/empty
  responses (`get_empty_handler` for most, `get_dl_handler`/`get_string_handler`
  for a few) — worth a one-line note in `doc/README-cisco-svc.md` or
  `ocserv.8.md` if administrators are expected to populate any of these.

## AC-CLIENT-EXT-031
**Requirement**: `get_config_handler` (registered for `/profiles/*` under
`ANYCONNECT_CLIENT_COMPAT`) MUST: (1) require a valid session cookie via
`cookie_authenticate_or_exit`; (2) respond 404 if
`ws->user_config->xml_config_file` is unset, or if `stat()` on that path fails;
(3) otherwise stream the file with `Content-Type: text/xml` and
`Content-Length` set to the file's size via `cstp_send_file`.
- Strength: MUST
- Source: `src/worker-http-handlers.c` lines 94-130
- Acceptance (positive): with `xml_config_file` configured for the authenticated
  user and the file present, `GET /profiles/<anything>` (cookie-authenticated)
  returns `200` with `Content-Type: text/xml` and the file's bytes.
- Acceptance (negative): without a valid cookie, `cookie_authenticate_or_exit`
  enforces the same 401/405/503 rules as REQ-WORKER-AUTH-004; with a valid cookie
  but no `xml_config_file` configured, or a configured-but-missing file, the
  response is 404.
- `[REVIEW]`: `ws->req.url` (the requested sub-path under `/profiles/`) does not
  appear to be used to select *which* file to serve — `get_config_handler` always
  serves `ws->user_config->xml_config_file` regardless of the URL suffix. This
  means any path under `/profiles/` (e.g. `/profiles/../../etc/passwd`) maps to
  the same single configured file — i.e. **the URL suffix is not used for file
  selection, so path traversal via the URL is not applicable here**. Confirmed by
  reading `get_config_handler`'s body (no `ws->req.url` reference after the
  initial debug log). Recorded as a negative-requirement *confirmation*, not a
  gap: `[CANDIDATE for unified.md negative requirements]` — "the `/profiles/<x>`
  URL suffix MUST NOT influence which file is served."
- Links: REQ-WORKER-AUTH-004, AC-CLIENT-AUTH-021 (webvpnc cookie below, which
  advertises the `/profiles/%s` URI to the client)

## AC-CLIENT-AUTH-021
**Requirement**: When built `WITH ANYCONNECT_CLIENT_COMPAT` and
`WSRCONFIG(ws)->xml_config_file` is set, the successful-authentication response
(`post_common_handler`) MUST:
  (a) append an `OC_SUCCESS_MSG_FOOT_PROFILE` XML fragment (a
      `<config type="private"><vpn-profile-manifest><vpn rev="1.0"><file
      type="profile" service-type="user"><uri>/profiles/%s</uri><hash
      type="sha1">%s</hash></file></vpn></vpn-profile-manifest></config>`,
      with `%s` = `xml_config_file` name and `xml_config_hash`) instead of the
      plain `OC_SUCCESS_MSG_FOOT`; and
  (b) set an additional `Set-Cookie: webvpnc=bu:/&p:t&iu:1/&sh:<cert_hash>&...
      &fu:profiles%2F<xml_config_file>&fh:<xml_config_hash>; path=/; Secure;
      HttpOnly` header (or, if `xml_config_file` is unset, the shorter
      `webvpnc=bu:/&p:t&iu:1/&sh:<cert_hash>; path=/; Secure; HttpOnly` form).
  Both forms are sent in addition to, and after, the unconditional
  `Set-Cookie: webvpn=<cookie>; Secure; HttpOnly` and the `webvpnc=` *clearing*
  cookie (`expires=Thu, 01 Jan 1970...`) that precede them.
- Strength: MUST (build-conditional)
- Source: `src/worker-auth.c` lines 1132-1151 (XML foot), 1219-1249 (cookies)
- Acceptance: under `ANYCONNECT_CLIENT_COMPAT` with `xml_config_file` configured,
  a successful auth response contains, in order: a `webvpn=` cookie, a clearing
  `webvpnc=; expires=...1970...` cookie, OWASP headers, then a non-expiring
  `webvpnc=bu:/&p:t&iu:1/&sh:<hash>&...&fu:profiles%2F<file>&fh:<hash>` cookie, then
  the XML body with the `<vpn-profile-manifest>` fragment referencing
  `/profiles/<xml_config_file>`.
- `[CANDIDATE for unified.md]`: classify as **EXTENSION** (config-profile delivery
  has no analogue in `openconnect.md`). `[REVIEW]`: the two `webvpnc=` `Set-Cookie`
  headers (one clearing, one setting) sent in the same response is unusual;
  confirm this ordering is intentional (clear-then-reset pattern, perhaps for
  clients that cache the first `Set-Cookie` for a given name) rather than a
  leftover from incremental development.
- Links: AC-CLIENT-EXT-031 (the `/profiles/<file>` URI this cookie/XML advertises)

---

# Completeness notes

- **`src/worker-svc.c` `client_auth()` internals** (HMAC construction, exact field
  population of `SecAuthInitMsg`/`SecAuthContMsg`): covered at the level of "same
  IPC shape as `/auth`" (AC-CLIENT-AUTH-011); a field-by-field diff against
  `post_auth_handler`'s equivalent call was not performed in this pass.
  `[CANDIDATE]` for a follow-up pass if sec-mod-side AC-CLIENT requirements are
  ever needed (currently sec-mod.md treats all `SEC_AUTH_INIT`/`CONT` sources
  uniformly).
- **`get_dl_handler` / `get_string_handler` / `get_empty_handler`** content:
  not inspected; assumed to serve static/stub content per AC-CLIENT-EXT-030's
  `[UNDOCUMENTED]` note.
- **DTLS cipher negotiation table (`ciphersuites[]` in `worker-http.c`)**: this
  table implements the `X-DTLS-CipherSuite` / `X-DTLS12-CipherSuite` HTTP-header
  based DTLS cipher negotiation referenced generically in `openconnect.md`
  (OC-PROTO-CTRL-* rekey/DTLS area) — it is **not** AnyConnect-specific (both
  OpenConnect and AnyConnect clients use this header-based negotiation), so it is
  intentionally excluded from this document and left to `openconnect.md` /
  `unified.md` to cover under CTRL or CONN.
- **`AGENT_OPENCONNECT_CLAVISTER` and `AGENT_ANYLINK`**: recognized for
  classification (AC-CLIENT-COMPAT-001) and IPv6 enablement
  (AC-CLIENT-CONN-003), but no further Clavister- or AnyLink-specific branches
  were found in the files read for this pass. `[UNDOCUMENTED]` whether these
  agent types have any other special-cased behavior elsewhere in the worker
  (not searched exhaustively).
