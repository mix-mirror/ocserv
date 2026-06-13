---
title: OpenConnect protocol (draft) requirement extraction
generator: requirements-elicitation
process: n/a
id-prefix: OC-PROTO
sources:
  - ~/projects/openconnect/protocol/draft-openconnect.xml (draft-mavrogiannopoulos-openconnect-04/05, "The OpenConnect VPN Protocol Version 1.2", 2023)
---

# OpenConnect Protocol — Extracted Requirements

This is a **working extraction**, not a normative spec for ocserv. It applies
`requirements-elicitation.md` to the OpenConnect protocol draft
(`draft-mavrogiannopoulos-openconnect-04`/`-05`), which describes the
**generic, client-agnostic** wire protocol that both the `openconnect` client
and `ocserv` implement, and which AnyConnect is "believed to be compatible
with."

IDs here are `OC-PROTO-<CAT>-<NNN>` using the `protocol/unified.md` category
tags (`CONN`, `AUTH`, `DATA`, `CTRL`, `SEC`, `EXT`, `COMPAT`) so that
`requirements-reconciliation.md` can align them directly against
`AC-CLIENT-*` (observed AnyConnect behavior) and `OCSERV` (current
`internal/worker.md` + code) entries. These IDs are **not** cited from
`internal/*` — only `protocol/unified.md` may reference them.

Per Phase 1 of the elicitation protocol: **in scope** is the wire protocol
(TLS/HTTP/CONNECT handshake sequence, CSTP/DTLS framing, rekey/DPD/keepalive,
compression). **Out of scope**: the specific XML schema validation rules
beyond the DTD given, and any ocserv-side IPC — those belong to `internal/*`.

---

## CONN — Tunnel establishment

### OC-PROTO-CONN-001
**Requirement:** The client SHOULD negotiate TLS 1.2 or later for the initial
HTTPS connection to the server's well-known port (conventionally 443).
**Strength:** SHOULD
**Source:** §"VPN tunnel establishment" (tunnel-establishment)
**Notes:** "SHOULD" not "MUST" — a server MAY be configured to accept earlier
TLS versions for legacy clients. `[CANDIDATE for unified.md: ocserv's
`min-tls-version` / `default-priorities` config interacts with this — check
default `priorities` string for the effective floor.]`

### OC-PROTO-CONN-002
**Requirement:** The client SHOULD include the Server Name Indication (SNI,
RFC 6066) extension in its initial TLS ClientHello, carrying the DNS name of
the server it intends to reach.
**Strength:** SHOULD
**Source:** §"Tunnel initiation" (tunnel-initiation)
**Notes:** Maps directly to `internal/worker.md` REQ-WORKER-NET-001
(`hello_hook_func` vhost selection by SNI). `[CANDIDATE: unified.md should
note ocserv's behavior for a client that omits SNI entirely — falls back to
default vhost, per REQ-WORKER-NET-001.]`

### OC-PROTO-CONN-003
**Requirement:** After the TLS session is established, the client MUST send
an HTTP POST to `/` with a `config-auth` XML body of `type="init"` and
`Content-Type: text/xml`, regardless of which authentication method(s) it
supports.
**Strength:** MUST
**Source:** §"Tunnel initiation" (tunnel-initiation), example XML
**Notes:** This is the protocol's single entry point — all authentication
flows (password, certificate, SPNEGO) begin from the server's response to
this POST.

### OC-PROTO-CONN-004
**Requirement:** Upon receipt of a `config-auth` reply of `type="complete"`
(with `<auth id="success">`), the client MUST issue an HTTP `CONNECT
/CSCOSSLC/tunnel HTTP/1.1` request over the same TLS connection to initiate
the VPN tunnel.
**Strength:** MUST
**Source:** §"Tunnel and channels establishment" (params-exchange)
**Notes:** The literal path `/CSCOSSLC/tunnel` is a fixed, Cisco-derived
string in the *generic* protocol — not an AnyConnect-only extension. Maps to
`internal/worker.md` REQ-WORKER-NET-002 (`connect_handler` accepts only this
path, plus a documented Clavister-client variant).

### OC-PROTO-CONN-005
**Requirement:** The CONNECT request MUST advertise client capabilities via
HTTP headers: `X-CSTP-Address-Type` (comma-separated `IPv4`/`IPv6`/both),
`X-CSTP-Base-MTU`, and optionally `X-CSTP-Accept-Encoding` and `User-Agent`.
**Strength:** MUST (Address-Type, Base-MTU) / MAY (Accept-Encoding,
User-Agent)
**Source:** §"Client capabilities" (capabilities)

### OC-PROTO-CONN-006
**Requirement:** After a successful CONNECT, the server's response MUST be
the last HTTP message on this connection — the TCP connection then becomes
the CSTP channel, transporting framed IP packets (§"primary-channel-protocol")
for the remainder of the session.
**Strength:** MUST
**Source:** §"The primary CSTP channel - TCP" (primary-channel)
**Notes:** **[Missing conditional branch — Phase 3]** The draft does not
specify what a client should do if the server sends *additional* HTTP
headers/data after the CONNECT response but before the first CSTP frame, nor
what a server should do if it receives non-CSTP-framed bytes immediately
after sending its CONNECT response. `[CANDIDATE: unified.md should record
ocserv's actual behavior here as `OCSERV`-side, likely DIVERGENT or
UNIVERSAL-by-silence.]`

### OC-PROTO-CONN-007
**Requirement:** The server's CONNECT response configuration headers
(`X-CSTP-Address`, `X-CSTP-Netmask`, `X-CSTP-Address-IP6`, `X-CSTP-DNS`,
`X-CSTP-Default-Domain`, `X-CSTP-Split-DNS`, `X-CSTP-Split-Include`,
`X-CSTP-Split-Exclude`, `X-CSTP-Base-MTU`, `X-CSTP-DynDNS`,
`X-CSTP-Content-Encoding`, `X-DTLS-Content-Encoding`) constitute the client's
tunnel networking configuration; absence of any `X-CSTP-Split-Include` header
means the client MUST route its default route through the VPN.
**Strength:** MUST (default-route inference) / the headers themselves are
each individually optional depending on what's been requested/negotiated
**Source:** §"Server response and tunnel configuration" (server-response)
**Notes:** "X-CSTP-Address-IP6 ... prefix length is RECOMMENDED to be set to
127-bits" (RFC 6164) and "X-CSTP-Netmask ... RECOMMENDED the server address to
be the first in defined network" are both SHOULD-strength conventions, not
MUST — `[CANDIDATE: check whether ocserv's `ip-lease.c` (REQ-MAIN-NET-001)
follows the /127 and "server address first" recommendations for IPv6/IPv4
respectively.]`

---

## AUTH — Authentication

### OC-PROTO-AUTH-001
**Requirement:** The server MUST always be authenticated to the client via
its X.509 certificate during the TLS handshake; the server's identity SHOULD
be carried in the certificate's `SubjectAlternativeName` (type `dNSName`).
**Strength:** MUST (server cert auth) / SHOULD (SAN dNSName placement)
**Source:** §"Server authentication" (server-authentication)

### OC-PROTO-AUTH-002
**Requirement:** The protocol allows client authentication via password,
X.509 client certificate, or HTTP SPNEGO (GSSAPI/Kerberos) — singly or in
combination ("or combinations of them").
**Strength:** MAY (the protocol permits all three; deployment-specific which
are enabled)
**Source:** §"Client authentication" (client-authentication)
**Notes:** **[Open-ended enumeration — Phase 3, resolved]** The enumeration
is closed: exactly {password, certificate, SPNEGO} and combinations thereof.
Any ocserv auth backend (PAM, RADIUS, OIDC, plain, GSSAPI) is an
*implementation* of "password" or "SPNEGO" from the protocol's perspective —
`internal/sec-mod.md`'s `auth_mod_st` vtable is the OCSERV-side
implementation point, not a protocol extension. `[CANDIDATE: unified.md
should classify ocserv's OIDC auth as EXTENSION if it doesn't map cleanly
onto "password" — it likely uses a browser redirect flow not described
here.]`

### OC-PROTO-AUTH-003
**Requirement:** It is RECOMMENDED that clients complete authentication
within a single TLS session and rely on TLS session resumption for
reconnection, because splitting username/password across separate TLS/HTTP
connections (a legacy pattern some clients use) prevents the server from
binding the TLS channel to the VPN session (RFC 5056 channel binding).
**Strength:** SHOULD NOT (split-connection auth) / SHOULD (single-session +
resumption)
**Source:** §"Client authentication" (client-authentication), penultimate
paragraph
**Notes:** This directly motivates `internal/ipc.md` REQ-IPC-010
(`sec_auth_init_hmac` anti-replay) and `internal/worker.md`
REQ-WORKER-SEC-003 (DTLS-PSK derived from the CSTP TLS session) — ocserv's
design assumes the RECOMMENDED single-session model and adds its own binding
(HMAC over `remote_ip`/`our_ip`/`session_start_time`) as defense for clients
that still split connections. `[CANDIDATE: unified.md SEC entry — does
ocserv's HMAC scheme provide equivalent channel binding to RFC 5056 for the
legacy split-connection case, or only mitigate replay?]`

### OC-PROTO-AUTH-004
**Requirement:** During password authentication, the server presents one or
more `config-auth` `type="auth-request"` forms (each potentially requesting
multiple fields, e.g. username+password, or a second-factor token in a
follow-up form); the client responds via HTTP POST to the form's `action`
URL with a `type="auth-reply"` body. The server MAY repeat this exchange
(HTTP 200 + new `auth-request`) an arbitrary number of times before either
`type="complete"` (success) or HTTP 401 (failure).
**Strength:** MUST (the request/reply/complete shapes) / MAY (number of
rounds)
**Source:** §"Tunnel authentication using passwords"
(authentication_pass)
**Notes:** Maps to `internal/ipc.md` REQ-IPC-015/016 (`SEC_AUTH_CONT`
multi-round) and `internal/authentication.md` REQ-AUTH-AUTH-002 (`auth_msg`
always called when continuing).

### OC-PROTO-AUTH-005
**Requirement:** If client authentication fails (password or SPNEGO), the
server MUST respond with HTTP 401 Unauthorized.
**Strength:** MUST
**Source:** §"Tunnel authentication using passwords" (authentication_pass),
§"Tunnel authentication using SPNEGO" (authentication_gssapi)
**Notes:** **[Missing negative requirement — Phase 3, resolved by spec
itself]** This *is* the negative requirement; pairs with OC-PROTO-AUTH-004's
success case. `[CANDIDATE: unified.md should check whether ocserv ever
returns a non-401 status (e.g. 403, 503) on auth failure for any auth
backend — `internal/worker.md` REQ-WORKER-AUTH-004 shows camouflage mode
deliberately returns 405 instead, which would be a documented DIVERGENT/
EXTENSION case.]`

### OC-PROTO-AUTH-006
**Requirement:** It is RECOMMENDED that clients pad authentication XML
bodies containing username/password to a multiple of 64 bytes (via an
`X-Pad` HTTP header with arbitrary printable data) to reduce the information
a passive eavesdropper gains from observing encrypted message lengths.
**Strength:** SHOULD
**Source:** §"Tunnel authentication using passwords" (authentication_pass),
final paragraph
**Notes:** Client-side mitigation; no corresponding server requirement is
stated. `[CANDIDATE: unified.md — does ocserv's worker do anything with an
`X-Pad` header if present (e.g. ignore it safely), or could an oversized
`X-Pad` header interact badly with HTTP header size limits
(`internal/worker.md` "Completeness notes" re: `worker-http.c`)?]`

### OC-PROTO-AUTH-007
**Requirement:** For certificate authentication, the TLS server MUST request
a client certificate during the handshake; because under TLS 1.2 client
certificates are sent unencrypted, certificates used with this protocol
SHOULD NOT contain identifying information beyond a username or pseudonymous
identifier, RECOMMENDED to be placed in the certificate DN's `UID` attribute
(OID 0.9.2342.19200300.100.1.1).
**Strength:** MUST (request cert) / SHOULD NOT (extraneous identifying info
in cert) / RECOMMENDED (UID OID placement)
**Source:** §"Tunnel authentication using certificates" (authentication_cert)
**Notes:** Maps to `internal/authentication.md` REQ-AUTH-AUTH-008/009
(`get_cert_username`, `cert-user-oid` config) and
REQ-AUTH-AUTH-005 (defense-in-depth re-verification).
`cert-user-oid` is configurable in ocserv (not hardcoded to the RFC 4519 UID
OID) — `[CANDIDATE: unified.md EXTENSION — ocserv generalizes "RECOMMENDED
UID OID" into a configurable OID, including the special value
`SAN(rfc822name)` not mentioned in the draft at all.]`

### OC-PROTO-AUTH-008
**Requirement:** On successful certificate validation (after the `init`
POST), the server replies HTTP 200 with `config-auth type="complete"`,
identical in shape to the password-success case; the client then proceeds
directly to CONNECT (OC-PROTO-CONN-004) — there is no certificate-specific
`auth-request`/`auth-reply` round trip.
**Strength:** MUST
**Source:** §"Tunnel authentication using certificates" (authentication_cert)

### OC-PROTO-AUTH-009
**Requirement:** A client supporting HTTP SPNEGO (RFC 4559 / GSSAPI, RFC
2743) MUST signal this in its `init` POST via the header
`X-Support-HTTP-Auth: true`. The server then responds HTTP 401 and SPNEGO
negotiation proceeds per RFC 4559. The server MAY additionally send
`X-Support-HTTP-Auth: fallback` to indicate alternative methods (e.g.
password) are available if SPNEGO fails — a client receiving this header
after a SPNEGO failure SHOULD retry without `X-Support-HTTP-Auth: true`.
**Strength:** MUST (signaling header) / MAY (fallback header) / SHOULD
(client retry behavior)
**Source:** §"Tunnel authentication using SPNEGO" (authentication_gssapi)
**Notes:** **[Missing conditional branch — Phase 3, resolved]** The
"fallback" branch is explicitly the else-case for "SPNEGO advertised but
failed." Maps to `internal/sec-mod.md` GSSAPI auth module (out of detailed
scope per that doc's completeness notes) — `[CANDIDATE: unified.md COMPAT —
does ocserv's GSSAPI module emit `X-Support-HTTP-Auth: fallback` correctly
when GSSAPI auth fails and another module is configured?]`

---

## DATA — CSTP and DTLS channel framing

### OC-PROTO-DATA-001
**Requirement:** Every CSTP channel packet MUST begin with an 8-byte header:
bytes 0-3 fixed to `0x53 0x54 0x46 0x01` ("STF" + 0x01), bytes 4-5 the
big-endian length of the following payload, byte 6 the payload type (see
OC-PROTO-DATA-002), byte 7 fixed `0x00`. The entire 8-byte-header-plus-payload
unit MUST be carried inside a single TLS record.
**Strength:** MUST
**Source:** §"The CSTP Channel Protocol" (primary-channel-protocol), table
`cstp_table`
**Notes:** **[Vague/undefined term — Phase 3]** "fixed to 0x53/0x54/0x46/0x01"
— a receiver encountering a different magic should presumably treat the
connection as protocol-violating, but the draft doesn't say so explicitly.
`[CANDIDATE: unified.md negative requirement — OCSERV's `worker-vpn.c`
`parse_cstp_data` behavior on a bad magic: does it terminate the connection,
log, or silently ignore?]`

### OC-PROTO-DATA-002
**Requirement:** The CSTP/DTLS payload type byte MUST be one of: `0x00`
DATA (IPv4/IPv6 packet), `0x03` DPD-REQ, `0x04` DPD-RESP, `0x05` DISCONNECT
(followed by 1 reason byte), `0x07` KEEPALIVE (no payload), `0x08` COMPRESSED
DATA, `0x09` TERMINATE (server→client only, no payload). A receiver MUST be
able to process both `0x00` and `0x08` regardless of whether compression was
negotiated for *outbound* data (OC-PROTO-EXT-002).
**Strength:** MUST
**Source:** §"The CSTP Channel Protocol" (primary-channel-protocol), table
`packet_table`
**Notes:** **[Open-ended enumeration — Phase 3, resolved]** The set of
payload types is closed (7 values). **[Missing negative requirement —
Phase 3]** No explicit statement of receiver behavior for an *unrecognized*
payload type byte (e.g. `0x01`, `0x02`, `0x06`, or `>=0x0a`).
`[CANDIDATE: unified.md — record OCSERV's actual behavior for unknown CSTP
type bytes as either DIVERGENT (if it errors/disconnects) or an
UNDOCUMENTED gap if it's silently ignored; this is security-relevant as a
potential DoS or parser-confusion vector.]`

### OC-PROTO-DATA-003
**Requirement:** DISCONNECT packets (type `0x05`) MUST carry exactly one
reason byte: `0x70` LOCAL ERROR (session invalidated), `0x91` VPN RECONNECT
(session preserved, client intends immediate reconnect), `0xb0` USER
DISCONNECT (session invalidated), `0xd1` VPN PAUSE (session preserved).
Reason codes not in this set MUST be treated by the receiver as equivalent
to `0x91` (temporary disconnect, session preserved).
**Strength:** MUST
**Source:** §"The CSTP Channel Protocol" (primary-channel-protocol), table
`disconnect_reason_table`
**Notes:** Directly maps to `internal/ipc.md` REQ-IPC-033
(`server_disconnected` → `REASON_SERVER_DISCONNECT`) and
`internal/sec-mod.md` REQ-SECMOD-SESSION-003 (persistent-cookies +
discon_reason). `REASON_USER_DISCONNECT` in ocserv corresponds to `0xb0`;
`[CANDIDATE: unified.md — verify ocserv's internal `discon_reason` enum
(referenced in REQ-SECMOD-SESSION-003) maps 1:1 onto these 4 wire values plus
the "unknown→0x91" fallback rule, including the "session should be
invalidated" vs "preserved" distinction matching
`IS_CLIENT_ENTRY_EXPIRED`/`expire_client_entry` logic.]`

### OC-PROTO-DATA-004
**Requirement:** The DTLS channel packet format consists of a 1-byte header
(same type values as OC-PROTO-DATA-002, from `packet_table`) followed by
data, the whole encapsulated in a single DTLS record (RFC 6347).
**Strength:** MUST
**Source:** §"The DTLS Channel Protocol" (secondary-channel-protocol)
**Notes:** **[Unanchored comparative / underspecified — Phase 3]** The DTLS
header is 1 byte vs. CSTP's 8 bytes — the draft doesn't restate which of the
7 payload types are meaningful over DTLS (e.g. is DISCONNECT/TERMINATE valid
over DTLS, or only DATA/DPD/KEEPALIVE since DTLS is the "secondary,
optional" channel and CSTP remains the control channel?). `[CANDIDATE:
unified.md AMBIGUOUS — needs OCSERV source inspection
(`parse_dtls_data` in worker-vpn.c) to determine which type bytes the
implementation actually accepts on the DTLS channel.]`

---

## CTRL — Rekey, DPD, keepalive

### OC-PROTO-CTRL-001
**Requirement:** The server advertises the rekey method for each channel via
`X-CSTP-Rekey-Method`/`X-DTLS-Rekey-Method`, one of: `none` (no rekey until
2^48 DTLS records / 2^64 TLS records), `ssl` (periodic TLS/DTLS
rehandshake-or-rekey), or `new-tunnel` (periodic full session teardown +
client reconnect). When not `none`, `X-CSTP-Rekey-Time`/`X-DTLS-Rekey-Time`
(seconds) gives the period.
**Strength:** MUST (header semantics) / the chosen method is server policy
**Source:** §"The Channel Re-Key Protocol" (rekey-protocol)
**Notes:** **[Open-ended enumeration — Phase 3, resolved]** Exactly 3 rekey
methods. `[CANDIDATE: unified.md — ocserv's `rekey-method`/`rekey-time`
config options (check `doc/sample.config`) map onto which of these 3? Is
`new-tunnel` actually implemented, or is it client-only behavior ocserv
merely advertises?]`

### OC-PROTO-CTRL-002
**Requirement:** When the `ssl` rekey method is used under TLS/DTLS 1.2, both
peers MUST ensure either safe renegotiation (RFC 5746) is used, or that the
peer's identity (certificate) remains unchanged across the rekey — to prevent
a renegotiation-based identity-substitution attack.
**Strength:** MUST
**Source:** §"The Channel Re-Key Protocol" (rekey-protocol), final paragraph
**Notes:** This is a `SEC`-flavored requirement embedded in the CTRL section.
`[CANDIDATE: unified.md SEC — does GnuTLS's RFC 5746 support make this
automatic for ocserv (i.e. is this requirement satisfied "for free" by the
TLS library and thus UNIVERSAL/no-action), or does ocserv need explicit
identity-pinning logic across a TLS 1.2 rehandshake?]`

### OC-PROTO-CTRL-003
**Requirement:** Any peer receiving a DPD-REQ packet MUST respond with a
DPD-RESP packet carrying identical contents to the request (enabling its use
for Path MTU detection via arbitrary attached data); any peer receiving a
KEEPALIVE packet MUST respond with another KEEPALIVE packet. DPD timing is
advisory to clients but the response obligation is unconditional ("MUST
respond").
**Strength:** MUST
**Source:** §"The Keepalive and Dead Peer Detection Protocols"
(dead-peer-detection)
**Notes:** Server-advertised timing via `X-CSTP-DPD`, `X-CSTP-Keepalive`,
`X-DTLS-DPD`, `X-DTLS-Keepalive` (relative seconds, per-channel).
`[CANDIDATE: unified.md — verify OCSERV worker responds to DPD-REQ with
byte-identical DPD-RESP payload, not just an empty/fixed DPD-RESP — the
"suitable for Path MTU detection" property depends on this.]`

---

## SEC — Security considerations

### OC-PROTO-SEC-001
**Requirement:** Implementations MUST NOT enable payload compression
(`oc-lz4`, `lzs`) by default, because compression before encryption can leak
information about plaintext length/content (CRIME/BREACH-style attacks);
each side MAY still choose to compress individual packets using the
COMPRESSED DATA payload type if compression was explicitly negotiated, and
MUST be able to *receive* both compressed and uncompressed payloads
regardless of its own send-side choice.
**Strength:** MUST NOT (default-on) / MAY (opt-in compression) / MUST
(bidirectional decode capability)
**Source:** §"Compression" (compression), §security-analysis
**Notes:** This is the spec's one explicit `MUST NOT` outside the auth
sections — a strong signal for `protocol/unified.md`. `[CANDIDATE: unified.md
SEC — confirm ocserv's default config has compression disabled
(`doc/sample.config` `compression` option default), and that enabling it
requires an explicit administrator opt-in, not just client advertisement via
`X-CSTP-Accept-Encoding`.]`

### OC-PROTO-SEC-002
**Requirement:** All security considerations of the referenced TLS (RFC 8446)
and DTLS (RFC 6347) specifications apply to this protocol; additionally,
while payload contents are encrypted, payload *lengths* remain visible and
may in some scenarios reveal information about the transferred data, an
effect compression can exacerbate.
**Strength:** MUST (RFC 8446/6347 considerations apply) / informational
(length-leakage caveat)
**Source:** §"Security Considerations" (security-analysis)
**Notes:** This is a blanket incorporation-by-reference — `[CANDIDATE:
unified.md should not attempt to re-derive RFC 8446/6347 requirements
verbatim, but should reference them as the "RFC-TLS/RFC-DTLS" source
category mentioned in the document map, and focus reconciliation on the
OpenConnect-specific deltas in this document.]`

### OC-PROTO-SEC-003
**Requirement:** Because TLS 1.2 and earlier do not encrypt client/server
certificates during the handshake, certificates used with this protocol
SHOULD contain the minimum possible identifying information (reiterates
OC-PROTO-AUTH-007's SHOULD NOT for client certs, extended to server certs).
**Strength:** SHOULD
**Source:** §"Security Considerations" (security-analysis), final paragraph

---

## EXT — Extensibility / compression algorithms

### OC-PROTO-EXT-001
**Requirement:** The set of named compression algorithms for CSTP/DTLS
channels is `oc-lz4` (stateless LZ4) and `lzs` (stateless LZS/Stacker); both
MUST be stateless, specifically so that compression context is not shared
across packets from different sources.
**Strength:** MUST (statelessness) — the algorithm *names* are a closed
enumeration in this draft version
**Source:** §"Compression" (compression), table `compression_table`
**Notes:** **[Open-ended enumeration — Phase 3, resolved for this draft
version]** Exactly 2 algorithms named. `[CANDIDATE: unified.md EXTENSION —
does ocserv support both, one, or additional algorithms beyond this list
(e.g. zlib)? Check `WSRCONFIG(ws)->...` compression config and GnuTLS
capabilities.]`

### OC-PROTO-EXT-002
**Requirement:** `X-CSTP-Content-Encoding` / `X-DTLS-Content-Encoding`
response headers, when present, MUST be set to one of the algorithm names the
client offered via `X-CSTP-Accept-Encoding` / `X-DTLS-Accept-Encoding` —
i.e. the server MUST NOT select a compression algorithm the client did not
advertise support for.
**Strength:** MUST NOT (select unadvertised algorithm)
**Source:** §"Server response and tunnel configuration" (server-response)

---

## Completeness notes

- **`example-session1.atxt`/`.uml`** (sibling files in the protocol repo, not
  read in this pass): likely a worked example consistent with the
  "Overview of the tunnel establishment" ASCII diagram already extracted
  inline (§example-session) — `[CANDIDATE: skip; the inline diagram already
  covers the same sequence as OC-PROTO-CONN-001..006.]`
- **DTD (`config-auth.dtd`, §dtd-decl)**: defines the XML schema for
  `config-auth`/`auth`/`form`/`input`/`select`/`option` elements, including a
  `select name="group_list"` element not otherwise discussed in the prose.
  `[UNDOCUMENTED in the prose: candidate OC-PROTO-AUTH-* for group selection
  via a `<select name="group_list">` form — this likely corresponds to
  ocserv's `auth-group`/multi-group selection UI (`internal/worker.md`
  `resolve_selected_group`/`append_group_idx` functions, referenced but not
  detailed in worker.md). Should be elicited as its own requirement before
  reconciliation, since `internal/worker.md` has direct code for this.]`
- **Versioning**: the draft is "Version 1.2" with no discussion of how a
  client/server negotiate or detect protocol version, beyond the
  `<version who="vpn">v5.01</version>` / `<version who="sg">0.1(1)</version>`
  free-form strings in the XML, which appear to be client/server *software*
  versions, not protocol versions. `[CANDIDATE: unified.md AMBIGUOUS — is
  there any protocol-level version negotiation at all, or is compatibility
  determined entirely by which optional headers/features are present
  ("feature detection" rather than version negotiation)?]`
