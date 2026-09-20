---
title: authentication and accounting requirements
generator: requirements-from-implementation
process: sec-mod (primary), worker (credential transport), main (vhost config)
id-prefix: REQ-AUTH
sources:
  - src/sec-mod-auth.c
  - src/sec-mod-auth.h
  - src/auth/common.c
  - src/auth/common.h
  - src/auth/plain.c
  - src/auth/plain.h
  - src/auth/pam.c
  - src/auth/pam.h
  - src/auth/radius.c
  - src/auth/radius.h
  - src/auth/gssapi.c
  - src/auth/gssapi.h
  - src/auth/openidconnect.c
  - src/auth/openidconnect.h
  - src/acct/pam.c
  - src/acct/radius.c
  - src/config.c
  - src/subconfig.c
  - src/worker-auth.c
  - doc/sample.config
  - doc/README-radius.md
  - doc/README-oidc.md
  - doc/requirements/internal/sec-mod.md
  - doc/requirements/internal/worker.md
  - doc/requirements/internal/ipc.md
---

# Authentication and Accounting Requirements

This document covers everything that decides *who a client is* and *which
group they belong to*: the `auth_mod_st` vtable contract (`src/sec-mod-auth.h`),
each authentication method implementing it (`src/auth/*`), how `auth=` /
`enable-auth=` / `acct=` are parsed and composed (`src/config.c`,
`src/subconfig.c`), and the worker-side credential-transport guarantees that
support it (`src/worker-auth.c`). It does not cover session/cookie lifecycle,
IP banning infrastructure, or the camouflage HTTP gate, which remain in
`internal/sec-mod.md` and `internal/worker.md`.

It also covers the **ACCT** category: selection of the `acct=` method
(`src/acct/*`) and the RADIUS accounting record lifecycle (`REQ-AUTH-ACCT-*`),
since both share the same `auth_mod_st`-adjacent module-registration and
per-vhost configuration machinery as authentication. The accounting-related
*configuration options* themselves (`acct=`, RADIUS/PAM accounting
suboptions, and their defaults) are documented for administrators in
`doc/sample.config` and `doc/ocserv.8.md`; this document covers the
*behavioral* requirements those options drive.

`doc/sample.config` documents six values for `auth=`/`enable-auth=`:
`certificate`, `pam[...]`, `plain[...]`, `radius[...]`, `gssapi[...]`, and (when
built with `SUPPORT_OIDC_AUTH`) `oidc[...]`. `acct=` accepts `radius` or `pam`.

## INIT — registration and composition of authentication methods

### REQ-AUTH-INIT-001 — Authentication methods are registered in a single table; per-method options are parsed by a dedicated `get_brackets_string`

**Requirement:** Every authentication method available to `auth=`/
`enable-auth=` MUST appear in `avail_auth_types[]` with a name, an
`auth_mod_st *` (or `NULL` for `certificate`, which has no module), an
`AUTH_TYPE_*` bitmask, and (optionally) a `get_brackets_string` callback that
parses the method's `[...]` suboptions into a per-method config struct
(`pam_cfg_st`, `plain_cfg_st`, `radius_cfg_st`, `gssapi_cfg_st`, oidc config
path). Unknown suboptions inside `[...]` MUST cause `exit(EXIT_FAILURE)` with
`unknown option '%s'`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:246-267 (`avail_auth_types[]`); src/subconfig.c:107-150
(gssapi), 215-286 (radius), 290-323 (pam), 326-367 (plain), 369+ (oidc)
**Acceptance:** unit, local — for each compiled-in method, configure
`auth = <name>[unknown-option=1]` and confirm `ocserv` exits with "unknown
option 'unknown-option'" before starting any listener.
**Links:** REQ-AUTH-AUTH-010 (certificate), REQ-AUTH-AUTH-011 (plain),
REQ-AUTH-AUTH-017 (pam), REQ-AUTH-AUTH-022 (radius), REQ-AUTH-AUTH-030 (gssapi),
REQ-AUTH-AUTH-036 (oidc)

### REQ-AUTH-INIT-002 — `auth=` (primary) composes methods with AND into a single `auth[0]` entry; at most one may own a module

**Requirement:** For `primary=1` (the `auth=` directive, which may repeat),
`figure_auth_funcs()` MUST merge every listed method into a single
`config->auth[0]`: OR-ing their `AUTH_TYPE_*` bits into `auth[0].type`,
concatenating their names with `+` (e.g. `certificate+pam`), and setting
`auth[0].amod` to the first method's non-NULL `auth_mod_st *`. If a second
listed method also has a non-NULL module (i.e. two password/credential-based
modules in the same `auth=` group), this MUST `exit(EXIT_FAILURE)` with "you
cannot mix multiple authentication methods of %s type". `certificate` (whose
`avail_auth_types[]` entry has `mod == NULL`) MAY be combined with exactly one
module-based method this way.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:304-375 (primary branch), :322-329 (duplicate-module
check)
**Acceptance:** positive, local — `auth = certificate` followed by
`auth = pam[service=ocserv]` in the same vhost; confirm `config->auth[0].type ==
AUTH_TYPE_CERTIFICATE | AUTH_TYPE_PAM | AUTH_TYPE_USERNAME_PASS` and
`auth[0].name == "certificate+pam"`. Negative: `auth = pam[...]` followed by
`auth = radius[...]`; confirm `exit(EXIT_FAILURE)` with "you cannot mix
multiple authentication methods of radius type".
**Links:** REQ-AUTH-INIT-005, REQ-AUTH-AUTH-010, REQ-AUTH-SEC-001

### REQ-AUTH-INIT-003 — `enable-auth=` (alternatives) composes methods with OR into separate `auth[1..]` entries; password-based methods cannot be mixed

**Requirement:** For `primary=0` (the `enable-auth=` directive), each listed
method MUST become its own `config->auth[x]` entry (`x` starting at
`config->auth_methods`), each independently `enabled`, up to
`MAX_AUTH_METHODS`; exceeding that limit MUST `exit(EXIT_FAILURE)`.
`check_for_duplicate_password_auth()` MUST `exit(EXIT_FAILURE)` with "you
cannot mix multiple password authentication methods" if more than one
configured `auth[i]` (across `auth[0]` from `auth=` and all `enable-auth=`
alternatives) has `AUTH_TYPE_USERNAME_PASS` set — i.e. `pam`, `plain`, and
`radius` cannot appear as alternatives to each other (each may still appear
combined with `certificate` per REQ-AUTH-INIT-002, and only once).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:376-438 (alternatives branch); :269-288
(`check_for_duplicate_password_auth`)
**Acceptance:** positive, local — `auth = certificate`,
`enable-auth = gssapi`; confirm `config->auth_methods == 2` with
`auth[1].type == AUTH_TYPE_GSSAPI`. Negative — `auth = pam[...]`,
`enable-auth = radius[...]`; confirm `exit(EXIT_FAILURE)` with "you cannot mix
multiple password authentication methods".
**Links:** REQ-AUTH-INIT-004, REQ-AUTH-SEC-001

### REQ-AUTH-INIT-004 — `set_module()` selects the first configured `auth[i]` whose type bitmask matches the worker's requested auth type

**Requirement:** On `SEC_AUTH_INIT`, sec-mod MUST scan
`vhost->static_config.auth[0..auth_methods-1]` in declaration order and select
the first entry `e` for which `(e.type & req_auth_type) != 0` (the worker's
requested auth method, derived from how the client authenticated to the HTTPS
endpoint — certificate presented, Basic-Auth credentials, SPNEGO token, OIDC
bearer token), binding `e->module = config->auth[i].amod`,
`e->auth_type = config->auth[i].type`, and the corresponding
`vhost_auth_ctx`/`vhost_acct_ctx`. If no entry matches, authentication MUST
fail.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:841-871 (`set_module`)
**Acceptance:** unit, local — with `auth = certificate+pam` and
`enable-auth = gssapi`, send `SEC_AUTH_INIT` with `auth_type =
AUTH_TYPE_GSSAPI`; confirm `e->module == gssapi_auth_funcs` and
`e->auth_type == AUTH_TYPE_GSSAPI` (the second configured entry, not the
first). Negative: send `auth_type = AUTH_TYPE_OIDC` (not configured for this
vhost); confirm `set_module` finds no match and authentication fails.
**Links:** REQ-AUTH-AUTH-001

### REQ-AUTH-INIT-005 — `cert-user-oid` is mandatory whenever certificate authentication causes a client certificate to be requested or required

**Requirement:** If `auth[0].type & AUTH_TYPE_CERTIFICATE` and
`auth_methods == 1` (certificate is the *only* primary method), config
validation MUST set `cert_req = GNUTLS_CERT_REQUIRE` (or `GNUTLS_CERT_REQUEST`
under `cisco-client-compat`). If certificate is combined with another method
(REQ-AUTH-INIT-002) or appears only as an `enable-auth=` alternative,
`cert_req = GNUTLS_CERT_REQUEST` (optional). In either case, if `cert_req != 0`
and `config->cert_user_oid == NULL`, config validation MUST
`exit(EXIT_FAILURE)`. If `cert_user_oid` is set, it MUST be either a numeric
OID or the literal string `SAN(rfc822name)`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:1992-2030
**Acceptance:** negative, local — set `auth = certificate` without
`cert-user-oid`; confirm config validation fails with "a certificate is
requested by the option 'cert-user-oid' is not set". Positive — set
`cert-user-oid = SAN(rfc822name)` and confirm it is accepted; set
`cert-user-oid = not-an-oid` and confirm rejection.
**Links:** REQ-AUTH-AUTH-005, REQ-AUTH-AUTH-010

## AUTH — `auth_mod_st` vtable contract

The vtable is defined in `src/sec-mod-auth.h`:
`type`, `allows_retries`, `vhost_init`/`vhost_deinit`, `auth_init`, `auth_msg`,
`auth_pass`, `auth_group`, `auth_user`, `auth_deinit`, `group_list`. The
following requirements were relocated here (with new IDs) from
`internal/sec-mod.md` (`REQ-SECMOD-AUTH-001..006`) and `internal/worker.md`
(`REQ-WORKER-AUTH-001..003`) because they describe the authentication-method
contract itself rather than sec-mod's or the worker's session machinery.
`internal/sec-mod.md` and `internal/worker.md` now cross-link here.

### REQ-AUTH-AUTH-001 — `auth_init` return value drives `PS_AUTH_INIT` vs multi-factor continuation

**Requirement:** `auth_mod_st.auth_init()` MUST return `0` for single-step
authentication that is immediately decided by `auth_pass`, or
`ERR_AUTH_CONTINUE` if the module requires `auth_msg`/`auth_pass` rounds before
a verdict (multi-factor); any other negative return MUST cause sec-mod to set
`e->status = PS_AUTH_FAILED` and reply `SEC_AUTH_REP(FAILED)` without calling
`auth_msg`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:946-952 (`handle_sec_auth_init` dispatch);
src/sec-mod-auth.c:374-381,440-460 (`handle_sec_auth_res`)
**Acceptance:** unit, local — for a mock module returning each of `0`,
`ERR_AUTH_CONTINUE`, and `-1` from `auth_init`, confirm sec-mod's resulting
`e->status` and the `SEC_AUTH_REP` reply type match this contract.
**Links:** REQ-IPC-010, REQ-AUTH-AUTH-002

### REQ-AUTH-AUTH-002 — `auth_msg` is called whenever continuing

**Requirement:** Whenever `auth_init`/`auth_pass` returns `0` or
`ERR_AUTH_CONTINUE` and `e->module` is non-NULL, sec-mod MUST call
`auth_msg()` to obtain the next prompt (`passwd_msg_st`) before deciding
whether the session is complete or needs another `SEC_AUTH_CONT` round. A
negative return from `auth_msg` MUST set `e->status = PS_AUTH_FAILED` and
propagate the error.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:374-387
**Acceptance:** unit, local — mock `auth_msg` returning `-1`; confirm
`handle_sec_auth_res` sets `PS_AUTH_FAILED` and returns the error without
sending `SEC_AUTH_REP(MSG)`.
**Links:** REQ-AUTH-AUTH-001

### REQ-AUTH-AUTH-003 — `passwd_counter` increases monotonically and gates retry scoring

**Requirement:** sec-mod MUST track `e->passwd_counter` from
`passwd_msg_st.counter`. A retry of the *same* password stage (`pst.counter <=
e->passwd_counter`) on a module with `allows_retries` set MUST add
`ban_points_wrong_password` to the client's IP score (via
`sec_mod_add_score_to_ip`); advancing to a *new* stage (`pst.counter >
e->passwd_counter`) MUST NOT add ban points.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:384-396
**Acceptance:** unit, local — drive two `SEC_AUTH_CONT` rounds with the same
`pst.counter` value against a module with `allows_retries=1`; confirm exactly
one `CMD_SECM_BAN_IP` is sent with `score = ban_points_wrong_password`. Repeat
with increasing `pst.counter` and confirm no ban message is sent.
**Links:** REQ-SECMOD-SEC-001, REQ-IPC-080, REQ-AUTH-AUTH-015,
REQ-AUTH-AUTH-018, REQ-AUTH-AUTH-027

### REQ-AUTH-AUTH-004 — `auth_group` failure fails the session post `auth_pass` success

**Requirement:** Even after `auth_pass`/`auth_init` report success
(`result == 0`), sec-mod MUST call `check_group()` (which calls
`auth_mod_st.auth_group` if set) and MUST set `e->status = PS_AUTH_FAILED` and
reply `SEC_AUTH_REP(FAILED)` if `check_group()` returns negative — i.e., a
credential check alone is not sufficient for `PS_AUTH_COMPLETED`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:405-415, 309-358
**Acceptance:** negative, local — configure a mock `auth_group` that always
returns `-1`; confirm a session with otherwise-valid credentials still
receives `SEC_AUTH_REP(FAILED)` and `e->status == PS_AUTH_FAILED`.
**Links:** REQ-AUTH-AUTH-005, REQ-AUTH-AUTH-006

### REQ-AUTH-AUTH-005 — Certificate auth: defense-in-depth re-check of `cert-user-oid` / `cert-group-oid`

**Requirement:** When `e->auth_type & AUTH_TYPE_CERTIFICATE`, sec-mod MUST
independently re-verify (not merely trust the worker's TLS handshake result):
  (a) if `vhost->config->cert_user_oid` is set, `e->cert_user_name` MUST be
      non-empty;
  (b) `e->tls_auth_ok` MUST be true;
  (c) if `e->acct_info.username` was already set (e.g. from a prior auth
      stage) and `cert_user_oid` is configured, it MUST equal
      `e->cert_user_name`;
  (d) if `cert_group_oid` is configured, `e->acct_info.groupname` MUST be
      among `e->cert_group_names[]`.
Any failure MUST cause `check_cert_user_group_status()` to return negative,
which `check_group()` propagates as a failed authentication
(REQ-AUTH-AUTH-004).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:229-307 (comment: "Defense in depth: ... The
worker already enforces this, but sec-mod should not rely on the worker having
done so.")
**Acceptance:** [SEC] negative, local — for each of (a)-(d), construct a
`SEC_AUTH_INIT`/`SEC_AUTH_CONT` sequence where the worker-supplied fields
(`tls_auth_ok`, `cert_user_name`, `cert_group_names`) violate the constraint
while `auth_pass` would otherwise succeed; confirm sec-mod rejects in each
case. This is the privilege-boundary test: sec-mod must not trust
worker-reported TLS state.
**Links:** REQ-AUTH-AUTH-004, REQ-AUTH-AUTH-010, REQ-IPC-014

### REQ-AUTH-AUTH-006 — Group selection precedence: module > certificate

**Requirement:** `check_group()` MUST first ask `auth_mod_st.auth_group` (if
set) to determine `e->acct_info.groupname`. Only if that leaves `groupname`
empty AND the user requested a group AND `vhost->config->cert_group_oid` is
configured does sec-mod fall back to matching the requested group against
`e->cert_group_names[]`. If the requested group is not in
`cert_group_names[]` in this fallback path, authentication MUST fail.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:309-358
**Acceptance:** unit, local — (a) mock `auth_group` setting a groupname;
confirm the cert-group fallback is not consulted even if it would disagree.
(b) no `auth_group`, `req_group_name` set to a group not in
`cert_group_names[]`, `cert_group_oid` configured; confirm rejection with log
"is not included on his certificate groups".
**Links:** REQ-AUTH-AUTH-005

### REQ-AUTH-AUTH-007 — Worker delegates all credential verification to sec-mod over `CMD_SEC_AUTH_*`

**Requirement:** The worker MUST NOT itself accept or reject a
username/password/OTP/GSSAPI/OIDC credential — `post_auth_handler()` and its
sub-handlers (`basic_auth_handler`, `oidc_auth_handler`) parse the HTTP
request body and forward credentials to sec-mod via `SEC_AUTH_INIT`/
`SEC_AUTH_CONT` (REQ-IPC-010/015/016), interpreting only the `SEC_AUTH_REP`
reply (`recv_auth_reply()`, `AUTH__REP__{MSG,OK,FAILED}`).
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/worker-auth.c:895-981, src/worker-auth.c:1572 (signature)
**Acceptance:** [SEC] negative — confirm (by code inspection / call-graph)
that no comparison of a client-supplied password against any locally-held
secret exists in `src/worker-*.c`. All `AUTH__REP__FAILED` paths originate
from a `recv_auth_reply`/`recv_cookie_auth_reply` result, never from local
string comparison. Cross-references REQ-AUTH-AUTH-001.
**Links:** REQ-IPC-010, REQ-IPC-015, REQ-IPC-016, REQ-AUTH-AUTH-001

### REQ-AUTH-AUTH-008 — Certificate username/groups are extracted once and cached; sec-mod's check is consistency-checking of worker-reported fields, not re-derivation from a raw certificate

**Requirement:** `get_cert_names()` MUST be idempotent — if
`ws->cert_username[0] != 0 || ws->cert_groups_size > 0`, it returns immediately
without re-parsing the certificate. The worker's parsed
`ws->cert_username`/`ws->cert_groups` are sent to sec-mod as part of
`SEC_AUTH_INIT` (`req->cert_user_name`/`req->cert_group_names`,
src/ipc.proto:251-252) and copied verbatim into
`e->cert_user_name`/`e->cert_group_names[]` (src/sec-mod-auth.c:990-995).
`sec_auth_init_msg` has **no raw-certificate, certificate-hash, or other
corroborating field** (src/ipc.proto:246-264), and neither
`cert_user_name`/`cert_group_names` nor `tls_auth_ok` is covered by
`sec_auth_init_hmac` (src/sec-mod-auth.c:899-908 builds the HMAC from
`orig_remote_ip`/`our_ip`/`session_start_time` only). REQ-AUTH-AUTH-005's
`check_cert_user_group_status()` therefore cross-checks these fields for
*internal consistency against other worker-supplied fields*
(`e->acct_info.username`/`groupname`, also from the same `SEC_AUTH_INIT`) — it
does **not** re-derive identity from any certificate material sec-mod itself
examines, because sec-mod never receives the certificate. The worker's parsing
exists for UI/cookie purposes (e.g. populating `ws->username` for logging
before sec-mod replies) and MUST NOT be treated as authoritative by anything
downstream of sec-mod (e.g. accounting), but sec-mod itself has no independent
ground truth to validate it against either.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-auth.c:605-704; src/sec-mod-auth.c:990-995, 899-908;
src/ipc.proto:246-264, 251-252
**Acceptance:** [SEC] negative — modify a test client to send a
`SEC_AUTH_INIT` with a `cert_username`/`cert_groups` that doesn't match the
actual certificate's DN (requires a custom worker build, since the real worker
always derives it from the cert); confirm `check_cert_user_group_status()`
(REQ-AUTH-AUTH-005) rejects an internally-*inconsistent* set of worker-supplied
fields (e.g. `cert_user_name` disagreeing with a pre-set `acct_info.username`).
`[SEC-RISK: this test cannot demonstrate the stronger property "sec-mod detects
a forged-but-internally-consistent set" — e.g. `tls_auth_ok=true`,
`cert_user_name="victim"`, `user_name="victim"`, `cert_group_names`/`group_name`
all naming the victim's group, sent together by a compromised worker without
any client certificate ever being presented. Under the trust model where a
worker is "potentially compromised" (contrib/ai/protocols/security-vulnerability.md,
Trust Boundary Model), this set passes every check in
`check_cert_user_group_status()` and is indistinguishable from a legitimate
certificate-authenticated session, for `auth = certificate` (and
`certificate+<password>`, on the certificate half) vhosts. Closing this gap
would require extending `sec_auth_init_hmac` (or a new IPC field) to cover
`tls_auth_ok`/`cert_user_name`/`cert_group_names`/`auth_type` so sec-mod can
detect a worker reporting values main did not expect for that connection, or
forwarding cert material (hash/DN) for sec-mod to check directly. Both options
change the worker/sec-mod IPC contract and need maintainer design review per
AGENTS.md's privilege-boundary criteria — flagging here, not resolving
unilaterally.]`
**Links:** REQ-AUTH-AUTH-005, REQ-AUTH-AUTH-006, REQ-AUTH-AUTH-010,
REQ-SECMOD-SEC-004

### REQ-AUTH-AUTH-009 — `get_cert_username` never returns a positive value, distinguishing "not found" from "SAN type" codes

**Requirement:** `get_cert_username()` MUST return 0 on success or a negative
GnuTLS error code (never a positive value) — specifically, when searching for
an `SAN(rfc822name)` and `gnutls_x509_crt_get_subject_alt_name` returns a
non-matching positive SAN-type code, the loop MUST continue (not return that
positive code), and exhaustion MUST yield
`GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE` (negative).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-auth.c:557-603 (comment explains the rationale)
**Acceptance:** unit, local — configure `cert-user-oid = SAN(rfc822name)` and
present a certificate whose SANs include only non-rfc822name entries (e.g. a
DNS SAN before any rfc822Name, or none at all); confirm `get_cert_username`
returns a negative value (and `get_cert_names` logs "the certificate does not
contain ... cannot determine username") rather than misinterpreting a positive
SAN-type return as success.
**Links:** REQ-AUTH-AUTH-010

## AUTH — certificate

### REQ-AUTH-AUTH-010 — Certificate authentication has no module; identity comes from the TLS handshake under `cert-user-oid`/`cert-group-oid`

**Requirement:** `certificate` in `avail_auth_types[]` has `mod == NULL` and no
`get_brackets_string` — it contributes only `AUTH_TYPE_CERTIFICATE` to
`auth[0].type`. There is no `auth_init`/`auth_pass` round for it: identity and
group membership come entirely from the already-completed TLS client
certificate verification (`e->tls_auth_ok`, `e->cert_user_name`,
`e->cert_group_names[]`), gated by `cert-user-oid`/`cert-group-oid`
(REQ-AUTH-INIT-005) and re-checked per REQ-AUTH-AUTH-005/006. When combined
with a password method (`certificate+pam`, etc., REQ-AUTH-INIT-002), both the
certificate check and the password module's `auth_init`/`auth_pass` MUST
succeed.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:262 (`avail_auth_types[]` entry); src/sec-mod-auth.c:
229-358
**Acceptance:** positive, local — `auth = certificate+pam`, present a valid
client certificate and correct PAM password; confirm `PS_AUTH_COMPLETED`.
Negative — same config, valid certificate but wrong PAM password; confirm
`PS_AUTH_FAILED` even though the certificate alone would pass
REQ-AUTH-AUTH-005.
**Links:** REQ-AUTH-INIT-002, REQ-AUTH-INIT-005, REQ-AUTH-AUTH-005,
REQ-AUTH-AUTH-006, REQ-AUTH-AUTH-008

### REQ-AUTH-AUTH-041 — Worker auto-selects the certificate group when exactly one is eligible, avoiding an unnecessary group-selection prompt

**Requirement:** In `post_auth_handler()`, when `AUTH_TYPE_CERTIFICATE` is
active, `ws->cert_groups_size > 0`, and the client did not request a group
(no `group_list`/`group-select` field, no `select-group-by-url` match, and
`default-select-group` not requested), the worker MUST NOT unconditionally
respond with the "Please select your group." prompt. It MUST first compute
the set of *eligible* certificate groups: if `select-group` is configured
(`WSRCONFIG(ws)->n_group_list > 0`), eligible groups are the entries of
`ws->cert_groups[]` that also appear in `WSRCONFIG(ws)->group_list[]`;
otherwise (no `select-group` configured) every entry of `ws->cert_groups[]`
is eligible. If exactly one eligible group exists, the worker MUST set
`ws->groupname` to it and proceed with `SEC_AUTH_INIT` as if the client had
requested that group, completing authentication without an extra round trip.
If zero or more than one eligible groups exist, the "Please select your
group." prompt (and the cert-group fallback of REQ-AUTH-AUTH-006) is
unchanged.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-auth.c:1730-1738
**Acceptance:** positive, local — `cert-group-oid` configured, no
`select-group` list, client certificate carries exactly one group (OU); a
first POST with no `<group-select>` completes directly with
`<auth id="success">` and a `Set-Cookie: webvpncontext=` header. Negative,
local — client certificate carries multiple groups (OUs) and no
`select-group` list is configured (or more than one of its groups matches a
configured `select-group` list); a first POST with no `<group-select>` still
yields "Please select your group." and no session cookie.
**Links:** REQ-AUTH-AUTH-006, REQ-AUTH-AUTH-010

## AUTH — plain (`auth = plain[passwd=...,otp=...]`)

### REQ-AUTH-AUTH-011 — `plain[...]` requires at least one of `passwd=`/`otp=`; `vhost_init` fails closed without it

**Requirement:** `plain_get_brackets_string()` MUST parse `passwd=<path>` and
(when built `HAVE_LIBOATH`) `otp=<path>`, also accepting the legacy
`[/path/to/passwd]` form for `passwd`. If neither is set,
config parsing MUST `exit(EXIT_FAILURE)` with "no password or OTP file
specified". `plain_vhost_init()` MUST itself `exit(EXIT_FAILURE)` if
`additional == NULL` (i.e. `plain` configured with no `[...]` at all).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/subconfig.c:326-367; src/auth/plain.c:63-83 (`plain_vhost_init`)
**Acceptance:** negative, local — `auth = plain` (no brackets); confirm
`exit(EXIT_FAILURE)`. `auth = plain[foo=bar]`; confirm "no password or OTP
file specified". Positive — `auth = plain[passwd=%SRCDIR%/tests/data/test1.passwd]`
starts successfully.
**Links:** REQ-AUTH-AUTH-012

### REQ-AUTH-AUTH-012 — `passwd=` file format is `username:groupname1,groupname2,...:hash`; a `dummy_salt` is captured for timing normalization

**Requirement:** `read_auth_pass()` MUST parse each line of the `passwd=` file
as `username:groups:hash`, splitting `groups` on `,` via `break_group_list()`
into `pctx->groupnames[]` (capped at `MAX_GROUPS`). The matched user's hash is
copied into `pctx->cpass`. While scanning, the first non-empty hash field seen
on *any* line (regardless of whether it matches the requested username) MUST
be copied into `pctx->dummy_salt` for use by REQ-AUTH-AUTH-013.
`read_auth_pass()` MUST always return `0` — an unknown username is not a parse
error.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/plain.c:142-218
**Acceptance:** unit, local — passwd file with two users `alice:grp1,grp2:$5$...`
and `bob:grp3:$5$...`; authenticate as `alice`; confirm `pctx->groupnames ==
{"grp1","grp2"}` and `pctx->cpass` matches alice's hash. Authenticate as an
unknown user `eve`; confirm `read_auth_pass` returns `0` and `pctx->cpass[0]
== 0` but `pctx->dummy_salt` is non-empty (taken from alice's or bob's entry).
**Links:** REQ-AUTH-AUTH-013, REQ-AUTH-AUTH-016

### REQ-AUTH-AUTH-013 — `plain_auth_pass` always calls `crypt()`, even for unknown users, to prevent timing-based username enumeration

**Requirement:** `plain_auth_pass()` MUST call `crypt(pass, salt)`
unconditionally on every invocation, regardless of whether the username was
found: `salt` is `pctx->cpass` if the user is known, else `pctx->dummy_salt`
if one was captured (REQ-AUTH-AUTH-012), else the fixed fallback
`"$5$fakesalt$"`. The result MUST be compared against `pctx->cpass` and MUST
NOT match for an unknown user (`pctx->cpass[0] == 0`), so the rejection path
for "unknown user" and "wrong password for a known user" perform the same
`crypt()` work and differ only in the final comparison.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/plain.c:300-330 (comment: "Always call crypt() to
normalize timing regardless of whether the user exists")
**Acceptance:** [SEC] negative — authenticate with a known username and wrong
password, and with an unknown username and any password; both MUST return
`ERR_AUTH_CONTINUE`/`ERR_AUTH_FAIL` per REQ-AUTH-AUTH-015's retry rules with no
`crypt()` call skipped (verify via strace/ltrace counting `crypt` calls, or a
build-time counter) — i.e. response timing must not distinguish "no such
user" from "bad password".
**Links:** REQ-AUTH-AUTH-012, REQ-AUTH-AUTH-015

### REQ-AUTH-AUTH-014 — OTP verification, when `otp=` is configured, is a second stage after the password stage

**Requirement:** When `HAVE_LIBOATH` and `pctx->config->otp_file` is set,
`plain_auth_pass()` MUST, after the password stage succeeds (or if no
`passwd=` is configured and the password stage is skipped), prompt for an OTP
(`pass_msg_otp`) and verify it with `oath_hotp_validate()` using
`HOTP_WINDOW = 20`. Failure of the OTP step MUST be `ERR_AUTH_FAIL` (no
separate retry budget beyond REQ-AUTH-AUTH-015). If neither `passwd=` nor
`otp=` ultimately yields a password to check (empty password and no OTP
file), `plain_auth_init`/`plain_auth_pass` MUST return `ERR_AUTH_FAIL`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/plain.c:219-256 (`plain_auth_init`), 300-367
(`plain_auth_pass`, OTP branch at 341-365)
**Acceptance:** positive, local — configure `plain[passwd=...,otp=...]`; after
a correct password, confirm a second `SEC_AUTH_CONT` round is required
(`pass_msg_otp`), and a valid HOTP code (within `HOTP_WINDOW`) completes
authentication. Negative — an out-of-window or reused HOTP code yields
`ERR_AUTH_FAIL`.
**Links:** REQ-AUTH-AUTH-011, REQ-AUTH-AUTH-015

### REQ-AUTH-AUTH-015 — `plain` allows up to `MAX_PASSWORD_TRIES - 1` retries via `ERR_AUTH_CONTINUE`

**Requirement:** `plain_auth_funcs.allows_retries == 1`. On a password
mismatch, `plain_auth_pass()` MUST increment `pctx->retries` and, while
`pctx->retries < MAX_PASSWORD_TRIES - 1` (i.e. up to 2 retries for the default
`MAX_PASSWORD_TRIES == 3`), return `ERR_AUTH_CONTINUE` with
`pass_msg_failed`; once the limit is reached, return `ERR_AUTH_FAIL`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/plain.c:300-330; src/auth/common.h
(`MAX_PASSWORD_TRIES == 3`); src/auth/plain.c:490-501 (`plain_auth_funcs`,
`.allows_retries = 1`)
**Acceptance:** negative, local — submit a wrong password 3 times in the same
session; confirm the first 2 return `SEC_AUTH_REP(MSG)` with
`pass_msg_failed` (and increment the IP ban score per REQ-AUTH-AUTH-003), and
the 3rd returns `SEC_AUTH_REP(FAILED)`.
**Links:** REQ-AUTH-AUTH-003, REQ-AUTH-AUTH-013

### REQ-AUTH-AUTH-016 — `plain_auth_group` validates the requested group against the passwd-file groups; `plain_auth_user`/`plain_group_list` do not change identity beyond the passwd file

**Requirement:** `plain_auth_group()` MUST return `-1` (rejecting the session
per REQ-AUTH-AUTH-004) if the worker's `suggested` group is non-empty and not
present in `pctx->groupnames[]`; otherwise it copies the (first, or suggested)
group into `groupname`. `plain_auth_user()` MUST always return `-1` (the
username from `SEC_AUTH_INIT` is authoritative; plain never rewrites it).
`plain_group_list()` MUST build the full set of group names available for
`select-group`/`auto-select-group` by scanning the entire `passwd=` file and
deduplicating via a hash table (`rehash`/`str_cmp`).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/plain.c:259-299 (`plain_auth_group`, `plain_auth_user`);
389-490 (`rehash`, `str_cmp`, `plain_group_list`)
**Acceptance:** negative, local — passwd file entry `alice:grp1,grp2:...`;
request group `grp3` (not in alice's list); confirm `PS_AUTH_FAILED` per
REQ-AUTH-AUTH-004. Positive — request `grp1`; confirm
`e->acct_info.groupname == "grp1"`. `select-group`/`occtl show users` MUST list
the union of all groups across all passwd-file entries.
**Links:** REQ-AUTH-AUTH-004, REQ-AUTH-AUTH-006, REQ-AUTH-AUTH-012

## AUTH — PAM (`auth = pam[service=...,gid-min=...]`)

### REQ-AUTH-AUTH-017 — `pam[...]` options are `service=` (default `"ocserv"`/`PACKAGE`) and `gid-min=`

**Requirement:** `pam_get_brackets_string()` MUST accept only `service` (a
string, stored as `service_name`) and `gid-min` (a non-negative integer,
`exit(EXIT_FAILURE)` if `< 0`); any other suboption MUST
`exit(EXIT_FAILURE)`. If `service` is unset, `pam_vhost_init()` MUST default
`config->service_name` to `PACKAGE` (`"ocserv"`).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/subconfig.c:290-323; src/auth/pam.c:59-76 (`pam_vhost_init`)
**Acceptance:** positive, local — `auth = pam` (no brackets, or
`pam[]`); confirm `pam_start()` is called with service name `"ocserv"`.
`auth = pam[service=sshd]`; confirm `pam_start("sshd", ...)`. Negative —
`pam[gid-min=-1]`; confirm `exit(EXIT_FAILURE)`.
**Links:** REQ-AUTH-AUTH-021

### REQ-AUTH-AUTH-018 — PAM conversation runs in a coroutine; the prompt hash drives `passwd_counter`

**Requirement:** `pam_auth_init()` MUST `pam_start()` and create a coroutine
(PCL `cr`) running `co_auth_user()`, returning `ERR_AUTH_CONTINUE`.
`ocserv_conv()` (the PAM conversation function, running inside the coroutine)
MUST: append `PAM_ERROR_MSG`/`PAM_TEXT_INFO` messages to `pctx->msg`; on
`PAM_PROMPT_ECHO_OFF`/`PAM_PROMPT_ECHO_ON`, set `pctx->state =
PAM_S_WAIT_FOR_PASS` and `co_resume()` back to the caller, then check
`pctx->aborted` before filling the reply from `pctx->password`.
`pam_auth_msg()` MUST, on first entry (`PAM_S_INIT`), `co_call()` to drive the
coroutine to its first prompt, then compute `prompt_hash = hash_any(pctx->msg.data,
pctx->msg.length, 0)`; `pst->counter = pctx->passwd_counter`, and only if
`prompt_hash != pctx->prev_prompt_hash` does it increment
`pctx->passwd_counter` (before updating `prev_prompt_hash`) — i.e. a repeated
identical prompt does NOT advance the counter (REQ-AUTH-AUTH-003 treats it as
a retry of the same stage), but a new/different prompt (e.g. a second factor)
does.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/pam.c:77-171 (`ocserv_conv`), 172-215 (`co_auth_user`),
216-269 (`pam_auth_init`), 270-318 (`pam_auth_msg`)
**Acceptance:** unit, local — configure a PAM service whose stack prompts
twice with different text (e.g. password then a second factor); confirm
`pst.counter` increments between the two `SEC_AUTH_CONT` rounds. Configure a
PAM service that re-prompts with the *same* text on retry (e.g. "Password:"
again after a failure); confirm `pst.counter` does NOT increment, so
REQ-AUTH-AUTH-003 scores it as a retry.
**Links:** REQ-AUTH-AUTH-003, REQ-AUTH-AUTH-019, REQ-AUTH-AUTH-020

### REQ-AUTH-AUTH-019 — `pam_auth_pass` rejects calls outside `PAM_S_WAIT_FOR_PASS`; completion requires `PAM_S_COMPLETE`

**Requirement:** `pam_auth_pass()` MUST return `ERR_AUTH_FAIL` if
`pctx->state != PAM_S_WAIT_FOR_PASS` (the worker sent a password when none was
requested, or sent it twice). On a valid call, it MUST copy `pass` into
`pctx->password`, `co_call()` to resume the PAM conversation, and return `0`
only if the coroutine reaches `PAM_S_COMPLETE`; otherwise (still
`PAM_S_WAIT_FOR_PASS`, another prompt pending) it MUST return
`ERR_AUTH_CONTINUE`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/pam.c:319-353
**Acceptance:** [SEC] negative — send `SEC_AUTH_CONT` with a password before
any `SEC_AUTH_REP(MSG)` prompt was issued (`pctx->state == PAM_S_INIT`);
confirm `ERR_AUTH_FAIL`. Positive — single-factor PAM stack: one
`SEC_AUTH_CONT` with the correct password yields `0` and `PS_AUTH_COMPLETED`
(after REQ-AUTH-AUTH-004's group check).
**Links:** REQ-AUTH-AUTH-018

### REQ-AUTH-AUTH-020 — Expired-password change flow via `PAM_NEW_AUTHTOK_REQD`/`pam_chauthtok`

**Requirement:** `co_auth_user()` MUST run `pam_authenticate()` then
`pam_acct_mgmt()`; if the latter returns `PAM_NEW_AUTHTOK_REQD`, it MUST set
`pctx->changing = 1` and call `pam_chauthtok(ph, PAM_CHANGE_EXPIRED_AUTHTOK)`,
continuing the same conversation (additional prompts for the new password,
each going through `ocserv_conv`/REQ-AUTH-AUTH-018) before reaching
`PAM_S_COMPLETE`. Any other non-`PAM_SUCCESS` result from
`pam_authenticate`/`pam_acct_mgmt`/`pam_chauthtok` MUST end the coroutine
without reaching `PAM_S_COMPLETE`, so `pam_auth_pass` keeps returning
`ERR_AUTH_CONTINUE` until the caller gives up (REQ-AUTH-AUTH-015's analogue:
PAM has no `allows_retries` set, so no extra ban score is added by
REQ-AUTH-AUTH-003 on these intermediate rounds).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/pam.c:172-215 (`co_auth_user`)
**Acceptance:** positive, local — configure a PAM service/account with an
expired password (e.g. `pam_unix` with `chage -d 0`); authenticate with the
old password; confirm additional `SEC_AUTH_CONT` rounds are issued for "new
password"/"retype new password" and, on success, `PS_AUTH_COMPLETED` with the
account's password actually changed (verify via the system password
database). Negative — supply mismatched new passwords; confirm authentication
does not complete.
**Links:** REQ-AUTH-AUTH-018

### REQ-AUTH-AUTH-021 — `pam_auth_group`/`pam_group_list` use the OS group database, filtered by `gid-min`

**Requirement:** `pam_auth_group()` MUST delegate to `get_user_auth_group()`
(`src/auth/auth-unix.h`), which validates/selects the group the same way for
all OS-account-backed methods. `pam_group_list()` MUST call
`unix_group_list(pool, gid_min, ...)`, excluding groups with GID below
`config->gid_min` (default `0`, i.e. no exclusion) from
`select-group`/`auto-select-group` enumeration. `pam_auth_user()` MUST read
`PAM_USER` via `pam_get_item()` (reflecting any username canonicalization PAM
itself performed, e.g. via `pam_unix`'s NSS lookup).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/pam.c:354-385 (`pam_auth_group`, `pam_auth_user`), 405-416
(`pam_group_list`)
**Acceptance:** unit, local — set `gid-min = 1000`; confirm a system group
with GID `999` does not appear in `occtl show ... groups` / is rejected as a
`select-group` value, while a GID `1001` group is accepted.
**Links:** REQ-AUTH-AUTH-004, REQ-AUTH-AUTH-006, REQ-AUTH-AUTH-017

## AUTH — RADIUS (`auth = radius[config=...,groupconfig=...,nas-identifier=...,group-separator=...]`)

### REQ-AUTH-AUTH-022 — `radius[...]` options: `config=` (required), `nas-identifier=`, `group-separator=` (`semicolon`|`comma`, default `;`), `groupconfig=`; legacy `[/path]` form supported

**Requirement:** `radius_get_brackets_string()` MUST accept either the legacy
form `radius[/path/to/radiusclient.conf]` (optionally followed by
`,groupconfig`), or the new form with named suboptions `config=`,
`nas-identifier=`, `group-separator=` (only `semicolon`→`;` or `comma`→`,`,
else `exit(EXIT_FAILURE)`), `groupconfig=` (boolean). `config=` (the
radcli config file path) MUST be set — its absence is
`exit(EXIT_FAILURE)` with "No radius configuration specified". `groupconfig`
(legacy or new) sets `config->sup_config_type = SUP_CONFIG_RADIUS`
(per-group/per-user supplemental config sourced from RADIUS attributes rather
than `occtl`/files — see `internal/config.md`).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/subconfig.c:181-287
**Acceptance:** negative, local — `auth = radius[nas-identifier=foo]` (no
`config=`); confirm "No radius configuration specified". `auth =
radius[config=/etc/radcli.conf,group-separator=pipe]`; confirm "unknown
group-separator value 'pipe'; use 'semicolon' or 'comma'". Positive —
`group-separator=comma` and a `Class` attribute `"OU=grp1,grp2"` splits into
`{"grp1","grp2"}` (REQ-AUTH-AUTH-026).
**Links:** REQ-AUTH-AUTH-026

### REQ-AUTH-AUTH-023 — `radius_vhost_init` loads the radcli config and dictionary at startup; failure is fatal

**Requirement:** `radius_vhost_init()` MUST call `rc_read_config(config->config)`
and `rc_read_dictionary(rh, rc_conf_str(rh, "dictionary"))`, and
`exit(EXIT_FAILURE)` (logging via `fprintf(stderr)`) if either fails — RADIUS
configuration errors MUST be caught at startup, not on the first
authentication attempt. `vctx->group_separator` is set from
`config->group_separator` or defaults to `";"` (REQ-AUTH-AUTH-022).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/radius.c:77-121
**Acceptance:** negative, local — point `config=` at a nonexistent file or one
with an invalid `dictionary` path; confirm `ocserv` exits at startup (before
accepting any connection), not on first client auth.
**Links:** REQ-AUTH-AUTH-022

### REQ-AUTH-AUTH-024 — Usernames without `@` get `default_realm` appended (if configured in the radcli config)

**Requirement:** `radius_auth_init()` MUST check
`rc_conf_str(pctx->vctx->rh, "default_realm")`; if non-empty and
`info->username` contains no `@`, it MUST construct `"<username>@<default_realm>"`
as the username sent in subsequent `Access-Request`s. If `default_realm` is
unset/empty, or the username already contains `@`, the username is used
verbatim.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/radius.c:130-174 (`radius_auth_init`, realm logic at
155-163)
**Acceptance:** positive, local — radcli config with `default_realm = example.com`;
authenticate as `alice`; confirm the `Access-Request`'s `User-Name` is
`alice@example.com`. Authenticate as `bob@other.realm`; confirm `User-Name ==
"bob@other.realm"` (unchanged).
**Links:** REQ-AUTH-AUTH-025

### REQ-AUTH-AUTH-025 — `Access-Request` attribute set

**Requirement:** `radius_auth_pass()` MUST build an `Access-Request`
containing: `User-Name` (REQ-AUTH-AUTH-024), `User-Password` (the submitted
password), `NAS-IP-Address` or `NAS-IPv6-Address` (from `e->our_ip`, whichever
family applies), `NAS-Identifier` if `nas-identifier=` is configured
(REQ-AUTH-AUTH-022), `Calling-Station-Id` (the client's `remote_ip`),
`Connect-Info` (the client's User-Agent string), `Acct-Session-Id` (the
session identifier, when available — see below), `Service-Type =
Authenticate-Only`, `NAS-Port-Type = Async`, and — when continuing a
challenge (REQ-AUTH-AUTH-027) — the `State` attribute echoed back from the
prior `Access-Challenge`.

The `Acct-Session-Id` carries the same session identifier
(`acct_info.safe_id`) that is later sent in the Accounting-Request packets
(REQ-AUTH-ACCT-*). RFC 2866 (section 5.5) allows an Access-Request to carry
`Acct-Session-Id` ("An Access-Request packet MAY have an Acct-Session-Id"),
and requires that if it does, the NAS MUST use the same value in the
Accounting-Request packets for that session — so the two exchanges correlate
on one key. Emitting it during authentication gives the RADIUS server a
per-session key already at Access-Request time (e.g. for `rlm_ippool`, so
concurrent sessions of the same user from the same client do not collide on a
single IP lease).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/radius.c:293-430 (request construction, before
`rc_auth()`/`rc_send_server()`)
**Acceptance:** unit, local — capture the RADIUS request (e.g. via a test
FreeRADIUS server with `auth_log`) for a normal login; confirm all listed
attributes are present with expected values, that a configured
`nas-identifier` appears as `NAS-Identifier`, and that `Acct-Session-Id` is
present and equals the session id reported in the matching Accounting-Request.
**Links:** REQ-AUTH-AUTH-024, REQ-AUTH-AUTH-026, REQ-AUTH-AUTH-027

### REQ-AUTH-AUTH-026 — `Access-Accept` attributes populate group membership and per-session network configuration

**Requirement:** On `OK_RC`, `radius_auth_pass()` MUST:
  (a) require `Service-Type == Framed` in the reply, else fail;
  (b) parse `Class`/`PW_CLASS` via `parse_groupnames()` — if the value matches
      `OU=<group1><sep><group2>...` (where `<sep>` is `group_separator`,
      REQ-AUTH-AUTH-022), split into up to `MAX_GROUPS` group names in
      `pctx->groupnames[]`; otherwise treat the whole value as a single group
      name;
  (c) map `Framed-IPv6-Address`/`Delegated-IPv6-Prefix`/`Framed-IPv6-Prefix` to
      `ipv6`/`ipv6_subnet_prefix`/routes, and `DNS-Server-IPv6-Address`
      (max 2 — a 3rd triggers a warning and is ignored) to `ipv6_dns1`/`ipv6_dns2`;
  (d) map `Framed-IP-Address`/`Framed-IP-Netmask` to `ipv4`/`ipv4_mask` — the
      special RFC 2865 values `0xfffffffe` ("negotiated") and `0xffffffff`
      ("assign from pool") MUST NOT be applied as literal addresses;
  (e) map vendor 311 (Microsoft) attributes 28/29
      (`MS-Primary/Secondary-DNS-Server`) to `ipv4_dns1`/`ipv4_dns2`;
  (f) map `Framed-Route`/`Framed-IPv6-Route` via `append_route()` — a route
      attribute without a `/` (prefix length) MUST be rejected/ignored;
  (g) map `Acct-Interim-Interval`→`pctx->interim_interval_secs` and
      `Session-Timeout`→`pctx->session_timeout_secs`;
  (h) map vendor 10055 (Roaring Penguin) attributes 1/2 to
      `rx_per_sec`/`tx_per_sec`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/radius.c:212-244 (`append_route`), 245-292
(`parse_groupnames`), 293-589 (`radius_auth_pass`, `OK_RC` branch)
**Acceptance:** positive, local — FreeRADIUS test config returning `Class =
"OU=eng;sales"` with `group-separator = semicolon`, `Framed-IP-Address`,
`Framed-Route = "10.0.0.0/24 192.168.1.1 1"`, and MS DNS attributes; confirm
the resulting session has `groupnames == {"eng","sales"}`, the configured
`ipv4`/route/DNS values, and (negative) that a reply with
`Service-Type != Framed` is rejected.
`pctx->interim_interval_secs`/`pctx->session_timeout_secs` from (g) reach the
session's `GroupCfgSt` (`config->interim_update_secs`/
`config->session_timeout_secs`, with the corresponding `has_*` flags) only via
`radius_sup_config.get_sup_config()` (src/sup-config/radius.c:48-54), which is
installed as `vhost->config_module` **only** when `groupconfig=true`
(`SUP_CONFIG_RADIUS`, REQ-AUTH-AUTH-022) — see `internal/config.md`'s
`get_sup_config()`/`apply_default_config()` merge mechanism, which leaves a
`has_*`-set field untouched and falls back to the vhost's
`stats-report-time`/`session-timeout` otherwise (REQ-AUTH-ACCT-003). Without
`groupconfig=true`, `pctx->interim_interval_secs`/`session_timeout_secs` are
parsed from `Acct-Interim-Interval`/`Session-Timeout` but never read —
a RADIUS-supplied interim/session-timeout override is silently ignored unless
`groupconfig=true` is set.
**Links:** REQ-AUTH-AUTH-022, REQ-AUTH-AUTH-006, REQ-AUTH-AUTH-029,
REQ-AUTH-ACCT-003

### REQ-AUTH-AUTH-027 — `Access-Challenge` round-trips the `State` attribute as RADIUS multi-factor; bounded by `MAX_CHALLENGES`

**Requirement:** On `CHALLENGE_RC`, `radius_auth_pass()` MUST extract the
`State` attribute and the challenge prompt (`Reply-Message`) into
`pctx->state`/`pctx->pass_msg`, increment `pctx->id`, and return
`ERR_AUTH_CONTINUE` — UNLESS `pass_msg` is empty, `state == NULL`, or
`pctx->passwd_counter >= MAX_CHALLENGES` (`16`), in which case it MUST fail
with `pass_msg_failed` instead. The next `Access-Request`
(REQ-AUTH-AUTH-025) MUST echo back the saved `State`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/radius.c:72-75 (`CHALLENGE_RC`, `MAX_CHALLENGES`
definitions), 590-652 (challenge handling)
**Acceptance:** positive, local — FreeRADIUS config issuing an
`Access-Challenge` (e.g. an OTP module) with `State` and `Reply-Message` set;
confirm `ERR_AUTH_CONTINUE` and that the follow-up `Access-Request` contains
the same `State`. Negative — a server returning `Access-Challenge` with no
`State` attribute; confirm `pass_msg_failed`/`ERR_AUTH_FAIL`. Negative — drive
`MAX_CHALLENGES + 1` challenge rounds; confirm the `(MAX_CHALLENGES+1)`th
fails regardless of server response.
**Links:** REQ-AUTH-AUTH-025, REQ-AUTH-AUTH-003

### REQ-AUTH-AUTH-028 — `Access-Reject` is retried (up to `MAX_PASSWORD_TRIES - 1`) only at the first stage

**Requirement:** On any RADIUS result other than `OK_RC`/`CHALLENGE_RC`
(typically `Access-Reject`/timeout), `radius_auth_pass()` MUST return
`ERR_AUTH_CONTINUE` with `pass_msg_failed` (allowing the client to retry the
*initial* password) only if `pctx->passwd_counter == 0` AND
`pctx->retries++ < MAX_PASSWORD_TRIES - 1`; otherwise (a reject occurring after
at least one `Access-Challenge` round, or the retry budget exhausted) it MUST
return `ERR_AUTH_FAIL`. `radius_auth_funcs.allows_retries == 1`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/radius.c:590-652 (final `else` branch),
src/auth/common.h (`MAX_PASSWORD_TRIES == 3`)
**Acceptance:** negative, local — `Access-Reject` on the first attempt, twice;
confirm both yield `ERR_AUTH_CONTINUE`/`pass_msg_failed` (2 retries allowed),
and a 3rd `Access-Reject` yields `ERR_AUTH_FAIL`. Negative — a multi-factor
RADIUS flow (one `Access-Challenge` round, `passwd_counter > 0`) followed by
`Access-Reject`; confirm immediate `ERR_AUTH_FAIL` (no retry), even though the
overall `pctx->retries` count is `0`.
**Links:** REQ-AUTH-AUTH-027, REQ-AUTH-AUTH-003

### REQ-AUTH-AUTH-029 — `radius_auth_group` validates against RADIUS-supplied groups; `radius_auth_user` and `radius_group_list` are no-ops

**Requirement:** `radius_auth_group()` MUST behave like
REQ-AUTH-AUTH-016/REQ-AUTH-AUTH-021 — reject (`-1`) a `suggested` group not
present in `pctx->groupnames[]` (populated per REQ-AUTH-AUTH-026), else select
it. `radius_auth_user()` MUST always return `-1` (RADIUS never rewrites the
authenticated username). `radius_auth_funcs.group_list == NULL` — RADIUS
provides no offline group enumeration, so `select-group`/`auto-select-group`
cannot list RADIUS-only groups in advance (they are only known after a
successful auth's `Access-Accept`).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/radius.c:175-211 (`radius_auth_group`,
`radius_auth_user`), 684-699 (`radius_auth_funcs`, `.group_list = NULL`)
**Acceptance:** negative, local — `Access-Accept` with `Class = "OU=eng"`;
request group `sales`; confirm `PS_AUTH_FAILED` per REQ-AUTH-AUTH-004.
Positive — request `eng`; confirm acceptance. Confirm
`auto-select-group`/`select-group` configuration referencing a RADIUS-only
group name does not cause a startup-time enumeration failure (since
`group_list == NULL`).
`[LIMITATION (gitlab#265): the "group" a client requests at connect time
(`req_group_name`, e.g. via `select-group`/`auto-select-group` or a
`https://fqdn/group`-style path — used to pick connect-time config such as
`[split]` routes, client profiles, or even the authentication backend) and the
"group" returned by the credential backend as a *permission* (RADIUS `Class`/
`OU=...`, REQ-AUTH-AUTH-026; or the PAM/plain group list, REQ-AUTH-AUTH-016/021)
are the same namespace and the same value: `radius_auth_group()` requires
`req_group_name` (if non-empty) to already be a member of `pctx->groupnames[]`
— the RADIUS-returned permission groups — or the session is rejected
(REQ-AUTH-AUTH-004). There is no way to select a connect-time configuration
profile that is independent of, or a superset/subset of, the permission
group(s) RADIUS assigns post-authentication; the only current workaround is
separate vhosts (distinct FQDNs) with their own `select-group`/`auth=`
configuration.

A concrete (unmerged, WIP) design exists for this: gitlab!154 proposed (a) a
vhost option (`radius_check_config_groups` in that patch) that, when set,
makes `radius_auth_group()` validate `req_group_name` against the vhost's
configured `select-group` list (`config->group_list[]`) instead of against
`pctx->groupnames[]` — decoupling the connect-time "login group"/tunnel-group
from RADIUS class membership entirely — and (b) a new `per-radius-class-dir`
sup-config source consulted by `radius_get_sup_config()`
(`src/sup-config/radius.c`) for each RADIUS class in `pctx->groupnames[]`,
looking up first `per-radius-class-dir/$class` and then
`per-radius-class-dir/$login_group/$class`, merged into the existing
`config-per-group`/`config-per-user` lookup order from REQ-CONFIG-CFG-006.
gitlab!154 was closed without merging (2020, marked WIP; reviewer requested
tests and `README-radius.md` documentation for each part, which were never
completed) — its approach is a reasonable starting point but would need to be
re-validated against the current `auth_mod_st`/`config_mod_st` interfaces
(both have changed signatures since 2020) and given the test/doc coverage the
review asked for. This would be a config-scope and possibly IPC-contract
change (how `req_group_name` is validated and how
`vhost_auth_ctx`/`vhost_acct_ctx`/per-group config are selected,
REQ-AUTH-INIT-004) and needs maintainer design review per AGENTS.md's
privilege-boundary and "new auth method" criteria — flagging here, not
resolving unilaterally.]`
**Links:** REQ-AUTH-AUTH-004, REQ-AUTH-AUTH-006, REQ-AUTH-AUTH-016,
REQ-AUTH-AUTH-021, REQ-AUTH-AUTH-026, REQ-AUTH-INIT-004

## AUTH — GSSAPI (`auth = gssapi[keytab=...,require-local-user-map=...,tgt-freshness-time=...]`)

### REQ-AUTH-AUTH-030 — `gssapi[...]` options: `keytab=`, `require-local-user-map=` (default true, inverted into `no_local_map`), `tgt-freshness-time=` (non-zero seconds), `gid-min=`

**Requirement:** `gssapi_get_brackets_string()` MUST accept `keytab` (path,
stored verbatim), `require-local-user-map` (boolean; `no_local_map = 1 -
CHECK_TRUE(value)`, so the *default* when unset is `no_local_map == 0`, i.e.
local-user mapping IS required by default), `tgt-freshness-time` (integer
seconds; `0` or non-numeric MUST `exit(EXIT_FAILURE)` with "Invalid value for
'tgt-freshness-time'"), and `gid-min` (non-negative integer). Any other
suboption MUST `exit(EXIT_FAILURE)`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/subconfig.c:107-150
**Acceptance:** negative, local — `gssapi[tgt-freshness-time=0]` and
`gssapi[tgt-freshness-time=notanumber]`; both `exit(EXIT_FAILURE)`. Positive —
`gssapi[require-local-user-map=false]` results in `no_local_map == 1`
(REQ-AUTH-AUTH-033 mapping skipped); default (`gssapi[]` or `require-local-user-map`
unset) results in `no_local_map == 0`.
**Links:** REQ-AUTH-AUTH-033, REQ-AUTH-AUTH-034, REQ-AUTH-AUTH-035

### REQ-AUTH-AUTH-031 — `gssapi_vhost_init` acquires credentials restricted to SPNEGO; failure is fatal

**Requirement:** `gssapi_vhost_init()` MUST call `gss_acquire_cred_from()` with
`keytab` (via `cred_store` if `keytab=` is configured) or `gss_acquire_cred()`
(default credential store otherwise), in both cases restricting
`desired_mechs` to the single-element set `{spnego_mech}`
(`spnego_mech == OID \x2b\x06\x01\x05\x05\x02`, i.e. SPNEGO). Any GSS failure
during credential acquisition MUST `exit(EXIT_FAILURE)` (logging via
`print_gss_err`).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/gssapi.c:87-89 (`spnego_mech`, `desired_mechs`), 91-145
(`gssapi_vhost_init`)
**Acceptance:** negative, local — configure `gssapi[keytab=/nonexistent]`;
confirm `exit(EXIT_FAILURE)` at startup with a GSS error logged. Positive — a
valid keytab readable by the worker's effective credentials before privilege
drop (or accessible after, per deployment) starts successfully.
**Links:** REQ-AUTH-SEC-003

### REQ-AUTH-AUTH-032 — SPNEGO token exchange: base64-decode, `gss_accept_sec_context`, `ERR_AUTH_CONTINUE` while `GSS_S_CONTINUE_NEEDED`

**Requirement:** Both `gssapi_auth_init()` and `gssapi_auth_pass()` MUST
base64-decode the client-supplied SPNEGO token and call
`gss_accept_sec_context()`. While the result is `GSS_S_CONTINUE_NEEDED`, the
function MUST return `ERR_AUTH_CONTINUE` and `gssapi_auth_msg()` MUST
base64-encode the output token (`pctx->msg`) into `pst->msg_str` for the next
round. On `GSS_S_COMPLETE`, the function MUST call `get_name()`
(REQ-AUTH-AUTH-033) and `verify_krb5_constraints()` (REQ-AUTH-AUTH-034); on any
other major status, it MUST return `ERR_AUTH_FAIL`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/gssapi.c:240-300 (`gssapi_auth_init`), 320-364
(`gssapi_auth_pass`), 365-384 (`gssapi_auth_msg`)
**Acceptance:** positive, local — a real Kerberos/SPNEGO client (e.g.
`kinit` + a SPNEGO-capable test client) completes a multi-round negotiation
ending in `PS_AUTH_COMPLETED`. Negative — a malformed/non-base64 token;
confirm `ERR_AUTH_FAIL` rather than a crash.
**Links:** REQ-AUTH-AUTH-033, REQ-AUTH-AUTH-034

### REQ-AUTH-AUTH-033 — `get_name` maps the GSS principal to a local username unless `no_local_map`

**Requirement:** On `GSS_S_COMPLETE`, `get_name()` MUST extract the GSS
principal via `gss_display_name()`. If `pctx->vctx->no_local_map == 0`
(default — see REQ-AUTH-AUTH-030), it MUST additionally call
`gss_localname()` to map the principal to a local username; failure of
`gss_localname()`, or a resulting username that is empty or exceeds the
username buffer, MUST cause `get_name()` to return `-1` (authentication
fails). If `no_local_map == 1`, the raw GSS principal name is used as the
username directly. `gssapi_auth_user()` MUST return this (mapped or raw)
username.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/gssapi.c:155-202 (`get_name`), 310-319
(`gssapi_auth_user`)
**Acceptance:** positive, local — with `require-local-user-map = true`
(default) and `/etc/krb5.conf` `auth_to_local` mapping `alice@REALM` to local
user `alice`; confirm the session's username is `alice`. Negative — a
principal with no local-user mapping; confirm `ERR_AUTH_FAIL`. Positive —
`require-local-user-map = false`; confirm the session's username is the raw
principal (e.g. `alice@REALM`).
**Links:** REQ-AUTH-AUTH-030, REQ-AUTH-AUTH-032

### REQ-AUTH-AUTH-034 — Kerberos ticket freshness check (`tgt-freshness-time`)

**Requirement:** `verify_krb5_constraints()` MUST be a no-op unless the
negotiated mechanism is `krb5` or `krb5_old` AND
`pctx->vctx->ticket_freshness_secs != 0` (REQ-AUTH-AUTH-030). When active, it
MUST extract the ticket's `authtime` via
`gsskrb5_extract_authtime_from_sec_context()` and reject (return `-1`,
yielding `ERR_AUTH_FAIL`) if `time(NULL) > authtime + ticket_freshness_secs` —
i.e. the client's TGT/ticket must have been obtained recently enough.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/gssapi.c:203-239
**Acceptance:** positive, local — `tgt-freshness-time = 3600`; authenticate
with a freshly-obtained Kerberos ticket; confirm success. Negative — present a
ticket whose `authtime` is older than `3600` seconds (e.g. via a test KDC with
a manipulated clock, or `kinit` followed by a sleep exceeding the threshold in
a local test setup); confirm `ERR_AUTH_FAIL`. Confirm `gssapi[]` with no
`tgt-freshness-time` (or a non-krb5 SPNEGO mech, e.g. NTLM-over-SPNEGO if
applicable) performs no freshness check.
**Links:** REQ-AUTH-AUTH-030, REQ-AUTH-AUTH-032

### REQ-AUTH-AUTH-035 — `gssapi_auth_group`/`gssapi_group_list` use the OS group database, filtered by `gid-min`; GSSAPI has no `allows_retries`

**Requirement:** `gssapi_auth_group()` MUST delegate to
`get_user_auth_group()` like REQ-AUTH-AUTH-021. `gssapi_group_list()` MUST
call `unix_group_list(pool, gid_min, ...)`. `gssapi_auth_funcs` does not set
`.allows_retries` (defaults to `0`) — a failed SPNEGO exchange MUST NOT add
`ban_points_wrong_password` via REQ-AUTH-AUTH-003's retry-scoring path
(GSSAPI failures are scored, if at all, only via the generic
`SEC_AUTH_REP(FAILED)` path in REQ-AUTH-AUTH-004's caller, not the
`allows_retries` branch).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/gssapi.c:301-309 (`gssapi_auth_group`), 396-407
(`gssapi_group_list`), 408-422 (`gssapi_auth_funcs`, no `.allows_retries`)
**Acceptance:** unit, local — `gid-min = 1000` excludes low-GID groups from
`select-group` enumeration, as REQ-AUTH-AUTH-021. Confirm (by code inspection
or a mock module) that a `GSS_S_*` failure in `gssapi_auth_pass` does not pass
through the `passwd_retries == 1 && allows_retries` branch of
REQ-AUTH-AUTH-003.
**Links:** REQ-AUTH-AUTH-003, REQ-AUTH-AUTH-021, REQ-AUTH-AUTH-030

## AUTH — OIDC (`auth = oidc[config=<path-to-json>]`, requires `SUPPORT_OIDC_AUTH`)

### REQ-AUTH-AUTH-036 — `oidc[...]` points at a JSON config file requiring `openid_configuration_url`, `required_claims`, `user_name_claim`; missing keys are fatal

**Requirement:** `oidc_get_brackets_string()` returns the configured path;
`oidc_vhost_init()` MUST `json_load_file()` it and `exit(EXIT_FAILURE)` (via
`mslog`/`fprintf` + exit) if the JSON cannot be parsed, or if any of
`openid_configuration_url`, `required_claims`, `user_name_claim` is absent.
`minimum_jwk_refresh_time` defaults to `MINIMUM_KEY_REFRESH_INTERVAL` (`900`
seconds) if not configured. `oidc_vhost_init()` MUST then call
`oidc_fetch_oidc_keys()` (REQ-AUTH-AUTH-037) and `exit(EXIT_FAILURE)` if it
fails — an unreachable OIDC provider at startup is fatal, not deferred.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/subconfig.c:369+ (`oidc_get_brackets_string`);
src/auth/openidconnect.c:36 (`MINIMUM_KEY_REFRESH_INTERVAL`), 57-119
(`oidc_vhost_init`)
**Acceptance:** negative, local — an `oidc` config JSON missing
`required_claims`; confirm `ocserv` exits at startup with "config file missing
required_claims". Missing `user_name_claim`: analogous message. An
unreachable `openid_configuration_url`: `exit(EXIT_FAILURE)` at startup.
**Links:** REQ-AUTH-AUTH-037, REQ-AUTH-AUTH-038

### REQ-AUTH-AUTH-037 — JWKS are fetched from the provider's `jwks_uri` and refreshed on unknown `kid`, throttled by `minimum_jwk_refresh_time`

**Requirement:** `oidc_fetch_oidc_keys()` MUST download
`openid_configuration_url` (curl), extract `jwks_uri`, download it, and store
the `keys` array plus `last_jwks_load_time = time(NULL)`. During signature
verification (REQ-AUTH-AUTH-038), if the token's `kid` is not found in the
cached JWKS, `oidc_verify_signature()` MUST re-fetch the JWKS — but only if
`now - last_jwks_load_time > minimum_jwk_refresh_time` (REQ-AUTH-AUTH-036) —
to avoid a refresh storm from repeated requests with an unknown/forged `kid`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/openidconnect.c:243-361 (`oidc_fetch_json_from_uri`,
`oidc_fetch_oidc_keys`), 532-627 (`oidc_verify_signature`, refresh-throttle
check around line 601)
**Acceptance:** positive, local — rotate the OIDC provider's signing key
(new `kid`); present a token signed with the new key; confirm the first
attempt within `minimum_jwk_refresh_time` of the last fetch still succeeds
(re-fetch happens) — then confirm a second token with yet another unknown
`kid` arriving before `minimum_jwk_refresh_time` elapses since that refresh is
rejected (no refresh storm). `[REVIEW: confirm the throttle window's start
point — last successful fetch vs. last attempted fetch.]`
**Links:** REQ-AUTH-AUTH-038

### REQ-AUTH-AUTH-038 — Token verification pipeline: signature → lifetime → required claims → username mapping

**Requirement:** `oidc_verify_token()` MUST, in order: (1)
`cjose_jws_import()` the bearer token as a JWS; (2)
`oidc_verify_signature()` — find the JWK by `kid` (REQ-AUTH-AUTH-037) and
`cjose_jws_verify()`; (3) `oidc_extract_claims()` — parse the JWS payload as
JSON; (4) `oidc_verify_lifetime()` — `nbf`, `iat`, and `exp` claims MUST all be
present, and the current time MUST be within `[nbf, exp]`; (5)
`oidc_verify_required_claims()` — every key configured in `required_claims`
MUST be present in the token claims and `json_equal` the configured value; (6)
`oidc_map_user_name()` — the claim named by `user_name_claim` MUST be present
and a non-empty string, copied into `user_name`. Any failure at any stage MUST
abort the pipeline with `token_verified == false`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/openidconnect.c:407-448 (`oidc_verify_lifetime`),
449-479 (`oidc_verify_required_claims`), 480-502 (`oidc_map_user_name`),
503-531 (`oidc_extract_claims`), 532-627 (`oidc_verify_signature`), 628-695
(`oidc_verify_token`)
**Acceptance:** [SEC] negative — for each stage, construct a token that fails
only that stage (bad signature; `exp` in the past; missing a
`required_claims` key; missing `user_name_claim`) and confirm
`oidc_auth_init` returns `ERR_AUTH_FAIL` in every case. Positive — a token
valid on all five checks completes authentication with
`e->acct_info.username` equal to the `user_name_claim` value.
**Links:** REQ-AUTH-AUTH-036, REQ-AUTH-AUTH-037, REQ-AUTH-AUTH-039

### REQ-AUTH-AUTH-039 — OIDC is single-step: the bearer token is submitted as the "username" in `auth_init`; `auth_pass` always fails

**Requirement:** `oidc_auth_init()` MUST treat `info->username` (the field
populated from the worker's `SEC_AUTH_INIT`) as the OIDC bearer token, call
`oidc_verify_token()` (REQ-AUTH-AUTH-038), and return `0` if
`token_verified`, else `ERR_AUTH_FAIL` — there is no `ERR_AUTH_CONTINUE`
round. `oidc_auth_pass()` MUST always return `ERR_AUTH_FAIL` (it exists only
to satisfy the vtable; OIDC never reaches a password stage).
`oidc_auth_user()` MUST return the `user_name` extracted in
REQ-AUTH-AUTH-038 if `token_verified`, else fail.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/openidconnect.c:139-160 (`oidc_auth_init`), 161-171
(`oidc_auth_user`), 172-176 (`oidc_auth_pass`)
**Acceptance:** positive, local — a valid bearer token in the initial
`SEC_AUTH_INIT` yields `PS_AUTH_COMPLETED` (modulo REQ-AUTH-AUTH-004's group
check) without any `SEC_AUTH_CONT` round. [SEC] negative — confirm that no
sequence of `SEC_AUTH_CONT` messages can reach `PS_AUTH_COMPLETED` for OIDC
(i.e. `oidc_auth_pass` is unreachable-success by construction).
**Links:** REQ-AUTH-AUTH-038, REQ-AUTH-SEC-002

### REQ-AUTH-AUTH-040 — OIDC has no group support; `allows_retries == 1`

**Requirement:** `oidc_auth_funcs.auth_group == NULL` and
`oidc_auth_funcs.group_list == NULL` — OIDC tokens carry no group concept in
this implementation, so REQ-AUTH-AUTH-004's `check_group()` skips the
module-`auth_group` step entirely for OIDC sessions (falling through to the
certificate-group fallback of REQ-AUTH-AUTH-006 only if `certificate` is also
combined). `oidc_auth_funcs.allows_retries == 1`: a failed token verification
on a retried `SEC_AUTH_INIT` (new connection attempt with a different token)
is scored via REQ-AUTH-AUTH-003 like other password-based methods, even though
OIDC itself has no `SEC_AUTH_CONT` rounds.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/auth/openidconnect.c:190-210 (`oidc_auth_funcs`)
**Acceptance:** unit, local — `auth = oidc[...]` with no `enable-auth`;
confirm `select-group`/`auto-select-group` configuration referencing any group
name is rejected or ignored at config time for an OIDC-only vhost (no
`group_list` to validate against). Confirm two `SEC_AUTH_INIT` attempts with
invalid tokens add `ban_points_wrong_password` twice (REQ-AUTH-AUTH-003).
**Links:** REQ-AUTH-AUTH-003, REQ-AUTH-AUTH-006, REQ-AUTH-AUTH-038

## ACCT — accounting method selection

### REQ-AUTH-ACCT-001 — `acct=` selects exactly one of `radius`/`pam`, compatible with the configured `auth=` type

**Requirement:** `figure_acct_funcs()` MUST accept `acct = radius[...]` or
`acct = pam` (only one `acct=` per vhost — later occurrences overwrite
earlier ones via `config->acct`), `exit(EXIT_FAILURE)` for any other value.
Both `radius_acct_funcs` and `pam_acct_funcs` declare `.auth_types =
ALL_AUTH_TYPES`, so `(avail_acct_types[i].mod->auth_types & config->auth[0].type)
== 0` is currently unreachable for these two — but the check exists as a
general compatibility gate for future accounting modules with restricted
`auth_types`, and `figure_acct_funcs()` MUST `exit(EXIT_FAILURE)` with "you
cannot mix the '%s' accounting method with the '%s' authentication method" if
it is ever violated.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:440-509 (`avail_acct_types[]`, `figure_acct_funcs`);
src/acct/pam.c:91-93, src/acct/radius.c:314-316 (`.auth_types = ALL_AUTH_TYPES`)
**Acceptance:** positive, local — `auth = pam[...]`, `acct = pam`; starts
successfully and accounting records are written via PAM session modules.
Negative — `acct = unknownmethod`; confirm "unknown or unsupported accounting
method". `[NOTE: the auth/acct type-compatibility branch (config.c:482-489) is
confirmed unreachable with the current `avail_acct_types[]`/`avail_auth_types[]`
and is not separately tested. `ALL_AUTH_TYPES` (src/vpn.h:140-143) is
`(AUTH_TYPE_PAM | AUTH_TYPE_PLAIN | AUTH_TYPE_CERTIFICATE | AUTH_TYPE_RADIUS |
AUTH_TYPE_GSSAPI | AUTH_TYPE_OIDC) & ~AUTH_TYPE_USERNAME_PASS` — i.e. every bit
used by any `avail_auth_types[]` entry except `AUTH_TYPE_USERNAME_PASS`
(src/vpn.h:132) itself, which never appears alone in any entry's `.type`
(`AUTH_TYPE_PAM`/`PLAIN`/`RADIUS` all OR it together with a bit that IS in
`ALL_AUTH_TYPES`). Consequently `config->auth[0].type` — built by ORing
together one or more `avail_auth_types[]` entries' `.type` values
(REQ-AUTH-INIT-002) — always has at least one bit in `ALL_AUTH_TYPES`, so
`avail_acct_types[i].mod->auth_types & config->auth[0].type` is nonzero for
both `radius_acct_funcs` and `pam_acct_funcs` (`.auth_types = ALL_AUTH_TYPES`)
regardless of which `auth=` method(s) are configured. The branch is therefore
intentional forward-compatibility dead code: it only becomes reachable if a
future accounting module declares `.auth_types` with a strict subset of
`ALL_AUTH_TYPES` that excludes all of the vhost's configured auth method bits.
No test is written for it now; add the negative test described above only
when such a module is introduced.]`
**Links:** REQ-AUTH-INIT-002, REQ-AUTH-INIT-003, REQ-AUTH-ACCT-002,
REQ-AUTH-ACCT-003, REQ-AUTH-ACCT-004

## ACCT — RADIUS accounting (`acct = radius[config=...]`)

### REQ-AUTH-ACCT-002 — Every RADIUS Accounting-Request carries a common attribute set

**Requirement:** `append_acct_standard()` MUST add to every
`PW_ACCOUNTING_REQUEST` (Start, Interim-Update, and Stop):
`NAS-Identifier` (if `nas-identifier=` configured, REQ-AUTH-AUTH-022),
`NAS-IP-Address`/`NAS-IPv6-Address` (from `e->acct_info.our_ip`, whichever
family parses), `User-Name`, `Service-Type = Framed`, `Framed-Protocol = PPP`,
`Framed-IP-Address`/`Framed-IPv6-Address` (if the session has an assigned
`ipv4`/`ipv6`), `Calling-Station-Id` (`e->acct_info.remote_ip`), and
`Acct-Session-Id` (`e->acct_info.safe_id`), and `Acct-Authentic = RADIUS`.
`append_stats()` MUST additionally add (when called, i.e. for Interim-Update
and Stop) `Acct-Session-Time` (if the `uptime` value passed by the caller —
`ai->uptime`, computed by sec-mod per REQ-AUTH-ACCT-007 — is nonzero),
`Acct-Input-Octets`, `Acct-Output-Octets`, `Acct-Input-Gigawords`, and
`Acct-Output-Gigawords` (the gigawords attributes are always sent, even when
`0`, to disambiguate a genuinely-zero count from a wrapped 32-bit counter).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/acct/radius.c:91-177 (`append_stats`, `append_acct_standard`);
src/sec-mod-auth.c:656-660,771-772 (`ai->uptime` computation)
**Acceptance:** positive, local — with a test RADIUS server logging received
attributes, open a session and confirm the Start Accounting-Request contains
`User-Name`, `Acct-Session-Id`, `Service-Type=Framed`,
`Framed-Protocol=PPP`, `Acct-Authentic=RADIUS`, and (if the session was
assigned an IPv4 address) `Framed-IP-Address`. Confirm a Stop request
additionally contains `Acct-Input-Octets`/`Acct-Output-Octets` and
`Acct-Input-Gigawords`/`Acct-Output-Gigawords` (the latter present and `0`
for a session under 4 GiB).
**Links:** REQ-AUTH-ACCT-001, REQ-AUTH-AUTH-022, REQ-AUTH-ACCT-003,
REQ-AUTH-ACCT-004

### REQ-AUTH-ACCT-003 — Accounting-Request lifecycle: Start/Interim-Update/Stop map to session open/periodic-stats/close

**Requirement:** `radius_acct_funcs.open_session` MUST send a
`PW_STATUS_START` Accounting-Request when sec-mod first opens the session
(`e->session_is_open == 0` on `SECM_SESSION_OPEN`, gated so a roaming
re-open does not re-send Start), including `Connect-Info` (the client's
User-Agent) if non-empty. `radius_acct_funcs.session_stats` MUST send a
`PW_STATUS_ALIVE` (Interim-Update) Accounting-Request whenever sec-mod
receives `CMD_SEC_CLI_STATS` from the worker; the worker sends this
periodically based on `ws->user_config->interim_update_secs`
(`src/worker-vpn.c:1402-1403`), which defaults to the vhost's
`stats-report-time` (`src/main-sec-mod-cmd.c:373-376`) unless a RADIUS
`Acct-Interim-Interval` was received during authentication AND
`groupconfig=true` is set (REQ-AUTH-AUTH-026(g)).
`radius_acct_funcs.close_session` MUST send a `PW_STATUS_STOP`
Accounting-Request on `CMD_SECM_SESSION_CLOSE`, with
`Acct-Terminate-Cause` set from `e->discon_reason`:
`REASON_USER_DISCONNECT`→`User-Request`,
`REASON_SERVER_DISCONNECT`→`Admin-Reset`,
`REASON_IDLE_TIMEOUT`→`Idle-Timeout`,
`REASON_SESSION_TIMEOUT`→`Session-Timeout`,
`REASON_DPD_TIMEOUT`→`Lost-Carrier`, `REASON_ERROR`→`User-Error`, and any
other/unset reason→`Lost-Service`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/acct/radius.c:178-375 (`radius_acct_session_stats`,
`radius_acct_open_session`, `radius_acct_close_session`);
src/sec-mod-auth.c:545-559 (`session_is_open` gating of `open_session`),
716-778 (`handle_sec_auth_stats_cmd` → `session_stats`), 1056-1072
(`close_session` invocation)
**Acceptance:** positive, local — connect a client, confirm Start
Accounting-Request; reconnect/roam without a full re-auth and confirm Start is
NOT re-sent (`session_is_open` already `1`); wait past `stats-report-time` and
confirm an Interim-Update (`Acct-Status-Type=Interim-Update`) is sent with
current byte counters. Disconnect the client normally; confirm Stop with
`Acct-Terminate-Cause=User-Request`. Negative — kill the worker process
abruptly (no `CMD_SECM_SESSION_CLOSE` from a clean disconnect path); confirm
behavior matches `proc->invalidated`/`server_disconnected` handling in
`session_close()` (src/main-sec-mod-cmd.c:738-781) — i.e. a Stop is still sent
by main's session-close path, not silently dropped.
**Links:** REQ-AUTH-ACCT-002, REQ-AUTH-ACCT-008, REQ-AUTH-ACCT-009,
REQ-AUTH-AUTH-026

### REQ-AUTH-ACCT-004 — `NAS-Port` is intentionally never sent in RADIUS auth or accounting requests

**Requirement:** Neither `src/auth/radius.c` nor `src/acct/radius.c` MUST add
a `PW_NAS_PORT` (attribute 5) attribute to any `Access-Request` or
`Accounting-Request`. This is a deliberate compatibility decision (since
ocserv 1.0.0): a prior NAS-Port value derived from the worker PID changed on
client roaming/reconnect, breaking RADIUS accounting correlation. Because
default FreeRADIUS configurations use `NAS-Port` in `acct_unique`, an
administrator enabling RADIUS accounting against a default FreeRADIUS server
MUST remove `NAS-Port` from that server's `acct_unique` computation (see
`doc/README-radius.md`).
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/auth/radius.c (no `PW_NAS_PORT` reference); src/acct/radius.c
(no `PW_NAS_PORT` reference); doc/README-radius.md (compatibility note)
**Acceptance:** negative, local — capture Access-Request and
Accounting-Request traffic against a test RADIUS server; confirm no
`NAS-Port` (attribute 5) attribute is present in any request. Cross-reference
`doc/README-radius.md`'s `acct_unique` guidance.
**Links:** REQ-AUTH-ACCT-002, REQ-AUTH-ACCT-003

### REQ-AUTH-ACCT-007 — Acct-Session-Time is the wall-clock lifetime of the logical session, spanning cookie-resumed reconnects

**Requirement:** `Acct-Session-Time` MUST represent the wall-clock lifetime
of the logical session — from the initial authentication
(`e->created`) to the last activity — not the sum of connected time across
individual TCP/DTLS connections. A single logical session spans all
reconnections performed under the same cookie (roaming, DTLS rekey, a brief
link loss, `new-tunnel` rekey), so an idle gap between such reconnections is
included in `Acct-Session-Time`. sec-mod MUST compute this value directly as
`now - e->created`, live for each Interim-Update
(`handle_sec_auth_stats_cmd`) and snapshotted at disconnect for the Stop
(`handle_secm_session_close_cmd`) so that a session with no worker currently
attached does not keep accruing time while it lingers within `cookie-timeout`.
Shutdown MUST preserve that snapshot for a retained entry whose `in_use` count
is zero, and MUST recompute `now - e->created` only for an entry with a worker
still attached. In particular sec-mod MUST NOT derive this value by
summing per-segment uptimes reported by the worker or main (each such report
is itself already cumulative since `e->created`, since `session_start_time`
is not reset across reconnects — summing them inflates the reported value
roughly linearly with the number of reconnects). The value is bounded above
by `session-timeout` (enforced on the same quantity, `e->created`), so a
session that runs its full term reports `Acct-Session-Time` ≈
`session-timeout`; any idle gap folded in by a reconnect is bounded by
`cookie-timeout`, since a longer gap expires the cookie and forces a fresh
authentication, starting a new accounting session with a new SID.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:657-661 (Stop snapshot), 772-773 (Interim-Update
live value); src/sec-mod-db.c:79-87 (shutdown snapshot handling);
doc/README-radius.md (definition); doc/sample.config (note next to
`stats-report-time`)
**Acceptance:** positive, local (`tests/radius-reconnect-acct`) — drive three
cookie-resumed segments (simulating reconnects via SIGKILL between segments,
as `tests/test-cookie-timeout` does) with idle gaps in between, then a clean
final disconnect; confirm the Stop's `Acct-Session-Time` is close to the
actual elapsed wall-clock time from first connect to final disconnect, not
the sum of the individual segments' cumulative uptimes (this is also the
regression test for the summation bug this requirement documents the fix
for). Negative — the same test's tolerance window excludes the pre-fix
summed value for a 3-segment timeline. With persistent cookies enabled,
disconnect a session and retain it until server shutdown; confirm its final
Stop reports the disconnect-time snapshot rather than including the idle
retention interval.
**Links:** REQ-AUTH-ACCT-002, REQ-AUTH-ACCT-003, REQ-IPC-032

### REQ-AUTH-ACCT-008 — A successful session re-open resets the previous connection segment's terminate cause

**Requirement:** After successfully sending `CMD_SECM_SESSION_REPLY` for a
cookie-resumed logical VPN session, sec-mod MUST clear the terminate cause
recorded for the previous connection segment. A subsequent nonzero cause
reported by the current worker MUST be preserved. When sec-mod shuts down
before the current worker reports a cause, it MUST leave the cause unset;
RADIUS accounting MUST map that existing fallback case to `Lost-Service`
instead of synthesizing a distinct internal shutdown reason.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:603-621 (`handle_secm_session_open_cmd`),
716-778 (`handle_sec_auth_stats_cmd`); src/sec-mod-db.c:71-90
(`sec_mod_client_db_deinit`); src/acct/radius.c:324-337
(`Acct-Terminate-Cause` mapping)
**Acceptance:** positive, local (`tests/radius`, root/full stack) — disconnect a
client normally, re-open the same logical VPN session with its cookie, prevent
the current worker from reporting shutdown first, and terminate ocserv;
confirm the final Stop reports `Acct-Terminate-Cause=Lost-Service`, not the
previous segment's `User-Request`. Allow the current worker to report
`REASON_SERVER_DISCONNECT` first and confirm the Stop preserves
`Acct-Terminate-Cause=Admin-Reset`.
**Links:** REQ-AUTH-ACCT-003, REQ-AUTH-ACCT-007, REQ-AUTH-ACCT-009,
REQ-IPC-032

### REQ-AUTH-ACCT-009 — sec-mod shutdown sends one non-blocking RADIUS Stop per open session to the first configured server

**Requirement:** When sec-mod terminates, it MUST close every open accounting
session through the shutdown-specific path. Each close MUST issue exactly one
`PW_STATUS_STOP` Accounting-Request to the first configured server
(`authserver` for TLS/DTLS transports, otherwise `acctserver`) with zero timeout
and zero retries; it MUST NOT call the response-waiting `rc_aaa()` path or send
the same Stop to later configured servers.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-db.c:71-90 (`sec_mod_client_db_deinit`);
src/sec-mod-auth.c:1056-1072 (`sec_auth_user_deinit`);
src/acct/radius.c:258-361 (`radius_acct_send_shutdown`,
`radius_acct_close_session`)
**Acceptance:** positive, local (`tests/radius`, root/full stack) — configure
two accounting-server entries that reach the same local RADIUS receiver,
retain one disconnected session, leave another active, and terminate ocserv;
confirm the receiver observes exactly one new Stop for each logical session
and ocserv exits without waiting for an Accounting-Response. Negative, CI —
repeat with an unavailable RADIUS server; confirm shutdown does not wait for
`radius_timeout` or execute retry processing.
**Links:** REQ-AUTH-ACCT-002, REQ-AUTH-ACCT-003, REQ-AUTH-ACCT-007,
REQ-AUTH-ACCT-008

## ACCT — PAM accounting (`acct = pam`)

### REQ-AUTH-ACCT-005 — `acct = pam`'s `open_session` is a non-interactive `pam_acct_mgmt()` check; failure denies the session even after successful authentication

**Requirement:** `pam_acct_open_session()` MUST fail (return negative) if
`ai->username` is empty, logging "PAM-acct: no username present". Otherwise it
MUST `pam_start(PACKAGE, ai->username, &dc, &ph)` with a conversation function
(`ocserv_conv`) that unconditionally returns `PAM_SUCCESS` with `*resp = NULL`
— i.e. it answers no prompts and cannot drive an interactive PAM stack — then
call `pam_acct_mgmt(ph, PAM_DISALLOW_NULL_AUTHTOK)`. A non-`PAM_SUCCESS` result
from either `pam_start` or `pam_acct_mgmt` MUST cause `pam_acct_open_session`
to return negative; `pam_end(ph, pret)` MUST be called on both the success and
the `pam_acct_mgmt` failure path. When `acct = pam` and
`e->session_is_open == 0`, sec-mod's `SECM_SESSION_OPEN` handler
(`handle_sec_auth_session_open`) MUST treat a negative `open_session` return
the same as REQ-AUTH-ACCT-003's session-open path treats any other denial: set
`e->status = PS_AUTH_FAILED`, log "denied session for user '%s'", and reply
with a failed session-open response — i.e. a PAM `account` restriction (locked
account, expired account, time-of-day restriction, etc.) discovered only at
session-open time MUST still deny the session, even though `auth_pass`
(REQ-AUTH-AUTH-019/020) already succeeded.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/acct/pam.c:40-83 (`ocserv_conv`, `pam_acct_open_session`),
91-96 (`pam_acct_funcs`); src/sec-mod-auth.c:545-558 (`SECM_SESSION_OPEN`
handling of `open_session < 0`)
**Acceptance:** positive, local — `auth = pam[...]`, `acct = pam`, a PAM
service whose `account` stack succeeds; confirm the session opens normally.
Negative — configure the PAM service's `account` stack to fail for the test
user (e.g. `pam_succeed_if account deny` or an expired/locked account via
`chage`/`passwd -l`); authenticate successfully (password stage passes) and
confirm `SECM_SESSION_OPEN` is still rejected (`PS_AUTH_FAILED`, "denied
session for user") even though `auth_pass` returned success.
**Links:** REQ-AUTH-ACCT-001, REQ-AUTH-AUTH-004, REQ-AUTH-AUTH-019,
REQ-AUTH-ACCT-006

### REQ-AUTH-ACCT-006 — `acct = pam` has no interim-update reporting and `close_session` does not invoke any PAM session module

**Requirement:** `pam_acct_funcs.session_stats` MUST be `NULL` — unlike
`acct = radius` (REQ-AUTH-ACCT-003), no `Acct-Interim-Interval`-style periodic
report is produced for `acct = pam`, and `CMD_SEC_CLI_STATS` from the worker
has no PAM-side effect. `pam_acct_close_session()` MUST be an empty function
(no body): on `CMD_SECM_SESSION_CLOSE` / `sec_auth_user_deinit`,
`acct.amod->close_session()` is still called when `session_is_open != 0`
(`src/sec-mod-auth.c:1030-1036`), but for PAM this performs no PAM operation —
in particular it MUST NOT call `pam_open_session()`/`pam_close_session()`, so
PAM `session` modules (e.g. `pam_lastlog`, `pam_limits`, `pam_systemd`) listed
in the service's `session` stack are never invoked by ocserv's PAM accounting,
and final session statistics (`stats_st`) passed to `close_session` are
discarded.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/acct/pam.c:85-96 (`pam_acct_close_session`, `pam_acct_funcs`);
src/sec-mod-auth.c:1030-1036 (`close_session` invocation)
**Acceptance:** unit/positive, local — configure a PAM service with a `session`
stack entry that has an observable side effect (e.g. a `pam_exec` line writing
to a file on session open/close); complete a full session lifecycle with
`acct = pam`; confirm the `session`-stack side effect never occurs, and that no
Interim-Update-equivalent log/record is produced between session open and
close (contrast with REQ-AUTH-ACCT-003's RADIUS Interim-Update).
**Links:** REQ-AUTH-ACCT-001, REQ-AUTH-ACCT-003, REQ-AUTH-ACCT-005

## SEC — cross-cutting negative requirements

Per `doc/requirements/README.md`, negative requirements are mandatory for
`AUTH` and `SEC` categories. Most per-method negatives are embedded above; the
following are method-composition or cross-method invariants.

### REQ-AUTH-SEC-001 — Password-based authentication methods (`pam`, `plain`, `radius`) MUST NOT be combined with each other

**Requirement:** Exactly one method with `AUTH_TYPE_USERNAME_PASS` set may be
active for a vhost. In `auth=` (AND composition, REQ-AUTH-INIT-002), this is
enforced because at most one listed method may have a non-NULL `amod`
(`pam`/`plain`/`radius` all have non-NULL `amod`; only `certificate` has
`NULL`) — a second password module triggers "you cannot mix multiple
authentication methods of %s type". Across `auth=` + `enable-auth=`
alternatives (OR composition, REQ-AUTH-INIT-003),
`check_for_duplicate_password_auth()` enforces the same invariant via "you
cannot mix multiple password authentication methods". `gssapi`, `oidc`, and
`certificate` do not set `AUTH_TYPE_USERNAME_PASS` and are unaffected by this
restriction.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/config.c:269-288, 322-329
**Acceptance:** [SEC] negative — covered by REQ-AUTH-INIT-002 and
REQ-AUTH-INIT-003's negative acceptance cases. Additionally: `auth =
certificate+pam`, `enable-auth = radius`; confirm rejection (both `pam` and
`radius` have `AUTH_TYPE_USERNAME_PASS`).
**Links:** REQ-AUTH-INIT-002, REQ-AUTH-INIT-003

### REQ-AUTH-SEC-002 — OIDC's password step (`auth_pass`) MUST NOT be able to complete authentication

**Requirement:** Because `oidc_auth_pass()` is hardcoded to return
`ERR_AUTH_FAIL` unconditionally (REQ-AUTH-AUTH-039), there is no code path by
which a `SEC_AUTH_CONT` message — regardless of its contents — can cause an
OIDC session to reach `PS_AUTH_COMPLETED`. Only `auth_init`'s token
verification (REQ-AUTH-AUTH-038) can do so.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/auth/openidconnect.c:172-176
**Acceptance:** [SEC] negative — send `SEC_AUTH_INIT` with an invalid token
followed by an arbitrary `SEC_AUTH_CONT` (any payload); confirm the session
never reaches `PS_AUTH_COMPLETED` and `auth_pass` is never the source of a `0`
return for OIDC.
**Links:** REQ-AUTH-AUTH-039

### REQ-AUTH-SEC-003 — GSSAPI credential acquisition MUST be restricted to SPNEGO; no other GSS mechanism is negotiable

**Requirement:** `gssapi_vhost_init()` restricts `gss_acquire_cred(_from)` to
`desired_mechs = {spnego_mech}` (REQ-AUTH-AUTH-031). Consequently
`gss_accept_sec_context()` (REQ-AUTH-AUTH-032) MUST NOT successfully negotiate
any mechanism the acquired credential does not advertise — a client offering a
non-SPNEGO mechanism directly (bypassing SPNEGO's mechanism negotiation) MUST
fail `gss_accept_sec_context()`.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/auth/gssapi.c:87-89, 91-145
**Acceptance:** [SEC] negative — a GSS client attempting raw Kerberos
(non-SPNEGO-wrapped) `gss_init_sec_context` against the worker's GSSAPI
endpoint; confirm `gss_accept_sec_context` fails (`ERR_AUTH_FAIL`) rather than
silently accepting a non-SPNEGO mechanism.
**Links:** REQ-AUTH-AUTH-031, REQ-AUTH-AUTH-032
