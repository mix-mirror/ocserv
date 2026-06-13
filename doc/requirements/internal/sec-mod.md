---
title: sec-mod requirements
generator: requirements-from-implementation
process: sec-mod
id-prefix: REQ-SECMOD
sources:
  - src/sec-mod.c
  - src/sec-mod-auth.c
  - src/sec-mod-auth.h
  - src/sec-mod-db.c
  - src/sec-mod-cookies.c
  - src/sec-mod-resume.c
  - src/sec-mod.h
  - src/defs.h
  - src/vpn.h
  - doc/design.md#the-security-module-process
  - doc/requirements/internal/ipc.md
---

# sec-mod Requirements

sec-mod runs as root, holds private keys, session state (`client_db`), and
performs authentication and accounting. It is the only process that may
access credentials and the only process trusted to assign SIDs and issue
session cookies. See `internal/ipc.md` for the message-level contracts;
this document covers sec-mod's internal state machine, the auth module
vtable (`auth_mod_st`, `src/sec-mod-auth.h`), and session/cookie lifecycle.

## INIT

### REQ-SECMOD-INIT-001 — Per-vhost module initialization is idempotent

**Requirement:** `sec_auth_init()` MUST initialize each enabled auth
module's `vhost_init` and the accounting module's `vhost_init` for a vhost
at most once: it MUST only call `vhost_init` when `auth_ctx`/`acct_ctx` is
still `NULL`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:63-85
**Acceptance:** unit, local — call `sec_auth_init(vhost)` twice; confirm
`vhost_init` is invoked exactly once per configured auth/acct module
(e.g. via a counting mock module).
**Links:** —

## AUTH — auth_mod_st vtable contract

The auth-module vtable (`src/sec-mod-auth.h`), per-method authentication
requirements, and the certificate defense-in-depth/group-selection logic
formerly numbered `REQ-SECMOD-AUTH-001..006` have moved to
`internal/authentication.md` as `REQ-AUTH-AUTH-001..006`, alongside a full
per-method (plain/PAM/RADIUS/GSSAPI/OIDC/certificate) requirements pass. The
old IDs are kept reserved (not reused) for citation stability:

| Old ID | New ID |
|--------|--------|
| `REQ-SECMOD-AUTH-001` | `REQ-AUTH-AUTH-001` |
| `REQ-SECMOD-AUTH-002` | `REQ-AUTH-AUTH-002` |
| `REQ-SECMOD-AUTH-003` | `REQ-AUTH-AUTH-003` |
| `REQ-SECMOD-AUTH-004` | `REQ-AUTH-AUTH-004` |
| `REQ-SECMOD-AUTH-005` | `REQ-AUTH-AUTH-005` |
| `REQ-SECMOD-AUTH-006` | `REQ-AUTH-AUTH-006` |

`REQ-SECMOD-AUTH-001..006` are `WITHDRAWN` (relocated; see table above).

## SEC — anti-replay, banning, key isolation

### REQ-SECMOD-SEC-001 — SID is generated with a CSPRNG and is per-instance-tagged

**Requirement:** `new_client_entry()` MUST generate `e->sid` using
`gnutls_rnd(GNUTLS_RND_RANDOM, ...)` (a cryptographically secure RNG), and
MUST overwrite `sid[0]` with `sec->sec_mod_instance_id` so that SIDs from
different sec-mod instances (in multi-instance deployments) are
distinguishable. If after 3 retries a collision still exists in
`client_db`, entry creation MUST fail rather than reuse a SID.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-db.c:98-156
**Acceptance:** [SEC] unit, local — generate many client entries and
confirm no two share a `sid`; confirm `sid[0]` always equals the
configured `sec_mod_instance_id`. Negative: simulate `find_client_entry`
always returning non-NULL (collision) and confirm `new_client_entry`
returns NULL after 3 retries rather than looping forever or reusing.
**Links:** REQ-IPC-017

### REQ-SECMOD-SEC-002 — safe_id is derived from SID, not independently random

**Requirement:** `e->acct_info.safe_id` (the value exposed to `occtl` and
external accounting, `SAFE_ID_SIZE` bytes printable) MUST be computed by
`calc_safe_id(e->sid, SID_SIZE, ...)` — a deterministic derivation from the
SID — not a separately generated random value, so that `safe_id` can be used
to look up sessions (REQ-IPC-070) without sec-mod maintaining a second
index.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-db.c:139-140; src/common/common.c:54-79
(`calc_safe_id` calls `safe_hash`, which runs `sid` through SHA-1 via
nettle's `sha1_init`/`sha1_update`/`sha1_digest`, then `oc_base64_encode`s
the 20-byte digest; comment at common.c:53 states "The goal is one-wayness")
**Acceptance:** unit, local — confirm `calc_safe_id(sid, ...)` is
deterministic (same `sid` -> same `safe_id`, since SHA-1 + base64 are
deterministic) and that `safe_id` does not trivially reveal `sid`: the
derivation is SHA-1(`sid`) (not a simple encoding/truncation), so recovering
`sid` from `safe_id` requires inverting SHA-1, which is computationally
infeasible. `safe_id` MUST nonetheless continue to be treated as sensitive:
since it is a deterministic function of `sid` and terminate-by-prefix
(REQ-IPC-070) accepts a `safe_id` prefix to select a session, possession of
`safe_id` is sufficient to identify/terminate that session even though `sid`
itself cannot be recovered from it.
**Links:** REQ-SECMOD-SEC-001, REQ-IPC-070

### REQ-SECMOD-SEC-003 — Wrong-password and connection scoring feed the IP ban list, gated by max-ban-score

**Requirement:** sec-mod MUST send `CMD_SECM_BAN_IP` with
`score = ban_points_wrong_password` on a qualifying failed/retried
authentication (REQ-AUTH-AUTH-003, and on final auth failure per
src/sec-mod-auth.c:443-445), but MUST NOT send any `CMD_SECM_BAN_IP`
message at all if `vhost->config->max_ban_score == 0` (banning disabled for
that vhost).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:89-119 (`sec_mod_add_score_to_ip`, early
return on `max_ban_score == 0`); src/config.c:796-805
(`DEFAULT_MAX_BAN_SCORE`, `DEFAULT_PASSWORD_POINTS`)
**Acceptance:** unit, local — set `max-ban-score = 0` in vhost config; drive
repeated failed authentications; confirm no `CMD_SECM_BAN_IP` is sent
(main's ban table for that IP remains empty). With `max-ban-score > 0`,
confirm `CMD_SECM_BAN_IP.score` matches the configured
`ban-points-wrong-password`. Cross-reference `doc/sample.config` `max-ban-score` /
`ban-points-wrong-password` documentation.
**Links:** REQ-AUTH-AUTH-003, REQ-IPC-080

### REQ-SECMOD-SEC-004 — sec-mod never serves a private-key operation for an unbound vhost

**Requirement:** sec-mod's connection-acceptance path (`accept()` plus
`check_upeer_id()` in its main loop) MUST establish which vhost a connecting
worker (`cfd`) was started for, and `process_worker_packet()` MUST use that
server-recorded vhost — not the `vhost` field of the incoming
`sec_op_msg`/`sec_get_pk_msg` — to select the vhost whose `key[key_idx]` is
used for `CMD_SEC_SIGN`, `CMD_SEC_DECRYPT`, `CMD_SEC_SIGN_DATA`,
`CMD_SEC_SIGN_HASH`, and `CMD_SEC_GET_PK`.
**Strength:** MUST NOT
**Status:** REVIEW
**Source:** src/sec-mod.c:219-338 (`process_worker_packet`, all five
key-operation cases call `find_vhost(sec->vconfig, op->vhost)` /
`find_vhost(sec->vconfig, pkm->vhost)` — the message-supplied string — then
bounds-check and index `vhost->key[key_idx]`); src/sec-mod.c:1160-1201
(accept loop — `check_upeer_id()` validates only the peer's uid/gid/pid, and
records no vhost for `cfd`); src/vhost.h:137-152 (`find_vhost()` — matches
any configured vhost by name, case-insensitively, falling back to
`default_vhost()`; never returns NULL); src/ipc.proto:284-300 (`sec_op_msg`,
`sec_get_pk_msg` — `vhost` is an optional string in the message, with no
`sid` or other connection-identity field); REQ-IPC-051
**Acceptance:** [REVIEW: as implemented, this requirement does NOT hold.
sec-mod's accept loop performs only OS-level peer-credential validation
(`check_upeer_id`) and records no per-`cfd` vhost binding. Each of the five
key-operation handlers in `process_worker_packet()` resolves the vhost
solely via `find_vhost(sec->vconfig, <message>->vhost)` — a string supplied
by the requesting worker — then indexes that vhost's `key[key_idx]`
(bounds-checked against `vhost->key_size`, but only for the
*message-resolved* vhost, not the requester's own). Concretely: a worker
process started for vhost A can send `sec_op_msg{vhost="B", key_idx=0,
sig=...}` over its existing sec-mod socket, and sec-mod will perform the
signing/decryption with vhost B's private key and return the result — there
is no check that the requester is actually serving vhost B. Negative test
(once fixed): a worker socket established for vhost A sends a
`sec_op_msg`/`sec_get_pk_msg` naming vhost B; sec-mod MUST reject it (e.g.
`ERR_AUTH_FAIL`/connection close) rather than performing the operation with
vhost B's key. This needs maintainer review per AGENTS.md's "Changes to
cookie or SID handling" / privilege-boundary criteria — flagging here rather
than resolving unilaterally.]
**Links:** REQ-IPC-050, REQ-IPC-051

## SESSION — client_db lifecycle, cookies, expiry

### REQ-SECMOD-SESSION-001 — A client_entry_st is keyed solely by SID

**Requirement:** `find_client_entry()` MUST locate entries by exact 32-byte
(`SID_SIZE`) match on `e->sid` only; sec-mod MUST NOT accept a partial or
prefix match for `SEC_AUTH_CONT`, `SECM_SESSION_OPEN`, or
`SECM_SESSION_CLOSE` (contrast with `terminate_session_by_sid`,
REQ-SECMOD-SESSION-005, which intentionally allows a `safe_id` prefix for
the human-facing `occtl terminate` command only).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-db.c:158-176
**Acceptance:** negative, local — send `SEC_AUTH_CONT` with a `sid` that is
a correct prefix of a valid SID but padded/truncated to `SID_SIZE`;
confirm `find_client_entry` returns NULL (no match) — i.e., this is a
full-value comparison, covered structurally by REQ-IPC-015.
**Links:** REQ-IPC-015, REQ-SECMOD-SESSION-005

### REQ-SECMOD-SESSION-002 — Expiry requires in_use == 0

**Requirement:** A `client_entry_st` MUST NOT be treated as expired
(`IS_CLIENT_ENTRY_EXPIRED`) while `e->in_use > 0`, regardless of
`e->exptime`, so that an active session (one with an open
`SECM_SESSION_OPEN` reference) is never reaped by `cleanup_client_entries()`
mid-use.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod.h:84-87 (`IS_CLIENT_ENTRY_EXPIRED_FULL`:
`e->exptime != -1 && now >= e->exptime && e->in_use == 0`)
**Acceptance:** unit, local — set `e->exptime` in the past while
`e->in_use == 1`; confirm `cleanup_client_entries()` does not delete the
entry. Decrement `in_use` to 0 (via `expire_client_entry`); confirm it is
now eligible for cleanup once `exptime` passes.
**Links:** REQ-IPC-022, REQ-SECMOD-SESSION-003

### REQ-SECMOD-SESSION-003 — expire_client_entry: persistent-cookies and disconnect-reason determine immediate delete vs. temporary close

**Requirement:** On `expire_client_entry()` with `e->in_use` reaching 0:
  - If `persistent_cookies == 0` AND `discon_reason` is one of
    `REASON_SERVER_DISCONNECT`, `REASON_SESSION_TIMEOUT`, or
    (`REASON_USER_DISCONNECT` AND `session_is_open`), the entry MUST be
    deleted immediately (`del_client_entry`) — no cookie reuse is possible.
  - Otherwise, the entry MUST be kept with a refreshed `exptime`:
    - For `REASON_USER_DISCONNECT`, `exptime` MUST only be shortened to
      `now + AUTH_SLACK_TIME` if not `persistent_cookies` or the entry would
      otherwise outlive `now + AUTH_SLACK_TIME`'s lower bound (i.e. never
      *extend* expiry on user disconnect).
    - For all other reasons, `exptime = now + cookie_timeout +
      AUTH_SLACK_TIME`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-db.c:210-247
**Acceptance:** unit, local — for each `discon_reason` value and each
`persistent_cookies` setting (0/1), call `expire_client_entry` and assert
the resulting state (deleted vs. kept) and, if kept, `exptime`. Cross-check
`doc/sample.config` for `persistent-cookies`.
**Links:** REQ-SECMOD-SESSION-002, REQ-IPC-031

### REQ-SECMOD-SESSION-004 — terminate_user_sessions deletes all matching entries unconditionally

**Requirement:** `terminate_user_sessions(sec, username)` MUST delete every
`client_entry_st` with `acct_info.username == username`, regardless of
`in_use`, `status`, or `exptime` — administrative termination overrides
normal expiry rules (REQ-SECMOD-SESSION-002 does not apply to this path). It
MUST return 1 if at least one entry was deleted, 0 if `username` is
NULL/empty or no entry matched.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-db.c:252-284
**Acceptance:** negative, local — terminate a user with `in_use > 0` (an
open session); confirm the entry is deleted immediately and a subsequent
`SECM_SESSION_OPEN`/`AUTH_COOKIE_REQ` for that SID fails (REQ-IPC-021,
REQ-IPC-072). Confirm return value 0 for an empty username.
**Links:** REQ-IPC-071, REQ-IPC-072, REQ-SECMOD-SESSION-002

### REQ-SECMOD-SESSION-005 — terminate_session_by_sid requires an exact-length safe_id and stops at first match

**Requirement:** `terminate_session_by_sid()` MUST reject a `safe_id` whose
length is not exactly `SAFE_ID_SIZE - 1`, MUST match by prefix
(`memcmp` over `safe_id_len` bytes) against `t->acct_info.safe_id`, and MUST
stop at the first match (session IDs are assumed unique at this length).
Disambiguation of *shorter* prefixes is occtl's responsibility
(REQ-IPC-070), not sec-mod's — by the time sec-mod receives
`SECM_TERMINATE_SESSION`, the `safe_id` MUST already be full-length.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-db.c:289-331
**Acceptance:** negative, local — send `SECM_TERMINATE_SESSION` with a
`safe_id` shorter than `SAFE_ID_SIZE - 1`; confirm rejection with log
`invalid session ID length` and `terminated == 0`. This is the
defense-in-depth backstop for REQ-IPC-070 (occtl-side prefix
disambiguation) — even if occtl's check were bypassed, sec-mod will not
act on a short prefix.
**Links:** REQ-IPC-070, REQ-IPC-071

### REQ-SECMOD-SESSION-006 — list-cookies omits expired entries and never-expiring in-use sessions report expires=0

**Requirement:** `handle_secm_list_cookies_reply()` MUST skip entries for
which `IS_CLIENT_ENTRY_EXPIRED` is true, and MUST report
`CookieIntMsg.expires = 0` (meaning "does not expire") for any entry with
`e->in_use > 0`, even if `e->exptime` is set to a finite value.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-cookies.c:74-114
**Acceptance:** unit, local — create entries in states {expired,
unexpired+in_use=0, unexpired+in_use>0}; request `SECM_LIST_COOKIES`;
confirm the expired entry is absent, and the `in_use>0` entry has
`expires=0` in the reply (`occtl show sessions valid` reflects this).
**Links:** REQ-SECMOD-SESSION-002, REQ-IPC-070

## TEARDOWN

### REQ-SECMOD-TEARDOWN-001 — db deinit calls auth_deinit for every remaining entry

**Requirement:** `sec_mod_client_db_deinit()` MUST call
`sec_auth_user_deinit()` (which invokes `auth_mod_st.auth_deinit` if the
entry has a module/`auth_ctx`) for every remaining `client_entry_st` before
freeing the hash table, so auth modules can release per-session resources
(e.g. PAM handles) on sec-mod shutdown — not only on normal session
completion.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-db.c:71-85
**Acceptance:** unit, local — populate `client_db` with entries that have a
mock module with a counting `auth_deinit`; call
`sec_mod_client_db_deinit()`; confirm `auth_deinit` was called once per
entry, including entries that never reached `PS_AUTH_COMPLETED`.
**Links:** —

## Completeness notes

- **Vtable gap**: `auth_mod_st` fields `vhost_deinit` and `group_list` have
  no requirement above — `[UNDOCUMENTED: vhost_deinit's call site was not
  located in this pass; group_list appears used only by occtl-facing group
  enumeration, not the auth state machine. Add requirements once call sites
  are confirmed.]`
- **PAM/RADIUS/GSSAPI/OIDC module-specific behaviors** (e.g. PAM
  conversation function quirks, RADIUS Access-Challenge mapping to
  `ERR_AUTH_CONTINUE`) are intentionally out of scope here — they implement
  the `auth_mod_st` contract above and should get their own
  `internal/auth-<module>.md` if/when needed; this document covers the
  vtable contract every module must satisfy.
- **Reload (`CMD_SECM_RELOAD`)**: sec-mod calls `reload_server(sec)` and
  replies `CMD_SECM_RELOAD_REPLY` (src/sec-mod.c:491-501) but this document
  does not enumerate which parts of `sec_mod_st` state survive reload vs.
  reset — `[UNDOCUMENTED: candidate REQ-SECMOD-INIT-* once reload semantics
  for client_db / vhost config are confirmed against doc/sample.config
  reload annotations.]`
