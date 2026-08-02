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
full-value comparison, covered structurally by REQ-IPC-015. This requirement
governs `find_client_entry()` specifically; it does not preclude the
pid-scoped pre-creation lookup (`find_client_entry_by_pid()`) added by
REQ-SECMOD-SESSION-007, which is a distinct, additional lookup used only to
decide whether `handle_sec_auth_init` may create a new entry.
**Links:** REQ-IPC-015, REQ-SECMOD-SESSION-005, REQ-SECMOD-SESSION-007

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

### REQ-SECMOD-SESSION-007 — At most one pid-stamped client_entry_st per worker pid; only a prior PS_AUTH_FAILED, unattached entry may be replaced, anything else is scored and rejected

**Requirement:** `handle_sec_auth_init()` MUST look up an existing
`client_entry_st` for the requesting worker's `pid` (`find_client_entry_by_pid()`)
before calling `new_client_entry()`, and MUST NOT allow more than one
`client_entry_st` to exist for the same pid at a time. This invariant covers
only entries currently carrying a non-zero `acct_info.id` (see the third
bullet below for when that is and is not the case):
  - If the existing entry's `status == PS_AUTH_FAILED` AND `in_use == 0`,
    sec-mod MUST delete it (`del_client_entry`) before creating the new one.
    `in_use == 0` MUST be checked because `PS_AUTH_FAILED` alone does not
    imply no session is open: `handle_sec_auth_ban_ip_reply()` sets
    `status = PS_AUTH_FAILED` on any SID-matched entry on a non-OK ban
    reply (`sec-mod-auth.c:709-712`) without touching `in_use`, so an
    open session (`in_use > 0`, reachable only via the replay described in
    the second bullet, since a conforming worker never re-sends
    `SEC_AUTH_INIT` once a session is open) could otherwise be deleted out
    from under main, which still holds its SID and TUN/IP state — the next
    `SECM_SESSION_CLOSE` for that SID would then hit the "non-existing SID"
    path and lose the final accounting Stop. If `in_use > 0`, this case
    MUST instead fall through to the reject-and-score handling below, the
    same as any other status.

    **This `PS_AUTH_FAILED` replace branch exists for exactly one reason:
    GSSAPI ticket-verification failure falling back to the next configured
    auth method.** `ws_switch_auth_to_next()` (`worker-auth.c:1930-1938`)
    is the only place a worker legitimately resets `ws->auth_state =
    S_AUTH_INACTIVE` — and therefore re-sends `SEC_AUTH_INIT` on the same
    pid — *after* a real sec-mod round trip has already created an entry;
    the worker-side contract for this reset (why it is bounded to these two
    call sites and cannot loop) is REQ-WORKER-AUTH-007. It is reached only
    when a GSSAPI attempt has
    already gone through `handle_sec_auth_res()`'s failure path
    (`sec-mod-auth.c:435-441`, setting `PS_AUTH_FAILED` without deleting the
    entry) and the worker falls back to the next method. This is *not* an
    illustrative example among several — no other configured auth type
    (certificate, plain, RADIUS, PAM, OIDC) produces this pattern: a missing
    client certificate is rejected before `SEC_AUTH_INIT` is ever sent
    (`worker-auth.c:1741-1751`, pre-secmod), and a failed plain/RADIUS/PAM
    password attempt terminates the connection outright
    (`goto auth_fail`) rather than resetting to `S_AUTH_INACTIVE`. If the
    GSSAPI fallback mechanism is ever removed or replaced with something
    that does not need to resurrect a failed pid's entry, this branch (and
    the `PS_AUTH_FAILED` special-casing throughout this requirement) has no
    remaining justification and MUST be reconsidered for removal — at that
    point every `SEC_AUTH_INIT` for a pid that already has an entry could
    revert to the simpler always-reject-and-score rule below, and
    `find_client_entry_by_pid()`'s only remaining caller would need
    re-evaluating too.
  - For any other status (`PS_AUTH_INIT`, `PS_AUTH_CONT`, `PS_AUTH_COMPLETED`),
    or `PS_AUTH_FAILED` with `in_use > 0`, sec-mod MUST NOT create a new
    entry, MUST NOT modify or delete the existing one, MUST NOT send any
    reply, and MUST call `sec_mod_add_score_to_ip()` with
    `score = ban_points_wrong_password` against the existing entry's
    vhost/IP (same mechanism as REQ-SECMOD-SEC-003) — a conforming worker
    never re-sends `SEC_AUTH_INIT` while a previous attempt on the same pid
    is still mid-flight (`PS_AUTH_INIT`/`PS_AUTH_CONT`), already completed
    (`PS_AUTH_COMPLETED`), or failed but still attached to an open session
    (`PS_AUTH_FAILED` with `in_use > 0`), so this is treated as a protocol
    violation (e.g. a compromised worker replaying `SEC_AUTH_INIT` with its
    still-valid original HMAC/`session_start_time`) and scored like a
    qualifying auth failure rather than silently retried for free.
  - `acct_info.id` is the pid correlator `find_client_entry_by_pid()`
    matches against. It is stamped in three places: `new_client_entry()` at
    entry creation, `handle_sec_auth_stats_cmd()` on every `CMD_SEC_CLI_STATS`
    from a worker presenting a valid SID (`sec-mod-auth.c:754`), and cleared
    (`= 0`) by `expire_client_entry()` whenever an entry is kept (not
    immediately deleted) after `e->in_use` reaches 0. A zero `acct_info.id`
    therefore means "no worker has reported against this entry since it was
    last detached" — it prevents a later, unrelated worker that inherits
    the same OS pid from spuriously matching a lingering/disconnected
    entry. It is NOT a guarantee that a non-zero-id match is the entry's
    originally-authenticating worker: any worker later presenting that
    entry's valid SID over `CMD_SEC_CLI_STATS` re-stamps the id to its own
    pid. One consequence: a `client_entry_st` resumed via
    `SECM_SESSION_OPEN` (persistent-cookie reconnect, a different pid) keeps
    `acct_info.id == 0` — `handle_secm_session_open()` bumps `in_use` but
    does not stamp the pid — until that worker's first `CMD_SEC_CLI_STATS`;
    during that window `find_client_entry_by_pid()` does not see it, so the
    new worker's pid is not yet protected by this requirement's one-entry
    rule (bounded impact: at most one extra `client_entry_st` for that pid
    until the first stats report).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:874-926 (`handle_sec_auth_init`);
src/sec-mod-auth.c:366-451 (`handle_sec_auth_res`, `PS_AUTH_FAILED`
transition); src/sec-mod-auth.c:694-713 (`handle_sec_auth_ban_ip_reply`,
the other `PS_AUTH_FAILED` transition); src/sec-mod-auth.c:715-778
(`handle_sec_auth_stats_cmd`, the `acct_info.id` re-stamp at line 754);
src/sec-mod-db.c:178-247 (`find_client_entry_by_pid`, `expire_client_entry`)
**Acceptance:** positive, `tests/test-gssapi-opt-pass` — a GSSAPI
ticket-verification failure (an NTLMSSP Type1 token replayed as its own
continuation, which `gss_accept_sec_context()` rejects) followed by a
password fallback on the same worker connection (driven over one persistent
`http.client.HTTPSConnection`, not curl - curl's connection reuse across
separate request legs is not portable across the curl versions in this
project's CI matrix) obtains a cookie
(`<auth id="success">`), and sec-mod's debug log shows exactly one
mid-test `sec_auth_user_deinit()` "permanently closing session" line (the
`PS_AUTH_FAILED` entry being replaced) — not zero (which would mean the
entry was never reclaimed until final shutdown, i.e. leaked). occtl's
"Sec-mod client entries" counter would be the more direct way to assert
this but requires a real uid 0 peer (`check_upeer_id()`), which the
`NO_NEED_ROOT`/`uid_wrapper` emulation this test relies on for the server
does not extend to occtl as a separate client process. Negative — (a) send a second
`CMD_SEC_AUTH_INIT` for a pid whose existing entry is still `PS_AUTH_INIT`
(don't complete the `SEC_AUTH_CONT` round); confirm no new entry is created,
no reply is sent, and `CMD_SECM_BAN_IP` is sent with
`score = ban_points_wrong_password`; confirm enough repeats
(`max_ban_score / ban_points_wrong_password`) get the source IP refused on
its next connection. (b) unit, local, `tests/sec-mod-db` — set `e->in_use = 1`
on a kept (non-deleted, `discon_reason` unset) entry, call
`expire_client_entry` (decrementing `in_use` to 0), confirm `acct_info.id
== 0` afterward and that `find_client_entry_by_pid()` no longer matches it
for that numeric pid. (c) unit, local, `tests/sec-mod-db` — populate a
`client_entry_st` with `status = PS_AUTH_FAILED` and `in_use = 1`
(simulating `handle_sec_auth_ban_ip_reply()` marking a live session
`PS_AUTH_FAILED`); confirm `find_client_entry_by_pid()` still matches it —
`find_client_entry_by_pid()` does not itself consult `status` or `in_use`,
which is precisely why `handle_sec_auth_init()` (the only caller that acts
on the match) MUST check `in_use == 0` itself rather than relying on the
lookup to exclude attached sessions. `[GAP: the `in_use == 0` condition in
handle_sec_auth_init() itself — i.e. that a PS_AUTH_FAILED entry with
in_use > 0 is scored-and-rejected rather than deleted — has no dedicated
test yet; exercising it requires either a full-stack CI test driving a
real SECM_BAN_IP round-trip against an open session, or a unit test
providing HMAC/vhost/auth-module fixtures for handle_sec_auth_init()
directly, neither of which exists today.]`
**Links:** REQ-SECMOD-SESSION-001, REQ-SECMOD-SESSION-002,
REQ-SECMOD-SEC-003, REQ-WORKER-AUTH-007

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
