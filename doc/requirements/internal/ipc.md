---
title: IPC requirements
generator: requirements-from-implementation
process: ipc
id-prefix: REQ-IPC
sources:
  - src/ipc.proto
  - src/ctl.proto
  - src/defs.h
  - src/sec-mod.c
  - src/sec-mod-auth.c
  - src/main-auth.c
  - src/main-worker-cmd.c
  - src/main-sec-mod-cmd.c
  - src/worker-auth.c
  - src/tlslib.c
  - doc/design.md#ipc-communication
  - doc/design.md#ipc-communication-for-sid-assignment
  - doc/design.md#ipc-communication-for-session-termination
---

# IPC Requirements

This document covers the Unix-socket, protobuf-c (`src/ipc.proto`,
`src/ctl.proto`) messages exchanged between the three ocserv processes
(main, sec-mod, worker) and `occtl`. It is the spine cited by
`internal/main.md`, `internal/sec-mod.md`, and `internal/worker.md` for any
behavior that crosses a process boundary.

`internal/*` documents MUST cite these IDs instead of restating the IPC
contract.

## REQ-IPC-001 — General framing

**Requirement:** All cross-process communication MUST use the
`cmd_request_t` framing (`src/defs.h`) over Unix domain sockets, with the
payload (if any) serialized as the protobuf-c message named in the comment
preceding each `cmd_request_t` value in `src/ipc.proto`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/defs.h:60-110; src/ipc.proto (per-message comments)
**Acceptance:** unit — `tests/` IPC round-trip tests pack/unpack each
message type and confirm `cmd_request_to_str()` covers every enum value.
**Links:** —

### REQ-IPC-002 — Unknown command rejection

**Requirement:** A process receiving a `cmd_request_t` value it does not
recognize for its role MUST log the value and return an error without
acting on the payload.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod.c:468-470 (`default: ... return -1`)
**Acceptance:** negative, local — send an out-of-range `cmd_request_t` to
sec-mod's socket and confirm it logs `unknown type` and closes/errors
without crashing.
**Links:** REQ-IPC-001

---

## SEC_AUTH_INIT / SEC_AUTH_REP / SEC_AUTH_CONT (worker <-> sec-mod)

```
worker -> sec-mod: SEC_AUTH_INIT  (sec_auth_init_msg)
sec-mod -> worker: SEC_AUTH_REP   (sec_auth_reply_msg, new SID)
worker -> sec-mod: SEC_AUTH_CONT  (sec_auth_cont_msg, SID + password)
sec-mod -> worker: SEC_AUTH_REP   (OK or FAILED)
```

### REQ-IPC-010 — SEC_AUTH_INIT HMAC anti-replay

**Requirement:** sec-mod MUST reject a `sec_auth_init_msg` whose `hmac`
field is not exactly `HMAC_DIGEST_SIZE` bytes, or whose value does not equal
`HMAC(orig_remote_ip || our_ip || session_start_time)` computed with
`sec->hmac_key`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:886-914
**Acceptance:** negative, local — send `SEC_AUTH_INIT` with a wrong-length
or mismatched `hmac` field and confirm sec-mod logs `hmac is the wrong
size` / `hmac presented by client doesn't match parameters provided` and
does not create a `client_entry_st`.
**Links:** REQ-IPC-011, REQ-WORKER-AUTH-* (worker side: HMAC is computed by
main at `WORKER_STARTUP` time, see REQ-IPC-040)

### REQ-IPC-011 — SEC_AUTH_INIT replay window

**Requirement:** sec-mod MUST reject a `sec_auth_init_msg` whose
`session_start_time` is older than `vhost->config->auth_timeout` seconds
relative to sec-mod's current time, even if the HMAC is valid.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:916-922
**Acceptance:** negative, local — replay a captured, HMAC-valid
`SEC_AUTH_INIT` after `auth-timeout` has elapsed; confirm sec-mod logs `hmac
presented by client expired - possible replay` and rejects.
**Links:** REQ-IPC-010

### REQ-IPC-012 — orig_remote_ip is required

**Requirement:** sec-mod MUST reject a `sec_auth_init_msg` with no
`orig_remote_ip` field, before computing the HMAC.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:895-898
**Acceptance:** negative, local — confirm sec-mod logs `missing remote IP in
auth init` and rejects a message that omits `orig_remote_ip`.
**Links:** REQ-IPC-010

### REQ-IPC-013 — auth_type determines auth module selection

**Requirement:** sec-mod MUST select the first enabled auth module on the
target vhost whose configured `type` bitmask contains all bits set in
`sec_auth_init_msg.auth_type`, and MUST reject the request (without creating
a session) if no such module exists.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:841-871 (`set_module`), 930-935
**Acceptance:** negative, local — send `SEC_AUTH_INIT` with `auth_type=0` or
a type not configured on the vhost; confirm sec-mod logs `no module found
for auth type` and returns failure.
**Links:** REQ-IPC-010

### REQ-IPC-014 — confidential username types are not echoed from SEC_AUTH_INIT

**Requirement:** When `sec_auth_init_msg.auth_type` has any bit set in
`CONFIDENTIAL_USER_NAME_AUTH_TYPES`, sec-mod MUST NOT copy
`sec_auth_init_msg.user_name` into the session's accounting username — the
real username is established only after authentication completes.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:971-977
**Acceptance:** unit, local — for a cert-based auth type, send `SEC_AUTH_INIT`
with a `user_name` set and confirm `e->acct_info.username` remains empty (or
is set only after `auth_init`/`auth_pass` completes) rather than the
submitted value.
**Links:** REQ-SECMOD-AUTH-*

### REQ-IPC-015 — SEC_AUTH_CONT requires valid SID and matching state

**Requirement:** sec-mod MUST reject a `sec_auth_cont_msg` if `sid.len !=
SID_SIZE`, if no `client_entry_st` exists for that SID, or if the entry's
state is not `PS_AUTH_INIT` or `PS_AUTH_CONT`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:784-805
**Acceptance:** negative, local — (a) send `SEC_AUTH_CONT` with a
wrong-length SID; (b) send it with a random 8-byte SID that was never issued
by `SEC_AUTH_REP`; (c) send a second `SEC_AUTH_CONT` after the session
reached `PS_AUTH_COMPLETED`. Each MUST be rejected.
**Links:** REQ-IPC-010

### REQ-IPC-016 — SEC_AUTH_CONT requires a password

**Requirement:** sec-mod MUST reject a `sec_auth_cont_msg` whose `password`
field is absent.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:810-816
**Acceptance:** negative, local — send `SEC_AUTH_CONT` without `password`
set; confirm rejection with `no password given in auth cont`.
**Links:** REQ-IPC-015

### REQ-IPC-017 — SID is assigned only by sec-mod

**Requirement:** A worker MUST NOT construct its own SID; the SID used in
`SEC_AUTH_CONT`, `AUTH_COOKIE_REQ`, `SECM_SESSION_OPEN/CLOSE`, and
`SEC_CLI_STATS` MUST be the `sid` value sec-mod returned in `SEC_AUTH_REP`
for that authentication attempt.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** doc/design.md#ipc-communication-for-sid-assignment;
src/sec-mod-auth.c:174-217 (sid assigned in `handle_sec_auth_res` /
`SEC_AUTH_REP` reply path)
**Acceptance:** [REVIEW: no automated negative test found — add one that
sends `AUTH_COOKIE_REQ`/`SEC_AUTH_CONT` with a SID the worker fabricated
rather than one received via `SEC_AUTH_REP`, and confirm
`find_client_entry()` rejects it (covered structurally by REQ-IPC-015 /
REQ-IPC-021, but no test isolates "worker-fabricated SID" specifically).]
**Links:** REQ-IPC-015, REQ-IPC-021

---

## AUTH_COOKIE_REQ / AUTH_COOKIE_REP (worker <-> main, main <-> sec-mod)

```
worker -> main:    AUTH_COOKIE_REQ  (auth_cookie_request_msg: cookie)
main -> sec-mod:   SECM_SESSION_OPEN (secm_session_open_msg: sid)
sec-mod -> main:   SECM_SESSION_REPLY (secm_session_reply_msg: config, OK/FAILED)
main -> worker:    AUTH_COOKIE_REP  (auth_cookie_reply_msg: OK + tun device, or FAILED)
```

### REQ-IPC-020 — AUTH_COOKIE_REQ only from PS_AUTH_INACTIVE

**Requirement:** main MUST reject an `AUTH_COOKIE_REQ` received from a
worker whose `proc->status != PS_AUTH_INACTIVE`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-worker-cmd.c:421-427
**Acceptance:** negative, local — after a worker has already completed
`AUTH_COOKIE_REQ` once (status advanced past `PS_AUTH_INACTIVE`), send a
second `AUTH_COOKIE_REQ` on the same connection and confirm main returns
`ERR_BAD_COMMAND`.
**Links:** REQ-IPC-021

### REQ-IPC-021 — SECM_SESSION_OPEN requires SID of a completed, unexpired session

**Requirement:** sec-mod MUST reply `FAILED` to `SECM_SESSION_OPEN` if
`sid.len != SID_SIZE`, if no `client_entry_st` exists for that SID, if the
entry's status is not `PS_AUTH_COMPLETED`, or if the entry is expired
(`IS_CLIENT_ENTRY_EXPIRED`).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:508-536
**Acceptance:** negative, local — (a) send `SECM_SESSION_OPEN` with a
wrong-length or unknown SID; (b) send it for a SID still in
`PS_AUTH_INIT`/`PS_AUTH_CONT`; (c) send it after the cookie's expiry time
has passed. Each MUST yield `secm_session_reply_msg.reply = FAILED` (via
`send_failed_session_open_reply`).
**Links:** REQ-IPC-015, REQ-IPC-022

### REQ-IPC-022 — SECM_SESSION_OPEN refreshes cookie expiry

**Requirement:** On a successful `SECM_SESSION_OPEN`, sec-mod MUST update
the client entry's `exptime` to `now + cookie_timeout + AUTH_SLACK_TIME` and
increment `e->in_use`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:617-620
**Acceptance:** unit, local — open a session via `SECM_SESSION_OPEN`,
inspect `e->exptime` before/after, confirm it advances by
`cookie_timeout + AUTH_SLACK_TIME`. Cross-reference `doc/sample.config`
`cookie-timeout` documentation.
**Links:** REQ-IPC-021

### REQ-IPC-023 — AUTH_COOKIE_REP carries the TUN device only on OK

**Requirement:** main MUST send `auth_cookie_reply_msg.reply = OK` together
with the allocated TUN device fd (via `send_socket_msg_to_worker`) only when
`proc->tun_lease.name` is set; otherwise it MUST send `reply = FAILED` with
no fd, via `send_msg_to_worker` (no socket transfer).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-auth.c:48-115
**Acceptance:** negative, local — force `SECM_SESSION_OPEN` to fail (e.g.
expired cookie) and confirm the worker receives `AUTH_COOKIE_REP` with
`reply = FAILED` and no fd is transferred (worker does not gain a TUN
device).
**Links:** REQ-IPC-021, REQ-MAIN-NET-* (TUN lease allocation)

### REQ-IPC-024 — Worker MUST NOT have a TUN device before AUTH_COOKIE_REP OK

**Requirement:** A worker process MUST NOT possess an open TUN device file
descriptor before it has received `AUTH_COOKIE_REP` with `reply = OK`.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/main-auth.c:53,103-106; doc/design.md#the-worker-processes
(TUN device "forwarded from main to worker after successful
authentication")
**Acceptance:** [REVIEW: this is a privilege-boundary invariant
(`AGENTS.md` "Architecture" table) but no test directly observes the
worker's fd table pre-/post-`AUTH_COOKIE_REP`. Add a negative test, e.g. via
seccomp audit or `/proc/<worker-pid>/fd` inspection in a CI harness, that
confirms the TUN fd does not exist before `AUTH_COOKIE_REP` OK.]
**Links:** REQ-IPC-023, REQ-SEC-* (privilege boundary)

---

## SECM_SESSION_CLOSE / SECM_CLI_STATS, SEC_CLI_STATS (session teardown)

```
worker -> sec-mod: SEC_CLI_STATS    (cli_stats_msg, SID)
main -> sec-mod:   SECM_SESSION_CLOSE (secm_session_close_msg, SID)
sec-mod -> main:   SECM_CLI_STATS   (cli_stats_msg)
```

### REQ-IPC-030 — SECM_SESSION_CLOSE requires a valid SID

**Requirement:** sec-mod MUST reject `SECM_SESSION_CLOSE` with
`ERR_BAD_COMMAND` if `sid.len != SID_SIZE`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:632-637
**Acceptance:** negative, local — send `SECM_SESSION_CLOSE` with a
malformed `sid`; confirm `ERR_BAD_COMMAND`.
**Links:** REQ-IPC-015

### REQ-IPC-031 — SECM_SESSION_CLOSE for unknown or unauthenticated SID still replies CLI_STATS

**Requirement:** If `SECM_SESSION_CLOSE` references a SID with no
`client_entry_st`, or one whose status is `< PS_AUTH_COMPLETED`, sec-mod
MUST still reply with `CMD_SECM_CLI_STATS` (a zeroed `cli_stats_msg`) rather
than an error, so main's session-close path does not block.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:639-656
**Acceptance:** negative, local — send `SECM_SESSION_CLOSE` for a SID that
was never opened (or only reached `PS_AUTH_INIT`); confirm sec-mod replies
with `CMD_SECM_CLI_STATS` and main does not hang waiting for a reply.
**Links:** REQ-IPC-030

### REQ-IPC-032 — Stats counters are monotonic, taking the maximum

**Requirement:** On `SECM_SESSION_CLOSE`, sec-mod MUST update
`e->stats.{uptime,bytes_in,bytes_out}` only if the incoming value is greater
than the stored value (`>` comparison), never overwriting with a smaller
number.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:658-666
**Acceptance:** unit, local — send `SECM_SESSION_CLOSE` twice for the same
SID, second time with smaller `bytes_in`/`bytes_out`/`uptime`; confirm
`e->stats` values are unchanged after the second message.
**Links:** REQ-IPC-031

### REQ-IPC-033 — server_disconnected sets discon_reason

**Requirement:** When `secm_session_close_msg.server_disconnected` is true,
sec-mod MUST set `e->discon_reason = REASON_SERVER_DISCONNECT` and report it
in the `cli_stats_msg.discon_reason` reply field.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod-auth.c:668-676
**Acceptance:** unit, local — send `SECM_SESSION_CLOSE` with
`server_disconnected = true`; confirm `CMD_SECM_CLI_STATS` reply has
`discon_reason = REASON_SERVER_DISCONNECT`. Cross-check `occtl show events`
output, which surfaces `discon_reason`.
**Links:** REQ-IPC-031

---

## WORKER_STARTUP (main -> worker)

### REQ-IPC-040 — sec_auth_init_hmac is computed by main, not the worker

**Requirement:** The `sec_auth_init_hmac` field used by the worker in
`SEC_AUTH_INIT` MUST be computed by main (using `sec->hmac_key`, which the
worker does not have) and forwarded to the worker via
`worker_startup_msg.sec_auth_init_hmac`; the worker MUST treat this value as
opaque and copy it verbatim into `sec_auth_init_msg.hmac`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main.c:1857-1858 (main computes and sends);
src/worker.c:289-307 (worker copies into `ws->sec_auth_init_hmac`,
bounds-checked against `sizeof(ws->sec_auth_init_hmac)`);
src/worker-auth.c:1762-1763, src/worker-svc.c:127-128 (worker forwards
verbatim in `SEC_AUTH_INIT`)
**Acceptance:** unit, local — confirm `worker_startup_msg.sec_auth_init_hmac`
has length `HMAC_DIGEST_SIZE`; confirm worker rejects/truncates a
`WORKER_STARTUP` message whose `sec_auth_init_hmac` exceeds
`sizeof(ws->sec_auth_init_hmac)` (src/worker.c:289-290).
**Links:** REQ-IPC-010, REQ-SEC-001 (worker has no access to `sec->hmac_key`)

### REQ-IPC-041 — WORKER_STARTUP transfers pre-opened fds, not raw keys

**Requirement:** `worker_startup_msg` MUST transfer only file descriptors
(`cmd_fd`, `conn_fd`, `snapshot_entries[].file_descriptor`) and
non-cryptographic identifiers (`secmod_addr`, IPs, group lists); it MUST NOT
contain private key material or HMAC secrets.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/ipc.proto (`worker_startup_msg` field list)
**Acceptance:** [REVIEW: this is a privilege-boundary assertion derivable
from the schema (no `bytes` field plausibly sized/named for key material),
but there is no automated check that a future field addition to
`worker_startup_msg` doesn't violate it. Consider a schema-diff check or
explicit comment in `ipc.proto` flagging this constraint for reviewers of
future `.proto` edits.]
**Links:** REQ-SEC-001

---

## SEC_SIGN / SEC_SIGN_DATA / SEC_SIGN_HASH / SEC_DECRYPT / SEC_GET_PK (worker <-> sec-mod, via main relay)

### REQ-IPC-050 — Private key operations are delegated, never performed by the worker

**Requirement:** All TLS private-key operations (signing, hash-signing,
decryption, and public-key retrieval) for a vhost's certificate key MUST be
performed by sec-mod in response to `CMD_SEC_SIGN`, `CMD_SEC_SIGN_DATA`,
`CMD_SEC_SIGN_HASH`, `CMD_SEC_DECRYPT`, and `CMD_SEC_GET_PK`; the worker's
GnuTLS `gnutls_privkey_t` callbacks (`key_cb_sign_data_func`,
`key_cb_sign_hash_func`, `key_cb_decrypt_func`) MUST only marshal requests
to sec-mod and return its response — they MUST NOT hold or derive key
material locally.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/tlslib.c:793-832 (`key_cb_*_func` -> `key_cb_common_func` ->
`CMD_SEC_*`); src/sec-mod.c:219-338 (sec-mod performs
`gnutls_privkey_sign_data`/`sign_hash`/`decrypt_data2` using
`vhost->key[i]`)
**Acceptance:** [SEC] negative, local — this is the core
worker/private-key privilege boundary from `AGENTS.md`. Verify (a) the
worker process never opens the vhost private key file (seccomp file-open
denial, or `strace`/audit showing no `open()` of the key path from the
worker PID), and (b) `sec_op_msg` / `sec_get_pk_msg` round trips correctly
for each of `CMD_SEC_SIGN`, `CMD_SEC_SIGN_DATA`, `CMD_SEC_SIGN_HASH`,
`CMD_SEC_DECRYPT`, `CMD_SEC_GET_PK`.
**Links:** REQ-SEC-001 (architecture invariant in AGENTS.md)

### REQ-IPC-051 — sec_op_msg.key_idx and vhost select the key

**Requirement:** sec-mod MUST select the private key for a `sec_op_msg` /
`sec_get_pk_msg` using the requesting worker's `vhost` field and
`key_idx`/`pk` fields, and MUST NOT use a key belonging to a different vhost
than the one the requesting worker was started for.
**Strength:** MUST NOT
**Status:** REVIEW
**Source:** src/sec-mod.c:219-338 (`vhost->key[i]` indexed by `key_idx`);
src/sec-mod.c:1160-1201 (accept loop — `check_upeer_id()` validates only the
peer process's uid/gid/pid, recording no vhost binding for `cfd`);
src/vhost.h:137-152 (`find_vhost()` — case-insensitive string match over
*all* configured vhosts on the message-supplied `name`, falling back to
`default_vhost()`, never failing)
**Acceptance:** [REVIEW: confirmed interpretation (b) — sec-mod's
connection-accept path (`accept()` + `check_upeer_id()` in
`src/sec-mod.c`'s main loop) establishes no per-connection vhost binding; it
checks only that the peer is a legitimate ocserv worker process (uid/gid/pid),
not which vhost it was started for. `process_worker_packet()` then resolves
the vhost for `CMD_SEC_GET_PK`/`CMD_SEC_SIGN_DATA`/`CMD_SEC_SIGN_HASH`/
`CMD_SEC_SIGN`/`CMD_SEC_DECRYPT` purely via `find_vhost(sec->vconfig,
op->vhost)` — a string supplied in the message itself — and then indexes
`vhost->key[key_idx]` (bounds-checked against that *resolved* vhost's
`key_size`, but not against the requesting worker's own vhost). A worker
that supplies a different, validly-configured vhost's name in
`op->vhost`/`pkm->vhost` causes sec-mod to perform the signing/decryption
operation with that other vhost's private key and return the result to the
requester. This appears to violate the stated MUST NOT and needs maintainer
review: either (i) sec-mod must record the vhost a worker was started for
(e.g. at `WORKER_STARTUP`/first request) and reject `sec_op_msg`/
`sec_get_pk_msg` whose `vhost` field does not match it, or (ii) the
requirement's premise that vhosts are mutually-distrusting boundaries needs
revising if cross-vhost key use is intentional in this deployment model.]
**Links:** REQ-IPC-050

---

## RESUME_STORE_REQ / RESUME_FETCH_REQ / RESUME_DELETE_REQ / RESUME_FETCH_REP (worker <-> sec-mod)

### REQ-IPC-060 — Resumption data is zeroized after use

**Requirement:** sec-mod MUST zero the raw IPC buffer and the unpacked
`session_resume_store_req_msg.session_data` with `safe_memset()` after
processing `RESUME_STORE_REQ`, regardless of success or failure.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod.c:393-397
**Acceptance:** unit, local — after `handle_resume_store_req()` returns,
inspect the buffer passed to `recv_msg` and `smsg->session_data.data`;
confirm both are zero-filled. This protects TLS session resumption secrets
from being left in process memory longer than necessary.
**Links:** —

### REQ-IPC-061 — RESUME_FETCH_REQ always replies, OK or FAILED

**Requirement:** sec-mod MUST always send a `RESUME_FETCH_REP`
(`session_resume_reply_msg`) in response to `RESUME_FETCH_REQ`, with
`reply = OK` and `session_data` populated on success, or `reply = FAILED`
(no `session_data`) if `handle_resume_fetch_req()` returns an error.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sec-mod.c:428-463
**Acceptance:** negative, local — request resumption for a `session_id`
that was never stored (or was deleted via `RESUME_DELETE_REQ`); confirm the
worker receives `RESUME_FETCH_REP` with `reply = FAILED` rather than no
reply or a connection error.
**Links:** —

---

## SECM_TERMINATE_USER_SESSIONS / SECM_TERMINATE_SESSION (occtl -> main -> sec-mod)

```
occtl -> main: CTL_CMD_LIST_COOKIES               (resolve short SID -> safe_id)
main -> occtl: cookie list
occtl -> main: CTL_CMD_TERMINATE_USER / ID / SESSION
main:          disconnect worker process(es)
main -> sec-mod: SECM_TERMINATE_USER_SESSIONS (username)  | SECM_TERMINATE_SESSION (safe_id)
sec-mod -> main: SECM_TERMINATE_SESSION_REPLY
main -> occtl: CTL_CMD_TERMINATE_*_REP
```

### REQ-IPC-070 — Session ID prefix ambiguity is rejected, not guessed

**Requirement:** When `occtl terminate session` is given a session ID
prefix that matches more than one entry in the cookie list returned by
`CTL_CMD_LIST_COOKIES`, main/occtl MUST refuse the operation and list the
matching sessions rather than acting on the first or any arbitrary match.
**Strength:** MUST
**Status:** DERIVED
**Source:** doc/design.md#ipc-communication-for-session-termination
("If the prefix is ambiguous (matches multiple sessions), occtl refuses the
operation and lists the matching sessions.")
**Acceptance:** negative, local — create two sessions whose `safe_id`
values share a common prefix; run `occtl terminate session <prefix>` and
confirm it refuses with a list of matches, and that neither session is
terminated. Scripts MUST instead use the full session ID from `occtl --json
show sessions valid` (`Full session` field).
**Links:** REQ-IPC-071

### REQ-IPC-071 — SECM_TERMINATE_* always elicits SECM_TERMINATE_SESSION_REPLY

**Requirement:** sec-mod MUST reply to both `SECM_TERMINATE_USER_SESSIONS`
and `SECM_TERMINATE_SESSION` with `secm_terminate_session_reply_msg`, with
`result = true` only if at least one matching session's cookie was
invalidated.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/ipc.proto (`secm_terminate_session_reply_msg`); src/sec-mod.c
(CMD_SECM_TERMINATE_* handlers near line 549+)
**Acceptance:** negative, local — issue `SECM_TERMINATE_USER_SESSIONS` for a
username with no active sessions; confirm `result = false` is returned (not
an error/timeout), and confirm main relays this via `CTL_CMD_TERMINATE_*_REP`
to occtl.
**Links:** REQ-IPC-070

### REQ-IPC-072 — Termination invalidates the cookie, not just the live connection

**Requirement:** A successful `SECM_TERMINATE_USER_SESSIONS` /
`SECM_TERMINATE_SESSION` MUST invalidate the session's cookie in sec-mod
(so a subsequent `AUTH_COOKIE_REQ` / `SECM_SESSION_OPEN` with that SID fails
per REQ-IPC-021), in addition to main disconnecting any live worker for that
session.
**Strength:** MUST
**Status:** DERIVED
**Source:** doc/design.md#ipc-communication-for-session-termination ("main
process disconnects the active worker (if any) and forwards the request to
sec-mod to invalidate the session cookie, preventing automatic
reconnection")
**Acceptance:** negative, local — terminate a session via `occtl`, then
attempt to reconnect a client using the previously-issued cookie; confirm
`AUTH_COOKIE_REQ` is rejected (`AUTH_COOKIE_REP` `reply = FAILED`) rather
than resuming the terminated session.
**Links:** REQ-IPC-021, REQ-IPC-071

---

## WORKER_BAN_IP / SECM_BAN_IP (worker -> main, sec-mod -> main)

### REQ-IPC-080 — ban_ip_reply_msg.sid is only meaningful from sec-mod

**Requirement:** The `sid` field of `ban_ip_reply_msg` (used by main to tell
sec-mod whether to disconnect a user, per the `ban_ip_msg` comment "sec-mod
sends it") MUST be populated only on the sec-mod -> main direction; main
MUST NOT depend on a worker-supplied `ban_ip_msg.sid` to disconnect a
different session than the one reporting the ban.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/ipc.proto (`ban_ip_msg.sid` comment "sec-mod sends it";
`ban_ip_reply_msg.sid` comment "sec-mod needs it");
src/worker-vpn.c:499-509 (`CMD_BAN_IP` send, `has_sid` never set);
src/main-worker-cmd.c:282-322 (`CMD_BAN_IP` handler, never reads `tmsg->sid`,
replies with `BAN_IP_REPLY_MSG__INIT` so `has_sid == 0`);
src/sec-mod-auth.c:103-105 (`CMD_SECM_BAN_IP` send, `sid = e->sid`,
`has_sid = 1`); src/main-sec-mod-cmd.c:143-181 (`CMD_SECM_BAN_IP` handler
echoes `tmsg->sid` into the reply); src/sec-mod.c:506-517
(`CMD_SECM_BAN_IP_REPLY` dispatches to `handle_sec_auth_ban_ip_reply`)
**Acceptance:** positive, local — confirm `BanIpMsg msg = BAN_IP_MSG__INIT`
in `src/worker-vpn.c` is never followed by an assignment to `msg.sid` or
`msg.has_sid`, so every `CMD_BAN_IP` message from a worker has `has_sid ==
0`. Confirm the `CMD_BAN_IP` case in `src/main-worker-cmd.c` has no
reference to `tmsg->sid` and constructs its reply from
`BAN_IP_REPLY_MSG__INIT` without setting `reply.sid`/`reply.has_sid`.
Negative — confirm `handle_sec_auth_ban_ip_reply()` (the only consumer of
`ban_ip_reply_msg.sid` for session lookup, via `find_client_entry`) is
reachable only from the `CMD_SECM_BAN_IP_REPLY` case in `src/sec-mod.c`,
never from `CMD_BAN_IP_REPLY` (the worker-facing reply, handled in
`src/worker-vpn.c` without inspecting `reply->sid`). Together these confirm
that even a compromised worker sending a crafted `ban_ip_msg` with
`has_sid=1` and an arbitrary `sid` would have that field silently ignored by
main — `sid` is meaningful only on the sec-mod <-> main `CMD_SECM_BAN_IP` /
`CMD_SECM_BAN_IP_REPLY` round trip.
**Links:** REQ-SEC-*

---

## Completeness notes

- **Coverage**: every `cmd_request_t` value in `src/defs.h` with a
  corresponding message in `src/ipc.proto` has at least one requirement
  above, except the latency-stats path (`CMD_LATENCY_STATS_DELTA`,
  `latency_stats_delta`) and `CMD_SECM_STATS`/`CMD_SECM_RELOAD`, which are
  periodic/administrative and have no security-relevant validation beyond
  REQ-IPC-001/002. `[UNDOCUMENTED: if these messages gain validation logic
  in the future, add requirements here.]`
- **ctl.proto**: only the termination flow (REQ-IPC-070..072) is covered in
  detail, since it is the security-relevant occtl path (it can end a user's
  VPN session). Read-only `occtl` queries (`status_rep`, `user_list_rep`,
  `ban_list_rep`, etc.) are reporting-only and have no MUST/MUST NOT
  contract beyond "reflect server state accurately" —
  `[UNDOCUMENTED: candidate for a future REQ-IPC-LOG-* style requirement if
  occtl output is found to diverge from server state]`.
- **Field coverage gap**: `group_cfg_st` (the per-user/group supplemental
  config forwarded in `auth_cookie_reply_msg.config` and
  `secm_session_reply_msg.config`) is not covered field-by-field here; its
  contract is primarily a `CFG` concern and is covered in
  `internal/sec-mod.md` (population) and `internal/worker.md` (consumption).
