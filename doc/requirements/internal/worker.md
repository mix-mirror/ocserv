---
title: worker process requirements
generator: requirements-from-implementation
process: worker
id-prefix: REQ-WORKER
sources:
  - src/worker.c
  - src/worker-vpn.c
  - src/worker-auth.c
  - src/worker-resume.c
  - src/worker-privs.c
  - src/isolate.c
  - src/tlslib.c
  - src/worker.h
  - doc/design.md#the-worker-processes
  - doc/requirements/internal/ipc.md
  - doc/requirements/internal/sec-mod.md
---

# worker Process Requirements

The worker is unprivileged, seccomp-confined, and handles exactly one
client's TLS/DTLS session and HTTP(S) authentication exchange. It has no
direct access to credentials, private keys, or the ban database — these are
delegated to sec-mod (REQ-IPC-050) and main (`ws_add_score_to_ip` /
`WORKER_BAN_IP`, REQ-IPC-080) respectively. This document covers the
worker's own state machine: startup/config receipt, privilege drop, seccomp
filter, TLS/DTLS session setup, the HTTP authentication handlers, and cookie
finalization.

## INIT

### REQ-WORKER-INIT-001 — Worker refuses to run without OCSERV_ENV_WORKER_STARTUP_MSG

**Requirement:** `main()` MUST check for the `OCSERV_ENV_WORKER_STARTUP_MSG`
environment variable and `exit(EXIT_FAILURE)` with a diagnostic if absent,
before any other initialization — the worker binary MUST NOT be runnable
standalone.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker.c:71-75
**Acceptance:** negative, local — run `ocserv-worker` directly (no env var
set); confirm it prints "This application is part of ocserv and should not
be run in isolation" and exits non-zero without opening any sockets.
**Links:** —

### REQ-WORKER-INIT-002 — set_ws_from_env bounds-checks every variable-length field before memcpy

**Requirement:** `set_ws_from_env()` MUST validate
`msg->secmod_addr.len <= sizeof(ws->secmod_addr)`,
`msg->remote_addr.len <= sizeof(ws->remote_addr)`,
`msg->our_addr.len <= sizeof(ws->our_addr)`, and
`msg->sec_auth_init_hmac.len <= sizeof(ws->sec_auth_init_hmac)` —
returning failure (and the worker exiting) if any check fails — before
copying the corresponding field with `memcpy`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker.c:277-307
**Acceptance:** [SEC] negative, unit — construct a `WorkerStartupMsg` with
`secmod_addr.len` (or each of the other three fields) larger than the
destination struct field; confirm `set_ws_from_env` returns 0 and the
worker exits via `return 1` in `main()`, rather than overflowing
`ws->secmod_addr`/etc. This is the worker-side mirror of REQ-IPC-041's
schema-diff concern — even if main never sends an oversized field, the
worker MUST NOT trust that invariant blindly, since `WorkerStartupMsg` is
attacker-influenced indirectly (fields like `remote_addr`/`our_addr`
ultimately derive from the client's connection).
**Links:** REQ-IPC-040, REQ-IPC-041

### REQ-WORKER-INIT-003 — drop_privileges performs chroot, then chdir("/"), then setgid/setuid, in that order

**Requirement:** If `chroot_dir` is configured, `drop_privileges()` MUST
`chdir(chroot_dir)`, then `chroot(chroot_dir)`, then `chdir("/")` — in this
order — each step fatal (`exit(EXIT_FAILURE)`) on failure. `setgid`/
`setgroups` (if `gid != -1` and currently root) MUST be performed before
`setuid` (if `uid != -1` and currently root) — reversing this order would
leave the process unable to change its group membership after dropping
root.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/isolate.c:127-184
**Acceptance:** [SEC] negative, local — configure `chroot`, `run-as-user`,
`run-as-group`; after worker startup, confirm (a) the worker's filesystem
root is the configured chroot directory (e.g. via `/proc/<pid>/root`), (b)
`getuid()`/`getgid()` in the worker match the configured non-root
user/group, and (c) `getgroups()` returns exactly the configured group
(supplementary groups dropped via `setgroups(1, &gid)`).
**Links:** —

### REQ-WORKER-INIT-004 — drop_privileges sets RLIMIT_NPROC to 0 after privilege drop

**Requirement:** `drop_privileges()` MUST call
`setrlimit(RLIMIT_NPROC, {0,0})` as its final step, preventing the worker
(now unprivileged) from forking any child process. A failure to set this
limit MUST be logged but is non-fatal (the worker continues — some
container/seccomp environments deny `setrlimit` itself).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/isolate.c:186-193
**Acceptance:** [SEC] negative, local — after worker startup, attempt
`fork()` from within the worker (e.g. a debug build hook); confirm it fails
with `EAGAIN`/`ENOMEM` due to `RLIMIT_NPROC=0`. This is defense-in-depth: a
worker that achieved arbitrary code execution still cannot spawn a shell via
`fork`+`exec`.
**Links:** REQ-WORKER-INIT-005

### REQ-WORKER-INIT-005 — Worker syscall filter is a fixed allowlist; unlisted syscalls terminate the process

**Requirement:** When built with `HAVE_LIBSECCOMP`, `disable_system_calls()`
MUST install a seccomp filter whose default action is
`SCMP_ACT_ERRNO(ENOSYS)` (or `SCMP_ACT_TRAP` under
`USE_SECCOMP_TRAP`, which logs via `oc_syslog` and calls
`exit(EXIT_FAILURE)` from `sigsys_action`) for any syscall not on the
explicit allowlist. The allowlist MUST be installed (`seccomp_load`)
before the worker processes any client-supplied data. `ioctl` is
allowed ONLY for `SIOCGIFMTU` (`SCMP_A1(SCMP_CMP_EQ, SIOCGIFMTU)`) — no
other `ioctl` request codes are permitted.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-privs.c:71-237
**Acceptance:** [SEC] negative, local — with seccomp enabled
(`ISOLATE_WORKERS=true`, not ASAN/coverage build), attempt to trigger a
disallowed syscall from the worker (e.g. `socketpair`, `execve`, `ptrace`,
or `ioctl` with a request other than `SIOCGIFMTU`); confirm the worker
terminates (under `SCMP_ACT_ERRNO`: the call fails with `ENOSYS` and
whatever error handling follows; under `SCMP_ACT_TRAP`: the process exits
via `SIGSYS`/`sigsys_action`). A worker that gained code execution via a
parsing bug MUST NOT be able to `execve()` a shell or `ptrace()` another
process.
**Links:** REQ-WORKER-INIT-004

### REQ-WORKER-INIT-006 — seccomp filter is conditionally relaxed only for socket_wrapper test environments

**Requirement:** `readlink`/`readlinkat` MUST be added to the seccomp
allowlist ONLY when `SOCKET_WRAPPER_DIR` is set in the environment (test
harness). Production deployments (no `SOCKET_WRAPPER_DIR`) MUST NOT have
these syscalls available to the worker.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/worker-privs.c:107-112
**Acceptance:** [SEC] negative, local — run a production-configured worker
(no `SOCKET_WRAPPER_DIR`) and confirm `readlink`/`readlinkat` are rejected
by the seccomp filter. Confirmed no other env-var-gated relaxations exist in
`disable_system_calls()` (src/worker-privs.c:71-220, the only function
adding `seccomp_rule_add(ctx, SCMP_ACT_ALLOW, ...)` rules, called from
src/worker-vpn.c:881): every other `ADD_SYSCALL(...)` invocation in that
function is unconditional — `SOCKET_WRAPPER_DIR` is the only `getenv()` check
in the file, gating exactly the `readlink`/`readlinkat` pair.
**Links:** REQ-WORKER-INIT-005

---

## AUTH

The credential-delegation principle and certificate-username-extraction
requirements formerly numbered `REQ-WORKER-AUTH-001..003` have moved to
`internal/authentication.md`, alongside the full per-auth-method requirements
pass. The old IDs are kept reserved (not reused) for citation stability:

| Old ID | New ID |
|--------|--------|
| `REQ-WORKER-AUTH-001` | `REQ-AUTH-AUTH-007` |
| `REQ-WORKER-AUTH-002` | `REQ-AUTH-AUTH-008` |
| `REQ-WORKER-AUTH-003` | `REQ-AUTH-AUTH-009` |

`REQ-WORKER-AUTH-001..003` are `WITHDRAWN` (relocated; see table above). The
cookie/camouflage/IPC-validation requirements below
(`REQ-WORKER-AUTH-004..006`) remain here — they concern worker session/cookie
handling rather than authentication-method semantics.

### REQ-WORKER-AUTH-004 — Camouflage gate: failed cookie auth under camouflage returns 405, not 401/503, until the secret is matched

**Requirement:** When `camouflage` is configured and
`ws->camouflage_check_passed == 0`, a failed `cookie_authenticate_or_exit()`
MUST respond `405 Method Not Allowed` (indistinguishable from a non-VPN web
server's response to an unexpected method) rather than `401`/`503`, which
would reveal the presence of an ocserv endpoint to an unauthenticated
prober. `check_camouflage_url()` sets `camouflage_check_passed = 1` only
when the request URL's query string exactly equals
`camouflage_secret`, OR when `ws->auth_state >= S_AUTH_COOKIE` (i.e. the
client has already gotten past the camouflage gate once this session).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-auth.c:1044-1057, src/worker-vpn.c:819-836
**Acceptance:** [SEC] negative — with `camouflage` configured and a secret
set, send a CONNECT request with an invalid cookie and no/incorrect
camouflage query string; confirm the response is `405`, not `401` or
`503`. Positive: append `?<camouflage-secret>` to the URL with an invalid
cookie; confirm the response reverts to `401`/`503` (camouflage passed,
real error now shown).
**Links:** —

### REQ-WORKER-AUTH-005 — Cookie auth reply from main is strictly validated before TUN claim and config acceptance

**Requirement:** `recv_cookie_auth_reply()`, on `AUTH__REP__OK`, MUST
validate (failing with `ERR_AUTH_FAIL` and NOT installing `ws->user_config`
or `ws->tun_fd` otherwise): `msg->vname`, `msg->config`, `msg->user_name`
all non-NULL; `msg->sid.len == sizeof(ws->sid)`;
`msg->session_id.len == sizeof(ws->session_id)`;
`msg->secmod_addr.len <= sizeof(ws->secmod_addr)`; and that
`tun_claim(ws->tun_fd)` succeeds for the fd received via
`send_socket_msg_to_worker` (REQ-IPC-023). Any failure MUST result in
`ERR_AUTH_FAIL` and the worker exiting via `cookie_authenticate_or_exit()`'s
`exit_worker(ws)` path — never falling through to `tun_mainloop` with a
partially-populated `ws->user_config`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-auth.c:721-867, src/worker-auth.c:1024-1060
**Acceptance:** [SEC] negative, local — (requires fault injection in main or
a test double for `AUTH_COOKIE_REP`) send `AUTH__REP__OK` with `sid.len`
one byte short of `SID_SIZE`; confirm the worker treats this as
`ERR_AUTH_FAIL`, never sets `ws->sid_set = 1`, and exits rather than
proceeding into `connect_handler`.
**Links:** REQ-IPC-023, REQ-IPC-024

### REQ-WORKER-AUTH-006 — user_config from AuthCookieReplyMsg is a borrowed pointer; freed only on the error path

**Requirement:** On `AUTH__REP__OK`, `ws->user_config = msg->config` MUST
alias memory owned by the unpacked `AuthCookieReplyMsg` (`msg`) for the
remainder of the worker's lifetime — `recv_cookie_auth_reply()` MUST NOT
call `auth_cookie_reply_msg__free_unpacked(msg, &pa)` on the success path.
On any error path (`ret < 0`), it MUST free `msg` and set
`ws->user_config = NULL` to avoid a dangling pointer.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-auth.c:856-866 (comment explicitly documents this
lifetime contract)
**Acceptance:** [SEC] This is a memory-safety invariant rather than a
behaviorally-observable one, and is covered by the existing `asan/clang/Fedora`
CI job (.gitlab-ci.yml:403-414) rather than a dedicated test. That job runs
with `DISABLE_ASAN_BROKEN_TESTS=1`, which `tests/common.sh:33-36` translates
into `ISOLATE_WORKERS=false` — i.e. worker processes run under ASAN/LSAN
instrumentation instead of seccomp isolation. `recv_cookie_auth_reply()` is
called from `auth_cookie_request()` (src/worker-auth.c:1102) on every
successful connection, and `ws->user_config` is dereferenced throughout
`worker-vpn.c` for the life of the worker, so the `AUTH__REP__OK` success
path (and the subsequent free of `msg`/`ws->user_config` at worker exit) is
exercised by every CONNECT-flow `root_scripts` test (e.g.
`test-cookie-timeout`, `traffic`) that job runs. A pass of `asan/clang/Fedora`
with no LeakSanitizer/ASAN report against `recv_cookie_auth_reply` or
`ws->user_config` is sufficient acceptance; no new test required.
**Links:** —

---

## SEC

### REQ-WORKER-SEC-001 — Private-key operations are marshaled to sec-mod; the worker never holds the private key

**Requirement:** `key_cb_sign_data_func`, `key_cb_sign_hash_func`,
`key_cb_sign_func`, and `key_cb_decrypt_func` (installed via
`gnutls_privkey_import_ext4`/`_ext2` with
`GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE`) MUST each call
`key_cb_common_func()`, which sends `CMD_SEC_SIGN_DATA` /
`CMD_SEC_SIGN_HASH` / `CMD_SEC_SIGN` / `CMD_SEC_DECRYPT` to sec-mod over
`cdata->sa` (the sec-mod socket address recorded at certificate-load time)
and returns sec-mod's result — the `gnutls_privkey_t` registered in the
worker's TLS credentials holds no exploitable key material, only `cdata`
(vhost name, key index, socket address).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/tlslib.c:793-836, src/tlslib.c:893-930; REQ-IPC-050
**Acceptance:** [SEC] negative, local — after worker startup (post
`drop_privileges`+seccomp), search the worker's heap/memory for the PEM
private key's byte pattern (e.g. via a debug build that logs the key,
compared against `/proc/<pid>/maps` + `gcore`); confirm it is absent — only
sec-mod's process memory contains it. This is the core privilege-boundary
invariant restated from the worker's perspective; REQ-IPC-050 covers the
IPC framing.
**Links:** REQ-IPC-050

### REQ-WORKER-SEC-002 — TLS session resumption data is size-capped before being sent to sec-mod

**Requirement:** `resume_db_store()` MUST reject (return
`GNUTLS_E_DB_ERROR` without contacting sec-mod) any resumption `data.size >
MAX_SESSION_DATA_SIZE` or `key.size > GNUTLS_MAX_SESSION_ID`.
`resume_db_fetch()`/`resume_db_delete()` MUST similarly reject
`key.size > GNUTLS_MAX_SESSION_ID` before sending `RESUME_FETCH_REQ`/
`RESUME_DELETE_REQ`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-resume.c:82-206
**Acceptance:** [SEC] negative, unit — call `resume_db_store` with a
`gnutls_datum_t` larger than `MAX_SESSION_DATA_SIZE`; confirm it returns
`GNUTLS_E_DB_ERROR` and `connect_to_secmod()` is never called (no socket
opened). This bounds the size of data sec-mod must store per session
(REQ-IPC-060) and prevents a malicious/buggy TLS stack from using session
tickets as an amplification vector against sec-mod's memory.
**Links:** REQ-IPC-060, REQ-IPC-061

### REQ-WORKER-SEC-003 — DTLS-PSK key is derived per-session via gnutls_prf from the already-authenticated TLS master secret

**Requirement:** `setup_dtls_psk_keys()` MUST derive the DTLS-PSK key via
`gnutls_prf(ws->session, ..., PSK_LABEL, ...)` over the existing
(authenticated) CSTP TLS session — it MUST NOT proceed
(`oclog(...); return -1`) if `ws->session == NULL` (no CSTP session to
derive from). The legacy DTLS path (`setup_legacy_dtls_keys`) similarly
requires `ws->req.selected_ciphersuite != NULL`, failing otherwise.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-vpn.c:273-381
**Acceptance:** unit, local — attempt DTLS setup before CSTP TLS handshake
completes (`ws->session == NULL`); confirm `setup_dtls_psk_keys` returns -1
and no DTLS session is established. This ensures the DTLS channel is always
cryptographically bound to an already-authenticated TLS session — a DTLS
channel cannot be the *first* authenticated channel for a worker.
**Links:** —

### REQ-WORKER-SEC-004 — Ban-score reports to main are advisory for final reports; main's verdict on non-final reports is enforced by immediate worker exit

**Requirement:** `ws_add_score_to_ip()` MUST send a `WORKER_BAN_IP`
(`BanIpMsg`) to main and act on `BanIpReplyMsg` (REQ-IPC-080) as follows:
the worker holds no ban database and cannot itself decide whether an IP is
banned — that decision is made by main (`add_str_ip_to_ban_list`,
`check_if_banned`, REQ-MAIN-SEC-002..007). For a **final** report
(`final == 1`, sent only from `exit_worker_reason()` when the worker has
already decided to exit for `reason`/`discon_reason`), the worker MUST NOT
let `reply->reply` alter that already-decided exit. For a **non-final**
report (`final == 0`, e.g. on a scoring event during an active session),
the worker MUST treat `reply->reply != AUTH__REP__OK` as main's
instruction to terminate the *current* connection immediately
(`exit(EXIT_FAILURE)`) — main is the sole authority on whether the ban
threshold (`max_ban_score`) has been exceeded, but the worker enforces that
single verdict locally.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-vpn.c:479-531 (`ws_add_score_to_ip`: `if (final == 0
&& reply->reply != AUTH__REP__OK) exit(EXIT_FAILURE);`); src/worker-vpn.c:600-618
(`exit_worker_reason` — calls `ws_add_score_to_ip(ws, 0, 1, reason)` only
after unconditionally committing to `talloc_free(ws->main_pool)` +
`worker_exit(EXIT_FAILURE)`, which execute regardless of `reply->reply`);
src/worker-kkdcp.c:153 (`ws_add_score_to_ip(ws,
WSRCONFIG(ws)->ban_points_kkdcp, 0, 0)` — the only `final == 0` call site);
src/ipc.proto:209-214 (`ban_ip_reply_msg.reply` comment: "whether to
disconnect the user"); src/main-worker-cmd.c:298-310 (`CMD_BAN_IP` handler —
`reply.reply = AUTH__REP__FAILED` iff `add_str_ip_to_ban_list()` reports the
score now exceeds `max_ban_score`, else `AUTH__REP__OK`)
**Acceptance:** [SEC] Confirmed by tracing both call sites of
`ws_add_score_to_ip`:
  - **Final report** (`exit_worker_reason`, `final=1`): the `exit()` check
    at worker-vpn.c:525 is gated on `final == 0`, so `reply->reply` has no
    effect — the worker exits for the reason it already had, independent of
    the ban reply. Positive test: drive a session to `exit_worker_reason`
    with `ws->ban_points > 0` while main's reply is `AUTH__REP__FAILED`;
    confirm the worker's exit code/log reflects `discon_reason`, not the
    ban reply.
  - **Non-final report** (`worker-kkdcp.c`, `final=0`): if main replies
    `AUTH__REP__FAILED` (max-ban-score exceeded for this IP), the worker
    calls `exit(EXIT_FAILURE)` immediately, tearing down the current
    connection. Positive test: configure a low `max-ban-score`, trigger
    repeated `ban_points_kkdcp`-scoring KKDCP requests from one IP; confirm
    the worker exits once main reports `AUTH__REP__FAILED`, and that the
    *next* connection attempt from that IP is rejected by main per
    REQ-MAIN-SEC-002..007 (the ban now applies to future connections too,
    not just this one).
  - Negative: confirm a worker cannot use `BanIpReplyMsg` to learn ban-list
    state for *other* IPs — `ban_ip_msg.ip = ws->remote_ip_str` is always the
    worker's own peer address (worker-vpn.c:500), so the reply is scoped to
    that single IP only.
**Links:** REQ-IPC-080, REQ-MAIN-SEC-002, REQ-MAIN-SEC-005

---

## NET

### REQ-WORKER-NET-001 — Virtual host selection from TLS SNI happens before credentials are set, and falls back to default vhost

**Requirement:** `hello_hook_func()` (or its `peek_client_hello` fallback
for GnuTLS < 3.4) MUST call `find_vhost(ws->vconfig, hostname)` using the
TLS ClientHello's `server_name` extension (parsed via manual
`SKIP8`/`SKIP16` traversal of the handshake message, bounds-checked against
`msg->size` and `sizeof(ws->buffer) - 1` at each step), and MUST call
`SET_VHOST_CREDS` (selecting the matching vhost's certificate/key
credentials for the handshake) regardless of whether a matching vhost was
found — falling back to the default vhost. A client requesting an unknown
hostname MUST NOT cause the handshake to abort; it proceeds with the
default vhost's credentials (logged at `LOG_INFO`).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-vpn.c:671-836
**Acceptance:** unit, local — connect with SNI set to a hostname not
matching any configured vhost; confirm the handshake completes using the
default vhost's certificate, and the server logs "client requested hostname
... does not match known vhost". [SEC] negative — send a ClientHello with a
server_name extension whose declared length (`hsize`) would read past
`msg->size` or past `sizeof(ws->buffer)`; confirm `hello_hook_func` detects
this (`hsize == 0 || hsize + pos > msg->size || hsize > sizeof(ws->buffer) -
1`) and aborts SNI parsing (`goto finish`) without an out-of-bounds
`memcpy`.
**Links:** —

### REQ-WORKER-NET-002 — connect_handler only accepts the literal CONNECT target /CSCOSSLC/tunnel

**Requirement:** `connect_handler()` MUST respond `404` and close the
connection (`cstp_fatal_close` + `exit_worker`) for any CONNECT request
whose `req->url` is neither `/CSCOSSLC/tunnel` nor `CSCOSSLC/tunnel`
(the latter accommodating a known Clavister Android client defect). This
check MUST happen after `cookie_authenticate_or_exit()` — i.e. an
unauthenticated client gets the cookie-auth error response, not a 404,
regardless of the URL it requested.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-vpn.c:2075-2085
**Acceptance:** negative, local — with a valid cookie, send
`CONNECT /not-the-tunnel-path HTTP/1.1`; confirm `404` and connection
close. With an invalid/absent cookie and the same bad path, confirm the
cookie-auth error (REQ-WORKER-AUTH-005) is returned, not `404` — ordering
matters for camouflage (REQ-WORKER-AUTH-004).
**Links:** REQ-WORKER-AUTH-004, REQ-WORKER-AUTH-005

### REQ-WORKER-NET-003 — DTLS is enabled only if UDP is configured, not disabled by user config, and a TLS master secret was captured

**Requirement:** `connect_handler()` MUST set
`DTLS_ACTIVE(ws)->udp_state = DTLS_INACTIVE(ws)->udp_state = UP_WAIT_FD`
(enabling DTLS) only if ALL of: `WSSCONFIG(ws)->udp_port != 0`,
`!WSRCONFIG(ws)->no_udp` (REQ-IPC AUTH_COOKIE_REP `config.no_udp`,
REQ-WORKER-AUTH-005), and `req->master_secret_set != 0` (the TLS handshake
exposed a master secret via the `SSLKEYLOGFILE`-style hook). If any
condition fails, DTLS MUST remain `UP_DISABLED` and `ws->master_secret`
MUST NOT be populated from `req->master_secret`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/worker-vpn.c:2157-2168
**Acceptance:** unit, local — (a) set `no_udp` for a user (via sec-mod
per-user config) and confirm `X-DTLS-*` headers are absent / DTLS never
activates for that session even though `udp-port` is globally configured;
(b) configure `udp-port = 0` and confirm the same.
**Links:** REQ-WORKER-SEC-003

## Completeness notes

- **`worker-vpn.c` main loops** (`tls_mainloop`, `dtls_mainloop`,
  `tun_mainloop`, `parse_data`/`parse_cstp_data`/`parse_dtls_data`,
  ~2600 lines combined): the per-packet CSTP/DTLS framing and tun-bridging
  protocol is largely *protocol*-level (what bytes mean) rather than
  process-security — those requirements belong in
  `protocol/sources/anyconnect.md` (AC-CLIENT-*) and `protocol/unified.md`
  (REQ-PROTO-DATA-*), not here. `[UNDOCUMENTED: candidate
  REQ-WORKER-NET-* if a process-boundary-relevant invariant is found in
  these loops, e.g. bounds-checking of attacker-controlled length fields
  before `tun_enqueue_write`.]`
- **`worker-kkdcp.c`** (GSSAPI KKDCP proxying, 334 lines): not examined in
  this pass. `[UNDOCUMENTED: candidate REQ-WORKER-AUTH-* / REQ-WORKER-NET-*
  covering how KKDCP requests are validated/forwarded — this is a
  worker-to-KDC proxy path and warrants its own security review given it
  involves the worker making outbound network connections.]`
- **`worker-proxyproto.c`** (492 lines, PROXY protocol v1/v2 parsing): not
  examined. `[UNDOCUMENTED: candidate REQ-WORKER-NET-* — this is the
  worker-side counterpart to REQ-MAIN-INIT-005's open question about
  post-PROXY-header ban enforcement; also a natural place for
  length/bounds-checking requirements on attacker-controlled proxy headers.]`
- **`worker-svc.c`** (Cisco SVC/AnyConnect-specific binary protocol
  handling, 304 lines): deferred to `protocol/sources/anyconnect.md`
  (AC-CLIENT-*) per the project layout — this is client-compatibility
  protocol surface, not a process-isolation concern.
- **`worker-http.c`/`worker-http-handlers.c`** (HTTP parsing via llhttp,
  ~1187 lines combined): the HTTP request/response framing itself
  (header limits, method routing) is protocol-level;
  `MAX_HTTP_REQUESTS`/`requests_left` (src/worker-vpn.c:860) bounds the
  number of pipelined requests per TLS connection — `[UNDOCUMENTED:
  candidate REQ-WORKER-NET-* if this bound has security significance
  beyond resource exhaustion, e.g. preventing auth-state confusion across
  pipelined requests.]`
- **GSSAPI/KKDCP ASN.1 init** (`asn1_array2tree(kkdcp_asn1_tab, ...)`,
  src/worker.c:175-182): fatal on failure at startup; not analyzed further.
