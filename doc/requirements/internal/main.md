---
title: main process requirements
generator: requirements-from-implementation
process: main
id-prefix: REQ-MAIN
sources:
  - src/main.c
  - src/main-ban.c
  - src/main-auth.c
  - src/main-worker-cmd.c
  - src/main-sec-mod-cmd.c
  - src/main-proc.c
  - src/ip-lease.c
  - src/vpn.h
  - doc/design.md#the-main-process
  - doc/requirements/internal/ipc.md
---

# main Process Requirements

main runs as root and owns the TCP/UDP listeners, TUN device allocation, IP
leasing, the per-connection ban list, and worker process lifecycle. It
delegates authentication and credential handling to sec-mod entirely (see
`internal/ipc.md` and `internal/sec-mod.md`). This document covers main's
own state: listener setup, the fork/worker-spawn sequence, IP lease
allocation, and the ban-score database (`src/main-ban.c`).

## INIT

### REQ-MAIN-INIT-001 — Worker fork clears parent listener and sec-mod fds before exec-equivalent setup

**Requirement:** Immediately after `fork()` for a new worker, the child
MUST: reset signal mask to `sig_default_set`; close the unused end of the
command socketpair (`cmd_fd[0]`); call `clear_lists(s)` to release the
parent's listener/proc lists; close `s->top_fd` if open; and close every
`sec_mod_instances[i].sec_mod_fd` / `sec_mod_fd_sync` — so the worker
inherits no listening sockets and no direct sec-mod control channel.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main.c:1197-1211
**Acceptance:** [SEC] negative, local — after a worker is spawned, inspect
its open file descriptors (`/proc/<pid>/fd`); confirm no listener socket fds
and no `sec_mod_fd`/`sec_mod_fd_sync` fds are present, only `cmd_fd[1]` and
the accepted client connection.
**Links:** REQ-IPC-040, REQ-SEC-001

### REQ-MAIN-INIT-002 — sec_auth_init_hmac is computed by main and the HMAC key is zeroized in the child

**Requirement:** The worker child MUST receive `ws->sec_auth_init_hmac`
computed by main from `s->hmac_key` plus the worker's
`remote_ip_str`/`our_ip_str`/`session_start_time` (REQ-IPC-040), and main
MUST `safe_memset()` its copy of `s->hmac_key` to zero in the child
immediately after computing this HMAC, so the worker process never holds
the key used to validate `SEC_AUTH_INIT` HMACs.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main.c:1254-1269
**Acceptance:** [SEC] negative, local — after worker spawn, confirm
`ws->sec_auth_init_hmac` is set (`HMAC_DIGEST_SIZE` bytes, non-zero) but
`s->hmac_key` is all-zero in the worker's memory image (e.g. via core dump
inspection in a test harness, or a debug build assertion). A worker that
recovered `hmac_key` could forge `SEC_AUTH_INIT` HMACs for sec-mod
(REQ-IPC-010).
**Links:** REQ-IPC-010, REQ-IPC-040, REQ-MAIN-SEC-001

### REQ-MAIN-INIT-003 — sec-mod instance for a session is selected by client IP hash, fixed at fork time

**Requirement:** The worker's `sec_mod_instance_index` (and thus which
sec-mod instance will own its `client_entry_st`/SID) MUST be computed once,
at fork time, as `hash(remote_addr) % sec_mod_instance_count`, and copied
into `ws->secmod_addr`/`secmod_addr_len`. This selection MUST NOT change for
the lifetime of the worker, because "each cookie is valid for its IP address
and when resuming it must reach the same sec-mod process that contains the
corresponding session information under the SID."
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main.c:1217-1234 (comment explains rationale)
**Acceptance:** unit, local — for `sec_mod_instance_count > 1`, confirm two
connections from the same client IP always select the same
`sec_mod_instance_index`, and that a resumed cookie (REQ-IPC-021) is routed
to the same instance that issued it (`AUTH_COOKIE_REQ` ->
`secmod_addr`/`secmod_addr_len` from `worker_startup_msg`, not
recomputed).
**Links:** REQ-IPC-017, REQ-IPC-021

### REQ-MAIN-INIT-004 — Connection limit and TCP-wrapper/ban checks precede fork

**Requirement:** main MUST reject a new connection — closing the accepted
fd without forking a worker — if (a) `max_clients > 0` and
`s->stats.active_clients >= max_clients`, (b) `check_tcp_wrapper(fd) < 0`
(`/etc/hosts.{allow,deny}`), or (c) for non-Unix, non-proxy-protocol
listeners, `check_if_banned()` is true for `ws->remote_addr`. These checks
MUST run before `socketpair()`/`fork()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main.c:1157-1186
**Acceptance:** negative, local — (a) set `max-clients` to current active
count and attempt a new connection, confirm it is closed and no worker
process appears; (b) configure `hosts.deny` to block the test client IP,
confirm rejection; (c) drive `check_if_banned` true (REQ-MAIN-SEC-002),
confirm rejection. In each case confirm no new PID is added to
`s->proc_list`.
**Links:** REQ-MAIN-SEC-002, REQ-MAIN-SEC-003

### REQ-MAIN-INIT-005 — Proxy-protocol listeners skip the connect-time ban check

**Requirement:** When `listen_proxy_proto` is enabled, main MUST NOT call
`check_if_banned()` using the immediate peer address at accept time (that
address is the load balancer's, not the client's) — ban enforcement for
proxy-protocol connections happens later once the real client address is
known from the PROXY protocol header.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/main.c:1173-1186 (`if (ws->conn_type != SOCK_TYPE_UNIX &&
!GETRCONFIG(s)->listen_proxy_proto)`)
**Acceptance:** [SEC] Confirmed — the post-PROXY-header ban check exists at
src/main-worker-cmd.c:387-405, in the `CMD_SESSION_INFO` handler. Sequencing:
the worker calls `parse_proxy_proto_header()` (src/worker-vpn.c:895) to
populate `ws->remote_addr` with the real client address *before* the TLS
handshake, then calls `session_info_send()` (src/worker-vpn.c:968, right
after the handshake completes) which, when `listen_proxy_proto` is set,
includes `remote_addr`/`our_addr` in `SessionInfoMsg` (src/worker-vpn.c:1146-1153).
Main's `CMD_SESSION_INFO` handler, when `GETRCONFIG(s)->listen_proxy_proto`
and `tmsg->has_remote_addr`, updates `proc->remote_addr` via
`proc_table_update_ip()` and calls `check_if_banned(s, &proc->remote_addr,
proc->remote_addr_len)` (main-worker-cmd.c:391-400) — which itself adds
`ban_points_connect` per REQ-MAIN-SEC-005 — and if the result is non-zero,
calls `kill_proc(proc)` (`SIGTERM`, main.h:189-193) to tear down the worker.
Ban enforcement is therefore **deferred, not bypassed**, for proxy-protocol
connections: a banned client's connection is terminated after the TLS
handshake rather than at accept time. Positive test: configure
`listen-proxy-proto`, ban an IP, send a PROXY-protocol-prefixed connection
from that IP; confirm the worker completes the TLS handshake but is then
`SIGTERM`'d (no CONNECT response). `[NOTE: unlike the non-proxy path (banned
before accept-time work begins), a banned client behind a proxy still
consumes one TLS handshake's worth of work before being killed — a minor
resource-amplification difference, not a bypass. Not flagged as
`[SEC-RISK]`; informational only.]`
**Links:** REQ-MAIN-SEC-002, REQ-MAIN-SEC-005, doc/design.md#load-balancer-integration

---

## NET — IP lease allocation

### REQ-MAIN-NET-001 — Leased IPs must not collide with existing leases, the TUN address, network, or broadcast address

**Requirement:** `get_ipv4_lease()` MUST reject a candidate address if (a)
an identical `/32` lease already exists (`ip_lease_exists`), (b) the
candidate equals the network address, or (c) the candidate equals the
computed broadcast address (`network | ~mask`). `get_ipv6_lease()` MUST
additionally reject a candidate `/prefix` subnet if it equals the TUN
device's own subnet (`ip_cmp(subnet, tun) == 0`) or if that subnet is
already leased.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/ip-lease.c:150-184 (`is_ipv6_ok`, `is_ipv4_ok`)
**Acceptance:** unit, local — exhaust the configured IPv4 pool to 2 free
addresses: the network and broadcast addresses of the subnet; confirm
`get_ipv4_lease` does not return either and instead fails with no lease
available after `MAX_IP_TRIES`. For IPv6, configure a lease subnet equal to
the TUN device's subnet and confirm `get_ipv6_lease` rejects it.
**Links:** —

### REQ-MAIN-NET-002 — IP lease allocation gives up after MAX_IP_TRIES random attempts

**Requirement:** `get_ipv4_lease()`/`get_ipv6_lease()` MUST attempt at most
`MAX_IP_TRIES` (16) randomly-generated candidate addresses before reporting
allocation failure; it MUST NOT loop indefinitely searching for a free
address in an exhausted pool.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/ip-lease.c:186-193 (`#define MAX_IP_TRIES 16`,
`max_loops = MAX_IP_TRIES`)
**Acceptance:** unit, local — configure an address pool with 0 free
addresses; confirm `get_ipv4_lease` returns an error within `MAX_IP_TRIES`
iterations (bounded time), not a hang. With `predictable-ips` enabled,
`proc->ipv4_seed` is set once at session creation to
`hash_any(username, ...)` (src/sec-mod-auth.c:571-573) and consumed only on
the *first* loop iteration (`max_loops == MAX_IP_TRIES`,
src/ip-lease.c:300-301). If that single deterministic candidate is rejected
by `is_ipv4_ok()` (already leased, or equal to the network/broadcast
address), the function does **not** retry other deterministic addresses
derived from the seed — it falls through to the same candidates used in the
non-predictable case: up to 5 further attempts via `gnutls_rnd()`
(src/ip-lease.c:303-313, true random) followed by up to 10 attempts via
`ip_from_seed()` chained off the last random value (src/ip-lease.c:314-319),
all under the same `max_loops`/`MAX_IP_TRIES` counter. Fallback behavior: a
colliding predictable seed silently degrades to random IP assignment for
that session, matching the "IP stays the same for the same user when
possible" wording in `doc/sample.config` (predictable-ips); after all 16
attempts fail, `ERR_NO_IP` is returned regardless of `predictable_ips`.
Positive test: with `predictable-ips = true` and the hashed candidate for a
test username already leased to another session, confirm the new session
receives a different (non-deterministic) IP within `MAX_IP_TRIES`
iterations rather than hanging or erroring.
**Links:** REQ-SECMOD-SESSION (predictable_ips / ipv4_seed, see
src/sec-mod-auth.c:570-579)

### REQ-MAIN-NET-003 — Reconnecting client (steal) transfers IP leases without re-fetching from the pool

**Requirement:** `steal_ip_leases(proc, thief)` (used when a client
reconnects and supersedes an existing session for the same SID/user) MUST
`talloc_move` the existing `ipv4`/`ipv6` lease structures from `proc` to
`thief`, MUST call `reset_tun(proc)` on the old process's TUN device (since
its fd is only valid in the old worker), and MUST leave `proc` with its own
*copy* of the lease addressing info (for disconnect scripts/accounting) —
not a shared pointer — by allocating a fresh `ip_lease_st` and `memcpy`-ing
`rip`/`lip`/`sig` fields.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/ip-lease.c:105-148
**Acceptance:** unit, local — simulate a reconnect (second `AUTH_COOKIE_REQ`
for a SID with an existing `proc_st`); confirm the new worker's `proc_st`
gets the same IPv4/IPv6 addresses as the old one, the old worker's TUN
device is reset, and disconnect accounting for the *old* session still
reports the correct (copied) IP — i.e., freeing `thief->ipv4` does not
corrupt `proc->ipv4`.
**Links:** —

---

## SEC — ban list

### REQ-MAIN-SEC-001 — hmac_key is generated once at startup, never traverses worker IPC, and is zeroed in worker children

**Requirement:** `s->hmac_key` MUST be generated exactly once, at main
startup, via `hmac_init_key()` (src/common/hmac.c:34-37 —
`gnutls_rnd(GNUTLS_RND_RANDOM, ...)`), called from src/main.c:1520 — before
`run_sec_mod()` forks any sec-mod instance (src/main.c:1658) and long before
any worker is forked per connection (src/main.c:1197). `s->hmac_key` MUST
NOT appear in any `*.proto` message exchanged over a worker's
`cmd_fd`/`cmd_fd_sync` sockets (confirmed by `internal/ipc.md` REQ-IPC-041:
no key material in `worker_startup_msg` or any other IPC message). The only
processes that ever hold a copy of `hmac_key` are main itself and each
sec-mod instance — sec-mod receives it as a direct function argument across
`fork()` (src/main-sec-mod-cmd.c:908-909 -> `sec_mod_server()` ->
`memcpy` into `sec->hmac_key` at src/sec-mod.c:1029), which it needs to
validate `SEC_AUTH_INIT` HMACs via `generate_hmac()`
(src/sec-mod-auth.c:906). For each worker, immediately after main computes
that worker's `ws->sec_auth_init_hmac = HMAC(s->hmac_key, remote_ip_str ||
our_ip_str || session_start_time)` (src/main.c:1262-1266), main MUST
`safe_memset()` its own `s->hmac_key` to zero **in the worker child
process** (src/main.c:1268-1269), so the unprivileged worker never observes
the key itself — only the single derived per-session HMAC.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/common/hmac.c:34-37; src/main.c:1520, 1197-1269, 1658;
src/main-sec-mod-cmd.c:908-909; src/sec-mod.c:1029; src/sec-mod-auth.c:906;
REQ-IPC-041
**Acceptance:** [SEC] (a) unit, local — confirm `hmac_init_key()` is called
exactly once per main process lifetime, using `GNUTLS_RND_RANDOM`, before
`run_sec_mod()`; (b) static, local — grep-confirm no `*.proto` message field
carries `hmac_key` or raw key bytes (REQ-IPC-041); (c) negative, local —
after a worker is spawned, inspect its memory image (debug build / core
dump) and confirm `s->hmac_key` is all-zero while `ws->sec_auth_init_hmac`
is a non-zero `HMAC_DIGEST_SIZE`-byte digest (REQ-MAIN-INIT-002); (d) unit,
local — confirm each sec-mod instance's `sec->hmac_key` equals main's
original (pre-zeroing) `hmac_key`, since sec-mod uses it to validate
`SEC_AUTH_INIT` HMACs.
**Links:** REQ-MAIN-INIT-002, REQ-IPC-040, REQ-IPC-041

### REQ-MAIN-SEC-002 — Ban score is additive, saturating, and IP-prefix-aware for IPv6

**Requirement:** `add_ip_to_ban_list()` MUST: treat an IPv6 address as its
`/64` prefix (zero the low 8 bytes via `massage_ipv6_address`) for banning
purposes; add `score` to the existing entry's score using saturating
arithmetic (`(e->score + score) > e->score ? ... : e->score` — i.e. never
wrap around on overflow); and MUST NOT extend `e->expires` on repeated
violations once the entry is already banned (`e->score >= max_ban_score`),
"or the user will never be unbanned if he periodically polls the server."
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ban.c:118-224
**Acceptance:** unit, local — (a) two IPv6 addresses differing only in the
low 64 bits MUST share one ban entry; (b) drive `e->score` to
`UINT_MAX - 1` then add more points, confirm `e->score` does not wrap to a
small value; (c) once banned, send further violations and confirm
`e->expires` does not move further into the future.
**Links:** REQ-SECMOD-SEC-003

### REQ-MAIN-SEC-003 — Ban score reset rules: time-based reset only while not currently banned, or after a completed ban expires

**Requirement:** `add_ip_to_ban_list()` MUST reset `e->score = 0` and
`e->last_reset = now` if EITHER (a) the entry's previous ban has expired
(`now > e->expires`) while it was still marked banned (`IS_BANNED`), OR (b)
`ban_reset_time` has elapsed since `last_reset` AND the entry is currently
*not* banned. It MUST NOT reset the score for an entry that is currently
banned and not yet expired, even if `ban_reset_time` has elapsed — an active
ban cannot be prematurely lifted by the reset-time check.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ban.c:164-176 (comment: "to avoid prematurely lifting
an active ban")
**Acceptance:** unit, local — (1) accumulate score to reach `max_ban_score`
(now banned, `expires = now + ban_time`); (2) advance time past
`ban_reset_time` but before `expires`; send another violation; confirm
`e->score` is NOT reset (still >= `max_ban_score`, ban continues). (3)
advance time past `expires`; send another violation; confirm `e->score` IS
reset to 0 (+ the new violation's points).
**Links:** REQ-MAIN-SEC-002

### REQ-MAIN-SEC-004 — Local interface addresses are exempt from ban checks

**Requirement:** `check_if_banned()` MUST return 0 (not banned) without
consulting `s->ban_db` for any address that matches a local interface
address/netmask in `s->if_addresses` (`if_address_test_local`).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ban.c:287-306
**Acceptance:** unit, local — add a local interface's address to the ban
list directly (e.g. via repeated `add_str_ip_to_ban_list`); confirm
`check_if_banned()` for that address still returns 0. This prevents a
misconfiguration (or an attacker spoofing a server-local source address)
from causing the server to ban itself / a trusted load-balancer IP.
**Links:** REQ-MAIN-INIT-005

### REQ-MAIN-SEC-005 — check_if_banned itself contributes ban_points_connect

**Requirement:** Every call to `check_if_banned()` for a non-exempt,
non-malformed address MUST itself call `add_ip_to_ban_list(..., 
ban_points_connect)` — i.e., merely attempting a connection contributes
points toward a future ban, independent of whether this particular
connection is accepted or rejected.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ban.c:322-325
**Acceptance:** unit, local — make `ban_points_connect` repeated connection
attempts (each individually allowed); confirm the `(connect_count *
ban_points_connect) >= max_ban_score` threshold results in the next
connection being rejected by `check_if_banned`, even though each prior
connection was itself accepted.
**Links:** REQ-MAIN-SEC-002, REQ-IPC-080

### REQ-MAIN-SEC-006 — Unban clears score and expiry but does not delete the entry

**Requirement:** `remove_ip_from_ban_list()` MUST set `e->score = 0` and
`e->expires = 0` for a matching entry (after applying the same `/64`
IPv6-prefix massaging as REQ-MAIN-SEC-002), and return non-zero, but MUST
NOT remove the entry from `s->ban_db` — the entry remains for
`last_reset`/future scoring bookkeeping. Returns 0 if no entry matches or
`size` is not 4 or 16.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ban.c:253-285
**Acceptance:** unit, local — `occtl unban <ip>` on a banned IP; confirm
`check_if_banned` now returns 0 for that IP, but the entry still exists in
`s->ban_db` (e.g. confirmed via a subsequent `occtl show ban points` if
such exists, or by re-violating and confirming `last_reset` carries over
rather than being treated as a brand-new entry).
**Links:** REQ-MAIN-SEC-002, REQ-MAIN-SEC-003

### REQ-MAIN-SEC-007 — cleanup_banned_entries removes only fully-expired-and-stale entries

**Requirement:** `cleanup_banned_entries()` MUST delete a ban entry only if
BOTH `now >= e->expires` AND `now > e->last_reset + ban_reset_time` — an
entry whose ban has expired but whose reset window has not yet elapsed MUST
be retained (so its score history is not lost prematurely).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ban.c:344-363
**Acceptance:** unit, local — create an entry with `expires` in the past but
`last_reset + ban_reset_time` in the future; run
`cleanup_banned_entries()`; confirm the entry is retained. Advance time past
`last_reset + ban_reset_time`; confirm it is now removed.
**Links:** REQ-MAIN-SEC-003

---

## TEARDOWN

### REQ-MAIN-TEARDOWN-001 — Workers exceeding auth_timeout without completing authentication are killed

**Requirement:** `kill_children_auth_timeout()` MUST terminate
(`remove_proc(..., RPROC_KILL)`) any `proc_st` with `status <
PS_AUTH_COMPLETED` whose `conn_time` is older than `now - auth_timeout`,
during periodic maintenance.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main.c:982-998
**Acceptance:** negative, local — start a connection, stall before
completing `SEC_AUTH_CONT`/`AUTH_COOKIE_REQ` past `auth-timeout`; confirm
the worker process is killed by the next maintenance tick. Cross-reference
REQ-IPC-011 (sec-mod's independent `auth_timeout` replay-window check —
both checks use the same configuration value but enforce it in different
processes).
**Links:** REQ-IPC-011

### REQ-MAIN-TEARDOWN-002 — SIGTERM with server-drain-ms stops listeners before terminating sessions

**Requirement:** On `SIGTERM`, if `server_drain_ms > 0`, main MUST first
stop and close all listening sockets (no new connections accepted) and
start a `server_drain_ms` timer, deferring `terminate_server()` (which kills
existing worker sessions) until that timer fires. If `server_drain_ms == 0`,
`terminate_server()` MUST run immediately on `SIGTERM`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main.c:1037-1068
**Acceptance:** unit, local — with `server-drain-ms > 0`, send `SIGTERM`;
confirm new connection attempts fail (listener closed) while existing
sessions continue for up to `server_drain_ms`, then are terminated. With
`server-drain-ms = 0`, confirm immediate termination. Cross-reference
`doc/sample.config` `server-drain-ms`.
**Links:** REQ-MAIN-TEARDOWN-003

### REQ-MAIN-TEARDOWN-003 — terminate_server force-kills remaining workers after a 5s grace period

**Requirement:** `terminate_server()` MUST send termination signals to all
children via `kill_children()`, then wait up to 5000ms (polling
`waitpid(-1, NULL, WNOHANG)`) for them to exit; if children remain after
5000ms, it MUST `kill(0, SIGKILL)` (signal the entire process group) rather
than waiting indefinitely.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main.c:1000-1028
**Acceptance:** unit, local — spawn a worker that ignores `SIGTERM`
(test-only signal handler); trigger server termination; confirm the worker
is force-killed via `SIGKILL` within ~5 seconds and `ev_break` is reached
(main exits).
**Links:** REQ-MAIN-TEARDOWN-002

---

## CFG — reload

### REQ-MAIN-CFG-001 — SIGHUP reloads sec-mod before main's own config

**Requirement:** On `SIGHUP`, main MUST, for each sec-mod instance: send
`SIGHUP` to the sec-mod process AND send `CMD_SECM_RELOAD` (via
`secmod_reload()`) — and only after all sec-mod instances have been signaled
does main call `reload_cfg_file()` for its own configuration. If
`secmod_reload()` fails for any instance, main MUST trigger a full
`SIGTERM` (`ev_feed_signal_event(loop, SIGTERM)`) rather than continuing
with an inconsistent reload.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main.c:1070-1091 (comment: "Reload on main needs to happen
later than sec-mod. That's because of a test that the certificate matches
the used key.")
**Acceptance:** unit, local — trigger `SIGHUP` and confirm ordering via
log timestamps: sec-mod's `CMD_SECM_RELOAD_REPLY` (REQ-SECMOD, see
src/sec-mod.c:491-501) is observed before main's `reload_cfg_file` log
entry. Negative: make `secmod_reload()` fail (e.g. stop one sec-mod
instance before SIGHUP); confirm main initiates full shutdown rather than a
partial reload.
**Links:** REQ-SECMOD-INIT-001

## Completeness notes

- **Listener setup** (`_listen_ports`, `listen_ports`,
  `set_udp_socket_options`, `set_common_socket_options`) is configuration
  plumbing with no MUST/MUST NOT contract beyond "bind what's configured in
  `doc/sample.config` (`listen-host`, `tcp-port`, `udp-port`, etc.)" —
  `[UNDOCUMENTED: candidate REQ-MAIN-INIT-* if specific socket-option
  requirements (e.g. SO_REUSEADDR, IPV6_V6ONLY) are found to matter for
  correctness rather than just performance.]`
- **UDP session forwarding** (`forward_udp_to_owner`,
  `CMD_UDP_FD`/`udp_fd_msg`): not covered here. `[UNDOCUMENTED: candidate
  REQ-MAIN-NET-* + REQ-IPC-* covering how main demultiplexes UDP packets to
  the owning worker by source address, and what happens on a DTLS
  client-hello from an address with no matching worker.]`
- **occtl control socket** (`main-ctl-unix.c`): only the termination flow is
  covered (`internal/ipc.md` REQ-IPC-070..072). Other `occtl` commands
  (`show status`, `show ip bans`, `reload`, `show iroutes`) are
  reporting/administrative with no further requirements in this pass.
- **chroot** (`src/main.c:1675-1691`): sec-mod's chdir-to-chroot behavior is
  noted but not analyzed for completeness — `[UNDOCUMENTED: candidate
  REQ-MAIN-SEC-* covering what happens if chroot_dir is misconfigured
  (relative vs absolute socket paths).]`
