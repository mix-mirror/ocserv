---
title: occtl control tool requirements
generator: requirements-from-implementation
process: occtl
id-prefix: REQ-OCCTL
sources:
  - src/occtl/occtl.c
  - src/occtl/occtl.h
  - src/occtl/ctl.h
  - src/occtl/unix.c
  - src/occtl/print.c
  - src/occtl/json.c
  - src/occtl/pager.c
  - src/occtl/cache.c
  - src/occtl/session-cache.c
  - src/occtl/ip-cache.c
  - src/occtl/nl.c
  - src/occtl/geoip.c
  - src/occtl/maxmind.c
  - src/main-ctl-unix.c
  - src/ctl.proto
  - src/common/system.c (check_upeer_id)
  - src/common/common.c (send_msg, recv_msg_headers, recv_msg_data)
  - doc/occtl.8.md
  - doc/sample.config (use-occtl, occtl-socket-file)
  - doc/design.md#ipc-communication-for-session-termination
  - doc/requirements/internal/ipc.md
---

# occtl Requirements

`occtl` is the administrator's control tool. It is a separate client
process that talks to **main** over a Unix stream socket
(`occtl-socket-file`, default `/var/run/occtl.socket`) using the
`CTL_CMD_*` command codes (`src/occtl/ctl.h`) and the messages in
`src/ctl.proto`. main answers read-only queries from its own state and
relays session-invalidation requests to sec-mod (`SECM_LIST_COOKIES`,
`SECM_TERMINATE_USER_SESSIONS`, `SECM_TERMINATE_SESSION`); occtl never talks
to sec-mod or to a worker directly.

This document covers both ends of that socket: the occtl client
(command-line parsing, command dispatch, output formats, exit status) and the
main-side handler (`src/main-ctl-unix.c`: socket setup, peer authorization,
request dispatch, replies). The termination message contract between main
and sec-mod is in `internal/ipc.md` (REQ-IPC-070..072) and the sec-mod side of
it in `internal/sec-mod.md` (REQ-SECMOD-SESSION-004..006); this document
links to those entries instead of restating them.

`CLI` is used in this document, in addition to the
`requirements-from-implementation.md` category tags, for the
administrator-facing command-line and output contract (option syntax,
command names, text/JSON output, exit status) that has no equivalent in the
daemon processes.

## Phase 1 — Surface enumeration (completeness checklist)

| occtl command | Handler (`src/occtl/unix.c`) | Request → reply | main handler (`src/main-ctl-unix.c`) | Covered by |
|---|---|---|---|---|
| `show status` | `handle_status_cmd` | `CTL_CMD_STATUS` (empty) → `status_rep` | `method_status` | CLI-005, ERR-003 |
| `show users` | `handle_list_users_cmd` | `CTL_CMD_LIST` → `user_list_rep` | `method_list_users` | CLI-006 |
| `show user NAME` | `handle_show_user_cmd` | `CTL_CMD_USER_INFO` `username_req` → `user_list_rep` | `method_user_info` | CLI-007, ERR-002 |
| `show id ID` | `handle_show_id_cmd` | `CTL_CMD_ID_INFO` `id_req` → `user_list_rep` | `method_id_info` | CLI-007, CLI-004, ERR-002 |
| `show iroutes` | `handle_list_iroutes_cmd` | `CTL_CMD_LIST` → `user_list_rep` | `method_list_users` | CLI-006 |
| `show events` | `handle_events_cmd` | `CTL_CMD_TOP` → `user_list_rep`, then `top_update_rep` stream | `method_top`, `ctl_handler_notify` | SESSION-008, IPC-004, ERR-004 |
| `show sessions all\|valid` (aliases `show cookies all\|valid`) | `handle_list_{all,valid}_sessions_cmd` | `CTL_CMD_LIST_COOKIES` → `secm_list_cookies_reply_msg` | `method_list_cookies` | SESSION-006, SESSION-007 |
| `show session SID` | `handle_show_session_cmd` | `CTL_CMD_LIST_COOKIES` → `secm_list_cookies_reply_msg` | `method_list_cookies` | SESSION-007 |
| `disconnect user NAME` | `handle_disconnect_user_cmd` | `CTL_CMD_DISCONNECT_NAME` `username_req` → `bool_msg` | `method_disconnect_user_name` | SESSION-001 |
| `disconnect id ID` | `handle_disconnect_id_cmd` | `CTL_CMD_DISCONNECT_ID` `id_req` → `bool_msg` | `method_disconnect_user_id` | SESSION-002 |
| `terminate user NAME` | `handle_terminate_user_cmd` | `CTL_CMD_TERMINATE_USER` `username_req` → `bool_msg` | `method_terminate_user` | SESSION-003 |
| `terminate id ID` | `handle_terminate_id_cmd` | `CTL_CMD_TERMINATE_ID` `id_req` → `bool_msg` | `method_terminate_id` | SESSION-004 |
| `terminate session SID` | `handle_terminate_session_cmd` | `CTL_CMD_LIST_COOKIES`, then `CTL_CMD_TERMINATE_SESSION` `safe_id_req` → `bool_msg` | `method_list_cookies`, `method_terminate_session` | SESSION-005 |
| `unban ip IP` | `handle_unban_ip_cmd` | `CTL_CMD_UNBAN_IP` `unban_req` → `bool_msg` | `method_unban_ip` | NET-001 |
| `show ip bans` / `show ip ban points` | `handle_list_banned_{ips,points}_cmd` | `CTL_CMD_LIST_BANNED` → `ban_list_rep` | `method_list_banned` | NET-002 |
| `reload` | `handle_reload_cmd` | `CTL_CMD_RELOAD` → `bool_msg` | `method_reload` | CFG-003 |
| `stop now` | `handle_stop_cmd` | `CTL_CMD_STOP` → `bool_msg` | `method_stop` | CLI-008 |
| `help`/`?`, `exit`/`quit`, `reset` | `occtl.c` local handlers | none (no connection) | — | CLI-002 |

Command-line options (`src/occtl/occtl.c` `main()`): `-s/--socket-file`,
`-j/--json`, `-n/--no-pager`, `--debug`, `-v/--version`, `-h/--help`
(CLI-001). Environment: `OCCTL_PAGER`, `PAGER`, `LESS` (CFG-002). Build
options: `-Dpager` (default pager), `-Dlibnl` (interface statistics),
maxmind/GeoIP (location lookup); occtl is not built without readline/libedit
(`src/occtl/meson.build`).

Error space: occtl reports failures as text on stdout/stderr and through its
exit status (ERR-001); main reports nothing to occtl on a malformed request —
it logs and closes the connection (IPC-003).

---

## SEC

### REQ-OCCTL-SEC-001 — main MUST NOT execute a ctl command for a non-root peer

**Requirement:** main MUST NOT dispatch any `CTL_CMD_*` request received on
an occtl connection whose peer credentials (`SO_PEERCRED` on Linux,
`getpeereid()` on BSD) are not uid 0; such a connection MUST be closed
immediately after `accept()` with `ctl: unauthorized connection` logged, so
that the right to disconnect users, invalidate cookies, unban addresses,
reload or stop the server is restricted to root regardless of the socket
file's permissions.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `ctl_handle_commands()` (`check_upeer_id("ctl",
..., cfd, 0, 0, ...)`); src/common/system.c `check_upeer_id()` (`cr.uid !=
0 && (cr.uid != uid || cr.gid != gid)` with `uid = gid = 0`)
**Acceptance:** [SEC] negative, CI (root/full stack) — start the server,
then run `occtl -s <socket> show status` as a non-root user with filesystem
access to the socket (e.g. `setpriv --reuid=nobody`); confirm occtl reports
`Status: offline` / exit 1 and main logs `ctl: unauthorized connection`.
Positive: the same command as root succeeds (`tests/test-occtl-commands`
Section 1). Note: `uid_wrapper` does not cover occtl as a separate process
(see REQ-SECMOD-SESSION-007 acceptance), so this needs a real non-root peer.
**Links:** REQ-GEN-SEC-002, REQ-OCCTL-INIT-003

### REQ-OCCTL-SEC-002 — occtl MUST NOT receive or display a raw SID

**Requirement:** Every session identifier main returns to occtl
(`user_info_rep.safe_id`, `cookie_int_msg.safe_id` inside
`secm_list_cookies_reply_msg`) MUST be the `safe_id`
(`calc_safe_id()` = base64(SHA1(SID))), never the SID itself, and occtl
MUST accept only a `safe_id` (or a prefix of one) as the argument of `show
session` / `terminate session`, so that holding occtl output never grants
the ability to resume a VPN session.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `append_user_info()`
(`calc_safe_id(ctmp->sid, ...)`); src/sec-mod-cookies.c
`handle_secm_list_cookies_reply()` (`t->acct_info.safe_id`);
src/ctl.proto `user_info_rep.safe_id` ("a value derived from the cookie");
src/ipc.proto `cookie_int_msg` (no `sid` field); README glossary "SID vs.
safe_id"
**Acceptance:** [SEC] negative, CI — connect a client, capture its cookie;
run `occtl --json show users` and `occtl --json show sessions all`; confirm
no `Full session`/`Session` value equals, or is a substring of, the
base64/hex encoding of the SID carried in the cookie, and that each
`Full session` value is 27 characters (`SAFE_ID_SIZE - 1`).
**Links:** REQ-SECMOD-SEC-002, REQ-IPC-070

### REQ-OCCTL-SEC-003 — occtl MUST NOT talk to sec-mod or workers directly

**Requirement:** occtl MUST connect only to main's occtl socket; every
operation that needs sec-mod state (session listing, cookie invalidation)
MUST be mediated by main over the `sec_mod_fd_sync` channel, so that the
occtl socket is the single administrative entry point and sec-mod keeps no
externally reachable control interface.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/occtl/unix.c `connect_to_ocserv()` (the only `connect()` in
occtl); src/main-ctl-unix.c `method_list_cookies()`,
`terminate_user_sessions_in_secmod()`, `terminate_session_in_secmod()`
(all over `sec_mod_fd_sync`)
**Acceptance:** [SEC] negative, local — code inspection: `grep -n connect
src/occtl/*.c` shows only `connect_to_ocserv`; at runtime `strace -f -e
trace=connect occtl show sessions all` shows a single `connect()` to the
occtl socket path.
**Links:** REQ-GEN-SEC-002, REQ-OCCTL-SEC-001

### REQ-OCCTL-SEC-004 — Worker processes MUST NOT inherit occtl socket descriptors

**Requirement:** A worker started by main (`fork()` + `execv()` of
`ocserv-worker`) MUST NOT hold the listening occtl socket (`s->ctl_fd`) or
any accepted occtl connection, so that a compromised worker can neither
accept an administrator's occtl connection nor write forged replies to one.
main MUST mark `ctl_fd` close-on-exec when creating it, in addition to
closing it in `clear_lists()`, so the guarantee does not depend on the
`use-occtl` value at fork time.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** src/main.c `listen_watcher_cb()` (`execv(worker_path, ...)`);
src/main-ctl-unix.c `ctl_handle_commands()` (accepted connections,
including `top_fd`, are `set_cloexec_flag`ed and so close at exec);
src/main-ctl-unix.c `ctl_handler_init()` (`ctl_fd` is marked
close-on-exec); src/main.c `clear_lists()` (calls
`ctl_handler_deinit()`); maintainer decision recorded with this
requirement.
**Acceptance:** [SEC] negative, CI — `tests/test-occtl-fd-inherit`: with a
worker running, no socket in `/proc/<worker-pid>/fd` is also open in main
(`/proc/<main-pid>/fd`); main closes its copy of every socket it hands to a
worker, so this covers the occtl listening socket without naming it. Checked
both at startup and after a reload that sets `use-occtl = false`.
**Links:** REQ-MAIN-INIT-001, REQ-GEN-SEC-002, REQ-OCCTL-CFG-004

---

## INIT

### REQ-OCCTL-INIT-001 — main creates the occtl socket only when enabled, replacing a stale file

**Requirement:** At startup, when `use-occtl` is true and
`occtl-socket-file` is set, main MUST remove any existing file at that
path, create a `SOCK_STREAM` Unix socket there, `chown` it to
`run-as-user`/`run-as-group`, and `listen()` on it; failure to create, bind
or listen MUST fail `ctl_handler_init()` (return -1). When `use-occtl` is
false, main MUST NOT create the socket and MUST log `not using control unix
socket`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `ctl_handler_init()`; src/main.c `main()`
(single call at startup); src/config.c `apply_default_conf()` (default
`OCCTL_UNIX_SOCKET`), `cfg_ini_handler()` (`occtl-socket-file`,
`use-occtl`)
**Acceptance:** positive, CI — every occtl test starts the server with
`occtl-socket-file = ./occtl-*.socket` and drives it (`tests/test-occtl`,
`tests/test-occtl-commands`). Negative, CI — start with `use-occtl =
false`; confirm the socket path does not exist and `occtl -s <path> show
status` prints `Status: offline` and exits 1.
**Links:** REQ-OCCTL-CFG-004

### REQ-OCCTL-INIT-002 — main removes the occtl socket file on exit

**Requirement:** On orderly shutdown main MUST `remove()` the
`occtl-socket-file` path, so that a later occtl invocation fails to connect
rather than connecting to a stale path.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main.c `main()` (shutdown path,
`remove(GETSCONFIG(s)->occtl_socket_file)`)
**Acceptance:** positive, CI — run `occtl stop now`, wait for the server to
exit, confirm the socket file no longer exists.
**Links:** REQ-OCCTL-CLI-008

### REQ-OCCTL-INIT-003 — occtl connects to the configured socket, defaulting to the build-time path

**Requirement:** occtl MUST connect to the socket given with `-s/--socket-file`
and, if none is given, to `OCCTL_UNIX_SOCKET` (`/var/run/occtl.socket`) —
the same constant main uses as the `occtl-socket-file` default — so that
the default client and default server agree without configuration.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/ctl.h `OCCTL_UNIX_SOCKET`; src/occtl/unix.c
`connect_to_ocserv()`; src/config.c `apply_default_conf()`; doc/occtl.8.md
(OPTIONS `-s`)
**Acceptance:** positive, CI — `occtl -s <socket> show status` succeeds
(`tests/test-occtl-commands`). Negative, local — `occtl -s /nonexistent show
status` prints `error connecting to ocserv socket '/nonexistent': ...` on
stderr and exits 1.
**Links:** REQ-OCCTL-ERR-001

### REQ-OCCTL-INIT-004 — occtl uses the C locale for comparisons and ignores SIGPIPE

**Requirement:** occtl MUST set `LC_CTYPE` and `LC_COLLATE` to `"C"` before
parsing commands, so that case-insensitive command matching and name/ID
completion do not depend on the administrator's locale, and MUST ignore
`SIGPIPE`, so that a server closing the connection, or a pager exiting
early, produces an error return instead of killing occtl.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/occtl.c `main()` (`setlocale()`, `ocsignal(SIGPIPE,
SIG_IGN)`)
**Acceptance:** unit, local — run `LC_ALL=tr_TR.UTF-8 occtl -s /nonexistent
SHOW STATUS` and confirm it is recognised as `show status` (offline output,
exit 1) rather than `unknown command`.
**Links:** REQ-OCCTL-CLI-002

---

## CFG

### REQ-OCCTL-CFG-001 — JSON string escaping preserves UTF-8 values

**Status:** WITHDRAWN — merged into REQ-OCCTL-CLI-009 (JSON output is
valid JSON). The ID is kept reserved, not reused, for citation stability.

### REQ-OCCTL-CFG-002 — Pager selection and bypass

**Requirement:** For list/detail output occtl MUST pipe through a pager
chosen from `$OCCTL_PAGER`, else `$PAGER`, else the build-time `-Dpager`
value (default `less`), setting `LESS=FRSX` only if `LESS` is unset; it
MUST write directly to stdout instead when `-n/--no-pager` is given, when
stdout is not a terminal, or when the selected pager is empty; if the pager
cannot be started it MUST print `unable to start pager; check your $PAGER
environment variable` and fall back to stdout.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/pager.c `get_pager()`, `pager_start()`,
`pager_stop()`; meson_options.txt (`pager`); meson.build (`OCCTL_PAGER`);
doc/occtl.8.md (`-n`)
**Acceptance:** positive, local — `OCCTL_PAGER=cat occtl ... show users |
cat` writes directly (non-tty). Under a pty (`script -qc`), `OCCTL_PAGER=
'sh -c "echo PAGED; cat"'` shows `PAGED`; with `-n` it does not.
`[UNDOCUMENTED: OCCTL_PAGER, PAGER and the LESS default are not in
doc/occtl.8.md.]`
**Links:** —

### REQ-OCCTL-CFG-003 — reload schedules a SIGHUP-equivalent reload and reports scheduling only

**Requirement:** On `CTL_CMD_RELOAD` main MUST feed `SIGHUP` to its event
loop (the same path as an external `SIGHUP`) and reply `bool_msg.status =
true`; occtl MUST print `Server scheduled to reload` and exit 0 on a true
reply, and `Error scheduling reload` with exit 1 otherwise. The reply
confirms scheduling, not that the reload succeeded.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `method_reload()`; src/occtl/unix.c
`handle_reload_cmd()`; doc/occtl.8.md (`reload`)
**Acceptance:** positive, CI — `tests/test-occtl-commands` Section 2 (edit
`pre-login-banner`, `occtl reload`, confirm the new banner and not the old
one). Negative, CI — `occtl -s /nonexistent reload` prints `Error scheduling
reload`, exit 1.
**Links:** REQ-MAIN-CFG-001

### REQ-OCCTL-CFG-004 — use-occtl is fixed at startup

**Requirement:** `use-occtl` MUST be `[scope: global (non-reloadable)]`:
main MUST decide whether to serve the occtl socket once, at startup, and a
reload that changes `use-occtl` MUST NOT open, close, or stop serving the
socket, so that the socket's lifetime and main's use of it always agree.
**Strength:** MUST
**Status:** DERIVED
**Source:** doc/sample.config `use-occtl` (`[scope: global
(non-reloadable)]`); src/vpn.h `static_cfg_st.use_occtl`; src/config.c
`cfg_ini_handler()` (`use-occtl` and its `use-dbus` alias are parsed only
on the initial load); src/main.c `main()` (`ctl_handler_init()` only at
startup); src/main-ctl-unix.c `ctl_handler_deinit()`,
`ctl_handler_set_fds()`, `ctl_handler_run_pending()` (read
`GETSCONFIG(s)->use_occtl`); maintainer decision recorded with this
requirement.
**Acceptance:** CI — `tests/test-occtl-fd-inherit`: start with `use-occtl
= true`, change it to `false` and reload; `occtl show status` still
succeeds. Local — `tests/check-config-scope.py` accepts the
`(non-reloadable)` annotation and finds the field in `static_cfg_st`.
**Links:** REQ-OCCTL-INIT-001, REQ-OCCTL-SEC-004, REQ-CONFIG-CFG-002

---

## IPC

### REQ-OCCTL-IPC-001 — One request per connection; main closes after replying

**Requirement:** main MUST read exactly one request from an occtl
connection, send at most one reply, and then close the connection — except
for `CTL_CMD_TOP` (REQ-OCCTL-SESSION-008). occtl MUST therefore open a new
connection for every command that talks to the server (and a second one for
the second step of `terminate session`), and MUST NOT open a connection for
the local commands `help`, `?`, `exit`, `quit`, `reset`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `ctl_cmd_wacher_cb()` (`indefinite` flag,
`close(wst->fd)`); src/occtl/occtl.c `commands[]` (`need_preconn`
column), `check_cmd()`; src/occtl/unix.c `handle_terminate_session_cmd()`
("server closes the socket after each command")
**Acceptance:** positive, CI — in interactive mode run `show status` twice
in one session; both succeed. `tests/terminate-commands` (terminate session
needs two connections).
**Links:** REQ-OCCTL-SESSION-005, REQ-OCCTL-SESSION-008

### REQ-OCCTL-IPC-002 — Framing and reply type check

**Requirement:** Each message on the occtl socket MUST be framed as one
command byte (`CTL_CMD_*`), a 4-byte host-order length, and that many bytes
of packed protobuf (`send_msg`/`recv_msg_headers`). occtl MUST reject a
reply whose command byte is not the one `msg_map[]` pairs with the request
(e.g. `CTL_CMD_USER_INFO` → `CTL_CMD_LIST_REP`), printing `Unexpected
message 'N', expected 'M'` and failing the command.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/unix.c `msg_map[]`, `send_cmd()`; src/common/common.c
`recv_msg_headers()`
**Acceptance:** unit, local — a fake server on a Unix socket answers
`CTL_CMD_STATUS` with `CTL_CMD_LIST_REP`; confirm `occtl -s <fake> show
status` prints the `Unexpected message` line and exits 1.
**Links:** REQ-IPC-001, REQ-GEN-TECH-003

### REQ-OCCTL-IPC-003 — main drops malformed, oversized or unknown requests without a reply; occtl does not send oversized ones

**Requirement:** main MUST close an occtl connection without sending a
reply when the request body exceeds `CTL_MAX_REQUEST_SIZE` (256 bytes),
does not arrive within `MAIN_SEC_MOD_TIMEOUT`, fails to unpack as the
message its command expects, or carries an unknown command code (logged as
`unknown unix ctl message`); it MUST NOT act on a partially parsed request.
occtl MUST NOT send a request it can tell main will drop: it MUST reject
locally, with a message naming the over-long argument and exit 1, any
argument whose packed request would exceed `CTL_MAX_REQUEST_SIZE`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/ctl.h `CTL_MAX_REQUEST_SIZE`; src/main-ctl-unix.c
`ctl_cmd_wacher_cb()` (`buffer[CTL_MAX_REQUEST_SIZE]`, `recv_msg_data()`);
`method_user_info()`, `method_id_info()`, `method_unban_ip()`,
`method_disconnect_user_name()`, `method_disconnect_user_id()`,
`method_terminate_user()`, `method_terminate_id()`,
`method_terminate_session()` (unpack failure → `return` with no reply);
src/common/common.c `recv_msg_data()` (`l32 > data_size` →
`ERR_BAD_COMMAND`); src/occtl/unix.c `username_req_fits()` (used by
`handle_show_user_cmd()`, `handle_disconnect_user_cmd()`,
`handle_terminate_user_cmd()`, the only commands whose argument can exceed
the limit); maintainer decision recorded with this requirement.
**Acceptance:** negative, local — `tests/test-occtl-local`: `show user`,
`disconnect user` and `terminate user` with a 300-character name exit 1,
print that the user name is too long, and send no request to the fake
server. Negative, CI — a raw client sends a `CTL_CMD_USER_INFO` request
with a 300-byte body to a running server: main logs `received more data
than expected`, sends no reply, and disconnects no user.
**Links:** REQ-IPC-002, REQ-OCCTL-ERR-001

### REQ-OCCTL-IPC-004 — occtl reply timeout

**Requirement:** occtl MUST give up waiting for a reply after 10 seconds
of inactivity and fail the command, so that a hung server does not hang
scripts indefinitely. This applies to every request/reply exchange; the
`show events` update stream waits indefinitely for the next update but
MUST apply the same bound to reading the body of an update once its header
has arrived.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/occtl.h `DEFAULT_TIMEOUT` (10, in seconds);
src/occtl/unix.c `send_cmd()` (passes it as the timeout to
`recv_msg_headers()` / `force_read_timeout()`), `handle_events_cmd()`
(reads update headers and bodies with `force_read_timeout()`);
src/common/common.c `force_read_timeout()`, `recvmsg_timeout()` (the
parameter is in seconds: `poll(..., sec * 1000)`)
**Acceptance:** local — `tests/test-occtl-local`: against a fake server
(`tests/occtl-fake-server.py`, scenario `silent`) that accepts and never
replies, `occtl show status` exits non-zero after 8–20 seconds.
**Links:** REQ-OCCTL-IPC-002

---

## SESSION

### REQ-OCCTL-SESSION-001 — disconnect user ends every live connection of that user, cookie kept

**Requirement:** On `CTL_CMD_DISCONNECT_NAME` main MUST call
`disconnect_proc()` on every worker whose `username` equals
`username_req.username` (exact, case-sensitive) and reply `bool_msg.status
= true` if at least one matched, `false` otherwise. It MUST NOT ask sec-mod
to invalidate the session, so the client can reconnect with its cookie
within `cookie-timeout`. occtl MUST print `user 'NAME' was disconnected`
(exit 0) or `could not disconnect user 'NAME'` (exit 1).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `method_disconnect_user_name()`;
src/occtl/unix.c `handle_disconnect_user_cmd()`; doc/occtl.8.md
(`disconnect user`)
**Acceptance:** positive, CI — `tests/disconnect-user`,
`tests/disconnect-user2`. Negative, CI — `occtl disconnect user nosuchuser`
exits 1 with `could not disconnect`.
**Links:** REQ-OCCTL-SESSION-003

### REQ-OCCTL-SESSION-002 — disconnect id ends the one worker with that ID

**Requirement:** On `CTL_CMD_DISCONNECT_ID` main MUST disconnect the worker
whose pid equals `id_req.id`, stop at the first match, leave the cookie
valid, and reply `status = true` only if a worker matched. occtl MUST reject
an ID that `atoi()` parses as 0 (including non-numeric input) locally by
printing the command help and exiting 1, without contacting the server.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `method_disconnect_user_id()`;
src/occtl/unix.c `handle_disconnect_id_cmd()`; doc/occtl.8.md
(`disconnect id`)
**Acceptance:** positive, CI — `tests/test-occtl-commands` Section 4.
Negative, local — `occtl disconnect id abc` exits 1 and makes no
connection (`strace -e connect`).
`[UNDOCUMENTED: main also treats id_req.id == -1 as "all workers whose pid
is -1" (no break), which matches no real worker; no documented purpose.]`
**Links:** REQ-OCCTL-CLI-004

### REQ-OCCTL-SESSION-003 — terminate user invalidates all of the user's cookies in every sec-mod instance

**Requirement:** On `CTL_CMD_TERMINATE_USER` main MUST disconnect every
worker of that user (as REQ-OCCTL-SESSION-001) and MUST send
`SECM_TERMINATE_USER_SESSIONS` to **every** sec-mod instance, so that no
cookie of that user survives in any instance; it MUST reply `status = true`
if any worker was disconnected or any instance reported `result = true`.
occtl MUST print `user 'NAME' was terminated (session invalidated)` (exit 0)
or `could not terminate user 'NAME'` (exit 1).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `terminate_user_sessions_in_secmod()`,
`method_terminate_user()`; src/main.c `main()` (`sec_mod_instance_count`
defaults to `MIN(processor_count, ...)`, so >1 on multi-core hosts);
src/main.c `listen_watcher_cb()` (a new login's instance is `hash(client
IP) % sec_mod_instance_count`, REQ-MAIN-INIT-003); src/main-worker-cmd.c
`handle_worker_commands()` (`CMD_AUTH_COOKIE_REQ`: a resumed cookie is
routed to the instance encoded in its SID, REQ-SECMOD-SEC-001);
doc/occtl.8.md (`terminate user`: "permanently invalidate all of their
session cookies").
Each session (SID) is held by exactly one sec-mod instance and is never
copied or moved, even when the client roams. A user with several separate
logins from client IPs that hash differently has those sessions in
different instances, so invalidating all of the user's cookies requires
asking every instance.
**Acceptance:** [SEC] negative, CI — `tests/terminate-user-multi-secmod`:
with `sec-mod-scale = 16`, the same user logs in from two client addresses;
the test reads each session's instance from its cookie (the first two SID
bytes) and skips if both are in the same instance; otherwise, after
`occtl terminate user test`, **both** cookies MUST be rejected on
reconnect. Positive, CI — `tests/test-occtl-commands` Section 7,
`tests/terminate-commands`.
**Links:** REQ-IPC-071, REQ-IPC-072, REQ-SECMOD-SESSION-004,
REQ-MAIN-INIT-003

### REQ-OCCTL-SESSION-004 — terminate id disconnects and invalidates that connection's cookie

**Requirement:** On `CTL_CMD_TERMINATE_ID` main MUST disconnect the worker
whose pid equals `id_req.id` and send `SECM_TERMINATE_SESSION` with its
full-length `safe_id` (`SAFE_ID_SIZE - 1` bytes) to the sec-mod instances
until one reports `result = true`, whatever the connection's
authentication state: main MUST NOT infer from that state whether a
cookie exists (while a connect-script runs, the connection is not
`PS_AUTH_COMPLETED` but its session is open in sec-mod). main MUST reply
`status = true` only if the worker was disconnected **and** no valid
cookie remains for it — sec-mod invalidated it now, or every instance
answered that it holds no such session (e.g. `terminate session` already
invalidated it, or main never learned the connection's SID). If some
instance could not be asked and none invalidated the cookie, main MUST log
that the cookie could not be invalidated and reply `status = false`. If no worker matches, main
MUST NOT contact sec-mod and MUST reply `status = false`. occtl MUST print
`connection ID 'ID' was terminated (session invalidated)` and exit 0 only
on `status = true`, and otherwise print `could not terminate ID 'ID'` and
exit 1.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `terminate_session_in_secmod()` (1
invalidated, 0 not found anywhere, -1 not found with an instance
unreachable), `method_terminate_id()`; src/main-auth.c `handle_auth_cookie_req()` (main
learns `proc->sid` from the cookie request, and opens the session in
sec-mod); src/main-worker-cmd.c `handle_cookie_auth_res()` (status is
`PS_AUTH_FAILED` until the connect-script exits); src/main-proc.c
`new_proc()` (`proc->sid` starts all zeros); src/occtl/unix.c
`handle_terminate_id_cmd()`; maintainer decision recorded with this
requirement.
**Acceptance:** positive, CI — `tests/terminate-commands` section 2
(`terminate id` then `assert_cookie_rejected`) and section 5 (`terminate
session`, then `terminate id` of the same connection still exits 0) and
section 7 (`terminate id` while the connect-script runs exits 0, and the
cookie is then rejected). Negative, CI — `tests/terminate-commands` section 6 (`occtl terminate id
999999` exits non-zero). The unreachable-instance case has no automated
test: it needs a sec-mod instance that fails to answer.
**Links:** REQ-IPC-072, REQ-SECMOD-SESSION-005

### REQ-OCCTL-SESSION-005 — terminate session resolves a prefix to exactly one full safe_id

**Requirement:** For `terminate session ARG` occtl MUST (1) reject an `ARG`
longer than `SAFE_ID_SIZE - 1` locally (`invalid session ID`); (2) fetch the
session list (`CTL_CMD_LIST_COOKIES`) and select the entries whose
`safe_id` starts with `ARG`; (3) on zero matches print `no session matching
'ARG' was found` and exit 1; (4) on more than one match refuse, list the
matches, and exit 1 (REQ-IPC-070); (5) on exactly one match send
`CTL_CMD_TERMINATE_SESSION` on a new connection with the **full** matched
`safe_id`, never the prefix. When the matched session has `in_use` set,
occtl MUST warn on stderr that the active connection will not be dropped.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/unix.c `handle_terminate_session_cmd()`;
src/main-ctl-unix.c `method_terminate_session()`; doc/occtl.8.md
(`terminate session`)
**Acceptance:** positive, CI — `tests/terminate-commands` (short 6-char SID
and full SID both invalidate the cookie). Negative, local — `occtl terminate
session` with a 28-character argument exits 1 without connecting; a prefix
matching nothing exits 1 with `no session matching`. Ambiguous prefix:
REQ-IPC-070 acceptance.
**Links:** REQ-IPC-070, REQ-SECMOD-SESSION-005, REQ-OCCTL-IPC-001

### REQ-OCCTL-SESSION-006 — Session list aggregates every sec-mod instance

**Requirement:** On `CTL_CMD_LIST_COOKIES` main MUST query every sec-mod
instance with `SECM_LIST_COOKIES` and reply with the concatenation of their
`cookie_int_msg` entries; an instance that fails to answer MUST be logged
and skipped, not fail the whole reply. The list is best-effort: a partial
list is acceptable, because `terminate session` sends a full-length
`safe_id` and sec-mod accepts only that (REQ-SECMOD-SESSION-005), so a
missed entry cannot cause a different session to be terminated.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `method_list_cookies()`; maintainer decision
recorded with this requirement.
**Acceptance:** positive, CI — with ≥ 2 sec-mod instances, sessions from
clients routed to different instances all appear in `occtl show sessions
all`.
**Links:** REQ-SECMOD-SESSION-006, REQ-OCCTL-SESSION-005

### REQ-OCCTL-SESSION-007 — show sessions / show session filtering

**Requirement:** `show sessions valid` MUST list only sessions whose
`cookie_int_msg.status == PS_AUTH_COMPLETED`; `show sessions all` MUST list
every entry returned (expired entries are already omitted by sec-mod,
REQ-SECMOD-SESSION-006); in text mode the column header MUST be printed
before the first row that is listed. `show session ARG` MUST print every
session, in any state, whose full `safe_id` starts with `ARG` — so the
6-character short ID, the full 27-character ID, and any prefix in between
all match, as for `terminate session` — and, when none matches, print
`Session ID not found or expired` and exit non-zero (2, as REQ-OCCTL-ERR-002).
The detail view MUST show the 6-character short ID and the full `safe_id`
(`Full session ID` in text, `Full session` in JSON). Where the full ID is
printed: JSON output of every session and user listing, and the text
detail view of `show session`; text listings show only the short ID.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/unix.c `session_list()`,
`handle_list_sessions_cmd()`, `handle_show_session_cmd()` (returns
`session_info_cmd()`'s result),
`session_info_cmd()`; doc/occtl.8.md (`show sessions`, `show session`);
maintainer decision recorded with this requirement.
**Acceptance:** positive, local — `tests/test-occtl-local` (fake server,
scenario `sessions`): `show session` with the 6-character ID and with the
full 27-character ID each show only the matching session, and `show
sessions valid` prints its header first although the first session
returned is still authenticating. Positive, CI — `tests/test-occtl-commands`
Section 6 (short SID). Negative, local — `tests/test-occtl-local`: `occtl
show session zzzzzz` prints `Session ID not found or expired` and exits 2.
**Links:** REQ-SECMOD-SESSION-006, REQ-OCCTL-ERR-002

### REQ-OCCTL-SESSION-008 — show events: initial list then one update per connect/disconnect

**Requirement:** On `CTL_CMD_TOP` main MUST reply with the current user list
(`CTL_CMD_LIST_REP`) and keep the connection open. main supports a single
event listener: if none is registered it MUST register this connection as
`top_fd` and then send one `CTL_CMD_TOP_UPDATE_REP` (`top_update_rep` with
`connected`, the `user_info_rep` of that worker, and for disconnects
`discon_reason` / `discon_reason_txt`) on every client connect and
disconnect. If a listener is already registered, main MUST send the new
connection the user list and then close it, rather than leave it waiting
silently; occtl, on seeing the server close the event connection, MUST say
that the server sends events to one listener at a time, so another `show
events` may be running (it cannot tell this from a server shutting down).
doc/occtl.8.md MUST document the one-listener limit. A send
failure MUST unregister the listener. occtl MUST print each update until
`q`/`Q`, `Ctrl+C`, or the server closes the connection; at end of input
on stdin it MUST stop reading stdin and keep printing updates, without
busy-waiting, so that it can run without a terminal (under `nohup`, or as
a service). It MUST ignore an update whose user list is empty, and MUST
restore the terminal mode and the `SIGINT` handler on every exit path.
**Strength:** MUST
**Status:** REVIEW
**Source:** src/main-ctl-unix.c `method_top()`, `ctl_cmd_wacher_cb()`,
`ctl_handler_notify()`; src/occtl/unix.c `handle_events_cmd()` (`have_tty`,
`watch_stdin`, `rep2->user->n_user == 0`);
doc/occtl.8.md (`show events`); maintainer decision recorded with this
requirement.
**Acceptance:** positive, CI — start `occtl show events` under a pty, connect
and disconnect a client; confirm `connected user 'test'` and `disconnect
user 'test' ... (reason: ...)` lines appear. Negative, local —
`tests/test-occtl-local` (fake server, scenario `events`): an update with
an empty user list is ignored, and with stdin at end of input occtl keeps
listening, using less than a second of CPU time in 3 seconds. Negative,
CI — start a second `show events` listener; confirm it reports that
another listener is active.
`[REVIEW: decided 2026-11-08 — keep one listener; main closes the
connection of any further listener after its user list, and occtl treats a
closed event connection as possibly due to another listener. Conform: the
terminal mode and SIGINT handler are restored on every exit path, empty
updates are ignored, end of input ends polling of stdin but not the
command, failures exit 1, and doc/occtl.8.md documents the one-listener
limit. Do not conform yet: main
keeps a second listener's connection open and sends it nothing; occtl does
not recognise a closed connection (REQ-OCCTL-ERR-004).]`
**Links:** REQ-OCCTL-IPC-001, REQ-OCCTL-SEC-004

---

## NET

### REQ-OCCTL-NET-001 — unban ip clears both the ban and the score

**Requirement:** occtl MUST parse the `unban ip` argument with
`inet_pton()` (IPv6 if it contains `:`, IPv4 otherwise) and send the 4- or
16-byte address in `unban_req.ip`; an unparsable argument MUST be rejected
locally with exit 1. main MUST, for a matching ban-db entry (IPv6
compared as its /64), set its score and expiry to 0 and reply `status =
true`; it MUST reply `false` for an address not in the ban db or of any
other length. occtl MUST print `IP 'X' was unbanned` (exit 0) or `could not
unban IP 'X'` (exit 1).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/unix.c `handle_unban_ip_cmd()`; src/main-ctl-unix.c
`method_unban_ip()`; src/main-ban.c `remove_ip_from_ban_list()`;
doc/occtl.8.md (`unban ip`: "accumulated ban points are also cleared")
**Acceptance:** positive, CI — `tests/test-occtl-commands` Section 8 (ban,
`unban ip`, `IPs in ban list: 0`, new cookie obtainable). Negative, local —
`occtl unban ip 300.1.1.1` exits 1 (`Cannot parse IP`); `occtl unban ip
192.0.2.1` on a server with no such entry exits 1.
**Links:** REQ-MAIN-SEC-006

### REQ-OCCTL-NET-002 — show ip bans vs. show ip ban points

**Requirement:** main MUST return every ban-db entry in `ban_list_rep`, with
`expires` set only when `max-ban-score > 0`, the entry is banned, and the
ban has not yet expired. `show ip bans` MUST list only entries carrying
`expires`; `show ip ban points` MUST list every entry with its score.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `append_ban_info()`, `method_list_banned()`;
src/occtl/unix.c `handle_list_banned_cmd()`; doc/occtl.8.md
**Acceptance:** positive, CI — `tests/test-occtl-commands` Section 8,
`tests/test-ban` (`jq length` on both lists). Negative — an address with
points below `max-ban-score` appears in `show ip ban points` and not in
`show ip bans`.
**Links:** REQ-MAIN-SEC-002

---

## CLI

### REQ-OCCTL-CLI-001 — Option syntax: documented options precede the command

**Requirement:** occtl MUST treat leading arguments starting with `-` as
options and everything after them as one command (words joined by single
spaces). The options are exactly the ones doc/occtl.8.md documents, in
their documented short and long forms: `-s FILE`, `--socket-file FILE` or
`--socket-file=FILE` selects the socket; `-j`/`--json` and
`-n`/`--no-pager` apply to the command; `--debug` adds debug-only fields;
`-v`/`--version` prints the version and exits 0; `-h`/`--help` prints
usage and exits 0. Any other argument starting with `-`, including an
abbreviation or extension of a documented option (`--j`, `-json`), MUST be
rejected: occtl prints usage and exits 1. With no command left (`occtl`,
`occtl -s FILE`, `occtl --debug`) occtl MUST start interactive mode, where
JSON output is disabled.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/occtl.c `main()`, `is_option()`, `usage()`; doc/occtl.8.md (OPTIONS, EXAMPLES:
"options must precede the command"; EXIT STATUS: 1 when "the command syntax
was not valid"); maintainer decision recorded with this requirement.
**Acceptance:** positive, local — `tests/test-occtl-local`: each
documented form (`-s`, `--socket-file FILE`, `--socket-file=FILE`, `-j`,
`--json`, `-n`, `--no-pager`, `--debug`) is accepted; `-h`, `--help`,
`-v`, `--version` exit 0. Negative, local — `-x`, `--j`, `-json`,
`--jxyz`, `-d` print usage and exit 1.
`occtl -j` / `occtl -n` with no command still runs an empty command and
exits 1 instead of starting interactive mode (not decided to change).
**Links:** REQ-OCCTL-ERR-001, REQ-OCCTL-CLI-011

### REQ-OCCTL-CLI-002 — Command matching

**Requirement:** occtl MUST match a command line against the command table
case-insensitively after collapsing runs of whitespace, choosing the first
table entry that is a prefix of the line; the remainder (leading whitespace
stripped) is the argument. A line that matches no command MUST print
`unknown command: ...` plus a hint (or the help for the partial command)
and fail with exit 1. Hidden aliases `?`, `quit`, `show cookies all`, `show
cookies valid` MUST behave as `help`, `exit`, `show sessions all`, `show
sessions valid`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/occtl.c `commands[]`, `check_cmd()`, `handle_cmd()`,
`check_cmd_help()`
**Acceptance:** unit, local — `occtl -s /nonexistent "SHOW   STATUS"` is
recognised (offline, exit 1); `occtl foo` prints `unknown command` and exits
1; `occtl show` prints the `show ...` help lines and exits 1.
**Links:** REQ-OCCTL-INIT-004

### REQ-OCCTL-CLI-003 — Commands that need an argument fail locally without one

**Requirement:** `show user`, `show id`, `show session`, `disconnect
user|id`, `terminate user|id|session`, and `unban ip` MUST, when given no
argument or `?`, print the help line for that command and return 1 without
sending a request.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/occtl.c `need_help()`; src/occtl/unix.c
`handle_unban_ip_cmd()`, `handle_disconnect_user_cmd()`,
`handle_disconnect_id_cmd()`, `handle_terminate_user_cmd()`,
`handle_terminate_id_cmd()`, `handle_terminate_session_cmd()`,
`handle_show_session_cmd()`, `handle_show_user_cmd()`,
`handle_show_id_cmd()`
**Acceptance:** negative, local — `occtl disconnect user` exits 1, prints
the `disconnect user [NAME]` help line, and `strace -e connect` shows no
connection to the occtl socket.
**Links:** REQ-OCCTL-CLI-002

### REQ-OCCTL-CLI-004 — Connection IDs are worker PIDs

**Requirement:** The `ID` shown by `show users` / `show user` and accepted
by `show id`, `disconnect id` and `terminate id` MUST be the worker process
ID (`user_info_rep.id = proc->pid`), so that an ID identifies one
connection, not a VPN session (a session can span several connections).
doc/occtl.8.md MUST call it a connection ID, following the README
glossary's session/connection distinction.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `append_user_info()` (`rep->id =
ctmp->pid`), `single_info_common()`, `method_disconnect_user_id()`,
`method_terminate_id()`; doc/occtl.8.md (`show id`, `disconnect id`:
"numeric connection ID")
**Acceptance:** positive, CI — the `ID` from `occtl --json show users`
equals the pid of a running `ocserv-worker` process
(`tests/test-occtl-commands` Section 4/5).
**Links:** REQ-OCCTL-SESSION-002, REQ-OCCTL-SESSION-004

### REQ-OCCTL-CLI-005 — show status reports main's and sec-mod's counters

**Requirement:** `show status` MUST print `Status: online` with main's PID,
the first sec-mod PID and the instance count, start time and uptime, active
sessions, total sessions, total authentication failures, banned IP count,
and the current-period statistics from `status_rep`; `--debug` MUST add
`Sec-mod client entries` and `TLS DB entries`. main MUST sum
`secmod_client_entries`/`tlsdb_entries` and average `avg_auth_time` across
all sec-mod instances. occtl MUST NOT read a sec-mod PID that the reply
does not carry (`n_sec_mod_pids` is 0 when main could not allocate the
list); it then omits the `Sec-mod PID` line. If the server cannot be
reached occtl MUST print `Status: offline` and exit 1.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `method_status()`; src/occtl/unix.c
`handle_status_cmd()` (`rep->n_sec_mod_pids > 0`)
**Acceptance:** positive, CI — `tests/test-occtl-commands` Section 1
(`Active sessions: 1`, `Server PID:`, `IPs in ban list: 0`); `tests/json`
(`--json [--debug] show status`). Negative, local — `occtl -s /nonexistent
show status` prints `Status: offline`, exit 1; `tests/test-occtl-local`
(fake server, scenario `status-nopids`): a reply without sec-mod PIDs
prints the server PID, no `Sec-mod PID` line, and exits 0.
**Links:** REQ-OCCTL-ERR-001

### REQ-OCCTL-CLI-006 — show users / show iroutes list every worker

**Requirement:** On `CTL_CMD_LIST` main MUST return one `user_info_rep` per
entry in its process list (connected and still-authenticating workers).
`show users` MUST print one row per entry (`id user vhost ip vpn-ip device
since dtls-cipher status`), using `(none)` for an empty user name;
`show iroutes` MUST print one row per iroute of each entry.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `append_user_info()`, `method_list_users()`;
src/occtl/unix.c `common_user_list()`, `handle_list_users_cmd()`,
`handle_list_iroutes_cmd()`
**Acceptance:** positive, CI — `tests/test-occtl` (`ID`, `raw_connected_at`
in JSON), `tests/test-occtl-commands` Section 3, `tests/json`.
**Links:** REQ-OCCTL-CLI-009

### REQ-OCCTL-CLI-007 — show user / show id print full per-connection detail

**Requirement:** `show user NAME` MUST print every connection whose user
name equals `NAME` exactly; `show id ID` MUST print the one connection with
that ID. The detail MUST include, when present: ID, user and group, state,
vhost, device and MTU, remote and local addresses, assigned IPv4/IPv6 and
P-t-P addresses, user agent, rate limits, interface RX/TX (libnl builds,
Linux only), DPD/keepalive, hostname, connect and session-start times,
short session ID (and full session ID in JSON), TLS/DTLS ciphersuites and
compression, DNS, NBNS, split-DNS domains, routes (`defaultroute` when
none), no-routes, iroutes, route restriction and restricted ports, and a
GeoIP location (`unknown` when no database).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `single_info_common()`,
`method_user_info()`, `method_id_info()`; src/occtl/unix.c
`common_info_cmd()`, `handle_show_user_cmd()`, `handle_show_id_cmd()`;
src/occtl/nl.c `print_iface_stats()`; src/occtl/maxmind.c,
src/occtl/geoip.c `geo_lookup()`
**Acceptance:** positive, CI — `tests/test-occtl-commands` Section 5,
`tests/json` (`--json show user`), `tests/test-year-2038` (`show user`).
Negative — `show user` for an absent user: REQ-OCCTL-ERR-002.
**Links:** REQ-OCCTL-ERR-002, REQ-OCCTL-CLI-009

### REQ-OCCTL-CLI-008 — stop requests an orderly SIGTERM shutdown

**Requirement:** The command is `stop`; any argument after it (the
customary `now` included) MUST be ignored. On `CTL_CMD_STOP` main MUST feed
`SIGTERM` to its event loop and reply `status = true`; occtl MUST print
`Server scheduled to stop` (exit 0), or `Error scheduling server stop`
(exit 1).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `method_stop()`; src/occtl/unix.c
`handle_stop_cmd()`; src/occtl/occtl.c `commands[]` (`ENTRY("stop", "now",
...)`); doc/occtl.8.md (`stop [now]`); maintainer decision recorded with this
requirement.
**Acceptance:** positive, CI — `occtl stop` and `occtl stop now` each make
the server exit, and REQ-OCCTL-INIT-002 holds.
**Links:** REQ-OCCTL-INIT-002

### REQ-OCCTL-CLI-009 — JSON output is valid JSON

**Requirement:** With `-j/--json`, each command's stdout MUST be one valid
JSON document (an array for list/detail commands, an object for `show
status`). Every string value, including list entries, MUST be JSON-escaped
(`"`, `\` and control characters), bytes of UTF-8 text MUST be passed
through unchanged, and no value MUST be replaced by a placeholder because
of its length. A field whose value is empty MAY be omitted, so consumers
MUST treat every key as optional. Machine-only companions (`raw_*`,
`_<name>`, `Full session`) MUST be emitted only in JSON mode.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/print.c `print_json_string()` (used by
`print_list_entries()`, `print_single_value()`, `print_single_value_ex()`,
`print_pair_value()`); src/occtl/json.h `JSON_ESCAPED_SIZE()`;
src/occtl/json.c `json_escape_val()` (compares bytes as `unsigned char`);
src/occtl/nl.c `print_iface_stats()`; maintainer decision recorded with
this requirement.
**Acceptance:** unit, local — `tests/json-escape.c`: 2-, 3- and 4-byte
UTF-8 sequences are copied unchanged, also next to an escaped character;
a buffer too small for the value yields `(invalid)` without writing outside
it; and a 2047-byte value escapes completely into a buffer of
`JSON_ESCAPED_SIZE()`. Negative, local — `tests/test-occtl-local` (fake
server, scenario `users`): `--json show users` with a user name containing
`"` and `\`, a UTF-8 group name, a DNS entry containing `"`, and a
600-byte user agent parses as JSON and round-trips each value. CI —
`tests/json` pipes each `--json` command through a JSON validator.
**Links:** REQ-OCCTL-CLI-006, REQ-OCCTL-CLI-007

### REQ-OCCTL-CLI-010 — Interactive mode: completion from last listing

**Requirement:** In interactive mode occtl MUST offer readline completion
of command words and, for `[NAME]`, `[ID]`, `[IP]` and `[SID]` arguments,
of the values seen in the most recent `show users`/`show events`, `show ip
...`, or session listing respectively; `Ctrl+C` MUST clear the current line
rather than exit; EOF or `exit`/`quit` MUST exit with status 0.
**Strength:** SHOULD
**Status:** DERIVED
**Source:** src/occtl/occtl.c `rl_gets()`, `command_generator()`,
`occtl_completion()`, `handle_sigint()`, `initialize_readline()`, `main()`;
src/occtl/cache.c, src/occtl/session-cache.c, src/occtl/ip-cache.c
**Acceptance:** manual, local — under a pty: `show users`, then `show user
<TAB>` completes a listed user name.
**Links:** —

### REQ-OCCTL-CLI-011 — occtl's command-line interface is stable across releases

**Requirement:** A new ocserv release MUST NOT remove an occtl command,
command alias, or command-line option in a form documented in
doc/occtl.8.md, MUST NOT change the arguments such a command or option
takes, and MUST NOT change the meaning of a documented exit status of a
command, so that scripts and administrator habits keep working across
upgrades. The interface is what is documented: an undocumented spelling
that an earlier release happened to accept (such as an abbreviated
option) is not part of it. A release
MAY add new commands and options, and MAY extend an existing command so it
accepts input it previously rejected or failed to match (a new optional
argument, a wider argument syntax), provided every invocation that worked
before still works with the same effect. A change that would break this
MUST be agreed with the maintainers before it is made.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** maintainer decisions (2026-11-08), recorded with this
requirement; src/occtl/occtl.c `commands[]` (command table, including the
hidden aliases kept for compatibility: `quit`, `?`, `show cookies
all|valid`); src/config.c `cfg_ini_handler()` (the `use-dbus` →
`use-occtl` precedent on the server side)
**Acceptance:** review — for every change under `src/occtl/` or to
doc/occtl.8.md, the reviewer confirms that each entry in the command table
and each option in `main()` still exists with the same arguments, and that
doc/occtl.8.md's EXIT STATUS entries keep their meaning. Regression, CI —
the occtl tests (`tests/test-occtl`, `tests/test-occtl-commands`,
`tests/terminate-commands`, `tests/json`) are run unmodified against the
new release.
**Links:** REQ-OCCTL-CLI-001, REQ-OCCTL-CLI-002, REQ-OCCTL-ERR-001

---

## ERR

### REQ-OCCTL-ERR-001 — Exit status reflects command success

**Requirement:** When a command is given on the command line, occtl's exit
status MUST be one of: 0 — the command succeeded; 1 — the server could not
be reached, replied negatively, the exchange failed, or the command or an
option was invalid; 2 — a `show` command for a specific user, ID or
session found nothing (REQ-OCCTL-ERR-002). doc/occtl.8.md MUST document
all three. occtl MUST print `could not send message; possibly insufficient
permissions or server is offline.` on stderr when the request/reply
exchange itself fails.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/occtl.c `single_cmd()`, `main()` (`exit(ret)`);
src/occtl/occtl.h `ERR_SERVER_UNREACHABLE`; doc/occtl.8.md (EXIT STATUS);
maintainer decision recorded with this requirement.
**Acceptance:** positive/negative, CI — every occtl call in
`tests/test-occtl-commands` and `tests/terminate-commands` checks `$?`;
`show user nosuchuser` exits 2. Local — `tests/test-occtl-local`: `show
session zzzzzz` exits 2, `occtl -x` exits 1.
**Links:** REQ-OCCTL-ERR-002, REQ-OCCTL-CLI-001

### REQ-OCCTL-ERR-002 — Not-found is a failure for show user / show id / show session

**Requirement:** `show user` and `show id` MUST exit 2 and, in text mode,
print `user or ID not found` when main returns an empty `user_list_rep`,
so that scripts can test whether a user is connected; `show session` MUST
exit 2 when no session matches (REQ-OCCTL-SESSION-007).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/occtl/unix.c `common_info_cmd()` (`ret = 2`),
`handle_show_user_cmd()`, `handle_show_id_cmd()`, `session_info_cmd()`,
`handle_show_session_cmd()`
**Acceptance:** negative, CI — `tests/disconnect-user`,
`tests/disconnect-user2`, `tests/test-occtl-commands` Section 4 rely on
`occtl show user test` failing after disconnect.
**Links:** REQ-OCCTL-ERR-001, REQ-OCCTL-SESSION-007

### REQ-OCCTL-ERR-003 — Statistics in show status are not real-time

**Requirement:** In text mode `show status` MUST state that session time
and RX/TX statistics are updated on user disconnect, so that the
administrator does not read them as live counters.
**Strength:** SHOULD
**Status:** DERIVED
**Source:** src/occtl/unix.c `handle_status_cmd()`
**Acceptance:** positive, local — `occtl show status` output begins with
`Note: the printed statistics are not real-time`.
**Links:** REQ-OCCTL-CLI-005

### REQ-OCCTL-ERR-004 — show events reports connection loss

**Requirement:** `show events` MUST print `events: server closed the
connection` (with the hint of REQ-OCCTL-SESSION-008) when main closes the
event connection — whether it does so between updates or while an update
is being read — and `events: Unexpected message ...` when it receives
anything other than `CTL_CMD_TOP_UPDATE_REP`, and stop listening in both
cases; a closed connection is not an error (exit 0).
**Strength:** MUST
**Status:** REVIEW
**Source:** src/occtl/unix.c `handle_events_cmd()`; src/common/common.c
`force_read_timeout()` (returns -1 with `errno = ENOENT` at end of file,
never 0)
**Acceptance:** positive, local — `tests/test-occtl-local` (fake server,
scenario `events-close`): the server sends the user list and closes the
connection; occtl prints `server closed the connection` and exits 0.
Positive, CI — start `occtl show events`, run `occtl stop now`; confirm the
same line and that occtl exits.
`[REVIEW: decided 2026-11-08 — a bug. Code does not yet conform:
handle_events_cmd() tests `ret == 0` for end of file, but
force_read_timeout() returns -1 with errno ENOENT then, so occtl prints
`events: read1: No such file or directory` and exits 1.]`
**Links:** REQ-OCCTL-SESSION-008

### REQ-OCCTL-TEARDOWN-001 — main releases per-request state after each command

**Requirement:** main MUST free the per-request talloc pool and close the
connection after every non-`TOP` command, and on a `TOP` connection's close
MUST clear `top_fd` if it referred to that connection, so that occtl usage
does not accumulate descriptors or memory in main.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/main-ctl-unix.c `ctl_cmd_wacher_cb()` (`ctx.pool =
talloc_new(wst)`, `fail:` path), `ctl_handler_notify()`
**Acceptance:** local — run `occtl show status` 1000 times; confirm main's
open-fd count (`/proc/<pid>/fd`) and RSS return to baseline.
**Links:** REQ-OCCTL-IPC-001

---

## TEST

### REQ-OCCTL-TEST-001 — An occtl test that cannot use ocserv MUST reproduce its scenario with `tests/occtl-fake-server.py`

**Requirement:** A test of occtl that cannot get the server behavior it
checks from a running ocserv — because main does not normally behave that
way (it never replies, closes the connection, or sends a reply with a
field missing or with values that need escaping), or because the test
must run without root (REQ-OCCTL-SEC-001) — MUST run occtl against
`tests/occtl-fake-server.py` and reproduce the scenario there. A test that
needs a behavior the fake server does not have MUST add a scenario to
`occtl-fake-server.py`; it MUST NOT build ctl replies itself, in the test
script, an inline script or a new helper program.

`tests/occtl-fake-server.py` MUST:

  (a) use only the Python standard library (`REQ-GEN-TECH-005`);
  (b) implement each scenario as one function registered in `SCENARIOS`,
      so that adding a scenario changes no other code of the tool, and
      state in its module docstring why the tool exists and how it is
      invoked;
  (c) frame its replies as `send_msg()` does and encode them as the
      messages of `src/ctl.proto`, and append every request it receives to
      its log file, so that a test can confirm occtl sent no request.

The fake server stands in for main only to test how occtl handles a
reply; what depends on main's state (sessions, sec-mod instances,
workers) MUST still be tested against ocserv.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/occtl-fake-server.py` (`SCENARIOS`, `frame()`,
`read_request()`, `main()`); `tests/test-occtl-local` (`start_server()`);
maintainer decision recorded with this requirement.
**Acceptance:** code-review — for each new or changed occtl test that
does not start ocserv, confirm occtl talks to `occtl-fake-server.py`, and
that each new scenario is one function registered in `SCENARIOS` and uses
no module outside the standard library. local — `tests/test-occtl-local`
passes without root.
**Links:** REQ-GEN-TEST-014, REQ-GEN-TEST-001, REQ-GEN-TECH-005,
REQ-OCCTL-IPC-004

---

## Completeness notes

- **Coverage**: every `CTL_CMD_*` request code in `src/occtl/ctl.h` and every
  message in `src/ctl.proto` is covered above (see the Phase 1 table).
  `status_rep` fields are covered collectively by REQ-OCCTL-CLI-005, not
  field by field; `latency_*` fields are only present in
  `CAPTURE_LATENCY_SUPPORT` builds.
- **Field coverage — proto2 `required` fields**: `src/ctl.proto` is proto2,
  so a reply missing a `required` field fails to unpack and occtl reports
  `ERR_SERVER_UNREACHABLE`. `optional` strings in `user_info_rep`
  (`groupname`, `tun`, `user_agent`, ...) are passed to `print_single_value()`,
  which dereferences `value[0]` without a NULL check — main always fills
  them today. `[UNDOCUMENTED: whether occtl must tolerate absent optional
  strings from an older/newer server.]`
- **Version skew**: occtl and ocserv share `ctl.h`/`ctl.proto` but exchange
  no version. occtl is supported only against the ocserv release it ships
  with; the ctl protocol is not a stable interface and `ctl.proto` changes
  need not stay backward compatible (maintainer decision, 2026-11-08).
- **`OCSERV_0_11_6_COMPAT`** JSON fields (`Raw cookie`, `Cookie`, `Last
  Modified`) are compiled out (`#undef OCSERV_0_11_6_COMPAT` in src/occtl/unix.c) and not
  covered.
- **`tests/json`** validates JSON syntax only; it ran `show session all`
  (singular, so `all` was taken as a session-ID prefix and matched
  nothing) until `show session` started exiting 2 on no match, and now
  runs `show sessions all` as intended.
- **Blocking reads in main**: main reads each occtl request synchronously
  in its event loop (`ctl_cmd_wacher_cb()` → `recv_msg_data()`), so a root
  client that stalls mid-request blocks main for up to
  `MAIN_SEC_MOD_TIMEOUT` (120 s). `[UNDOCUMENTED: not decided whether this
  needs a requirement; only uid 0 peers reach this point
  (REQ-OCCTL-SEC-001).]`
- **Tests that cannot run locally**: every acceptance above that starts the
  server needs root (CI), because main accepts only uid 0 occtl peers
  (REQ-OCCTL-SEC-001) and `uid_wrapper` does not reach occtl as a separate
  process.
