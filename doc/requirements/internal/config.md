---
title: configuration subsystem requirements
generator: requirements-from-implementation
process: main, sec-mod, worker (shared)
id-prefix: REQ-CONFIG
sources:
  - src/config.c
  - src/config-ports.c
  - src/config-kkdcp.c
  - src/subconfig.c
  - src/sup-config/file.c
  - src/cfg.proto
  - src/vpn.h
  - src/vhost.h
  - src/inih/ini.h
  - doc/sample.config
  - tests/check-config-scope.py
  - tests/config-inherit.c
---

# Configuration Subsystem Requirements

`src/config.c` (plus `src/config-ports.c`, `src/config-kkdcp.c`,
`src/subconfig.c`, `src/sup-config/file.c`) implements `ocserv.conf` parsing
via `inih`. It is linked into all three processes — main, sec-mod (each
sec-mod instance reloads its own copy), and the worker (which re-parses a
root-created snapshot rather than the live file, REQ-CONFIG-SEC-001) — so
this document is cross-process, like `internal/ipc.md`.

The central design event covered here is commit `139ff827` ("config:
restructure per-vhost configuration for clarity and maintainability",
resolves #705): it split per-vhost configuration into a protobuf-generated
`ReloadableConfig` (`src/cfg.proto`, SIGHUP-reloadable) and a `static_cfg_st`
(`src/vpn.h`, restart-only), and introduced named-vhost inheritance from the
default vhost via a pack/unpack round-trip for the former and explicit
field-by-field copy for the latter.

## INIT

### REQ-CONFIG-INIT-001 — `ocserv.conf` is parsed as INI with `[vhost:<name>]` sections; the unnamed/first vhost is the default

**Requirement:** `parse_cfg_file()` MUST parse the configuration file with
`ini_parse()` and `cfg_ini_handler()`. A line with no enclosing section
applies to the **default vhost** (`vhost->name == NULL`, always the list
tail per `default_vhost()`). A section header `[vhost:<name>]` MUST select
or create (`vhost_add()`) a named vhost for all subsequent lines until the
next section header; any other non-empty section name MUST be rejected with
a `skipping unknown section` warning (non-fatal, line ignored) unless
`reload` or `is_worker` is set (in which case the warning is suppressed).
Virtual host names are canonicalized via `sanitize_name()`/`idna_map()`; a
canonicalization that changes the name MUST print a `note:` (suppressed
under reload/worker). Name-length bounds, and rejection of names the parser
could not represent in full, are specified in REQ-CONFIG-INIT-003.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:943-1030 (`cfg_ini_handler`), src/vhost.h:115-122
(`GETVHOST`/`default_vhost`)
**Acceptance:** unit, local — a config with one `[vhost:example]` section
and no other vhost sections MUST produce exactly two `vhost_cfg_st` entries
(default + `example`); `find_vhost(head, "example")` MUST return the named
one, `find_vhost(head, NULL)` and `find_vhost(head, "unknown")` MUST both
return the default. Negative: a config containing `[bogus]` MUST NOT abort
parsing (line ignored, warning printed on first parse only).
**Links:** REQ-CONFIG-INIT-003, REQ-CONFIG-CFG-002, REQ-CONFIG-CFG-003

### REQ-CONFIG-INIT-002 — Two-tier per-vhost config: `ReloadableConfig` (SIGHUP-reloadable) vs `static_cfg_st` (restart-only)

**Requirement:** Every `vhost_cfg_st` MUST carry exactly two configuration
sub-objects with disjoint lifetimes: `config` (`ReloadableConfig *`,
protobuf-generated from `src/cfg.proto`, replaced wholesale on every
`reload_cfg_file()`) and `static_config` (`struct static_cfg_st`, `src/vpn.h`,
populated once at startup and never replaced by reload). Code MUST access
these only via `GETRCONFIG(s)` / `GETSCONFIG(s)` (`src/vhost.h:116-117`),
never by reaching into `vhost_cfg_st` fields directly, so that the
reload/no-reload distinction stays enforced at a single point. Adding a new
*reloadable* field requires only editing `cfg.proto` (regenerate with
`protoc-c` per `AGENTS.md`); adding a new *restart-only* field requires
editing `static_cfg_st` in `src/vpn.h` AND (per REQ-CONFIG-CFG-003) deciding
its inheritance behavior in `vhost_inherit_static_config()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/vhost.h:35-78, 101-117; src/cfg.proto; src/vpn.h:224-275
**Acceptance:** `grep -rn '\->config\.\|->static_config\.' src/*.c` (outside
`config.c`/`vhost.h`) MUST find no direct struct-field access bypassing
`GETRCONFIG`/`GETSCONFIG` — `[OPEN]`, not run in this pass; recommended as a
lint/CI check given how easy it is to reintroduce direct access after #705.
**Links:** REQ-CONFIG-CFG-001, REQ-CONFIG-CFG-002, REQ-CONFIG-CFG-003

### REQ-CONFIG-INIT-003 — `[vhost:NAME]` names are bounded by `MAX_VHOST_NAME_LEN` and MUST NOT be silently truncated

**Requirement:** A virtual host name of up to `MAX_VHOST_NAME_LEN` (253, the
DNS maximum) characters MUST be stored by `vhost_add()` and matched by
`find_vhost()` in full. `cfg_ini_handler()` MUST reject, as a fatal
configuration error (handler returns 0, which under
`INI_STOP_ON_FIRST_ERROR` aborts `ini_parse()`; `parse_cfg_file()`, which
`reload_cfg_file()` also calls, then prints `config file error in line N`
via `CONFIG_ERROR` and exits with `EXIT_FAILURE`), any
`vhost:` section header that the parser could not represent in full — either
because it filled `inih`'s section buffer
(`strlen(section) >= INI_MAX_SECTION - 1`, which means `ini_strncpy0()`
truncated it) or because the canonicalized virtual host name exceeds
`MAX_VHOST_NAME_LEN`. This check MUST apply only after the `vhost:` prefix
test, so that an over-long *unknown* section is still skipped with a warning
per REQ-CONFIG-INIT-001 rather than made fatal. `INI_MAX_SECTION` MUST be
large enough to hold `"vhost:"`, a maximum-length name, and the NUL
terminator, so that no legal name can reach the truncation path. That bound
cannot be asserted from `config.c`, which sees only the value in `config.h`
and not the array actually declared in `ini.c`; it is enforced behaviourally
instead, by requiring a maximum-length name to parse successfully.

The rationale is that a truncated name is not a cosmetic defect: the stored
name is what client SNI is matched against
(`find_vhost(ws->vconfig, ws->buffer)` in `worker-vpn.c`), and `find_vhost()`
falls back to the **default vhost** on no match. A truncated name therefore
means the administrator's virtual host configuration — its certificate,
authentication methods and network settings — silently never takes effect,
and every client for that host is served by the default vhost instead. Two
distinct virtual hosts whose names share a long common prefix MUST NOT
collapse into a single `vhost_cfg_st`, which is what the existing name-match
in `cfg_ini_handler()` would otherwise do once both names truncate to the
same string.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:972-1004 (`cfg_ini_handler` name checks),
src/vhost.h:32 (`MAX_VHOST_NAME_LEN`),
src/vhost.h:141-157 (`find_vhost`), src/inih/ini.h:144-155
(`INI_MAX_SECTION`), src/inih/ini.c:90-98, 112 (`ini_strncpy0`, section
buffer), src/config.c:1597-1714 (`parse_cfg_file`, `ini_parse()` failure
→ `CONFIG_ERROR` + `exit(EXIT_FAILURE)`), src/worker-vpn.c:742 (SNI-based
vhost selection)
**Acceptance:** tests/test-vhost-name-length — positive/negative ; local,
CI. Driven through `ocserv -t`, so it exercises the real parser rather than
any internal entry point, and therefore also detects a regression introduced
by re-vendoring `src/inih`. Positive: a name longer than the historical
43-character budget MUST be reported as added in full and MUST NOT appear
truncated; two names sharing a 43-character prefix MUST each be added as
their own vhost; a name of exactly `MAX_VHOST_NAME_LEN` characters MUST be
accepted, which is what pins `INI_MAX_SECTION` above the legal maximum.
Negative: a name of `MAX_VHOST_NAME_LEN + 1` characters, and one long enough
to overflow the section buffer, MUST both make `ocserv -t` exit non-zero and
report that the name is too long.
**Links:** REQ-CONFIG-INIT-001

---

## CFG — scope, inheritance, defaults, reload

### REQ-CONFIG-CFG-001 — Every config option has exactly one of five `[scope: ...]` annotations, enforced by `tests/check-config-scope.py`

**Requirement:** Every option documented in `doc/sample.config` MUST carry a
`# [scope: ...]` annotation from a closed vocabulary of five values:
`global (non-reloadable)`, `vhost (non-reloadable)`, `global`, `vhost`,
`vhost user`. Every field of `struct cfg_st`/`struct static_cfg_st` in
`src/vpn.h` MUST carry a matching inline `[scope: ...]` comment.
`tests/check-config-scope.py` MUST pass, enforcing the following
cross-references (its checks a–h):
  - (a) every `sample.config` option has a scope annotation;
  - (b) every reloadable `[... global]` option has a matching
    `error_on_vhost()` call in `config.c` (REQ-CONFIG-CFG-004);
  - (c) every `error_on_vhost()` call in `config.c` is annotated
    `[... global]` in `sample.config` (modulo
    `DEPRECATED_GLOBAL_ALIASES`);
  - (d)/(e) every `[...user...]`-annotated option is handled in
    `src/sup-config/file.c` and vice versa (REQ-CONFIG-CFG-006);
  - (f) every `[...user...]` option is also `[...vhost...]` (per-user
    overrides require a per-vhost base);
  - (g) every `cfg_st`/`static_cfg_st` field in `src/vpn.h` has a
    `[scope:]` comment;
  - (h) every `[scope: vhost (non-reloadable)]` field in `static_cfg_st` is
    referenced in `vhost_inherit_static_config()` or listed in
    `STATIC_VHOST_INHERIT_EXCEPTIONS` (REQ-CONFIG-CFG-003).
**Strength:** MUST
**Status:** DERIVED
**Source:** tests/check-config-scope.py (full file); src/vpn.h:224-275
(`static_cfg_st` annotations)
**Acceptance:** `meson test -C build check-config-scope` (or
`tests/check-config-scope.py` directly) exits 0. Negative: adding a new
option to `sample.config` without a `[scope:]` line, or a new
`static_cfg_st` field without a `[scope:]` comment, MUST fail check (a) or
(g) respectively — this is the project's primary safeguard against
config/doc/code drift for scope semantics.
**Links:** REQ-CONFIG-CFG-002, REQ-CONFIG-CFG-003, REQ-CONFIG-CFG-004,
REQ-CONFIG-CFG-006

### REQ-CONFIG-CFG-002 — Named vhosts inherit `ReloadableConfig` from the default vhost via a protobuf pack/unpack deep copy, taken on first entry into the `[vhost:NAME]` section

**Requirement:** The first time `cfg_ini_handler()` encounters a
`[vhost:NAME]` section for a given vhost (`vhost->cfg_inherited == 0`), and
**before** parsing any option in that section, it MUST replace
`vhost->config` with `cfg_copy_from_default(defvhost->config, vhost->pool)`
— a full protobuf `pack()`/`unpack()` round-trip of the default vhost's
*current* `ReloadableConfig` (including all scalars, strings, repeated
fields, and sub-messages such as `NetworkConfig`), reallocated under
`vhost->pool` via a talloc-backed `ProtobufCAllocator` so a single
`talloc_free(vhost->config)` releases the entire copy. It MUST then set
`vhost->cfg_inherited = 1` so the copy happens at most once per
parse/reload pass. Options subsequently parsed in the `[vhost:NAME]` section
overlay this inherited snapshot field-by-field; a repeated field is one field,
replaced as a whole (REQ-CONFIG-CFG-010).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:540-568 (`cfg_copy_from_default`), 1014-1029
(call site); tests/config-inherit.c (phases 1–3)
**Acceptance:** tests/config-inherit.c phase 1 — a `[vhost:named]` section
that sets only `auth`/`server-cert`/`server-key`/`ipv4-network`/
`ipv4-netmask` MUST end up with `keepalive`, `dpd`, `idle_timeout`,
`cookie_timeout`, `deny_roaming`, `banner`, `default_domain`, `rx_per_sec`,
and `default_mtu` all equal to the default vhost's values
(`check_inherited()`). Phase 2 — if the named vhost additionally sets
`keepalive = 55555`, only `keepalive` differs; all other inherited fields
are unchanged. Phase 3 — both properties survive `reload_cfg_file()`.
**Divergence / ordering caveat `[REVIEW]`**: the snapshot is of the default
vhost's `ReloadableConfig` **as parsed up to that point in the file** — if
`doc/sample.config`'s convention of "default vhost options first, named
`[vhost:...]` sections last" is violated (a default-vhost option appears
*after* a `[vhost:NAME]` section in the file), that option will **not** be
inherited by vhosts whose `[vhost:NAME]` section already triggered the
copy. This ordering dependency is not validated by `check_cfg()` or
documented in `doc/ocserv.8.md`/`doc/sample.config`. `[CANDIDATE for doc
addition]`: document the required section ordering, or `[OPEN]`: consider
deferring the inheritance copy to the post-parse loop
(`src/config.c:1700-1799`, where `vhost_inherit_static_config()` already
runs) so it is order-independent like REQ-CONFIG-CFG-003.
**Links:** REQ-CONFIG-CFG-001, REQ-CONFIG-CFG-003, REQ-CONFIG-CFG-005,
REQ-CONFIG-CFG-007

### REQ-CONFIG-CFG-003 — Named vhosts inherit `static_cfg_st` fields via `vhost_inherit_static_config()`, run once after the full file is parsed

**Requirement:** After `ini_parse()` completes, `parse_cfg_file()` MUST walk
all vhosts in reverse-add order (default vhost first, per
`list_for_each_rev`) and, for every named vhost, call
`vhost_inherit_static_config(vhost, defvhost)`. This function MUST:
  - **unconditionally** copy every `[scope: global (non-reloadable)]` field
    (`port`, `udp_port`, `uid`, `gid`, `sec_mod_scale`, `stats_reset_time`,
    `socket_file_prefix`, `occtl_socket_file`, `chroot_dir`) from the default
    vhost — named vhosts cannot override these regardless of what they set;
  - **conditionally** copy every `[scope: vhost (non-reloadable)]` field
    (`cert`/`cert_size`, `key`/`key_size`, `ca`, `dh_params_file`,
    `cert_hash` (`ANYCONNECT_CLIENT_COMPAT`), `pin_file`, `srk_pin_file`,
    `key_pin`, `srk_pin`, `auth`/`auth_methods`, `acct`) **only if** the
    named vhost left that field unset (NULL / zero-size / zero-count) —
    "inherit if not set, else keep the vhost's own value";
  - **exclude** `sup_config_type`: `cfg_alloc_vhost()` pre-sets it to
    `SUP_CONFIG_FILE` (non-zero) for every vhost, so there is no zero
    sentinel to distinguish "not set" from "explicitly set to the default" —
    a named vhost needing a different `sup-config` MUST set it explicitly.
    This exclusion is enumerated in `STATIC_VHOST_INHERIT_EXCEPTIONS`
    (REQ-CONFIG-CFG-001(h)).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:1766-1768 (call site, post-parse loop),
1820-1915 (`vhost_inherit_static_config`, `VHOST_INHERIT*` macros);
tests/config-inherit.c phase 4
**Acceptance:** tests/config-inherit.c phase 4 — a `[vhost:named]` section
that sets only `ipv4-network`/`ipv4-netmask` (omitting `auth`,
`server-cert`, `server-key` entirely) MUST end up with
`named->static_config.cert`/`cert_size`, `key`/`key_size`, and
`auth`/`auth_methods` all equal to the default vhost's (deep-copied
strings, not shared pointers, except `acct`/`auth[].auth_ctx`/`dl_ctx` which
are intentionally shared read-only module state per the function's
docstring). Negative: a named vhost that DOES set its own `auth`/cert/key
MUST keep them — `vhost_inherit_static_config` must not clobber
explicitly-set values.
**Links:** REQ-CONFIG-CFG-001, REQ-CONFIG-CFG-002

### REQ-CONFIG-CFG-004 — `[scope: ... global]` reloadable options MUST be rejected inside `[vhost:NAME]` sections via `error_on_vhost()`

**Requirement:** When `cfg_ini_handler()` parses an option annotated
`[scope: global]` or `[scope: global (non-reloadable)]` in `sample.config`
(e.g. `listen-host`, `udp-listen-host`, `tcp-port`, `udp-port`,
`run-as-user`, `run-as-group`, `socket-file`, `occtl-socket-file`,
`chroot-dir`, `server-stats-reset-time` and others — see
`tests/check-config-scope.py` checks (b)/(c) for the full set) while
`vhost->name != NULL` (i.e. inside a `[vhost:NAME]` section), it MUST call
`error_on_vhost(vhost->name, "<option-name>")`, which prints `'<option-name>'
cannot be set inside a virtual host section` to stderr and returns `true`;
the calling code path MUST then skip applying the value (the option is a
no-op inside the vhost section, not a fatal error — parsing continues).
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:893-904 (`error_on_vhost`), 1047-1320 (call sites)
**Acceptance:** [SEC/CFG] negative — a config with `tcp-port = 9000` inside
a `[vhost:example]` section MUST print the `error_on_vhost` message, MUST
NOT change `example`'s `static_config.port` (it remains inherited from the
default per REQ-CONFIG-CFG-003), and parsing MUST continue (not
`exit(EXIT_FAILURE)`) — confirm via `check-config-scope.py` test (b)/(c) plus
a targeted parse test.
**Links:** REQ-CONFIG-CFG-001, REQ-CONFIG-CFG-003

### REQ-CONFIG-CFG-005 — Reloadable scalar defaults are applied via `apply_default_conf()` with explicit `has_<field>=1`, before parsing and before any inheritance copy

**Requirement:** `cfg_new()` (called for every vhost at `vhost_add()` time,
and again per-vhost on every reload via `reload_cfg_file()`) MUST call
`apply_default_conf()` immediately after `reloadable_config__init()`. For
every `ReloadableConfig` optional scalar with a non-zero/non-empty default
(`rekey_time`, `cookie_timeout`, `auth_timeout`, `ban_time`,
`ban_reset_time`, `max_ban_score`, `ban_points_wrong_password`,
`ban_points_connect`, `ban_points_kkdcp`, `dpd`, `mobile_dpd`, `keepalive`,
`switch_to_tcp_timeout`, `mobile_idle_timeout`,
`network->ipv6_subnet_prefix`, plus boolean-with-default-true fields
`dtls_legacy`, `dtls_psk`, `predictable_ips`, `use_utmp`, and (if
`ENABLE_COMPRESSION`) `no_compress_limit`), `apply_default_conf()` MUST set
both the value AND `has_<field> = 1`. Setting `has_<field>` is what makes
the default participate in protobuf pack/unpack (REQ-CONFIG-CFG-002): a
named vhost that never overlays one of these fields inherits the **default
vhost's effective value** (its own default, or whatever the default vhost
section explicitly set), not a protobuf-zero/absent value. Permanent
(`static_cfg_st`) defaults (`stats_reset_time = 1 week`, `log_level`,
`syslog_facility = LOG_DAEMON`, `occtl_socket_file`) are applied only when
`!reload`.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:766-824 (`apply_default_conf`), 826-845 (`cfg_new`)
**Acceptance:** unit, local — a minimal config with no `keepalive`/`dpd`/
`rekey-time`/etc. directives MUST produce `DEFAULT_KEEPALIVE_TIME` /
`DEFAULT_DPD_TIME` / `DEFAULT_REKEY_TIME` (etc., from `defaults.h` or
equivalent) in the default vhost's `ReloadableConfig`, with the
corresponding `has_*` flags set to 1; a named vhost in the same config MUST
inherit these exact values (REQ-CONFIG-CFG-002), not protobuf defaults
(0/NULL).
**Links:** REQ-CONFIG-CFG-002

### REQ-CONFIG-CFG-006 — `[scope: vhost user]` options are additionally parsed per-user/per-group via `src/sup-config/file.c`, transit IPC as `GroupCfgSt`, and are merged onto the vhost default by main in `apply_default_config()`

**Requirement:** Options annotated `[scope: vhost user]` in
`sample.config` MUST be both (a) settable at vhost level (subject to
REQ-CONFIG-CFG-002/003 inheritance) as a default, AND (b) individually
overridable per-user or per-group via the supplemental-config mechanism
(`sup-config = file`, `per-user-dir`/`per-group-dir`), parsed by
`src/sup-config/file.c`'s INI handler using the `READ_RAW_*`/`READ_TF`
macro family. These macros write directly into a `GroupCfgSt` (`config`
field of `SecmSessionReplyMsg`, `src/ipc.proto`) — a real protobuf message
— setting its generated `has_<field>=1` flags (e.g.
`msg->config->has_no_udp`, src/sup-config/file.c:112) for every field
present in the per-user/per-group file. This is the **same** `has_<field>`
mechanism as REQ-CONFIG-CFG-005, not a distinct `is_set` convention: a
`GroupCfgSt` with no per-user overrides is `GROUP_CFG_ST__INIT`-initialized
(all `has_*` false, all pointers NULL) by `handle_secm_session_open_cmd()`
(src/sec-mod-auth.c:504-505), and `get_sup_config()`
(src/sec-mod-auth.c:593-594) only sets the fields the per-user/group file
actually overrides. `iroute` directives are additionally collected across
all per-user config files into `config->known_iroutes` via
`load_iroutes()`/`append_iroutes_from_file()` when `expose_iroutes` is set,
for `occtl show iroutes`.

The populated `GroupCfgSt` travels from sec-mod to main as
`SecmSessionReplyMsg.config` over `CMD_SECM_SESSION_REPLY`
(src/main-sec-mod-cmd.c:537/recv at 537-538) — i.e. per-user overrides DO
cross the sec-mod->main IPC boundary as part of this message, same as the
rest of the session-open reply. The merge with the vhost-level default
happens entirely in **main**: `session_open()`
(src/main-sec-mod-cmd.c:494) sets `proc->config = msg->config` (line ~593)
and then calls `apply_default_config(sec_mod_instance, proc, proc->config)`
(src/main-sec-mod-cmd.c:336-491, called at line 597). For each
`[scope: vhost user]` field, `apply_default_config()` checks
`!gc->has_<field>` (scalars/bools) or `gc-><field> == NULL`
(strings/repeated fields); if unset — meaning no per-user/per-group override
was found — it copies the vhost-level value (`vhost->config->...`) into
`gc` and, for the `has_*` cases, sets `has_<field> = 1`. If the field was
already set by `get_sup_config()`, the per-user/group value is left
untouched. The resulting merged `GroupCfgSt` (`proc->config`) is what main
forwards to the worker as the session's effective configuration.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sup-config/file.c:44-80 (`READ_RAW_*`/`READ_TF` macros),
112 (`has_no_udp` example); src/ipc.proto:30-69 (`group_cfg_st`), 342-347
(`secm_session_reply_msg`); src/sec-mod-auth.c:474-505, 593-594
(`GROUP_CFG_ST__INIT`, `get_sup_config()`); src/main-sec-mod-cmd.c:336-491
(`apply_default_config`), 494-598 (`session_open`); src/config.c:686-764
(`iroutes_handler`, `append_iroutes_from_file`, `load_iroutes`);
tests/check-config-scope.py checks (d)/(e)/(f)
**Acceptance:** `tests/check-config-scope.py` checks (d)–(f) pass (every
`[...user...]` option is handled in `sup-config/file.c` and vice versa,
modulo `PER_USER_ONLY`; every `[...user...]` option is also
`[...vhost...]`). Functional: a per-user config file setting `rx-data-per-sec`
for user `alice` MUST override the vhost-level `rx-data-per-sec` for
`alice`'s session only — confirm by setting different vhost-default and
per-user values, and observing `apply_default_config()` leaves
`gc->has_rx_per_sec`/`gc->rx_per_sec` at the per-user value (does not
overwrite it from `vhost->config`), while a second user with no per-user
override receives the vhost default.
`[LIMITATION (gitlab#265/!154): there is no per-RADIUS-class sup-config
source — config-per-group/config-per-user and `radius_get_sup_config()`'s
attribute mapping (REQ-AUTH-AUTH-026) are the only contributors to
`GroupCfgSt`. gitlab!154 (closed, unmerged) sketched a `per-radius-class-dir`
source for this; see the related limitation note on REQ-AUTH-AUTH-029.]`
**Links:** REQ-CONFIG-CFG-001, REQ-CONFIG-CFG-005, REQ-AUTH-AUTH-026,
REQ-AUTH-AUTH-029, REQ-CONFIG-SEC-002

### REQ-CONFIG-CFG-007 — SIGHUP reload replaces each vhost's `ReloadableConfig` via archive-and-reparse (main) or immediate-free-and-reparse (sec-mod); in-flight references are kept alive via an attic + usage-count until drained

**Requirement:** `reload_cfg_file()` MUST, for each vhost: (a) if called for
**main** (`sec_mod == 0`), call `archive_cfg()`, which moves the vhost's
current `config` and `usage_count` into a new `attic_entry_st`
(`talloc_steal`'d so they survive the parent's lifetime), adds the entry to
`vhost->attic` **only if** `*usage_count != 0` (otherwise frees it
immediately), sets `vhost->config = NULL` and `vhost->usage_count = NULL`,
and resets `vhost->cfg_inherited = 0` so the next parse re-triggers
REQ-CONFIG-CFG-002's inheritance copy against the *new* default-vhost
config; (b) if called for **sec-mod** (`sec_mod == 1`), call `clear_cfg()`,
which immediately `talloc_free()`s the old `config` (sec-mod holds no
long-lived references that survive a reload, unlike main's in-flight
`proc_st` workers) and likewise resets `cfg_inherited = 0`; (c) for every
vhost with `config == NULL`, call `cfg_new()` (re-applying defaults, REQ-
CONFIG-CFG-005); (d) re-run `parse_cfg_file()` with `CFG_FLAG_RELOAD` (and
`CFG_FLAG_SECMOD` if `sec_mod`). Separately, `clear_old_configs()` MUST be
called periodically (or after reload) to walk each vhost's `attic` and
`talloc_free()` any entry whose `*usage_count` has dropped to 0, releasing
the old `ReloadableConfig` once no in-flight worker still references it.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:2384-2432 (`archive_cfg`, `clear_cfg`),
2501-2525 (`reload_cfg_file`), 2579-2595 (`clear_old_configs`);
src/vhost.h:41-43 (`usage_count`, `attic`); tests/config-inherit.c phase 3
**Acceptance:** tests/config-inherit.c phase 3 — after `reload_cfg_file()`
with an unchanged config, `check_inherited(named)` MUST still pass (inherited
fields survive reload because `cfg_inherited` was reset and the inheritance
copy re-ran against the freshly-reparsed default vhost). `[OPEN]`: this pass
did not add a test for the attic/usage_count drain path itself (a worker
holding a reference across a reload, then exiting, should cause its vhost's
attic entry to be freed by a subsequent `clear_old_configs()`).
**Links:** REQ-CONFIG-CFG-002, REQ-CONFIG-CFG-003, REQ-CONFIG-CFG-005,
REQ-MAIN-CFG-001 (cross-process ordering: main calls `reload_cfg_file()`
only after all sec-mod instances have completed their own reload)

### REQ-CONFIG-CFG-008 — Multi-line option arrays are delimited by their count field and hold exactly the values appended

**Requirement:** `_add_multi_line_val()` MUST be able to append to an array
however it was allocated, including an array that holds exactly its elements
because it came from the protobuf inheritance copy (REQ-CONFIG-CFG-002). It
MUST NOT write outside the array's allocation. The number of values is given
only by the corresponding count field; the arrays carry no NULL terminator and
no code may rely on one. There is no limit on the number of values of an
option other than available memory. Which values a named vhost ends up with
is set by REQ-CONFIG-CFG-010.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c (`_add_multi_line_val`, `READ_MULTI_LINE`);
src/sup-config/file.c (`READ_RAW_MULTI_LINE`); tests/config-inherit.c
(`check_many_values`)
**Acceptance:** tests/config-inherit.c, both after parsing and after
`reload_cfg_file()` — 200 `custom-header` values in the default vhost and 200
in the named vhost MUST leave each vhost with its own 200, all with the
expected values, and running the test under ASAN MUST report no
out-of-bounds access.
**Links:** REQ-CONFIG-CFG-002, REQ-CONFIG-CFG-006, REQ-CONFIG-CFG-010

### REQ-CONFIG-CFG-009 — `select-group` entries carry their label, and a named vhost's list replaces the inherited one

**Requirement:** Each `select-group` value MUST be stored as one `SelectGroup`
entry of `ReloadableConfig.select_groups`, holding the group's `name` and, when
the value has a non-empty bracketed label, its `label`; an empty or missing
label MUST leave `label` absent. A named vhost with no `select-group` option
MUST inherit the default vhost's entries with their labels
(REQ-CONFIG-CFG-002). A vhost that sets `select-group` MUST replace the
inherited entries, as for every option (REQ-CONFIG-CFG-010), so that the vhost
offers exactly the groups its section lists and an administrator can offer
fewer groups on a vhost than on the default one; a group listed only by the
default vhost MUST NOT be offered or accepted on such a vhost. `auto-select-group`, when it applies to a vhost,
MUST replace that vhost's entries with the discovered groups, without labels.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/cfg.proto (`SelectGroup`); src/config.c (`read_select_group`,
`add_select_group`, `clear_select_groups`, `cfg_ini_handler`, `parse_cfg_file`);
src/worker-auth.c (`group_display_name`, `resolve_selected_group`);
tests/config-inherit.c phase 6; tests/test-vhost-select-group
**Acceptance:** tests/config-inherit.c phase 6, each case both after parsing and
after `reload_cfg_file()` — default `group1[Label One]`, `group2` with nothing
in the named vhost MUST leave the named vhost with both, `group2` without a
label; the named vhost adding `group3[Label Three]`, `group4` MUST leave it with
only those two, and the default vhost unchanged; `group1[]` MUST have no label;
200 entries in each section MUST leave each with its own 200;
`auto-select-group` with a labelled `select-group` MUST yield only the
discovered groups, with no labels. tests/test-vhost-select-group — the login
form of a vhost that inherits MUST offer `group1` as `Label One`, and resolve
that label when a client proposes it; the form of a vhost that replaces MUST
NOT offer `group1` or `group2`.
**Links:** REQ-CONFIG-CFG-002, REQ-CONFIG-CFG-007, REQ-CONFIG-CFG-008,
REQ-CONFIG-CFG-010, REQ-PROTO-AUTH-010

### REQ-CONFIG-CFG-010 — An option set in a `[vhost:NAME]` section replaces the inherited value as a whole, including options given multiple times

**Requirement:** A named vhost MUST inherit each option it does not set from
the default vhost (REQ-CONFIG-CFG-002, REQ-CONFIG-CFG-003). If its section sets
an option, the values given in that section MUST replace the inherited value
as a whole. For an option that may be given multiple times, the vhost MUST end
up with exactly the values its section lists, in order, and none of the
default vhost's; an administrator who wants to keep inherited values lists
them again. Inherited values are never merged with the vhost's own. This
applies to the reloadable options `route`, `no-route`, `dns`, `nbns`,
`split-dns`, `custom-header`, `included-http-headers`, `select-group` and
`restrict-user-to-ports`, and to the non-reloadable options `auth`,
`enable-auth`, `server-cert`, `server-key` and `kkdcp`. `ipv4-dns` and
`ipv6-dns` are spellings of `dns`, and `ipv4-nbns` and `ipv6-nbns` of `nbns`:
each set of spellings is one option, so a vhost setting any of them replaces
all the inherited values of that option. Setting an option in the default
vhost MUST NOT change any named vhost's own values. The same rule applies one
level down: a per-user or per-group file that sets a `[scope: vhost user]`
option replaces the vhost's values for that session (REQ-CONFIG-CFG-006).
**Strength:** MUST
**Status:** REVIEW
**Source:** src/config.c (`cfg_ini_handler`, `_add_multi_line_val`,
`read_select_group`, `vhost_inherit_static_config`, `parse_kkdcp`);
src/config-ports.c (`cfg_parse_ports`); src/main-sec-mod-cmd.c
(`apply_default_config`); tests/config-inherit.c phases 5–7
**Acceptance:** tests/config-inherit.c, each case both after parsing and after
`reload_cfg_file()`: (a) for each option listed above, a named vhost that does
not set it MUST have the default vhost's values; (b) a named vhost that sets
it MUST have only its own values, and the default vhost only its own;
(c) `dns` in the default vhost and `ipv6-dns` in the named vhost MUST leave the
named vhost with only the `ipv6-dns` value; (d) a named vhost that sets
`enable-auth` but not `auth` MUST keep the inherited `auth` method and have
only its own `enable-auth` method.
**Divergence `[REVIEW]`:** written ahead of the code. Before this requirement,
reloadable list options set in a named vhost appended to the inherited values
(REQ-CONFIG-CFG-002 did not say which), except `select-group`. Status becomes
`DERIVED` once tests/config-inherit.c phase 7 passes.
**Links:** REQ-CONFIG-CFG-002, REQ-CONFIG-CFG-003, REQ-CONFIG-CFG-006,
REQ-CONFIG-CFG-008, REQ-CONFIG-CFG-009

---

## SEC

### REQ-CONFIG-SEC-001 — The worker process parses configuration from a root-created snapshot, never the live config file path

**Requirement:** When `parse_cfg_file()` is called with `CFG_FLAG_WORKER`
set (`PROC_FS_SUPPORTED` builds), it MUST NOT call `ini_parse()` on the
configured file path directly. Instead it MUST resolve the path via
`snapshot_lookup_filename(config_snapshot, file, ...)` (falling back to
`OLD_DEFAULT_CFG_FILE`'s snapshot), parse that snapshot file, and then
rewrite `dh_params_file`, `ocsp_response`, and every `cert[]` entry to their
snapshot equivalents via `replace_file_with_snapshot()`. The non-worker path
(main/sec-mod) parses the live file directly and additionally calls
`snapshot_create()` for the config file itself plus the same
cert/DH-params/OCSP-response files, so the snapshots the worker later reads
are root-controlled copies taken at main/sec-mod's privilege level, not
paths the unprivileged worker resolves itself.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:1592-1673 (`PROC_FS_SUPPORTED` branch of
`parse_cfg_file`)
**Divergence**: on non-`PROC_FS_SUPPORTED` (BSD) builds, this snapshot
indirection does not exist — `src/config.c:1674-1694` has the worker parse
the live file path directly, same as main/sec-mod. Per `AGENTS.md`'s BSD
best-effort policy, this is an accepted platform difference, not a defect,
but it does mean the SEC property above is Linux-only — `[REVIEW]`: confirm
whether worker-side TLS/cert paths on BSD builds are otherwise protected by
`chroot`/seccomp such that direct file access doesn't reintroduce a
privilege-boundary concern (`AGENTS.md`'s "no direct filesystem access
outside its seccomp profile" rule).
**Acceptance:** [SEC] — on Linux, confirm the worker process's open file
descriptors for cert/key/CRL/config files resolve under the snapshot
directory (e.g. `/proc/<pid>/fd`), not the configured `server-cert`/
`ocserv.conf` paths.
**Links:** —

### REQ-CONFIG-SEC-002 — `get_sup_config()` treats `username`/`groupname` as untrusted and cannot be made to read outside `per-user-dir`/`per-group-dir`

**Requirement:** `get_sup_config()` (`src/sup-config/file.c`) MUST NOT build
the per-user/per-group config path by string concatenation of
`per_user_dir`/`per_group_dir` with `entry->acct_info.username`/`groupname`
and hand it to `ini_parse()`. `entry->acct_info.username`/`groupname`
originate from the authenticated client (certificate CN/SAN, or whatever a
PAM/RADIUS/plain `auth_group`/`auth_user` callback returns) and are not
otherwise restricted to safe filename characters. Instead,
`read_sup_config_file()` MUST: (a) reject `username`/`groupname` outright —
returning `ERR_READ_CONFIG` with no fallback to `default_user_conf`/
`default_group_conf` — if the value is empty, is `.` or `..`, or contains
`/` (`is_safe_path_component()`); and (b) for values that pass (a), resolve
the file via `openat(dirfd, name, O_NOFOLLOW)` relative to an fd freshly
opened on `per_user_dir`/`per_group_dir`, never via a concatenated path
string, so a symlink placed at that name cannot redirect the read. A
rejection at (a) MUST propagate as a negative return through
`get_sup_config()` to `handle_secm_session_open_cmd()`, which responds
`AUTH__REP__FAILED` and fails the session open entirely (no degraded
fallback) — same as any other `get_sup_config()` error.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/sup-config/file.c (`is_safe_path_component()`,
`read_sup_config_file()`, `get_sup_config()`); src/sec-mod-auth.c:592-602
(`handle_secm_session_open_cmd()` failing the session on `ret < 0`)
**Acceptance:** positive, local — `tests/test-config-per-group`: a user
whose (default-selected) group is a normal name (`tost`) still has
`config-per-group/tost` applied (existing DNS/route assertions). Negative,
local — same test, a second user (`test6`) whose only/default group is
`../escape` MUST fail to establish a session at all (cookie rejected, no
client process left running, `occtl show users` does not list it) —
confirming the traversal name is rejected before any `openat()`/`ini_parse`
on a path outside `config-per-group/`.
**Links:** REQ-CONFIG-CFG-006

---

## ERR

### REQ-CONFIG-ERR-001 — `check_cfg()` enforces mandatory options and fails closed (`exit(EXIT_FAILURE)`) at parse/reload time, per-vhost

**Requirement:** After inheritance (REQ-CONFIG-CFG-002/003) and auth/acct
setup, `check_cfg(vhost, defvhost, silent)` MUST `exit(EXIT_FAILURE)` (after
printing an `error:` message, prefixed with the vhost name if named) if, for
that vhost: no authentication method was configured
(`static_config.auth[0].enabled == 0`); `socket_file_prefix` is unset
(default vhost only — "the 'socket-file' configuration option must be
specified"); `static_config.port == 0` ("the tcp-port option is mandatory");
`cert_size == 0 || key_size == 0`; or neither `ipv4-network` nor
`ipv6-network` is set, or either is set without its corresponding
netmask/prefix. These checks run for **every** vhost (default and named)
after inheritance has had a chance to fill in missing values from the
default vhost — i.e. a named vhost satisfies these checks via inheritance,
not by repeating every mandatory option.
**Strength:** MUST
**Status:** DERIVED
**Source:** src/config.c:1917-1976 (`check_cfg`)
**Acceptance:** [CFG] negative — a `[vhost:example]` section that sets
`ipv4-network` without `ipv4-netmask`, with no default-vhost
`ipv4-netmask` to inherit, MUST cause `ocserv -c <file> -t` (or worker/main
startup) to print `no mask found for IPv4 network` (prefixed with
`example: `) and `exit(EXIT_FAILURE)` — process does not start with a
partially-valid config. Positive: the same config with the netmask present
(either set directly or inherited from the default vhost) MUST pass.
**Links:** REQ-CONFIG-CFG-002, REQ-CONFIG-CFG-003

---

## Completeness notes

- **`src/config-ports.c` / `src/config-kkdcp.c`**: port-range and KKDCP
  (Kerberos KDC proxy, `HAVE_GSSAPI`) parsing helpers are included by
  `config.c` but not separately analyzed in this pass —
  `[UNDOCUMENTED: candidate REQ-CONFIG-CFG-* for port-list/range syntax and
  KKDCP URL-forwarding config (parse_kkdcp, REQ-CONFIG-CFG-005's
  `urlfw`/`urlfw_size` handling), if found to have non-obvious validation
  rules.]`
- **`src/subconfig.c`** (`auth = pam[...]`/`radius[...]`/etc. bracketed
  sub-option syntax, `expand_brackets_string`, `MAX_SUBOPTIONS`): the
  bracket-expansion mechanism itself is generic INI-within-INI parsing with
  no MUST/MUST NOT beyond "the configured module's `get_brackets_string`
  receives the expanded suboptions" — per-module option semantics belong to
  `internal/sec-mod.md` (auth/acct module config), not here.
  `[UNDOCUMENTED: candidate REQ-CONFIG-CFG-* if a malformed `[...]` bracket
  (unterminated, nested) is found to have a non-obvious failure mode rather
  than a parse error.]`
- **`camouflage`/`camouflage_secret`/`camouflage_realm`**: these are
  `[scope: vhost]` `ReloadableConfig` fields parsed by the ordinary
  mechanisms covered by REQ-CONFIG-CFG-002/004; their *behavioral* contract
  (URL-secret gate, 401/404/405 responses) is fully specified in
  `protocol/unified.md` REQ-PROTO-COMPAT-006 and `internal/worker.md`
  REQ-WORKER-AUTH-004 — not duplicated here.
- **`occtl reload`** (`CMD_SECM_RELOAD` / SIGHUP from `occtl`): triggers the
  same `reload_cfg_file()` path as `SIGHUP`; the IPC framing is covered by
  `internal/ipc.md`, the cross-process ordering by `REQ-MAIN-CFG-001`. Not
  re-derived here.
- **Command-line flags** (`-c`, `-f`/`--foreground`, `-d`/`--debug`, `-t`/
  `--test`, `--pid-file`, etc., `src/config.c` `getopt` handling): out of
  scope for this pass — these select *which* file is parsed and how the
  process behaves around parsing (foreground vs daemonize, test-and-exit),
  not configuration *content* semantics.
