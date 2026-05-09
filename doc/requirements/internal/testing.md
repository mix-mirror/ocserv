---
title: test authorship and quality requirements
generator: requirements-elicitation
process: all
id-prefix: REQ-GEN-TEST
sources:
  - AGENTS.md
  - tests/meson.build
  - tests/common.sh
  - tests/random-vpnnet.sh
  - tests/random-net.sh
  - tests/random-net2.sh
  - tests/check-test-addresses.py
  - tests/scripts/vpnc-script
  - .gitlab-ci.yml
  - meson_options.txt
---

# Test Authorship and Quality Requirements

These requirements constrain how tests in `tests/` are written, independent
of which subsystem they cover — they are what make every other document's
"Acceptance" criteria trustworthy rather than decorative. Split out of
`internal/general.md`, which still holds the other cross-cutting policy
categories (`SEC`, `TECH`, `STYLE`, `COMPAT`); IDs stay under the `REQ-GEN`
prefix since these remain project-wide policy, not a new subsystem.

### REQ-GEN-TEST-001 — Every feature or fix MUST have both a positive and a negative test; tests MUST be self-diagnosing and registered in `tests/meson.build`

**Requirement:** No feature addition or bug fix is complete without tests.
The following apply to all tests in `tests/`:

  (a) **Coverage**: every new feature or changed behavior MUST have at least
      one positive test (the correct behavior is exercised and confirmed) and
      at least one negative test (invalid input or error conditions are
      correctly rejected). For `SEC`, `AUTH`, and `IPC` changes, the negative
      test is the more important of the two and MUST be written first.
  (b) **Bug-fix test order**: for a bug fix, the reproducing test MUST be
      written and confirmed to fail against the unmodified code before the fix
      is applied. A test written after the fix cannot demonstrate it is
      meaningful.
  (c) **Self-diagnosing output**: a test failure MUST be explainable from the
      test's own output without local reproduction. Shell tests MUST print what
      they were testing and why it failed (e.g.
      `echo "FAIL: expected exit 0, got $ret"`). C unit tests MUST print the
      failing condition and relevant values before returning non-zero. Tests
      that exit non-zero with no diagnostic output MUST NOT be accepted.
  (d) **Registration**: every new test MUST be registered in
      `tests/meson.build`. An unregistered test is not run by CI and provides
      no coverage guarantee.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Testing New Functionality); `tests/meson.build`;
`tests/common.sh`
**Acceptance:** code-review — confirm for every MR that: (1) `tests/meson.build`
contains an entry for each new test file; (2) at least one test is a negative
case; (3) running the negative test against the pre-fix code produces a
non-zero exit and a human-readable failure message. CI runs all registered
tests on every MR; a passing CI run with no newly registered test for a
behavior change is itself a review finding.
**Links:** REQ-GEN-SEC-001, REQ-GEN-SEC-002

---

### REQ-GEN-TEST-002 — Unit tests MUST couple only to a module's public contract; a test that a behavior-preserving refactor could break MUST NOT be merged

**Requirement:** A module's public contract is its header-declared
functions/vtables/types plus their documented input/output behavior.
Everything else — private constants, struct layout, internal control flow,
in-memory representation — is private surface.

A unit test MUST depend only on the public contract, or on private surface
explicitly promoted into the module's header for that purpose. A unit test
MUST NOT depend on private surface it reconstructs itself (by duplicating,
guessing, or imitating it) rather than references by compiler-checked
symbol.

**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** AGENTS.md (Design Principles — Locality of complexity; Testing
New Functionality)
**Acceptance:** code-review — for any test reaching past a module's header,
apply: *would a refactor that preserves the module's public-contract
behavior break this test?* If yes, it is a finding; resolve by promoting the
needed symbol into the header, or replacing the test with one that drives
the module only through its public contract.
**Links:** REQ-GEN-TEST-001

---

### REQ-GEN-TEST-003 — A test needing root privilege, a network identity, system users/groups, or a PAM stack MUST use the project's existing wrapper libraries; it MUST NOT invent a new isolation mechanism

**Requirement:** ocserv's test suite provides `socket_wrapper`,
`uid_wrapper`, `nss_wrapper`, and `pam_wrapper` (via `cwrap`) specifically so
tests can fake a network interface, root privilege, system users/groups, or
a PAM service without touching real system state. A test that needs any of
these MUST use the existing `LD_PRELOAD` wrapper plus the corresponding
`common.sh` helper (`launch_simple_sr_server`, `launch_simple_pam_server`,
etc.), consistent with `REQ-GEN-TECH-005`'s bar on new external
dependencies. It MUST NOT mutate real `/etc/passwd`/`/etc/group`, bind to a
real network interface, or otherwise touch system state outside the
wrapper sandbox to achieve isolation.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/common.sh:130-172` (`launch_simple_pam_server`,
`launch_simple_sr_server`); `tests/meson.build` `have_cwrap`/`have_cwrap_pam`
gating; used by 53 test scripts.
**Acceptance:** code-review, local — confirm any new test requiring
elevated/faked privilege sources one of `common.sh`'s `launch_simple_*`
helpers rather than shelling out to real `sudo`/`useradd`/interface
configuration.
**Links:** REQ-GEN-TECH-005

---

### REQ-GEN-TEST-004 — A test MUST require the least privilege that suffices to exercise its behavior; it MUST NOT default to root or other elevated setup when the unprivileged wrapper path would do

**Requirement:** A test MUST be written to need as little privilege as the
property under test allows. If `NO_NEED_ROOT` plus the `*_wrapper`
libraries (`REQ-GEN-TEST-003`) can exercise the behavior, the test MUST use
that path instead of requiring root. Root, real namespaces, or other
CI-only setup MUST be justified by the property under test itself (e.g. an
actual TUN device or network namespace) — they MUST NOT be reached for as a
default that avoids writing the unprivileged path.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/common.sh:34-40` (root gated by `NO_NEED_ROOT`, not
assumed); 60 of the test scripts in `tests/` run under `NO_NEED_ROOT` with
wrapper libraries rather than requiring real root.
**Acceptance:** code-review — for a new test requiring root, confirm and
record why `NO_NEED_ROOT` + wrapper libraries cannot exercise the same
behavior (e.g. it genuinely needs a TUN device, a real network namespace,
or another capability the wrapper libraries do not fake). Absent that
justification, the test MUST be rewritten to the unprivileged path.
**Links:** REQ-GEN-TEST-003

---

### REQ-GEN-TEST-005 — A test whose precondition is unmet in the current run MUST `exit 77` (SKIP); it MUST NOT report a false pass or fail

**Requirement:** After minimizing its precondition per `REQ-GEN-TEST-004`,
a test may still have one genuinely necessary to its current run — missing
root, a missing optional dependency (`openconnect`, `ss`/`netstat`), or an
LD_PRELOAD mechanism incompatible with the active sanitizer. When that
precondition is unmet, the test MUST `exit 77`. It MUST NOT `exit 0` (a
false pass hiding zero coverage) and MUST NOT run anyway and fail for an
unrelated reason (a false fail indistinguishable from a real regression).
A hard test dependency (`REQ-GEN-TEST-012`) is not a precondition under
this requirement: its absence is a broken test environment and fails the
test instead of skipping it.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/common.sh:35-40` (no-root skip), `tests/common.sh:58-63`
(ASAN/ld-preload-incompatible skip); the same `exit 77` pattern recurs in 60
files across `tests/`.
**Acceptance:** code-review, local — grep the new test for its environment
precondition checks; confirm each unmet precondition path is `exit 77`
before any assertion runs. Running the test locally without root (where
`NO_NEED_ROOT` is not set) MUST print the skip reason and exit 77, not hang
or fail.
**Links:** REQ-GEN-TEST-001, REQ-GEN-TEST-004, REQ-GEN-TEST-012

---

### REQ-GEN-TEST-006 — A precondition that makes a test skip locally MUST be satisfied by the project's primary CI matrix; `exit 77` MUST NOT be a way for a test to skip everywhere

**Requirement:** `exit 77` (`REQ-GEN-TEST-005`) covers an unmet precondition
of *this run*, not a standing exemption from ever being executed. Whatever
precondition remains after `REQ-GEN-TEST-004` MUST be satisfied by at least
one job in the project's primary CI matrix, so the test actually runs
there. A test whose precondition also fails in every CI job is not
exercising anything and MUST be fixed — narrow the precondition, or add/
adjust a CI job that satisfies it — rather than left to skip silently
everywhere. Build configurations that disable a whole precondition class on
purpose (`-Droot-tests=false`, used only for the feature-minimal and
FreeBSD jobs) are the documented, scoped exception; they MUST NOT be read
as license for an individual test to avoid execution.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `meson_options.txt:26` (`root-tests` defaults `true`);
`.gitlab-ci.yml` — every primary platform job (Debian, Ubuntu, Fedora,
CentOS, Alpine, seccomp, asan, ubsan, …) runs root-requiring tests with that
default, executing as root in an otherwise-unprivileged container;
`-Droot-tests=false` appears only in `MINIMAL_OPTIONS` and the `.FreeBSD`
template.
**Acceptance:** CI-config review — confirm at least one job in the primary
matrix in `.gitlab-ci.yml` satisfies the new test's precondition (i.e. the
test is not `-Droot-tests=false`'d, nor excluded by a `--no-suite`/`except`
rule, in every job that would otherwise reach it).
**Links:** REQ-GEN-TEST-005

---

### REQ-GEN-TEST-007 — A test that binds a TCP/UDP port MUST obtain it dynamically; it MUST NOT hardcode a fixed port number

**Requirement:** meson runs tests in parallel by default. A test that binds
ocserv (or any helper) to a hardcoded port number will intermittently
collide with another test's listener. A test that needs a port MUST obtain
one via the existing `GETPORT`/`check_if_port_in_use` mechanism in
`tests/common.sh` (or an equivalent unused-port probe), never a literal
port number.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/common.sh:289-300` (`GETPORT`), `tests/common.sh:264-268`
(`check_if_port_in_use`); used by 120 of the test scripts in `tests/`, with
no counterexample of a hardcoded `PORT=<number>`.
**Acceptance:** code-review, local — confirm the new test sources
`eval "${GETPORT}"` (or calls `check_if_port_in_use` itself) before binding
any port, and that no numeric literal is assigned to `PORT`/`ADDRESS:PORT`.

---

### REQ-GEN-TEST-008 — A test's server config MUST be generated from a `tests/data/` template via `update_config()`; it MUST NOT hardcode absolute paths, usernames, or other build-specific values

**Requirement:** A test that needs an ocserv config file MUST derive it from
a template in `tests/data/` using `update_config()`'s `@PLACEHOLDER@`
substitution (`@SRCDIR@`, `@PORT@`, `@USERNAME@`, etc.), so the same test
config works unmodified across out-of-tree builds, parallel build
directories, and CI runners. A test MUST NOT write a config file containing
a literal absolute path, username, or port baked in by the test author.
The same applies to a per-user or per-group configuration directory
(`config-per-user`, `config-per-group`): its files MUST live under
`tests/data/<dir>/` and be materialized with `update_config_dir <dir>`,
which applies the same substitution to every file and sets
`CONFIG_PER_USER_DIR` (referenced from the server config as
`@CONFIG_PER_USER_DIR@`). A test using FreeRADIUS MUST call `update_raddb`
before starting `radiusd`: it copies
`$RADDB_DIR` into a private directory, applies the same substitution to its
`users` file, removes group and world write permission (which FreeRADIUS
requires), and points `RADDB_DIR` at the copy, which the test removes on
exit; the shared build-tree copy MUST NOT be used directly, since its
`users` file contains placeholders. Generated networks
(`REQ-GEN-TEST-010`) reach templates through `@NAME@`, `@NAME_BASE@` and
`@NAME_ADDR@` for every network `NAME` allocated by
`tests/random-vpnnet.sh` (`VPNNET`, `VPNNET6`, and any further network
from `alloc_vpnnet4`/`alloc_vpnnet6`), plus the older aliases `@VPNADDR@`
and `@VPNADDR6@`. When a template uses a `@VPN…@` placeholder whose
variable is not set, the substitution MUST fail the test with a message
naming the placeholder; it MUST NOT substitute an empty string.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/common.sh` (`_subst_placeholders()`, `update_config()`,
`update_config_dir()`, `update_raddb()`); `tests/data/raddb/users`; `update_config` is used by 119 of the test scripts
in `tests/`; placeholder vocabulary documented in AGENTS.md (Test
Structure).
**Acceptance:** code-review, local — confirm the new test's config
template, and any per-user/per-group directory it uses, live under
`tests/data/` and are materialized via `update_config`/`update_config_dir`,
not `cp`'d or hand-written with resolved values; after materialization no
`@PLACEHOLDER@` remains in the generated files. local, negative — call
`update_config` on a template containing `@VPNNET@` without sourcing
`random-vpnnet.sh`; confirm it prints
`FAIL: … uses @VPNNET@ but VPNNET is not set …` and exits 1.
**Links:** REQ-GEN-TEST-010, REQ-GEN-TEST-011

---

### REQ-GEN-TEST-009 — A test MUST terminate every process it started and remove every resource it created, on both the pass and the fail path

**Requirement:** A test that launches an ocserv process tree (main, its
forked workers, sec-mod) MUST ensure every one of those processes is
terminated, and every resource it created (config file, socket-wrapper
directory, PAM-wrapper directory) is removed, regardless of whether the
test passes or fails. The mechanism is not prescribed — `common.sh`'s
`fail()`/`cleanup()`/`cleanup_client_server()` helpers, or an explicit
`trap` — but the outcome MUST hold on every exit path, including an
unexpected early exit. A leaked server process holds its port and
socket/PAM-wrapper directories open, which can cause unrelated later tests
in the same run to fail for a reason that has nothing to do with what they
test.
**Strength:** MUST
**Status:** DERIVED
**Source:** `tests/common.sh:99-104` (`fail()` kills `$PID` before exiting),
`tests/common.sh:183-190` (`cleanup()`), `tests/common.sh:209-231`
(`cleanup_client_server()`), `tests/common.sh:301` (fallback `trap` on the
launch-failure path); `tests/test-pam-abort` as a representative caller
(`PID=$!` captured at launch, `fail $PID "..."` on the failure branch,
`cleanup` on the success path).
**Acceptance:** code-review, local — trace every exit point in the new
test (including the top-level failure of any command not wrapped in
`|| fail ...`) and confirm the server PID(s) captured at launch are killed
on each one. Running the test and checking `ps`/`pgrep ocserv` afterward
MUST show no surviving process.

---

### REQ-GEN-TEST-010 — A test MUST take addresses configured on an interface from the generated-network subsystem and use documentation ranges for all other addresses; it MUST NOT hardcode any other address

**Requirement:** An IPv4 or IPv6 address or network in a test — its
script (including expected values in assertions and failure messages),
its `tests/data/` configuration template, its per-user/per-group
configuration templates, or the RADIUS `users` file — falls in one of
two classes:

  (a) **Configured on an interface**, on the host or in a test's network
      namespace: `ipv4-network`, `ipv6-network`, `explicit-ipv4`,
      `explicit-ipv6`, RADIUS `Framed-IP-Address`/`Framed-IPv6-Prefix`,
      `ns.sh` endpoint addresses, and any other address the test itself
      assigns to an interface. These MUST be derived from the
      variables of the generated-network subsystem (`REQ-GEN-TEST-011`) —
      `VPNNET`, `VPNNET6`, any network from `alloc_vpnnet4`/
      `alloc_vpnnet6` and their `_BASE`/`_ADDR` forms, and for namespace
      tests `ADDRESS`, `CLI_ADDRESS`, `ADDRESS2`, `CLI_ADDRESS2` — and
      reach configuration files through the `REQ-GEN-TEST-008`
      placeholders. Hosts and sub-networks inside a generated IPv4
      network are written relative to it (e.g. `@VPNNET_BASE@.4/30` in a
      template, `${VPNNET_BASE}.10` in a script). This holds even when
      the test creates no TUN device, if its template is shared with a
      test that does.
  (b) **Data only**, never configured on an interface of the machine
      running the test: routes and `no-route`/`iroute` entries pushed to
      a client, DNS/NBNS servers, split-DNS entries, and the address pool
      of a test that creates no TUN device. These MUST either be derived
      from a generated network as in (a) — e.g. a route to, or a DNS
      server in, the VPN network itself — or use documentation ranges:
      `192.0.2.0/24`, `198.51.100.0/24` or `203.0.113.0/24` (RFC 5737);
      `198.18.0.0/15` (RFC 2544) only when a prefix shorter than `/24`
      or more distinct networks than the RFC 5737 ranges provide are
      needed; and `2001:db8::/32` (RFC 3849) for IPv6. Distinct networks
      in the original test MUST stay distinct after conversion.

A test MUST NOT contain any other literal address, so that it can never
collide with the local network of the machine running it.

Out of scope: loopback addresses (`127.0.0.0/8`, `::1`) and
socket_wrapper's interface addresses (`fd00::5357:5f00/120`); the
unspecified addresses and default routes (`0.0.0.0/0`, `::/0`, and
`2000::/3`, which ocserv itself sends to Apple clients as the IPv6
default route);
netmasks and prefix lengths; IPv6 link-local addresses (`fe80::/10`),
which are scoped to one interface and cannot collide; C unit tests
(`tests/*.c`), and shell tests whose addresses are only input data to the
script under test (`tests/test-fw-normalize-route`,
`tests/test-fw-script`).
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/random-vpnnet.sh`, `tests/random-net.sh`,
`tests/check-test-addresses.py`; `tests/test-ipv4-p2p` as the reference
consumer; maintainer decision recorded with this requirement.
**Acceptance:** CI — `tests/check-test-addresses.py`, run by the
`test-addresses-check` job in the `preliminaries` stage of
`.gitlab-ci.yml`, scans every file under `tests/` except C sources,
certificates and the out-of-scope files above, reports each literal outside
the allowed ranges as `file:line: literal`, and passes. local, negative —
add an untracked file under `tests/` containing `VPNNET=192.168.7.0/24` and
confirm the check prints `tests/<file>:<line>: 192.168.7.0` and exits 1.
code-review — for each literal the check accepts
because it is in a documentation range, confirm it is data only (class
(b)); a class (a) value in a documentation range is a finding. local — run
a converted test twice and confirm from its printed banner that different
networks were used and both runs pass.
**Links:** REQ-GEN-TEST-008, REQ-GEN-TEST-011

---

### REQ-GEN-TEST-011 — The generated-network subsystem MUST provide distinct random private networks that no local route overlaps

**Requirement:** The subsystem consists of three shell fragments that a
test sources after `common.sh`:

  (a) `tests/random-vpnnet.sh` MUST allocate `VPNNET`, a random IPv4 `/24`
      from the private ranges of RFC 1918 (`ipcalc -r 24`), and
      `VPNNET6`, a random IPv6 `/112` from the unique-local range
      `fc00::/7` (`ipcalc -r 112`). It MUST define `alloc_vpnnet4 NAME`
      and `alloc_vpnnet6 NAME`, which allocate a further network of the
      same kind into `NAME`. For every allocated `NAME` it MUST set
      `NAME_BASE`, the network address without its last all-zero octet
      (IPv4, e.g. `10.22.134`) or group (IPv6, ending in `:`), and
      `NAME_ADDR`, the server address: the first host address
      (`NAME_BASE` followed by `.1`) for IPv4, and the network address
      itself for IPv6 (`REQ-MAIN-NET-006`), and it MUST append `NAME` to `VPNNET_VARS` so that
      `update_config` substitutes it (`REQ-GEN-TEST-008`). It MUST also
      set `VPNADDR` and `VPNADDR6` to `VPNNET_ADDR` and `VPNNET6_ADDR`.
      It MUST NOT modify `ADDRESS` or `CLI_ADDRESS`, so a test using
      socket_wrapper keeps the loopback address set by `common.sh`.
  (b) `tests/random-net.sh` MUST provide everything in (a) and
      additionally set `ADDRESS` and `CLI_ADDRESS` to random private
      `/32` addresses for use as `ns.sh` endpoints.
  (c) `tests/random-net2.sh`, sourced after (b), MUST additionally set
      `ADDRESS2` and `CLI_ADDRESS2` the same way.

A drawn network or endpoint address MUST be discarded and redrawn while
a route in any routing table of the network namespace running the test
overlaps it, or while it equals a network or address already allocated
by the same test. A route overlaps the drawn prefix when it lies inside
it (`ip route show table all root PREFIX`) or covers it
(`ip route show table all match PREFIX`); this includes the addresses of
local interfaces, which appear in the `local` table. Default-like
covering routes are ignored: `default` and any route whose prefix is
shorter than the private block the draw comes from (`/8` for IPv4, `/7`
for IPv6), such as the `0.0.0.0/1` split default of a VPN client —
otherwise every draw would be rejected on such a host. `ip` is looked up
in `PATH`, with `/usr/sbin` and `/sbin` appended.

The check MUST fail closed: if `ip` exits non-zero, the subsystem MUST
print the failing command and `exit 1`; it MUST NOT treat a failed query
as "no route". If 100 consecutive draws for one variable are rejected,
it MUST print that no free network was found and `exit 1` rather than
loop forever. It MUST print every allocated network and address to
standard output, so that a failing test's log identifies them
(`REQ-GEN-TEST-001`(c)).

Known limitations, accepted as-is: networks reachable only through a
default-like route (e.g. a remote site behind the default gateway) are
not detected — the more specific route to the generated network wins on
the test host, and `ns.sh` configures it in isolated namespaces anyway;
and two tests running in parallel may draw the same network (the IPv4
draw space is about 70,000 `/24` networks).
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/random-vpnnet.sh` (`_is_routed()`, `_alloc_vpnnet()`,
`_alloc_addr()`), `tests/random-net.sh`, `tests/random-net2.sh`,
`tests/common.sh` (`_subst_placeholders()`)
**Acceptance:** local — with `ADDRESS=127.0.0.2` set, source
`random-vpnnet.sh`, call `alloc_vpnnet4 VPNNET2`, and confirm: `ADDRESS`
is unchanged and `CLI_ADDRESS` unset; `"${VPNNET_BASE}.0/24" = "$VPNNET"`
and `VPNADDR = VPNNET_ADDR = ${VPNNET_BASE}.1`; `VPNNET6` ends in `/112`
and `VPNADDR6` equals the network address of `VPNNET6`; `VPNNET2 != VPNNET`; and a template
containing `@VPNNET2@ @VPNNET2_BASE@.9 @VPNNET2_ADDR@` is materialized by
`update_config` with those values. Source `random-net.sh` and confirm
`ADDRESS` and `CLI_ADDRESS` are set to addresses different from
`127.0.0.2`. In a fresh network namespace with routes covering
`10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/17` and a `0.0.0.0/1`
route, confirm `VPNNET` falls in `192.168.128.0/17`. With an `ip` in
`PATH` that exits 1, confirm the subsystem prints the failing command
and exits 1. CI — every test sourcing the subsystem prints the allocated
networks in its log.
**Links:** REQ-GEN-TEST-008, REQ-GEN-TEST-010, REQ-GEN-TEST-012

---

### REQ-GEN-TEST-012 — `ipcalc` and `ip` are hard test dependencies; their absence MUST fail the test, not skip it

**Requirement:** The generated-network subsystem (`REQ-GEN-TEST-011`)
MUST use `ipcalc-ng`, falling back to `ipcalc`, found in `PATH`, and
`ip` (iproute2), found in `PATH` with `/usr/sbin` and `/sbin` appended.
When no `ipcalc` is found, it MUST print `ipcalc was not found` and
`exit 1`; when `ip` is not found, it MUST print `ip was not found` and
`exit 1`. It MUST NOT `exit 77`: both are listed among the test build
dependencies in `README.md` and are present in every CI image, so their
absence is a broken test environment, and skipping would silently drop
the coverage of every test that uses the subsystem (`REQ-GEN-TEST-006`).
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/random-vpnnet.sh` (`ipcalc` and `ip` lookup);
`README.md` (build dependencies: `ipcalc-ng` and `iproute2` on
Debian/Ubuntu, `ipcalc` and `iproute` on Fedora/RHEL)
**Acceptance:** local — run a test that sources `random-vpnnet.sh` with a
`PATH` that contains neither `ipcalc` nor `ipcalc-ng`; confirm it prints
`ipcalc was not found` and exits 1. Likewise, with `ipcalc` available
but no `ip` in `PATH`, `/usr/sbin` or `/sbin` (e.g. in a container
without iproute2), confirm it prints `ip was not found` and exits 1.
**Links:** REQ-GEN-TEST-005, REQ-GEN-TEST-006, REQ-GEN-TEST-011

---

### REQ-GEN-TEST-013 — State a test or its client script keeps between steps MUST live in a file no other test uses; it MUST NOT use a fixed name shared by several tests

**Requirement:** Tests run in parallel from the same `build/tests`
directory (`REQ-GEN-TEST-007`), so a file with a fixed name in the working
directory is shared by every test that uses it. State that a test, or a
helper it runs, writes in one step and reads back in a later one MUST be
kept in a file that no other test writes: a file used by a single test may
have a fixed name that identifies that test (e.g. `test-iroute.tmp` in
`tests/test-iroute`), while a helper run by several tests MUST take the
file name from the calling test. In particular the
default route that `tests/scripts/vpnc-script` saves on connect and
restores on disconnect MUST be stored in the file named by
`DEFAULT_ROUTE_FILE`, which `tests/common.sh` MUST export as
`./defaultroute.<test name>.<test PID>`; the script MUST fall back to
`./defaultroute` only when `DEFAULT_ROUTE_FILE` is unset (manual use
outside the test suite). Otherwise one test's client can restore another
test's route in its own namespace (`Cannot find device "ocen1c<pid>"`),
leaving the client with no route to the server and the test hanging until
the meson timeout.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `tests/scripts/vpnc-script` (`DEFAULT_ROUTE_FILE`,
`set_default_route()`, `reset_default_route()`), `tests/common.sh`
(`DEFAULT_ROUTE_FILE` export); CI job 16818030683, where `disconnect-user`
timed out after restoring the default route saved by `disconnect-user2`.
**Acceptance:** code-review, local — confirm that `tests/common.sh`
exports `DEFAULT_ROUTE_FILE` containing `$$`, that `vpnc-script` honours
it, and that no inter-step state file in the working directory is written
by more than one test, whether directly or through a shared helper script
or template. Running `disconnect-user` and
`disconnect-user2` concurrently (`meson test -C build disconnect-user
disconnect-user2 --repeat 10`) MUST show no `Cannot find device` message
in either test's log and no timeout.
**Links:** REQ-GEN-TEST-007, REQ-GEN-TEST-009
