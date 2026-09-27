#!/usr/bin/env python3
"""
Check that tests do not hard-code IP addresses or networks
(REQ-GEN-TEST-010).

A test must take any network or address configured on an interface from
tests/random-vpnnet.sh (via @VPNNET@-style placeholders or variables), and
must use documentation ranges for addresses that are only data (routes,
DNS servers, pools of tests that create no TUN device). This script scans
the tracked files under tests/ and reports every IPv4/IPv6 literal outside
the allowed ranges below.

Exit code: 0 on success, 1 if any errors are found.
"""

import ipaddress
import re
import subprocess
import sys
from pathlib import Path

ALLOWED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        # documentation ranges (RFC 5737, RFC 3849)
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
        # benchmarking range (RFC 2544), for prefixes shorter than /24
        "198.18.0.0/15",
        # loopback, used by socket_wrapper and local listeners
        "127.0.0.0/8",
        "::1/128",
        # socket_wrapper's IPv6 interface addresses (FD00::5357:5FXX)
        "fd00::5357:5f00/120",
        # link-local IPv6 is scoped to the interface and cannot collide
        "fe80::/10",
        # 2000::/3, sent by ocserv itself as the IPv6 default route of
        # Apple clients (src/worker-vpn.c)
        "2000::/128",
    )
]

# Files whose addresses are input data to the script under test rather
# than networks configured by the test (REQ-GEN-TEST-010, out of scope).
EXEMPT = {
    "tests/test-fw-normalize-route",
    "tests/test-fw-script",
}

SKIP_SUFFIXES = {
    ".c", ".h", ".py", ".md", ".txt", ".supp", ".pem", ".der", ".crl",
    ".key", ".p12", ".csr", ".tmpl", ".json",
}
SKIP_NAMES = {"meson.build"}

IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:])")


def is_netmask(addr):
    """True for contiguous IPv4 netmasks such as 255.255.255.0."""
    if addr.version != 4:
        return False
    value = int(addr)
    inverted = ~value & 0xFFFFFFFF
    return inverted & (inverted + 1) == 0


def offending(literal):
    try:
        addr = ipaddress.ip_address(literal)
    except ValueError:
        return False
    if addr.is_unspecified or is_netmask(addr):
        return False
    return not any(addr in net for net in ALLOWED_NETWORKS
                   if net.version == addr.version)


def candidate_files(root):
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others",
                              "--exclude-standard", "tests"], cwd=root,
                             capture_output=True, text=True,
                             check=True).stdout
        return out.splitlines()
    except (OSError, subprocess.CalledProcessError):
        # no git, or git refusing the checkout (e.g., dubious ownership in CI)
        return [str(p.relative_to(root)) for p in (root / "tests").rglob("*")
                if p.is_file()]


def scanned_files(root):
    for name in candidate_files(root):
        path = Path(name)
        if path.suffix in SKIP_SUFFIXES or path.name in SKIP_NAMES:
            continue
        if path.parts[:2] == ("tests", "certs"):
            continue
        if name in EXEMPT:
            continue
        yield name


def check_file(root, name):
    errors = []
    try:
        text = (root / name).read_text()
    except UnicodeDecodeError:
        return errors
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith(";"):
            continue
        if re.search(r"oid\s*=", line, re.IGNORECASE):
            continue
        # addresses inside regular expressions, e.g. grep "1\.2\.3\.4"
        line = line.replace("\\.", ".")
        for regex in (IPV4_RE, IPV6_RE):
            for m in regex.finditer(line):
                if offending(m.group(1)):
                    errors.append(f"{name}:{lineno}: {m.group(1)}")
    return errors


def main():
    root = Path(__file__).resolve().parent.parent
    failures = []
    for name in scanned_files(root):
        failures.extend(check_file(root, name))

    if failures:
        print("Hard-coded addresses in tests (REQ-GEN-TEST-010): use "
              "random-vpnnet.sh placeholders for networks configured on an "
              "interface, or documentation ranges (192.0.2.0/24, "
              "198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) for data.")
        for f in failures:
            print(f"  {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
