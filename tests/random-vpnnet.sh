#!/bin/bash
#
# Copyright (C) 2023 Nikos Mavrogiannopoulos
#
# This file is part of ocserv.
#
# ocserv is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# ocserv is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This script generates random IPv4 and IPv6 networks, which no local
# route overlaps, for use with the VPN; see REQ-GEN-TEST-010 and REQ-GEN-TEST-011. It does not touch ADDRESS
# or CLI_ADDRESS; tests using ns.sh should include random-net.sh instead.
# Usage:
#
#   . `dirname $0`/common.sh
#   . `dirname $0`/random-vpnnet.sh
#   alloc_vpnnet4 VPNNET2        # only if a second network is needed
#   update_config test.config    # uses @VPNNET@, @VPNNET_BASE@, @VPNNET2@, ...
#
# Provides:
#   VPNNET      - random IPv4 /24 network, e.g., 10.22.134.0/24
#   VPNNET_BASE - VPNNET without its last octet, e.g., 10.22.134; use it
#                 to derive addresses and sub-networks within VPNNET
#   VPNNET_ADDR - the first host address of VPNNET (also as VPNADDR)
#   VPNNET6     - random IPv6 /112 network
#   VPNNET6_BASE, VPNNET6_ADDR (also as VPNADDR6) - likewise for VPNNET6
#   alloc_vpnnet4 NAME, alloc_vpnnet6 NAME - allocate a further network,
#                 distinct from the ones already allocated, into NAME,
#                 NAME_BASE and NAME_ADDR. Every allocated NAME is
#                 substituted by update_config as @NAME@, @NAME_BASE@ and
#                 @NAME_ADDR@.

IPCALC=$(command -v ipcalc-ng)
if test -z "${IPCALC}"; then
	IPCALC=$(command -v ipcalc)
fi

if test -z "${IPCALC}"; then
	echo "ipcalc was not found"
	exit 1
fi

IP=$(PATH="${PATH}:/usr/sbin:/sbin" command -v ip)
if test -z "${IP}"; then
	echo "ip was not found"
	exit 1
fi

# _route_query match|root PREFIX: sets _routes to the routes, in any table,
# that cover (match) or lie inside (root) PREFIX. A failed query must not be
# mistaken for "no route", so it aborts the test.
_route_query() {
	case "$2" in
		*:*) _family=-6;;
		*) _family=-4;;
	esac
	_routes=$(${IP} ${_family} route show table all $1 "$2") || {
		echo "FAIL: '${IP} ${_family} route show table all $1 $2' failed; cannot check the local routes" >&2
		exit 1
	}
}

# _is_routed PREFIX MINLEN: succeeds if a local route or address overlaps
# PREFIX. Covering routes shorter than MINLEN (the private block drawn
# from) are default-like, e.g. a VPN client's 0.0.0.0/1, and are ignored.
_is_routed() {
	_route_query root "$1"
	test -n "${_routes}" && return 0
	_route_query match "$1"
	printf '%s\n' "${_routes}" | awk -v min="$2" '
		NF == 0 { next }
		$1 ~ /^(unicast|local|broadcast|multicast|anycast|unreachable|blackhole|prohibit|throw|nat)$/ {
			$0 = substr($0, length($1) + 2)
		}
		$1 == "default" { next }
		$1 ~ /\// { split($1, a, "/"); if (a[2] + 0 < min) next }
		{ found = 1 }
		END { exit !found }'
}

# _draw_ok TRIES CANDIDATE: fails if CANDIDATE was already allocated by
# this test; aborts the test after 100 draws
_draw_ok() {
	if test "$1" -gt 100; then
		echo "FAIL: no unrouted network found for ${_name} after 100 draws" >&2
		exit 1
	fi
	case " ${_VPNNETS_ALLOCATED} " in
		*" $2 "*) return 1;;
	esac
	return 0
}

# _alloc_vpnnet NAME PREFIX MINLEN: draws a random private network of the
# given prefix which no local route overlaps and which was not already
# allocated by this test
_alloc_vpnnet() {
	_name=$1
	_tries=0
	while :; do
		_tries=$((_tries + 1))
		eval $(${IPCALC} -r $2 -np)
		_draw_ok ${_tries} "${NETWORK}" || continue
		_is_routed "${NETWORK}/${PREFIX}" $3 || break
		echo "VPN network $1: ${NETWORK}/${PREFIX} overlaps a local route, redrawing"
	done
	# the network address minus its last all-zero group or octet;
	# for IPv6 it ends in ':', so BASE + host number is an address
	if test "$2" = 24; then
		_base="${NETWORK%.0}"
		_addr="${_base}.1"
	else
		_base="${NETWORK%0}"
		_addr="${_base}1"
	fi
	_VPNNETS_ALLOCATED="${_VPNNETS_ALLOCATED} ${NETWORK}"
	VPNNET_VARS="${VPNNET_VARS} $1"
	eval "$1=\"${NETWORK}/${PREFIX}\""
	eval "$1_BASE=\"${_base}\""
	eval "$1_ADDR=\"${_addr}\""
	echo "VPN network $1: ${NETWORK}/${PREFIX} (server address ${_addr})"
}

# _alloc_addr NAME: draws a random private address, for an ns.sh endpoint,
# which no local route overlaps and which was not already allocated
_alloc_addr() {
	_name=$1
	_tries=0
	while :; do
		_tries=$((_tries + 1))
		eval $(${IPCALC} -r 32 --minaddr)
		_draw_ok ${_tries} "${MINADDR}" || continue
		_is_routed "${MINADDR}/32" 8 || break
	done
	_VPNNETS_ALLOCATED="${_VPNNETS_ALLOCATED} ${MINADDR}"
	eval "$1=\"${MINADDR}\""
}

alloc_vpnnet4() {
	_alloc_vpnnet $1 24 8
}

alloc_vpnnet6() {
	_alloc_vpnnet $1 112 7
}

echo "**************************"
alloc_vpnnet4 VPNNET
alloc_vpnnet6 VPNNET6
echo "**************************"
VPNADDR=${VPNNET_ADDR}
VPNADDR6=${VPNNET6_ADDR}
