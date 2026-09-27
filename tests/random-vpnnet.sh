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

# This script generates random IPv4 and IPv6 networks for use with the
# VPN; see REQ-GEN-TEST-010 and REQ-GEN-TEST-011. It does not touch ADDRESS
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

PINGOPS="-W 1 -c 2"

# _alloc_vpnnet NAME PREFIX: draws a random private network of the given
# prefix whose first host address does not answer ping and which was not
# already allocated by this test
_alloc_vpnnet() {
	while :; do
		eval $(${IPCALC} -r $2 -np)
		case " ${_VPNNETS_ALLOCATED} " in
			*" ${NETWORK} "*) continue;;
		esac
		# the network address minus its last all-zero group or octet;
		# for IPv6 it ends in ':', so BASE + host number is an address
		if test "$2" = 24; then
			_base="${NETWORK%.0}"
			_addr="${_base}.1"
		else
			_base="${NETWORK%0}"
			_addr="${_base}1"
		fi
		ping ${PINGOPS} ${_addr} >/dev/null 2>&1 || break
	done
	_VPNNETS_ALLOCATED="${_VPNNETS_ALLOCATED} ${NETWORK}"
	VPNNET_VARS="${VPNNET_VARS} $1"
	eval "$1=\"${NETWORK}/${PREFIX}\""
	eval "$1_BASE=\"${_base}\""
	eval "$1_ADDR=\"${_addr}\""
	echo "VPN network $1: ${NETWORK}/${PREFIX} (server address ${_addr})"
}

alloc_vpnnet4() {
	_alloc_vpnnet $1 24
}

alloc_vpnnet6() {
	_alloc_vpnnet $1 112
}

echo "**************************"
alloc_vpnnet4 VPNNET
alloc_vpnnet6 VPNNET6
echo "**************************"
VPNADDR=${VPNNET_ADDR}
VPNADDR6=${VPNNET6_ADDR}
