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

# This script generates a pair of random client and server addresses and
# two (IPv4+IPv6) random network addresses for use with the VPN (via
# random-vpnnet.sh); it sets variables needed by ns.sh. For tests that need
# two server sets include additionally random-net2.sh. Tests that do not use
# ns.sh should include random-vpnnet.sh instead.

. "$(dirname "$0")/random-vpnnet.sh"

_alloc_addr ADDRESS
_alloc_addr CLI_ADDRESS

echo "**************************"
echo "Client address: $CLI_ADDRESS"
echo "Server address: $ADDRESS"
echo "**************************"
