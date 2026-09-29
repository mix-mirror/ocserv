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

# This script generates an additional pair of random server and client
# addresses for use by ns.sh. It is intended to be used by tests that
# require two separate ocserv instances and clients.

if ! type _alloc_addr >/dev/null 2>&1; then
	echo "random-net2.sh must be sourced after random-net.sh"
	exit 1
fi

_alloc_addr ADDRESS2
_alloc_addr CLI_ADDRESS2

echo "**************************"
echo "Client address2: $CLI_ADDRESS2"
echo "Server address2: $ADDRESS2"
echo "**************************"
