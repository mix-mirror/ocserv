#!/usr/bin/env bash

# Copyright (C) 2016  Lance LeFlore

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# About this test suite:
# 
# This test suite exploits Linux kernel network namespaces in order to
# provide a fake tun interface (${DEVICE}) for ocserv-fw to create packet 
# filtering rules against. This approach has the advantage of not requiring
# a functional instance of ocserv in order to test ocserv-fw's 
# functionality. Iptables does not (appear to) care whether the device
# used in the filtering/nat chains is a true tun interface or a 
# virtual ethernet (veth) interface.
#
# In a nutshell, ${0} kicks off the suite by first exporting most of the 
# environment variables that ocserv-fw needs. It then calls 
# ocserv-fw-assertions.sh which sets up an isolated network namespace so that we
# can simulate what ocserv-fw would do with a tun interface, 
# ocserv-fw-assertions.sh then calls ocserv-fw, runs a few curl commands against
# some addresses and ports, checks the exit status of libcurl and then calls 
# ocserv-fw once more to clean up the iptables chains.
#
# To run the test suite: 
# 1) Ensure forwarding is enabled (echo 1 > /proc/sys/net/ipv4/ip_forward)
# 2) Create a source NAT for ${OCSERV_CLIENT_IPADDR}:
#   - iptables -t nat -A POSTROUTING -s <ipv4-client-ip> \
# ! -d <ipv4-network> -j MASQUERADE
# 3) Ensure the FORWARD filter chain policy is 'DROP':
#   - iptables -P FORWARD DROP
# 4) Execute ${0}
#
# If you run into issues with the test, it may be useful to 'set -x' in ${0} as
# well as in the assertions script. It is also useful to enable a sleep in the
# assertions script that occurs just before cleaning up the testing environment;
# this will give you time to run the curl commands in the network namespace and
# or view the iptables chains statuses before their states are reset.

export DEVICE=vpns0
# Use nameservers from host
# TODO: Handle cases of 'nameserver 127.0.0.1'
export OCSERV_DNS4=$(egrep 'nameserver\s' /etc/resolv.conf | cut -d ' ' -f2)
export OCSERV_DNS=${OCSERV_DNS4}
# ipv4.icanhazip.com
export OCSERV_ROUTES4="
64.182.208.181/255.255.255.255
64.182.208.182/255.255.255.255
"
# gitlab.com
export OCSERV_NO_ROUTES4="104.210.2.228/255.255.255.255"
export OCSERV_ALLOW_PORTS="tcp 80 tcp 443"
export OCSERV_RESTRICT_TO_ROUTES=1
export OCSERV_ROUTES=${OCSERV_ROUTES4}
export REASON=connect
export OCSERV_FW_PATH=../../src/ocserv-fw
export OCSERV_CLIENT_NAMESPACE=ocserv
export OCSERV_CLIENT_VETH_DEV=vethclient
export OCSERV_CLIENT_IPADDR="10.0.0.2/24"
export OCSERV_SERVER_VETH_DEV=${DEVICE}
export OCSERV_SERVER_IPADDR="10.0.0.1/24"
export OCSERV_CLIENT_GATEWAY=$(echo ${OCSERV_SERVER_IPADDR} | cut -d '/' -f1 )

if test "$(which assertions.sh &> /dev/null;echo $?)" = 1; then
	export OCSERV_NEXT_SCRIPT=./assertions.sh
else
	export OCSERV_NEXT_SCRIPT=$(which assertions.sh)
fi

if test "$(which ocserv-fw &> /dev/null;echo $?)" = 1;then
	/bin/sh ${OCSERV_FW_PATH}
else
	export OCSERV_FW_PATH=$(which ocserv-fw)
	ocserv-fw
fi
