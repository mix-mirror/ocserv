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

# This test suite currently covers the ipv4 scenario only.
# The ipv6 features of ocserv-fw will not be tested here.

function tear_down_test_env() {
	if [[ $(ip link show "${OCSERV_SERVER_VETH_DEV}" \
		&> /dev/null;echo $?) == 0 ]]; then
		ip link del "${OCSERV_SERVER_VETH_DEV}"
	fi
		ip netns del ${OCSERV_CLIENT_NAMESPACE} &> /dev/null
		return 0
}

function set_up_test_env() {

	# clean up any lingering config
	tear_down_test_env

	# create the ocserv client namespace
	ip netns add ${OCSERV_CLIENT_NAMESPACE}

	# bring up loopback interface in namespace
	ip netns exec ${OCSERV_CLIENT_NAMESPACE} ip link set dev lo up

	# add some veth interfaces
	ip link add ${OCSERV_SERVER_VETH_DEV} type veth \
		peer name ${OCSERV_CLIENT_VETH_DEV}

	# add server and client interfaces to namespace
	ip link set ${OCSERV_CLIENT_VETH_DEV} netns ${OCSERV_CLIENT_NAMESPACE}

	# bring client interface an up and assign ip
	ip netns exec ${OCSERV_CLIENT_NAMESPACE} \
		ip link set ${OCSERV_CLIENT_VETH_DEV} up
	ip netns exec ${OCSERV_CLIENT_NAMESPACE} \
		ip addr add ${OCSERV_CLIENT_IPADDR} dev \
			${OCSERV_CLIENT_VETH_DEV}

	# bring server interface an up - assign ip
	ip link set ${OCSERV_SERVER_VETH_DEV} up
	ip addr add ${OCSERV_SERVER_IPADDR} dev ${OCSERV_SERVER_VETH_DEV}

	# configure default gateway in client namespace
	ip netns exec ${OCSERV_CLIENT_NAMESPACE} \
		ip r add default via ${OCSERV_CLIENT_GATEWAY}
}

##############
# Assertions #
##############

function assert4_forwarding_is_configured() {
	echo "Assert forwarding is enabled:"
	if [[ $(cat /proc/sys/net/ipv4/ip_forward) == "0" ]];then
		echo -e "->  FAIL: Forwarding is not enabled.\n"
		return 1
	else
		echo -e "->  PASS: Fowarding is enabled.\n"
	fi
}

# If the forward policy is not DROP, then and and all
# traffic will likely be allowed through - negating our testing.
function assert4_forward_chain_policy_is_drop() {
	echo "Assert FORWARD chain policy is DROP:"
	if [[ $(iptables -S FORWARD | grep -q "P FORWARD DROP"; echo $?) == 1 ]] 
	then
		echo -e "->  FAIL: FOWARD chain policy is not set to DROP.\n"
		return 1
	else
		echo -e "->  PASS: FORWARD chain policy is set to DROP.\n"
	fi
}

# Source NATing must currently be configured manually.
# The following command should suffice:
# iptables -t nat -A POSTROUTING \
#   -s <ipv4-client-ip> ! -d <ipv4-network> -j MASQUERADE
function assert4_snat_is_configured() {
	echo "Assert Source NAT is configured:"
	local has_snat=$(
		iptables -t nat -S POSTROUTING | grep MASQUERADE \
		| grep -q $(echo ${OCSERV_CLIENT_IPADDR} \
		| sed 's/\/24/\/32/g'); echo $?)

	if [[ ${has_snat} == 1 ]];then
		echo -e "->  FAIL: No source NAT configuration for \
		${OCSERV_CLIENT_IPADDR}.\n"
		return 1
	else
		echo -e "->  PASS: Source NAT exists for \
${OCSERV_CLIENT_IPADDR}.\n"
	fi
}

function assert4_allowed_routes_are_reachable_on_allowed_ports() {
	echo "Assert allowed routes are reachable on allowed ports:"

	if [[ -z ${OCSERV_ROUTES4+x} ]]; then
		echo -e "->  FAIL: OCSERV_ROUTES4 is not set."
		return 1
	elif [[ -z "${OCSERV_ROUTES4}" ]]; then
		echo -e "->  FAIL: OCSERV_ROUTES4 is empty."
		return 1
	else
		# Test the other routes in $OCSERV_ROUTES4
		# We are specifically passing /32 routes only so that we can 
		# deal with a single address in a network.
		set ${OCSERV_ALLOW_PORTS}
		while [[ $# -gt 1 ]]; do
			proto=$1
			port=$2
			for route in ${OCSERV_ROUTES4}; do
			# strip off netmask
			local r=$(echo ${route}|sed 's/\/255\.255\.255\.255//g')
			if [[ $(ip netns exec ${OCSERV_CLIENT_NAMESPACE} \
				curl -Is $r:$port \
					--connect-timeout 2 &> /dev/null; \
					echo $?) == "0" ]];then
						echo -e "->  PASS: \
($r on $port/$proto)"
			else
				echo -e "->  FAIL: ($r on $port/$proto)"
			fi
			done

			if [[ $# -gt 1 ]];then
				shift 2
			else
				break
			fi
		done
	fi
	echo ""
}

function assert4_allowed_routes_are_not_reachable_on_other_ports() {
	echo "Assert allowed routes are not \
reachable on other ports (i.e. ports not in OCSERV_ALLOW_PORTS):"

	OTHER_PORTS="tcp 8080 tcp 8443"

	if [[ -z ${OCSERV_ROUTES4+x} ]]; then
		echo -e "->  FAIL: OCSERV_ROUTES4 is not set."
		return 1
	elif [[ -z "${OCSERV_ROUTES4}" ]]; then
		echo -e "->  FAIL: OCSERV_ROUTES4 is empty."
		return 1
	else
		# Test the other routes in $OCSERV_ROUTES4
		# We are specifically passing /32 routes only so that we can 
		# deal with a single address in a network.
		set ${OTHER_PORTS}
		while [[ $# -gt 1 ]]; do
			proto=$1
			port=$2
			for route in ${OCSERV_ROUTES4}; do
				# strip off netmask
				local r=$(echo ${route}\
					|sed 's/\/255\.255\.255\.255//g')

				local curl_status=$(ip netns exec \
					${OCSERV_CLIENT_NAMESPACE} \
					curl -Is $r:$port --connect-timeout 2 \
					&> /dev/null; echo $?)

				if [[ ${curl_status}  == "7" ]];then
					echo -e "->  PASS: \
($r unreachable on $port/$proto)"
				else
					echo -e "->  FAIL: \
($r reachable on $port/$proto)"
				fi
			done

			if [[ $# -gt 1 ]];then
				shift 2
			else
				break
			fi
		done
	fi
	echo ""
}

function assert4_disallowed_routes_are_not_reachable_on_allowed_ports() {
	echo "Assert disallowed routes are not reachable allowed ports:"

	if [[ -z ${OCSERV_NO_ROUTES4+x} ]]; then
		echo -e "->  FAIL: OCSERV_NO_ROUTES4 is not set."
		return 1
	elif [[ -z "${OCSERV_NO_ROUTES4}" ]]; then
		echo -e "->  FAIL: OCSERV_NO_ROUTES4 is empty."
		return 1
	else
		set ${OCSERV_ALLOW_PORTS}
		while [[ $# -gt 1 ]]; do
			proto=$1
			port=$2
			for route in ${OCSERV_NO_ROUTES4}; do
				# strip off netmask
				local r=$(echo ${route}\
					|sed 's/\/255\.255\.255\.255//g')

				local curl_status=$(ip netns exec \
					${OCSERV_CLIENT_NAMESPACE} \
					curl -Is $r:$port --connect-timeout 2 \
					&> /dev/null; echo $?)

				# https://curl.haxx.se/libcurl/c/libcurl-errors.html
				if [[ ${curl_status} == "28" ]];then
					echo -e "->  PASS: \
($r unreachable on $port/$proto)"
				else
					echo -e "->  FAIL: \
($r reachable on $port/$proto)"
				fi
			done

			if [[ $# -gt 1 ]];then
				shift 2
			else
				break
			fi
		done
	fi
	echo ""
}

function assert4_dns_servers_are_reachable() {
	echo "Assert IPv4 DNS servers are reachable:"
	
	if [[ -z ${OCSERV_DNS4+x} ]]; then
		echo -e "->  FAIL: OCSERV_DNS4 is not set."
		return 1
	elif [[ -z "${OCSERV_DNS4}" ]]; then
		echo -e "->  FAIL: OCSERV_DNS4 is empty."
		return 1
	else
		has_dig=$(which dig &> /dev/null;echo $?)
		has_drill=$(which drill &> /dev/null;echo $?)
		has_host=$(which host &> /dev/null;echo $?)
		
		if [[ ${has_dig} == 0 ]];then
			for host in ${OCSERV_DNS4};do
				status=$(ip netns exec ${OCSERV_CLIENT_NAMESPACE} dig +short -t a gitlab.com @${host} &> /dev/null;echo $?)
				if [[ $status == 0 ]]; then
					echo \
					"->  PASS: Queried: ${host}"
				else
					echo \
					"->  FAIL: Could not reach ${host}"
				fi
			done
		elif [[ ${has_drill} == 0 ]];then
			for host in ${OCSERV_DNS4};do
				status=$(ip netns exec ${OCSERV_CLIENT_NAMESPACE} drill @gitlab.com ${host} a &> /dev/null;echo $?)
				if [[ $status == 0 ]]; then
					echo \
					"->  PASS: Queried: ${host}"
				else
					echo \
					"->  FAIL: Could not reach ${host}"
				fi
			done
		elif [[ ${has_host} == 0 ]];then
			for host in ${OCSERV_DNS4};do
				status=$(ip netns exec ${OCSERV_CLIENT_NAMESPACE} host -t a google.com ${host} &> /dev/null;echo $?)
				if [[ $status == 0 ]]; then
					echo \
					"->  PASS: Queried: ${host}"
				else
					echo \
					"->  FAIL: Could not reach ${host}"
				fi
			done
		else
			echo "->  FAIL: No suitable DNS lookup utility found."
		fi
	fi
	echo ""
}

function assert4_ocserv_host_tun_accepts_icmp_rejects_all_else() {

	echo "Assert ocserv host tun interface only accepts ICMP from peer:"
	
	local ports="1111 2222 3333"
	local err_count=0
	
	for p in ${ports};do
		nc -l ${OCSERV_CLIENT_GATEWAY} $p &> /dev/null&
		status=$(echo EOF | ip netns exec ${OCSERV_CLIENT_NAMESPACE} nc -w 3 --send-only ${OCSERV_CLIENT_GATEWAY} $p &> /dev/null;echo $?)
		if [[ ${status} == 1 ]];then
			((err_count-=1))
		else
			((err_count+=1))
		fi
	done

	if [[ ${err_count} == -3 ]];then
		ping_status=$(ip netns exec ${OCSERV_CLIENT_NAMESPACE} ping -c 4 -q ${OCSERV_CLIENT_GATEWAY} &> /dev/null;echo $?)
		if [[ $ping_status == 0 ]];then
			echo "->  PASS: Ocserv tun interface only accepts ICMP traffic."
		else
			echo "->  FAIL: Ocserv tun interface rejects all traffic _including_ ICMP."
		fi
	else
		echo "->  FAIL: Ocserv tun interface accepted traffic to one or more of these TCP ports: ${ports}"
	fi
	
	echo ""
	
}

if [[ ${REASON} == "disconnect" ]];then
	tear_down_test_env
	exit 0
fi

set_up_test_env

# Run the tests
assert4_forwarding_is_configured
assert4_forward_chain_policy_is_drop
assert4_snat_is_configured
assert4_allowed_routes_are_reachable_on_allowed_ports
assert4_allowed_routes_are_not_reachable_on_other_ports
assert4_disallowed_routes_are_not_reachable_on_allowed_ports
assert4_dns_servers_are_reachable
assert4_ocserv_host_tun_accepts_icmp_rejects_all_else
# <TODO>
# ipv6 assertions
# </TODO>

# Allow 30 seconds for observing iptables chains before tearing the
# test environment down - useful for debugging.
# sleep 30s

# Perform clean up

export REASON=disconnect
export OCSERV_NEXT_SCRIPT="${0}"
/bin/sh $OCSERV_FW_PATH

tear_down_test_env
