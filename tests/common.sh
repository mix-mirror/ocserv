#!/bin/bash
#
# Copyright (C) 2011-2013 Free Software Foundation, Inc.
# Copyright 2013 Nikos Mavrogiannopoulos
#
# This file is part of ocserv.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

builddir=${builddir:-.}

OPENCONNECT=${OPENCONNECT:-$(command -v openconnect)}

# Tests run in parallel from the same directory; give each run its own
# file for the default route that scripts/vpnc-script saves and restores.
export DEFAULT_ROUTE_FILE="./defaultroute.$(basename "$0").$$"

if test -z "${OPENCONNECT}" || ! test -x ${OPENCONNECT};then
	echo "You need openconnect to run this test"
	exit 1
fi

if test "${DISABLE_ASAN_BROKEN_TESTS}" = 1;then
	echo "Disabling worker isolation to enable asan"
	ISOLATE_WORKERS=false
fi

if test -z "${NO_NEED_ROOT}";then
	if test "$(id -u)" != "0";then
		echo "You need to run this script as root"
		exit 77
	fi
fi

# Increase verbosity as this disables the anti-debugging measures
# of the worker processes.
if test "${COVERAGE}" = "1" && test -z "${VERBOSE}";then
	VERBOSE=1
fi

# NO_NEED_ROOT implies NEED_SOCKET_WRAPPER
if test "${NEED_SOCKET_WRAPPER}" = 1 || test "${NO_NEED_ROOT}" = 1;then
	SOCKDIR="sockwrap.$$.tmp"
	mkdir -p $SOCKDIR
	export SOCKET_WRAPPER_DIR=$SOCKDIR
	export SOCKET_WRAPPER_DEFAULT_IFACE=2
	export NSS_WRAPPER_HOSTS="${srcdir}/data/vhost.hosts"
	ADDRESS=127.0.0.$SOCKET_WRAPPER_DEFAULT_IFACE
	RAW_OPENCONNECT="${OPENCONNECT}"
	OPENCONNECT="eval LD_PRELOAD=libsocket_wrapper.so ${OPENCONNECT}"

	if test "${DISABLE_ASAN_BROKEN_TESTS}" = 1;then
		echo "Skipping test requiring ldpreload"
		exit 77
	fi
fi

# value_of NAME: prints the value of the variable called NAME
value_of() {
	eval "printf '%s' \"\${$1}\""
}

_subst_placeholders() {
	username=$(whoami)
	group=$(groups|cut -f 1 -d ' ')

	if test -z "${ISOLATE_WORKERS}";then
		if test "${COVERAGE}" = "1";then
			ISOLATE_WORKERS=false
		else
			ISOLATE_WORKERS=true
		fi
	fi

	# a VPN network placeholder without a value would silently produce
	# a broken config; see REQ-GEN-TEST-008
	for _var in $(grep -o '@VPN[A-Z0-9_]*@' "$1" | tr -d @ | sort -u); do
		if test -z "$(value_of ${_var})"; then
			echo "FAIL: $1 uses @${_var}@ but ${_var} is not set; source random-vpnnet.sh (or random-net.sh) before update_config" >&2
			exit 1
		fi
	done

	vpnnet_subst=""
	for _net in ${VPNNET_VARS}; do
		for _var in ${_net} ${_net}_BASE ${_net}_ADDR; do
			vpnnet_subst="${vpnnet_subst} -e s|@${_var}@|$(value_of ${_var})|g"
		done
	done

	sed -i ${vpnnet_subst} \
	       -e 's|@USERNAME@|'${username}'|g' \
	       -e 's|@GROUP@|'${group}'|g' \
	       -e 's|@SRCDIR@|'${srcdir}'|g' \
	       -e 's|@ISOLATE_WORKERS@|'${ISOLATE_WORKERS}'|g' \
	       -e 's|@OTP_FILE@|'${OTP_FILE}'|g' \
	       -e 's|@CRLNAME@|'${CRLNAME}'|g' \
	       -e 's|@PORT@|'${PORT}'|g' \
	       -e 's|@ADDRESS@|'${ADDRESS}'|g' \
	       -e 's|@VPNNET@|'${VPNNET}'|g' \
	       -e 's|@VPNNET_BASE@|'${VPNNET_BASE}'|g' \
	       -e 's|@VPNADDR@|'${VPNADDR}'|g' \
	       -e 's|@VPNNET6@|'${VPNNET6}'|g' \
	       -e 's|@VPNADDR6@|'${VPNADDR6}'|g' \
	       -e 's|@ROUTE1@|'${ROUTE1}'|g' \
	       -e 's|@ROUTE2@|'${ROUTE2}'|g' \
	       -e 's|@MATCH_CIPHERS@|'${MATCH_CIPHERS}'|g' \
	       -e 's|@OCCTL_SOCKET@|'${OCCTL_SOCKET}'|g' \
	       -e 's|@LISTEN_NS@|'${LISTEN_NS}'|g' \
	       -e 's|@CONFIG_PER_USER_DIR@|'${CONFIG_PER_USER_DIR}'|g' \
	       -e 's|@RADIUSCLIENT_DIR@|'${RADIUSCLIENT_DIR}'|g' "$1"
}

# update_config FILE: materializes tests/data/FILE into $CONFIG
update_config() {
	file=$1
	cp "${srcdir}/data/${file}" "$file.$$.tmp"
	_subst_placeholders "$file.$$.tmp"
	CONFIG="$file.$$.tmp"
}

# update_config_dir DIR: materializes the per-user or per-group config
# directory tests/data/DIR into $CONFIG_PER_USER_DIR; call it before
# update_config so that @CONFIG_PER_USER_DIR@ in the server config resolves.
update_config_dir() {
	dir=$1
	rm -rf "$dir.$$.tmp"
	cp -r "${srcdir}/data/${dir}" "$dir.$$.tmp"
	for f in "$dir.$$.tmp"/*; do
		_subst_placeholders "$f"
	done
	CONFIG_PER_USER_DIR="$(pwd)/$dir.$$.tmp"
}

# update_raddb: gives this test a private copy of the FreeRADIUS directory
# in $RADDB_DIR, with the users file materialized so that its framed
# addresses fall in the test's generated networks; see REQ-GEN-TEST-010
update_raddb() {
	rm -rf "raddb.$$.tmp"
	cp -r "${RADDB_DIR}" "raddb.$$.tmp"
	_subst_placeholders "raddb.$$.tmp/users"
	# FreeRADIUS refuses group- or world-writable configuration
	chmod -R go-w "raddb.$$.tmp"
	RADDB_DIR="$(pwd)/raddb.$$.tmp"
}

fail() {
   PID=$1
   shift;
   echo "Failure: $1" >&2
   kill $PID
   exit 1
}

launch_simple_pam_server() {
	test -z "${TEST_PAMDIR}" && exit 2
	export PAM_WRAPPER_DEBUGLEVEL=3
	export PAM_WRAPPER_SERVICE_DIR="${builddir}/pam.$$.tmp/"
	mkdir -p "${PAM_WRAPPER_SERVICE_DIR}"
	test -f "${srcdir}/${TEST_PAMDIR}/users.oath.templ" && cp "${srcdir}/${TEST_PAMDIR}/users.oath.templ" "${PAM_WRAPPER_SERVICE_DIR}/users.oath"

	for f in "${srcdir}/${TEST_PAMDIR}"/passdb*.templ; do
		test -f "${f}" && cp "${f}" "${PAM_WRAPPER_SERVICE_DIR}/$(basename "${f%.templ}")"
	done

	cp "${builddir}/data/pam/ocserv" "${PAM_WRAPPER_SERVICE_DIR}/"
	for f in "${builddir}/${TEST_PAMDIR}"/ocserv*; do
		test -f "${f}" && cp -f "${f}" "${PAM_WRAPPER_SERVICE_DIR}/"
	done
	sed -i -e 's|%PAM_WRAPPER_SERVICE_DIR%|'${PAM_WRAPPER_SERVICE_DIR}'|g' "${PAM_WRAPPER_SERVICE_DIR}"/ocserv*

	cp "${builddir}/data/pam/nss-passwd" "${PAM_WRAPPER_SERVICE_DIR}/"
	cp "${builddir}/data/pam/nss-group" "${PAM_WRAPPER_SERVICE_DIR}/"
	export NSS_WRAPPER_PASSWD=${PAM_WRAPPER_SERVICE_DIR}/nss-passwd
	export NSS_WRAPPER_GROUP=${PAM_WRAPPER_SERVICE_DIR}/nss-group
	if test "$SOCKET_WRAPPER" != 0;then
		SR="libsocket_wrapper.so:"
	fi
	if test -n "${VERBOSE}" && test "${VERBOSE}" -ge 1;then
		LD_PRELOAD=libnss_wrapper.so:${SR}libpam_wrapper.so:libuid_wrapper.so PAM_WRAPPER=1 UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $PRELOAD_CMD $SERV $* &
	else
		LD_PRELOAD=libnss_wrapper.so:${SR}libpam_wrapper.so:libuid_wrapper.so PAM_WRAPPER=1 UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $PRELOAD_CMD $SERV $* >/dev/null 2>&1 &
	fi
	unset NSS_WRAPPER_PASSWD
	unset NSS_WRAPPER_GROUP
}

launch_simple_sr_pam_server() {
	SOCKET_WRAPPER=1 launch_simple_pam_server $*
}

# If SYSLOG_SHIM_OUT is set (and SYSLOG_SHIM points at the built shim),
# echoes ":${SYSLOG_SHIM}" so callers can append it to an LD_PRELOAD chain
# and have syslog(3)/openlog(3) calls recorded to $SYSLOG_SHIM_OUT (see
# tests/syslog-shim.c). Echoes nothing otherwise, so callers that don't use
# it see no change in behavior.
_syslog_shim_ld_preload() {
	if test -n "${SYSLOG_SHIM_OUT}" && test -n "${SYSLOG_SHIM}";then
		printf ':%s' "${SYSLOG_SHIM}"
	fi
}

launch_simple_sr_server() {
	preload="libsocket_wrapper.so:libuid_wrapper.so$(_syslog_shim_ld_preload)"
	if test -n "${VERBOSE}" && test "${VERBOSE}" -ge 1;then
		LD_PRELOAD=${preload} UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $SERV $* -d 3 &
	else
		LD_PRELOAD=${preload} UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $SERV $* >/dev/null 2>&1 &
	fi
}

launch_simple_server() {
	preload="$(_syslog_shim_ld_preload)"
	preload="${preload#:}"
	if test -n "${VERBOSE}" && test "${VERBOSE}" -ge 1;then
		LD_PRELOAD=${preload} $PRELOAD_CMD $SERV $* &
	else
		LD_PRELOAD=${preload} $PRELOAD_CMD $SERV $* >/dev/null 2>&1 &
	fi
}

launch_simple_debug_server() {
	PRELOAD_CMD="valgrind --leak-check=full" VERBOSE=1 launch_simple_server $*
}

wait_server() {
	trap "kill $1" 1 15 2
	sleep 5
}

cleanup() {
	ret=0
	kill $PID
	if test $? != 0;then
		ret=1
	fi
	wait
	test -n "${PAM_WRAPPER_SERVICE_DIR}" && rm -rf ${PAM_WRAPPER_SERVICE_DIR}
	test -n "${SOCKDIR}" && rm -rf ${SOCKDIR}
	rm -f ${CONFIG}
	return $ret
}

# cleanup_client_server: kill the VPN client BEFORE the server so that the
# worker process detects the peer disconnect and exits cleanly (calling
# __gcov_dump() in coverage builds) instead of being force-killed by
# terminate_server() after its 5-second SIGKILL deadline.
#
# Usage from a finish() trap:
#   cleanup_client_server
# followed by any test-specific file removals.
#
# Expects the caller to have set:
#   CLIPID  - file holding the openconnect client PID  (may be unset/absent)
#   PID     - ocserv main process PID
#   PIDFILE - file holding the ocserv PID              (may be unset/absent)
cleanup_client_server() {
	set +e
	test -n "${CLIPID}" && test -f "${CLIPID}" && kill $(cat ${CLIPID}) >/dev/null 2>&1
	test -n "${CLIPID}" && rm -f "${CLIPID}" >/dev/null 2>&1
	sleep 2
	if test -n "${PID}"; then
		kill ${PID} >/dev/null 2>&1
		# Wait up to 10 s for graceful exit; force-kill if main is stuck
		# (e.g. blocked on a sec-mod IPC call during shutdown).
		for _cleanup_i in $(seq 1 10); do
			kill -0 "${PID}" 2>/dev/null || break
			sleep 1
		done
		kill -9 "${PID}" 2>/dev/null
		wait ${PID} 2>/dev/null
	fi
	test -n "${PIDFILE}" && rm -f "${PIDFILE}" >/dev/null 2>&1
	test -n "${DEFAULT_ROUTE_FILE}" && rm -f "${DEFAULT_ROUTE_FILE}" >/dev/null 2>&1
	test -n "${CONFIG}" && rm -f "${CONFIG}" >/dev/null 2>&1
}

# Check for a utility to list ports.  Both ss and netstat will list
# ports for normal users, and have similar semantics, so put the
# command in the caller's PFCMD, or exit, indicating an unsupported
# test.  Prefer ss from iproute2 over the older netstat.
have_port_finder() {
	for file in $(command -v ss) /*bin/ss /usr/*bin/ss /usr/local/*bin/ss;do
		if test -x "$file";then
			PFCMD="$file";return 0
		fi
	done

	if test -z "$PFCMD";then
	for file in $(command -v netstat) /bin/netstat /usr/bin/netstat /usr/local/bin/netstat;do
		if test -x "$file";then
			PFCMD="$file";return 0
		fi
	done
	fi

	if test -z "$PFCMD";then
		echo "neither ss nor netstat found"
		exit 1
	fi
}

check_if_port_in_use() {
	local PORT="$1"
	local PFCMD; have_port_finder
	$PFCMD -an|grep "[\:\.]$PORT" >/dev/null 2>&1
}

# wait_ns_port PROTO PORT [MAX_SECS]
# Poll inside CMDNS2 until the given port is listening, or exit on timeout.
# PROTO is 't' for TCP or 'u' for UDP.  Requires CMDNS2 to be set (ns.sh).
wait_ns_port() {
	local proto="$1" port="$2" max="${3:-30}" elapsed=0
	while [ "${elapsed}" -lt "${max}" ]; do
		${CMDNS2} ss -${proto}lnp 2>/dev/null | grep -q ":${port}" && return 0
		sleep 1
		elapsed=$((elapsed + 1))
	done
	echo "Timeout: port ${port} not ready after ${max}s" >&2
	exit 1
}

# wait_file_contents FILE PATTERN [MAX_SECS]
# Poll until FILE contains PATTERN (ERE), or exit on timeout.
# Polls every second; safe to call before the file exists.
wait_file_contents() {
	local file="$1" pattern="$2" max="${3:-60}" elapsed=0
	while [ "${elapsed}" -lt "${max}" ]; do
		grep -qE "${pattern}" "${file}" 2>/dev/null && return 0
		sleep 1
		elapsed=$((elapsed + 1))
	done
	echo "Timeout: '${pattern}' not found in ${file} after ${max}s" >&2
	exit 1
}

# Find a port number not currently in use.
GETPORT='
    rc=0
    unset myrandom
    while test $rc = 0; do
        if test -n "$RANDOM"; then myrandom=$(($RANDOM + $RANDOM)); fi
        if test -z "$myrandom"; then myrandom=$(date +%N | sed s/^0*//); fi
        if test -z "$myrandom"; then myrandom=0; fi
        PORT="$(((($$<<15)|$myrandom) % 63001 + 2000))"
        check_if_port_in_use $PORT;rc=$?
    done
'

trap "fail \"Failed to launch the server, aborting test... \"" 10
