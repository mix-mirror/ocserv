/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Exercises REQ-MAIN-NET-004: icmp_echo4()/icmp_echo6() must send an ICMP
 * echo request and correctly distinguish a genuine echo reply from "no
 * reply"/"unreachable". UNDER_TEST excludes icmp_ping4()/icmp_ping6()
 * (the ocserv-facing wrappers, which need a full main_server_st/vhost
 * config tree) from this translation unit, so only the pure send/receive
 * logic is under test here. Requires CAP_NET_RAW (root), hence gated as a
 * root test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../src/ip-util.c"
#include "../src/icmp-ping.c"

/* keep the negative-reply tests fast rather than the real 3s PING_TIMEOUT */
#define TEST_TIMEOUT_SECS 1

static void run_test4(const char *desc, const char *ip, int expect_reply)
{
	struct sockaddr_in addr;
	int ret;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
		fprintf(stderr, "FAIL: %s: inet_pton(%s) failed\n", desc, ip);
		exit(1);
	}

	ret = icmp_echo4(&addr, TEST_TIMEOUT_SECS);

	if (expect_reply && ret <= 0) {
		fprintf(stderr,
			"FAIL: %s: expected a ping reply from %s, got ret=%d\n",
			desc, ip, ret);
		exit(1);
	}
	if (!expect_reply && ret != 0) {
		fprintf(stderr,
			"FAIL: %s: expected no ping reply from %s, got ret=%d\n",
			desc, ip, ret);
		exit(1);
	}

	printf("PASS: %s (%s) -> %d\n", desc, ip, ret);
}

int main(void)
{
	/* positive: the kernel answers ICMP echo requests sent to loopback,
	 * so a genuine ICMP_ECHOREPLY must be observed and reported. */
	run_test4("loopback replies to ping", "127.0.0.1", 1);

	/* negative: a TEST-NET-1 (RFC 5737) address is not assigned to any
	 * host reachable from the test environment, so no ICMP_ECHOREPLY
	 * can arrive; icmp_echo4() must not mistake silence (or a
	 * destination-unreachable) for the address being in use, and must
	 * not hang past the given timeout. */
	run_test4("non-responding address is treated as free", "192.0.2.1", 0);

	return 0;
}
