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

/* REQ-MAIN-SEC-008: ip_route_sanity_check() is the only validation a
 * route string undergoes before it can be substituted into
 * route-add-cmd/route-del-cmd and executed via `/bin/sh -c` as root
 * (src/route-add.c:50). It must reject anything that is not a
 * well-formed IPv4/IPv6 CIDR, not merely normalize IPv4 prefix syntax.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>

#include "../src/ip-util.h"
#include "../src/ip-util.c"

static void expect_reject(const char *route)
{
	void *pool = talloc_new(NULL);
	char *r = talloc_strdup(pool, route);
	int ret;

	ret = ip_route_sanity_check(pool, &r);
	if (ret >= 0) {
		fprintf(stderr,
			"error: route '%s' should have been REJECTED but was accepted as '%s'\n",
			route, r);
		exit(1);
	}
	talloc_free(pool);
}

static void expect_accept(const char *route, const char *expected)
{
	void *pool = talloc_new(NULL);
	char *r = talloc_strdup(pool, route);
	int ret;

	ret = ip_route_sanity_check(pool, &r);
	if (ret < 0) {
		fprintf(stderr,
			"error: route '%s' should have been ACCEPTED but was rejected\n",
			route);
		exit(1);
	}
	if (strcmp(r, expected) != 0) {
		fprintf(stderr,
			"error: route '%s' normalized to '%s', expected '%s'\n",
			route, r, expected);
		exit(1);
	}
	talloc_free(pool);
}

int main(void)
{
	/* --- malicious routes: MUST be rejected regardless of family --- */

	/* dot-free routes (IPv6, or garbage) used to bypass all validation */
	expect_reject("::/0; touch /tmp/x");
	expect_reject("2001:db8::/32; touch /tmp/x");
	expect_reject("not-a-route-at-all");
	expect_reject("$(touch /tmp/x)");
	expect_reject("`touch /tmp/x`");

	/* dotted-netmask routes used to pass through unexamined */
	expect_reject("1.2.3.4/5.6.7.8; touch /tmp/x");
	expect_reject("10.0.0.0/255.255.255.0; touch /tmp/x");
	expect_reject("10.0.0.0/255.255.255.0 && touch /tmp/x");

	/* out-of-range / malformed prefixes */
	expect_reject("10.0.0.0/33");
	expect_reject("2001:db8::/129");
	expect_reject("10.0.0.0/abc");
	expect_reject("999.999.999.999/24");

	/* --- legitimate routes: MUST still be accepted --- */
	expect_accept("10.0.0.0/24", "10.0.0.0/255.255.255.0");
	expect_accept("10.0.0.0/255.255.255.0", "10.0.0.0/255.255.255.0");
	expect_accept("2001:db8::/32", "2001:db8::/32");
	expect_accept("fd00::/8", "fd00::/8");
	expect_accept("0.0.0.0/0", "0.0.0.0/0.0.0.0");
	expect_accept("::/0", "::/0");

	/* the documented "route = default" keyword (sample.config,
	 * config.c:2199-2200) is not an address and MUST be accepted
	 * unchanged, exact-match only (not as a prefix/substring) */
	expect_accept("default", "default");
	expect_reject("Default");
	expect_reject("default/24");
	expect_reject("default; touch /tmp/x");

	printf("All route sanity check tests passed.\n");
	return 0;
}
