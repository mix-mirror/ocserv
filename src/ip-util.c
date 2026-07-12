/*
 * Copyright (C) 2013-2016 Nikos Mavrogiannopoulos
 * Copyright (C) 2015-2016 Red Hat, Inc.
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

#include "config.h"
#include "ip-util.h"
#include "common/common.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <talloc.h>
#include <assert.h>
#include <stddef.h>
/* for inet_ntop */
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "log.h"

int ip_cmp(const struct sockaddr_storage *s1, const struct sockaddr_storage *s2)
{
	if (((struct sockaddr *)s1)->sa_family == AF_INET) {
		return memcmp(SA_IN_P(s1), SA_IN_P(s2), sizeof(struct in_addr));
	} else { /* inet6 */
		return memcmp(SA_IN6_P(s1), SA_IN6_P(s2),
			      sizeof(struct in6_addr));
	}
}

/* returns an allocated string with the mask to apply for the prefix
 */
char *ipv4_prefix_to_strmask(void *pool, unsigned int prefix)
{
	struct in_addr in;
	char str[MAX_IP_STR];

	if (prefix == 0 || prefix > 32)
		return NULL;

	in.s_addr = ntohl(((uint32_t)0xFFFFFFFF) << (32 - prefix));
	if (inet_ntop(AF_INET, &in, str, sizeof(str)) == NULL)
		return NULL;

	return talloc_strdup(pool, str);
}

unsigned int ipv6_prefix_to_mask(struct in6_addr *in6, unsigned int prefix)
{
	int i, j;

	if (prefix == 0 || prefix > 128)
		return 0;

	memset(in6, 0x0, sizeof(*in6));
	for (i = prefix, j = 0; i > 0; i -= 8, j++) {
		if (i >= 8) {
			in6->s6_addr[j] = 0xff;
		} else {
			in6->s6_addr[j] = (unsigned long)(0xffU << (8 - i));
		}
	}

	return 1;
}

static int bit_count(uint32_t i)
{
	int c = 0;
	unsigned int seen_one = 0;

	while (i > 0) {
		if (i & 1) {
			seen_one = 1;
			c++;
		} else {
			if (seen_one) {
				return -1;
			}
		}
		i >>= 1;
	}

	return c;
}

static int mask2prefix(struct in_addr mask)
{
	return bit_count(ntohl(mask.s_addr));
}

static int ipv4_mask_to_int(const char *prefix)
{
	int ret;
	struct in_addr in;

	ret = inet_pton(AF_INET, prefix, &in);
	if (ret == 0)
		return -1;

	return mask2prefix(in);
}

/* parses 'str' as a decimal, non-negative integer with no leading/
 * trailing garbage, in [0, max]; returns 0 and sets *out on success */
static int parse_uint_full(const char *str, unsigned int max, unsigned int *out)
{
	char *end;
	unsigned long val;

	if (str == NULL || *str == 0)
		return -1;

	errno = 0;
	val = strtoul(str, &end, 10);
	if (errno != 0 || *end != 0 || val > max)
		return -1;

	*out = (unsigned int)val;
	return 0;
}

/* Checks that a route is a well-formed IPv4 or IPv6 address plus
 * prefix (xxx.xxx.xxx.xxx/prefix, xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx, or
 * an IPv6 address/prefix), and returns a negative code for anything
 * else, including any route containing characters that do not belong
 * to a valid address or prefix.
 *
 * This is a security boundary, not just a format check: the validated
 * route is later substituted into route-add-cmd/route-del-cmd and
 * executed via a shell as root (see route_adddel() in route-add.c), so
 * a route string that is not fully consumed by address/prefix parsing
 * must be rejected rather than passed through or partially normalized.
 *
 * For IPv4, normalizes a numeric /prefix to the equivalent dotted
 * netmask, matching this function's historical output format.
 *
 * The literal string "default" is accepted unchanged: it is not an
 * address at all, but the documented keyword (sample.config, "route =
 * default") that config.c recognizes as a request to route all client
 * traffic through the VPN (config.c:2199-2200). It carries no shell
 * metacharacters, so accepting it here does not reopen the injection
 * this function guards against.
 */
int ip_route_sanity_check(void *pool, char **_route)
{
	char *route = *_route, *n;
	char *slash_ptr, *addr_part, *prefix_part;
	struct in_addr in4;
	struct in6_addr in6;
	unsigned int prefix;
	int is_ipv6;

	if (strcmp(route, "default") == 0)
		return 0;

	is_ipv6 = (strchr(route, ':') != NULL);

	slash_ptr = strchr(route, '/');
	if (slash_ptr == NULL) {
		oc_syslog(LOG_ERR,
			  "route '%s' is missing a /prefix, use address/prefix",
			  route);
		return -1;
	}

	addr_part = talloc_strndup(pool, route, slash_ptr - route);
	if (addr_part == NULL)
		return -1;
	prefix_part = slash_ptr + 1;

	if (is_ipv6) {
		if (inet_pton(AF_INET6, addr_part, &in6) != 1) {
			oc_syslog(LOG_ERR,
				  "route '%s' has an invalid IPv6 address",
				  route);
			talloc_free(addr_part);
			return -1;
		}

		if (parse_uint_full(prefix_part, 128, &prefix) < 0) {
			oc_syslog(LOG_ERR,
				  "route '%s' has an invalid IPv6 prefix",
				  route);
			talloc_free(addr_part);
			return -1;
		}

		talloc_free(addr_part);
		return 0;
	}

	if (inet_pton(AF_INET, addr_part, &in4) != 1) {
		oc_syslog(LOG_ERR, "route '%s' has an invalid IPv4 address",
			  route);
		talloc_free(addr_part);
		return -1;
	}

	if (strchr(prefix_part, '.') != NULL) {
		/* dotted-netmask form; must be a valid, contiguous mask */
		if (ipv4_mask_to_int(prefix_part) < 0) {
			oc_syslog(LOG_ERR,
				  "route '%s' has an invalid IPv4 netmask",
				  route);
			talloc_free(addr_part);
			return -1;
		}
		talloc_free(addr_part);
		return 0;
	}

	if (parse_uint_full(prefix_part, 32, &prefix) < 0) {
		oc_syslog(LOG_ERR, "route '%s' has an invalid IPv4 prefix",
			  route);
		talloc_free(addr_part);
		return -1;
	}

	if (prefix == 0) {
		n = talloc_asprintf(pool, "%s/0.0.0.0", addr_part);
	} else {
		char *pstr = ipv4_prefix_to_strmask(pool, prefix);

		if (pstr == NULL) {
			talloc_free(addr_part);
			return -1;
		}
		n = talloc_asprintf(pool, "%s/%s", addr_part, pstr);
		talloc_free(pstr);
	}
	talloc_free(addr_part);
	if (n == NULL) {
		oc_syslog(LOG_ERR, "memory error");
		return -1;
	}

	talloc_free(route);
	*_route = n;
	return 0;
}

/* Converts a route from xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx format, to
 * xxx.xxx.xxx.xxx/prefix format.
 */
char *ipv4_route_to_cidr(void *pool, const char *route)
{
	int prefix;
	int len;
	const char *p;

	/* this check is valid for IPv4 only */
	p = strchr(route, '.');
	if (p == NULL)
		return talloc_strdup(pool, route);

	p = strchr(p, '/');
	if (p == NULL) {
		return NULL;
	}
	len = (ptrdiff_t)(p - route);
	p++;

	/* if we are in CIDR format exit */
	if (strchr(p, '.') == 0)
		return talloc_strdup(pool, route);

	prefix = ipv4_mask_to_int(p);
	if (prefix <= 0 || prefix > 32)
		return NULL;

	return talloc_asprintf(pool, "%.*s/%d", len, route, prefix);
}

char *human_addr2(const struct sockaddr *sa, socklen_t salen, void *_buf,
		  size_t buflen, unsigned int full)
{
	char *save_buf = _buf;
	char *buf = _buf;
	size_t l;
	const char *ret;
	unsigned int port;

	if (!buf || !buflen)
		return NULL;

	if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) {
		return NULL;
	}

	if (salen == sizeof(struct sockaddr_in6)) {
		port = (unsigned int)ntohs(
			((struct sockaddr_in6 *)sa)->sin6_port);

		if (full != 0 && port != 0) {
			assert(buflen >
			       0); /* already checked, but to avoid regression */
			*buf = '[';
			buf++;
			buflen--;
		}

		ret = inet_ntop(AF_INET6,
				&((struct sockaddr_in6 *)sa)->sin6_addr, buf,
				buflen);
	} else {
		port = (unsigned int)ntohs(
			((struct sockaddr_in *)sa)->sin_port);

		ret = inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr,
				buf, buflen);
	}

	if (ret == NULL) {
		return NULL;
	}

	if (full == 0)
		goto finish;

	l = strlen(buf);
	buf += l;
	buflen -= l;

	if (salen == sizeof(struct sockaddr_in6) && port != 0 && buflen > 0) {
		*buf = ']';
		buf++;
		buflen--;
	}

	if (port != 0 && buflen > 0) {
		*buf = ':';
		buf++;
		buflen--;

		snprintf(buf, buflen, "%u", port);
	}

finish:
	return save_buf;
}

void set_mtu_disc(int fd, int family, int val)
{
	int y;

	if (family == AF_INET6) {
		y = val;
#if defined(IPV6_DONTFRAG)
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG,
			       (const void *)&y, sizeof(y)) < 0)
			oc_syslog(LOG_INFO, "setsockopt(IPV6_DF) failed");
#elif defined(IPV6_MTU_DISCOVER)
		if (val)
			y = IP_PMTUDISC_DO;
		else
			y = IP_PMTUDISC_DONT;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
			       (const void *)&y, sizeof(y)) < 0)
			oc_syslog(LOG_INFO,
				  "setsockopt(IPV6_MTU_DISCOVER) failed");
#endif
	} else {
		y = val;
#if defined(IP_DONTFRAG)
		if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, (const void *)&y,
			       sizeof(y)) < 0)
			oc_syslog(LOG_INFO, "setsockopt(IP_DF) failed");
#elif defined(IP_MTU_DISCOVER)
		if (val)
			y = IP_PMTUDISC_DO;
		else
			y = IP_PMTUDISC_DONT;
		if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER,
			       (const void *)&y, sizeof(y)) < 0)
			oc_syslog(LOG_INFO,
				  "setsockopt(IP_MTU_DISCOVER) failed");
#endif
	}
}
