/*
 * Copyright (C) 2016 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* RFC 1035 section 2.3.4 */
#define MAX_DNS_LABEL_LENGTH 63
#define MAX_DNS_NAME_LENGTH 253

/* Validates a single hostname label per RFC 952 as updated by RFC 1123:
 *  - first character: letter or digit (RFC 1123 relaxes RFC 952's letter-only rule)
 *  - interior characters: letters, digits, or hyphens
 *  - last character: letter or digit (no trailing hyphen)
 *  - maximum label length: 63 characters (RFC 1123 §2.1)
 */
unsigned int valid_hostname(const char *host)
{
	const char *p = host;

	if (p == NULL || *p == '\0' || *p == '-')
		return 0;

	while (*p != 0) {
		if (!(isalnum(*p)) && !(*p == '-'))
			return 0;
		p++;
	}

	if (*(p - 1) == '-')
		return 0;

	if ((p - host) > MAX_DNS_LABEL_LENGTH)
		return 0;

	return 1;
}

/*
 * Validates a fully qualified name: a sequence of labels separated by
 * dots, each valid per valid_hostname(). Used where the name is echoed
 * back to the client (e.g. in URLs), so it must not carry anything but
 * hostname characters.
 */
unsigned int valid_fqdn(const char *host)
{
	char label[MAX_DNS_LABEL_LENGTH + 1];
	const char *p = host;
	const char *dot;
	size_t len;

	if (p == NULL || *p == '\0')
		return 0;

	if (strlen(host) > MAX_DNS_NAME_LENGTH)
		return 0;

	/* a trailing dot denotes the root label; it does not appear in a Host
	 * header and would end up in the URLs handed to the client */
	if (host[strlen(host) - 1] == '.')
		return 0;

	while (*p != 0) {
		dot = strchr(p, '.');
		len = (dot != NULL) ? (size_t)(dot - p) : strlen(p);

		if (len == 0 || len > MAX_DNS_LABEL_LENGTH)
			return 0;

		memcpy(label, p, len);
		label[len] = 0;

		if (!valid_hostname(label))
			return 0;

		if (dot == NULL)
			break;
		p = dot + 1;
	}

	return 1;
}

/*
 * Validates a name with an optional port, as it appears in a Host header.
 * Used where the value is echoed back to the client inside URLs, so every
 * character of it has to be accounted for.
 */
unsigned int valid_hostport(const char *host)
{
	char name[MAX_DNS_NAME_LENGTH + 1];
	const char *colon;
	const char *p;
	size_t len;

	if (host == NULL || *host == '\0')
		return 0;

	colon = strchr(host, ':');
	if (colon == NULL)
		return valid_fqdn(host);

	/* the port must be present and decimal */
	if (colon[1] == '\0')
		return 0;

	for (p = colon + 1; *p != '\0'; p++) {
		if (!isdigit((unsigned char)*p))
			return 0;
	}

	len = colon - host;
	if (len == 0 || len > MAX_DNS_NAME_LENGTH)
		return 0;

	memcpy(name, host, len);
	name[len] = '\0';

	return valid_fqdn(name);
}

void strip_domain(char *host)
{
	char *dot;
	struct in_addr addr;

	if (host == NULL || host[0] == '.')
		return;

	/* do not strip if it's an IPv4 address */
	if (inet_pton(AF_INET, host, &addr) == 1)
		return;

	dot = strchr(host, '.');
	if (dot)
		*dot = '\0';
}
