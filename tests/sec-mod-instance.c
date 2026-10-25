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

/* REQ-IPC-094, REQ-MAIN-INIT-006, REQ-IPC-093 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "common/common.h"

static void check_index(unsigned int index, uint8_t b0, uint8_t b1)
{
	uint8_t out[SEC_MOD_INSTANCE_INDEX_SIZE + 1];

	memset(out, 0xaa, sizeof(out));
	sec_mod_instance_index_put(out, index);
	if (out[0] != b0 || out[1] != b1) {
		fprintf(stderr,
			"FAIL: index %u: expected %02x%02x, got %02x%02x\n",
			index, b0, b1, out[0], out[1]);
		exit(1);
	}
	if (out[SEC_MOD_INSTANCE_INDEX_SIZE] != 0xaa) {
		fprintf(stderr, "FAIL: index %u: written past %d bytes\n",
			index, SEC_MOD_INSTANCE_INDEX_SIZE);
		exit(1);
	}
	if (sec_mod_instance_index_get(out) != index) {
		fprintf(stderr, "FAIL: index %u: expected it back, got %u\n",
			index, sec_mod_instance_index_get(out));
		exit(1);
	}
}

static void check_addr(const char *base, unsigned int index,
		       const char *expected)
{
	struct sockaddr_un addr;
	socklen_t addr_len = 0;

	memset(&addr, 0, sizeof(addr));
	if (sec_mod_instance_addr(base, index, &addr, &addr_len) < 0) {
		fprintf(stderr, "FAIL: %s, %u: expected %s, got an error\n",
			base, index, expected);
		exit(1);
	}
	if (addr.sun_family != AF_UNIX ||
	    strcmp(addr.sun_path, expected) != 0 ||
	    addr_len != SUN_LEN(&addr)) {
		fprintf(stderr,
			"FAIL: %s, %u: expected %s (len %u), got %s (len %u)\n",
			base, index, expected, (unsigned int)SUN_LEN(&addr),
			addr.sun_path, (unsigned int)addr_len);
		exit(1);
	}
}

int main(void)
{
	struct sockaddr_un addr, orig;
	socklen_t addr_len = 7;
	char base[sizeof(addr.sun_path)];
	char expected[sizeof(base) + 8];

	if (MAX_SEC_MOD_INSTANCES != 65535) {
		fprintf(stderr, "FAIL: expected a limit of 65535, got %u\n",
			(unsigned int)MAX_SEC_MOD_INSTANCES);
		exit(1);
	}

	check_index(0, 0x00, 0x00);
	check_index(1, 0x00, 0x01);
	check_index(255, 0x00, 0xff);
	check_index(256, 0x01, 0x00);
	check_index(0x1234, 0x12, 0x34);
	check_index(MAX_SEC_MOD_INSTANCES - 1, 0xff, 0xfe);
	check_index(65535, 0xff, 0xff);

	check_addr("/var/run/ocserv-socket.1a2b", 0,
		   "/var/run/ocserv-socket.1a2b.0");
	check_addr("var/run/ocserv-socket.1a2b", 65535,
		   "var/run/ocserv-socket.1a2b.65535");

	/* a name which fits with a short index but not with a long one */
	memset(base, 'a', sizeof(base));
	base[sizeof(addr.sun_path) - 5] = 0;
	snprintf(expected, sizeof(expected), "%s.0", base);
	check_addr(base, 0, expected);

	memset(&addr, 0x5a, sizeof(addr));
	orig = addr;
	if (sec_mod_instance_addr(base, 65535, &addr, &addr_len) >= 0) {
		fprintf(stderr,
			"FAIL: expected a name of %u bytes to be refused, got %s\n",
			(unsigned int)(strlen(base) + 6), addr.sun_path);
		exit(1);
	}
	if (memcmp(&addr, &orig, sizeof(addr)) != 0 || addr_len != 7) {
		fprintf(stderr,
			"FAIL: expected the address untouched on an error, got it changed\n");
		exit(1);
	}

	return 0;
}
