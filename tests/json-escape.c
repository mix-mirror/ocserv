/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "../src/occtl/json.h"
#include "../src/occtl/json.c"
#include "../src/common/common.h"

static char *strings[] = {

	"hello there",
	"hi bro\n",
	"small ascii\x10\x01\x03\x04\x18\x20\x21\x1f end",
	"try to escape \"quotes",
	"try to escape \\escapes",
	"\tbig pile  \b\b of stuff\r\n",
	"",
	"\xc3\xa9",
	"\xe4\xb8\xad",
	"\xf0\x9f\x98\x80",
	"\xc3\xa9\n"
};

static char *encoded_strings[] = {

	"hello there",
	"hi bro\\u000a",
	"small ascii\\u0010\\u0001\\u0003\\u0004\\u0018 !\\u001f end",
	"try to escape \\\"quotes",
	"try to escape \\\\escapes",
	"\\u0009big pile  \\u0008\\u0008 of stuff\\u000d\\u000a",
	"",
	"\xc3\xa9",
	"\xe4\xb8\xad",
	"\xf0\x9f\x98\x80",
	"\xc3\xa9\\u000a"
};

int main(void)
{
	char tmp[512];
	char guarded[10];
	char *p;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(strings); i++) {
		tmp[0] = 0;
		p = json_escape_val(tmp, sizeof(tmp), strings[i]);
		if (strcmp(p, encoded_strings[i]) != 0) {
			fprintf(stderr,
				"string %u, fails encoding:\n\tinput: '%s'\n\texpected: '%s'\n\toutput: '%s'\n",
				i, strings[i], encoded_strings[i], p);
			exit(1);
		}
	}
	memset(guarded, 'Z', sizeof(guarded));
	p = json_escape_val(guarded + 1, 7, "A");
	if (strcmp(p, "(invalid)") != 0 || guarded[0] != 'Z' ||
	    guarded[8] != 'Z') {
		fprintf(stderr,
			"FAIL: capacity 7: expected '(invalid)' and guards Z/Z, got '%s' and %c/%c\n",
			p, guarded[0], guarded[8]);
		return 1;
	}
	memset(guarded, 'Z', sizeof(guarded));
	p = json_escape_val(guarded + 1, 8, "A");
	if (strcmp(p, "A") != 0 || guarded[0] != 'Z' || guarded[9] != 'Z') {
		fprintf(stderr,
			"FAIL: capacity 8: expected 'A' and guards Z/Z, got '%s' and %c/%c\n",
			p, guarded[0], guarded[9]);
		return 1;
	}

	/* a buffer of JSON_ESCAPED_SIZE() holds the escaped value however
	 * long it is and whatever it contains */
	{
		char in[2048];
		char *out;
		size_t size;

		memset(in, '"', sizeof(in) - 1);
		in[sizeof(in) - 1] = 0;
		in[0] = '\x01';
		size = JSON_ESCAPED_SIZE(strlen(in));
		out = malloc(size);
		if (out == NULL)
			exit(1);
		p = json_escape_val(out, size, in);
		if (p != out || strncmp(p, "\\u0001\\\"", 8) != 0 ||
		    strlen(p) != 6 + 2 * (sizeof(in) - 2)) {
			fprintf(stderr,
				"long value fails encoding: got '%.40s...' of length %zu\n",
				p, strlen(p));
			exit(1);
		}
		free(out);
	}
	return 0;
}
