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
 * LD_PRELOAD shim that intercepts openlog(3) and syslog(3) and appends
 * records to the file named by $SYSLOG_SHIM_OUT:
 *   - openlog() calls append the facility name on its own line (e.g. "daemon").
 *   - syslog() calls append a line "MSG <priority> <message>".
 * The two record kinds cannot collide: a facility name is never "MSG ...".
 *
 * Used by tests to verify what ocserv actually passes to the syslog(3) API
 * (facility, priority, message) without requiring a real syslog daemon and
 * without depending on stdio/fd redirection of the daemon's own stdout or
 * stderr, which is not reliable across all CI environments.
 *
 * Multiple processes (main, sec-mod, worker) may log concurrently; each
 * record is written with a single write(2) call on an O_APPEND fd so
 * records from different processes are never interleaved.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

static const char *facility_name(int facility)
{
	switch (facility) {
	case LOG_DAEMON:
		return "daemon";
	case LOG_USER:
		return "user";
	case LOG_AUTH:
		return "auth";
	case LOG_LOCAL0:
		return "local0";
	case LOG_LOCAL1:
		return "local1";
	case LOG_LOCAL2:
		return "local2";
	case LOG_LOCAL3:
		return "local3";
	case LOG_LOCAL4:
		return "local4";
	case LOG_LOCAL5:
		return "local5";
	case LOG_LOCAL6:
		return "local6";
	case LOG_LOCAL7:
		return "local7";
#ifdef LOG_AUTHPRIV
	case LOG_AUTHPRIV:
		return "authpriv";
#endif
	default:
		return "unknown";
	}
}

void openlog(const char *ident, int logopt, int facility)
{
	static void (*real_openlog)(const char *, int, int);
	const char *out;
	FILE *f;

	out = getenv("SYSLOG_SHIM_OUT");
	if (out != NULL) {
		f = fopen(out, "a");
		if (f != NULL) {
			fprintf(f, "%s\n", facility_name(facility));
			fclose(f);
		}
	}

	if (real_openlog == NULL)
		real_openlog = dlsym(RTLD_NEXT, "openlog");
	if (real_openlog != NULL)
		real_openlog(ident, logopt, facility);
}

void syslog(int priority, const char *format, ...)
{
	const char *out;
	char msg[1024];
	char line[1200];
	va_list args;
	int fd, len;

	out = getenv("SYSLOG_SHIM_OUT");
	if (out != NULL) {
		va_start(args, format);
		vsnprintf(msg, sizeof(msg), format, args);
		va_end(args);

		len = snprintf(line, sizeof(line), "MSG %d %s\n", priority,
			       msg);
		if (len > 0 && (size_t)len > sizeof(line) - 1)
			len = sizeof(line) - 1;

		fd = open(out, O_WRONLY | O_CREAT | O_APPEND, 0600);
		if (fd >= 0) {
			write(fd, line, len);
			close(fd);
		}
	}

	/* vsyslog(3) is not intercepted, so this reaches the real syslog. */
	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
