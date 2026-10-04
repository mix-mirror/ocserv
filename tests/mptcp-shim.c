/*
 * Copyright (C) 2026 Pierre-Yves Le Borgne
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
 * LD_PRELOAD shim that creates Multipath TCP sockets where the program asks
 * for TCP ones, as mptcpize (mptcpd) does. tests/test-listen-mptcp loads it
 * into openconnect, which has no MPTCP option, to connect with MPTCP.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

int socket(int domain, int type, int protocol)
{
	static int (*real_socket)(int, int, int);
	int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

	if (real_socket == NULL)
		real_socket = dlsym(RTLD_NEXT, "socket");
	if (real_socket == NULL) {
		errno = ENOSYS;
		return -1;
	}

	if ((domain == AF_INET || domain == AF_INET6) &&
	    base_type == SOCK_STREAM &&
	    (protocol == 0 || protocol == IPPROTO_TCP))
		protocol = IPPROTO_MPTCP;

	return real_socket(domain, type, protocol);
}
