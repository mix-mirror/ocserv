/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef OC_ICMP_PING_H
#define OC_ICMP_PING_H

#include "main.h"

/* Pure ICMP echo request/reply probe: no ocserv config or logging
 * dependency, so it can be unit tested directly. Returns the number of
 * positive replies received within timeout_secs, or 0 if none arrived
 * (including the case where a destination-unreachable was received
 * instead). */
int icmp_echo4(const struct sockaddr_in *addr1, unsigned int timeout_secs);
int icmp_echo6(const struct sockaddr_in6 *addr1, unsigned int timeout_secs);

/* ocserv-facing wrappers: honor the ping-leases config option and log
 * the outcome. Same return convention as icmp_echo4()/icmp_echo6(). */
int icmp_ping4(main_server_st *s, struct sockaddr_in *addr1);
int icmp_ping6(main_server_st *s, struct sockaddr_in6 *addr1);

#endif
