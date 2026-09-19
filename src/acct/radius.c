/*
 * Copyright (C) 2014-2016 Red Hat, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "vpn.h"
#include <ctype.h>
#include <arpa/inet.h> /* inet_ntop */
#include "acct/radius.h"
#include "auth/common.h"

#include "log.h"

#ifdef HAVE_RADIUS

#ifdef LEGACY_RADIUS
#include <freeradius-client.h>
#else
#include <radcli/radcli.h>
#endif

#include "sec-mod-acct.h"
#include "auth/radius.h"
#include "common-config.h"

static void acct_radius_vhost_init(void **_vctx, void *pool, void *additional)
{
	radius_cfg_st *config = additional;
	struct radius_vhost_ctx *vctx;

	if (config == NULL)
		goto fail;

	vctx = talloc_zero(pool, struct radius_vhost_ctx);
	if (vctx == NULL)
		goto fail;

	vctx->rh = rc_read_config(config->config);
	if (vctx->rh == NULL) {
		goto fail;
	}

	if (config->nas_identifier) {
		strlcpy(vctx->nas_identifier, config->nas_identifier,
			sizeof(vctx->nas_identifier));
	} else {
		vctx->nas_identifier[0] = 0;
	}

	if (rc_read_dictionary(vctx->rh, rc_conf_str(vctx->rh, "dictionary")) !=
	    0) {
		fprintf(stderr, "error reading the radius dictionary\n");
		exit(EXIT_FAILURE);
	}
	*_vctx = vctx;

	return;
fail:
	fprintf(stderr, "radius initialization error\n");
	exit(EXIT_FAILURE);
}

static void acct_radius_vhost_deinit(void *_vctx)
{
	struct radius_vhost_ctx *vctx = _vctx;

	if (vctx->rh != NULL)
		rc_destroy(vctx->rh);
}

static void append_stats(rc_handle *rh, VALUE_PAIR **send, stats_st *stats,
			 time_t uptime)
{
	uint32_t uin, uout;

	if (uptime) {
		uin = (uint32_t)MIN(uptime, UINT32_MAX);
		rc_avpair_add(rh, send, PW_ACCT_SESSION_TIME, &uin, -1, 0);
	}

	uin = stats->bytes_in;
	uout = stats->bytes_out;

	rc_avpair_add(rh, send, PW_ACCT_INPUT_OCTETS, &uin, -1, 0);
	rc_avpair_add(rh, send, PW_ACCT_OUTPUT_OCTETS, &uout, -1, 0);

	uin = stats->bytes_in / 4294967296;
	rc_avpair_add(rh, send, PW_ACCT_INPUT_GIGAWORDS, &uin, -1, 0);

	uout = stats->bytes_out / 4294967296;
	rc_avpair_add(rh, send, PW_ACCT_OUTPUT_GIGAWORDS, &uout, -1, 0);
}

static void append_acct_standard(struct radius_vhost_ctx *vctx, rc_handle *rh,
				 const common_acct_info_st *ai,
				 VALUE_PAIR **send)
{
	uint32_t i;

	if (vctx->nas_identifier[0] != 0) {
		rc_avpair_add(rh, send, PW_NAS_IDENTIFIER, vctx->nas_identifier,
			      -1, 0);
	}

	if (ai->our_ip[0] != 0) {
		struct in_addr in;
		struct in6_addr in6;

		if (inet_pton(AF_INET, ai->our_ip, &in) != 0) {
			in.s_addr = ntohl(in.s_addr);
			rc_avpair_add(rh, send, PW_NAS_IP_ADDRESS, (char *)&in,
				      sizeof(struct in_addr), 0);
		} else if (inet_pton(AF_INET6, ai->our_ip, &in6) != 0) {
			rc_avpair_add(rh, send, PW_NAS_IPV6_ADDRESS,
				      (char *)&in6, sizeof(struct in6_addr), 0);
		}
	}

	rc_avpair_add(rh, send, PW_USER_NAME, ai->username, -1, 0);

	i = PW_FRAMED;
	rc_avpair_add(rh, send, PW_SERVICE_TYPE, &i, -1, 0);

	i = PW_PPP;
	rc_avpair_add(rh, send, PW_FRAMED_PROTOCOL, &i, -1, 0);

	if (ai->ipv4[0] != 0) {
		struct in_addr in;

		if (inet_pton(AF_INET, ai->ipv4, &in) == 1) {
			in.s_addr = ntohl(in.s_addr);
			if (rc_avpair_add(rh, send, PW_FRAMED_IP_ADDRESS, &in,
					  sizeof(in), 0) == NULL) {
				return;
			}
		}
	}

#ifndef LEGACY_RADIUS /* bug in freeradius-client */
	if (ai->ipv6[0] != 0) {
		struct in6_addr in;

		if (inet_pton(AF_INET6, ai->ipv6, &in) == 1) {
			if (rc_avpair_add(rh, send, PW_FRAMED_IPV6_ADDRESS, &in,
					  sizeof(in), 0) == NULL) {
				return;
			}
		}
	}
#endif

	rc_avpair_add(rh, send, PW_CALLING_STATION_ID, ai->remote_ip, -1, 0);
	rc_avpair_add(rh, send, PW_ACCT_SESSION_ID, ai->safe_id, -1, 0);

	i = PW_RADIUS;
	rc_avpair_add(rh, send, PW_ACCT_AUTHENTIC, &i, -1, 0);
}

static void radius_acct_session_stats(void *_vctx, unsigned int auth_method,
				      const common_acct_info_st *ai,
				      stats_st *stats)
{
	int ret;
	uint32_t status_type;
	VALUE_PAIR *send = NULL, *recvd = NULL;
	struct radius_vhost_ctx *vctx = _vctx;

	status_type = PW_STATUS_ALIVE;

	oc_syslog(LOG_DEBUG, "radius-auth: sending session interim update");

	if (rc_avpair_add(vctx->rh, &send, PW_ACCT_STATUS_TYPE, &status_type,
			  -1, 0) == NULL) {
		goto cleanup;
	}

	append_acct_standard(vctx, vctx->rh, ai, &send);
	append_stats(vctx->rh, &send, stats, ai->uptime);

	ret = rc_aaa(vctx->rh, 0, send, &recvd, NULL, 0, PW_ACCOUNTING_REQUEST);

	if (recvd != NULL)
		rc_avpair_free(recvd);

	if (ret != OK_RC) {
		oc_syslog(LOG_NOTICE, "radius-auth: radius_open_session: %d",
			  ret);
		goto cleanup;
	}

cleanup:
	rc_avpair_free(send);
}

static int radius_acct_open_session(void *_vctx, unsigned int auth_method,
				    const common_acct_info_st *ai,
				    const void *sid, unsigned int sid_size)
{
	int ret;
	uint32_t status_type;
	VALUE_PAIR *send = NULL, *recvd = NULL;
	struct radius_vhost_ctx *vctx = _vctx;

	status_type = PW_STATUS_START;

	if (sid_size != SID_SIZE) {
		oc_syslog(LOG_DEBUG, "radius-auth: incorrect sid size");
		return -1;
	}

	oc_syslog(LOG_DEBUG, "radius-auth: opening session %s", ai->safe_id);

	if (rc_avpair_add(vctx->rh, &send, PW_ACCT_STATUS_TYPE, &status_type,
			  -1, 0) == NULL) {
		ret = -1;
		goto cleanup;
	}

	if (ai->user_agent[0] != 0) {
		rc_avpair_add(vctx->rh, &send, PW_CONNECT_INFO, ai->user_agent,
			      -1, 0);
	}

	append_acct_standard(vctx, vctx->rh, ai, &send);

	ret = rc_aaa(vctx->rh, 0, send, &recvd, NULL, 0, PW_ACCOUNTING_REQUEST);

	if (recvd != NULL)
		rc_avpair_free(recvd);

	if (ret != OK_RC) {
		oc_syslog(LOG_NOTICE, "radius-auth: radius_open_session: %d",
			  ret);
		ret = -1;
		goto cleanup;
	}

	ret = 0;
cleanup:
	rc_avpair_free(send);
	return ret;
}

#ifndef LEGACY_RADIUS
static void radius_acct_send_shutdown(rc_handle *rh, VALUE_PAIR *send)
{
	SERVER *servers;
	SEND_DATA data;
	rc_socket_type socket_type = rc_get_socket_type(rh);
	rc_type type;
	uint32_t delay = 0;
	int result = OK_RC;
	int ret;

	if (socket_type == RC_SOCKET_TLS || socket_type == RC_SOCKET_DTLS) {
		servers = rc_conf_srv(rh, "authserver");
		type = AUTH;
	} else {
		servers = rc_conf_srv(rh, "acctserver");
		type = ACCT;
	}

	if (servers == NULL || servers->max == 0) {
		result = ERROR_RC;
		goto done;
	}

	if (rc_avpair_add(rh, &send, PW_ACCT_DELAY_TIME, &delay, -1, 0) ==
	    NULL) {
		result = ERROR_RC;
		goto done;
	}

	memset(&data, 0, sizeof(data));
	data.send_pairs = send;
	rc_buildreq(rh, &data, PW_ACCOUNTING_REQUEST, servers->name[0],
		    servers->port[0], servers->secret[0], 0, 0);

	ret = rc_send_server(rh, &data, NULL, type);
	if (data.receive_pairs != NULL)
		rc_avpair_free(data.receive_pairs);

	/* A zero timeout reports TIMEOUT_RC after the packet is sent. */
	if (ret != OK_RC && ret != TIMEOUT_RC)
		result = ret;

done:
	if (result != OK_RC)
		oc_syslog(LOG_INFO,
			  "radius-auth: shutdown accounting stop failed: %d",
			  result);
}
#else
static void radius_acct_send_shutdown(rc_handle *rh, VALUE_PAIR *send)
{
	(void)rh;
	(void)send;
}
#endif /* LEGACY_RADIUS */

static void radius_acct_close_session(void *_vctx, unsigned int auth_method,
				      const common_acct_info_st *ai,
				      stats_st *stats,
				      unsigned int discon_reason,
				      bool server_shutdown)
{
	int ret;
	uint32_t status_type;
	VALUE_PAIR *send = NULL, *recvd = NULL;
	struct radius_vhost_ctx *vctx = _vctx;

	status_type = PW_STATUS_STOP;

	oc_syslog(LOG_DEBUG, "radius-auth: closing session");
	if (rc_avpair_add(vctx->rh, &send, PW_ACCT_STATUS_TYPE, &status_type,
			  -1, 0) == NULL)
		return;

	if (discon_reason == REASON_USER_DISCONNECT)
		ret = PW_USER_REQUEST;
	else if (discon_reason == REASON_SERVER_DISCONNECT)
		ret = PW_ADMIN_RESET;
	else if (discon_reason == REASON_IDLE_TIMEOUT)
		ret = PW_ACCT_IDLE_TIMEOUT;
	else if (discon_reason == REASON_SESSION_TIMEOUT)
		ret = PW_ACCT_SESSION_TIMEOUT;
	else if (discon_reason == REASON_DPD_TIMEOUT)
		ret = PW_LOST_CARRIER;
	else if (discon_reason == REASON_ERROR)
		ret = PW_USER_ERROR;
	else
		ret = PW_LOST_SERVICE;
	rc_avpair_add(vctx->rh, &send, PW_ACCT_TERMINATE_CAUSE, &ret, -1, 0);

	append_acct_standard(vctx, vctx->rh, ai, &send);
	append_stats(vctx->rh, &send, stats, ai->uptime);

	if (server_shutdown) {
		radius_acct_send_shutdown(vctx->rh, send);
		goto cleanup;
	}

	ret = rc_aaa(vctx->rh, 0, send, &recvd, NULL, 0, PW_ACCOUNTING_REQUEST);
	if (recvd != NULL)
		rc_avpair_free(recvd);

	if (ret != OK_RC) {
		oc_syslog(LOG_INFO, "radius-auth: radius_close_session: %d",
			  ret);
		goto cleanup;
	}

cleanup:
	rc_avpair_free(send);
}

const struct acct_mod_st radius_acct_funcs = {
	.type = ACCT_TYPE_RADIUS,
	.auth_types = ALL_AUTH_TYPES,
	.vhost_init = acct_radius_vhost_init,
	.vhost_deinit = acct_radius_vhost_deinit,
	.open_session = radius_acct_open_session,
	.close_session = radius_acct_close_session,
	.session_stats = radius_acct_session_stats
};

#endif
