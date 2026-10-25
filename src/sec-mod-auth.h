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
#ifndef OC_SEC_MOD_AUTH_H
#define OC_SEC_MOD_AUTH_H

#include "main.h"
#include "sec-mod.h"

#define MAX_AUTH_REQS 8

typedef struct passwd_msg_st {
	char *msg_str;
	unsigned int counter;
} passwd_msg_st;

typedef struct auth_mod_st {
	unsigned int type;
	unsigned int
		allows_retries; /* whether the module allows retries of the same password */
	void (*vhost_init)(void **vctx, void *pool, void *additional);
	void (*vhost_deinit)(void *vctx);
	int (*auth_init)(void **ctx, void *pool, void *vctx,
			 const common_auth_init_st *);
	int (*auth_msg)(void *ctx, void *pool, passwd_msg_st *);
	int (*auth_pass)(void *ctx, const char *pass, unsigned int pass_len);
	int (*auth_group)(void *ctx, const char *suggested, char *groupname,
			  int groupname_size);
	int (*auth_user)(void *ctx, char *groupname, int groupname_size);

	void (*auth_deinit)(void *ctx);
	void (*group_list)(void *pool, void *additional, char ***groupname,
			   unsigned int *groupname_size);
	/* optional: begin a browser-based login for the client at remote_ip;
	 * return the authorization URL to open and the state which identifies
	 * the request. The state and the token returned by sso_finish name the
	 * sec-mod instance and are authenticated with 'kd', see
	 * REQ-IPC-093 */
	int (*sso_start)(void *vctx, void *pool, const sso_key_data_st *kd,
			 const char *remote_ip, const char *strap_dh_pubkey,
			 char **url, char **state);
	/* optional: exchange the code returned by the provider and remember
	 * the identity under a fresh token, which is returned in the clear
	 * for an embedded browser, or only encrypted when the client asked
	 * for an external one */
	int (*sso_finish)(void *vctx, void *pool, const sso_key_data_st *kd,
			  const char *code, const char *state, char **token,
			  char **sso_token);
} auth_mod_st;

void main_auth_init(main_server_st *s);
void proc_auth_deinit(main_server_st *s, struct proc_st *proc);

/* The authentication with the worker thread is shown in ipc.proto.
 */
#endif
