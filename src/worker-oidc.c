/*
 * Copyright (C) 2026 ocserv contributors
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

#include <config.h>

#ifdef SUPPORT_OIDC_AUTH

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ipc.pb-c.h>

#include <vpn.h>
#include <worker.h>
#include <common.h>
#include <tlslib.h>
#include "common-config.h"
#include "html.h"
#include <ccan/str/hex/hex.h>

/*
 * The port Cisco's external browser protocol uses for the client's local
 * listener, and the path it expects the token on.
 */
#define OIDC_EXTERNAL_BROWSER_PORT (29786)

/*
 * Whether the browser login is offered on this virtual host, that is,
 * whether its OpenID Connect method is configured with mode=browser. There
 * is at most one such method. The configured methods are checked rather
 * than the enabled ones, as the worker disables a method once it fails
 * over to the next one.
 */
bool oidc_browser_login_enabled(worker_st *ws)
{
	unsigned int i;

	for (i = 0; i < WSSCONFIG(ws)->auth_methods; i++) {
		const auth_struct_st *auth = &WSSCONFIG(ws)->auth[i];

		if ((auth->type & AUTH_TYPE_OIDC) && auth->additional != NULL)
			return ((const oidc_cfg_st *)auth->additional)->mode ==
			       OIDC_MODE_BROWSER;
	}

	return false;
}

/*
 * The index of the sec-mod instance which a state or a token of a browser
 * login names: its first byte, in hex, as in the session ID. The browser and
 * the client may reach the server from different addresses, and so be served
 * by workers assigned to different instances. The sec-mod instance
 * authenticates the value, which is all that this is for.
 */
bool oidc_value_instance(const char *value, unsigned int *instance)
{
	uint8_t idx;

	if (value == NULL || !hex_decode(value, 2, &idx, sizeof(idx)))
		return false;

	*instance = idx;
	return true;
}

/*
 * Extract a query string parameter. Returns a newly allocated,
 * URL-decoded value, or NULL when the parameter is absent.
 */
static char *oidc_query_param(worker_st *ws, const char *url, const char *name)
{
	const char *query = strchr(url, '?');
	const char *p;
	size_t namelen = strlen(name);

	if (query == NULL)
		return NULL;

	p = query + 1;
	while (*p != 0) {
		const char *end = strchr(p, '&');
		size_t len = (end != NULL) ? (size_t)(end - p) : strlen(p);

		if (len > namelen + 1 && strncmp(p, name, namelen) == 0 &&
		    p[namelen] == '=') {
			return unescape_url(ws, p + namelen + 1,
					    len - namelen - 1, NULL);
		}

		if (end == NULL)
			break;
		p = end + 1;
	}

	return NULL;
}

/*
 * Ask the security module to begin an authorization request and return
 * the URL the browser is to open, at the provider. The caller owns the
 * result.
 */
char *oidc_get_login_url(worker_st *ws, unsigned int external_browser)
{
	SecOidcStartMsg req = SEC_OIDC_START_MSG__INIT;
	SecOidcStartReplyMsg *rep = NULL;
	char *url = NULL;
	int ret, sd = -1;

	PROTOBUF_ALLOCATOR(pa, ws);

	req.vhost = ws->vhost->name;
	req.remote_ip = ws->remote_ip_str;

	/*
	 * The key is only of use when the client drives a browser of its
	 * own; otherwise the token travels in a cookie.
	 */
	if (external_browser && ws->req.strap_dh_pubkey[0] != 0)
		req.strap_dh_pubkey = ws->req.strap_dh_pubkey;

	sd = connect_to_secmod(ws);
	if (sd == -1) {
		oclog(ws, LOG_ERR, "failed connecting to sec mod");
		return NULL;
	}

	ret = send_msg_to_secmod(
		ws, sd, CMD_SEC_OIDC_START, &req,
		(pack_size_func)sec_oidc_start_msg__get_packed_size,
		(pack_func)sec_oidc_start_msg__pack);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "failed sending oidc start to sec mod");
		close(sd);
		return NULL;
	}

	ret = recv_msg(ws, sd, CMD_SEC_OIDC_START_REPLY, (void *)&rep,
		       (unpack_func)sec_oidc_start_reply_msg__unpack,
		       WSRCONFIG(ws)->auth_timeout);
	close(sd);

	if (ret < 0) {
		oclog(ws, LOG_ERR, "error receiving oidc start reply");
		return NULL;
	}

	if (rep->ok && rep->authorization_url != NULL)
		url = talloc_strdup(ws, rep->authorization_url);
	else
		oclog(ws, LOG_ERR, "sec-mod could not start the login");

	sec_oidc_start_reply_msg__free_unpacked(rep, &pa);
	return url;
}

/*
 * The page the browser lands on once the login is done. A client with an
 * embedded browser only uses it as a signal and never renders it, but with
 * an external browser the user is left looking at this window.
 */
int get_oidc_final_handler(worker_st *ws, unsigned int http_ver)
{
	static const char page[] =
		"<!DOCTYPE html><html><head>"
		"<meta charset=\"utf-8\"><title>Signed in</title></head>"
		"<body><p>You are signed in. You can close this window.</p>"
		"</body></html>";
	int ret;

	oclog(ws, LOG_HTTP_DEBUG, "OIDC: the final page was reached");

	cstp_cork(ws);
	ret = cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret >= 0)
		ret = cstp_puts(ws,
				"Content-Type: text/html; charset=utf-8\r\n");
	if (ret >= 0)
		ret = cstp_printf(ws, "Content-Length: %d\r\n",
				  (int)(sizeof(page) - 1));
	if (ret >= 0)
		ret = cstp_puts(ws, "\r\n");
	if (ret >= 0)
		ret = cstp_send(ws, page, sizeof(page) - 1);
	if (ret >= 0)
		ret = cstp_uncork(ws);

	return ret;
}

/*
 * The identity provider sent the user back with an authorization code.
 * Hand it to sec-mod, which exchanges it and returns a fresh token; the
 * token is handed only to this browser.
 */
int get_oidc_callback_handler(worker_st *ws, unsigned int http_ver)
{
	SecOidcFinishMsg req = SEC_OIDC_FINISH_MSG__INIT;
	SecOidcFinishReplyMsg *rep = NULL;
	const char *secret = "";
	char *secret_param = NULL;
	char *location = NULL;
	char *token_cookie = NULL;
	char *code = NULL;
	char *state = NULL;
	unsigned int instance;
	int ret, sd = -1;

	PROTOBUF_ALLOCATOR(pa, ws);

	code = oidc_query_param(ws, ws->req.url, "code");
	state = oidc_query_param(ws, ws->req.url, "state");

	if (code == NULL || state == NULL) {
		oclog(ws, LOG_INFO, "OIDC callback without code or state");
		goto fail;
	}

	req.vhost = ws->vhost->name;
	req.state = state;
	req.code = code;

	if (!oidc_value_instance(state, &instance)) {
		oclog(ws, LOG_INFO, "the presented state names no instance");
		goto fail;
	}

	sd = connect_to_specific_secmod(ws, instance);
	if (sd == -1) {
		oclog(ws, LOG_ERR, "failed connecting to sec mod");
		goto fail;
	}

	ret = send_msg_to_secmod(
		ws, sd, CMD_SEC_OIDC_FINISH, &req,
		(pack_size_func)sec_oidc_finish_msg__get_packed_size,
		(pack_func)sec_oidc_finish_msg__pack);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "failed sending oidc finish to sec mod");
		close(sd);
		goto fail;
	}

	ret = recv_msg(ws, sd, CMD_SEC_OIDC_FINISH_REPLY, (void *)&rep,
		       (unpack_func)sec_oidc_finish_reply_msg__unpack,
		       WSRCONFIG(ws)->auth_timeout);
	close(sd);

	if (ret < 0) {
		oclog(ws, LOG_ERR, "error receiving oidc finish reply");
		goto fail;
	}

	if (!rep->ok || (rep->token == NULL && rep->sso_token == NULL)) {
		oclog(ws, LOG_INFO, "the browser login was not accepted");
		goto fail;
	}

	oclog(ws, LOG_HTTP_DEBUG, "the browser login completed");

	/*
	 * With camouflage enabled the browser must present the secret to
	 * reach the final page as well.
	 */
	if (WSRCONFIG(ws)->camouflage &&
	    WSRCONFIG(ws)->camouflage_secret != NULL) {
		secret_param = talloc_asprintf(
			ws, "?%s", WSRCONFIG(ws)->camouflage_secret);
		if (secret_param == NULL)
			goto fail;
		secret = secret_param;
	}

	if (rep->sso_token != NULL) {
		/*
		 * The client is driving a browser of its own and listens for
		 * the token on a local port; hand it over there. The value is
		 * encrypted to the key the client sent, so it is safe to put
		 * in a redirect.
		 */
		const char *host = ws->req.full_hostname[0] ?
					   ws->req.full_hostname :
					   ws->our_ip_str;
		char *final_url;
		char *escaped = NULL;
		char *escaped_final = NULL;

		final_url = talloc_asprintf(
			ws, "https://%s/+CSCOE+/saml_ac_login.html%s", host,
			secret);
		if (final_url == NULL)
			goto fail;

		escaped = escape_url(ws, rep->sso_token, strlen(rep->sso_token),
				     NULL);
		escaped_final =
			escape_url(ws, final_url, strlen(final_url), NULL);
		talloc_free(final_url);

		if (escaped != NULL && escaped_final != NULL)
			location = talloc_asprintf(
				ws, "http://localhost:%d/api/sso/%s?return=%s",
				OIDC_EXTERNAL_BROWSER_PORT, escaped,
				escaped_final);
		talloc_free(escaped);
		talloc_free(escaped_final);
	} else {
		/* the embedded browser picks the token out of this cookie */
		token_cookie = talloc_asprintf(
			ws,
			"Set-Cookie: acSamlv2Token=%s; Path=/; Secure; HttpOnly\r\n",
			rep->token);
		if (token_cookie == NULL)
			goto fail;

		location = talloc_asprintf(ws, "/+CSCOE+/saml_ac_login.html%s",
					   secret);
	}

	if (location == NULL)
		goto fail;

	cstp_cork(ws);
	ret = cstp_printf(ws, "HTTP/1.%u 302 Found\r\n", http_ver);
	if (ret >= 0 && token_cookie != NULL)
		ret = cstp_printf(ws, "%s", token_cookie);
	if (ret >= 0)
		ret = cstp_printf(ws, "Location: %s\r\n", location);
	if (ret >= 0)
		ret = cstp_puts(ws, "Content-Length: 0\r\n\r\n");
	if (ret >= 0)
		ret = cstp_uncork(ws);

	talloc_free(location);
	talloc_free(token_cookie);
	sec_oidc_finish_reply_msg__free_unpacked(rep, &pa);
	talloc_free(secret_param);
	talloc_free(code);
	talloc_free(state);
	return ret;

fail:
	talloc_free(location);
	talloc_free(token_cookie);
	if (rep != NULL)
		sec_oidc_finish_reply_msg__free_unpacked(rep, &pa);
	talloc_free(secret_param);
	talloc_free(code);
	talloc_free(state);
	return -1;
}

#endif
