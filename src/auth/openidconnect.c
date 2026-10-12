/*
 * Copyright (C) 2020 Microsoft Corporation
 *
 * Author: Alan Jowett
 *
 * This file is part of ocserv.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "vpn.h"
#include <ctype.h>
#include "auth/plain.h"
#include "common-config.h"
#include "auth/common.h"

#ifdef SUPPORT_OIDC_AUTH
#include <curl/curl.h>
#include <jansson.h>
#include <cjose/cjose.h>
#include <time.h>
#include <gnutls/crypto.h>
#include <ccan/hash/hash.h>
#include <ccan/htable/htable.h>
#include <ccan/list/list.h>
#include <base64-helper.h>
#include <gnutls/abstract.h>

#include "log.h"

#define MINIMUM_KEY_REFRESH_INTERVAL (900)

/* Default window for the user to complete the browser login; can be
 * overridden with 'sso_login_timeout' in the config file. */
#define DEFAULT_SSO_LOGIN_TIMEOUT (600)
/* the random values bound to a request: the state, the value set in the
 * browser, and the token which claims the session */
#define OIDC_RANDOM_SIZE (32)
/* How long a completed login waits for the client to claim it. The client
 * does so as soon as the browser leg is over, so it can be short. */
#define OIDC_CLAIM_TIMEOUT (60)
/*
 * Every login form served creates a pending request, before anything is
 * known about the client, so their number is bounded: overall, and per
 * address so that one client cannot take them all. Both can be overridden
 * with 'sso_max_pending' and 'sso_max_pending_per_ip' in the config file.
 * The per-address limit allows for many users behind one NAT address.
 */
#define DEFAULT_SSO_MAX_PENDING (1024)
#define DEFAULT_SSO_MAX_PENDING_PER_IP (32)
#define OIDC_VERIFIER_SIZE (64)
#define OIDC_NONCE_SIZE (32)

/* room for the terminating null of an encoded value */
#define OIDC_B64_SIZE(x) (BASE64_ENCODE_RAW_LENGTH(x) + 1)
#define OIDC_HEX_SIZE(x) ((x) * 2 + 1)

/*
 * The security module is single threaded, so a provider which stops
 * responding must not hold it for longer than necessary.
 */
#define OIDC_CONNECT_TIMEOUT (5)
#define OIDC_REQUEST_TIMEOUT (10)

/*
 * Cisco's external browser hands the token back to the client through a
 * local redirect, encrypted to the key agreement key the client sent. The
 * pieces are carried in a tag-length-value blob.
 */
#define HPKE_TAG_PUBKEY (1)
#define HPKE_TAG_AEAD_TAG (2)
#define HPKE_TAG_CIPHERTEXT (3)
#define HPKE_TAG_IV (4)
#define HPKE_IV_SIZE (12)
#define HPKE_AEAD_TAG_SIZE (12)
#define HPKE_KEY_SIZE (32)

/*
 * An authorization request, created when the login form is served.
 *
 * Two random values belong to it, each known to a different party:
 * 'state' travels through the browser and the provider and is public;
 * 'token' is issued once the code has been exchanged and is handed only
 * to the browser which completed the login, and it alone claims the
 * session. The verifier (PKCE) and the nonce never leave the server.
 *
 * A request waits in the pending table, keyed by state, until the
 * callback takes it; once the login succeeds it moves to the completed
 * table, keyed by token, until the client claims it.
 */

/*
 * A table of requests: a hash for lookups, and a list in order of
 * creation. All entries of a table live for the same time, so the list is
 * also in order of expiry and expired entries are found at its head,
 * without scanning the rest.
 */
typedef struct oidc_sso_table_st {
	struct htable htable;
	struct list_head list;
	size_t (*rehash)(const void *, void *);
	unsigned int size;
} oidc_sso_table_st;

/* how many pending requests an address has */
typedef struct oidc_sso_ip_st {
	char ip[MAX_IP_STR];
	unsigned int count;
} oidc_sso_ip_st;
typedef struct oidc_sso_state_st {
	/* position in the table's list, which is in order of expiry */
	struct list_node list;
	/* the client which asked for the form; pending requests are
	 * counted per address */
	char remote_ip[MAX_IP_STR];
	/*
	 * The values are handed back to clients driving an external browser,
	 * which accept only alphanumeric characters, so they are hex rather
	 * than base64url.
	 */
	char state[OIDC_HEX_SIZE(OIDC_RANDOM_SIZE)];
	char token[OIDC_HEX_SIZE(OIDC_RANDOM_SIZE)];
	char verifier[OIDC_B64_SIZE(OIDC_VERIFIER_SIZE)];
	char nonce[OIDC_B64_SIZE(OIDC_NONCE_SIZE)];
	time_t expires;
	char username[MAX_USERNAME_SIZE];
	char **groups;
	unsigned int groups_size;
	/* the client's key agreement key, when it asked for an external
	 * browser; the token is encrypted to it */
	char *strap_dh_pubkey;
} oidc_sso_state_st;

typedef struct oidc_vctx_st {
	json_t *config;
	json_t *jwks;
	void *pool;
	int minimum_jwk_refresh_time;
	int sso_login_timeout;
	int sso_max_pending;
	int sso_max_pending_per_ip;
	/* OIDC_MODE_BEARER or OIDC_MODE_BROWSER, from oidc[mode=...] */
	unsigned int mode;
	time_t last_jwks_load_time;
	oidc_sso_table_st *sso_states;
	oidc_sso_table_st *sso_claims;
	struct htable *sso_ips;
	/* from the provider's metadata document */
	char *issuer;
	char *authorization_endpoint;
	char *token_endpoint;
	const char *client_id;
	const char *client_secret;
	const char *redirect_uri;
	const char *groups_claim;
} oidc_vctx_st;

typedef struct oidc_ctx_st {
	oidc_vctx_st *vctx_st;
	char username[MAX_USERNAME_SIZE];
	int token_verified;
	char **groups;
	unsigned int groups_size;
} oidc_ctx_st;

static bool oidc_fetch_oidc_keys(oidc_vctx_st *vctx);
static bool oidc_verify_token(oidc_vctx_st *vctx, const char *token,
			      size_t token_length, const char *expected_nonce,
			      char user_name[MAX_USERNAME_SIZE],
			      oidc_ctx_st *ct);
static json_t *oidc_token_exchange(oidc_vctx_st *vctx, const char *code,
				   const char *verifier);
static int oidc_sso_start(void *vctx, void *pool, const char *remote_ip,
			  const char *strap_dh_pubkey, char **url,
			  char **state);
static int oidc_sso_finish(void *vctx, void *pool, const char *code,
			   const char *state, char **token, char **sso_token);

static char *oidc_encrypt_for_client(void *pool, const char *pubkey_b64,
				     const char *value);

static void oidc_extract_groups(json_t *token_claims, const char *claim_name,
				oidc_ctx_st *ct);

static size_t oidc_sso_state_rehash(const void *_e, void *unused)
{
	const oidc_sso_state_st *e = _e;

	return hash_string(e->state);
}

/* The first argument is the entry from the hash, the second the key. */
static bool oidc_sso_state_cmp(const void *_c1, void *_c2)
{
	const oidc_sso_state_st *c1 = _c1;
	const oidc_sso_state_st *c2 = _c2;

	return strcmp(c1->state, c2->state) == 0;
}

static size_t oidc_sso_claim_rehash(const void *_e, void *unused)
{
	const oidc_sso_state_st *e = _e;

	return hash_string(e->token);
}

static bool oidc_sso_claim_cmp(const void *_c1, void *_c2)
{
	const oidc_sso_state_st *c1 = _c1;
	const oidc_sso_state_st *c2 = _c2;

	return strcmp(c1->token, c2->token) == 0;
}

static size_t oidc_sso_ip_rehash(const void *_e, void *unused)
{
	const oidc_sso_ip_st *e = _e;

	return hash_string(e->ip);
}

static bool oidc_sso_ip_cmp(const void *_c1, void *_c2)
{
	const oidc_sso_ip_st *c1 = _c1;
	const oidc_sso_ip_st *c2 = _c2;

	return strcmp(c1->ip, c2->ip) == 0;
}

static oidc_sso_table_st *
oidc_sso_table_new(oidc_vctx_st *vctx, size_t (*rehash)(const void *, void *))
{
	oidc_sso_table_st *t = talloc_zero(vctx->pool, oidc_sso_table_st);

	if (t == NULL) {
		oc_syslog(LOG_ERR, "ocserv-oidc: cannot allocate state DB");
		exit(EXIT_FAILURE);
	}

	htable_init(&t->htable, rehash, NULL);
	list_head_init(&t->list);
	t->rehash = rehash;
	return t;
}

static bool oidc_sso_table_add(oidc_sso_table_st *t, oidc_sso_state_st *e)
{
	if (!htable_add(&t->htable, t->rehash(e, NULL), e))
		return false;

	list_add_tail(&t->list, &e->list);
	t->size++;
	return true;
}

static void oidc_sso_table_del(oidc_sso_table_st *t, oidc_sso_state_st *e)
{
	htable_del(&t->htable, t->rehash(e, NULL), e);
	list_del(&e->list);
	t->size--;
}

static void oidc_sso_table_free(oidc_sso_table_st *t)
{
	oidc_sso_state_st *e, *next;

	if (t == NULL)
		return;

	list_for_each_safe(&t->list, e, next, list)
	{
		talloc_free(e);
	}

	htable_clear(&t->htable);
	talloc_free(t);
}

/* The entry counting the pending requests of an address, if any. */
static oidc_sso_ip_st *oidc_sso_ip_find(oidc_vctx_st *vctx, const char *ip)
{
	oidc_sso_ip_st key;

	strlcpy(key.ip, ip, sizeof(key.ip));

	return htable_get(vctx->sso_ips, oidc_sso_ip_rehash(&key, NULL),
			  oidc_sso_ip_cmp, &key);
}

static void oidc_sso_state_db_init(oidc_vctx_st *vctx)
{
	vctx->sso_states = oidc_sso_table_new(vctx, oidc_sso_state_rehash);
	vctx->sso_claims = oidc_sso_table_new(vctx, oidc_sso_claim_rehash);

	vctx->sso_ips = talloc(vctx->pool, struct htable);
	if (vctx->sso_ips == NULL) {
		oc_syslog(LOG_ERR, "ocserv-oidc: cannot allocate state DB");
		exit(EXIT_FAILURE);
	}
	htable_init(vctx->sso_ips, oidc_sso_ip_rehash, NULL);
}

static void oidc_sso_state_db_deinit(oidc_vctx_st *vctx)
{
	oidc_sso_ip_st *t;
	struct htable_iter iter;

	oidc_sso_table_free(vctx->sso_states);
	vctx->sso_states = NULL;
	oidc_sso_table_free(vctx->sso_claims);
	vctx->sso_claims = NULL;

	if (vctx->sso_ips == NULL)
		return;

	t = htable_first(vctx->sso_ips, &iter);
	while (t != NULL) {
		talloc_free(t);
		t = htable_next(vctx->sso_ips, &iter);
	}
	htable_clear(vctx->sso_ips);
	talloc_free(vctx->sso_ips);
	vctx->sso_ips = NULL;
}

/*
 * Add a pending request, within the limits. The per-address count is
 * kept alongside.
 */
static bool oidc_sso_pending_add(oidc_vctx_st *vctx, oidc_sso_state_st *e)
{
	oidc_sso_ip_st *ip;

	if (vctx->sso_states->size >= (unsigned int)vctx->sso_max_pending) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: too many pending authorization requests; refusing one from %s",
			e->remote_ip);
		return false;
	}

	ip = oidc_sso_ip_find(vctx, e->remote_ip);
	if (ip != NULL &&
	    ip->count >= (unsigned int)vctx->sso_max_pending_per_ip) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: too many pending authorization requests from %s",
			e->remote_ip);
		return false;
	}

	if (ip == NULL) {
		ip = talloc_zero(vctx->pool, oidc_sso_ip_st);
		if (ip == NULL)
			return false;
		strlcpy(ip->ip, e->remote_ip, sizeof(ip->ip));
		if (!htable_add(vctx->sso_ips, oidc_sso_ip_rehash(ip, NULL),
				ip)) {
			talloc_free(ip);
			return false;
		}
	}

	if (!oidc_sso_table_add(vctx->sso_states, e)) {
		if (ip->count == 0) {
			htable_del(vctx->sso_ips, oidc_sso_ip_rehash(ip, NULL),
				   ip);
			talloc_free(ip);
		}
		return false;
	}

	ip->count++;
	return true;
}

static void oidc_sso_pending_del(oidc_vctx_st *vctx, oidc_sso_state_st *e)
{
	oidc_sso_ip_st *ip;

	oidc_sso_table_del(vctx->sso_states, e);

	ip = oidc_sso_ip_find(vctx, e->remote_ip);
	if (ip != NULL && --ip->count == 0) {
		htable_del(vctx->sso_ips, oidc_sso_ip_rehash(ip, NULL), ip);
		talloc_free(ip);
	}
}

/*
 * Drop requests and logins which were not taken in time. Only the expired
 * entries at the head of each list are visited.
 */
static void oidc_sso_state_expire(oidc_vctx_st *vctx)
{
	oidc_sso_state_st *e;
	time_t now = time(NULL);

	while ((e = list_top(&vctx->sso_states->list, oidc_sso_state_st,
			     list)) != NULL &&
	       e->expires <= now) {
		oidc_sso_pending_del(vctx, e);
		talloc_free(e);
	}

	while ((e = list_top(&vctx->sso_claims->list, oidc_sso_state_st,
			     list)) != NULL &&
	       e->expires <= now) {
		oidc_sso_table_del(vctx->sso_claims, e);
		talloc_free(e);
	}
}

/* Fill 'out' with OIDC_RANDOM_SIZE random bytes, hex encoded. */
static int oidc_random_hex(char out[OIDC_HEX_SIZE(OIDC_RANDOM_SIZE)])
{
	uint8_t rnd[OIDC_RANDOM_SIZE];
	gnutls_datum_t d = { rnd, sizeof(rnd) };
	size_t len = OIDC_HEX_SIZE(OIDC_RANDOM_SIZE);

	if (gnutls_rnd(GNUTLS_RND_RANDOM, rnd, sizeof(rnd)) < 0)
		return -1;

	if (gnutls_hex_encode(&d, out, &len) < 0)
		return -1;

	return 0;
}

/*
 * Create a pending authorization request. The returned entry stays owned
 * by the state DB. Returns NULL on failure.
 */
static oidc_sso_state_st *oidc_sso_state_new(oidc_vctx_st *vctx,
					     const char *remote_ip)
{
	oidc_sso_state_st *e;
	uint8_t rnd[OIDC_VERIFIER_SIZE];

	oidc_sso_state_expire(vctx);

	e = talloc_zero(vctx->pool, oidc_sso_state_st);
	if (e == NULL)
		return NULL;

	if (oidc_random_hex(e->state) < 0)
		goto fail;

	if (gnutls_rnd(GNUTLS_RND_RANDOM, rnd, OIDC_VERIFIER_SIZE) < 0)
		goto fail;
	oc_base64url_encode((char *)rnd, OIDC_VERIFIER_SIZE, e->verifier,
			    sizeof(e->verifier));

	if (gnutls_rnd(GNUTLS_RND_RANDOM, rnd, OIDC_NONCE_SIZE) < 0)
		goto fail;
	oc_base64url_encode((char *)rnd, OIDC_NONCE_SIZE, e->nonce,
			    sizeof(e->nonce));

	if (e->state[0] == 0 || e->verifier[0] == 0 || e->nonce[0] == 0)
		goto fail;

	e->expires = time(NULL) + vctx->sso_login_timeout;
	strlcpy(e->remote_ip, remote_ip != NULL ? remote_ip : "",
		sizeof(e->remote_ip));

	if (!oidc_sso_pending_add(vctx, e))
		goto fail;

	return e;

fail:
	talloc_free(e);
	return NULL;
}

/* Look up a pending request without removing it. */
static oidc_sso_state_st *oidc_sso_state_find(oidc_vctx_st *vctx,
					      const char *state)
{
	oidc_sso_state_st key;

	if (state == NULL || state[0] == 0)
		return NULL;

	oidc_sso_state_expire(vctx);

	strlcpy(key.state, state, sizeof(key.state));

	return htable_get(&vctx->sso_states->htable,
			  oidc_sso_state_rehash(&key, NULL), oidc_sso_state_cmp,
			  &key);
}

/*
 * Look up and remove a pending request. The caller owns the returned
 * entry and must free it or hand it back to a table.
 */
static oidc_sso_state_st *oidc_sso_state_take(oidc_vctx_st *vctx,
					      const char *state)
{
	oidc_sso_state_st *e;

	e = oidc_sso_state_find(vctx, state);
	if (e == NULL)
		return NULL;

	oidc_sso_pending_del(vctx, e);
	return e;
}

/*
 * Look up and remove a completed login by its token. The caller owns the
 * returned entry and must free it. A token is never accepted twice.
 */
static oidc_sso_state_st *oidc_sso_claim_take(oidc_vctx_st *vctx,
					      const char *token)
{
	oidc_sso_state_st key;
	oidc_sso_state_st *e;

	if (token == NULL || token[0] == 0)
		return NULL;

	oidc_sso_state_expire(vctx);

	strlcpy(key.token, token, sizeof(key.token));

	e = htable_get(&vctx->sso_claims->htable,
		       oidc_sso_claim_rehash(&key, NULL), oidc_sso_claim_cmp,
		       &key);
	if (e == NULL)
		return NULL;

	oidc_sso_table_del(vctx->sso_claims, e);
	return e;
}

/* A positive number from the config file, or the default. */
static int oidc_config_limit(json_t *config, const char *name, int def)
{
	json_t *v = json_object_get(config, name);

	if (v == NULL)
		return def;

	if (!json_is_integer(v) || json_integer_value(v) <= 0 ||
	    json_integer_value(v) > INT_MAX) {
		oc_syslog(LOG_ERR, "ocserv-oidc: invalid %s; using default",
			  name);
		return def;
	}

	return (int)json_integer_value(v);
}

static void oidc_vhost_init(void **vctx, void *pool, void *additional)
{
	const oidc_cfg_st *cfg = (const oidc_cfg_st *)additional;
	const char *config = cfg != NULL ? cfg->config : NULL;
	json_error_t err;
	struct oidc_vctx_st *vc;

	vc = talloc(pool, struct oidc_vctx_st);
	if (vc == NULL) {
		oc_syslog(LOG_ERR, "ocserv-oidc allocation failure!");
		exit(EXIT_FAILURE);
	}
	vc->config = NULL;
	vc->jwks = NULL;
	vc->issuer = NULL;
	vc->authorization_endpoint = NULL;
	vc->token_endpoint = NULL;
	vc->client_id = NULL;
	vc->client_secret = NULL;
	vc->redirect_uri = NULL;
	vc->groups_claim = NULL;
	vc->mode = cfg != NULL ? cfg->mode : OIDC_MODE_BEARER;
	vc->pool = pool;
	oidc_sso_state_db_init(vc);

	if (config == NULL) {
		oc_syslog(LOG_ERR, "ocserv-oidc: no configuration passed!");
		exit(EXIT_FAILURE);
	}

	vc->config = json_load_file(config, 0, &err);
	if (vc->config == NULL) {
		oc_syslog(LOG_ERR,
			  "ocserv-oidc: failed to load config file: %s",
			  config);
		exit(EXIT_FAILURE);
	}

	if (!json_object_get(vc->config, "openid_configuration_url")) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: config file missing openid_configuration_url");
		exit(EXIT_FAILURE);
	}

	if (!json_object_get(vc->config, "required_claims")) {
		oc_syslog(LOG_ERR,
			  "ocserv-oidc: config file missing required_claims");
		exit(EXIT_FAILURE);
	}

	if (!json_object_get(vc->config, "user_name_claim")) {
		oc_syslog(LOG_ERR,
			  "ocserv-oidc: config file missing user_name_claim");
		exit(EXIT_FAILURE);
	}

	if (json_object_get(vc->config, "minimum_jwk_refresh_time")) {
		vc->minimum_jwk_refresh_time = json_integer_value(
			json_object_get(vc->config,
					"minimum_jwk_refresh_time"));
	} else {
		vc->minimum_jwk_refresh_time = MINIMUM_KEY_REFRESH_INTERVAL;
	}

	if (json_object_get(vc->config, "sso_login_timeout")) {
		vc->sso_login_timeout = json_integer_value(
			json_object_get(vc->config, "sso_login_timeout"));
		if (vc->sso_login_timeout <= 0) {
			oc_syslog(
				LOG_ERR,
				"ocserv-oidc: invalid sso_login_timeout; using default");
			vc->sso_login_timeout = DEFAULT_SSO_LOGIN_TIMEOUT;
		}
	} else {
		vc->sso_login_timeout = DEFAULT_SSO_LOGIN_TIMEOUT;
	}

	vc->sso_max_pending = oidc_config_limit(vc->config, "sso_max_pending",
						DEFAULT_SSO_MAX_PENDING);
	vc->sso_max_pending_per_ip =
		oidc_config_limit(vc->config, "sso_max_pending_per_ip",
				  DEFAULT_SSO_MAX_PENDING_PER_IP);

	vc->client_id =
		json_string_value(json_object_get(vc->config, "client_id"));
	vc->client_secret =
		json_string_value(json_object_get(vc->config, "client_secret"));
	vc->redirect_uri =
		json_string_value(json_object_get(vc->config, "redirect_uri"));
	vc->groups_claim =
		json_string_value(json_object_get(vc->config, "groups_claim"));

	/*
	 * The mode decides how users log in; a setting which only the other
	 * mode uses is pointed out rather than silently ignored.
	 */
	if (vc->mode == OIDC_MODE_BROWSER &&
	    (vc->client_id == NULL || vc->redirect_uri == NULL)) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: mode=browser needs client_id and redirect_uri in the config file");
		exit(EXIT_FAILURE);
	}

	if (vc->mode == OIDC_MODE_BEARER && vc->client_id != NULL) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: client_id is set but the mode is bearer; set mode=browser to offer the browser login");
	}

	if (!oidc_fetch_oidc_keys(vc)) {
		oc_syslog(LOG_ERR, "ocserv-oidc: failed to load jwks");
		exit(EXIT_FAILURE);
	}

	if (vc->mode == OIDC_MODE_BROWSER &&
	    (vc->issuer == NULL || vc->authorization_endpoint == NULL ||
	     vc->token_endpoint == NULL)) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: mode=browser needs the issuer and the authorization and token endpoints in the provider's metadata document");
		exit(EXIT_FAILURE);
	}

	*vctx = (void *)vc;
}

static void oidc_vhost_deinit(void *ctx)
{
	oidc_vctx_st *vctx = (oidc_vctx_st *)ctx;

	if (!vctx) {
		return;
	}

	oidc_sso_state_db_deinit(vctx);
	talloc_free(vctx->issuer);
	vctx->issuer = NULL;
	talloc_free(vctx->authorization_endpoint);
	vctx->authorization_endpoint = NULL;
	talloc_free(vctx->token_endpoint);
	vctx->token_endpoint = NULL;

	if (vctx->jwks) {
		json_decref(vctx->jwks);
		vctx->jwks = NULL;
	}

	if (vctx->config) {
		json_decref(vctx->config);
		vctx->config = NULL;
	}
}

static int oidc_auth_init(void **ctx, void *pool, void *vctx,
			  const common_auth_init_st *info)
{
	oidc_vctx_st *vt = (oidc_vctx_st *)vctx;
	oidc_ctx_st *ct;

	ct = talloc_zero(pool, struct oidc_ctx_st);
	if (!ct) {
		return ERR_AUTH_FAIL;
	}
	ct->vctx_st = vt;
	*ctx = (void *)ct;

	if (info->oidc_token != NULL && info->oidc_token[0] != 0) {
		/*
		 * The client presents the token the browser login handed to
		 * it; the identity was established when the code was
		 * exchanged.
		 */
		oidc_sso_state_st *st;

		st = oidc_sso_claim_take(vt, info->oidc_token);
		if (st == NULL) {
			oc_syslog(
				LOG_NOTICE,
				"ocserv-oidc: no completed login for the presented token");
			return ERR_AUTH_FAIL;
		}

		strlcpy(ct->username, st->username, sizeof(ct->username));
		if (st->groups != NULL && st->groups_size > 0) {
			ct->groups = talloc_steal(ct, st->groups);
			ct->groups_size = st->groups_size;
		}

		talloc_free(st);
		ct->token_verified = 1;
		return 0;
	}

	/* the client presented a token it obtained on its own, which only
	 * the bearer token mode accepts */
	if (vt->mode != OIDC_MODE_BEARER) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: a bearer token was presented, but the mode is browser");
		return ERR_AUTH_FAIL;
	}

	if (oidc_verify_token(ct->vctx_st, info->username,
			      strlen(info->username), NULL, ct->username, ct)) {
		ct->token_verified = 1;
		return 0;
	}

	return ERR_AUTH_FAIL;
}

static int oidc_auth_user(void *ctx, char *username, int username_size)
{
	oidc_ctx_st *ct = (oidc_ctx_st *)ctx;

	if (ct->token_verified) {
		strlcpy(username, ct->username, username_size);
		return 0;
	}
	return ERR_AUTH_FAIL;
}

static int oidc_auth_group(void *ctx, const char *suggested, char *groupname,
			   int groupname_size)
{
	oidc_ctx_st *ct = (oidc_ctx_st *)ctx;
	unsigned int i, found = 0;

	groupname[0] = 0;

	/*
	 * Unlike a radius reply, which the VPN administrator composes, the
	 * claim comes from the directory and carries every group the user
	 * has, in no guaranteed order. Some of them may well match a
	 * config-per-group entry, so picking one on the user's behalf would
	 * silently apply a configuration they did not ask for. The session
	 * uses the server defaults instead.
	 */
	if (suggested == NULL)
		return 0;

	for (i = 0; i < ct->groups_size; i++) {
		if (strcmp(suggested, ct->groups[i]) == 0) {
			strlcpy(groupname, ct->groups[i], groupname_size);
			found = 1;
			break;
		}
	}

	if (found == 0) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: user '%s' requested group '%s' but is not a member",
			ct->username, suggested);
		return -1;
	}

	return 0;
}

static int oidc_auth_pass(void *ctx, const char *pass, unsigned int pass_len)
{
	return ERR_AUTH_FAIL;
}

static int oidc_auth_msg(void *ctx, void *pool, passwd_msg_st *pst)
{
	pst->counter = 0; /* we support a single password */

	/* use the default prompt */
	return 0;
}

static void oidc_auth_deinit(void *ctx)
{
	talloc_free(ctx);
}

const struct auth_mod_st oidc_auth_funcs = { .type = AUTH_TYPE_OIDC,
					     .allows_retries = 1,
					     .vhost_init = oidc_vhost_init,
					     .vhost_deinit = oidc_vhost_deinit,
					     .auth_init = oidc_auth_init,
					     .auth_deinit = oidc_auth_deinit,
					     .auth_msg = oidc_auth_msg,
					     .auth_pass = oidc_auth_pass,
					     .auth_user = oidc_auth_user,
					     .auth_group = oidc_auth_group,
					     .group_list = NULL,
					     .sso_start = oidc_sso_start,
					     .sso_finish = oidc_sso_finish };

// Key management
typedef struct oidc_json_parser_context {
	void *pool;
	char *buffer;
	size_t length;
	size_t offset;
} oidc_json_parser_context;

// Callback from CURL for each block as it is downloaded
static size_t oidc_json_parser_context_callback(char *ptr, size_t size,
						size_t nmemb, void *userdata)
{
	oidc_json_parser_context *context =
		(oidc_json_parser_context *)userdata;
	size_t new_offset = context->offset + nmemb;

	// Check for buffer overflow
	if (new_offset < nmemb) {
		return 0;
	}

	if (context->offset + nmemb > context->length) {
		size_t new_size = (nmemb + context->length) * 3 / 2;
		void *new_buffer = talloc_realloc_size(
			context->pool, context->buffer, new_size);

		if (new_buffer) {
			context->buffer = new_buffer;
			context->length = new_size;
		} else {
			return 0;
		}
	}

	memcpy(context->buffer + context->offset, ptr, nmemb);
	context->offset = new_offset;

	return nmemb;
}

/*
 * Download a JSON document from the provided URI and return it in a jansson
 * object. When post_data is not NULL the request is a POST with an
 * application/x-www-form-urlencoded body.
 */
static json_t *oidc_fetch_json_from_uri(void *pool, const char *uri,
					const char *post_data)
{
	oidc_json_parser_context context = { pool, NULL, 0, 0 };
	json_t *json = NULL;
	json_error_t err;
	CURL *curl = NULL;
	CURLcode res;

	context.length = 4096;
	context.buffer = talloc_size(context.pool, context.length);

	if (context.buffer == NULL) {
		goto cleanup;
	}

	curl = curl_easy_init();
	if (!curl) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: failed to download JSON document: URI %s",
			uri);
		goto cleanup;
	}

	res = curl_easy_setopt(curl, CURLOPT_URL, uri);
	if (res != CURLE_OK) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: failed to download JSON document: URI %s, CURLcode %d",
			uri, res);
		goto cleanup;
	}

	res = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
			       (long)OIDC_CONNECT_TIMEOUT);
	if (res != CURLE_OK) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: failed to set the connect timeout: URI %s, CURLcode %d",
			uri, res);
		goto cleanup;
	}

	res = curl_easy_setopt(curl, CURLOPT_TIMEOUT,
			       (long)OIDC_REQUEST_TIMEOUT);
	if (res != CURLE_OK) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: failed to set the request timeout: URI %s, CURLcode %d",
			uri, res);
		goto cleanup;
	}

	if (post_data != NULL) {
		res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
		if (res != CURLE_OK) {
			oc_syslog(
				LOG_ERR,
				"ocserv-oidc: failed to set POST body: URI %s, CURLcode %d",
				uri, res);
			goto cleanup;
		}
	}

	res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			       oidc_json_parser_context_callback);
	if (res != CURLE_OK) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: failed to download JSON document: URI %s, CURLcode %d",
			uri, res);
		goto cleanup;
	}

	res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &context);
	if (res != CURLE_OK) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: failed to download JSON document: URI %s, CURLcode %d",
			uri, res);
		goto cleanup;
	}

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: failed to download JSON document: URI %s, CURLcode %d",
			uri, res);
		goto cleanup;
	}

	json = json_loadb(context.buffer, context.offset, 0, &err);
	if (!json) {
		oc_syslog(LOG_ERR,
			  "ocserv-oidc: failed to parse JSON document: URI %s",
			  uri);
		goto cleanup;
	}

cleanup:
	if (context.buffer) {
		talloc_free(context.buffer);
	}

	if (curl) {
		curl_easy_cleanup(curl);
	}

	return json;
}

/*
 * Exchange an authorization code for tokens (RFC 6749 section 4.1.3),
 * proving possession of the PKCE verifier. Returns the token endpoint
 * response, or NULL on failure.
 */
static json_t *oidc_token_exchange(oidc_vctx_st *vctx, const char *code,
				   const char *verifier)
{
	json_t *response = NULL;
	CURL *curl = NULL;
	char *esc_code = NULL;
	char *esc_verifier = NULL;
	char *esc_redirect = NULL;
	char *esc_client = NULL;
	char *esc_secret = NULL;
	char *body = NULL;

	if (vctx->token_endpoint == NULL || vctx->client_id == NULL ||
	    vctx->redirect_uri == NULL) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: the authorization code flow is not configured");
		goto cleanup;
	}

	/* only used to percent-encode the parameters */
	curl = curl_easy_init();
	if (curl == NULL) {
		goto cleanup;
	}

	esc_code = curl_easy_escape(curl, code, 0);
	esc_verifier = curl_easy_escape(curl, verifier, 0);
	esc_redirect = curl_easy_escape(curl, vctx->redirect_uri, 0);
	esc_client = curl_easy_escape(curl, vctx->client_id, 0);

	if (esc_code == NULL || esc_verifier == NULL || esc_redirect == NULL ||
	    esc_client == NULL) {
		goto cleanup;
	}

	if (vctx->client_secret != NULL) {
		esc_secret = curl_easy_escape(curl, vctx->client_secret, 0);
		if (esc_secret == NULL) {
			goto cleanup;
		}
	}

	body = talloc_asprintf(
		vctx->pool,
		"grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s%s%s",
		esc_code, esc_redirect, esc_client, esc_verifier,
		esc_secret ? "&client_secret=" : "",
		esc_secret ? esc_secret : "");
	if (body == NULL) {
		goto cleanup;
	}

	response = oidc_fetch_json_from_uri(vctx->pool, vctx->token_endpoint,
					    body);
	if (response == NULL) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: token endpoint request failed");
		goto cleanup;
	}

	if (json_object_get(response, "error")) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: token endpoint returned error: %s",
			json_string_value(json_object_get(response, "error")));
		json_decref(response);
		response = NULL;
		goto cleanup;
	}

cleanup:
	if (body) {
		talloc_free(body);
	}
	if (esc_code) {
		curl_free(esc_code);
	}
	if (esc_verifier) {
		curl_free(esc_verifier);
	}
	if (esc_redirect) {
		curl_free(esc_redirect);
	}
	if (esc_client) {
		curl_free(esc_client);
	}
	if (esc_secret) {
		curl_free(esc_secret);
	}
	if (curl) {
		curl_easy_cleanup(curl);
	}

	return response;
}

/*
 * Begin an authorization code flow: create a pending request and build
 * the URL the user's browser should be sent to. The caller owns the
 * returned strings.
 */
static int oidc_sso_start(void *vctx, void *pool, const char *remote_ip,
			  const char *strap_dh_pubkey, char **url, char **state)
{
	oidc_vctx_st *vc = (oidc_vctx_st *)vctx;
	oidc_sso_state_st *st;
	uint8_t hash[32];
	char challenge[OIDC_B64_SIZE(sizeof(hash))];
	CURL *curl = NULL;
	char *esc_client = NULL;
	char *esc_redirect = NULL;
	int ret = -1;

	*url = NULL;
	*state = NULL;

	if (vc->mode != OIDC_MODE_BROWSER) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: a browser login was requested, but the mode is bearer");
		return -1;
	}

	if (vc->issuer == NULL || vc->authorization_endpoint == NULL ||
	    vc->client_id == NULL || vc->redirect_uri == NULL) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: the authorization code flow is not configured");
		return -1;
	}

	st = oidc_sso_state_new(vc, remote_ip);
	if (st == NULL) {
		oc_syslog(LOG_ERR,
			  "ocserv-oidc: cannot create authorization request");
		return -1;
	}

	if (strap_dh_pubkey != NULL && strap_dh_pubkey[0] != 0) {
		st->strap_dh_pubkey = talloc_strdup(st, strap_dh_pubkey);
		if (st->strap_dh_pubkey == NULL)
			goto cleanup;
	}

	curl = curl_easy_init();
	if (curl == NULL)
		goto cleanup;

	esc_client = curl_easy_escape(curl, vc->client_id, 0);
	esc_redirect = curl_easy_escape(curl, vc->redirect_uri, 0);
	if (esc_client == NULL || esc_redirect == NULL)
		goto cleanup;

	/* PKCE S256: challenge = base64url(sha256(verifier)) */
	if (gnutls_hash_fast(GNUTLS_DIG_SHA256, st->verifier,
			     strlen(st->verifier), hash) < 0)
		goto cleanup;
	oc_base64url_encode((char *)hash, sizeof(hash), challenge,
			    sizeof(challenge));

	*url = talloc_asprintf(
		pool,
		"%s?response_type=code&scope=openid&client_id=%s&redirect_uri=%s&state=%s&nonce=%s&code_challenge=%s&code_challenge_method=S256",
		vc->authorization_endpoint, esc_client, esc_redirect, st->state,
		st->nonce, challenge);
	if (*url == NULL)
		goto cleanup;

	*state = talloc_strdup(pool, st->state);
	if (*state == NULL)
		goto cleanup;

	ret = 0;

cleanup:
	if (ret < 0) {
		talloc_free(*url);
		*url = NULL;
		talloc_free(oidc_sso_state_take(vc, st->state));
	}
	if (esc_client)
		curl_free(esc_client);
	if (esc_redirect)
		curl_free(esc_redirect);
	if (curl)
		curl_easy_cleanup(curl);
	return ret;
}

/*
 * Exchange the authorization code and remember the resulting identity
 * under a fresh token, which only the browser completing the login
 * receives. The request is taken whatever the outcome, so a state serves
 * one callback at most.
 */
static int oidc_sso_finish(void *vctx, void *pool, const char *code,
			   const char *state, char **token, char **sso_token)
{
	oidc_vctx_st *vc = (oidc_vctx_st *)vctx;
	oidc_sso_state_st *st;
	oidc_ctx_st *tmp;
	json_t *tokens;
	json_t *id_token;
	bool verified;

	*token = NULL;
	*sso_token = NULL;

	st = oidc_sso_state_take(vc, state);
	if (st == NULL) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: no pending authorization request for the presented state");
		return -1;
	}

	tokens = oidc_token_exchange(vc, code, st->verifier);
	if (tokens == NULL)
		goto fail;

	id_token = json_object_get(tokens, "id_token");
	if (!id_token || !json_string_value(id_token)) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: token endpoint response has no id_token");
		json_decref(tokens);
		goto fail;
	}

	tmp = talloc_zero(st, oidc_ctx_st);
	if (tmp == NULL) {
		json_decref(tokens);
		goto fail;
	}
	tmp->vctx_st = vc;

	verified = oidc_verify_token(vc, json_string_value(id_token),
				     strlen(json_string_value(id_token)),
				     st->nonce, tmp->username, tmp);
	json_decref(tokens);

	if (!verified)
		goto fail;

	strlcpy(st->username, tmp->username, sizeof(st->username));
	if (tmp->groups != NULL && tmp->groups_size > 0) {
		st->groups = talloc_steal(st, tmp->groups);
		st->groups_size = tmp->groups_size;
	}
	talloc_free(tmp);

	if (oidc_random_hex(st->token) < 0)
		goto fail;

	/*
	 * The token is handed out in the one form the browser needs, so that
	 * it is never in the clear where it does not have to be.
	 */
	if (st->strap_dh_pubkey == NULL) {
		/* the embedded browser picks it out of a cookie */
		*token = talloc_strdup(pool, st->token);
	} else {
		/*
		 * A client which asked for an external browser cannot pick
		 * the value out of a cookie, so it is encrypted to the key
		 * it sent and handed back through a redirect to its local
		 * listener.
		 */
		*sso_token = oidc_encrypt_for_client(pool, st->strap_dh_pubkey,
						     st->token);
	}

	if (*token == NULL && *sso_token == NULL) {
		oc_syslog(LOG_ERR, "ocserv-oidc: cannot hand the token over");
		goto fail;
	}

	st->expires = time(NULL) + OIDC_CLAIM_TIMEOUT;
	if (!oidc_sso_table_add(vc->sso_claims, st))
		goto fail;

	oc_syslog(LOG_INFO, "ocserv-oidc: browser login completed for '%s'",
		  st->username);
	return 0;

fail:
	talloc_free(*token);
	*token = NULL;
	talloc_free(*sso_token);
	*sso_token = NULL;
	talloc_free(st);
	return -1;
}

static void hpke_put_be16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

/*
 * Encrypt a value to the client's key agreement key, in the form the
 * external browser expects: an ephemeral ECDH exchange over secp256r1, a
 * key derived with HKDF-SHA256, and AES-256-GCM. Returns the blob in
 * base64, or NULL on failure.
 */
static char *oidc_encrypt_for_client(void *pool, const char *pubkey_b64,
				     const char *value)
{
	gnutls_pubkey_t peer = NULL;
	gnutls_privkey_t ours = NULL;
	gnutls_pubkey_t ours_pub = NULL;
	gnutls_datum_t peer_der = { NULL, 0 };
	gnutls_datum_t our_der = { NULL, 0 };
	gnutls_datum_t secret = { NULL, 0 };
	gnutls_cipher_hd_t cipher = NULL;
	uint8_t prk[HPKE_KEY_SIZE];
	uint8_t key[HPKE_KEY_SIZE];
	uint8_t iv[HPKE_IV_SIZE];
	uint8_t aead_tag[HPKE_AEAD_TAG_SIZE];
	gnutls_datum_t secret_d, prk_d, info_d, key_d, iv_d;
	uint8_t *ct = NULL;
	size_t ct_len = strlen(value);
	uint8_t *blob = NULL;
	size_t blob_len, pos;
	char *b64 = NULL;
	size_t b64_len;

	peer_der.data = talloc_size(pool, strlen(pubkey_b64));
	if (peer_der.data == NULL)
		goto cleanup;

	{
		size_t len = strlen(pubkey_b64);

		if (oc_base64_decode((uint8_t *)pubkey_b64, len, peer_der.data,
				     &len) == 0) {
			oc_syslog(LOG_NOTICE,
				  "ocserv-oidc: cannot decode the client key");
			goto cleanup;
		}
		peer_der.size = len;
	}

	if (gnutls_pubkey_init(&peer) < 0)
		goto cleanup;

	if (gnutls_pubkey_import(peer, &peer_der, GNUTLS_X509_FMT_DER) < 0) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: cannot import the client key");
		goto cleanup;
	}

	if (gnutls_privkey_init(&ours) < 0)
		goto cleanup;

	if (gnutls_privkey_generate(
		    ours, GNUTLS_PK_EC,
		    GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0) < 0) {
		oc_syslog(LOG_ERR,
			  "ocserv-oidc: cannot generate an ephemeral key");
		goto cleanup;
	}

	if (gnutls_privkey_derive_secret(ours, peer, NULL, &secret, 0) < 0) {
		oc_syslog(LOG_ERR, "ocserv-oidc: key agreement failed");
		goto cleanup;
	}

	if (secret.size != HPKE_KEY_SIZE)
		goto cleanup;

	secret_d.data = secret.data;
	secret_d.size = secret.size;
	prk_d.data = prk;
	prk_d.size = sizeof(prk);

	if (gnutls_hkdf_extract(GNUTLS_MAC_SHA256, &secret_d, NULL, prk) < 0)
		goto cleanup;

	info_d.data = (unsigned char *)"AC_ECIES";
	info_d.size = sizeof("AC_ECIES") - 1;

	if (gnutls_hkdf_expand(GNUTLS_MAC_SHA256, &prk_d, &info_d, key,
			       sizeof(key)) < 0)
		goto cleanup;

	if (gnutls_rnd(GNUTLS_RND_NONCE, iv, sizeof(iv)) < 0)
		goto cleanup;

	ct = talloc_size(pool, ct_len);
	if (ct == NULL)
		goto cleanup;
	memcpy(ct, value, ct_len);

	key_d.data = key;
	key_d.size = sizeof(key);
	iv_d.data = iv;
	iv_d.size = sizeof(iv);

	if (gnutls_cipher_init(&cipher, GNUTLS_CIPHER_AES_256_GCM, &key_d,
			       &iv_d) < 0)
		goto cleanup;

	if (gnutls_cipher_encrypt(cipher, ct, ct_len) < 0)
		goto cleanup;

	if (gnutls_cipher_tag(cipher, aead_tag, sizeof(aead_tag)) < 0)
		goto cleanup;

	if (gnutls_pubkey_init(&ours_pub) < 0)
		goto cleanup;

	if (gnutls_pubkey_import_privkey(ours_pub, ours, 0, 0) < 0)
		goto cleanup;

	if (gnutls_pubkey_export2(ours_pub, GNUTLS_X509_FMT_DER, &our_der) < 0)
		goto cleanup;

	/* the marker, then four tag-length-value records */
	blob_len = 2 + (4 + our_der.size) + (4 + sizeof(aead_tag)) +
		   (4 + ct_len) + (4 + sizeof(iv));

	blob = talloc_size(pool, blob_len);
	if (blob == NULL)
		goto cleanup;

	pos = 0;
	hpke_put_be16(blob + pos, 0x0001);
	pos += 2;

	hpke_put_be16(blob + pos, HPKE_TAG_PUBKEY);
	hpke_put_be16(blob + pos + 2, our_der.size);
	memcpy(blob + pos + 4, our_der.data, our_der.size);
	pos += 4 + our_der.size;

	hpke_put_be16(blob + pos, HPKE_TAG_AEAD_TAG);
	hpke_put_be16(blob + pos + 2, sizeof(aead_tag));
	memcpy(blob + pos + 4, aead_tag, sizeof(aead_tag));
	pos += 4 + sizeof(aead_tag);

	hpke_put_be16(blob + pos, HPKE_TAG_CIPHERTEXT);
	hpke_put_be16(blob + pos + 2, ct_len);
	memcpy(blob + pos + 4, ct, ct_len);
	pos += 4 + ct_len;

	hpke_put_be16(blob + pos, HPKE_TAG_IV);
	hpke_put_be16(blob + pos + 2, sizeof(iv));
	memcpy(blob + pos + 4, iv, sizeof(iv));

	b64_len = BASE64_ENCODE_RAW_LENGTH(blob_len) + 1;
	b64 = talloc_size(pool, b64_len);
	if (b64 == NULL)
		goto cleanup;

	oc_base64_encode((char *)blob, blob_len, b64, b64_len);

cleanup:
	if (cipher)
		gnutls_cipher_deinit(cipher);
	if (ours_pub)
		gnutls_pubkey_deinit(ours_pub);
	if (ours)
		gnutls_privkey_deinit(ours);
	if (peer)
		gnutls_pubkey_deinit(peer);
	gnutls_free(secret.data);
	gnutls_free(our_der.data);
	talloc_free(ct);
	talloc_free(blob);
	talloc_free(peer_der.data);

	return b64;
}

// Download and parse the JWT keys for this virtual server context
static bool oidc_fetch_oidc_keys(oidc_vctx_st *vctx)
{
	bool result = false;
	json_t *jwks = NULL;
	json_t *oidc_config = NULL;
	json_t *openid_configuration_url =
		json_object_get(vctx->config, "openid_configuration_url");

	json_t *array;
	size_t index;
	json_t *value;

	if (!openid_configuration_url) {
		oc_syslog(
			LOG_ERR,
			"ocserv-oidc: openid_configuration_url missing from config");
		goto cleanup;
	}

	oidc_config = oidc_fetch_json_from_uri(
		vctx->pool, json_string_value(openid_configuration_url), NULL);

	if (!oidc_config) {
		oc_syslog(LOG_ERR,
			  "ocserv-oidc: Unable to fetch config doc from %s",
			  json_string_value(openid_configuration_url));
		goto cleanup;
	}

	json_t *jwks_uri = json_object_get(oidc_config, "jwks_uri");

	if (!jwks_uri || !json_string_value(jwks_uri)) {
		oc_syslog(LOG_ERR,
			  "ocserv-oidc: jwks_uri missing from config doc");
		goto cleanup;
	}

	{
		json_t *issuer = json_object_get(oidc_config, "issuer");
		json_t *authz_ep =
			json_object_get(oidc_config, "authorization_endpoint");
		json_t *token_ep =
			json_object_get(oidc_config, "token_endpoint");

		talloc_free(vctx->issuer);
		vctx->issuer = NULL;
		talloc_free(vctx->authorization_endpoint);
		vctx->authorization_endpoint = NULL;
		talloc_free(vctx->token_endpoint);
		vctx->token_endpoint = NULL;

		/*
		 * The tokens of the code flow must come from the provider
		 * described here; a metadata document without an issuer does
		 * not say which that is.
		 */
		if (issuer && json_string_value(issuer)) {
			vctx->issuer = talloc_strdup(vctx->pool,
						     json_string_value(issuer));
		} else {
			oc_syslog(
				LOG_INFO,
				"ocserv-oidc: issuer missing from config doc; mode=browser cannot be used");
		}

		if (authz_ep && json_string_value(authz_ep)) {
			vctx->authorization_endpoint = talloc_strdup(
				vctx->pool, json_string_value(authz_ep));
		} else {
			oc_syslog(
				LOG_INFO,
				"ocserv-oidc: authorization_endpoint missing from config doc; mode=browser cannot be used");
		}

		if (token_ep && json_string_value(token_ep)) {
			vctx->token_endpoint = talloc_strdup(
				vctx->pool, json_string_value(token_ep));
		} else {
			oc_syslog(
				LOG_INFO,
				"ocserv-oidc: token_endpoint missing from config doc; mode=browser cannot be used");
		}
	}

	jwks = oidc_fetch_json_from_uri(vctx->pool, json_string_value(jwks_uri),
					NULL);
	if (!jwks) {
		oc_syslog(LOG_ERR,
			  "ocserv-oidc: failed to fetch keys from jwks_uri %s",
			  json_string_value(jwks_uri));
		goto cleanup;
	}

	array = json_object_get(jwks, "keys");
	if (array == NULL) {
		oc_syslog(LOG_ERR, "ocserv-oidc: JWK keys malformed");
		goto cleanup;
	}

	// Log the keys obtained
	json_array_foreach(array, index, value)
	{
		json_t *key_kid = json_object_get(value, "kid");

		oc_syslog(LOG_INFO, "ocserv-oidc: fetched new JWK %s",
			  json_string_value(key_kid));
	}

	if (vctx->jwks) {
		json_decref(vctx->jwks);
	}

	vctx->last_jwks_load_time = time(NULL);

	vctx->jwks = jwks;
	jwks = NULL;
	result = true;

cleanup:
	if (oidc_config) {
		json_decref(oidc_config);
	}

	if (jwks) {
		json_decref(jwks);
	}
	return result;
}

static bool oidc_verify_lifetime(json_t *token_claims)
{
	bool result = false;

	// Get the time bounds of the token
	json_t *token_nbf = json_object_get(token_claims, "nbf");
	json_t *token_iat = json_object_get(token_claims, "iat");
	json_t *token_exp = json_object_get(token_claims, "exp");
	time_t current_time = time(NULL);

	/*
	 * 'nbf' is not among the ID Token claims required by OpenID Connect
	 * Core 1.0 section 2, and several providers omit it; enforce it only
	 * when present.
	 */
	if (token_nbf && !json_is_integer(token_nbf)) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: Token has a malformed 'nbf' claim");
		goto cleanup;
	}

	if (!token_exp || !json_integer_value(token_exp)) {
		oc_syslog(LOG_NOTICE, "ocserv-oidc: Token missing 'exp' claim");
		goto cleanup;
	}

	if (!token_iat || !json_integer_value(token_iat)) {
		oc_syslog(LOG_NOTICE, "ocserv-oidc: Token missing 'iat' claim");
		goto cleanup;
	}

	// Check to ensure the token is within it's validity
	if ((token_nbf && json_integer_value(token_nbf) > current_time) ||
	    json_integer_value(token_exp) < current_time) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: Token not within validity period NBF: %lld EXP: %lld Current: %ld",
			token_nbf ? json_integer_value(token_nbf) : 0,
			json_integer_value(token_exp), current_time);
		goto cleanup;
	}

	result = true;

cleanup:
	return result;
}

static bool oidc_verify_required_claims(json_t *required_claims,
					json_t *token_claims)
{
	bool result = false;

	const char *required_claim_name;
	json_t *required_claim_value;
	json_t *token_claim_value;

	// Ensure all the required claims are present in the token
	json_object_foreach(required_claims, required_claim_name,
			    required_claim_value)
	{
		token_claim_value =
			json_object_get(token_claims, required_claim_name);
		if (!json_equal(required_claim_value, token_claim_value)) {
			oc_syslog(
				LOG_NOTICE,
				"ocserv-oidc: Required claim not met. Claim: %s Expected Value: %s",
				required_claim_name,
				json_string_value(required_claim_value));
			goto cleanup;
		}
	}

	result = true;

cleanup:
	return result;
}

/*
 * An ID Token obtained through the code flow must come from the provider
 * whose metadata was read, and name this server as its audience (OpenID
 * Connect Core 1.0, section 3.1.3.7): 'iss' must equal the issuer of the
 * metadata exactly, and 'aud' must contain the client_id. When 'aud' names
 * other audiences as well, 'azp' must be present to say which party the
 * token was issued to, and whenever 'azp' is present it must be the
 * client_id.
 */
static bool oidc_verify_issuer_audience(json_t *token_claims,
					const char *issuer,
					const char *client_id)
{
	json_t *iss = json_object_get(token_claims, "iss");
	json_t *aud = json_object_get(token_claims, "aud");
	json_t *azp = json_object_get(token_claims, "azp");
	json_t *value;
	size_t i;
	bool found = false;

	/*
	 * The issuer is read again whenever the metadata document is
	 * refetched, and a document without one leaves it unset, possibly
	 * while a login started earlier is still waiting for its callback.
	 */
	if (issuer == NULL || client_id == NULL) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: no issuer or client_id to check the token against");
		return false;
	}

	if (!json_is_string(iss) ||
	    strcmp(json_string_value(iss), issuer) != 0) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: token was not issued by '%s'", issuer);
		return false;
	}

	if (json_is_string(aud)) {
		found = strcmp(json_string_value(aud), client_id) == 0;
	} else if (json_is_array(aud)) {
		json_array_foreach(aud, i, value)
		{
			if (json_is_string(value) &&
			    strcmp(json_string_value(value), client_id) == 0)
				found = true;
		}

		if (found && json_array_size(aud) > 1 && azp == NULL) {
			oc_syslog(
				LOG_NOTICE,
				"ocserv-oidc: token has several audiences but no 'azp' claim");
			return false;
		}
	}

	if (!found) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: token audience does not include '%s'",
			  client_id);
		return false;
	}

	if (azp != NULL && (!json_is_string(azp) ||
			    strcmp(json_string_value(azp), client_id) != 0)) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: token was issued to another party");
		return false;
	}

	return true;
}

static bool oidc_map_user_name(json_t *user_name_claim, json_t *token_claims,
			       char user_name[MAX_USERNAME_SIZE])
{
	bool result = false;

	// Pull the user name from the token
	json_t *token_user_name_claim = json_object_get(
		token_claims, json_string_value(user_name_claim));
	if (!token_user_name_claim ||
	    !json_string_value(token_user_name_claim)) {
		oc_syslog(LOG_NOTICE, "ocserv-oidc: Token missing '%s' claim",
			  json_string_value(user_name_claim));
		goto cleanup;
	}

	strlcpy(user_name, json_string_value(token_user_name_claim),
		MAX_USERNAME_SIZE);
	result = true;

cleanup:
	return result;
}

static json_t *oidc_extract_claims(cjose_jws_t *jws)
{
	cjose_err err;
	json_error_t json_err;
	uint8_t *plain_text = NULL;
	size_t plain_text_size = 0;
	json_t *token_claims = NULL;

	// Extract the claim portion from the token
	if (!cjose_jws_get_plaintext(jws, &plain_text, &plain_text_size,
				     &err)) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: Failed to get plain text from token");
		goto cleanup;
	}

	// Parse the claim JSON
	token_claims =
		json_loadb((char *)plain_text, plain_text_size, 0, &json_err);
	if (!token_claims) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: Failed to get claims from token");
		goto cleanup;
	}

cleanup:
	return token_claims;
}

/*
 * Collect the group names from the configured claim. The claim may be an
 * array of strings or a single string; anything else is ignored. Values
 * are stored verbatim: normalising them is the identity provider's job.
 */
static void oidc_extract_groups(json_t *token_claims, const char *claim_name,
				oidc_ctx_st *ct)
{
	json_t *value = json_object_get(token_claims, claim_name);
	size_t index;
	json_t *item;
	unsigned int n = 0;

	ct->groups = NULL;
	ct->groups_size = 0;

	if (value == NULL)
		return;

	if (json_is_string(value)) {
		ct->groups = talloc_array(ct, char *, 1);
		if (ct->groups == NULL)
			return;
		ct->groups[0] =
			talloc_strdup(ct->groups, json_string_value(value));
		if (ct->groups[0] == NULL) {
			talloc_free(ct->groups);
			ct->groups = NULL;
			return;
		}
		ct->groups_size = 1;
		return;
	}

	if (!json_is_array(value))
		return;

	ct->groups = talloc_array(ct, char *, json_array_size(value));
	if (ct->groups == NULL)
		return;

	json_array_foreach(value, index, item)
	{
		if (!json_is_string(item))
			continue;
		ct->groups[n] =
			talloc_strdup(ct->groups, json_string_value(item));
		if (ct->groups[n] == NULL)
			break;
		n++;
	}

	ct->groups_size = n;
}

static bool oidc_verify_signature(oidc_vctx_st *vctx, cjose_jws_t *jws)
{
	bool result = false;

	cjose_err err;
	cjose_jwk_t *jwk = NULL;
	json_t *token_header;
	json_t *token_kid;
	json_t *token_typ;
	json_t *array;
	size_t index;
	json_t *value;

	if (vctx->jwks == NULL) {
		oc_syslog(LOG_NOTICE, "ocserv-oidc: JWK keys not available");
		goto cleanup;
	}

	array = json_object_get(vctx->jwks, "keys");
	if (array == NULL) {
		oc_syslog(LOG_NOTICE, "ocserv-oidc: JWK keys malformed");
		goto cleanup;
	}

	// Get the token header
	token_header = cjose_jws_get_protected(jws);
	if (token_header == NULL) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: Token malformed - no header");
		goto cleanup;
	}

	// Get the kid of the key used to sign this token
	token_kid = json_object_get(token_header, "kid");
	if (token_kid == NULL || !json_string_value(token_kid)) {
		oc_syslog(LOG_NOTICE, "ocserv-oidc: Token malformed - no kid");
		goto cleanup;
	}

	token_typ = json_object_get(token_header, "typ");
	if (token_typ == NULL || !json_string_value(token_typ) ||
	    strcmp(json_string_value(token_typ), "JWT")) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: Token malformed - wrong typ claim");
		goto cleanup;
	}

	// Find the signing key in the keys collection
	json_array_foreach(array, index, value)
	{
		json_t *key_kid = json_object_get(value, "kid");

		if (json_equal(key_kid, token_kid)) {
			jwk = cjose_jwk_import_json(value, &err);
			break;
		}
	}

	if (jwk == NULL) {
		time_t now;

		oc_syslog(LOG_NOTICE, "ocserv-oidc: JWK with kid=%s not found",
			  json_string_value(token_kid));

		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: attempting to download new JWKs");
		now = time(NULL);
		if ((now - vctx->last_jwks_load_time) >
		    vctx->minimum_jwk_refresh_time) {
			oidc_fetch_oidc_keys(vctx);
		} else {
			oc_syslog(LOG_NOTICE,
				  "ocserv-oidc: skipping JWK refresh");
		}

		// Fail the request and let the client try again.
		goto cleanup;
	}

	if (!cjose_jws_verify(jws, jwk, &err)) {
		oc_syslog(LOG_NOTICE, "ocserv-oidc: Token failed validation %s",
			  err.message);
		goto cleanup;
	}

	result = true;

cleanup:
	if (jwk) {
		cjose_jwk_release(jwk);
	}

	return result;
}

// Verify that the provided token is signed
static bool oidc_verify_token(oidc_vctx_st *vctx, const char *token,
			      size_t token_length, const char *expected_nonce,
			      char user_name[MAX_USERNAME_SIZE],
			      oidc_ctx_st *ct)
{
	bool result = false;
	cjose_err err;
	cjose_jws_t *jws = NULL;
	json_t *token_claims = NULL;

	jws = cjose_jws_import(token, token_length, &err);
	if (jws == NULL) {
		oc_syslog(LOG_NOTICE, "ocserv-oidc: Token malformed - %s",
			  err.message);
		goto cleanup;
	}

	if (!oidc_verify_signature(vctx, jws)) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: Token signature validation failed");
		goto cleanup;
	}

	token_claims = oidc_extract_claims(jws);
	if (!token_claims) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: Unable to access token claims");
		goto cleanup;
	}

	if (!oidc_verify_lifetime(token_claims)) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: Token lifetime validation failed");
		goto cleanup;
	}

	if (!oidc_verify_required_claims(json_object_get(vctx->config,
							 "required_claims"),
					 token_claims)) {
		oc_syslog(
			LOG_NOTICE,
			"ocserv-oidc: Token required claims validation failed");
		goto cleanup;
	}

	/*
	 * A token from the code flow was issued to this server by the
	 * provider it asked, so it must say both. A bearer token was
	 * obtained by the client for its own purposes, and its issuer and
	 * audience are left to required_claims.
	 */
	if (expected_nonce != NULL &&
	    !oidc_verify_issuer_audience(token_claims, vctx->issuer,
					 vctx->client_id))
		goto cleanup;

	/*
	 * Binds the token to the authorization request we started; only
	 * applies to the code flow, where we generated the nonce.
	 */
	if (expected_nonce != NULL) {
		json_t *token_nonce = json_object_get(token_claims, "nonce");

		if (!token_nonce || !json_string_value(token_nonce) ||
		    strcmp(json_string_value(token_nonce), expected_nonce) !=
			    0) {
			oc_syslog(LOG_NOTICE,
				  "ocserv-oidc: Token nonce mismatch");
			goto cleanup;
		}
	}

	if (!oidc_map_user_name(json_object_get(vctx->config,
						"user_name_claim"),
				token_claims, user_name)) {
		oc_syslog(LOG_NOTICE,
			  "ocserv-oidc: Unable to map user name claim");
		goto cleanup;
	}

	/*
	 * Group membership is optional; when a claim is configured its
	 * values are used as-is, so that the naming policy stays with the
	 * identity provider.
	 */
	if (ct != NULL && vctx->groups_claim != NULL) {
		oidc_extract_groups(token_claims, vctx->groups_claim, ct);
	}

	result = true;

cleanup:
	if (jws) {
		cjose_jws_release(jws);
	}

	if (token_claims) {
		json_decref(token_claims);
	}

	return result;
}

#endif
