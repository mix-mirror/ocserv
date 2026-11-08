/*
 * Copyright (C) 2025 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Test: vhost config inheritance (#705).
 *
 * Verifies that a named vhost inherits a representative spread of fields
 * from the default vhost when those fields are not set in the vhost section,
 * and that vhost-specific values correctly override inherited ones.
 *
 * Covers both the ReloadableConfig path (cfg_copy_without_lists) and the
 * static_cfg_st path (vhost_inherit_static_config).
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <talloc.h>

#include "../src/main.h"
#include "../src/tlslib.h"
#include <snapshot.h>

/* -----------------------------------------------------------------------
 * TLS stubs: config.c calls these five functions; no real TLS is needed.
 * ----------------------------------------------------------------------- */
void tls_vhost_init(struct vhost_cfg_st *v)
{
	(void)v;
}
void tls_vhost_deinit(struct vhost_cfg_st *v)
{
	(void)v;
}
void tls_load_files(struct main_server_st *s, struct vhost_cfg_st *v,
		    unsigned int silent)
{
	(void)s;
	(void)v;
	(void)silent;
}
void tls_load_prio(struct main_server_st *s, struct vhost_cfg_st *v)
{
	(void)s;
	(void)v;
}
void tls_reload_crl(struct main_server_st *s, struct vhost_cfg_st *v,
		    unsigned int force)
{
	(void)s;
	(void)v;
	(void)force;
}
void *calc_sha1_hash(void *pool, char *file, unsigned int cert)
{
	(void)pool;
	(void)file;
	(void)cert;
	return NULL;
}

/* -----------------------------------------------------------------------
 * Compression stub: called from config.c under OCSERV_WORKER_PROCESS.
 * ----------------------------------------------------------------------- */
unsigned int switch_comp_priority(void *pool, const char *modstring)
{
	(void)pool;
	(void)modstring;
	return 1;
}

/* -----------------------------------------------------------------------
 * Worker group-list globals: used by the OCSERV_WORKER_PROCESS auth stubs
 * at the bottom of config.c.
 * ----------------------------------------------------------------------- */
char **pam_auth_group_list = NULL;
unsigned int pam_auth_group_list_size = 0;
char **gssapi_auth_group_list = NULL;
unsigned int gssapi_auth_group_list_size = 0;
char **plain_auth_group_list = NULL;
unsigned int plain_auth_group_list_size = 0;

/* -----------------------------------------------------------------------
 * Snapshot stubs: config.c creates/looks up file snapshots on Linux
 * (PROC_FS_SUPPORTED).  For the unit test we don't need real snapshots;
 * snapshot_lookup_filename returning -1 keeps the non-worker code path.
 * ----------------------------------------------------------------------- */
static int _dummy_snapshot_sentinel;

int snapshot_init(void *pool, struct snapshot_t **snap, const char *prefix)
{
	(void)pool;
	(void)prefix;
	*snap = (struct snapshot_t *)&_dummy_snapshot_sentinel;
	return 0;
}
int snapshot_create(struct snapshot_t *snap, const char *file)
{
	(void)snap;
	(void)file;
	return 0;
}
void snapshot_terminate(struct snapshot_t *snap)
{
	(void)snap;
}
int snapshot_lookup_filename(struct snapshot_t *snap, const char *name,
			     char **out)
{
	(void)snap;
	(void)name;
	(void)out;
	return -1;
}
size_t snapshot_entry_count(struct snapshot_t *snap)
{
	(void)snap;
	return 0;
}
int snapshot_first(struct snapshot_t *snap, struct htable_iter *iter, int *fd,
		   const char **name)
{
	(void)snap;
	(void)iter;
	(void)fd;
	(void)name;
	return -1;
}
int snapshot_next(struct snapshot_t *snap, struct htable_iter *iter, int *fd,
		  const char **name)
{
	(void)snap;
	(void)iter;
	(void)fd;
	(void)name;
	return -1;
}
int snapshot_restore_entry(struct snapshot_t *snap, int fd, const char *name)
{
	(void)snap;
	(void)fd;
	(void)name;
	return 0;
}

/* -----------------------------------------------------------------------
 * Pull in the config subsystems that config.c depends on.  These files are
 * all in core_sources (not in common_dep), so there are no duplicate-symbol
 * issues when linking against test_base_deps.
 * ----------------------------------------------------------------------- */
#include "../src/ip-util.c"
#include "../src/config-ports.c"
#include "../src/subconfig.c"
#include "../src/config-kkdcp.c"
#include "../src/config-copy.c"
#include "../src/config.c"

/* -----------------------------------------------------------------------
 * Helper: write the test config to a temp file.
 *
 * phase == 0: named vhost has no extra fields (pure inheritance test)
 * phase == 1: named vhost overrides keepalive
 * ----------------------------------------------------------------------- */
static void write_default_vhost(FILE *f, const char *srcdir)
{
	/* Default vhost — sets all fields under test */
	fprintf(f,
		"auth = \"plain[%s/data/test1.passwd]\"\n"
		"tcp-port = 4443\n"
		"socket-file = /tmp/ocserv-inherit-test.sock\n"
		"server-cert = %s/certs/server-cert.pem\n"
		"server-key = %s/certs/server-key.pem\n"
		"device = vpns\n"
		"ipv4-network = 192.168.100.0\n"
		"ipv4-netmask = 255.255.255.0\n"
		"keepalive = 11111\n"
		"dpd = 2222\n"
		"idle-timeout = 3333\n"
		"cookie-timeout = 4444\n"
		"deny-roaming = true\n"
		"banner = test-inherit-banner\n"
		"default-domain = inherit.example.com\n"
		"rx-data-per-sec = 100000\n"
		"mtu = 1280\n"
		"server-stats-reset-time = 86400\n",
		srcdir, srcdir, srcdir);
}

static void write_config(const char *path, const char *srcdir, int phase)
{
	FILE *f = fopen(path, "w");
	if (f == NULL) {
		fprintf(stderr, "cannot open temp config %s\n", path);
		exit(1);
	}

	write_default_vhost(f, srcdir);
	fprintf(f, "\n");

	if (phase == 2) {
		/* Named vhost omits auth/cert/key entirely — all must be inherited
		 * from the default vhost via vhost_inherit_static_config. */
		fprintf(f, "[vhost:named]\n"
			   "ipv4-network = 192.168.101.0\n"
			   "ipv4-netmask = 255.255.255.0\n");
	} else {
		/* Named vhost — only the mandatory fields; everything else inherited */
		fprintf(f,
			"[vhost:named]\n"
			"auth = \"plain[%s/data/test1.passwd]\"\n"
			"server-cert = %s/certs/server-cert.pem\n"
			"server-key = %s/certs/server-key.pem\n"
			"ipv4-network = 192.168.101.0\n"
			"ipv4-netmask = 255.255.255.0\n",
			srcdir, srcdir, srcdir);

		if (phase == 1) {
			/* Override a single ReloadableConfig scalar */
			fprintf(f, "keepalive = 55555\n");
		}
	}

	fclose(f);
}

/* -----------------------------------------------------------------------
 * Assertion helpers
 * ----------------------------------------------------------------------- */
#define CHECK_EQ_U(label, got, want)                                        \
	do {                                                                \
		if ((got) != (unsigned)(want)) {                            \
			fprintf(stderr,                                     \
				"FAIL %s: expected %u got %u (line %d)\n",  \
				(label), (unsigned)(want), (unsigned)(got), \
				__LINE__);                                  \
			exit(1);                                            \
		}                                                           \
	} while (0)

#define CHECK_EQ_U64(label, got, want)                                       \
	do {                                                                 \
		if ((got) != (uint64_t)(want)) {                             \
			fprintf(stderr,                                      \
				"FAIL %s: expected %" PRIu64 " got %" PRIu64 \
				" (line %d)\n",                              \
				(label), (uint64_t)(want), (uint64_t)(got),  \
				__LINE__);                                   \
			exit(1);                                             \
		}                                                            \
	} while (0)

#define CHECK_STR(label, got, want)                                          \
	do {                                                                 \
		if ((got) == NULL || strcmp((got), (want)) != 0) {           \
			fprintf(stderr,                                      \
				"FAIL %s: expected \"%s\" got \"%s\" (line " \
				"%d)\n",                                     \
				(label), (want), (got) ? (got) : "(null)",   \
				__LINE__);                                   \
			exit(1);                                             \
		}                                                            \
	} while (0)

/* Assert all 10 inherited fields on the named vhost */
static void check_inherited(vhost_cfg_st *named)
{
	ReloadableConfig *c = named->config;

	CHECK_EQ_U("keepalive", c->keepalive, 11111);
	CHECK_EQ_U("dpd", c->dpd, 2222);
	CHECK_EQ_U("idle_timeout", c->idle_timeout, 3333);
	CHECK_EQ_U("cookie_timeout", c->cookie_timeout, 4444);
	CHECK_EQ_U("deny_roaming", c->deny_roaming, 1);
	CHECK_STR("banner", c->banner, "test-inherit-banner");
	CHECK_STR("default_domain", c->default_domain, "inherit.example.com");
	CHECK_EQ_U64("rx_per_sec", c->rx_per_sec,
		     100); /* stored in KB: 100000/1000 */
	CHECK_EQ_U("default_mtu", c->default_mtu, 1280);
	CHECK_EQ_U("stats_reset_time", named->static_config.stats_reset_time,
		   86400);
}

/* -----------------------------------------------------------------------
 * Multi-line options: write a config with the given options in the default
 * and named vhost sections, and check it both parsed and after a reload.
 * ----------------------------------------------------------------------- */
static void write_options_config(const char *path, const char *srcdir,
				 const char *default_opts,
				 const char *named_opts)
{
	FILE *f = fopen(path, "w");

	if (f == NULL) {
		fprintf(stderr, "cannot open temp config %s\n", path);
		exit(1);
	}

	write_default_vhost(f, srcdir);
	fprintf(f,
		"%s\n"
		"[vhost:named]\n"
		"ipv4-network = 192.168.101.0\n"
		"ipv4-netmask = 255.255.255.0\n"
		"%s\n",
		default_opts, named_opts);
	fclose(f);
}

typedef void (*options_check_fn)(vhost_cfg_st *defvhost, vhost_cfg_st *named);

static void check_vhosts(struct list_head *vconfig, int reloaded,
			 options_check_fn check)
{
	vhost_cfg_st *defvhost = find_vhost(vconfig, NULL);
	vhost_cfg_st *named = find_vhost(vconfig, "named");

	if (defvhost == NULL || named == NULL || named->name == NULL) {
		fprintf(stderr, "FAIL: vhost not found (reloaded=%d)\n",
			reloaded);
		exit(1);
	}
	check(defvhost, named);
}

static void parse_options(void *pool, struct list_head *vconfig,
			  const char *path)
{
	list_head_init(vconfig);
	if (vhost_add(pool, vconfig, NULL, 0) == NULL) {
		fprintf(stderr, "vhost_add failed\n");
		exit(1);
	}
	parse_cfg_file(pool, path, vconfig, 0);
}

static void check_options(void *pool, const char *path, const char *srcdir,
			  const char *default_opts, const char *named_opts,
			  options_check_fn check)
{
	struct list_head vconfig;

	write_options_config(path, srcdir, default_opts, named_opts);
	parse_options(pool, &vconfig, path);
	check_vhosts(&vconfig, 0, check);

	reload_cfg_file(pool, &vconfig, 0);
	check_vhosts(&vconfig, 1, check);

	clear_old_configs(&vconfig);
}

/* Start with @named_opts in the named vhost, change them to
 * @reload_named_opts and reload: @check must hold after the reload. */
static void check_options_reload(void *pool, const char *path,
				 const char *srcdir, const char *default_opts,
				 const char *named_opts,
				 const char *reload_named_opts,
				 options_check_fn check)
{
	struct list_head vconfig;

	write_options_config(path, srcdir, default_opts, named_opts);
	parse_options(pool, &vconfig, path);

	write_options_config(path, srcdir, default_opts, reload_named_opts);
	reload_cfg_file(pool, &vconfig, 0);
	check_vhosts(&vconfig, 1, check);

	clear_old_configs(&vconfig);
}

/* Parsing a configuration whose named vhost sets @option must fail, with an
 * error naming the option and the vhost. parse_cfg_file() exits on a
 * configuration error, so it runs in a child. */
static void check_options_fail(void *pool, const char *path, const char *srcdir,
			       const char *default_opts, const char *named_opts,
			       const char *option)
{
	char *errpath = talloc_asprintf(pool, "%s.err", path);
	char err[4096];
	struct list_head vconfig;
	FILE *fp;
	size_t len;
	pid_t pid;
	int status;

	write_options_config(path, srcdir, default_opts, named_opts);

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "FAIL: fork failed\n");
		exit(1);
	}
	if (pid == 0) {
		if (freopen(errpath, "w", stderr) == NULL)
			_exit(2);
		list_head_init(&vconfig);
		if (vhost_add(pool, &vconfig, NULL, 0) == NULL)
			_exit(2);
		parse_cfg_file(pool, path, &vconfig, 0);
		_exit(0);
	}

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "FAIL: waitpid failed\n");
		exit(1);
	}

	fp = fopen(errpath, "r");
	len = fp ? fread(err, 1, sizeof(err) - 1, fp) : 0;
	err[len] = 0;
	if (fp)
		fclose(fp);
	unlink(errpath);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_FAILURE) {
		fprintf(stderr,
			"FAIL %s without auth: expected exit status %d, got 0x%x\n%s",
			option, EXIT_FAILURE, (unsigned)status, err);
		exit(1);
	}
	if (strstr(err, "vhost:named") == NULL ||
	    strstr(err, talloc_asprintf(pool, "'%s'", option)) == NULL) {
		fprintf(stderr,
			"FAIL %s without auth: expected an error naming '%s' and vhost:named, got:\n%s",
			option, option, err);
		exit(1);
	}
}

static void check_list(const char *label, char **list, size_t size,
		       const char *value)
{
	CHECK_EQ_U(label, size, 1);
	CHECK_STR(label, list[0], value);
}

/* Each vhost has one value of every list option: its own, or the default
 * vhost's if it does not set the option. */
static void check_lists(vhost_cfg_st *named, const char *dns, const char *nbns,
			const char *route, const char *no_route,
			const char *split_dns, const char *custom_header,
			const char *included_header)
{
	ReloadableConfig *c = named->config;

	check_list("dns", c->network->dns, c->network->n_dns, dns);
	check_list("nbns", c->network->nbns, c->network->n_nbns, nbns);
	check_list("route", c->network->routes, c->network->n_routes, route);
	check_list("no-route", c->network->no_routes, c->network->n_no_routes,
		   no_route);
	check_list("split-dns", c->split_dns, c->n_split_dns, split_dns);
	check_list("custom-header", c->custom_header, c->n_custom_header,
		   custom_header);
	check_list("included-http-headers", c->included_http_headers,
		   c->n_included_http_headers, included_header);
}

static void check_default_lists(vhost_cfg_st *vhost)
{
	check_lists(vhost, "192.0.2.1", "192.0.2.3",
		    "198.51.100.1/255.255.255.255",
		    "198.51.100.3/255.255.255.255", "a.example.com", "X-A: 1",
		    "X-C: 3");
}

static void check_inherited_lists(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_default_lists(defvhost);
	check_default_lists(named);
}

static void check_replaced_lists(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_default_lists(defvhost);
	check_lists(named, "192.0.2.2", "192.0.2.4",
		    "198.51.100.2/255.255.255.255",
		    "198.51.100.4/255.255.255.255", "b.example.com", "X-B: 2",
		    "X-D: 4");
}

static void check_dns_spellings(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_list("default dns", defvhost->config->network->dns,
		   defvhost->config->network->n_dns, "192.0.2.1");
	check_list("named ipv6-dns", named->config->network->dns,
		   named->config->network->n_dns, "2001:db8::1");
	check_list("default nbns", defvhost->config->network->nbns,
		   defvhost->config->network->n_nbns, "192.0.2.3");
	check_list("named ipv4-nbns", named->config->network->nbns,
		   named->config->network->n_nbns, "192.0.2.4");
}

static void check_port(const char *label, const ReloadableConfig *c,
		       unsigned int port)
{
	CHECK_EQ_U(label, c->n_fw_ports, 1);
	CHECK_EQ_U(label, c->fw_ports[0]->port, port);
}

static void check_ports_inherited(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_port("default restrict-user-to-ports", defvhost->config, 443);
	check_port("named restrict-user-to-ports", named->config, 443);
}

static void check_ports_replaced(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_port("default restrict-user-to-ports", defvhost->config, 443);
	check_port("named restrict-user-to-ports", named->config, 53);
}

static void check_suffix(const char *label, const char *got, const char *want)
{
	size_t glen = got ? strlen(got) : 0, wlen = strlen(want);

	if (glen < wlen || strcmp(got + glen - wlen, want) != 0) {
		fprintf(stderr, "FAIL %s: expected \"...%s\" got \"%s\"\n",
			label, want, got ? got : "(null)");
		exit(1);
	}
}

static void check_certs(const char *label, vhost_cfg_st *vhost,
			const char *cert, const char *key)
{
	CHECK_EQ_U(label, vhost->static_config.cert_size, 1);
	check_suffix(label, vhost->static_config.cert[0], cert);
	CHECK_EQ_U(label, vhost->static_config.key_size, 1);
	check_suffix(label, vhost->static_config.key[0], key);
}

static void check_certs_replaced(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_certs("default certs", defvhost, "/server-cert.pem",
		    "/server-key.pem");
	check_certs("named certs", named, "/server-cert-secp521r1.pem",
		    "/server-key-secp521r1.pem");
}

static void check_plain_auth(const char *label, vhost_cfg_st *vhost,
			     unsigned int methods, const char *passwd)
{
	const plain_cfg_st *plain =
		(const plain_cfg_st *)vhost->static_config.auth[0].additional;

	CHECK_EQ_U(label, vhost->static_config.auth_methods, methods);
	CHECK_EQ_U(label, vhost->static_config.auth[0].type,
		   AUTH_TYPE_PLAIN | AUTH_TYPE_USERNAME_PASS);
	check_suffix(label, plain->passwd, passwd);
}

static void check_auth_replaced(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_plain_auth("default auth", defvhost, 1, "/test1.passwd");
	check_plain_auth("named auth", named, 1, "/test-group.passwd");
}

/* The authentication options of REQ-CONFIG-CFG-011. The default vhost sets
 * all three; acct is only checked when compiled in. */
#ifdef HAVE_PAM
#define AUTH_GROUP_ACCT "acct = \"pam\"\n"
#else
#define AUTH_GROUP_ACCT ""
#endif /* HAVE_PAM */

static void check_acct(const char *label, vhost_cfg_st *vhost, int has_acct)
{
	if (AUTH_GROUP_ACCT[0] == 0)
		return;

	CHECK_EQ_U(label, vhost->static_config.acct.amod != NULL, has_acct);
}

static void check_auth_group_default(vhost_cfg_st *defvhost)
{
	check_plain_auth("default auth", defvhost, 2, "/test1.passwd");
	check_acct("default acct", defvhost, 1);
}

static void check_auth_group_inherited(vhost_cfg_st *defvhost,
				       vhost_cfg_st *named)
{
	check_auth_group_default(defvhost);
	check_plain_auth("named auth", named, 2, "/test1.passwd");
	CHECK_EQ_U("named enable-auth", named->static_config.auth[1].type,
		   AUTH_TYPE_CERTIFICATE);
	check_acct("named acct", named, 1);
}

static void check_auth_group_own_auth(vhost_cfg_st *defvhost,
				      vhost_cfg_st *named)
{
	check_auth_group_default(defvhost);
	check_plain_auth("named auth", named, 1, "/test-group.passwd");
	check_acct("named acct", named, 0);
}

static void check_auth_group(void *pool, const char *path, const char *srcdir)
{
	const char *defaults =
		talloc_asprintf(pool,
				"enable-auth = \"certificate\"\n"
				"ca-cert = %s/certs/ca.pem\n"
				"cert-user-oid = 0.9.2342.19200300.100.1.1\n"
				"%s",
				srcdir, AUTH_GROUP_ACCT);
	const char *own_auth = talloc_asprintf(
		pool, "auth = \"plain[%s/data/test-group.passwd]\"\n", srcdir);

	check_options(pool, path, srcdir, defaults, "",
		      check_auth_group_inherited);
	check_options(pool, path, srcdir, defaults, own_auth,
		      check_auth_group_own_auth);

	/* without auth, the vhost may not set enable-auth or acct */
	check_options_fail(pool, path, srcdir, defaults,
			   "enable-auth = \"certificate\"\n", "enable-auth");
	if (AUTH_GROUP_ACCT[0] != 0)
		check_options_fail(pool, path, srcdir, defaults,
				   AUTH_GROUP_ACCT, "acct");

	/* the group is decided at startup; a reload does not change it */
	check_options_reload(pool, path, srcdir, defaults, "", own_auth,
			     check_auth_group_inherited);
	check_options_reload(pool, path, srcdir, defaults, "",
			     "enable-auth = \"certificate\"\n",
			     check_auth_group_inherited);
	check_options_reload(pool, path, srcdir, defaults, own_auth, "",
			     check_auth_group_own_auth);
}

#ifdef HAVE_GSSAPI
#define DEFAULT_KKDCP "kkdcp = \"/KdcProxy EXAMPLE.COM udp@127.0.0.1:88\"\n"
#define OWN_KKDCP "kkdcp = \"/KdcProxy2 EXAMPLE.COM udp@127.0.0.1:88\"\n"

static void check_kkdcp(const char *label, const ReloadableConfig *c,
			const char *url)
{
	CHECK_EQ_U(label, c->n_kkdcp, 1);
	CHECK_STR(label, c->kkdcp[0]->url, url);
}

static void check_kkdcp_inherited(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_kkdcp("default kkdcp", defvhost->config, "/KdcProxy");
	check_kkdcp("named kkdcp", named->config, "/KdcProxy");
}

static void check_kkdcp_replaced(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_kkdcp("default kkdcp", defvhost->config, "/KdcProxy");
	check_kkdcp("named kkdcp", named->config, "/KdcProxy2");
}

/* kkdcp is inherited on its own, whether or not the vhost sets auth, and
 * a reload applies a change to it (REQ-CONFIG-CFG-010) */
static void check_kkdcp_inheritance(void *pool, const char *path,
				    const char *srcdir)
{
	const char *own_auth = talloc_asprintf(
		pool, "auth = \"plain[%s/data/test-group.passwd]\"\n", srcdir);

	check_options(pool, path, srcdir, DEFAULT_KKDCP, "",
		      check_kkdcp_inherited);
	check_options(pool, path, srcdir, DEFAULT_KKDCP, own_auth,
		      check_kkdcp_inherited);
	check_options(pool, path, srcdir, DEFAULT_KKDCP, OWN_KKDCP,
		      check_kkdcp_replaced);
	check_options(pool, path, srcdir, DEFAULT_KKDCP,
		      talloc_asprintf(pool, "%s%s", own_auth, OWN_KKDCP),
		      check_kkdcp_replaced);

	check_options_reload(pool, path, srcdir, DEFAULT_KKDCP, "", OWN_KKDCP,
			     check_kkdcp_replaced);
	check_options_reload(pool, path, srcdir, DEFAULT_KKDCP, "",
			     talloc_asprintf(pool, "%s%s", own_auth, OWN_KKDCP),
			     check_kkdcp_replaced);
	check_options_reload(pool, path, srcdir, DEFAULT_KKDCP, OWN_KKDCP, "",
			     check_kkdcp_inherited);
}
#else
static void check_kkdcp_inheritance(void *pool, const char *path,
				    const char *srcdir)
{
}
#endif /* HAVE_GSSAPI */

#define DEFAULT_LISTS                  \
	"dns = 192.0.2.1\n"            \
	"nbns = 192.0.2.3\n"           \
	"route = 198.51.100.1/32\n"    \
	"no-route = 198.51.100.3/32\n" \
	"split-dns = a.example.com\n"  \
	"custom-header = X-A: 1\n"     \
	"included-http-headers = X-C: 3\n"

#define MANY_VALUES 200

static char *many_options(void *pool, const char *option, const char *prefix,
			  unsigned int first)
{
	char *str = talloc_strdup(pool, "");
	unsigned int i;

	for (i = 0; i < MANY_VALUES; i++)
		str = talloc_asprintf_append(str, "%s = %s%u\n", option, prefix,
					     first + i);
	if (str == NULL) {
		fprintf(stderr, "memory\n");
		exit(1);
	}
	return str;
}

static void check_many_values(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	ReloadableConfig *d = defvhost->config;
	ReloadableConfig *c = named->config;
	char want[32];
	unsigned int i;

	CHECK_EQ_U("default custom-header count", d->n_custom_header,
		   MANY_VALUES);
	CHECK_EQ_U("named custom-header count", c->n_custom_header,
		   MANY_VALUES);
	for (i = 0; i < MANY_VALUES; i++) {
		snprintf(want, sizeof(want), "X-H%u", i);
		CHECK_STR("default custom-header", d->custom_header[i], want);
		snprintf(want, sizeof(want), "X-H%u", MANY_VALUES + i);
		CHECK_STR("named custom-header", c->custom_header[i], want);
	}
}

static void check_group(const char *what, const ReloadableConfig *c,
			unsigned int i, const char *name, const char *label)
{
	const SelectGroup *group = c->select_groups[i];

	CHECK_STR(what, group->name, name);
	if (label != NULL) {
		CHECK_STR(what, group->label, label);
	} else if (group->label != NULL) {
		fprintf(stderr,
			"FAIL %s: expected no label for %s, got \"%s\"\n", what,
			name, group->label);
		exit(1);
	}
}

static void check_groups_default(const ReloadableConfig *d)
{
	CHECK_EQ_U("default groups", d->n_select_groups, 2);
	check_group("default groups", d, 0, "group1", "Label One");
	check_group("default groups", d, 1, "group2", NULL);
}

static void check_groups_inherited(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_groups_default(defvhost->config);
	CHECK_EQ_U("inherited groups", named->config->n_select_groups, 2);
	check_group("inherited groups", named->config, 0, "group1",
		    "Label One");
	check_group("inherited groups", named->config, 1, "group2", NULL);
}

static void check_groups_replaced(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	check_groups_default(defvhost->config);
	CHECK_EQ_U("replaced groups", named->config->n_select_groups, 2);
	check_group("replaced groups", named->config, 0, "group3",
		    "Label Three");
	check_group("replaced groups", named->config, 1, "group4", NULL);
}

static void check_groups_empty_label(vhost_cfg_st *defvhost,
				     vhost_cfg_st *named)
{
	CHECK_EQ_U("empty label", named->config->n_select_groups, 2);
	check_group("empty label", named->config, 0, "group1", NULL);
	check_group("empty label", named->config, 1, "group2", "Label Two");
	check_group("empty label", defvhost->config, 0, "group1", NULL);
}

static void check_many_groups(vhost_cfg_st *defvhost, vhost_cfg_st *named)
{
	char want[32];
	unsigned int i;

	CHECK_EQ_U("default group count", defvhost->config->n_select_groups,
		   MANY_VALUES);
	CHECK_EQ_U("named group count", named->config->n_select_groups,
		   MANY_VALUES);
	for (i = 0; i < MANY_VALUES; i++) {
		snprintf(want, sizeof(want), "g%u", i);
		check_group("default groups", defvhost->config, i, want, NULL);
		snprintf(want, sizeof(want), "g%u", MANY_VALUES + i);
		check_group("named groups", named->config, i, want, NULL);
	}
}

static void check_groups_auto_selected(vhost_cfg_st *defvhost,
				       vhost_cfg_st *named)
{
	CHECK_EQ_U("default auto groups", defvhost->config->n_select_groups, 2);
	check_group("default auto groups", defvhost->config, 0, "auto1", NULL);
	check_group("default auto groups", defvhost->config, 1, "auto2", NULL);
	CHECK_EQ_U("named auto groups", named->config->n_select_groups, 2);
	check_group("named auto groups", named->config, 0, "auto1", NULL);
	check_group("named auto groups", named->config, 1, "auto2", NULL);
}

int main(void)
{
	void *pool;
	struct list_head vconfig;
	vhost_cfg_st *named;
	char tmpfile[256];
	const char *srcdir;
	static char auto1[] = "auto1", auto2[] = "auto2";
	static char *auto_groups[] = { auto1, auto2 };

	srcdir = getenv("srcdir");
	if (srcdir == NULL)
		srcdir = ".";

	snprintf(tmpfile, sizeof(tmpfile), "/tmp/ocserv-inherit-test-%d.conf",
		 (int)getpid());

	pool = talloc_new(NULL);
	if (pool == NULL) {
		fprintf(stderr, "talloc_new failed\n");
		exit(1);
	}

	/* Initialise the snapshot subsystem (needed by parse_cfg_file) */
	if (snapshot_init(pool, &config_snapshot, "/tmp/ocserv_ci_") < 0) {
		fprintf(stderr, "snapshot_init failed\n");
		exit(1);
	}

	/* ----------------------------------------------------------------
	 * Phase 1: pure inheritance — named vhost sets nothing extra.
	 * ---------------------------------------------------------------- */
	write_config(tmpfile, srcdir, 0);

	list_head_init(&vconfig);
	/* pre-create default vhost — parse_cfg_file requires it */
	if (vhost_add(pool, &vconfig, NULL, 0) == NULL) {
		fprintf(stderr, "vhost_add failed\n");
		exit(1);
	}
	strlcpy(cfg_file, tmpfile, sizeof(cfg_file));
	parse_cfg_file(pool, tmpfile, &vconfig, 0);

	named = find_vhost(&vconfig, "named");
	if (named == NULL || named->name == NULL) {
		fprintf(stderr, "FAIL: named vhost not found after parse\n");
		exit(1);
	}

	check_inherited(named);

	/* Named vhost must have its own network, not the default's */
	if (named->config->network->ipv4 == NULL ||
	    strcmp(named->config->network->ipv4, "192.168.101.0") != 0) {
		fprintf(stderr,
			"FAIL: named vhost ipv4 not overridden: got %s\n",
			named->config->network->ipv4 ?
				named->config->network->ipv4 :
				"(null)");
		exit(1);
	}

	clear_old_configs(&vconfig);

	/* ----------------------------------------------------------------
	 * Phase 2: override — named vhost explicitly sets keepalive.
	 * ---------------------------------------------------------------- */
	write_config(tmpfile, srcdir, 1);

	list_head_init(&vconfig);
	if (vhost_add(pool, &vconfig, NULL, 0) == NULL) {
		fprintf(stderr, "vhost_add failed\n");
		exit(1);
	}
	parse_cfg_file(pool, tmpfile, &vconfig, 0);

	named = find_vhost(&vconfig, "named");
	if (named == NULL || named->name == NULL) {
		fprintf(stderr,
			"FAIL: named vhost not found after override parse\n");
		exit(1);
	}

	/* keepalive must be overridden */
	CHECK_EQ_U("keepalive-override", named->config->keepalive, 55555);

	/* All other fields must still be inherited */
	CHECK_EQ_U("dpd-after-override", named->config->dpd, 2222);
	CHECK_EQ_U("idle_timeout-after-override", named->config->idle_timeout,
		   3333);
	CHECK_STR("banner-after-override", named->config->banner,
		  "test-inherit-banner");
	CHECK_STR("default_domain-after-override",
		  named->config->default_domain, "inherit.example.com");

	clear_old_configs(&vconfig);

	/* ----------------------------------------------------------------
	 * Phase 3: reload — verify inheritance survives a SIGHUP-style reload.
	 * ---------------------------------------------------------------- */
	write_config(tmpfile, srcdir, 0);

	list_head_init(&vconfig);
	if (vhost_add(pool, &vconfig, NULL, 0) == NULL) {
		fprintf(stderr, "vhost_add failed\n");
		exit(1);
	}
	parse_cfg_file(pool, tmpfile, &vconfig, 0);

	reload_cfg_file(pool, &vconfig, 0);

	named = find_vhost(&vconfig, "named");
	if (named == NULL || named->name == NULL) {
		fprintf(stderr, "FAIL: named vhost not found after reload\n");
		exit(1);
	}

	check_inherited(named);

	clear_old_configs(&vconfig);

	/* ----------------------------------------------------------------
	 * Phase 4: static_cfg_st inheritance — named vhost omits auth,
	 * cert, and key entirely; they must be inherited from the default.
	 * ---------------------------------------------------------------- */
	write_config(tmpfile, srcdir, 2);

	list_head_init(&vconfig);
	if (vhost_add(pool, &vconfig, NULL, 0) == NULL) {
		fprintf(stderr, "vhost_add failed\n");
		exit(1);
	}
	parse_cfg_file(pool, tmpfile, &vconfig, 0);

	named = find_vhost(&vconfig, "named");
	if (named == NULL || named->name == NULL) {
		fprintf(stderr,
			"FAIL: named vhost not found in static-inherit phase\n");
		exit(1);
	}

	/* cert and key must have been inherited from the default vhost */
	if (named->static_config.cert_size == 0 ||
	    named->static_config.cert == NULL ||
	    named->static_config.cert[0] == NULL) {
		fprintf(stderr,
			"FAIL static-inherit: cert not inherited (cert_size=%zu)\n",
			named->static_config.cert_size);
		exit(1);
	}
	if (named->static_config.key_size == 0 ||
	    named->static_config.key == NULL ||
	    named->static_config.key[0] == NULL) {
		fprintf(stderr,
			"FAIL static-inherit: key not inherited (key_size=%zu)\n",
			named->static_config.key_size);
		exit(1);
	}

	/* auth must have been inherited */
	if (named->static_config.auth_methods == 0 ||
	    named->static_config.auth[0].enabled == 0) {
		fprintf(stderr,
			"FAIL static-inherit: auth not inherited (auth_methods=%u)\n",
			named->static_config.auth_methods);
		exit(1);
	}

	/* reloadable fields must still be inherited normally */
	check_inherited(named);

	clear_old_configs(&vconfig);

	/* ----------------------------------------------------------------
	 * Phase 5: multi-line options are inherited when the named vhost
	 * does not set them, and replaced as a whole when it does.
	 * ---------------------------------------------------------------- */
	check_options(pool, tmpfile, srcdir, DEFAULT_LISTS, "",
		      check_inherited_lists);

	check_options(pool, tmpfile, srcdir, DEFAULT_LISTS,
		      "dns = 192.0.2.2\n"
		      "nbns = 192.0.2.4\n"
		      "route = 198.51.100.2/32\n"
		      "no-route = 198.51.100.4/32\n"
		      "split-dns = b.example.com\n"
		      "custom-header = X-B: 2\n"
		      "included-http-headers = X-D: 4\n",
		      check_replaced_lists);

	check_options(pool, tmpfile, srcdir, DEFAULT_LISTS,
		      "ipv6-dns = 2001:db8::1\n"
		      "ipv4-nbns = 192.0.2.4\n",
		      check_dns_spellings);

	check_options(pool, tmpfile, srcdir,
		      many_options(pool, "custom-header", "X-H", 0),
		      many_options(pool, "custom-header", "X-H", MANY_VALUES),
		      check_many_values);

	/* ----------------------------------------------------------------
	 * Phase 6: select-group is inherited with its labels, unless the
	 * named vhost sets its own, which replaces the inherited list.
	 * ---------------------------------------------------------------- */
	check_options(pool, tmpfile, srcdir,
		      "select-group = group1[Label One]\n"
		      "select-group = group2\n",
		      "", check_groups_inherited);

	check_options(pool, tmpfile, srcdir,
		      "select-group = group1[Label One]\n"
		      "select-group = group2\n",
		      "select-group = group3[Label Three]\n"
		      "select-group = group4\n",
		      check_groups_replaced);

	check_options(pool, tmpfile, srcdir,
		      "select-group = group1[]\n"
		      "select-group = group2[Label Two]\n",
		      "", check_groups_empty_label);

	check_options(pool, tmpfile, srcdir,
		      many_options(pool, "select-group", "g", 0),
		      many_options(pool, "select-group", "g", MANY_VALUES),
		      check_many_groups);

	/* auto-select-group discovers the groups, and labels of a previous
	 * select-group list do not apply to them. */
	plain_auth_group_list = auto_groups;
	plain_auth_group_list_size = 2;
	check_options(pool, tmpfile, srcdir,
		      "select-group = group1[Label One]\n"
		      "auto-select-group = true\n",
		      talloc_asprintf(
			      pool, "auth = \"plain[%s/data/test1.passwd]\"\n",
			      srcdir),
		      check_groups_auto_selected);

	/* ----------------------------------------------------------------
	 * Phase 7: the same rule for restrict-user-to-ports and for the
	 * non-reloadable options that may be given multiple times.
	 * ---------------------------------------------------------------- */
	check_options(pool, tmpfile, srcdir,
		      "restrict-user-to-ports = \"tcp(443)\"\n", "",
		      check_ports_inherited);
	check_options(pool, tmpfile, srcdir,
		      "restrict-user-to-ports = \"tcp(443)\"\n",
		      "restrict-user-to-ports = \"udp(53)\"\n",
		      check_ports_replaced);

	check_options(
		pool, tmpfile, srcdir, "",
		talloc_asprintf(
			pool,
			"server-cert = %s/certs/server-cert-secp521r1.pem\n"
			"server-key = %s/certs/server-key-secp521r1.pem\n",
			srcdir, srcdir),
		check_certs_replaced);

	check_options(
		pool, tmpfile, srcdir, "",
		talloc_asprintf(pool,
				"auth = \"plain[%s/data/test-group.passwd]\"\n",
				srcdir),
		check_auth_replaced);

	check_auth_group(pool, tmpfile, srcdir);
	check_kkdcp_inheritance(pool, tmpfile, srcdir);

	unlink(tmpfile);
	talloc_free(pool);

	fprintf(stderr, "config-inherit: all checks passed\n");
	return 0;
}
