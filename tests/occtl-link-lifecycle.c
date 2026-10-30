/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include "occtl/occtl.h"

static unsigned int acquired, released;

int __wrap_rtnl_link_get_kernel(struct nl_sock *sock, int index,
				const char *name, struct rtnl_link **result)
{
	if (strcmp(name, "missing") == 0)
		return -NLE_OBJ_NOTFOUND;
	*result = rtnl_link_alloc();
	if (*result == NULL) {
		fputs("FAIL: native link allocation failed\n", stderr);
		exit(1);
	}
	acquired++;
	return 0;
}

void __real_rtnl_link_put(struct rtnl_link *link);

void __wrap_rtnl_link_put(struct rtnl_link *link)
{
	if (link == NULL || released >= acquired) {
		fputs("FAIL: released an unacquired link\n", stderr);
		exit(1);
	}
	released++;
	__real_rtnl_link_put(link);
}

void bytes2human(unsigned long bytes, char *output, unsigned int size,
		 const char *suffix)
{
	if (size)
		output[0] = 0;
}

int main(void)
{
	cmd_params_st params = { 0 };
	FILE *out = tmpfile();

	if (out == NULL) {
		perror("FAIL: statistics output");
		return 1;
	}
	print_iface_stats(NULL, time(NULL), out, &params, 0);
	print_iface_stats("", time(NULL), out, &params, 0);
	print_iface_stats("missing", time(NULL), out, &params, 0);
	if (acquired || released) {
		fputs("FAIL: empty/failed lookup acquired a link\n", stderr);
		return 1;
	}
	for (params.json = 0; params.json <= 1; params.json++) {
		print_iface_stats("owned", time(NULL), out, &params, 0);
		if (acquired != params.json + 1 || released != acquired) {
			fprintf(stderr,
				"FAIL: format %u acquired %u, released %u\n",
				params.json, acquired, released);
			return 1;
		}
	}
	fclose(out);
	puts("PASS: successful text/JSON statistics release native link references; rejected lookups release none");
	return 0;
}
