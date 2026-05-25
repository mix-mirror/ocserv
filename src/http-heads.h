#ifndef OC_HTTP_HEADS_H
#define OC_HTTP_HEADS_H

#include <stddef.h>

struct http_headers_st {
	const char *name;
	unsigned id;
};

const struct http_headers_st *in_word_set(const char *str, size_t len);

#endif
