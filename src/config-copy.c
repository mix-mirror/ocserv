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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <talloc.h>

#include "config-copy.h"

/* Two-phase talloc allocator for protobuf-c unpack: every block is allocated
 * under the first one, the message itself, so that a single talloc_free() of
 * the copy releases all of it. PROTOBUF_ALLOCATOR() in common.h allocates
 * each block under its pool instead, which does not allow that. */
struct cfg_alloc_ctx {
	TALLOC_CTX *pool;
	void *top; /* NULL until first alloc */
};

static void *cfg_talloc_alloc(void *data, size_t size)
{
	struct cfg_alloc_ctx *ctx = data;

	if (ctx->top == NULL) {
		ctx->top = talloc_size(ctx->pool, size);
		return ctx->top;
	}
	return talloc_size(ctx->top, size);
}

static void cfg_talloc_free(void *data, void *ptr)
{
	(void)data;
	talloc_free(ptr);
}

/* A deep copy of @src under @pool, via protobuf pack+unpack */
static ReloadableConfig *cfg_copy(const ReloadableConfig *src, void *pool)
{
	struct cfg_alloc_ctx ctx = { .pool = pool, .top = NULL };
	ProtobufCAllocator alloc = {
		.alloc = cfg_talloc_alloc,
		.free = cfg_talloc_free,
		.allocator_data = &ctx,
	};
	size_t len;
	uint8_t *buf;
	ReloadableConfig *copy;

	/* rejects a list left with a count but no array by set_lists() */
	if (!protobuf_c_message_check(&src->base))
		return NULL;

	len = reloadable_config__get_packed_size(src);
	buf = talloc_size(pool, len);
	if (buf == NULL)
		return NULL;
	reloadable_config__pack(src, buf);
	copy = (ReloadableConfig *)protobuf_c_message_unpack(
		&reloadable_config__descriptor, &alloc, len, buf);
	talloc_free(buf);
	return copy;
}

/* The repeated fields of a ReloadableConfig hold the options that may be given
 * several times. A named vhost inherits such an option only if its section
 * does not set it (REQ-CONFIG-CFG-010), so its lists are left out when it is
 * populated from the default vhost, and the ones still empty after parsing are
 * taken from the default vhost. The repeated fields are found from the
 * protobuf descriptor, so that a list added to cfg.proto needs no code here. */

/* The member of @msg that holds @f: the array of a repeated field, or the
 * pointer of a sub-message. No other member may be read as a pointer. */
static void **field_ptr(const ProtobufCMessage *msg,
			const ProtobufCFieldDescriptor *f)
{
	assert(f->label == PROTOBUF_C_LABEL_REPEATED ||
	       f->type == PROTOBUF_C_TYPE_MESSAGE);
	return (void **)((char *)msg + f->offset);
}

/* The element count of the repeated field @f of @msg */
static size_t *field_count(const ProtobufCMessage *msg,
			   const ProtobufCFieldDescriptor *f)
{
	assert(f->label == PROTOBUF_C_LABEL_REPEATED);
	return (size_t *)((char *)msg + f->quantifier_offset);
}

/* Sets the lists of @msg, at any depth, to those of @from: all of them when
 * @from is NULL, which leaves them empty, else only the ones @msg left empty.
 * The arrays are shared with @from, so @msg must be deep-copied before @from
 * is freed. */
static void set_lists(ProtobufCMessage *msg, const ProtobufCMessage *from)
{
	const ProtobufCMessageDescriptor *desc = msg->descriptor;
	const ProtobufCFieldDescriptor *f;
	ProtobufCMessage *sub;
	const ProtobufCMessage *from_sub;
	unsigned int i;

	assert(desc->magic == PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC);
	assert(from == NULL || from->descriptor == desc);

	for (i = 0; i < desc->n_fields; i++) {
		f = &desc->fields[i];

		/* oneof members share storage, which this would mishandle */
		assert(!(f->flags & PROTOBUF_C_FIELD_FLAG_ONEOF));
		if (f->label == PROTOBUF_C_LABEL_REPEATED) {
			if (from == NULL) {
				*field_count(msg, f) = 0;
				*field_ptr(msg, f) = NULL;
			} else if (*field_count(msg, f) == 0) {
				*field_count(msg, f) = *field_count(from, f);
				*field_ptr(msg, f) = *field_ptr(from, f);
			}
		} else if (f->type == PROTOBUF_C_TYPE_MESSAGE) {
			sub = *field_ptr(msg, f);
			from_sub = from ? *field_ptr(from, f) : NULL;
			if (sub != NULL && (from == NULL || from_sub != NULL))
				set_lists(sub, from_sub);
		}
	}
}

ReloadableConfig *cfg_copy_without_lists(const ReloadableConfig *def,
					 void *pool)
{
	ReloadableConfig *tmp, *copy;

	tmp = cfg_copy(def, pool);
	if (tmp == NULL)
		return NULL;

	set_lists(&tmp->base, NULL);
	/* a second copy, so that the lists of @def are not kept under it */
	copy = cfg_copy(tmp, pool);
	talloc_free(tmp);
	return copy;
}

ReloadableConfig *cfg_inherit_lists(ReloadableConfig *cfg,
				    const ReloadableConfig *def, void *pool)
{
	ReloadableConfig *copy;

	set_lists(&cfg->base, &def->base);
	copy = cfg_copy(cfg, pool);
	if (copy != NULL)
		talloc_free(cfg);
	return copy;
}
