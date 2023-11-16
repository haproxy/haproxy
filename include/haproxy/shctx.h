/*
 * include/haproxy/shctx.h - shared context management functions for SSL
 *
 * Copyright (C) 2011-2012 EXCELIANCE
 *
 * Author: Emeric Brun - emeric@exceliance.fr
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef __HAPROXY_SHCTX_H
#define __HAPROXY_SHCTX_H

#include <haproxy/api.h>
#include <haproxy/list.h>
#include <haproxy/shctx-t.h>
#include <haproxy/thread.h>

int shctx_init(struct shared_context **orig_shctx,
               int maxblocks, int blocksize, unsigned int maxobjsz,
               int extra, int shared);
struct shared_block *shctx_row_reserve_hot(struct shared_context *shctx,
                                           struct shared_block *last, int data_len);
void shctx_row_detach(struct shared_context *shctx, struct shared_block *first);
void shctx_row_reattach(struct shared_context *shctx, struct shared_block *first);
int shctx_row_data_append(struct shared_context *shctx,
                          struct shared_block *first,
                          unsigned char *data, int len);
int shctx_row_data_get(struct shared_context *shctx, struct shared_block *first,
                       unsigned char *dst, int offset, int len);


/* Lock functions */

extern int use_shared_mem;

#define shctx_lock(shctx)   if (use_shared_mem) HA_SPIN_LOCK(SHCTX_LOCK, &shctx->lock)
#define shctx_unlock(shctx) if (use_shared_mem) HA_SPIN_UNLOCK(SHCTX_LOCK, &shctx->lock)


/* List Macros */

/*
 * Insert <s> block after <head> which is not necessarily the head of a list,
 * so between <head> and the next element after <head>.
 */
static inline void shctx_block_append_hot(struct shared_context *shctx,
                                          struct shared_block *first,
                                          struct shared_block *s)
{
	shctx->nbav--;
	LIST_DELETE(&s->list);
	LIST_APPEND(&first->list, &s->list);
}

static inline struct shared_block *shctx_block_detach(struct shared_context *shctx,
						      struct shared_block *s)
{
	shctx->nbav--;
	LIST_DELETE(&s->list);
	LIST_INIT(&s->list);
	return s;
}

#endif /* __HAPROXY_SHCTX_H */

