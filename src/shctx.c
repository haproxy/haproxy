/*
 * shctx.c - shared context management functions for SSL
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

#include <sys/mman.h>
#include <arpa/inet.h>
#include <ebmbtree.h>

#include <proto/connection.h>
#include <proto/shctx.h>
#include <proto/ssl_sock.h>
#include <proto/openssl-compat.h>

#include <types/global.h>
#include <types/shctx.h>


#if !defined (USE_PRIVATE_CACHE)
int use_shared_mem = 0;
#endif

/* Tree Macros */

/* shared session functions */

/* Free session blocks, returns number of freed blocks */
int shsess_free(struct shared_context *shctx, struct shared_session *shsess)
{
	struct shared_block *block;
	int ret = 1;

	if (((struct shared_block *)shsess)->data_len <= sizeof(shsess->data)) {
		shblock_set_free(shctx, (struct shared_block *)shsess);
		return ret;
	}
	block = ((struct shared_block *)shsess)->n;
	shblock_set_free(shctx, (struct shared_block *)shsess);
	while (1) {
		struct shared_block *next;

		if (block->data_len <= sizeof(block->data)) {
			/* last block */
			shblock_set_free(shctx, block);
			ret++;
			break;
		}
		next = block->n;
		shblock_set_free(shctx, block);
		ret++;
		block = next;
	}
	return ret;
}

/* This function frees enough blocks to store a new session of data_len.
 * Returns a ptr on a free block if it succeeds, or NULL if there are not
 * enough blocks to store that session.
 */
struct shared_session *shsess_get_next(struct shared_context *shctx, int data_len)
{
	int head = 0;
	struct shared_block *b;

	b = shctx->free.n;
	while (b != &shctx->free) {
		if (!head) {
			data_len -= sizeof(b->data.session.data);
			head = 1;
		}
		else
			data_len -= sizeof(b->data.data);
		if (data_len <= 0)
			return &shctx->free.n->data.session;
		b = b->n;
	}
	b = shctx->active.n;
	while (b != &shctx->active) {
		int freed;

		shsess_tree_delete(&b->data.session);
		freed = shsess_free(shctx, &b->data.session);
		if (!head)
			data_len -= sizeof(b->data.session.data) + (freed-1)*sizeof(b->data.data);
		else
			data_len -= freed*sizeof(b->data.data);
		if (data_len <= 0)
			return &shctx->free.n->data.session;
		b = shctx->active.n;
	}
	return NULL;
}

/* store a session into the cache
 * s_id : session id padded with zero to SSL_MAX_SSL_SESSION_ID_LENGTH
 * data: asn1 encoded session
 * data_len: asn1 encoded session length
 * Returns 1 id session was stored (else 0)
 */
int shsess_store(struct shared_context *shctx, unsigned char *s_id, unsigned char *data, int data_len)
{
	struct shared_session *shsess, *oldshsess;

	shsess = shsess_get_next(shctx, data_len);
	if (!shsess) {
		/* Could not retrieve enough free blocks to store that session */
		return 0;
	}

	/* prepare key */
	memcpy(shsess->key_data, s_id, SSL_MAX_SSL_SESSION_ID_LENGTH);

	/* it returns the already existing node
           or current node if none, never returns null */
	oldshsess = shsess_tree_insert(shctx, shsess);
	if (oldshsess != shsess) {
		/* free all blocks used by old node */
		shsess_free(shctx, oldshsess);
		shsess = oldshsess;
	}

	((struct shared_block *)shsess)->data_len = data_len;
	if (data_len <= sizeof(shsess->data)) {
		/* Store on a single block */
		memcpy(shsess->data, data, data_len);
		shblock_set_active(shctx, (struct shared_block *)shsess);
	}
	else {
		unsigned char *p;
		/* Store on multiple blocks */
		int cur_len;

		memcpy(shsess->data, data, sizeof(shsess->data));
		p = data + sizeof(shsess->data);
		cur_len = data_len - sizeof(shsess->data);
		shblock_set_active(shctx, (struct shared_block *)shsess);
		while (1) {
			/* Store next data on free block.
			 * shsess_get_next guarantees that there are enough
			 * free blocks in queue.
			 */
			struct shared_block *block;

			block = shctx->free.n;
			if (cur_len <= sizeof(block->data)) {
				/* This is the last block */
				block->data_len = cur_len;
				memcpy(block->data.data, p, cur_len);
				shblock_set_active(shctx, block);
				break;
			}
			/* Intermediate block */
			block->data_len = cur_len;
			memcpy(block->data.data, p, sizeof(block->data));
			p += sizeof(block->data.data);
			cur_len -= sizeof(block->data.data);
			shblock_set_active(shctx, block);
		}
	}

	return 1;
}



/* Allocate shared memory context.
 * <size> is maximum cached sessions.
 * If <size> is set to less or equal to 0, ssl cache is disabled.
 * Returns: -1 on alloc failure, <size> if it performs context alloc,
 * and 0 if cache is already allocated.
 */
int shared_context_init(struct shared_context **orig_shctx, int size, int shared)
{
	int i;
	struct shared_context *shctx;
	int ret;
#ifndef USE_PRIVATE_CACHE
#ifdef USE_PTHREAD_PSHARED
	pthread_mutexattr_t attr;
#endif
#endif
	struct shared_block *prev,*cur;
	int maptype = MAP_PRIVATE;

	if (orig_shctx && *orig_shctx)
		return 0;

	if (size<=0)
		return 0;

	/* Increate size by one to reserve one node for lookup */
	size++;
#ifndef USE_PRIVATE_CACHE
	if (shared)
		maptype = MAP_SHARED;
#endif

	shctx = (struct shared_context *)mmap(NULL, sizeof(struct shared_context)+(size*sizeof(struct shared_block)),
	                                      PROT_READ | PROT_WRITE, maptype | MAP_ANON, -1, 0);
	if (!shctx || shctx == MAP_FAILED) {
		shctx = NULL;
		ret = SHCTX_E_ALLOC_CACHE;
		goto err;
	}

#ifndef USE_PRIVATE_CACHE
	if (maptype == MAP_SHARED) {
#ifdef USE_PTHREAD_PSHARED
		if (pthread_mutexattr_init(&attr)) {
			munmap(shctx, sizeof(struct shared_context)+(size*sizeof(struct shared_block)));
			shctx = NULL;
			ret = SHCTX_E_INIT_LOCK;
			goto err;
		}

		if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
			pthread_mutexattr_destroy(&attr);
			munmap(shctx, sizeof(struct shared_context)+(size*sizeof(struct shared_block)));
			shctx = NULL;
			ret = SHCTX_E_INIT_LOCK;
			goto err;
		}

		if (pthread_mutex_init(&shctx->mutex, &attr)) {
			pthread_mutexattr_destroy(&attr);
			munmap(shctx, sizeof(struct shared_context)+(size*sizeof(struct shared_block)));
			shctx = NULL;
			ret = SHCTX_E_INIT_LOCK;
			goto err;
		}
#else
		shctx->waiters = 0;
#endif
		use_shared_mem = 1;
	}
#endif

	memset(&shctx->active.data.session.key, 0, sizeof(struct ebmb_node));
	memset(&shctx->free.data.session.key, 0, sizeof(struct ebmb_node));

	/* No duplicate authorized in tree: */
	shctx->active.data.session.key.node.branches = EB_ROOT_UNIQUE;

	cur = &shctx->active;
	cur->n = cur->p = cur;

	cur = &shctx->free;
	for (i = 0 ; i < size ; i++) {
		prev = cur;
		cur++;
		prev->n = cur;
		cur->p = prev;
	}
	cur->n = &shctx->free;
	shctx->free.p = cur;

	ret = size;

err:
	*orig_shctx = shctx;
	return ret;
}

