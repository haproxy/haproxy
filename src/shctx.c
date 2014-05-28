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
#ifndef USE_PRIVATE_CACHE
#ifdef USE_PTHREAD_PSHARED
#include <pthread.h>
#else
#ifdef USE_SYSCALL_FUTEX
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#endif
#endif
#endif
#include <arpa/inet.h>
#include <ebmbtree.h>
#include <types/global.h>
#include "proto/shctx.h"

struct shsess_packet_hdr {
	unsigned int eol;
	unsigned char final:1;
	unsigned char seq:7;
	unsigned char id[SSL_MAX_SSL_SESSION_ID_LENGTH];
};

struct shsess_packet {
	unsigned char version;
	unsigned char sig[SHA_DIGEST_LENGTH];
	struct shsess_packet_hdr hdr;
	unsigned char data[0];
};

struct shared_session {
	struct ebmb_node key;
	unsigned char key_data[SSL_MAX_SSL_SESSION_ID_LENGTH];
	unsigned char data[SHSESS_BLOCK_MIN_SIZE];
};

struct shared_block {
	union {
		struct shared_session session;
		unsigned char data[sizeof(struct shared_session)];
	} data;
	short int data_len;
	struct shared_block *p;
	struct shared_block *n;
};

struct shared_context {
#ifndef USE_PRIVATE_CACHE
#ifdef USE_PTHREAD_PSHARED
	pthread_mutex_t mutex;
#else
	unsigned int waiters;
#endif
#endif
	struct shsess_packet_hdr upd;
	unsigned char data[SHSESS_MAX_DATA_LEN];
	short int data_len;
	struct shared_block active;
	struct shared_block free;
};

/* Static shared context */
static struct shared_context *shctx = NULL;

/* Lock functions */

#if defined (USE_PRIVATE_CACHE)

#define shared_context_lock()
#define shared_context_unlock()

#elif defined (USE_PTHREAD_PSHARED)
static int use_shared_mem = 0;

#define shared_context_lock()   if (use_shared_mem) pthread_mutex_lock(&shctx->mutex)
#define shared_context_unlock() if (use_shared_mem) pthread_mutex_unlock(&shctx->mutex)

#else
static int use_shared_mem = 0;

#ifdef USE_SYSCALL_FUTEX
static inline void _shared_context_wait4lock(unsigned int *count, unsigned int *uaddr, int value)
{
	syscall(SYS_futex, uaddr, FUTEX_WAIT, value, NULL, 0, 0);
}

static inline void _shared_context_awakelocker(unsigned int *uaddr)
{
	syscall(SYS_futex, uaddr, FUTEX_WAKE, 1, NULL, 0, 0);
}

#else /* internal spin lock */

#if defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)
static inline void relax()
{
	__asm volatile("rep;nop\n" ::: "memory");
}
#else /* if no x86_64 or i586 arch: use less optimized but generic asm */
static inline void relax()
{
	__asm volatile("" ::: "memory");
}
#endif

static inline void _shared_context_wait4lock(unsigned int *count, unsigned int *uaddr, int value)
{
        int i;

        for (i = 0; i < *count; i++) {
                relax();
                relax();
        }
        *count = *count << 1;
}

#define _shared_context_awakelocker(a)

#endif

#if defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)
static inline unsigned int xchg(unsigned int *ptr, unsigned int x)
{
	__asm volatile("lock xchgl %0,%1"
		     : "=r" (x), "+m" (*ptr)
		     : "0" (x)
		     : "memory");
	return x;
}

static inline unsigned int cmpxchg(unsigned int *ptr, unsigned int old, unsigned int new)
{
	unsigned int ret;

	__asm volatile("lock cmpxchgl %2,%1"
		     : "=a" (ret), "+m" (*ptr)
		     : "r" (new), "0" (old)
		     : "memory");
	return ret;
}

static inline unsigned char atomic_dec(unsigned int *ptr)
{
	unsigned char ret;
	__asm volatile("lock decl %0\n"
		     "setne %1\n"
		     : "+m" (*ptr), "=qm" (ret)
		     :
		     : "memory");
	return ret;
}

#else /* if no x86_64 or i586 arch: use less optimized gcc >= 4.1 built-ins */
static inline unsigned int xchg(unsigned int *ptr, unsigned int x)
{
	return __sync_lock_test_and_set(ptr, x);
}

static inline unsigned int cmpxchg(unsigned int *ptr, unsigned int old, unsigned int new)
{
	return __sync_val_compare_and_swap(ptr, old, new);
}

static inline unsigned char atomic_dec(unsigned int *ptr)
{
	return __sync_sub_and_fetch(ptr, 1) ? 1 : 0;
}

#endif

static inline void _shared_context_lock(void)
{
	unsigned int x;
	unsigned int count = 4;

	x = cmpxchg(&shctx->waiters, 0, 1);
	if (x) {
		if (x != 2)
			x = xchg(&shctx->waiters, 2);

		while (x) {
			_shared_context_wait4lock(&count, &shctx->waiters, 2);
			x = xchg(&shctx->waiters, 2);
		}
	}
}

static inline void _shared_context_unlock(void)
{
	if (atomic_dec(&shctx->waiters)) {
		shctx->waiters = 0;
		_shared_context_awakelocker(&shctx->waiters);
	}
}

#define shared_context_lock()   if (use_shared_mem) _shared_context_lock()

#define shared_context_unlock() if (use_shared_mem) _shared_context_unlock()

#endif

/* List Macros */

#define shblock_unset(s)	(s)->n->p = (s)->p; \
				(s)->p->n = (s)->n;

#define shblock_set_free(s)	shblock_unset(s) \
				(s)->n = &shctx->free; \
				(s)->p = shctx->free.p; \
				shctx->free.p->n = s; \
				shctx->free.p = s;


#define shblock_set_active(s)	shblock_unset(s) \
				(s)->n = &shctx->active; \
				(s)->p = shctx->active.p; \
				shctx->active.p->n = s; \
				shctx->active.p = s;


/* Tree Macros */

#define shsess_tree_delete(s)	ebmb_delete(&(s)->key);

#define shsess_tree_insert(s)	(struct shared_session *)ebmb_insert(&shctx->active.data.session.key.node.branches, \
								     &(s)->key, SSL_MAX_SSL_SESSION_ID_LENGTH);

#define shsess_tree_lookup(k)	(struct shared_session *)ebmb_lookup(&shctx->active.data.session.key.node.branches, \
								     (k), SSL_MAX_SSL_SESSION_ID_LENGTH);

/* shared session functions */

/* Free session blocks, returns number of freed blocks */
static int shsess_free(struct shared_session *shsess)
{
	struct shared_block *block;
	int ret = 1;

	if (((struct shared_block *)shsess)->data_len <= sizeof(shsess->data)) {
		shblock_set_free((struct shared_block *)shsess);
		return ret;
	}
	block = ((struct shared_block *)shsess)->n;
	shblock_set_free((struct shared_block *)shsess);
	while (1) {
		struct shared_block *next;

		if (block->data_len <= sizeof(block->data)) {
			/* last block */
			shblock_set_free(block);
			ret++;
			break;
		}
		next = block->n;
		shblock_set_free(block);
		ret++;
		block = next;
	}
	return ret;
}

/* This function frees enough blocks to store a new session of data_len.
 * Returns a ptr on a free block if it succeeds, or NULL if there are not
 * enough blocks to store that session.
 */
static struct shared_session *shsess_get_next(int data_len)
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
		freed = shsess_free(&b->data.session);
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
static int shsess_store(unsigned char *s_id, unsigned char *data, int data_len)
{
	struct shared_session *shsess, *oldshsess;

	shsess = shsess_get_next(data_len);
	if (!shsess) {
		/* Could not retrieve enough free blocks to store that session */
		return 0;
	}

	/* prepare key */
	memcpy(shsess->key_data, s_id, SSL_MAX_SSL_SESSION_ID_LENGTH);

	/* it returns the already existing node
           or current node if none, never returns null */
	oldshsess = shsess_tree_insert(shsess);
	if (oldshsess != shsess) {
		/* free all blocks used by old node */
		shsess_free(oldshsess);
		shsess = oldshsess;
	}

	((struct shared_block *)shsess)->data_len = data_len;
	if (data_len <= sizeof(shsess->data)) {
		/* Store on a single block */
		memcpy(shsess->data, data, data_len);
		shblock_set_active((struct shared_block *)shsess);
	}
	else {
		unsigned char *p;
		/* Store on multiple blocks */
		int cur_len;

		memcpy(shsess->data, data, sizeof(shsess->data));
		p = data + sizeof(shsess->data);
		cur_len = data_len - sizeof(shsess->data);
		shblock_set_active((struct shared_block *)shsess);
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
				shblock_set_active(block);
				break;
			}
			/* Intermediate block */
			block->data_len = cur_len;
			memcpy(block->data.data, p, sizeof(block->data));
			p += sizeof(block->data.data);
			cur_len -= sizeof(block->data.data);
			shblock_set_active(block);
		}
	}

	return 1;
}


/* SSL context callbacks */

/* SSL callback used on new session creation */
int shctx_new_cb(SSL *ssl, SSL_SESSION *sess)
{
	unsigned char encsess[sizeof(struct shsess_packet)+SHSESS_MAX_DATA_LEN];
	struct shsess_packet *packet = (struct shsess_packet *)encsess;
	unsigned char *p;
	int data_len, sid_length, sid_ctx_length;


	/* Session id is already stored in to key and session id is known
	 * so we dont store it to keep size.
	 */
	sid_length = sess->session_id_length;
	sess->session_id_length = 0;
	sid_ctx_length = sess->sid_ctx_length;
	sess->sid_ctx_length = 0;

	/* check if buffer is large enough for the ASN1 encoded session */
	data_len = i2d_SSL_SESSION(sess, NULL);
	if (data_len > SHSESS_MAX_DATA_LEN)
		goto err;

	/* process ASN1 session encoding before the lock */
	p = packet->data;
	i2d_SSL_SESSION(sess, &p);

	memcpy(packet->hdr.id, sess->session_id, sid_length);
	if (sid_length < SSL_MAX_SSL_SESSION_ID_LENGTH)
		memset(&packet->hdr.id[sid_length], 0, SSL_MAX_SSL_SESSION_ID_LENGTH-sid_length);

	shared_context_lock();

	/* store to cache */
	shsess_store(packet->hdr.id, packet->data, data_len);

	shared_context_unlock();

err:
	/* reset original length values */
	sess->session_id_length = sid_length;
	sess->sid_ctx_length = sid_ctx_length;

	return 0; /* do not increment session reference count */
}

/* SSL callback used on lookup an existing session cause none found in internal cache */
SSL_SESSION *shctx_get_cb(SSL *ssl, unsigned char *key, int key_len, int *do_copy)
{
	struct shared_session *shsess;
	unsigned char data[SHSESS_MAX_DATA_LEN], *p;
	unsigned char tmpkey[SSL_MAX_SSL_SESSION_ID_LENGTH];
	int data_len;
	SSL_SESSION *sess;

	global.shctx_lookups++;

	/* allow the session to be freed automatically by openssl */
	*do_copy = 0;

	/* tree key is zeros padded sessionid */
	if (key_len < SSL_MAX_SSL_SESSION_ID_LENGTH) {
		memcpy(tmpkey, key, key_len);
		memset(tmpkey + key_len, 0, SSL_MAX_SSL_SESSION_ID_LENGTH - key_len);
		key = tmpkey;
	}

	/* lock cache */
	shared_context_lock();

	/* lookup for session */
	shsess = shsess_tree_lookup(key);
	if (!shsess) {
		/* no session found: unlock cache and exit */
		shared_context_unlock();
		global.shctx_misses++;
		return NULL;
	}

	data_len = ((struct shared_block *)shsess)->data_len;
	if (data_len <= sizeof(shsess->data)) {
		/* Session stored on single block */
		memcpy(data, shsess->data, data_len);
		shblock_set_active((struct shared_block *)shsess);
	}
	else {
		/* Session stored on multiple blocks */
		struct shared_block *block;

		memcpy(data, shsess->data, sizeof(shsess->data));
		p = data + sizeof(shsess->data);
		block = ((struct shared_block *)shsess)->n;
		shblock_set_active((struct shared_block *)shsess);
		while (1) {
			/* Retrieve data from next block */
			struct shared_block *next;

			if (block->data_len <= sizeof(block->data.data)) {
				/* This is the last block */
				memcpy(p, block->data.data, block->data_len);
				p += block->data_len;
				shblock_set_active(block);
				break;
			}
			/* Intermediate block */
			memcpy(p, block->data.data, sizeof(block->data.data));
			p += sizeof(block->data.data);
			next = block->n;
			shblock_set_active(block);
			block = next;
		}
	}

	shared_context_unlock();

	/* decode ASN1 session */
	p = data;
	sess = d2i_SSL_SESSION(NULL, (const unsigned char **)&p, data_len);
	/* Reset session id and session id contenxt */
	if (sess) {
		memcpy(sess->session_id, key, key_len);
		sess->session_id_length = key_len;
		memcpy(sess->sid_ctx, (const unsigned char *)SHCTX_APPNAME, strlen(SHCTX_APPNAME));
		sess->sid_ctx_length = ssl->sid_ctx_length;
	}

	return sess;
}

/* SSL callback used to signal session is no more used in internal cache */
void shctx_remove_cb(SSL_CTX *ctx, SSL_SESSION *sess)
{
	struct shared_session *shsess;
	unsigned char tmpkey[SSL_MAX_SSL_SESSION_ID_LENGTH];
	unsigned char *key = sess->session_id;
	(void)ctx;

	/* tree key is zeros padded sessionid */
	if (sess->session_id_length < SSL_MAX_SSL_SESSION_ID_LENGTH) {
		memcpy(tmpkey, sess->session_id, sess->session_id_length);
		memset(tmpkey+sess->session_id_length, 0, SSL_MAX_SSL_SESSION_ID_LENGTH - sess->session_id_length);
		key = tmpkey;
	}

	shared_context_lock();

	/* lookup for session */
	shsess = shsess_tree_lookup(key);
	if (shsess) {
		/* free session */
		shsess_tree_delete(shsess);
		shsess_free(shsess);
	}

	/* unlock cache */
	shared_context_unlock();
}

/* Allocate shared memory context.
 * <size> is maximum cached sessions.
 * If <size> is set to less or equal to 0, ssl cache is disabled.
 * Returns: -1 on alloc failure, <size> if it performs context alloc,
 * and 0 if cache is already allocated.
 */
int shared_context_init(int size, int shared)
{
	int i;
#ifndef USE_PRIVATE_CACHE
#ifdef USE_PTHREAD_PSHARED
	pthread_mutexattr_t attr;
#endif
#endif
	struct shared_block *prev,*cur;
	int maptype = MAP_PRIVATE;

	if (shctx)
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
		return SHCTX_E_ALLOC_CACHE;
	}

#ifndef USE_PRIVATE_CACHE
	if (maptype == MAP_SHARED) {
#ifdef USE_PTHREAD_PSHARED
		if (pthread_mutexattr_init(&attr)) {
			munmap(shctx, sizeof(struct shared_context)+(size*sizeof(struct shared_block)));
			shctx = NULL;
			return SHCTX_E_INIT_LOCK;
		}

		if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
			pthread_mutexattr_destroy(&attr);
			munmap(shctx, sizeof(struct shared_context)+(size*sizeof(struct shared_block)));
			shctx = NULL;
			return SHCTX_E_INIT_LOCK;
		}

		if (pthread_mutex_init(&shctx->mutex, &attr)) {
			pthread_mutexattr_destroy(&attr);
			munmap(shctx, sizeof(struct shared_context)+(size*sizeof(struct shared_block)));
			shctx = NULL;
			return SHCTX_E_INIT_LOCK;
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

	/* Init remote update cache */
	shctx->upd.eol = 0;
	shctx->upd.seq = 0;
	shctx->data_len = 0;

	cur = &shctx->active;
	cur->n = cur->p = cur;

	cur = &shctx->free;
	for (i = 0 ; i < size ; i++) {
		prev = cur;
		cur = (struct shared_block *)((char *)prev + sizeof(struct shared_block));
		prev->n = cur;
		cur->p = prev;
	}
	cur->n = &shctx->free;
	shctx->free.p = cur;

	return size;
}


/* Set session cache mode to server and disable openssl internal cache.
 * Set shared cache callbacks on an ssl context.
 * Shared context MUST be firstly initialized */
void shared_context_set_cache(SSL_CTX *ctx)
{
	SSL_CTX_set_session_id_context(ctx, (const unsigned char *)SHCTX_APPNAME, strlen(SHCTX_APPNAME));

	if (!shctx) {
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
		return;
	}

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER |
	                                    SSL_SESS_CACHE_NO_INTERNAL |
	                                    SSL_SESS_CACHE_NO_AUTO_CLEAR);

	/* Set callbacks */
	SSL_CTX_sess_set_new_cb(ctx, shctx_new_cb);
	SSL_CTX_sess_set_get_cb(ctx, shctx_get_cb);
	SSL_CTX_sess_set_remove_cb(ctx, shctx_remove_cb);
}
