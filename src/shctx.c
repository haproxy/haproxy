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
#ifdef USE_SYSCALL_FUTEX
#include <unistd.h>
#ifndef u32
#define u32 unsigned int
#endif
#include <linux/futex.h>
#include <sys/syscall.h>
#else /* USE_SYSCALL_FUTEX */
#include <pthread.h>
#endif /* USE_SYSCALL_FUTEX */
#endif

#include "ebmbtree.h"
#include "proto/shctx.h"

struct shared_session {
	struct ebmb_node key;
	unsigned char key_data[SSL_MAX_SSL_SESSION_ID_LENGTH];
	long c_date;
	int data_len;
	unsigned char data[SHSESS_MAX_DATA_LEN];
	struct shared_session *p;
	struct shared_session *n;
};


struct shared_context {
#ifndef USE_PRIVATE_CACHE
#ifdef USE_SYSCALL_FUTEX
	unsigned int waiters;
#else /* USE_SYSCALL_FUTEX */
	pthread_mutex_t mutex;
#endif
#endif
	struct shared_session active;
	struct shared_session free;
};

/* Static shared context */
static struct shared_context *shctx = NULL;
#ifndef USE_PRIVATE_CACHE
static int use_shared_mem = 0;
#endif

/* Callbacks */
static void (*shared_session_new_cbk)(unsigned char *session, unsigned int session_len, long cdate);

/* Lock functions */
#ifdef USE_PRIVATE_CACHE
#define shared_context_lock()
#define shared_context_unlock()

#else
#ifdef USE_SYSCALL_FUTEX
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

	x = cmpxchg(&shctx->waiters, 0, 1);
	if (x) {
		if (x != 2)
			x = xchg(&shctx->waiters, 2);

		while (x) {
			syscall(SYS_futex, &shctx->waiters, FUTEX_WAIT, 2, NULL, 0, 0);
			x = xchg(&shctx->waiters, 2);
		}
	}
}

static inline void _shared_context_unlock(void)
{
	if (atomic_dec(&shctx->waiters)) {
		shctx->waiters = 0;
		syscall(SYS_futex, &shctx->waiters, FUTEX_WAKE, 1, NULL, 0, 0);
	}
}

#define shared_context_lock()   if (use_shared_mem) _shared_context_lock()

#define shared_context_unlock() if (use_shared_mem) _shared_context_unlock()

#else /* USE_SYSCALL_FUTEX */

#define shared_context_lock()   if (use_shared_mem) pthread_mutex_lock(&shctx->mutex)

#define shared_context_unlock() if (use_shared_mem) pthread_mutex_unlock(&shctx->mutex)

#endif
#endif

/* List Macros */

#define shsess_unset(s)		(s)->n->p = (s)->p; \
				(s)->p->n = (s)->n;

#define shsess_set_free(s)	shsess_unset(s) \
				(s)->p = &shctx->free; \
				(s)->n = shctx->free.n; \
				shctx->free.n->p = s; \
				shctx->free.n = s;


#define shsess_set_active(s)	shsess_unset(s) \
				(s)->p = &shctx->active; \
				(s)->n = shctx->active.n; \
				shctx->active.n->p = s; \
				shctx->active.n = s;


#define shsess_get_next()	(shctx->free.p == shctx->free.n) ? \
				     shctx->active.p : shctx->free.p;

/* Tree Macros */

#define shsess_tree_delete(s)	ebmb_delete(&(s)->key);

#define shsess_tree_insert(s)	(struct shared_session *)ebmb_insert(&shctx->active.key.node.branches, \
								     &(s)->key, SSL_MAX_SSL_SESSION_ID_LENGTH);

#define shsess_tree_lookup(k)	(struct shared_session *)ebmb_lookup(&shctx->active.key.node.branches, \
								     (k), SSL_MAX_SSL_SESSION_ID_LENGTH);

/* Other Macros */

#define shsess_set_key(s,k,l)	{ memcpy((s)->key_data, (k), (l)); \
				  if ((l) < SSL_MAX_SSL_SESSION_ID_LENGTH) \
					memset((s)->key_data+(l), 0, SSL_MAX_SSL_SESSION_ID_LENGTH-(l)); };


/* SSL context callbacks */

/* SSL callback used on new session creation */
int shctx_new_cb(SSL *ssl, SSL_SESSION *sess)
{
	struct shared_session *shsess;
	unsigned char *data,*p;
	unsigned int data_len;
	unsigned char encsess[SHSESS_MAX_ENCODED_LEN];
	(void)ssl;

	/* check if session reserved size in aligned buffer is large enougth for the ASN1 encode session */
	data_len=i2d_SSL_SESSION(sess, NULL);
	if(data_len > SHSESS_MAX_DATA_LEN)
		return 0;

	/* process ASN1 session encoding before the lock: lower cost */
	p = data = encsess+SSL_MAX_SSL_SESSION_ID_LENGTH;
	i2d_SSL_SESSION(sess, &p);

	shared_context_lock();

	shsess = shsess_get_next();

	shsess_tree_delete(shsess);

	shsess_set_key(shsess, sess->session_id, sess->session_id_length);

	/* it returns the already existing node or current node if none, never returns null */
	shsess = shsess_tree_insert(shsess);

	/* store ASN1 encoded session into cache */
	shsess->data_len = data_len;
	memcpy(shsess->data, data, data_len);

	/* store creation date */
	shsess->c_date = SSL_SESSION_get_time(sess);

	shsess_set_active(shsess);

	shared_context_unlock();

	if (shared_session_new_cbk) { /* if user level callback is set */
		/* copy sessionid padded with 0 into the sessionid + data aligned buffer */
		memcpy(encsess, sess->session_id, sess->session_id_length);
		if (sess->session_id_length < SSL_MAX_SSL_SESSION_ID_LENGTH)
			memset(encsess+sess->session_id_length, 0, SSL_MAX_SSL_SESSION_ID_LENGTH-sess->session_id_length);

		shared_session_new_cbk(encsess, SSL_MAX_SSL_SESSION_ID_LENGTH+data_len, SSL_SESSION_get_time(sess));
	}

	return 0; /* do not increment session reference count */
}

/* SSL callback used on lookup an existing session cause none found in internal cache */
SSL_SESSION *shctx_get_cb(SSL *ssl, unsigned char *key, int key_len, int *do_copy)
{
	struct shared_session *shsess;
	unsigned char data[SHSESS_MAX_DATA_LEN], *p;
	unsigned char tmpkey[SSL_MAX_SSL_SESSION_ID_LENGTH];
	unsigned int data_len;
	long cdate;
	SSL_SESSION *sess;
	(void)ssl;

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
		return NULL;
	}

	/* backup creation date to reset in session after ASN1 decode */
	cdate = shsess->c_date;

	/* copy ASN1 session data to decode outside the lock */
	data_len = shsess->data_len;
	memcpy(data, shsess->data, shsess->data_len);

	shsess_set_active(shsess);

	shared_context_unlock();

	/* decode ASN1 session */
	p = data;
	sess = d2i_SSL_SESSION(NULL, (const unsigned char **)&p, data_len);

	/* reset creation date */
	if (sess)
		SSL_SESSION_set_time(sess, cdate);

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
		shsess_set_free(shsess);
	}

	/* unlock cache */
	shared_context_unlock();
}

/* User level function called to add a session to the cache (remote updates) */
void shctx_sess_add(const unsigned char *encsess, unsigned int len, long cdate)
{
	struct shared_session *shsess;

	/* check buffer is at least padded key long + 1 byte
		and data_len not too long */
	if ((len <= SSL_MAX_SSL_SESSION_ID_LENGTH)
		 || (len > SHSESS_MAX_DATA_LEN+SSL_MAX_SSL_SESSION_ID_LENGTH))
		return;

	shared_context_lock();

	shsess = shsess_get_next();

	shsess_tree_delete(shsess);

	shsess_set_key(shsess, encsess, SSL_MAX_SSL_SESSION_ID_LENGTH);

	/* it returns the already existing node or current node if none, never returns null */
	shsess = shsess_tree_insert(shsess);

	/* store into cache and update earlier on session get events */
	if (cdate)
		shsess->c_date = (long)cdate;

	/* copy ASN1 session data into cache */
	shsess->data_len = len-SSL_MAX_SSL_SESSION_ID_LENGTH;
	memcpy(shsess->data, encsess+SSL_MAX_SSL_SESSION_ID_LENGTH, shsess->data_len);

	shsess_set_active(shsess);

	shared_context_unlock();
}

/* Function used to set a callback on new session creation */
void shsess_set_new_cbk(void (*func)(unsigned char *, unsigned int, long))
{
	shared_session_new_cbk = func;
}

/* Allocate shared memory context.
 * size is maximum cached sessions.
 * if set less or equal to 0, SHCTX_DEFAULT_SIZE is used.
 * Returns: -1 on alloc failure, size if it performs context alloc,
 * and 0 if cache is already allocated */
int shared_context_init(int size, int shared)
{
	int i;
#ifndef USE_PRIVATE_CACHE
#ifndef USE_SYSCALL_FUTEX
	pthread_mutexattr_t attr;
#endif /* USE_SYSCALL_FUTEX */
#endif
	struct shared_session *prev,*cur;
	int maptype = MAP_PRIVATE;

	if (shctx)
		return 0;

	if (size<=0)
		size = SHCTX_DEFAULT_SIZE;

#ifndef USE_PRIVATE_CACHE
	if (shared)
		maptype = MAP_SHARED;
#endif

	shctx = (struct shared_context *)mmap(NULL, sizeof(struct shared_context)+(size*sizeof(struct shared_session)),
	                                      PROT_READ | PROT_WRITE, maptype | MAP_ANON, -1, 0);
	if (!shctx || shctx == MAP_FAILED) {
		shctx = NULL;
		return -1;
	}

#ifndef USE_PRIVATE_CACHE
#ifdef USE_SYSCALL_FUTEX
	shctx->waiters = 0;
#else
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&shctx->mutex, &attr);
#endif
	if (maptype == MAP_SHARED)
		use_shared_mem = 1;
#endif

	memset(&shctx->active.key, 0, sizeof(struct ebmb_node));
	memset(&shctx->free.key, 0, sizeof(struct ebmb_node));

	/* No duplicate authorized in tree: */
	//shctx->active.key.node.branches.b[1] = (void *)1;
	shctx->active.key.node.branches = EB_ROOT_UNIQUE;

	cur = &shctx->active;
	cur->n = cur->p = cur;

	cur = &shctx->free;
	for (i = 0 ; i < size ; i++) {
		prev = cur;
		cur = (struct shared_session *)((char *)prev + sizeof(struct shared_session));
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
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER |
	                                    SSL_SESS_CACHE_NO_INTERNAL |
	                                    SSL_SESS_CACHE_NO_AUTO_CLEAR);
	if (!shctx)
		return;

	/* Set callbacks */
	SSL_CTX_sess_set_new_cb(ctx, shctx_new_cb);
	SSL_CTX_sess_set_get_cb(ctx, shctx_get_cb);
	SSL_CTX_sess_set_remove_cb(ctx, shctx_remove_cb);
}
