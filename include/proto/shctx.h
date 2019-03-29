/*
 * shctx.h - shared context management functions for SSL
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

#ifndef SHCTX_H
#define SHCTX_H

#include <common/mini-clist.h>
#include <types/shctx.h>

#include <inttypes.h>

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

int shctx_init(struct shared_context **orig_shctx,
               int maxblocks, int blocksize, unsigned int maxobjsz,
               int extra, int shared);
struct shared_block *shctx_row_reserve_hot(struct shared_context *shctx,
                                           struct shared_block *last, int data_len);
void shctx_row_inc_hot(struct shared_context *shctx, struct shared_block *first);
void shctx_row_dec_hot(struct shared_context *shctx, struct shared_block *first);
int shctx_row_data_append(struct shared_context *shctx,
                          struct shared_block *first, struct shared_block *from,
                          unsigned char *data, int len);
int shctx_row_data_get(struct shared_context *shctx, struct shared_block *first,
                       unsigned char *dst, int offset, int len);


/* Lock functions */

#if defined (USE_PRIVATE_CACHE)

#define shctx_lock(shctx)
#define shctx_unlock(shctx)

#elif defined (USE_PTHREAD_PSHARED)
extern int use_shared_mem;

#define shctx_lock(shctx)   if (use_shared_mem) pthread_mutex_lock(&shctx->mutex)
#define shctx_unlock(shctx) if (use_shared_mem) pthread_mutex_unlock(&shctx->mutex)

#else
extern int use_shared_mem;

#ifdef USE_SYSCALL_FUTEX
static inline void _shctx_wait4lock(unsigned int *count, unsigned int *uaddr, int value)
{
	syscall(SYS_futex, uaddr, FUTEX_WAIT, value, NULL, 0, 0);
}

static inline void _shctx_awakelocker(unsigned int *uaddr)
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

static inline void _shctx_wait4lock(unsigned int *count, unsigned int *uaddr, int value)
{
        int i;

        for (i = 0; i < *count; i++) {
                relax();
                relax();
        }
        *count = *count << 1;
}

#define _shctx_awakelocker(a)

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

static inline void _shctx_lock(struct shared_context *shctx)
{
	unsigned int x;
	unsigned int count = 4;

	x = cmpxchg(&shctx->waiters, 0, 1);
	if (x) {
		if (x != 2)
			x = xchg(&shctx->waiters, 2);

		while (x) {
			_shctx_wait4lock(&count, &shctx->waiters, 2);
			x = xchg(&shctx->waiters, 2);
		}
	}
}

static inline void _shctx_unlock(struct shared_context *shctx)
{
	if (atomic_dec(&shctx->waiters)) {
		shctx->waiters = 0;
		_shctx_awakelocker(&shctx->waiters);
	}
}

#define shctx_lock(shctx)   if (use_shared_mem) _shctx_lock(shctx)

#define shctx_unlock(shctx) if (use_shared_mem) _shctx_unlock(shctx)

#endif

/* List Macros */

/*
 * Insert <s> block after <head> which is not necessarily the head of a list,
 * so between <head> and the next element after <head>.
 */
static inline void shctx_block_append_hot(struct shared_context *shctx,
                                          struct list *head,
                                          struct shared_block *s)
{
	shctx->nbav--;
	LIST_DEL(&s->list);
	LIST_ADD(head, &s->list);
}

static inline void shctx_block_set_hot(struct shared_context *shctx,
				    struct shared_block *s)
{
	shctx->nbav--;
	LIST_DEL(&s->list);
	LIST_ADDQ(&shctx->hot, &s->list);
}

static inline void shctx_block_set_avail(struct shared_context *shctx,
				      struct shared_block *s)
{
	shctx->nbav++;
	LIST_DEL(&s->list);
	LIST_ADDQ(&shctx->avail, &s->list);
}

#endif /* SHCTX_H */

