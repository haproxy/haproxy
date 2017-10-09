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

#include <types/shctx.h>

#include <openssl/ssl.h>
#include <stdint.h>

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


/* Allocate shared memory context.
 * <size> is the number of allocated blocks into cache (default 128 bytes)
 * A block is large enough to contain a classic session (without client cert)
 * If <size> is set less or equal to 0, ssl cache is disabled.
 * Set <use_shared_memory> to 1 to use a mapped shared memory instead
 * of private. (ignored if compiled with USE_PRIVATE_CACHE=1).
 * Returns: -1 on alloc failure, <size> if it performs context alloc,
 * and 0 if cache is already allocated.
 */
int shared_context_init(int size, int shared);
/* Set shared cache callbacks on an ssl context.
 * Set session cache mode to server and disable openssl internal cache.
 * Shared context MUST be firstly initialized */
void shared_context_set_cache(SSL_CTX *ctx);

/* Lock functions */

#if defined (USE_PRIVATE_CACHE)

#define shared_context_lock(shctx)
#define shared_context_unlock(shctx)

#elif defined (USE_PTHREAD_PSHARED)
extern int use_shared_mem;

#define shared_context_lock(shctx)   if (use_shared_mem) pthread_mutex_lock(&shctx->mutex)
#define shared_context_unlock(shctx) if (use_shared_mem) pthread_mutex_unlock(&shctx->mutex)

#else
extern int use_shared_mem;

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

static inline void _shared_context_lock()
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

static inline void _shared_context_unlock()
{
	if (atomic_dec(&shctx->waiters)) {
		shctx->waiters = 0;
		_shared_context_awakelocker(&shctx->waiters);
	}
}

#define shared_context_lock()   if (use_shared_mem) _shared_context_lock()

#define shared_context_unlock() if (use_shared_mem) _shared_context_unlock()

#endif


#endif /* SHCTX_H */

