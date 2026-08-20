/*
 * include/haproxy/twork-t.h
 * Cross-thread/thread-group deferred work - type definitions
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 */

#ifndef _HAPROXY_TWORK_T_H
#define _HAPROXY_TWORK_T_H

#include <stdint.h>

#include <import/mt_list.h>

/* argument and return value of a deferred work function. Always store
 * through one of the twk_*() constructors so that the whole union is
 * initialized whatever the member used.
 */
union twork_arg {
	uint32_t  u32;
	uint64_t  u64;
	void     *ptr;
};

/* twork flags */
#define TWORK_FL_DYN    0x00000001  /* allocated from the pool, released after completion */
#define TWORK_FL_REPLY  0x00000002  /* fn() already ran, the item carries the reply to done() */
#define TWORK_FL_BUSY   0x00000004  /* a runner is currently executing one of the item's phases */

/*
 * Work to be executed from another thread, or another thread group
 */
struct twork {
	struct mt_list link;                              /* in the target (then caller) queue */
	union twork_arg (*fn)(union twork_arg arg);       /* runs on the target thread */
	union twork_arg arg;                              /* argument passed to fn() and done() */
	union twork_arg ret;                              /* fn()'s return value */
	void (*done)(union twork_arg arg, union twork_arg ret); /* optional: completion, on the calling thread */
	int caller_tid;                                   /* tid which posted the work, target of <done> */
	uint flags;                                       /* TWORK_FL_* */
};

#endif /* _HAPROXY_TWORK_T_H */
