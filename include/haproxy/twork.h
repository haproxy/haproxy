/*
 * include/haproxy/twork.h
 * Cross-thread/thread-group deferred work - exported functions
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 */

#ifndef _HAPROXY_TWORK_H
#define _HAPROXY_TWORK_H

#include <haproxy/twork-t.h>

/* Run function fn on another thread */
int twork_call_on(struct twork *tw, int tid,
                  union twork_arg (*fn)(union twork_arg),
                  union twork_arg arg,
                  void (*done)(union twork_arg arg, union twork_arg ret));
/* Run function fn on another thread group */
int twork_call_tgroup(struct twork *tw, uint tgid,
                      union twork_arg (*fn)(union twork_arg),
                      union twork_arg arg,
                      void (*done)(union twork_arg arg, union twork_arg ret));

/* fire-and-forget variants, the return value of fn() is discarded */
static inline int twork_post_on(struct twork *tw, int tid,
                                union twork_arg (*fn)(union twork_arg),
                                union twork_arg arg)
{
	return twork_call_on(tw, tid, fn, arg, NULL);
}

static inline int twork_post_tgroup(struct twork *tw, uint tgid,
                                    union twork_arg (*fn)(union twork_arg),
                                    union twork_arg arg)
{
	return twork_call_tgroup(tw, tgid, fn, arg, NULL);
}

/*
 * Attempt to cancel a pending twork. Returns 1 if successful, or 0
 * if the work was currently running, and will be completed.
 */
extern int twork_cancel(struct twork *tw);

/* reports whether caller-provided item <tw> is still queued or executing */
static inline int twork_pending(const struct twork *tw)
{
	return MT_LIST_INLIST((struct mt_list *)&tw->link) ||
	       (HA_ATOMIC_LOAD(&tw->flags) & (TWORK_FL_BUSY | TWORK_FL_REPLY));
}

/* prepares caller-provided work item <tw> for its first use */
static inline void twork_init(struct twork *tw)
{
	MT_LIST_INIT(&tw->link);
	tw->flags = 0;
}

/* constructors, always initializing the whole union */
static inline union twork_arg twk_ptr(void *p)
{
	union twork_arg a;

	a.u64 = 0;
	a.ptr = p;
	return a;
}

static inline union twork_arg twk_u32(uint32_t v)
{
	union twork_arg a;

	a.u64 = 0;
	a.u32 = v;
	return a;
}

static inline union twork_arg twk_u64(uint64_t v)
{
	union twork_arg a;

	a.u64 = v;
	return a;
}

#endif /* _HAPROXY_TWORK_H */
