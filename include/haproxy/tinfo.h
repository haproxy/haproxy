/*
 * include/haproxy/tinfo.h
 * Export of ha_thread_info[] and ti pointer.
 *
 * Copyright (C) 2020 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_TINFO_H
#define _HAPROXY_TINFO_H

#include <haproxy/api.h>
#include <haproxy/tinfo-t.h>
#include <haproxy/intops.h>

/* the structs are in thread.c */
extern struct tgroup_info ha_tgroup_info[MAX_TGROUPS];
extern THREAD_LOCAL const struct tgroup_info *tg;

extern struct thread_info ha_thread_info[MAX_THREADS];
extern THREAD_LOCAL const struct thread_info *ti;   /* thread_info for the current thread */

extern struct tgroup_ctx ha_tgroup_ctx[MAX_TGROUPS];
extern THREAD_LOCAL struct tgroup_ctx *tg_ctx; /* ha_tgroup_ctx for the current thread */

extern struct thread_ctx ha_thread_ctx[MAX_THREADS];
extern THREAD_LOCAL struct thread_ctx *th_ctx; /* ha_thread_ctx for the current thread */

/* returns the number of threads set in set <ts>. */
static inline int thread_set_count(const struct thread_set *ts)
{
	int i, n;

	/* iterating over tgroups guarantees to visit all possible threads, the
	 * opposite is not true.
	 */
	for (i = n = 0; i < MAX_TGROUPS; i++)
		n += my_popcountl(ts->rel[i]);
	return n;
}

/* returns zero if the thread set <ts> has at least one thread set,
 * otherwise non-zero.
 */
static inline int thread_set_is_empty(const struct thread_set *ts)
{
	int i;

	/* iterating over tgroups guarantees to visit all possible threads, the
	 * opposite is not true.
	 */
	for (i = 0; i < MAX_TGROUPS; i++)
		if (ts->rel[i])
			return 0;
	return 1;
}

/* returns the number starting at 1 of the <n>th thread-group set in thread set
 * <ts>, or zero if the set is empty or if thread numbers are only absolute.
 * <n> starts at zero and corresponds to the number of non-empty groups to be
 * skipped (i.e. 0 returns the first one).
 */
static inline int thread_set_nth_group(const struct thread_set *ts, int n)
{
	int i;

	if (ts->nbgrps) {
		for (i = 0; i < MAX_TGROUPS; i++)
			if (ts->rel[i] && !n--)
				return i + 1;
	}
	return 0;
}

/* returns the thread mask of the <n>th assigned thread-group in the thread
 * set <ts> for relative sets, the first thread mask at all in case of absolute
 * sets, or zero if the set is empty. This is only used temporarily to ease the
 * transition. <n> starts at zero and corresponds to the number of non-empty
 * groups to be skipped (i.e. 0 returns the first one).
 */
static inline ulong thread_set_nth_tmask(const struct thread_set *ts, int n)
{
	int i;

	if (ts->nbgrps) {
		for (i = 0; i < MAX_TGROUPS; i++)
			if (ts->rel[i] && !n--)
				return ts->rel[i];
	}
	return ts->abs[0];
}

/* Pins the thread set to the specified thread mask on group 1 (use ~0UL for
 * all threads). This is for compatibility with some rare legacy code. If a
 * "thread" directive on a bind line is parsed, this one will be overwritten.
 */
static inline void thread_set_pin_grp1(struct thread_set *ts, ulong mask)
{
	int i;

	ts->nbgrps = 1;
	ts->rel[0] = mask;
	for (i = 1; i < MAX_TGROUPS; i++)
		ts->rel[i] = 0;
}

/* switches the current execution context to <ctx> and returns the previous one
 * so that this may even be used to save and restore. Setting EXEC_CTX_NONE
 * resets it. It's efficient because it uses a pair of registers on input and
 * output.
 */
static inline struct thread_exec_ctx switch_exec_ctx(const struct thread_exec_ctx ctx)
{
	const struct thread_exec_ctx prev = th_ctx->exec_ctx;

	th_ctx->exec_ctx = ctx;
	return prev;
}

/* used to reset the execution context */
#define EXEC_CTX_NONE ((struct thread_exec_ctx){ .type = 0, .pointer = NULL })

/* make an execution context from a type and a pointer */
#define EXEC_CTX_MAKE(_type, _pointer) ((struct thread_exec_ctx){ .type = (_type), .pointer = (_pointer) })

/* execute expression <expr> under context <new_ctx> then restore the previous
 * one, and return the expression's return value.
 */
#define EXEC_CTX_WITH_RET(new_ctx, expr) ({                                  \
	const struct thread_exec_ctx __prev_ctx = switch_exec_ctx(new_ctx);  \
	typeof(expr) __ret = (expr);                                         \
	switch_exec_ctx(__prev_ctx);                                         \
	__ret;                                                               \
})

/* execute expression <expr> under context <new_ctx> then restore the previous
 * one. This one has no return value.
 */
#define EXEC_CTX_NO_RET(new_ctx, expr) do {                                  \
	const struct thread_exec_ctx __prev_ctx = switch_exec_ctx(new_ctx);  \
	do { expr; } while (0);                                              \
	switch_exec_ctx(__prev_ctx);                                         \
} while (0)

#endif /* _HAPROXY_TINFO_H */
