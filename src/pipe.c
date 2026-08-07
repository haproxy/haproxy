/*
 * Pipe management
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <unistd.h>
#include <fcntl.h>

#include <haproxy/api.h>
#include <haproxy/global.h>
#include <haproxy/pipe-t.h>
#include <haproxy/pool.h>
#include <haproxy/thread.h>
#include <haproxy/tinfo.h>


DECLARE_STATIC_TYPED_POOL(pool_head_pipe, "pipe", struct pipe);

/* The pools of pipes which are still ready to use, one per thread group:
 * with per-thread-group FD tables, a pipe's FDs are only valid within the
 * kernel table of the group that created it, so free pipes must never
 * travel across groups. With shared FD tables any pipe is usable by any
 * thread, so only the first pool is used then. The spinlocks rely on
 * being zero-initialized.
 */
static struct {
	struct pipe *live;        /* pipes which are still ready to use */
	uint max;                 /* max pipes this pool may own */
	uint count;               /* pipes owned by this pool (used + free) */
	__decl_thread(HA_SPINLOCK_T lock); /* lock used to protect the list */
} pipe_pools[MAX_TGROUPS] __attribute__((aligned(64)));

/* returns the index of the pool the current thread must use */
static inline int pipe_pool_id(void)
{
	return (global.tune.options & GTUNE_NO_TG_FD_SHARING) ? tgid - 1 : 0;
}

/* returns the number of threads sharing the current thread's pool */
static inline int pipe_pool_threads(void)
{
	if (global.tune.options & GTUNE_NO_TG_FD_SHARING)
		return tg->count;
	return global.nbthread;
}

static int init_pipes_per_thread(void)
{
	uint pools, id, base, rem;

	if (global.tune.options & GTUNE_NO_TG_FD_SHARING) {
		pools = global.nbtgroups;
		id    = tgid - 1;
	} else {
		pools = 1;
		id    = 0;
	}

	base = global.maxpipes / pools;
	rem  = global.maxpipes % pools;

	/* all the threads of a pool compute the same value */
	HA_ATOMIC_STORE(&pipe_pools[id].max, base + (id < rem));
	return 1;
}
REGISTER_PER_THREAD_INIT(init_pipes_per_thread);

static THREAD_LOCAL int local_pipes_free = 0;  /* #cache objects   */
static THREAD_LOCAL struct pipe *local_pipes = NULL;

int pipes_used = 0;             /* # of pipes in use (2 fds each) */
int pipes_free = 0;             /* # of pipes unused */

/* return a pre-allocated empty pipe. Try to allocate one if there isn't any
 * left. NULL is returned if a pipe could not be allocated.
 */
struct pipe *get_pipe()
{
	struct pipe *ret = NULL;
	int pipefd[2];
	int grp;
	uint count;

	ret = local_pipes;
	if (likely(ret)) {
		local_pipes = ret->next;
		local_pipes_free--;
		HA_ATOMIC_DEC(&pipes_free);
		HA_ATOMIC_INC(&pipes_used);
		goto out;
	}

	grp = pipe_pool_id();

	if (likely(pipe_pools[grp].live)) {
		HA_SPIN_LOCK(PIPES_LOCK, &pipe_pools[grp].lock);
		ret = pipe_pools[grp].live;
		if (likely(ret))
			pipe_pools[grp].live = ret->next;
		HA_SPIN_UNLOCK(PIPES_LOCK, &pipe_pools[grp].lock);
		if (ret) {
			HA_ATOMIC_DEC(&pipes_free);
			HA_ATOMIC_INC(&pipes_used);
			goto out;
		}
	}

	count = HA_ATOMIC_LOAD(&pipe_pools[grp].count);
	for (;; __ha_cpu_relax()) {
		if (count >= HA_ATOMIC_LOAD(&pipe_pools[grp].max))
			return NULL;
		if (HA_ATOMIC_CAS(&pipe_pools[grp].count, &count, count + 1))
			break;
	}

	HA_ATOMIC_INC(&pipes_used);

	ret = pool_alloc(pool_head_pipe);
	if (!ret)
		goto fail;

	if (pipe(pipefd) < 0)
		goto fail;

#ifdef F_SETPIPE_SZ
	if (global.tune.pipesize)
		fcntl(pipefd[0], F_SETPIPE_SZ, global.tune.pipesize);
#endif
	ret->data = 0;
	ret->prod = pipefd[1];
	ret->cons = pipefd[0];
	ret->next = NULL;
 out:
	return ret;
 fail:
	pool_free(pool_head_pipe, ret);
	HA_ATOMIC_DEC(&pipes_used);
	HA_ATOMIC_DEC(&pipe_pools[grp].count);
	return NULL;

}

/* destroy a pipe, possibly because an error was encountered on it. Its FDs
 * will be closed and it will not be reinjected into the live pool.
 */
void kill_pipe(struct pipe *p)
{
	close(p->prod);
	close(p->cons);
	pool_free(pool_head_pipe, p);
	HA_ATOMIC_DEC(&pipes_used);
	HA_ATOMIC_DEC(&pipe_pools[pipe_pool_id()].count);
}

/* put back a unused pipe into the live pool. If it still has data in it, it is
 * closed and not reinjected into the live pool. The caller is not allowed to
 * use it once released.
 */
void put_pipe(struct pipe *p)
{
	int grp;

	if (unlikely(p->data)) {
		kill_pipe(p);
		return;
	}

	grp = pipe_pool_id();

	if (likely((uint)(local_pipes_free + 1) * pipe_pool_threads() <= HA_ATOMIC_LOAD(&pipe_pools[grp].max))) {
		p->next = local_pipes;
		local_pipes = p;
		local_pipes_free++;
		goto out;
	}

	HA_SPIN_LOCK(PIPES_LOCK, &pipe_pools[grp].lock);
	p->next = pipe_pools[grp].live;
	pipe_pools[grp].live = p;
	HA_SPIN_UNLOCK(PIPES_LOCK, &pipe_pools[grp].lock);
 out:
	HA_ATOMIC_INC(&pipes_free);
	HA_ATOMIC_DEC(&pipes_used);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
