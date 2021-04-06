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


DECLARE_STATIC_POOL(pool_head_pipe, "pipe", sizeof(struct pipe));

struct pipe *pipes_live = NULL; /* pipes which are still ready to use */

__decl_spinlock(pipes_lock); /* lock used to protect pipes list */

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

	ret = local_pipes;
	if (likely(ret)) {
		local_pipes = ret->next;
		local_pipes_free--;
		HA_ATOMIC_DEC(&pipes_free);
		HA_ATOMIC_INC(&pipes_used);
		goto out;
	}

	if (likely(pipes_live)) {
		HA_SPIN_LOCK(PIPES_LOCK, &pipes_lock);
		ret = pipes_live;
		if (likely(ret))
			pipes_live = ret->next;
		HA_SPIN_UNLOCK(PIPES_LOCK, &pipes_lock);
		if (ret) {
			HA_ATOMIC_DEC(&pipes_free);
			HA_ATOMIC_INC(&pipes_used);
			goto out;
		}
	}

	HA_ATOMIC_INC(&pipes_used);
	if (pipes_used + pipes_free >= global.maxpipes)
		goto fail;

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
}

/* put back a unused pipe into the live pool. If it still has data in it, it is
 * closed and not reinjected into the live pool. The caller is not allowed to
 * use it once released.
 */
void put_pipe(struct pipe *p)
{
	if (unlikely(p->data)) {
		kill_pipe(p);
		return;
	}

	if (likely(local_pipes_free * global.nbthread < global.maxpipes - pipes_used)) {
		p->next = local_pipes;
		local_pipes = p;
		local_pipes_free++;
		goto out;
	}

	HA_SPIN_LOCK(PIPES_LOCK, &pipes_lock);
	p->next = pipes_live;
	pipes_live = p;
	HA_SPIN_UNLOCK(PIPES_LOCK, &pipes_lock);
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
