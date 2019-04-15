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

#include <common/config.h>
#include <common/hathreads.h>
#include <common/memory.h>

#include <types/global.h>
#include <types/pipe.h>

DECLARE_STATIC_POOL(pool_head_pipe, "pipe", sizeof(struct pipe));

struct pipe *pipes_live = NULL; /* pipes which are still ready to use */

__decl_spinlock(pipes_lock); /* lock used to protect pipes list */

int pipes_used = 0;             /* # of pipes in use (2 fds each) */
int pipes_free = 0;             /* # of pipes unused */

/* return a pre-allocated empty pipe. Try to allocate one if there isn't any
 * left. NULL is returned if a pipe could not be allocated.
 */
struct pipe *get_pipe()
{
	struct pipe *ret = NULL;
	int pipefd[2];

	HA_SPIN_LOCK(PIPES_LOCK, &pipes_lock);
	if (likely(pipes_live)) {
		ret = pipes_live;
		pipes_live = pipes_live->next;
		pipes_free--;
		pipes_used++;
		goto out;
	}

	if (pipes_used >= global.maxpipes)
		goto out;

	ret = pool_alloc(pool_head_pipe);
	if (!ret)
		goto out;

	if (pipe(pipefd) < 0) {
		pool_free(pool_head_pipe, ret);
		goto out;
	}
#ifdef F_SETPIPE_SZ
	if (global.tune.pipesize)
		fcntl(pipefd[0], F_SETPIPE_SZ, global.tune.pipesize);
#endif
	ret->data = 0;
	ret->prod = pipefd[1];
	ret->cons = pipefd[0];
	ret->next = NULL;
	pipes_used++;
 out:
	HA_SPIN_UNLOCK(PIPES_LOCK, &pipes_lock);
	return ret;
}

static inline void __kill_pipe(struct pipe *p)
{
	close(p->prod);
	close(p->cons);
	pool_free(pool_head_pipe, p);
	pipes_used--;
	return;
}

/* destroy a pipe, possibly because an error was encountered on it. Its FDs
 * will be closed and it will not be reinjected into the live pool.
 */
void kill_pipe(struct pipe *p)
{
	HA_SPIN_LOCK(PIPES_LOCK, &pipes_lock);
	__kill_pipe(p);
	HA_SPIN_UNLOCK(PIPES_LOCK, &pipes_lock);
	return;
}

/* put back a unused pipe into the live pool. If it still has data in it, it is
 * closed and not reinjected into the live pool. The caller is not allowed to
 * use it once released.
 */
void put_pipe(struct pipe *p)
{
	HA_SPIN_LOCK(PIPES_LOCK, &pipes_lock);
	if (p->data) {
		__kill_pipe(p);
		goto out;
	}
	p->next = pipes_live;
	pipes_live = p;
	pipes_free++;
	pipes_used--;
 out:
	HA_SPIN_UNLOCK(PIPES_LOCK, &pipes_lock);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
