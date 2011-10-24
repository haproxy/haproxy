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
#include <common/memory.h>

#include <types/global.h>
#include <types/pipe.h>

struct pool_head *pool2_pipe = NULL;
struct pipe *pipes_live = NULL; /* pipes which are still ready to use */
int pipes_used = 0;             /* # of pipes in use (2 fds each) */
int pipes_free = 0;             /* # of pipes unused */

/* allocate memory for the pipes */
static void init_pipe()
{
	pool2_pipe = create_pool("pipe", sizeof(struct pipe), MEM_F_SHARED);
	pipes_used = 0;
	pipes_free = 0;
}

/* return a pre-allocated empty pipe. Try to allocate one if there isn't any
 * left. NULL is returned if a pipe could not be allocated.
 */
struct pipe *get_pipe()
{
	struct pipe *ret;
	int pipefd[2];

	if (likely(pipes_live)) {
		ret = pipes_live;
		pipes_live = pipes_live->next;
		pipes_free--;
		pipes_used++;
		return ret;
	}

	if (pipes_used >= global.maxpipes)
		return NULL;

	ret = pool_alloc2(pool2_pipe);
	if (!ret)
		return NULL;

	if (pipe(pipefd) < 0) {
		pool_free2(pool2_pipe, ret);
		return NULL;
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
	return ret;
}

/* destroy a pipe, possibly because an error was encountered on it. Its FDs
 * will be closed and it will not be reinjected into the live pool.
 */
void kill_pipe(struct pipe *p)
{
	close(p->prod);
	close(p->cons);
	pool_free2(pool2_pipe, p);
	pipes_used--;
	return;
}

/* put back a unused pipe into the live pool. If it still has data in it, it is
 * closed and not reinjected into the live pool. The caller is not allowed to
 * use it once released.
 */
void put_pipe(struct pipe *p)
{
	if (p->data) {
		kill_pipe(p);
		return;
	}
	p->next = pipes_live;
	pipes_live = p;
	pipes_free++;
	pipes_used--;
}


__attribute__((constructor))
static void __pipe_module_init(void)
{
	init_pipe();
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
