/*
 * Stream management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/buffer.h>
#include <common/debug.h>
#include <common/memory.h>

#include <types/global.h>
#include <types/session.h>

struct pool_head *pool2_session;

void session_free(struct session *sess)
{
	pool_free2(pool2_session, sess);
}

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_session()
{
	pool2_session = create_pool("session", sizeof(struct session), MEM_F_SHARED);
	return pool2_session != NULL;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
