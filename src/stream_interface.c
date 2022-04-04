/*
 * Functions managing stream_interface structures
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/channel.h>
#include <haproxy/connection.h>
#include <haproxy/conn_stream.h>
#include <haproxy/cs_utils.h>
#include <haproxy/dynbuf.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/pipe-t.h>
#include <haproxy/pipe.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/stream-t.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>


DECLARE_POOL(pool_head_streaminterface, "stream_interface", sizeof(struct stream_interface));

struct stream_interface *si_new(struct conn_stream *cs)
{
	struct stream_interface *si;

	si = pool_alloc(pool_head_streaminterface);
	if (unlikely(!si))
		return NULL;
	si->flags = SI_FL_NONE;
	if (si_init(si) < 0) {
		pool_free(pool_head_streaminterface, si);
		return NULL;
	}
	si->cs = cs;
	return si;
}

void si_free(struct stream_interface *si)
{
	if (!si)
		return;

	pool_free(pool_head_streaminterface, si);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
