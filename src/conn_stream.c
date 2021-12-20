/*
 * Conn-stream management functions
 *
 * Copyright 2021 Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/conn_stream.h>
#include <haproxy/pool.h>
//#include <haproxy/stream_interface.h>

DECLARE_POOL(pool_head_connstream, "conn_stream", sizeof(struct conn_stream));


/* Tries to allocate a new conn_stream and initialize its main fields. On
 * failure, nothing is allocated and NULL is returned.
 */
struct conn_stream *cs_new(enum obj_type *endp)
{
	struct conn_stream *cs;

	cs = pool_alloc(pool_head_connstream);
	if (unlikely(!cs))
		return NULL;
	cs_init(cs, endp);
	return cs;
}

/* Releases a conn_stream previously allocated by cs_new(), as well as any
 * buffer it would still hold.
 */
void cs_free(struct conn_stream *cs)
{
	pool_free(pool_head_connstream, cs);
}
