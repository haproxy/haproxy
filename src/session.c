/*
 * Server management functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdlib.h>

#include <common/config.h>
#include <common/memory.h>

#include <types/backend.h>
#include <types/capture.h>
#include <types/log.h>
#include <types/proxy.h>
#include <types/server.h>

#include <proto/session.h>
#include <proto/queue.h>


void **pool_session = NULL;

/*
 * frees  the context associated to a session. It must have been removed first.
 */
void session_free(struct session *s)
{
	if (s->pend_pos)
		pendconn_free(s->pend_pos);
	if (s->req)
		pool_free(buffer, s->req);
	if (s->rep)
		pool_free(buffer, s->rep);

	if (s->hreq.hdr_idx.v != NULL)
		pool_free_to(s->fe->hdr_idx_pool, s->hreq.hdr_idx.v);

	if (s->rsp_cap != NULL) {
		struct cap_hdr *h;
		for (h = s->fe->fiprm->rsp_cap; h; h = h->next) {
			if (s->rsp_cap[h->index] != NULL)
				pool_free_to(h->pool, s->rsp_cap[h->index]);
		}
		pool_free_to(s->fe->fiprm->rsp_cap_pool, s->rsp_cap);
	}
	if (s->hreq.cap != NULL) {
		struct cap_hdr *h;
		for (h = s->fe->fiprm->req_cap; h; h = h->next) {
			if (s->hreq.cap[h->index] != NULL)
				pool_free_to(h->pool, s->hreq.cap[h->index]);
		}
		pool_free_to(s->fe->fiprm->req_cap_pool, s->hreq.cap);
	}

	if (s->logs.uri)
		pool_free(requri, s->logs.uri);
	if (s->logs.cli_cookie)
		pool_free(capture, s->logs.cli_cookie);
	if (s->logs.srv_cookie)
		pool_free(capture, s->logs.srv_cookie);

	pool_free(session, s);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
