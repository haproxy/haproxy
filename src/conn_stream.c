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
#include <haproxy/stream_interface.h>

DECLARE_POOL(pool_head_connstream, "conn_stream", sizeof(struct conn_stream));
DECLARE_POOL(pool_head_cs_endpoint, "cs_endpoint", sizeof(struct cs_endpoint));

void cs_endpoint_init(struct cs_endpoint *endp)
{
	endp->target = NULL;
	endp->ctx = NULL;
	endp->flags = CS_EP_NONE;
}

struct cs_endpoint *cs_endpoint_new()
{
	struct cs_endpoint *endp;

	endp = pool_alloc(pool_head_cs_endpoint);
	if (unlikely(!endp))
		return NULL;

	cs_endpoint_init(endp);
	return endp;
}

void cs_endpoint_free(struct cs_endpoint *endp)
{
	pool_free(pool_head_cs_endpoint, endp);
}

/* Tries to allocate a new conn_stream and initialize its main fields. On
 * failure, nothing is allocated and NULL is returned.
 */
struct conn_stream *cs_new()
{
	struct conn_stream *cs;
	struct cs_endpoint *endp;

	cs = pool_alloc(pool_head_connstream);

	if (unlikely(!cs))
		goto alloc_error;

	cs->obj_type = OBJ_TYPE_CS;
	cs->flags = CS_FL_NONE;
	cs->app = NULL;
	cs->si = NULL;
	cs->data_cb = NULL;

	endp = cs_endpoint_new();
	if (unlikely(!endp))
		goto alloc_error;
	cs->endp = endp;

	return cs;

  alloc_error:
	pool_free(pool_head_connstream, cs);
	return NULL;
}

/* Releases a conn_stream previously allocated by cs_new(), as well as any
 * buffer it would still hold.
 */
void cs_free(struct conn_stream *cs)
{
	si_free(cs->si);
	if (cs->endp) {
		cs_endpoint_free(cs->endp);
	}
	pool_free(pool_head_connstream, cs);
}


/* Attaches a conn_stream to an mux endpoint and sets the endpoint ctx */
void cs_attach_endp_mux(struct conn_stream *cs, void *endp, void *ctx)
{
	struct connection *conn = ctx;

	cs->endp->target = endp;
	cs->endp->ctx = ctx;
	cs->endp->flags |= CS_EP_T_MUX;
	if (!conn->ctx)
		conn->ctx = cs;
	if (cs_strm(cs)) {
		cs->si->ops = &si_conn_ops;
		cs->data_cb = &si_conn_cb;
	}
	else if (cs_check(cs))
		cs->data_cb = &check_conn_cb;
}

/* Attaches a conn_stream to an applet endpoint and sets the endpoint ctx */
void cs_attach_endp_app(struct conn_stream *cs, void *endp, void *ctx)
{
	struct appctx *appctx = endp;

	cs->endp->target = endp;
	cs->endp->ctx = ctx;
	cs->endp->flags |= CS_EP_T_APPLET;
	appctx->owner = cs;
	if (cs->si) {
		cs->si->ops = &si_applet_ops;
		cs->data_cb = NULL;
	}
}

/* Attaches a conn_stream to a app layer and sets the relevant callbacks */
int cs_attach_app(struct conn_stream *cs, enum obj_type *app)
{
	cs->app = app;

	if (objt_stream(app)) {
		if (!cs->si)
			cs->si = si_new(cs);
		if (unlikely(!cs->si))
			return -1;

		if (cs->endp->flags & CS_EP_T_MUX) {
			cs->si->ops = &si_conn_ops;
			cs->data_cb = &si_conn_cb;
		}
		else if (cs->endp->flags & CS_EP_T_APPLET) {
			cs->si->ops = &si_applet_ops;
			cs->data_cb = NULL;
		}
		else {
			cs->si->ops = &si_embedded_ops;
			cs->data_cb = NULL;
		}
	}
	else if (objt_check(app))
		cs->data_cb = &check_conn_cb;
	return 0;
}

/* Detach the conn_stream from the endpoint, if any. For a connecrion, if a mux
 * owns the connection ->detach() callback is called. Otherwise, it means the
 * conn-stream owns the connection. In this case the connection is closed and
 * released. For an applet, the appctx is released. At the end, the conn-stream
 * is not released but some fields a reset.
 */
void cs_detach_endp(struct conn_stream *cs)
{
	if (cs->endp->flags & CS_EP_T_MUX) {
		struct connection *conn = cs_conn(cs);

		if (conn->mux) {
			/* TODO: handle unsubscribe for healthchecks too */
			if (cs->si && cs->si->wait_event.events != 0)
				conn->mux->unsubscribe(cs, cs->si->wait_event.events, &cs->si->wait_event);
			conn->mux->detach(cs);
		}
		else {
			/* It's too early to have a mux, let's just destroy
			 * the connection
			 */
			conn_stop_tracking(conn);
			conn_full_close(conn);
			if (conn->destroy_cb)
				conn->destroy_cb(conn);
			conn_free(conn);
		}
	}
	else if (cs->endp->flags & CS_EP_T_APPLET) {
		struct appctx *appctx = cs_appctx(cs);

		if (cs->si)
			si_applet_release(cs->si);
		appctx_free(appctx);
	}

	if (cs->endp) {
		cs_endpoint_init(cs->endp);
	}

	/* FIXME: Rest CS for now but must be reviewed. CS flags are only
	 *        connection related for now but this will evolved
	 */
	cs->flags = CS_FL_NONE;
	if (cs->si)
		cs->si->ops = &si_embedded_ops;
	cs->data_cb = NULL;

	if (cs->app == NULL)
		cs_free(cs);
}

void cs_detach_app(struct conn_stream *cs)
{
	si_free(cs->si);
	cs->app = NULL;
	cs->si  = NULL;
	cs->data_cb = NULL;

	if (!cs->endp || !cs->endp->target)
		cs_free(cs);
}
