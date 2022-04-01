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
struct conn_stream *cs_new(struct cs_endpoint *endp)
{
	struct conn_stream *cs;

	cs = pool_alloc(pool_head_connstream);

	if (unlikely(!cs))
		goto alloc_error;

	cs->obj_type = OBJ_TYPE_CS;
	cs->flags = CS_FL_NONE;
	cs->state = CS_ST_INI;
	cs->hcto = TICK_ETERNITY;
	cs->app = NULL;
	cs->si = NULL;
	cs->data_cb = NULL;
	cs->src = NULL;
	cs->dst = NULL;
	cs->wait_event.tasklet = NULL;
	cs->wait_event.events = 0;

	if (!endp) {
		endp = cs_endpoint_new();
		if (unlikely(!endp))
			goto alloc_error;
	}
	cs->endp = endp;

	return cs;

  alloc_error:
	pool_free(pool_head_connstream, cs);
	return NULL;
}

struct conn_stream *cs_new_from_mux(struct cs_endpoint *endp, struct session *sess, struct buffer *input)
{
	struct conn_stream *cs;

	cs = cs_new(endp);
	if (unlikely(!cs))
		return NULL;
	if (unlikely(!stream_new(sess, cs, input))) {
		pool_free(pool_head_connstream, cs);
		cs = NULL;
	}
	endp->flags &= ~CS_EP_ORPHAN;
	return cs;
}

struct conn_stream *cs_new_from_applet(struct cs_endpoint *endp, struct session *sess, struct buffer *input)
{
	struct conn_stream *cs;
	struct appctx *appctx = endp->ctx;

	cs = cs_new(endp);
	if (unlikely(!cs))
		return NULL;
	appctx->owner = cs;
	if (unlikely(!stream_new(sess, cs, input))) {
		pool_free(pool_head_connstream, cs);
		cs = NULL;
	}
	endp->flags &= ~CS_EP_ORPHAN;
	return cs;
}

struct conn_stream *cs_new_from_strm(struct stream *strm, unsigned int flags)
{
	struct conn_stream *cs;

	cs = cs_new(NULL);
	if (unlikely(!cs))
		return NULL;
	cs->flags |= flags;
	cs->endp->flags |=  CS_EP_DETACHED;
	cs->si = si_new(cs);
	if (unlikely(!cs->si)) {
		cs_free(cs);
		return NULL;
	}

	cs->app = &strm->obj_type;
	cs->ops = &cs_app_embedded_ops;
	cs->data_cb = NULL;
	return cs;
}

struct conn_stream *cs_new_from_check(struct check *check, unsigned int flags)
{
	struct conn_stream *cs;

	cs = cs_new(NULL);
	if (unlikely(!cs))
		return NULL;
	cs->flags |= flags;
	cs->endp->flags |=  CS_EP_DETACHED;
	cs->app = &check->obj_type;
	cs->data_cb = &check_conn_cb;
	return cs;
}

/* Releases a conn_stream previously allocated by cs_new(), as well as any
 * buffer it would still hold.
 */
void cs_free(struct conn_stream *cs)
{
	si_free(cs->si);
	sockaddr_free(&cs->src);
	sockaddr_free(&cs->dst);
	if (cs->endp) {
		BUG_ON(!(cs->endp->flags & CS_EP_DETACHED));
		cs_endpoint_free(cs->endp);
	}
	if (cs->wait_event.tasklet)
		tasklet_free(cs->wait_event.tasklet);
	pool_free(pool_head_connstream, cs);
}


/* Attaches a conn_stream to an mux endpoint and sets the endpoint ctx */
int cs_attach_mux(struct conn_stream *cs, void *target, void *ctx)
{
	struct connection *conn = ctx;

	cs->endp->target = target;
	cs->endp->ctx = ctx;
	cs->endp->flags |= CS_EP_T_MUX;
	cs->endp->flags &= ~CS_EP_DETACHED;
	if (!conn->ctx)
		conn->ctx = cs;
	if (cs_strm(cs)) {
		if (!cs->wait_event.tasklet) {
			cs->wait_event.tasklet = tasklet_new();
			if (!cs->wait_event.tasklet)
				return -1;
			cs->wait_event.tasklet->process = si_cs_io_cb;
			cs->wait_event.tasklet->context = cs->si;
			cs->wait_event.events = 0;
		}

		cs->ops = &cs_app_conn_ops;
		cs->data_cb = &si_conn_cb;
	}
	else if (cs_check(cs))
		cs->data_cb = &check_conn_cb;
	return 0;
}

/* Attaches a conn_stream to an applet endpoint and sets the endpoint ctx */
void cs_attach_applet(struct conn_stream *cs, void *target, void *ctx)
{
	struct appctx *appctx = target;

	cs->endp->target = target;
	cs->endp->ctx = ctx;
	cs->endp->flags |= CS_EP_T_APPLET;
	cs->endp->flags &= ~CS_EP_DETACHED;
	appctx->owner = cs;
	if (cs_strm(cs)) {
		cs->ops = &cs_app_applet_ops;
		cs->data_cb = NULL;
	}
}

/* Attaches a conn_stream to a app layer and sets the relevant callbacks */
int cs_attach_strm(struct conn_stream *cs, struct stream *strm)
{
	cs->app = &strm->obj_type;

	cs->si = si_new(cs);
	if (unlikely(!cs->si))
		return -1;

	cs->endp->flags &= ~CS_EP_ORPHAN;
	if (cs->endp->flags & CS_EP_T_MUX) {
		cs->wait_event.tasklet = tasklet_new();
		if (!cs->wait_event.tasklet) {
			si_free(cs->si);
			cs->si = NULL;
			return -1;
		}
		cs->wait_event.tasklet->process = si_cs_io_cb;
		cs->wait_event.tasklet->context = cs->si;
		cs->wait_event.events = 0;

		cs->ops = &cs_app_conn_ops;
		cs->data_cb = &si_conn_cb;
	}
	else if (cs->endp->flags & CS_EP_T_APPLET) {
		cs->ops = &cs_app_applet_ops;
		cs->data_cb = NULL;
	}
	else {
		cs->ops = &cs_app_embedded_ops;
		cs->data_cb = NULL;
	}
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
	if (!cs->endp)
		goto reset_cs;

	if (cs->endp->flags & CS_EP_T_MUX) {
		struct connection *conn = cs_conn(cs);

		if (conn->mux) {
			/* TODO: handle unsubscribe for healthchecks too */
			cs->endp->flags |= CS_EP_ORPHAN;
			if (cs->wait_event.events != 0)
				conn->mux->unsubscribe(cs, cs->wait_event.events, &cs->wait_event);
			conn->mux->detach(cs);
			cs->endp = NULL;
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

		cs->endp->flags |= CS_EP_ORPHAN;
		if (cs->si)
			si_applet_release(cs->si);
		appctx_free(appctx);
		cs->endp = NULL;
	}

	if (cs->endp) {
		/* the cs is the only one one the endpoint */
		cs_endpoint_init(cs->endp);
		cs->endp->flags |= CS_EP_DETACHED;
	}

  reset_cs:
	/* FIXME: Rest CS for now but must be reviewed. CS flags are only
	 *        connection related for now but this will evolved
	 */
	cs->flags &= CS_FL_ISBACK;
	if (cs->si)
		cs->ops = &cs_app_embedded_ops;
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
	sockaddr_free(&cs->src);
	sockaddr_free(&cs->dst);

	if (cs->wait_event.tasklet)
		tasklet_free(cs->wait_event.tasklet);
	cs->wait_event.tasklet = NULL;
	cs->wait_event.events = 0;

	if (!cs->endp || (cs->endp->flags & CS_EP_DETACHED))
		cs_free(cs);
}

int cs_reset_endp(struct conn_stream *cs)
{
	struct cs_endpoint *new_endp;

	BUG_ON(!cs->app);
	if (!__cs_endp_target(cs)) {
		/* endpoint not attached or attached to a mux with no
		 * target. Thus the endpoint will not be release but just
		 * reset
		 */
		cs_detach_endp(cs);
		return 0;
	}

	/* allocate the new endpoint first to be able to set error if it
	 * fails */
	new_endp = cs_endpoint_new();
	if (!unlikely(new_endp)) {
		cs->endp->flags |= CS_EP_ERROR;
		return -1;
	}

	cs_detach_endp(cs);
	BUG_ON(cs->endp);
	cs->endp = new_endp;
	cs->endp->flags |= CS_EP_DETACHED;
	return 0;
}
