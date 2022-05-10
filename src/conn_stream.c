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
#include <haproxy/applet.h>
#include <haproxy/connection.h>
#include <haproxy/conn_stream.h>
#include <haproxy/cs_utils.h>
#include <haproxy/check.h>
#include <haproxy/http_ana.h>
#include <haproxy/pipe.h>
#include <haproxy/pool.h>

DECLARE_POOL(pool_head_connstream, "conn_stream", sizeof(struct conn_stream));
DECLARE_POOL(pool_head_cs_endpoint, "cs_endpoint", sizeof(struct cs_endpoint));

/* functions used by default on a detached conn-stream */
static void cs_app_shutr(struct conn_stream *cs);
static void cs_app_shutw(struct conn_stream *cs);
static void cs_app_chk_rcv(struct conn_stream *cs);
static void cs_app_chk_snd(struct conn_stream *cs);

/* functions used on a mux-based conn-stream */
static void cs_app_shutr_conn(struct conn_stream *cs);
static void cs_app_shutw_conn(struct conn_stream *cs);
static void cs_app_chk_rcv_conn(struct conn_stream *cs);
static void cs_app_chk_snd_conn(struct conn_stream *cs);

/* functions used on an applet-based conn-stream */
static void cs_app_shutr_applet(struct conn_stream *cs);
static void cs_app_shutw_applet(struct conn_stream *cs);
static void cs_app_chk_rcv_applet(struct conn_stream *cs);
static void cs_app_chk_snd_applet(struct conn_stream *cs);

/* conn-stream operations for connections */
struct cs_app_ops cs_app_conn_ops = {
	.chk_rcv = cs_app_chk_rcv_conn,
	.chk_snd = cs_app_chk_snd_conn,
	.shutr   = cs_app_shutr_conn,
	.shutw   = cs_app_shutw_conn,
};

/* conn-stream operations for embedded tasks */
struct cs_app_ops cs_app_embedded_ops = {
	.chk_rcv = cs_app_chk_rcv,
	.chk_snd = cs_app_chk_snd,
	.shutr   = cs_app_shutr,
	.shutw   = cs_app_shutw,
};

/* conn-stream operations for connections */
struct cs_app_ops cs_app_applet_ops = {
	.chk_rcv = cs_app_chk_rcv_applet,
	.chk_snd = cs_app_chk_snd_applet,
	.shutr   = cs_app_shutr_applet,
	.shutw   = cs_app_shutw_applet,
};

static int cs_conn_process(struct conn_stream *cs);
static int cs_conn_recv(struct conn_stream *cs);
static int cs_conn_send(struct conn_stream *cs);
static int cs_applet_process(struct conn_stream *cs);

struct data_cb cs_data_conn_cb = {
	.wake    = cs_conn_process,
	.name    = "STRM",
};

struct data_cb cs_data_applet_cb = {
	.wake    = cs_applet_process,
	.name    = "STRM",
};


/* Initializes an endpoint */
void cs_endpoint_init(struct cs_endpoint *endp)
{
	endp->target = NULL;
	endp->ctx = NULL;
	endp->cs = NULL;
	endp->flags = CS_EP_NONE;
}

/* Tries to alloc an endpoint and initialize it. Returns NULL on failure. */
struct cs_endpoint *cs_endpoint_new()
{
	struct cs_endpoint *endp;

	endp = pool_alloc(pool_head_cs_endpoint);
	if (unlikely(!endp))
		return NULL;

	cs_endpoint_init(endp);
	return endp;
}

/* Releases an endpoint. It is the caller responsibility to be sure it is safe
 * and it is not shared with another entity
 */
void cs_endpoint_free(struct cs_endpoint *endp)
{
	pool_free(pool_head_cs_endpoint, endp);
}

/* Tries to allocate a new conn_stream and initialize its main fields. On
 * failure, nothing is allocated and NULL is returned. It is an internal
 * function. The caller must, at least, set the CS_EP_ORPHAN or CS_EP_DETACHED
 * flag.
 */
static struct conn_stream *cs_new(struct cs_endpoint *endp)
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
	cs->data_cb = NULL;
	cs->src = NULL;
	cs->dst = NULL;
	cs->wait_event.tasklet = NULL;
	cs->wait_event.events = 0;

	/* If there is no endpoint, allocate a new one now */
	if (!endp) {
		endp = cs_endpoint_new();
		if (unlikely(!endp))
			goto alloc_error;
	}
	cs->endp = endp;
	endp->cs = cs;

	return cs;

  alloc_error:
	pool_free(pool_head_connstream, cs);
	return NULL;
}

/* Creates a new conn-stream and its associated stream from a mux. <endp> must be
 * defined. It returns NULL on error. On success, the new conn-stream is
 * returned. In this case, CS_EP_ORPHAN flag is removed.
 */
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

/* Creates a new conn-stream and its associated stream from an applet. <endp>
 * must be defined. It returns NULL on error. On success, the new conn-stream is
 * returned. In this case, CS_EP_ORPHAN flag is removed. The created CS is used
 * to set the appctx owner.
 */
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

/* Creates a new conn-stream from an stream. There is no endpoint here, thus it
 * will be created by cs_new(). So the CS_EP_DETACHED flag is set. It returns
 * NULL on error. On success, the new conn-stream is returned.
 */
struct conn_stream *cs_new_from_strm(struct stream *strm, unsigned int flags)
{
	struct conn_stream *cs;

	cs = cs_new(NULL);
	if (unlikely(!cs))
		return NULL;
	cs->flags |= flags;
	cs->endp->flags |=  CS_EP_DETACHED;
	cs->app = &strm->obj_type;
	cs->ops = &cs_app_embedded_ops;
	cs->data_cb = NULL;
	return cs;
}

/* Creates a new conn-stream from an health-check. There is no endpoint here,
 * thus it will be created by cs_new(). So the CS_EP_DETACHED flag is set. It
 * returns NULL on error. On success, the new conn-stream is returned.
 */
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

/* Releases a conn_stream previously allocated by cs_new(), as well as its
 * endpoint, if it exists. This function is called internally or on error path.
 */
void cs_free(struct conn_stream *cs)
{
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

/* Conditionally removes a conn-stream if it is detached and if there is no app
 * layer defined. Except on error path, this one must be used. if release, the
 * pointer on the CS is set to NULL.
 */
static void cs_free_cond(struct conn_stream **csp)
{
	struct conn_stream *cs = *csp;

	if (!cs->app && (!cs->endp || (cs->endp->flags & CS_EP_DETACHED))) {
		cs_free(cs);
		*csp = NULL;
	}
}


/* Attaches a conn_stream to a mux endpoint and sets the endpoint ctx. Returns
 * -1 on error and 0 on sucess. CS_EP_DETACHED flag is removed. This function is
 * called from a mux when it is attached to a stream or a health-check.
 */
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
			cs->wait_event.tasklet->process = cs_conn_io_cb;
			cs->wait_event.tasklet->context = cs;
			cs->wait_event.events = 0;
		}

		cs->ops = &cs_app_conn_ops;
		cs->data_cb = &cs_data_conn_cb;
	}
	else if (cs_check(cs))
		cs->data_cb = &check_conn_cb;
	return 0;
}

/* Attaches a conn_stream to an applet endpoint and sets the endpoint
 * ctx. Returns -1 on error and 0 on sucess. CS_EP_DETACHED flag is
 * removed. This function is called by a stream when a backend applet is
 * registered.
 */
static void cs_attach_applet(struct conn_stream *cs, void *target, void *ctx)
{
	struct appctx *appctx = target;

	cs->endp->target = target;
	cs->endp->ctx = ctx;
	cs->endp->flags |= CS_EP_T_APPLET;
	cs->endp->flags &= ~CS_EP_DETACHED;
	appctx->owner = cs;
	if (cs_strm(cs)) {
		cs->ops = &cs_app_applet_ops;
		cs->data_cb = &cs_data_applet_cb;
	}
}

/* Attaches a conn_stream to a app layer and sets the relevant
 * callbacks. Returns -1 on error and 0 on success. CS_EP_ORPHAN flag is
 * removed. This function is called by a stream when it is created to attach it
 * on the conn-stream on the client side.
 */
int cs_attach_strm(struct conn_stream *cs, struct stream *strm)
{
	cs->app = &strm->obj_type;
	cs->endp->flags &= ~CS_EP_ORPHAN;
	if (cs->endp->flags & CS_EP_T_MUX) {
		cs->wait_event.tasklet = tasklet_new();
		if (!cs->wait_event.tasklet)
			return -1;
		cs->wait_event.tasklet->process = cs_conn_io_cb;
		cs->wait_event.tasklet->context = cs;
		cs->wait_event.events = 0;

		cs->ops = &cs_app_conn_ops;
		cs->data_cb = &cs_data_conn_cb;
	}
	else if (cs->endp->flags & CS_EP_T_APPLET) {
		cs->ops = &cs_app_applet_ops;
		cs->data_cb = &cs_data_applet_cb;
	}
	else {
		cs->ops = &cs_app_embedded_ops;
		cs->data_cb = NULL;
	}
	return 0;
}

/* Detaches the conn_stream from the endpoint, if any. For a connecrion, if a
 * mux owns the connection ->detach() callback is called. Otherwise, it means
 * the conn-stream owns the connection. In this case the connection is closed
 * and released. For an applet, the appctx is released. If still allocated, the
 * endpoint is reset and flag as detached. If the app layer is also detached,
 * the conn-stream is released.
 */
static void cs_detach_endp(struct conn_stream **csp)
{
	struct conn_stream *cs = *csp;

	if (!cs)
		return;

	if (!cs->endp)
		goto reset_cs;

	if (cs->endp->flags & CS_EP_T_MUX) {
		struct connection *conn = __cs_conn(cs);
		struct cs_endpoint *endp = cs->endp;

		if (conn->mux) {
			/* TODO: handle unsubscribe for healthchecks too */
			if (cs->wait_event.events != 0)
				conn->mux->unsubscribe(cs, cs->wait_event.events, &cs->wait_event);
			endp->flags |= CS_EP_ORPHAN;
			endp->cs = NULL;
			cs->endp = NULL;
			conn->mux->detach(endp);
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
		struct appctx *appctx = __cs_appctx(cs);

		cs_applet_shut(cs);
		cs->endp->flags |= CS_EP_ORPHAN;
		cs->endp->cs = NULL;
		appctx_free(appctx);
		cs->endp = NULL;
	}

	if (cs->endp) {
		/* the cs is the only one one the endpoint */
		cs->endp->target = NULL;
		cs->endp->ctx = NULL;
		cs->endp->flags &= CS_EP_APP_MASK;
		cs->endp->flags |= CS_EP_DETACHED;
	}

  reset_cs:
	/* FIXME: Rest CS for now but must be reviewed. CS flags are only
	 *        connection related for now but this will evolved
	 */
	cs->flags &= CS_FL_ISBACK;
	if (cs_strm(cs))
		cs->ops = &cs_app_embedded_ops;
	cs->data_cb = NULL;
	cs_free_cond(csp);
}

/* Detaches the conn_stream from the app layer. If there is no endpoint attached
 * to the conn_stream
 */
static void cs_detach_app(struct conn_stream **csp)
{
	struct conn_stream *cs = *csp;

	if (!cs)
		return;

	cs->app = NULL;
	cs->data_cb = NULL;
	sockaddr_free(&cs->src);
	sockaddr_free(&cs->dst);

	if (cs->wait_event.tasklet)
		tasklet_free(cs->wait_event.tasklet);
	cs->wait_event.tasklet = NULL;
	cs->wait_event.events = 0;
	cs_free_cond(csp);
}

/* Destroy the conn_stream. It is detached from its endpoint and its
 * application. After this call, the conn_stream must be considered as released.
 */
void cs_destroy(struct conn_stream *cs)
{
	cs_detach_endp(&cs);
	cs_detach_app(&cs);
	BUG_ON_HOT(cs);
}

/* Resets the conn-stream endpoint. It happens when the app layer want to renew
 * its endpoint. For a connection retry for instance. If a mux or an applet is
 * attached, a new endpoint is created. Returns -1 on error and 0 on sucess.
 *
 * Only CS_EP_ERROR flag is removed on the endpoint. Orther flags are preserved.
 * It is the caller responsibility to remove other flags if needed.
 */
int cs_reset_endp(struct conn_stream *cs)
{
	struct cs_endpoint *new_endp;

	BUG_ON(!cs->app);

	cs->endp->flags &= ~CS_EP_ERROR;
	if (!__cs_endp_target(cs)) {
		/* endpoint not attached or attached to a mux with no
		 * target. Thus the endpoint will not be release but just
		 * reset. The app is still attached, the cs will not be
		 * released.
		 */
		cs_detach_endp(&cs);
		return 0;
	}

	/* allocate the new endpoint first to be able to set error if it
	 * fails */
	new_endp = cs_endpoint_new();
	if (!unlikely(new_endp)) {
		cs->endp->flags |= CS_EP_ERROR;
		return -1;
	}
	new_endp->flags = (cs->endp->flags & CS_EP_APP_MASK);

	/* The app is still attached, the cs will not be released */
	cs_detach_endp(&cs);
	BUG_ON(cs->endp);
	cs->endp = new_endp;
	cs->endp->cs = cs;
	cs->endp->flags |= CS_EP_DETACHED;
	return 0;
}


/* Create an applet to handle a conn-stream as a new appctx. The CS will
 * wake it up every time it is solicited. The appctx must be deleted by the task
 * handler using cs_detach_endp(), possibly from within the function itself.
 * It also pre-initializes the applet's context and returns it (or NULL in case
 * it could not be allocated).
 */
struct appctx *cs_applet_create(struct conn_stream *cs, struct applet *app)
{
	struct appctx *appctx;

	DPRINTF(stderr, "registering handler %p for cs %p (was %p)\n", app, cs, cs_strm_task(cs));

	appctx = appctx_new(app, cs->endp);
	if (!appctx)
		return NULL;
	cs_attach_applet(cs, appctx, appctx);
	appctx->owner = cs;
	appctx->t->nice = __cs_strm(cs)->task->nice;
	cs_cant_get(cs);
	appctx_wakeup(appctx);

	cs->state = CS_ST_RDY;
	return appctx;
}

/* call the applet's release function if any. Needs to be called upon close() */
void cs_applet_shut(struct conn_stream *cs)
{
	struct appctx *appctx = __cs_appctx(cs);

	if (cs->endp->flags & (CS_EP_SHR|CS_EP_SHW))
		return;

	if (appctx->applet->release)
		appctx->applet->release(appctx);

	cs->endp->flags |= CS_EP_SHRR | CS_EP_SHWN;
}

/*
 * This function performs a shutdown-read on a detached conn-stream in a
 * connected or init state (it does nothing for other states). It either shuts
 * the read side or marks itself as closed. The buffer flags are updated to
 * reflect the new state. If the conn-stream has CS_FL_NOHALF, we also
 * forward the close to the write side. The owner task is woken up if it exists.
 */
static void cs_app_shutr(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	cs_rx_shut_blk(cs);
	if (ic->flags & CF_SHUTR)
		return;
	ic->flags |= CF_SHUTR;
	ic->rex = TICK_ETERNITY;

	if (!cs_state_in(cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST))
		return;

	if (cs_oc(cs)->flags & CF_SHUTW) {
		cs->state = CS_ST_DIS;
		__cs_strm(cs)->conn_exp = TICK_ETERNITY;
	}
	else if (cs->flags & CS_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		return cs_app_shutw(cs);
	}

	/* note that if the task exists, it must unregister itself once it runs */
	if (!(cs->flags & CS_FL_DONT_WAKE))
		task_wakeup(cs_strm_task(cs), TASK_WOKEN_IO);
}

/*
 * This function performs a shutdown-write on a detached conn-stream in a
 * connected or init state (it does nothing for other states). It either shuts
 * the write side or marks itself as closed. The buffer flags are updated to
 * reflect the new state. It does also close everything if the CS was marked as
 * being in error state. The owner task is woken up if it exists.
 */
static void cs_app_shutw(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);
	struct channel *oc = cs_oc(cs);

	oc->flags &= ~CF_SHUTW_NOW;
	if (oc->flags & CF_SHUTW)
		return;
	oc->flags |= CF_SHUTW;
	oc->wex = TICK_ETERNITY;
	cs_done_get(cs);

	if (tick_isset(cs->hcto)) {
		ic->rto = cs->hcto;
		ic->rex = tick_add(now_ms, ic->rto);
	}

	switch (cs->state) {
	case CS_ST_RDY:
	case CS_ST_EST:
		/* we have to shut before closing, otherwise some short messages
		 * may never leave the system, especially when there are remaining
		 * unread data in the socket input buffer, or when nolinger is set.
		 * However, if CS_FL_NOLINGER is explicitly set, we know there is
		 * no risk so we close both sides immediately.
		 */
		if (!(cs->endp->flags & CS_EP_ERROR) && !(cs->flags & CS_FL_NOLINGER) &&
		    !(ic->flags & (CF_SHUTR|CF_DONT_READ)))
			return;

		/* fall through */
	case CS_ST_CON:
	case CS_ST_CER:
	case CS_ST_QUE:
	case CS_ST_TAR:
		/* Note that none of these states may happen with applets */
		cs->state = CS_ST_DIS;
		/* fall through */
	default:
		cs->flags &= ~CS_FL_NOLINGER;
		cs_rx_shut_blk(cs);
		ic->flags |= CF_SHUTR;
		ic->rex = TICK_ETERNITY;
		__cs_strm(cs)->conn_exp = TICK_ETERNITY;
	}

	/* note that if the task exists, it must unregister itself once it runs */
	if (!(cs->flags & CS_FL_DONT_WAKE))
		task_wakeup(cs_strm_task(cs), TASK_WOKEN_IO);
}

/* default chk_rcv function for scheduled tasks */
static void cs_app_chk_rcv(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	DPRINTF(stderr, "%s: cs=%p, cs->state=%d ic->flags=%08x oc->flags=%08x\n",
		__FUNCTION__,
		cs, cs->state, ic->flags, cs_oc(cs)->flags);

	if (ic->pipe) {
		/* stop reading */
		cs_rx_room_blk(cs);
	}
	else {
		/* (re)start reading */
		if (!(cs->flags & CS_FL_DONT_WAKE))
			task_wakeup(cs_strm_task(cs), TASK_WOKEN_IO);
	}
}

/* default chk_snd function for scheduled tasks */
static void cs_app_chk_snd(struct conn_stream *cs)
{
	struct channel *oc = cs_oc(cs);

	DPRINTF(stderr, "%s: cs=%p, cs->state=%d ic->flags=%08x oc->flags=%08x\n",
		__FUNCTION__,
		cs, cs->state, cs_ic(cs)->flags, oc->flags);

	if (unlikely(cs->state != CS_ST_EST || (oc->flags & CF_SHUTW)))
		return;

	if (!(cs->endp->flags & CS_EP_WAIT_DATA) ||  /* not waiting for data */
	    channel_is_empty(oc))                  /* called with nothing to send ! */
		return;

	/* Otherwise there are remaining data to be sent in the buffer,
	 * so we tell the handler.
	 */
	cs->endp->flags &= ~CS_EP_WAIT_DATA;
	if (!tick_isset(oc->wex))
		oc->wex = tick_add_ifset(now_ms, oc->wto);

	if (!(cs->flags & CS_FL_DONT_WAKE))
		task_wakeup(cs_strm_task(cs), TASK_WOKEN_IO);
}

/*
 * This function performs a shutdown-read on a conn-stream attached to
 * a connection in a connected or init state (it does nothing for other
 * states). It either shuts the read side or marks itself as closed. The buffer
 * flags are updated to reflect the new state. If the conn-stream has
 * CS_FL_NOHALF, we also forward the close to the write side. If a control
 * layer is defined, then it is supposed to be a socket layer and file
 * descriptors are then shutdown or closed accordingly. The function
 * automatically disables polling if needed.
 */
static void cs_app_shutr_conn(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	BUG_ON(!cs_conn(cs));

	cs_rx_shut_blk(cs);
	if (ic->flags & CF_SHUTR)
		return;
	ic->flags |= CF_SHUTR;
	ic->rex = TICK_ETERNITY;

	if (!cs_state_in(cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST))
		return;

	if (cs_oc(cs)->flags & CF_SHUTW) {
		cs_conn_shut(cs);
		cs->state = CS_ST_DIS;
		__cs_strm(cs)->conn_exp = TICK_ETERNITY;
	}
	else if (cs->flags & CS_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		return cs_app_shutw_conn(cs);
	}
}

/*
 * This function performs a shutdown-write on a conn-stream attached to
 * a connection in a connected or init state (it does nothing for other
 * states). It either shuts the write side or marks itself as closed. The
 * buffer flags are updated to reflect the new state.  It does also close
 * everything if the CS was marked as being in error state. If there is a
 * data-layer shutdown, it is called.
 */
static void cs_app_shutw_conn(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);
	struct channel *oc = cs_oc(cs);

	BUG_ON(!cs_conn(cs));

	oc->flags &= ~CF_SHUTW_NOW;
	if (oc->flags & CF_SHUTW)
		return;
	oc->flags |= CF_SHUTW;
	oc->wex = TICK_ETERNITY;
	cs_done_get(cs);

	if (tick_isset(cs->hcto)) {
		ic->rto = cs->hcto;
		ic->rex = tick_add(now_ms, ic->rto);
	}

	switch (cs->state) {
	case CS_ST_RDY:
	case CS_ST_EST:
		/* we have to shut before closing, otherwise some short messages
		 * may never leave the system, especially when there are remaining
		 * unread data in the socket input buffer, or when nolinger is set.
		 * However, if CS_FL_NOLINGER is explicitly set, we know there is
		 * no risk so we close both sides immediately.
		 */

		if (cs->endp->flags & CS_EP_ERROR) {
			/* quick close, the socket is already shut anyway */
		}
		else if (cs->flags & CS_FL_NOLINGER) {
			/* unclean data-layer shutdown, typically an aborted request
			 * or a forwarded shutdown from a client to a server due to
			 * option abortonclose. No need for the TLS layer to try to
			 * emit a shutdown message.
			 */
			cs_conn_shutw(cs, CO_SHW_SILENT);
		}
		else {
			/* clean data-layer shutdown. This only happens on the
			 * frontend side, or on the backend side when forwarding
			 * a client close in TCP mode or in HTTP TUNNEL mode
			 * while option abortonclose is set. We want the TLS
			 * layer to try to signal it to the peer before we close.
			 */
			cs_conn_shutw(cs, CO_SHW_NORMAL);

			if (!(ic->flags & (CF_SHUTR|CF_DONT_READ)))
				return;
		}

		/* fall through */
	case CS_ST_CON:
		/* we may have to close a pending connection, and mark the
		 * response buffer as shutr
		 */
		cs_conn_shut(cs);
		/* fall through */
	case CS_ST_CER:
	case CS_ST_QUE:
	case CS_ST_TAR:
		cs->state = CS_ST_DIS;
		/* fall through */
	default:
		cs->flags &= ~CS_FL_NOLINGER;
		cs_rx_shut_blk(cs);
		ic->flags |= CF_SHUTR;
		ic->rex = TICK_ETERNITY;
		__cs_strm(cs)->conn_exp = TICK_ETERNITY;
	}
}

/* This function is used for inter-conn-stream calls. It is called by the
 * consumer to inform the producer side that it may be interested in checking
 * for free space in the buffer. Note that it intentionally does not update
 * timeouts, so that we can still check them later at wake-up. This function is
 * dedicated to connection-based conn-streams.
 */
static void cs_app_chk_rcv_conn(struct conn_stream *cs)
{
	BUG_ON(!cs_conn(cs));

	/* (re)start reading */
	if (cs_state_in(cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST))
		tasklet_wakeup(cs->wait_event.tasklet);
}


/* This function is used for inter-conn-stream calls. It is called by the
 * producer to inform the consumer side that it may be interested in checking
 * for data in the buffer. Note that it intentionally does not update timeouts,
 * so that we can still check them later at wake-up.
 */
static void cs_app_chk_snd_conn(struct conn_stream *cs)
{
	struct channel *oc = cs_oc(cs);

	BUG_ON(!cs_conn(cs));

	if (unlikely(!cs_state_in(cs->state, CS_SB_RDY|CS_SB_EST) ||
	    (oc->flags & CF_SHUTW)))
		return;

	if (unlikely(channel_is_empty(oc)))  /* called with nothing to send ! */
		return;

	if (!oc->pipe &&                          /* spliced data wants to be forwarded ASAP */
	    !(cs->endp->flags & CS_EP_WAIT_DATA))       /* not waiting for data */
		return;

	if (!(cs->wait_event.events & SUB_RETRY_SEND) && !channel_is_empty(cs_oc(cs)))
		cs_conn_send(cs);

	if (cs->endp->flags & (CS_EP_ERROR|CS_EP_ERR_PENDING) || cs_is_conn_error(cs)) {
		/* Write error on the file descriptor */
		if (cs->state >= CS_ST_CON)
			cs->endp->flags |= CS_EP_ERROR;
		goto out_wakeup;
	}

	/* OK, so now we know that some data might have been sent, and that we may
	 * have to poll first. We have to do that too if the buffer is not empty.
	 */
	if (channel_is_empty(oc)) {
		/* the connection is established but we can't write. Either the
		 * buffer is empty, or we just refrain from sending because the
		 * ->o limit was reached. Maybe we just wrote the last
		 * chunk and need to close.
		 */
		if (((oc->flags & (CF_SHUTW|CF_AUTO_CLOSE|CF_SHUTW_NOW)) ==
		     (CF_AUTO_CLOSE|CF_SHUTW_NOW)) &&
		    cs_state_in(cs->state, CS_SB_RDY|CS_SB_EST)) {
			cs_shutw(cs);
			goto out_wakeup;
		}

		if ((oc->flags & (CF_SHUTW|CF_SHUTW_NOW)) == 0)
			cs->endp->flags |= CS_EP_WAIT_DATA;
		oc->wex = TICK_ETERNITY;
	}
	else {
		/* Otherwise there are remaining data to be sent in the buffer,
		 * which means we have to poll before doing so.
		 */
		cs->endp->flags &= ~CS_EP_WAIT_DATA;
		if (!tick_isset(oc->wex))
			oc->wex = tick_add_ifset(now_ms, oc->wto);
	}

	if (likely(oc->flags & CF_WRITE_ACTIVITY)) {
		struct channel *ic = cs_ic(cs);

		/* update timeout if we have written something */
		if ((oc->flags & (CF_SHUTW|CF_WRITE_PARTIAL)) == CF_WRITE_PARTIAL &&
		    !channel_is_empty(oc))
			oc->wex = tick_add_ifset(now_ms, oc->wto);

		if (tick_isset(ic->rex) && !(cs->flags & CS_FL_INDEP_STR)) {
			/* Note: to prevent the client from expiring read timeouts
			 * during writes, we refresh it. We only do this if the
			 * interface is not configured for "independent streams",
			 * because for some applications it's better not to do this,
			 * for instance when continuously exchanging small amounts
			 * of data which can full the socket buffers long before a
			 * write timeout is detected.
			 */
			ic->rex = tick_add_ifset(now_ms, ic->rto);
		}
	}

	/* in case of special condition (error, shutdown, end of write...), we
	 * have to notify the task.
	 */
	if (likely((oc->flags & (CF_WRITE_NULL|CF_WRITE_ERROR|CF_SHUTW)) ||
	          ((oc->flags & CF_WAKE_WRITE) &&
	           ((channel_is_empty(oc) && !oc->to_forward) ||
	            !cs_state_in(cs->state, CS_SB_EST))))) {
	out_wakeup:
		if (!(cs->flags & CS_FL_DONT_WAKE))
			task_wakeup(cs_strm_task(cs), TASK_WOKEN_IO);
	}
}

/*
 * This function performs a shutdown-read on a conn-stream attached to an
 * applet in a connected or init state (it does nothing for other states). It
 * either shuts the read side or marks itself as closed. The buffer flags are
 * updated to reflect the new state. If the conn-stream has CS_FL_NOHALF,
 * we also forward the close to the write side. The owner task is woken up if
 * it exists.
 */
static void cs_app_shutr_applet(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	BUG_ON(!cs_appctx(cs));

	cs_rx_shut_blk(cs);
	if (ic->flags & CF_SHUTR)
		return;
	ic->flags |= CF_SHUTR;
	ic->rex = TICK_ETERNITY;

	/* Note: on shutr, we don't call the applet */

	if (!cs_state_in(cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST))
		return;

	if (cs_oc(cs)->flags & CF_SHUTW) {
		cs_applet_shut(cs);
		cs->state = CS_ST_DIS;
		__cs_strm(cs)->conn_exp = TICK_ETERNITY;
	}
	else if (cs->flags & CS_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		return cs_app_shutw_applet(cs);
	}
}

/*
 * This function performs a shutdown-write on a conn-stream attached to an
 * applet in a connected or init state (it does nothing for other states). It
 * either shuts the write side or marks itself as closed. The buffer flags are
 * updated to reflect the new state. It does also close everything if the SI
 * was marked as being in error state. The owner task is woken up if it exists.
 */
static void cs_app_shutw_applet(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);
	struct channel *oc = cs_oc(cs);

	BUG_ON(!cs_appctx(cs));

	oc->flags &= ~CF_SHUTW_NOW;
	if (oc->flags & CF_SHUTW)
		return;
	oc->flags |= CF_SHUTW;
	oc->wex = TICK_ETERNITY;
	cs_done_get(cs);

	if (tick_isset(cs->hcto)) {
		ic->rto = cs->hcto;
		ic->rex = tick_add(now_ms, ic->rto);
	}

	/* on shutw we always wake the applet up */
	appctx_wakeup(__cs_appctx(cs));

	switch (cs->state) {
	case CS_ST_RDY:
	case CS_ST_EST:
		/* we have to shut before closing, otherwise some short messages
		 * may never leave the system, especially when there are remaining
		 * unread data in the socket input buffer, or when nolinger is set.
		 * However, if CS_FL_NOLINGER is explicitly set, we know there is
		 * no risk so we close both sides immediately.
		 */
		if (!(cs->endp->flags & CS_EP_ERROR) && !(cs->flags & CS_FL_NOLINGER) &&
		    !(ic->flags & (CF_SHUTR|CF_DONT_READ)))
			return;

		/* fall through */
	case CS_ST_CON:
	case CS_ST_CER:
	case CS_ST_QUE:
	case CS_ST_TAR:
		/* Note that none of these states may happen with applets */
		cs_applet_shut(cs);
		cs->state = CS_ST_DIS;
		/* fall through */
	default:
		cs->flags &= ~CS_FL_NOLINGER;
		cs_rx_shut_blk(cs);
		ic->flags |= CF_SHUTR;
		ic->rex = TICK_ETERNITY;
		__cs_strm(cs)->conn_exp = TICK_ETERNITY;
	}
}

/* chk_rcv function for applets */
static void cs_app_chk_rcv_applet(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	BUG_ON(!cs_appctx(cs));

	DPRINTF(stderr, "%s: cs=%p, cs->state=%d ic->flags=%08x oc->flags=%08x\n",
		__FUNCTION__,
		cs, cs->state, ic->flags, cs_oc(cs)->flags);

	if (!ic->pipe) {
		/* (re)start reading */
		appctx_wakeup(__cs_appctx(cs));
	}
}

/* chk_snd function for applets */
static void cs_app_chk_snd_applet(struct conn_stream *cs)
{
	struct channel *oc = cs_oc(cs);

	BUG_ON(!cs_appctx(cs));

	DPRINTF(stderr, "%s: cs=%p, cs->state=%d ic->flags=%08x oc->flags=%08x\n",
		__FUNCTION__,
		cs, cs->state, cs_ic(cs)->flags, oc->flags);

	if (unlikely(cs->state != CS_ST_EST || (oc->flags & CF_SHUTW)))
		return;

	/* we only wake the applet up if it was waiting for some data */

	if (!(cs->endp->flags & CS_EP_WAIT_DATA))
		return;

	if (!tick_isset(oc->wex))
		oc->wex = tick_add_ifset(now_ms, oc->wto);

	if (!channel_is_empty(oc)) {
		/* (re)start sending */
		appctx_wakeup(__cs_appctx(cs));
	}
}


/* This function is designed to be called from within the stream handler to
 * update the input channel's expiration timer and the conn-stream's
 * Rx flags based on the channel's flags. It needs to be called only once
 * after the channel's flags have settled down, and before they are cleared,
 * though it doesn't harm to call it as often as desired (it just slightly
 * hurts performance). It must not be called from outside of the stream
 * handler, as what it does will be used to compute the stream task's
 * expiration.
 */
void cs_update_rx(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	if (ic->flags & CF_SHUTR) {
		cs_rx_shut_blk(cs);
		return;
	}

	/* Read not closed, update FD status and timeout for reads */
	if (ic->flags & CF_DONT_READ)
		cs_rx_chan_blk(cs);
	else
		cs_rx_chan_rdy(cs);

	if (!channel_is_empty(ic) || !channel_may_recv(ic)) {
		/* stop reading, imposed by channel's policy or contents */
		cs_rx_room_blk(cs);
	}
	else {
		/* (re)start reading and update timeout. Note: we don't recompute the timeout
		 * every time we get here, otherwise it would risk never to expire. We only
		 * update it if is was not yet set. The stream socket handler will already
		 * have updated it if there has been a completed I/O.
		 */
		cs_rx_room_rdy(cs);
	}
	if (cs->endp->flags & CS_EP_RXBLK_ANY & ~CS_EP_RX_WAIT_EP)
		ic->rex = TICK_ETERNITY;
	else if (!(ic->flags & CF_READ_NOEXP) && !tick_isset(ic->rex))
		ic->rex = tick_add_ifset(now_ms, ic->rto);

	cs_chk_rcv(cs);
}

/* This function is designed to be called from within the stream handler to
 * update the output channel's expiration timer and the conn-stream's
 * Tx flags based on the channel's flags. It needs to be called only once
 * after the channel's flags have settled down, and before they are cleared,
 * though it doesn't harm to call it as often as desired (it just slightly
 * hurts performance). It must not be called from outside of the stream
 * handler, as what it does will be used to compute the stream task's
 * expiration.
 */
void cs_update_tx(struct conn_stream *cs)
{
	struct channel *oc = cs_oc(cs);
	struct channel *ic = cs_ic(cs);

	if (oc->flags & CF_SHUTW)
		return;

	/* Write not closed, update FD status and timeout for writes */
	if (channel_is_empty(oc)) {
		/* stop writing */
		if (!(cs->endp->flags & CS_EP_WAIT_DATA)) {
			if ((oc->flags & CF_SHUTW_NOW) == 0)
				cs->endp->flags |= CS_EP_WAIT_DATA;
			oc->wex = TICK_ETERNITY;
		}
		return;
	}

	/* (re)start writing and update timeout. Note: we don't recompute the timeout
	 * every time we get here, otherwise it would risk never to expire. We only
	 * update it if is was not yet set. The stream socket handler will already
	 * have updated it if there has been a completed I/O.
	 */
	cs->endp->flags &= ~CS_EP_WAIT_DATA;
	if (!tick_isset(oc->wex)) {
		oc->wex = tick_add_ifset(now_ms, oc->wto);
		if (tick_isset(ic->rex) && !(cs->flags & CS_FL_INDEP_STR)) {
			/* Note: depending on the protocol, we don't know if we're waiting
			 * for incoming data or not. So in order to prevent the socket from
			 * expiring read timeouts during writes, we refresh the read timeout,
			 * except if it was already infinite or if we have explicitly setup
			 * independent streams.
			 */
			ic->rex = tick_add_ifset(now_ms, ic->rto);
		}
	}
}

/* This function is the equivalent to cs_update() except that it's
 * designed to be called from outside the stream handlers, typically the lower
 * layers (applets, connections) after I/O completion. After updating the stream
 * interface and timeouts, it will try to forward what can be forwarded, then to
 * wake the associated task up if an important event requires special handling.
 * It may update CS_EP_WAIT_DATA and/or CS_EP_RXBLK_ROOM, that the callers are
 * encouraged to watch to take appropriate action.
 * It should not be called from within the stream itself, cs_update()
 * is designed for this.
 */
static void cs_notify(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);
	struct channel *oc = cs_oc(cs);
	struct conn_stream *cso = cs_opposite(cs);
	struct task *task = cs_strm_task(cs);

	/* process consumer side */
	if (channel_is_empty(oc)) {
		struct connection *conn = cs_conn(cs);

		if (((oc->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW) &&
		    (cs->state == CS_ST_EST) && (!conn || !(conn->flags & (CO_FL_WAIT_XPRT | CO_FL_EARLY_SSL_HS))))
			cs_shutw(cs);
		oc->wex = TICK_ETERNITY;
	}

	/* indicate that we may be waiting for data from the output channel or
	 * we're about to close and can't expect more data if SHUTW_NOW is there.
	 */
	if (!(oc->flags & (CF_SHUTW|CF_SHUTW_NOW)))
		cs->endp->flags |= CS_EP_WAIT_DATA;
	else if ((oc->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW)
		cs->endp->flags &= ~CS_EP_WAIT_DATA;

	/* update OC timeouts and wake the other side up if it's waiting for room */
	if (oc->flags & CF_WRITE_ACTIVITY) {
		if ((oc->flags & (CF_SHUTW|CF_WRITE_PARTIAL)) == CF_WRITE_PARTIAL &&
		    !channel_is_empty(oc))
			if (tick_isset(oc->wex))
				oc->wex = tick_add_ifset(now_ms, oc->wto);

		if (!(cs->flags & CS_FL_INDEP_STR))
			if (tick_isset(ic->rex))
				ic->rex = tick_add_ifset(now_ms, ic->rto);
	}

	if (oc->flags & CF_DONT_READ)
		cs_rx_chan_blk(cso);
	else
		cs_rx_chan_rdy(cso);

	/* Notify the other side when we've injected data into the IC that
	 * needs to be forwarded. We can do fast-forwarding as soon as there
	 * are output data, but we avoid doing this if some of the data are
	 * not yet scheduled for being forwarded, because it is very likely
	 * that it will be done again immediately afterwards once the following
	 * data are parsed (eg: HTTP chunking). We only CS_EP_RXBLK_ROOM once
	 * we've emptied *some* of the output buffer, and not just when there
	 * is available room, because applets are often forced to stop before
	 * the buffer is full. We must not stop based on input data alone because
	 * an HTTP parser might need more data to complete the parsing.
	 */
	if (!channel_is_empty(ic) &&
	    (cso->endp->flags & CS_EP_WAIT_DATA) &&
	    (!(ic->flags & CF_EXPECT_MORE) || c_full(ic) || ci_data(ic) == 0 || ic->pipe)) {
		int new_len, last_len;

		last_len = co_data(ic);
		if (ic->pipe)
			last_len += ic->pipe->data;

		cs_chk_snd(cso);

		new_len = co_data(ic);
		if (ic->pipe)
			new_len += ic->pipe->data;

		/* check if the consumer has freed some space either in the
		 * buffer or in the pipe.
		 */
		if (new_len < last_len)
			cs_rx_room_rdy(cs);
	}

	if (!(ic->flags & CF_DONT_READ))
		cs_rx_chan_rdy(cs);

	cs_chk_rcv(cs);
	cs_chk_rcv(cso);

	if (cs_rx_blocked(cs)) {
		ic->rex = TICK_ETERNITY;
	}
	else if ((ic->flags & (CF_SHUTR|CF_READ_PARTIAL)) == CF_READ_PARTIAL) {
		/* we must re-enable reading if cs_chk_snd() has freed some space */
		if (!(ic->flags & CF_READ_NOEXP) && tick_isset(ic->rex))
			ic->rex = tick_add_ifset(now_ms, ic->rto);
	}

	/* wake the task up only when needed */
	if (/* changes on the production side */
	    (ic->flags & (CF_READ_NULL|CF_READ_ERROR)) ||
	    !cs_state_in(cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST) ||
	    (cs->endp->flags & CS_EP_ERROR) ||
	    ((ic->flags & CF_READ_PARTIAL) &&
	     ((ic->flags & CF_EOI) || !ic->to_forward || cso->state != CS_ST_EST)) ||

	    /* changes on the consumption side */
	    (oc->flags & (CF_WRITE_NULL|CF_WRITE_ERROR)) ||
	    ((oc->flags & CF_WRITE_ACTIVITY) &&
	     ((oc->flags & CF_SHUTW) ||
	      (((oc->flags & CF_WAKE_WRITE) ||
		!(oc->flags & (CF_AUTO_CLOSE|CF_SHUTW_NOW|CF_SHUTW))) &&
	       (cso->state != CS_ST_EST ||
	        (channel_is_empty(oc) && !oc->to_forward)))))) {
		task_wakeup(task, TASK_WOKEN_IO);
	}
	else {
		/* Update expiration date for the task and requeue it */
		task->expire = tick_first((tick_is_expired(task->expire, now_ms) ? 0 : task->expire),
					  tick_first(tick_first(ic->rex, ic->wex),
						     tick_first(oc->rex, oc->wex)));

		task->expire = tick_first(task->expire, ic->analyse_exp);
		task->expire = tick_first(task->expire, oc->analyse_exp);
		task->expire = tick_first(task->expire, __cs_strm(cs)->conn_exp);

		task_queue(task);
	}
	if (ic->flags & CF_READ_ACTIVITY)
		ic->flags &= ~CF_READ_DONTWAIT;
}

/*
 * This function propagates a null read received on a socket-based connection.
 * It updates the conn-stream. If the conn-stream has CS_FL_NOHALF,
 * the close is also forwarded to the write side as an abort.
 */
static void cs_conn_read0(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);
	struct channel *oc = cs_oc(cs);

	BUG_ON(!cs_conn(cs));

	cs_rx_shut_blk(cs);
	if (ic->flags & CF_SHUTR)
		return;
	ic->flags |= CF_SHUTR;
	ic->rex = TICK_ETERNITY;

	if (!cs_state_in(cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST))
		return;

	if (oc->flags & CF_SHUTW)
		goto do_close;

	if (cs->flags & CS_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		/* force flag on ssl to keep stream in cache */
		cs_conn_shutw(cs, CO_SHW_SILENT);
		goto do_close;
	}

	/* otherwise that's just a normal read shutdown */
	return;

 do_close:
	/* OK we completely close the socket here just as if we went through cs_shut[rw]() */
	cs_conn_shut(cs);

	oc->flags &= ~CF_SHUTW_NOW;
	oc->flags |= CF_SHUTW;
	oc->wex = TICK_ETERNITY;

	cs_done_get(cs);

	cs->state = CS_ST_DIS;
	__cs_strm(cs)->conn_exp = TICK_ETERNITY;
	return;
}

/*
 * This is the callback which is called by the connection layer to receive data
 * into the buffer from the connection. It iterates over the mux layer's
 * rcv_buf function.
 */
static int cs_conn_recv(struct conn_stream *cs)
{
	struct connection *conn = __cs_conn(cs);
	struct channel *ic = cs_ic(cs);
	int ret, max, cur_read = 0;
	int read_poll = MAX_READ_POLL_LOOPS;
	int flags = 0;

	/* If not established yet, do nothing. */
	if (cs->state != CS_ST_EST)
		return 0;

	/* If another call to cs_conn_recv() failed, and we subscribed to
	 * recv events already, give up now.
	 */
	if (cs->wait_event.events & SUB_RETRY_RECV)
		return 0;

	/* maybe we were called immediately after an asynchronous shutr */
	if (ic->flags & CF_SHUTR)
		return 1;

	/* we must wait because the mux is not installed yet */
	if (!conn->mux)
		return 0;

	/* stop here if we reached the end of data */
	if (cs->endp->flags & CS_EP_EOS)
		goto end_recv;

	/* stop immediately on errors. Note that we DON'T want to stop on
	 * POLL_ERR, as the poller might report a write error while there
	 * are still data available in the recv buffer. This typically
	 * happens when we send too large a request to a backend server
	 * which rejects it before reading it all.
	 */
	if (!(cs->endp->flags & CS_EP_RCV_MORE)) {
		if (!conn_xprt_ready(conn))
			return 0;
		if (cs->endp->flags & CS_EP_ERROR)
			goto end_recv;
	}

	/* prepare to detect if the mux needs more room */
	cs->endp->flags &= ~CS_EP_WANT_ROOM;

	if ((ic->flags & (CF_STREAMER | CF_STREAMER_FAST)) && !co_data(ic) &&
	    global.tune.idle_timer &&
	    (unsigned short)(now_ms - ic->last_read) >= global.tune.idle_timer) {
		/* The buffer was empty and nothing was transferred for more
		 * than one second. This was caused by a pause and not by
		 * congestion. Reset any streaming mode to reduce latency.
		 */
		ic->xfer_small = 0;
		ic->xfer_large = 0;
		ic->flags &= ~(CF_STREAMER | CF_STREAMER_FAST);
	}

	/* First, let's see if we may splice data across the channel without
	 * using a buffer.
	 */
	if (cs->endp->flags & CS_EP_MAY_SPLICE &&
	    (ic->pipe || ic->to_forward >= MIN_SPLICE_FORWARD) &&
	    ic->flags & CF_KERN_SPLICING) {
		if (c_data(ic)) {
			/* We're embarrassed, there are already data pending in
			 * the buffer and we don't want to have them at two
			 * locations at a time. Let's indicate we need some
			 * place and ask the consumer to hurry.
			 */
			flags |= CO_RFL_BUF_FLUSH;
			goto abort_splice;
		}

		if (unlikely(ic->pipe == NULL)) {
			if (pipes_used >= global.maxpipes || !(ic->pipe = get_pipe())) {
				ic->flags &= ~CF_KERN_SPLICING;
				goto abort_splice;
			}
		}

		ret = conn->mux->rcv_pipe(cs, ic->pipe, ic->to_forward);
		if (ret < 0) {
			/* splice not supported on this end, let's disable it */
			ic->flags &= ~CF_KERN_SPLICING;
			goto abort_splice;
		}

		if (ret > 0) {
			if (ic->to_forward != CHN_INFINITE_FORWARD)
				ic->to_forward -= ret;
			ic->total += ret;
			cur_read += ret;
			ic->flags |= CF_READ_PARTIAL;
		}

		if (cs->endp->flags & (CS_EP_EOS|CS_EP_ERROR))
			goto end_recv;

		if (conn->flags & CO_FL_WAIT_ROOM) {
			/* the pipe is full or we have read enough data that it
			 * could soon be full. Let's stop before needing to poll.
			 */
			cs_rx_room_blk(cs);
			goto done_recv;
		}

		/* splice not possible (anymore), let's go on on standard copy */
	}

 abort_splice:
	if (ic->pipe && unlikely(!ic->pipe->data)) {
		put_pipe(ic->pipe);
		ic->pipe = NULL;
	}

	if (ic->pipe && ic->to_forward && !(flags & CO_RFL_BUF_FLUSH) && cs->endp->flags & CS_EP_MAY_SPLICE) {
		/* don't break splicing by reading, but still call rcv_buf()
		 * to pass the flag.
		 */
		goto done_recv;
	}

	/* now we'll need a input buffer for the stream */
	if (!cs_alloc_ibuf(cs, &(__cs_strm(cs)->buffer_wait)))
		goto end_recv;

	/* For an HTX stream, if the buffer is stuck (no output data with some
	 * input data) and if the HTX message is fragmented or if its free space
	 * wraps, we force an HTX deframentation. It is a way to have a
	 * contiguous free space nad to let the mux to copy as much data as
	 * possible.
	 *
	 * NOTE: A possible optim may be to let the mux decides if defrag is
	 *       required or not, depending on amount of data to be xferred.
	 */
	if (IS_HTX_STRM(__cs_strm(cs)) && !co_data(ic)) {
		struct htx *htx = htxbuf(&ic->buf);

		if (htx_is_not_empty(htx) && ((htx->flags & HTX_FL_FRAGMENTED) || htx_space_wraps(htx)))
			htx_defrag(htx, NULL, 0);
	}

	/* Instruct the mux it must subscribed for read events */
	flags |= ((!conn_is_back(conn) && (__cs_strm(cs)->be->options & PR_O_ABRT_CLOSE)) ? CO_RFL_KEEP_RECV : 0);

	/* Important note : if we're called with POLL_IN|POLL_HUP, it means the read polling
	 * was enabled, which implies that the recv buffer was not full. So we have a guarantee
	 * that if such an event is not handled above in splice, it will be handled here by
	 * recv().
	 */
	while ((cs->endp->flags & CS_EP_RCV_MORE) ||
	       (!(conn->flags & CO_FL_HANDSHAKE) &&
	       (!(cs->endp->flags & (CS_EP_ERROR|CS_EP_EOS))) && !(ic->flags & CF_SHUTR))) {
		int cur_flags = flags;

		/* Compute transient CO_RFL_* flags */
		if (co_data(ic)) {
			cur_flags |= (CO_RFL_BUF_WET | CO_RFL_BUF_NOT_STUCK);
		}

		/* <max> may be null. This is the mux responsibility to set
		 * CS_EP_RCV_MORE on the CS if more space is needed.
		 */
		max = channel_recv_max(ic);
		ret = conn->mux->rcv_buf(cs, &ic->buf, max, cur_flags);

		if (cs->endp->flags & CS_EP_WANT_ROOM) {
			/* CS_EP_WANT_ROOM must not be reported if the channel's
			 * buffer is empty.
			 */
			BUG_ON(c_empty(ic));

			cs_rx_room_blk(cs);
			/* Add READ_PARTIAL because some data are pending but
			 * cannot be xferred to the channel
			 */
			ic->flags |= CF_READ_PARTIAL;
		}

		if (ret <= 0) {
			/* if we refrained from reading because we asked for a
			 * flush to satisfy rcv_pipe(), we must not subscribe
			 * and instead report that there's not enough room
			 * here to proceed.
			 */
			if (flags & CO_RFL_BUF_FLUSH)
				cs_rx_room_blk(cs);
			break;
		}

		cur_read += ret;

		/* if we're allowed to directly forward data, we must update ->o */
		if (ic->to_forward && !(ic->flags & (CF_SHUTW|CF_SHUTW_NOW))) {
			unsigned long fwd = ret;
			if (ic->to_forward != CHN_INFINITE_FORWARD) {
				if (fwd > ic->to_forward)
					fwd = ic->to_forward;
				ic->to_forward -= fwd;
			}
			c_adv(ic, fwd);
		}

		ic->flags |= CF_READ_PARTIAL;
		ic->total += ret;

		/* End-of-input reached, we can leave. In this case, it is
		 * important to break the loop to not block the CS because of
		 * the channel's policies.This way, we are still able to receive
		 * shutdowns.
		 */
		if (cs->endp->flags & CS_EP_EOI)
			break;

		if ((ic->flags & CF_READ_DONTWAIT) || --read_poll <= 0) {
			/* we're stopped by the channel's policy */
			cs_rx_chan_blk(cs);
			break;
		}

		/* if too many bytes were missing from last read, it means that
		 * it's pointless trying to read again because the system does
		 * not have them in buffers.
		 */
		if (ret < max) {
			/* if a streamer has read few data, it may be because we
			 * have exhausted system buffers. It's not worth trying
			 * again.
			 */
			if (ic->flags & CF_STREAMER) {
				/* we're stopped by the channel's policy */
				cs_rx_chan_blk(cs);
				break;
			}

			/* if we read a large block smaller than what we requested,
			 * it's almost certain we'll never get anything more.
			 */
			if (ret >= global.tune.recv_enough) {
				/* we're stopped by the channel's policy */
				cs_rx_chan_blk(cs);
				break;
			}
		}

		/* if we are waiting for more space, don't try to read more data
		 * right now.
		 */
		if (cs_rx_blocked(cs))
			break;
	} /* while !flags */

 done_recv:
	if (cur_read) {
		if ((ic->flags & (CF_STREAMER | CF_STREAMER_FAST)) &&
		    (cur_read <= ic->buf.size / 2)) {
			ic->xfer_large = 0;
			ic->xfer_small++;
			if (ic->xfer_small >= 3) {
				/* we have read less than half of the buffer in
				 * one pass, and this happened at least 3 times.
				 * This is definitely not a streamer.
				 */
				ic->flags &= ~(CF_STREAMER | CF_STREAMER_FAST);
			}
			else if (ic->xfer_small >= 2) {
				/* if the buffer has been at least half full twice,
				 * we receive faster than we send, so at least it
				 * is not a "fast streamer".
				 */
				ic->flags &= ~CF_STREAMER_FAST;
			}
		}
		else if (!(ic->flags & CF_STREAMER_FAST) &&
			 (cur_read >= ic->buf.size - global.tune.maxrewrite)) {
			/* we read a full buffer at once */
			ic->xfer_small = 0;
			ic->xfer_large++;
			if (ic->xfer_large >= 3) {
				/* we call this buffer a fast streamer if it manages
				 * to be filled in one call 3 consecutive times.
				 */
				ic->flags |= (CF_STREAMER | CF_STREAMER_FAST);
			}
		}
		else {
			ic->xfer_small = 0;
			ic->xfer_large = 0;
		}
		ic->last_read = now_ms;
	}

 end_recv:
	ret = (cur_read != 0);

	/* Report EOI on the channel if it was reached from the mux point of
	 * view. */
	if ((cs->endp->flags & CS_EP_EOI) && !(ic->flags & CF_EOI)) {
		ic->flags |= (CF_EOI|CF_READ_PARTIAL);
		ret = 1;
	}

	if (cs->endp->flags & CS_EP_ERROR)
		ret = 1;
	else if (cs->endp->flags & CS_EP_EOS) {
		/* we received a shutdown */
		ic->flags |= CF_READ_NULL;
		if (ic->flags & CF_AUTO_CLOSE)
			channel_shutw_now(ic);
		cs_conn_read0(cs);
		ret = 1;
	}
	else if (!cs_rx_blocked(cs)) {
		/* Subscribe to receive events if we're blocking on I/O */
		conn->mux->subscribe(cs, SUB_RETRY_RECV, &cs->wait_event);
		cs_rx_endp_done(cs);
	} else {
		cs_rx_endp_more(cs);
		ret = 1;
	}
	return ret;
}

/* This tries to perform a synchronous receive on the conn-stream to
 * try to collect last arrived data. In practice it's only implemented on
 * conn_streams. Returns 0 if nothing was done, non-zero if new data or a
 * shutdown were collected. This may result on some delayed receive calls
 * to be programmed and performed later, though it doesn't provide any
 * such guarantee.
 */
int cs_conn_sync_recv(struct conn_stream *cs)
{
	if (!cs_state_in(cs->state, CS_SB_RDY|CS_SB_EST))
		return 0;

	if (!cs_conn_mux(cs))
		return 0; // only conn_streams are supported

	if (cs->wait_event.events & SUB_RETRY_RECV)
		return 0; // already subscribed

	if (!cs_rx_endp_ready(cs) || cs_rx_blocked(cs))
		return 0; // already failed

	return cs_conn_recv(cs);
}

/*
 * This function is called to send buffer data to a stream socket.
 * It calls the mux layer's snd_buf function. It relies on the
 * caller to commit polling changes. The caller should check conn->flags
 * for errors.
 */
static int cs_conn_send(struct conn_stream *cs)
{
	struct connection *conn = __cs_conn(cs);
	struct stream *s = __cs_strm(cs);
	struct channel *oc = cs_oc(cs);
	int ret;
	int did_send = 0;

	if (cs->endp->flags & (CS_EP_ERROR|CS_EP_ERR_PENDING) || cs_is_conn_error(cs)) {
		/* We're probably there because the tasklet was woken up,
		 * but process_stream() ran before, detected there were an
		 * error and put the CS back to CS_ST_TAR. There's still
		 * CO_FL_ERROR on the connection but we don't want to add
		 * CS_EP_ERROR back, so give up
		 */
		if (cs->state < CS_ST_CON)
			return 0;
		cs->endp->flags |= CS_EP_ERROR;
		return 1;
	}

	/* We're already waiting to be able to send, give up */
	if (cs->wait_event.events & SUB_RETRY_SEND)
		return 0;

	/* we might have been called just after an asynchronous shutw */
	if (oc->flags & CF_SHUTW)
		return 1;

	/* we must wait because the mux is not installed yet */
	if (!conn->mux)
		return 0;

	if (oc->pipe && conn->xprt->snd_pipe && conn->mux->snd_pipe) {
		ret = conn->mux->snd_pipe(cs, oc->pipe);
		if (ret > 0)
			did_send = 1;

		if (!oc->pipe->data) {
			put_pipe(oc->pipe);
			oc->pipe = NULL;
		}

		if (oc->pipe)
			goto end;
	}

	/* At this point, the pipe is empty, but we may still have data pending
	 * in the normal buffer.
	 */
	if (co_data(oc)) {
		/* when we're here, we already know that there is no spliced
		 * data left, and that there are sendable buffered data.
		 */

		/* check if we want to inform the kernel that we're interested in
		 * sending more data after this call. We want this if :
		 *  - we're about to close after this last send and want to merge
		 *    the ongoing FIN with the last segment.
		 *  - we know we can't send everything at once and must get back
		 *    here because of unaligned data
		 *  - there is still a finite amount of data to forward
		 * The test is arranged so that the most common case does only 2
		 * tests.
		 */
		unsigned int send_flag = 0;

		if ((!(oc->flags & (CF_NEVER_WAIT|CF_SEND_DONTWAIT)) &&
		     ((oc->to_forward && oc->to_forward != CHN_INFINITE_FORWARD) ||
		      (oc->flags & CF_EXPECT_MORE) ||
		      (IS_HTX_STRM(s) &&
		       (!(oc->flags & (CF_EOI|CF_SHUTR)) && htx_expect_more(htxbuf(&oc->buf)))))) ||
		    ((oc->flags & CF_ISRESP) &&
		     ((oc->flags & (CF_AUTO_CLOSE|CF_SHUTW_NOW)) == (CF_AUTO_CLOSE|CF_SHUTW_NOW))))
			send_flag |= CO_SFL_MSG_MORE;

		if (oc->flags & CF_STREAMER)
			send_flag |= CO_SFL_STREAMER;

		if (s->txn && s->txn->flags & TX_L7_RETRY && !b_data(&s->txn->l7_buffer)) {
			/* If we want to be able to do L7 retries, copy
			 * the data we're about to send, so that we are able
			 * to resend them if needed
			 */
			/* Try to allocate a buffer if we had none.
			 * If it fails, the next test will just
			 * disable the l7 retries by setting
			 * l7_conn_retries to 0.
			 */
			if (s->txn->req.msg_state != HTTP_MSG_DONE)
				s->txn->flags &= ~TX_L7_RETRY;
			else {
				if (b_alloc(&s->txn->l7_buffer) == NULL)
					s->txn->flags &= ~TX_L7_RETRY;
				else {
					memcpy(b_orig(&s->txn->l7_buffer),
					       b_orig(&oc->buf),
					       b_size(&oc->buf));
					s->txn->l7_buffer.head = co_data(oc);
					b_add(&s->txn->l7_buffer, co_data(oc));
				}

			}
		}

		ret = conn->mux->snd_buf(cs, &oc->buf, co_data(oc), send_flag);
		if (ret > 0) {
			did_send = 1;
			c_rew(oc, ret);
			c_realign_if_empty(oc);

			if (!co_data(oc)) {
				/* Always clear both flags once everything has been sent, they're one-shot */
				oc->flags &= ~(CF_EXPECT_MORE | CF_SEND_DONTWAIT);
			}
			/* if some data remain in the buffer, it's only because the
			 * system buffers are full, we will try next time.
			 */
		}
	}

 end:
	if (did_send) {
		oc->flags |= CF_WRITE_PARTIAL | CF_WROTE_DATA;
		if (cs->state == CS_ST_CON)
			cs->state = CS_ST_RDY;

		cs_rx_room_rdy(cs_opposite(cs));
	}

	if (cs->endp->flags & (CS_EP_ERROR|CS_EP_ERR_PENDING)) {
		cs->endp->flags |= CS_EP_ERROR;
		return 1;
	}

	/* We couldn't send all of our data, let the mux know we'd like to send more */
	if (!channel_is_empty(oc))
		conn->mux->subscribe(cs, SUB_RETRY_SEND, &cs->wait_event);
	return did_send;
}

/* perform a synchronous send() for the conn-stream. The CF_WRITE_NULL and
 * CF_WRITE_PARTIAL flags are cleared prior to the attempt, and will possibly
 * be updated in case of success.
 */
void cs_conn_sync_send(struct conn_stream *cs)
{
	struct channel *oc = cs_oc(cs);

	oc->flags &= ~(CF_WRITE_NULL|CF_WRITE_PARTIAL);

	if (oc->flags & CF_SHUTW)
		return;

	if (channel_is_empty(oc))
		return;

	if (!cs_state_in(cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST))
		return;

	if (!cs_conn_mux(cs))
		return;

	cs_conn_send(cs);
}

/* Called by I/O handlers after completion.. It propagates
 * connection flags to the conn-stream, updates the stream (which may or
 * may not take this opportunity to try to forward data), then update the
 * connection's polling based on the channels and conn-stream's final
 * states. The function always returns 0.
 */
static int cs_conn_process(struct conn_stream *cs)
{
	struct connection *conn = __cs_conn(cs);
	struct channel *ic = cs_ic(cs);
	struct channel *oc = cs_oc(cs);

	BUG_ON(!conn);

	/* If we have data to send, try it now */
	if (!channel_is_empty(oc) && !(cs->wait_event.events & SUB_RETRY_SEND))
		cs_conn_send(cs);

	/* First step, report to the conn-stream what was detected at the
	 * connection layer : errors and connection establishment.
	 * Only add CS_EP_ERROR if we're connected, or we're attempting to
	 * connect, we may get there because we got woken up, but only run
	 * after process_stream() noticed there were an error, and decided
	 * to retry to connect, the connection may still have CO_FL_ERROR,
	 * and we don't want to add CS_EP_ERROR back
	 *
	 * Note: This test is only required because cs_conn_process is also the SI
	 *       wake callback. Otherwise cs_conn_recv()/cs_conn_send() already take
	 *       care of it.
	 */

	if (cs->state >= CS_ST_CON) {
		if (cs_is_conn_error(cs))
			cs->endp->flags |= CS_EP_ERROR;
	}

	/* If we had early data, and the handshake ended, then
	 * we can remove the flag, and attempt to wake the task up,
	 * in the event there's an analyser waiting for the end of
	 * the handshake.
	 */
	if (!(conn->flags & (CO_FL_WAIT_XPRT | CO_FL_EARLY_SSL_HS)) &&
	    (cs->endp->flags & CS_EP_WAIT_FOR_HS)) {
		cs->endp->flags &= ~CS_EP_WAIT_FOR_HS;
		task_wakeup(cs_strm_task(cs), TASK_WOKEN_MSG);
	}

	if (!cs_state_in(cs->state, CS_SB_EST|CS_SB_DIS|CS_SB_CLO) &&
	    (conn->flags & CO_FL_WAIT_XPRT) == 0) {
		__cs_strm(cs)->conn_exp = TICK_ETERNITY;
		oc->flags |= CF_WRITE_NULL;
		if (cs->state == CS_ST_CON)
			cs->state = CS_ST_RDY;
	}

	/* Report EOS on the channel if it was reached from the mux point of
	 * view.
	 *
	 * Note: This test is only required because cs_conn_process is also the SI
	 *       wake callback. Otherwise cs_conn_recv()/cs_conn_send() already take
	 *       care of it.
	 */
	if (cs->endp->flags & CS_EP_EOS && !(ic->flags & CF_SHUTR)) {
		/* we received a shutdown */
		ic->flags |= CF_READ_NULL;
		if (ic->flags & CF_AUTO_CLOSE)
			channel_shutw_now(ic);
		cs_conn_read0(cs);
	}

	/* Report EOI on the channel if it was reached from the mux point of
	 * view.
	 *
	 * Note: This test is only required because cs_conn_process is also the SI
	 *       wake callback. Otherwise cs_conn_recv()/cs_conn_send() already take
	 *       care of it.
	 */
	if ((cs->endp->flags & CS_EP_EOI) && !(ic->flags & CF_EOI))
		ic->flags |= (CF_EOI|CF_READ_PARTIAL);

	/* Second step : update the conn-stream and channels, try to forward any
	 * pending data, then possibly wake the stream up based on the new
	 * conn-stream status.
	 */
	cs_notify(cs);
	stream_release_buffers(__cs_strm(cs));
	return 0;
}

/* This is the ->process() function for any conn-stream's wait_event task.
 * It's assigned during the conn-stream's initialization, for any type of
 * conn-stream. Thus it is always safe to perform a tasklet_wakeup() on a
 * conn-stream, as the presence of the CS is checked there.
 */
struct task *cs_conn_io_cb(struct task *t, void *ctx, unsigned int state)
{
	struct conn_stream *cs = ctx;
	int ret = 0;

	if (!cs_conn(cs))
		return t;

	if (!(cs->wait_event.events & SUB_RETRY_SEND) && !channel_is_empty(cs_oc(cs)))
		ret = cs_conn_send(cs);
	if (!(cs->wait_event.events & SUB_RETRY_RECV))
		ret |= cs_conn_recv(cs);
	if (ret != 0)
		cs_conn_process(cs);

	stream_release_buffers(__cs_strm(cs));
	return t;
}

/* Callback to be used by applet handlers upon completion. It updates the stream
 * (which may or may not take this opportunity to try to forward data), then
 * may re-enable the applet's based on the channels and conn-stream's final
 * states.
 */
static int cs_applet_process(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	BUG_ON(!cs_appctx(cs));

	/* If the applet wants to write and the channel is closed, it's a
	 * broken pipe and it must be reported.
	 */
	if (!(cs->endp->flags & CS_EP_RX_WAIT_EP) && (ic->flags & CF_SHUTR))
		cs->endp->flags |= CS_EP_ERROR;

	/* automatically mark the applet having data available if it reported
	 * begin blocked by the channel.
	 */
	if (cs_rx_blocked(cs))
		cs_rx_endp_more(cs);

	/* update the conn-stream, channels, and possibly wake the stream up */
	cs_notify(cs);
	stream_release_buffers(__cs_strm(cs));

	/* cs_notify may have passed through chk_snd and released some
	 * RXBLK flags. Process_stream will consider those flags to wake up the
	 * appctx but in the case the task is not in runqueue we may have to
	 * wakeup the appctx immediately.
	 */
	if ((cs_rx_endp_ready(cs) && !cs_rx_blocked(cs)) ||
	    (cs_tx_endp_ready(cs) && !cs_tx_blocked(cs)))
		appctx_wakeup(__cs_appctx(cs));
	return 0;
}
