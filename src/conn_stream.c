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
#include <haproxy/pool.h>
#include <haproxy/stream_interface.h>

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
		cs_applet_release(cs);
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


/* Register an applet to handle a conn-stream as a new appctx. The CS will
 * wake it up every time it is solicited. The appctx must be deleted by the task
 * handler using cs_detach_endp(), possibly from within the function itself.
 * It also pre-initializes the applet's context and returns it (or NULL in case
 * it could not be allocated).
 */
struct appctx *cs_register_applet(struct conn_stream *cs, struct applet *app)
{
	struct appctx *appctx;

	DPRINTF(stderr, "registering handler %p for cs %p (was %p)\n", app, cs, cs_strm_task(cs));

	appctx = appctx_new(app, cs->endp);
	if (!appctx)
		return NULL;
	cs_attach_applet(cs, appctx, appctx);
	appctx->owner = cs;
	appctx->t->nice = __cs_strm(cs)->task->nice;
	si_cant_get(cs->si);
	appctx_wakeup(appctx);
	return appctx;
}

/* call the applet's release function if any. Needs to be called upon close() */
void cs_applet_release(struct conn_stream *cs)
{
	struct appctx *appctx = __cs_appctx(cs);

	if (appctx->applet->release && !cs_state_in(cs->state, CS_SB_DIS|CS_SB_CLO))
		appctx->applet->release(appctx);
}

/*
 * This function performs a shutdown-read on a detached conn-stream in a
 * connected or init state (it does nothing for other states). It either shuts
 * the read side or marks itself as closed. The buffer flags are updated to
 * reflect the new state. If the stream interface has CS_FL_NOHALF, we also
 * forward the close to the write side. The owner task is woken up if it exists.
 */
static void cs_app_shutr(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	si_rx_shut_blk(cs->si);
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
 * reflect the new state. It does also close everything if the SI was marked as
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
	si_done_get(cs->si);

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
		si_rx_shut_blk(cs->si);
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
		si_rx_room_blk(cs->si);
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

	if (!(cs->si->flags & SI_FL_WAIT_DATA) ||  /* not waiting for data */
	    channel_is_empty(oc))                  /* called with nothing to send ! */
		return;

	/* Otherwise there are remaining data to be sent in the buffer,
	 * so we tell the handler.
	 */
	cs->si->flags &= ~SI_FL_WAIT_DATA;
	if (!tick_isset(oc->wex))
		oc->wex = tick_add_ifset(now_ms, oc->wto);

	if (!(cs->flags & CS_FL_DONT_WAKE))
		task_wakeup(cs_strm_task(cs), TASK_WOKEN_IO);
}

/*
 * This function performs a shutdown-read on a conn-stream attached to
 * a connection in a connected or init state (it does nothing for other
 * states). It either shuts the read side or marks itself as closed. The buffer
 * flags are updated to reflect the new state. If the stream interface has
 * CS_FL_NOHALF, we also forward the close to the write side. If a control
 * layer is defined, then it is supposed to be a socket layer and file
 * descriptors are then shutdown or closed accordingly. The function
 * automatically disables polling if needed.
 */
static void cs_app_shutr_conn(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	BUG_ON(!cs_conn(cs));

	si_rx_shut_blk(cs->si);
	if (ic->flags & CF_SHUTR)
		return;
	ic->flags |= CF_SHUTR;
	ic->rex = TICK_ETERNITY;

	if (!cs_state_in(cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST))
		return;

	if (cs_oc(cs)->flags & CF_SHUTW) {
		cs_conn_close(cs);
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
 * everything if the SI was marked as being in error state. If there is a
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
	si_done_get(cs->si);

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
		cs_conn_close(cs);
		/* fall through */
	case CS_ST_CER:
	case CS_ST_QUE:
	case CS_ST_TAR:
		cs->state = CS_ST_DIS;
		/* fall through */
	default:
		cs->flags &= ~CS_FL_NOLINGER;
		si_rx_shut_blk(cs->si);
		ic->flags |= CF_SHUTR;
		ic->rex = TICK_ETERNITY;
		__cs_strm(cs)->conn_exp = TICK_ETERNITY;
	}
}

/* This function is used for inter-conn-stream calls. It is called by the
 * consumer to inform the producer side that it may be interested in checking
 * for free space in the buffer. Note that it intentionally does not update
 * timeouts, so that we can still check them later at wake-up. This function is
 * dedicated to connection-based stream interfaces.
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

	if (unlikely(!cs_state_in(cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST) ||
	    (oc->flags & CF_SHUTW)))
		return;

	if (unlikely(channel_is_empty(oc)))  /* called with nothing to send ! */
		return;

	if (!oc->pipe &&                          /* spliced data wants to be forwarded ASAP */
	    !(cs->si->flags & SI_FL_WAIT_DATA))       /* not waiting for data */
		return;

	if (!(cs->wait_event.events & SUB_RETRY_SEND) && !channel_is_empty(cs_oc(cs)))
		si_cs_send(cs);

	if (cs->endp->flags & (CS_EP_ERROR|CS_EP_ERR_PENDING) || si_is_conn_error(cs->si)) {
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
			cs->si->flags |= SI_FL_WAIT_DATA;
		oc->wex = TICK_ETERNITY;
	}
	else {
		/* Otherwise there are remaining data to be sent in the buffer,
		 * which means we have to poll before doing so.
		 */
		cs->si->flags &= ~SI_FL_WAIT_DATA;
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
 * updated to reflect the new state. If the stream interface has CS_FL_NOHALF,
 * we also forward the close to the write side. The owner task is woken up if
 * it exists.
 */
static void cs_app_shutr_applet(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	BUG_ON(!cs_appctx(cs));

	si_rx_shut_blk(cs->si);
	if (ic->flags & CF_SHUTR)
		return;
	ic->flags |= CF_SHUTR;
	ic->rex = TICK_ETERNITY;

	/* Note: on shutr, we don't call the applet */

	if (!cs_state_in(cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST))
		return;

	if (cs_oc(cs)->flags & CF_SHUTW) {
		cs_applet_release(cs);
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
	si_done_get(cs->si);

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
		cs_applet_release(cs);
		cs->state = CS_ST_DIS;
		/* fall through */
	default:
		cs->flags &= ~CS_FL_NOLINGER;
		si_rx_shut_blk(cs->si);
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

	if (!(cs->si->flags & SI_FL_WAIT_DATA))
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
		si_rx_shut_blk(cs->si);
		return;
	}

	/* Read not closed, update FD status and timeout for reads */
	if (ic->flags & CF_DONT_READ)
		si_rx_chan_blk(cs->si);
	else
		si_rx_chan_rdy(cs->si);

	if (!channel_is_empty(ic) || !channel_may_recv(ic)) {
		/* stop reading, imposed by channel's policy or contents */
		si_rx_room_blk(cs->si);
	}
	else {
		/* (re)start reading and update timeout. Note: we don't recompute the timeout
		 * every time we get here, otherwise it would risk never to expire. We only
		 * update it if is was not yet set. The stream socket handler will already
		 * have updated it if there has been a completed I/O.
		 */
		si_rx_room_rdy(cs->si);
	}
	if (cs->si->flags & SI_FL_RXBLK_ANY & ~SI_FL_RX_WAIT_EP)
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
		if (!(cs->si->flags & SI_FL_WAIT_DATA)) {
			if ((oc->flags & CF_SHUTW_NOW) == 0)
				cs->si->flags |= SI_FL_WAIT_DATA;
			oc->wex = TICK_ETERNITY;
		}
		return;
	}

	/* (re)start writing and update timeout. Note: we don't recompute the timeout
	 * every time we get here, otherwise it would risk never to expire. We only
	 * update it if is was not yet set. The stream socket handler will already
	 * have updated it if there has been a completed I/O.
	 */
	cs->si->flags &= ~SI_FL_WAIT_DATA;
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

/* Updates at once the channel flags, and timers of both conn-streams of a
 * same stream, to complete the work after the analysers, then updates the data
 * layer below. This will ensure that any synchronous update performed at the
 * data layer will be reflected in the channel flags and/or conn-stream.
 * Note that this does not change the conn-stream's current state, though
 * it updates the previous state to the current one.
 */
void cs_update_both(struct conn_stream *csf, struct conn_stream *csb)
{
	struct channel *req = cs_ic(csf);
	struct channel *res = cs_oc(csf);

	req->flags &= ~(CF_READ_NULL|CF_READ_PARTIAL|CF_READ_ATTACHED|CF_WRITE_NULL|CF_WRITE_PARTIAL);
	res->flags &= ~(CF_READ_NULL|CF_READ_PARTIAL|CF_READ_ATTACHED|CF_WRITE_NULL|CF_WRITE_PARTIAL);

	__cs_strm(csb)->prev_conn_state = csb->state;

	/* let's recompute both sides states */
	if (cs_state_in(csf->state, CS_SB_RDY|CS_SB_EST))
		cs_update(csf);

	if (cs_state_in(csb->state, CS_SB_RDY|CS_SB_EST))
		cs_update(csb);

	/* stream ints are processed outside of process_stream() and must be
	 * handled at the latest moment.
	 */
	if (cs_appctx(csf) &&
	    ((si_rx_endp_ready(csf->si) && !si_rx_blocked(csf->si)) ||
	     (si_tx_endp_ready(csf->si) && !si_tx_blocked(csf->si))))
		appctx_wakeup(__cs_appctx(csf));

	if (cs_appctx(csb) &&
	    ((si_rx_endp_ready(csb->si) && !si_rx_blocked(csb->si)) ||
	     (si_tx_endp_ready(csb->si) && !si_tx_blocked(csb->si))))
		appctx_wakeup(__cs_appctx(csb));
}
