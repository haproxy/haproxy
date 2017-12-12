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

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <proto/applet.h>
#include <proto/channel.h>
#include <proto/connection.h>
#include <proto/mux_pt.h>
#include <proto/pipe.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

#include <types/pipe.h>

/* socket functions used when running a stream interface as a task */
static void stream_int_shutr(struct stream_interface *si);
static void stream_int_shutw(struct stream_interface *si);
static void stream_int_chk_rcv(struct stream_interface *si);
static void stream_int_chk_snd(struct stream_interface *si);
static void stream_int_shutr_conn(struct stream_interface *si);
static void stream_int_shutw_conn(struct stream_interface *si);
static void stream_int_chk_rcv_conn(struct stream_interface *si);
static void stream_int_chk_snd_conn(struct stream_interface *si);
static void stream_int_shutr_applet(struct stream_interface *si);
static void stream_int_shutw_applet(struct stream_interface *si);
static void stream_int_chk_rcv_applet(struct stream_interface *si);
static void stream_int_chk_snd_applet(struct stream_interface *si);
static void si_cs_recv_cb(struct conn_stream *cs);
static void si_cs_send_cb(struct conn_stream *cs);
static int si_cs_wake_cb(struct conn_stream *cs);
static int si_idle_conn_wake_cb(struct conn_stream *cs);
static void si_idle_conn_null_cb(struct conn_stream *cs);

/* stream-interface operations for embedded tasks */
struct si_ops si_embedded_ops = {
	.chk_rcv = stream_int_chk_rcv,
	.chk_snd = stream_int_chk_snd,
	.shutr   = stream_int_shutr,
	.shutw   = stream_int_shutw,
};

/* stream-interface operations for connections */
struct si_ops si_conn_ops = {
	.update  = stream_int_update_conn,
	.chk_rcv = stream_int_chk_rcv_conn,
	.chk_snd = stream_int_chk_snd_conn,
	.shutr   = stream_int_shutr_conn,
	.shutw   = stream_int_shutw_conn,
};

/* stream-interface operations for connections */
struct si_ops si_applet_ops = {
	.update  = stream_int_update_applet,
	.chk_rcv = stream_int_chk_rcv_applet,
	.chk_snd = stream_int_chk_snd_applet,
	.shutr   = stream_int_shutr_applet,
	.shutw   = stream_int_shutw_applet,
};

struct data_cb si_conn_cb = {
	.recv    = si_cs_recv_cb,
	.send    = si_cs_send_cb,
	.wake    = si_cs_wake_cb,
	.name    = "STRM",
};

struct data_cb si_idle_conn_cb = {
	.recv    = si_idle_conn_null_cb,
	.send    = si_idle_conn_null_cb,
	.wake    = si_idle_conn_wake_cb,
	.name    = "IDLE",
};

/*
 * This function only has to be called once after a wakeup event in case of
 * suspected timeout. It controls the stream interface timeouts and sets
 * si->flags accordingly. It does NOT close anything, as this timeout may
 * be used for any purpose. It returns 1 if the timeout fired, otherwise
 * zero.
 */
int stream_int_check_timeouts(struct stream_interface *si)
{
	if (tick_is_expired(si->exp, now_ms)) {
		si->flags |= SI_FL_EXP;
		return 1;
	}
	return 0;
}

/* to be called only when in SI_ST_DIS with SI_FL_ERR */
void stream_int_report_error(struct stream_interface *si)
{
	if (!si->err_type)
		si->err_type = SI_ET_DATA_ERR;

	si_oc(si)->flags |= CF_WRITE_ERROR;
	si_ic(si)->flags |= CF_READ_ERROR;
}

/*
 * Returns a message to the client ; the connection is shut down for read,
 * and the request is cleared so that no server connection can be initiated.
 * The buffer is marked for read shutdown on the other side to protect the
 * message, and the buffer write is enabled. The message is contained in a
 * "chunk". If it is null, then an empty message is used. The reply buffer does
 * not need to be empty before this, and its contents will not be overwritten.
 * The primary goal of this function is to return error messages to a client.
 */
void stream_int_retnclose(struct stream_interface *si, const struct chunk *msg)
{
	struct channel *ic = si_ic(si);
	struct channel *oc = si_oc(si);

	channel_auto_read(ic);
	channel_abort(ic);
	channel_auto_close(ic);
	channel_erase(ic);
	channel_truncate(oc);

	if (likely(msg && msg->len))
		co_inject(oc, msg->str, msg->len);

	oc->wex = tick_add_ifset(now_ms, oc->wto);
	channel_auto_read(oc);
	channel_auto_close(oc);
	channel_shutr_now(oc);
}

/*
 * This function performs a shutdown-read on a detached stream interface in a
 * connected or init state (it does nothing for other states). It either shuts
 * the read side or marks itself as closed. The buffer flags are updated to
 * reflect the new state. If the stream interface has SI_FL_NOHALF, we also
 * forward the close to the write side. The owner task is woken up if it exists.
 */
static void stream_int_shutr(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);

	ic->flags &= ~CF_SHUTR_NOW;
	if (ic->flags & CF_SHUTR)
		return;
	ic->flags |= CF_SHUTR;
	ic->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return;

	if (si_oc(si)->flags & CF_SHUTW) {
		si->state = SI_ST_DIS;
		si->exp = TICK_ETERNITY;
	}
	else if (si->flags & SI_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		return stream_int_shutw(si);
	}

	/* note that if the task exists, it must unregister itself once it runs */
	if (!(si->flags & SI_FL_DONT_WAKE))
		task_wakeup(si_task(si), TASK_WOKEN_IO);
}

/*
 * This function performs a shutdown-write on a detached stream interface in a
 * connected or init state (it does nothing for other states). It either shuts
 * the write side or marks itself as closed. The buffer flags are updated to
 * reflect the new state. It does also close everything if the SI was marked as
 * being in error state. The owner task is woken up if it exists.
 */
static void stream_int_shutw(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);
	struct channel *oc = si_oc(si);

	oc->flags &= ~CF_SHUTW_NOW;
	if (oc->flags & CF_SHUTW)
		return;
	oc->flags |= CF_SHUTW;
	oc->wex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_DATA;

	if (tick_isset(si->hcto)) {
		ic->rto = si->hcto;
		ic->rex = tick_add(now_ms, ic->rto);
	}

	switch (si->state) {
	case SI_ST_EST:
		/* we have to shut before closing, otherwise some short messages
		 * may never leave the system, especially when there are remaining
		 * unread data in the socket input buffer, or when nolinger is set.
		 * However, if SI_FL_NOLINGER is explicitly set, we know there is
		 * no risk so we close both sides immediately.
		 */
		if (!(si->flags & (SI_FL_ERR | SI_FL_NOLINGER)) &&
		    !(ic->flags & (CF_SHUTR|CF_DONT_READ)))
			return;

		/* fall through */
	case SI_ST_CON:
	case SI_ST_CER:
	case SI_ST_QUE:
	case SI_ST_TAR:
		/* Note that none of these states may happen with applets */
		si->state = SI_ST_DIS;
	default:
		si->flags &= ~(SI_FL_WAIT_ROOM | SI_FL_NOLINGER);
		ic->flags &= ~CF_SHUTR_NOW;
		ic->flags |= CF_SHUTR;
		ic->rex = TICK_ETERNITY;
		si->exp = TICK_ETERNITY;
	}

	/* note that if the task exists, it must unregister itself once it runs */
	if (!(si->flags & SI_FL_DONT_WAKE))
		task_wakeup(si_task(si), TASK_WOKEN_IO);
}

/* default chk_rcv function for scheduled tasks */
static void stream_int_chk_rcv(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);

	DPRINTF(stderr, "%s: si=%p, si->state=%d ic->flags=%08x oc->flags=%08x\n",
		__FUNCTION__,
		si, si->state, ic->flags, si_oc(si)->flags);

	if (unlikely(si->state != SI_ST_EST || (ic->flags & (CF_SHUTR|CF_DONT_READ))))
		return;

	if (!channel_may_recv(ic) || ic->pipe) {
		/* stop reading */
		si->flags |= SI_FL_WAIT_ROOM;
	}
	else {
		/* (re)start reading */
		si->flags &= ~SI_FL_WAIT_ROOM;
		if (!(si->flags & SI_FL_DONT_WAKE))
			task_wakeup(si_task(si), TASK_WOKEN_IO);
	}
}

/* default chk_snd function for scheduled tasks */
static void stream_int_chk_snd(struct stream_interface *si)
{
	struct channel *oc = si_oc(si);

	DPRINTF(stderr, "%s: si=%p, si->state=%d ic->flags=%08x oc->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si_ic(si)->flags, oc->flags);

	if (unlikely(si->state != SI_ST_EST || (oc->flags & CF_SHUTW)))
		return;

	if (!(si->flags & SI_FL_WAIT_DATA) ||        /* not waiting for data */
	    channel_is_empty(oc))           /* called with nothing to send ! */
		return;

	/* Otherwise there are remaining data to be sent in the buffer,
	 * so we tell the handler.
	 */
	si->flags &= ~SI_FL_WAIT_DATA;
	if (!tick_isset(oc->wex))
		oc->wex = tick_add_ifset(now_ms, oc->wto);

	if (!(si->flags & SI_FL_DONT_WAKE))
		task_wakeup(si_task(si), TASK_WOKEN_IO);
}

/* Register an applet to handle a stream_interface as a new appctx. The SI will
 * wake it up everytime it is solicited. The appctx must be deleted by the task
 * handler using si_release_endpoint(), possibly from within the function itself.
 * It also pre-initializes the applet's context and returns it (or NULL in case
 * it could not be allocated).
 */
struct appctx *stream_int_register_handler(struct stream_interface *si, struct applet *app)
{
	struct appctx *appctx;

	DPRINTF(stderr, "registering handler %p for si %p (was %p)\n", app, si, si_task(si));

	appctx = si_alloc_appctx(si, app);
	if (!appctx)
		return NULL;

	si_applet_cant_get(si);
	appctx_wakeup(appctx);
	return si_appctx(si);
}

/* This callback is used to send a valid PROXY protocol line to a socket being
 * established. It returns 0 if it fails in a fatal way or needs to poll to go
 * further, otherwise it returns non-zero and removes itself from the connection's
 * flags (the bit is provided in <flag> by the caller). It is designed to be
 * called by the connection handler and relies on it to commit polling changes.
 * Note that it can emit a PROXY line by relying on the other end's address
 * when the connection is attached to a stream interface, or by resolving the
 * local address otherwise (also called a LOCAL line).
 */
int conn_si_send_proxy(struct connection *conn, unsigned int flag)
{
	/* we might have been called just after an asynchronous shutw */
	if (conn->flags & CO_FL_SOCK_WR_SH)
		goto out_error;

	if (!conn_ctrl_ready(conn))
		goto out_error;

	/* If we have a PROXY line to send, we'll use this to validate the
	 * connection, in which case the connection is validated only once
	 * we've sent the whole proxy line. Otherwise we use connect().
	 */
	while (conn->send_proxy_ofs) {
		struct conn_stream *cs;
		int ret;

		cs = conn->mux_ctx;
		/* The target server expects a PROXY line to be sent first.
		 * If the send_proxy_ofs is negative, it corresponds to the
		 * offset to start sending from then end of the proxy string
		 * (which is recomputed every time since it's constant). If
		 * it is positive, it means we have to send from the start.
		 * We can only send a "normal" PROXY line when the connection
		 * is attached to a stream interface. Otherwise we can only
		 * send a LOCAL line (eg: for use with health checks).
		 */
		if (conn->mux == &mux_pt_ops && cs->data_cb == &si_conn_cb) {
			struct stream_interface *si = cs->data;
			struct conn_stream *remote_cs = objt_cs(si_opposite(si)->end);
			ret = make_proxy_line(trash.str, trash.size, objt_server(conn->target), remote_cs ? remote_cs->conn : NULL);
		}
		else {
			/* The target server expects a LOCAL line to be sent first. Retrieving
			 * local or remote addresses may fail until the connection is established.
			 */
			conn_get_from_addr(conn);
			if (!(conn->flags & CO_FL_ADDR_FROM_SET))
				goto out_wait;

			conn_get_to_addr(conn);
			if (!(conn->flags & CO_FL_ADDR_TO_SET))
				goto out_wait;

			ret = make_proxy_line(trash.str, trash.size, objt_server(conn->target), conn);
		}

		if (!ret)
			goto out_error;

		if (conn->send_proxy_ofs > 0)
			conn->send_proxy_ofs = -ret; /* first call */

		/* we have to send trash from (ret+sp for -sp bytes). If the
		 * data layer has a pending write, we'll also set MSG_MORE.
		 */
		ret = conn_sock_send(conn, trash.str + ret + conn->send_proxy_ofs, -conn->send_proxy_ofs,
		                     (conn->flags & CO_FL_XPRT_WR_ENA) ? MSG_MORE : 0);

		if (ret < 0)
			goto out_error;

		conn->send_proxy_ofs += ret; /* becomes zero once complete */
		if (conn->send_proxy_ofs != 0)
			goto out_wait;

		/* OK we've sent the whole line, we're connected */
		break;
	}

	/* The connection is ready now, simply return and let the connection
	 * handler notify upper layers if needed.
	 */
	if (conn->flags & CO_FL_WAIT_L4_CONN)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
	conn->flags &= ~flag;
	return 1;

 out_error:
	/* Write error on the file descriptor */
	conn->flags |= CO_FL_ERROR;
	return 0;

 out_wait:
	__conn_sock_stop_recv(conn);
	return 0;
}


/* Tiny I/O callback called on recv/send I/O events on idle connections.
 * It simply sets the CO_FL_SOCK_RD_SH flag so that si_idle_conn_wake_cb()
 * is notified and can kill the connection.
 */
static void si_idle_conn_null_cb(struct conn_stream *cs)
{
	conn_sock_drain(cs->conn);
}

/* Callback to be used by connection I/O handlers when some activity is detected
 * on an idle server connection. Its main purpose is to kill the connection once
 * a close was detected on it. It returns 0 if it did nothing serious, or -1 if
 * it killed the connection.
 */
static int si_idle_conn_wake_cb(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct stream_interface *si = cs->data;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH) || cs->flags & CS_FL_ERROR) {
		/* warning, we can't do anything on <conn> after this call ! */
		si_release_endpoint(si);
		return -1;
	}
	return 0;
}

/* This function is the equivalent to stream_int_update() except that it's
 * designed to be called from outside the stream handlers, typically the lower
 * layers (applets, connections) after I/O completion. After updating the stream
 * interface and timeouts, it will try to forward what can be forwarded, then to
 * wake the associated task up if an important event requires special handling.
 * It should not be called from within the stream itself, stream_int_update()
 * is designed for this.
 */
void stream_int_notify(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);
	struct channel *oc = si_oc(si);

	/* process consumer side */
	if (channel_is_empty(oc)) {
		struct connection *conn = objt_cs(si->end) ? objt_cs(si->end)->conn : NULL;

		if (((oc->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW) &&
		    (si->state == SI_ST_EST) && (!conn || !(conn->flags & (CO_FL_HANDSHAKE | CO_FL_EARLY_SSL_HS))))
			si_shutw(si);
		oc->wex = TICK_ETERNITY;
	}

	/* indicate that we may be waiting for data from the output channel or
	 * we're about to close and can't expect more data if SHUTW_NOW is there.
	 */
	if ((oc->flags & (CF_SHUTW|CF_SHUTW_NOW)) == 0 && channel_may_recv(oc))
		si->flags |= SI_FL_WAIT_DATA;
	else if ((oc->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW)
		si->flags &= ~SI_FL_WAIT_DATA;

	/* update OC timeouts and wake the other side up if it's waiting for room */
	if (oc->flags & CF_WRITE_ACTIVITY) {
		if ((oc->flags & (CF_SHUTW|CF_WRITE_PARTIAL)) == CF_WRITE_PARTIAL &&
		    !channel_is_empty(oc))
			if (tick_isset(oc->wex))
				oc->wex = tick_add_ifset(now_ms, oc->wto);

		if (!(si->flags & SI_FL_INDEP_STR))
			if (tick_isset(ic->rex))
				ic->rex = tick_add_ifset(now_ms, ic->rto);

		if (likely((oc->flags & (CF_SHUTW|CF_WRITE_PARTIAL|CF_DONT_READ)) == CF_WRITE_PARTIAL &&
			   channel_may_recv(oc) &&
			   (si_opposite(si)->flags & SI_FL_WAIT_ROOM)))
			si_chk_rcv(si_opposite(si));
	}

	/* Notify the other side when we've injected data into the IC that
	 * needs to be forwarded. We can do fast-forwarding as soon as there
	 * are output data, but we avoid doing this if some of the data are
	 * not yet scheduled for being forwarded, because it is very likely
	 * that it will be done again immediately afterwards once the following
	 * data are parsed (eg: HTTP chunking). We only SI_FL_WAIT_ROOM once
	 * we've emptied *some* of the output buffer, and not just when there
	 * is available room, because applets are often forced to stop before
	 * the buffer is full. We must not stop based on input data alone because
	 * an HTTP parser might need more data to complete the parsing.
	 */

	/* ensure it's only set if a write attempt has succeeded */
	ic->flags &= ~CF_WRITE_PARTIAL;

	if (!channel_is_empty(ic) &&
	    (si_opposite(si)->flags & SI_FL_WAIT_DATA) &&
	    (ic->buf->i == 0 || ic->pipe)) {
		int new_len, last_len;

		last_len = ic->buf->o;
		if (ic->pipe)
			last_len += ic->pipe->data;

		si_chk_snd(si_opposite(si));

		new_len = ic->buf->o;
		if (ic->pipe)
			new_len += ic->pipe->data;

		/* check if the consumer has freed some space either in the
		 * buffer or in the pipe.
		 */
		if (channel_may_recv(ic) && new_len < last_len)
			si->flags &= ~SI_FL_WAIT_ROOM;
	}

	if (si->flags & SI_FL_WAIT_ROOM) {
		ic->rex = TICK_ETERNITY;
	}
	else if ((ic->flags & (CF_SHUTR|CF_READ_PARTIAL|CF_DONT_READ)) == CF_READ_PARTIAL &&
		 channel_may_recv(ic)) {
		/* we must re-enable reading if si_chk_snd() has freed some space */
		if (!(ic->flags & CF_READ_NOEXP) && tick_isset(ic->rex))
			ic->rex = tick_add_ifset(now_ms, ic->rto);
	}

	/* wake the task up only when needed */
	if (/* changes on the production side */
	    (ic->flags & (CF_READ_NULL|CF_READ_ERROR)) ||
	    si->state != SI_ST_EST ||
	    (si->flags & SI_FL_ERR) ||
	    ((ic->flags & CF_READ_PARTIAL) &&
	     (!ic->to_forward || si_opposite(si)->state != SI_ST_EST)) ||

	    /* changes on the consumption side */
	    (oc->flags & (CF_WRITE_NULL|CF_WRITE_ERROR)) ||
	    ((oc->flags & (CF_WRITE_ACTIVITY|CF_WRITE_EVENT)) &&
	     ((oc->flags & CF_SHUTW) ||
	      ((oc->flags & CF_WAKE_WRITE) &&
	       (si_opposite(si)->state != SI_ST_EST ||
	        (channel_is_empty(oc) && !oc->to_forward)))))) {
		task_wakeup(si_task(si), TASK_WOKEN_IO);
	}
	if (ic->flags & CF_READ_ACTIVITY)
		ic->flags &= ~CF_READ_DONTWAIT;
}


/* Callback to be used by connection I/O handlers upon completion. It propagates
 * connection flags to the stream interface, updates the stream (which may or
 * may not take this opportunity to try to forward data), then update the
 * connection's polling based on the channels and stream interface's final
 * states. The function always returns 0.
 */
static int si_cs_wake_cb(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct stream_interface *si = cs->data;
	struct channel *ic = si_ic(si);
	struct channel *oc = si_oc(si);

	/* First step, report to the stream-int what was detected at the
	 * connection layer : errors and connection establishment.
	 */
	if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR)
		si->flags |= SI_FL_ERR;

	/* If we had early data, and the handshake ended, then
	 * we can remove the flag, and attempt to wake the task up,
	 * in the event there's an analyser waiting for the end of
	 * the handshake.
	 */
	if ((conn->flags & (CO_FL_EARLY_DATA | CO_FL_EARLY_SSL_HS)) == CO_FL_EARLY_DATA) {
		task_wakeup(si_task(si), TASK_WOKEN_MSG);
	}

	if ((si->state < SI_ST_EST) &&
	    (conn->flags & (CO_FL_CONNECTED | CO_FL_HANDSHAKE)) == CO_FL_CONNECTED) {
		si->exp = TICK_ETERNITY;
		oc->flags |= CF_WRITE_NULL;
	}

	/* Second step : update the stream-int and channels, try to forward any
	 * pending data, then possibly wake the stream up based on the new
	 * stream-int status.
	 */
	stream_int_notify(si);
	channel_release_buffer(ic, &(si_strm(si)->buffer_wait));

	/* Third step : update the connection's polling status based on what
	 * was done above (eg: maybe some buffers got emptied).
	 */
	if (channel_is_empty(oc))
		__cs_stop_send(cs);


	if (si->flags & SI_FL_WAIT_ROOM) {
		__cs_stop_recv(cs);
	}
	else if ((ic->flags & (CF_SHUTR|CF_READ_PARTIAL|CF_DONT_READ)) == CF_READ_PARTIAL &&
		 channel_may_recv(ic)) {
		__cs_want_recv(cs);
	}
	return 0;
}

/*
 * This function is called to send buffer data to a stream socket.
 * It calls the mux layer's snd_buf function. It relies on the
 * caller to commit polling changes. The caller should check conn->flags
 * for errors.
 */
static void si_cs_send(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct stream_interface *si = cs->data;
	struct channel *oc = si_oc(si);
	int ret;

	/* ensure it's only set if a write attempt has succeeded */
	oc->flags &= ~CF_WRITE_PARTIAL;

	if (oc->pipe && conn->xprt->snd_pipe && conn->mux->snd_pipe) {
		ret = conn->mux->snd_pipe(cs, oc->pipe);
		if (ret > 0)
			oc->flags |= CF_WRITE_PARTIAL | CF_WROTE_DATA | CF_WRITE_EVENT;

		if (!oc->pipe->data) {
			put_pipe(oc->pipe);
			oc->pipe = NULL;
		}

		if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR)
			return;
	}

	/* At this point, the pipe is empty, but we may still have data pending
	 * in the normal buffer.
	 */
	if (!oc->buf->o)
		return;

	/* when we're here, we already know that there is no spliced
	 * data left, and that there are sendable buffered data.
	 */
	if (!(conn->flags & (CO_FL_ERROR | CO_FL_SOCK_WR_SH | CO_FL_HANDSHAKE)) &&
	    !(cs->flags & CS_FL_ERROR) && !(oc->flags & CF_SHUTW)) {
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
		      (oc->flags & CF_EXPECT_MORE))) ||
		    ((oc->flags & CF_ISRESP) &&
		     ((oc->flags & (CF_AUTO_CLOSE|CF_SHUTW_NOW)) == (CF_AUTO_CLOSE|CF_SHUTW_NOW))))
			send_flag |= CO_SFL_MSG_MORE;

		if (oc->flags & CF_STREAMER)
			send_flag |= CO_SFL_STREAMER;

		ret = conn->mux->snd_buf(cs, oc->buf, send_flag);
		if (ret > 0) {
			oc->flags |= CF_WRITE_PARTIAL | CF_WROTE_DATA | CF_WRITE_EVENT;

			if (!oc->buf->o) {
				/* Always clear both flags once everything has been sent, they're one-shot */
				oc->flags &= ~(CF_EXPECT_MORE | CF_SEND_DONTWAIT);
			}

			/* if some data remain in the buffer, it's only because the
			 * system buffers are full, we will try next time.
			 */
		}
	}
}

/* This function is designed to be called from within the stream handler to
 * update the channels' expiration timers and the stream interface's flags
 * based on the channels' flags. It needs to be called only once after the
 * channels' flags have settled down, and before they are cleared, though it
 * doesn't harm to call it as often as desired (it just slightly hurts
 * performance). It must not be called from outside of the stream handler,
 * as what it does will be used to compute the stream task's expiration.
 */
void stream_int_update(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);
	struct channel *oc = si_oc(si);

	if (!(ic->flags & CF_SHUTR)) {
		/* Read not closed, update FD status and timeout for reads */
		if ((ic->flags & CF_DONT_READ) || !channel_may_recv(ic)) {
			/* stop reading */
			if (!(si->flags & SI_FL_WAIT_ROOM)) {
				if (!(ic->flags & CF_DONT_READ)) /* full */
					si->flags |= SI_FL_WAIT_ROOM;
				ic->rex = TICK_ETERNITY;
			}
		}
		else {
			/* (re)start reading and update timeout. Note: we don't recompute the timeout
			 * everytime we get here, otherwise it would risk never to expire. We only
			 * update it if is was not yet set. The stream socket handler will already
			 * have updated it if there has been a completed I/O.
			 */
			si->flags &= ~SI_FL_WAIT_ROOM;
			if (!(ic->flags & (CF_READ_NOEXP|CF_DONT_READ)) && !tick_isset(ic->rex))
				ic->rex = tick_add_ifset(now_ms, ic->rto);
		}
	}

	if (!(oc->flags & CF_SHUTW)) {
		/* Write not closed, update FD status and timeout for writes */
		if (channel_is_empty(oc)) {
			/* stop writing */
			if (!(si->flags & SI_FL_WAIT_DATA)) {
				if ((oc->flags & CF_SHUTW_NOW) == 0)
					si->flags |= SI_FL_WAIT_DATA;
				oc->wex = TICK_ETERNITY;
			}
		}
		else {
			/* (re)start writing and update timeout. Note: we don't recompute the timeout
			 * everytime we get here, otherwise it would risk never to expire. We only
			 * update it if is was not yet set. The stream socket handler will already
			 * have updated it if there has been a completed I/O.
			 */
			si->flags &= ~SI_FL_WAIT_DATA;
			if (!tick_isset(oc->wex)) {
				oc->wex = tick_add_ifset(now_ms, oc->wto);
				if (tick_isset(ic->rex) && !(si->flags & SI_FL_INDEP_STR)) {
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
	}
}

/* Updates the polling status of a connection outside of the connection handler
 * based on the channel's flags and the stream interface's flags. It needs to be
 * called once after the channels' flags have settled down and the stream has
 * been updated. It is not designed to be called from within the connection
 * handler itself.
 */
void stream_int_update_conn(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);
	struct channel *oc = si_oc(si);
	struct conn_stream *cs = __objt_cs(si->end);

	if (!(ic->flags & CF_SHUTR)) {
		/* Read not closed */
		if ((ic->flags & CF_DONT_READ) || !channel_may_recv(ic))
			__cs_stop_recv(cs);
		else
			__cs_want_recv(cs);
	}

	if (!(oc->flags & CF_SHUTW)) {
		/* Write not closed */
		if (channel_is_empty(oc))
			__cs_stop_send(cs);
		else
			__cs_want_send(cs);
	}

	cs_update_mux_polling(cs);
}

/*
 * This function performs a shutdown-read on a stream interface attached to
 * a connection in a connected or init state (it does nothing for other
 * states). It either shuts the read side or marks itself as closed. The buffer
 * flags are updated to reflect the new state. If the stream interface has
 * SI_FL_NOHALF, we also forward the close to the write side. If a control
 * layer is defined, then it is supposed to be a socket layer and file
 * descriptors are then shutdown or closed accordingly. The function
 * automatically disables polling if needed.
 */
static void stream_int_shutr_conn(struct stream_interface *si)
{
	struct conn_stream *cs = __objt_cs(si->end);
	struct connection *conn = cs->conn;
	struct channel *ic = si_ic(si);

	ic->flags &= ~CF_SHUTR_NOW;
	if (ic->flags & CF_SHUTR)
		return;
	ic->flags |= CF_SHUTR;
	ic->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return;

	if (si_oc(si)->flags & CF_SHUTW) {
		cs_close(cs);
		si->state = SI_ST_DIS;
		si->exp = TICK_ETERNITY;
	}
	else if (si->flags & SI_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		return stream_int_shutw_conn(si);
	}
	else if (conn->ctrl) {
		/* we want the caller to disable polling on this FD */
		cs_stop_recv(cs);
	}
}

/*
 * This function performs a shutdown-write on a stream interface attached to
 * a connection in a connected or init state (it does nothing for other
 * states). It either shuts the write side or marks itself as closed. The
 * buffer flags are updated to reflect the new state.  It does also close
 * everything if the SI was marked as being in error state. If there is a
 * data-layer shutdown, it is called.
 */
static void stream_int_shutw_conn(struct stream_interface *si)
{
	struct conn_stream *cs = __objt_cs(si->end);
	struct connection *conn = cs->conn;
	struct channel *ic = si_ic(si);
	struct channel *oc = si_oc(si);

	oc->flags &= ~CF_SHUTW_NOW;
	if (oc->flags & CF_SHUTW)
		return;
	oc->flags |= CF_SHUTW;
	oc->wex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_DATA;

	if (tick_isset(si->hcto)) {
		ic->rto = si->hcto;
		ic->rex = tick_add(now_ms, ic->rto);
	}

	switch (si->state) {
	case SI_ST_EST:
		/* we have to shut before closing, otherwise some short messages
		 * may never leave the system, especially when there are remaining
		 * unread data in the socket input buffer, or when nolinger is set.
		 * However, if SI_FL_NOLINGER is explicitly set, we know there is
		 * no risk so we close both sides immediately.
		 */
		if (si->flags & SI_FL_ERR) {
			/* quick close, the socket is alredy shut anyway */
		}
		else if (si->flags & SI_FL_NOLINGER) {
			/* unclean data-layer shutdown, typically an aborted request
			 * or a forwarded shutdown from a client to a server due to
			 * option abortonclose. No need for the TLS layer to try to
			 * emit a shutdown message.
			 */
			cs_shutw(cs, CS_SHW_SILENT);
		}
		else {
			/* clean data-layer shutdown. This only happens on the
			 * frontend side, or on the backend side when forwarding
			 * a client close in TCP mode or in HTTP TUNNEL mode
			 * while option abortonclose is set. We want the TLS
			 * layer to try to signal it to the peer before we close.
			 */
			cs_shutw(cs, CS_SHW_NORMAL);

			if (!(ic->flags & (CF_SHUTR|CF_DONT_READ))) {
				/* OK just a shutw, but we want the caller
				 * to disable polling on this FD if exists.
				 */
				conn_cond_update_polling(conn);
				return;
			}
		}

		/* fall through */
	case SI_ST_CON:
		/* we may have to close a pending connection, and mark the
		 * response buffer as shutr
		 */
		cs_close(cs);
		/* fall through */
	case SI_ST_CER:
	case SI_ST_QUE:
	case SI_ST_TAR:
		si->state = SI_ST_DIS;
		/* fall through */
	default:
		si->flags &= ~(SI_FL_WAIT_ROOM | SI_FL_NOLINGER);
		ic->flags &= ~CF_SHUTR_NOW;
		ic->flags |= CF_SHUTR;
		ic->rex = TICK_ETERNITY;
		si->exp = TICK_ETERNITY;
	}
}

/* This function is used for inter-stream-interface calls. It is called by the
 * consumer to inform the producer side that it may be interested in checking
 * for free space in the buffer. Note that it intentionally does not update
 * timeouts, so that we can still check them later at wake-up. This function is
 * dedicated to connection-based stream interfaces.
 */
static void stream_int_chk_rcv_conn(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);
	struct conn_stream *cs = __objt_cs(si->end);

	if (unlikely(si->state > SI_ST_EST || (ic->flags & CF_SHUTR)))
		return;

	if ((ic->flags & CF_DONT_READ) || !channel_may_recv(ic)) {
		/* stop reading */
		if (!(ic->flags & CF_DONT_READ)) /* full */
			si->flags |= SI_FL_WAIT_ROOM;
		__cs_stop_recv(cs);
	}
	else {
		/* (re)start reading */
		si->flags &= ~SI_FL_WAIT_ROOM;
		__cs_want_recv(cs);
	}
	cs_update_mux_polling(cs);
}


/* This function is used for inter-stream-interface calls. It is called by the
 * producer to inform the consumer side that it may be interested in checking
 * for data in the buffer. Note that it intentionally does not update timeouts,
 * so that we can still check them later at wake-up.
 */
static void stream_int_chk_snd_conn(struct stream_interface *si)
{
	struct channel *oc = si_oc(si);
	struct conn_stream *cs = __objt_cs(si->end);

	/* ensure it's only set if a write attempt has succeeded */
	oc->flags &= ~CF_WRITE_PARTIAL;

	if (unlikely(si->state > SI_ST_EST || (oc->flags & CF_SHUTW)))
		return;

	if (unlikely(channel_is_empty(oc)))  /* called with nothing to send ! */
		return;

	if (!oc->pipe &&                          /* spliced data wants to be forwarded ASAP */
	    !(si->flags & SI_FL_WAIT_DATA))       /* not waiting for data */
		return;

	if (cs->flags & CS_FL_DATA_WR_ENA) {
		/* already subscribed to write notifications, will be called
		 * anyway, so let's avoid calling it especially if the reader
		 * is not ready.
		 */
		return;
	}

	__cs_want_send(cs);

	si_cs_send(cs);
	if (cs->flags & CS_FL_ERROR || cs->conn->flags & CO_FL_ERROR) {
		/* Write error on the file descriptor */
		__cs_stop_both(cs);
		si->flags |= SI_FL_ERR;
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
		__cs_stop_send(cs);
		if (((oc->flags & (CF_SHUTW|CF_AUTO_CLOSE|CF_SHUTW_NOW)) ==
		     (CF_AUTO_CLOSE|CF_SHUTW_NOW)) &&
		    (si->state == SI_ST_EST)) {
			si_shutw(si);
			goto out_wakeup;
		}

		if ((oc->flags & (CF_SHUTW|CF_SHUTW_NOW)) == 0)
			si->flags |= SI_FL_WAIT_DATA;
		oc->wex = TICK_ETERNITY;
	}
	else {
		/* Otherwise there are remaining data to be sent in the buffer,
		 * which means we have to poll before doing so.
		 */
		__cs_want_send(cs);
		si->flags &= ~SI_FL_WAIT_DATA;
		if (!tick_isset(oc->wex))
			oc->wex = tick_add_ifset(now_ms, oc->wto);
	}

	if (likely(oc->flags & CF_WRITE_ACTIVITY)) {
		struct channel *ic = si_ic(si);

		/* update timeout if we have written something */
		if ((oc->flags & (CF_SHUTW|CF_WRITE_PARTIAL)) == CF_WRITE_PARTIAL &&
		    !channel_is_empty(oc))
			oc->wex = tick_add_ifset(now_ms, oc->wto);

		if (tick_isset(ic->rex) && !(si->flags & SI_FL_INDEP_STR)) {
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
	            si->state != SI_ST_EST)))) {
	out_wakeup:
		if (!(si->flags & SI_FL_DONT_WAKE))
			task_wakeup(si_task(si), TASK_WOKEN_IO);
	}

	/* commit possible polling changes */
	cs_update_mux_polling(cs);
}

/*
 * This is the callback which is called by the connection layer to receive data
 * into the buffer from the connection. It iterates over the mux layer's
 * rcv_buf function.
 */
static void si_cs_recv_cb(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct stream_interface *si = cs->data;
	struct channel *ic = si_ic(si);
	int ret, max, cur_read;
	int read_poll = MAX_READ_POLL_LOOPS;

	/* stop immediately on errors. Note that we DON'T want to stop on
	 * POLL_ERR, as the poller might report a write error while there
	 * are still data available in the recv buffer. This typically
	 * happens when we send too large a request to a backend server
	 * which rejects it before reading it all.
	 */
	if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR)
		return;

	/* maybe we were called immediately after an asynchronous shutr */
	if (ic->flags & CF_SHUTR)
		return;

	/* stop here if we reached the end of data */
	if (cs->flags & CS_FL_EOS)
		goto out_shutdown_r;

	cur_read = 0;

	if ((ic->flags & (CF_STREAMER | CF_STREAMER_FAST)) && !ic->buf->o &&
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
	if (conn->xprt->rcv_pipe && conn->mux->rcv_pipe &&
	    (ic->pipe || ic->to_forward >= MIN_SPLICE_FORWARD) &&
	    ic->flags & CF_KERN_SPLICING) {
		if (buffer_not_empty(ic->buf)) {
			/* We're embarrassed, there are already data pending in
			 * the buffer and we don't want to have them at two
			 * locations at a time. Let's indicate we need some
			 * place and ask the consumer to hurry.
			 */
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

		if (cs->flags & CS_FL_EOS)
			goto out_shutdown_r;

		if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR)
			return;

		if (conn->flags & CO_FL_WAIT_ROOM) {
			/* the pipe is full or we have read enough data that it
			 * could soon be full. Let's stop before needing to poll.
			 */
			si->flags |= SI_FL_WAIT_ROOM;
			__cs_stop_recv(cs);
		}

		/* splice not possible (anymore), let's go on on standard copy */
	}

 abort_splice:
	if (ic->pipe && unlikely(!ic->pipe->data)) {
		put_pipe(ic->pipe);
		ic->pipe = NULL;
	}

	/* now we'll need a input buffer for the stream */
	if (!channel_alloc_buffer(ic, &(si_strm(si)->buffer_wait))) {
		si->flags |= SI_FL_WAIT_ROOM;
		goto end_recv;
	}

	/* Important note : if we're called with POLL_IN|POLL_HUP, it means the read polling
	 * was enabled, which implies that the recv buffer was not full. So we have a guarantee
	 * that if such an event is not handled above in splice, it will be handled here by
	 * recv().
	 */
	while (!(conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_WAIT_ROOM | CO_FL_HANDSHAKE)) &&
	       !(cs->flags & (CS_FL_ERROR|CS_FL_EOS)) && !(ic->flags & CF_SHUTR)) {
		max = channel_recv_max(ic);

		if (!max) {
			si->flags |= SI_FL_WAIT_ROOM;
			break;
		}

		ret = conn->mux->rcv_buf(cs, ic->buf, max);
		if (cs->flags & CS_FL_RCV_MORE)
			si->flags |= SI_FL_WAIT_ROOM;

		if (ret <= 0)
			break;

		cur_read += ret;

		/* if we're allowed to directly forward data, we must update ->o */
		if (ic->to_forward && !(ic->flags & (CF_SHUTW|CF_SHUTW_NOW))) {
			unsigned long fwd = ret;
			if (ic->to_forward != CHN_INFINITE_FORWARD) {
				if (fwd > ic->to_forward)
					fwd = ic->to_forward;
				ic->to_forward -= fwd;
			}
			b_adv(ic->buf, fwd);
		}

		ic->flags |= CF_READ_PARTIAL;
		ic->total += ret;

		if (!channel_may_recv(ic)) {
			si->flags |= SI_FL_WAIT_ROOM;
			break;
		}

		if ((ic->flags & CF_READ_DONTWAIT) || --read_poll <= 0) {
			/*
			 * This used to be __conn_xprt_done_recv()
			 * This was changed to accomodate with the mux code,
			 * but we may have lost a worthwhile optimization.
			 */
			__cs_stop_recv(cs);
			si->flags |= SI_FL_WAIT_ROOM;
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
			if (ic->flags & CF_STREAMER)
				break;

			/* if we read a large block smaller than what we requested,
			 * it's almost certain we'll never get anything more.
			 */
			if (ret >= global.tune.recv_enough)
				break;
		}
	} /* while !flags */

	if (cur_read) {
		if ((ic->flags & (CF_STREAMER | CF_STREAMER_FAST)) &&
		    (cur_read <= ic->buf->size / 2)) {
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
			 (cur_read >= ic->buf->size - global.tune.maxrewrite)) {
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
	if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR)
		return;

	if (cs->flags & CS_FL_EOS)
		/* connection closed */
		goto out_shutdown_r;

	return;

 out_shutdown_r:
	/* we received a shutdown */
	ic->flags |= CF_READ_NULL;
	if (ic->flags & CF_AUTO_CLOSE)
		channel_shutw_now(ic);
	stream_sock_read0(si);
	return;
}

/*
 * This is the callback which is called by the connection layer to send data
 * from the buffer to the connection. It iterates over the transport layer's
 * snd_buf function.
 */
static void si_cs_send_cb(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct stream_interface *si = cs->data;

	if (conn->flags & CO_FL_ERROR || cs->flags & CS_FL_ERROR)
		return;

	if (conn->flags & CO_FL_HANDSHAKE)
		/* a handshake was requested */
		return;

	/* we might have been called just after an asynchronous shutw */
	if (si_oc(si)->flags & CF_SHUTW)
		return;

	/* OK there are data waiting to be sent */
	si_cs_send(cs);

	/* OK all done */
	return;
}

/*
 * This function propagates a null read received on a socket-based connection.
 * It updates the stream interface. If the stream interface has SI_FL_NOHALF,
 * the close is also forwarded to the write side as an abort.
 */
void stream_sock_read0(struct stream_interface *si)
{
	struct conn_stream *cs = __objt_cs(si->end);
	struct channel *ic = si_ic(si);
	struct channel *oc = si_oc(si);

	ic->flags &= ~CF_SHUTR_NOW;
	if (ic->flags & CF_SHUTR)
		return;
	ic->flags |= CF_SHUTR;
	ic->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return;

	if (oc->flags & CF_SHUTW)
		goto do_close;

	if (si->flags & SI_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		/* force flag on ssl to keep stream in cache */
		cs_shutw(cs, CS_SHW_SILENT);
		goto do_close;
	}

	/* otherwise that's just a normal read shutdown */
	__cs_stop_recv(cs);
	return;

 do_close:
	/* OK we completely close the socket here just as if we went through si_shut[rw]() */
	cs_close(cs);

	oc->flags &= ~CF_SHUTW_NOW;
	oc->flags |= CF_SHUTW;
	oc->wex = TICK_ETERNITY;

	si->flags &= ~(SI_FL_WAIT_DATA | SI_FL_WAIT_ROOM);

	si->state = SI_ST_DIS;
	si->exp = TICK_ETERNITY;
	return;
}

/* Callback to be used by applet handlers upon completion. It updates the stream
 * (which may or may not take this opportunity to try to forward data), then
 * may re-enable the applet's based on the channels and stream interface's final
 * states.
 */
void si_applet_wake_cb(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);

	/* If the applet wants to write and the channel is closed, it's a
	 * broken pipe and it must be reported.
	 */
	if ((si->flags & SI_FL_WANT_PUT) && (ic->flags & CF_SHUTR))
		si->flags |= SI_FL_ERR;

	/* update the stream-int, channels, and possibly wake the stream up */
	stream_int_notify(si);

	/* stream_int_notify may pass throught checksnd and released some
	 * WAIT_ROOM flags. The process_stream will consider those flags
	 * to wakeup the appctx but in the case the task is not in runqueue
	 * we may have to wakeup the appctx immediately.
	 */
	if (!task_in_rq(si_task(si)))
		stream_int_update_applet(si);
}

/* Updates the activity status of an applet outside of the applet handler based
 * on the channel's flags and the stream interface's flags. It needs to be
 * called once after the channels' flags have settled down and the stream has
 * been updated. It is not designed to be called from within the applet handler
 * itself.
 */
void stream_int_update_applet(struct stream_interface *si)
{
	if (((si->flags & (SI_FL_WANT_PUT|SI_FL_WAIT_ROOM)) == SI_FL_WANT_PUT) ||
	    ((si->flags & (SI_FL_WANT_GET|SI_FL_WAIT_DATA)) == SI_FL_WANT_GET))
		appctx_wakeup(si_appctx(si));
}

/*
 * This function performs a shutdown-read on a stream interface attached to an
 * applet in a connected or init state (it does nothing for other states). It
 * either shuts the read side or marks itself as closed. The buffer flags are
 * updated to reflect the new state. If the stream interface has SI_FL_NOHALF,
 * we also forward the close to the write side. The owner task is woken up if
 * it exists.
 */
static void stream_int_shutr_applet(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);

	ic->flags &= ~CF_SHUTR_NOW;
	if (ic->flags & CF_SHUTR)
		return;
	ic->flags |= CF_SHUTR;
	ic->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	/* Note: on shutr, we don't call the applet */

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return;

	if (si_oc(si)->flags & CF_SHUTW) {
		si_applet_release(si);
		si->state = SI_ST_DIS;
		si->exp = TICK_ETERNITY;
	}
	else if (si->flags & SI_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		return stream_int_shutw_applet(si);
	}
}

/*
 * This function performs a shutdown-write on a stream interface attached to an
 * applet in a connected or init state (it does nothing for other states). It
 * either shuts the write side or marks itself as closed. The buffer flags are
 * updated to reflect the new state. It does also close everything if the SI
 * was marked as being in error state. The owner task is woken up if it exists.
 */
static void stream_int_shutw_applet(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);
	struct channel *oc = si_oc(si);

	oc->flags &= ~CF_SHUTW_NOW;
	if (oc->flags & CF_SHUTW)
		return;
	oc->flags |= CF_SHUTW;
	oc->wex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_DATA;

	if (tick_isset(si->hcto)) {
		ic->rto = si->hcto;
		ic->rex = tick_add(now_ms, ic->rto);
	}

	/* on shutw we always wake the applet up */
	appctx_wakeup(si_appctx(si));

	switch (si->state) {
	case SI_ST_EST:
		/* we have to shut before closing, otherwise some short messages
		 * may never leave the system, especially when there are remaining
		 * unread data in the socket input buffer, or when nolinger is set.
		 * However, if SI_FL_NOLINGER is explicitly set, we know there is
		 * no risk so we close both sides immediately.
		 */
		if (!(si->flags & (SI_FL_ERR | SI_FL_NOLINGER)) &&
		    !(ic->flags & (CF_SHUTR|CF_DONT_READ)))
			return;

		/* fall through */
	case SI_ST_CON:
	case SI_ST_CER:
	case SI_ST_QUE:
	case SI_ST_TAR:
		/* Note that none of these states may happen with applets */
		si_applet_release(si);
		si->state = SI_ST_DIS;
	default:
		si->flags &= ~(SI_FL_WAIT_ROOM | SI_FL_NOLINGER);
		ic->flags &= ~CF_SHUTR_NOW;
		ic->flags |= CF_SHUTR;
		ic->rex = TICK_ETERNITY;
		si->exp = TICK_ETERNITY;
	}
}

/* chk_rcv function for applets */
static void stream_int_chk_rcv_applet(struct stream_interface *si)
{
	struct channel *ic = si_ic(si);

	DPRINTF(stderr, "%s: si=%p, si->state=%d ic->flags=%08x oc->flags=%08x\n",
		__FUNCTION__,
		si, si->state, ic->flags, si_oc(si)->flags);

	if (unlikely(si->state != SI_ST_EST || (ic->flags & (CF_SHUTR|CF_DONT_READ))))
		return;
	/* here we only wake the applet up if it was waiting for some room */
	if (!(si->flags & SI_FL_WAIT_ROOM))
		return;

	if (channel_may_recv(ic) && !ic->pipe) {
		/* (re)start reading */
		appctx_wakeup(si_appctx(si));
	}
}

/* chk_snd function for applets */
static void stream_int_chk_snd_applet(struct stream_interface *si)
{
	struct channel *oc = si_oc(si);

	DPRINTF(stderr, "%s: si=%p, si->state=%d ic->flags=%08x oc->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si_ic(si)->flags, oc->flags);

	if (unlikely(si->state != SI_ST_EST || (oc->flags & CF_SHUTW)))
		return;

	/* we only wake the applet up if it was waiting for some data */

	if (!(si->flags & SI_FL_WAIT_DATA))
		return;

	if (!tick_isset(oc->wex))
		oc->wex = tick_add_ifset(now_ms, oc->wto);

	if (!channel_is_empty(oc)) {
		/* (re)start sending */
		appctx_wakeup(si_appctx(si));
	}
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
