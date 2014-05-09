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

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <proto/channel.h>
#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/pipe.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

#include <types/pipe.h>

/* socket functions used when running a stream interface as a task */
static void stream_int_update_embedded(struct stream_interface *si);
static void stream_int_shutr(struct stream_interface *si);
static void stream_int_shutw(struct stream_interface *si);
static void stream_int_chk_rcv(struct stream_interface *si);
static void stream_int_chk_snd(struct stream_interface *si);
static void stream_int_update_conn(struct stream_interface *si);
static void stream_int_shutr_conn(struct stream_interface *si);
static void stream_int_shutw_conn(struct stream_interface *si);
static void stream_int_chk_rcv_conn(struct stream_interface *si);
static void stream_int_chk_snd_conn(struct stream_interface *si);
static void si_conn_recv_cb(struct connection *conn);
static void si_conn_send_cb(struct connection *conn);
static int si_conn_wake_cb(struct connection *conn);
static int si_idle_conn_wake_cb(struct connection *conn);
static void si_idle_conn_null_cb(struct connection *conn);

/* stream-interface operations for embedded tasks */
struct si_ops si_embedded_ops = {
	.update  = stream_int_update_embedded,
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

struct data_cb si_conn_cb = {
	.recv    = si_conn_recv_cb,
	.send    = si_conn_send_cb,
	.wake    = si_conn_wake_cb,
};

struct data_cb si_idle_conn_cb = {
	.recv    = si_idle_conn_null_cb,
	.send    = si_idle_conn_null_cb,
	.wake    = si_idle_conn_wake_cb,
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

	si->ob->flags |= CF_WRITE_ERROR;
	si->ib->flags |= CF_READ_ERROR;
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
	channel_auto_read(si->ib);
	channel_abort(si->ib);
	channel_auto_close(si->ib);
	channel_erase(si->ib);

	bi_erase(si->ob);
	if (likely(msg && msg->len))
		bo_inject(si->ob, msg->str, msg->len);

	si->ob->wex = tick_add_ifset(now_ms, si->ob->wto);
	channel_auto_read(si->ob);
	channel_auto_close(si->ob);
	channel_shutr_now(si->ob);
}

/* default update function for embedded tasks, to be used at the end of the i/o handler */
static void stream_int_update_embedded(struct stream_interface *si)
{
	int old_flags = si->flags;

	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (si->state != SI_ST_EST)
		return;

	if ((si->ob->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW &&
	    channel_is_empty(si->ob))
		si_shutw(si);

	if ((si->ob->flags & (CF_SHUTW|CF_SHUTW_NOW)) == 0 && !channel_full(si->ob))
		si->flags |= SI_FL_WAIT_DATA;

	/* we're almost sure that we need some space if the buffer is not
	 * empty, even if it's not full, because the applets can't fill it.
	 */
	if ((si->ib->flags & (CF_SHUTR|CF_DONT_READ)) == 0 && !channel_is_empty(si->ib))
		si->flags |= SI_FL_WAIT_ROOM;

	if (si->ob->flags & CF_WRITE_ACTIVITY) {
		if (tick_isset(si->ob->wex))
			si->ob->wex = tick_add_ifset(now_ms, si->ob->wto);
	}

	if (si->ib->flags & CF_READ_ACTIVITY ||
	    (si->ob->flags & CF_WRITE_ACTIVITY && !(si->flags & SI_FL_INDEP_STR))) {
		if (tick_isset(si->ib->rex))
			si->ib->rex = tick_add_ifset(now_ms, si->ib->rto);
	}

	/* save flags to detect changes */
	old_flags = si->flags;
	if (likely((si->ob->flags & (CF_SHUTW|CF_WRITE_PARTIAL|CF_DONT_READ)) == CF_WRITE_PARTIAL &&
		   !channel_full(si->ob) &&
		   (si->ob->prod->flags & SI_FL_WAIT_ROOM)))
		si_chk_rcv(si->ob->prod);

	if (((si->ib->flags & CF_READ_PARTIAL) && !channel_is_empty(si->ib)) &&
	    (si->ib->cons->flags & SI_FL_WAIT_DATA)) {
		si_chk_snd(si->ib->cons);
		/* check if the consumer has freed some space */
		if (!channel_full(si->ib))
			si->flags &= ~SI_FL_WAIT_ROOM;
	}

	/* Note that we're trying to wake up in two conditions here :
	 *  - special event, which needs the holder task attention
	 *  - status indicating that the applet can go on working. This
	 *    is rather hard because we might be blocking on output and
	 *    don't want to wake up on input and vice-versa. The idea is
	 *    to only rely on the changes the chk_* might have performed.
	 */
	if (/* check stream interface changes */
	    ((old_flags & ~si->flags) & (SI_FL_WAIT_ROOM|SI_FL_WAIT_DATA)) ||

	    /* changes on the production side */
	    (si->ib->flags & (CF_READ_NULL|CF_READ_ERROR)) ||
	    si->state != SI_ST_EST ||
	    (si->flags & SI_FL_ERR) ||
	    ((si->ib->flags & CF_READ_PARTIAL) &&
	     (!si->ib->to_forward || si->ib->cons->state != SI_ST_EST)) ||

	    /* changes on the consumption side */
	    (si->ob->flags & (CF_WRITE_NULL|CF_WRITE_ERROR)) ||
	    ((si->ob->flags & CF_WRITE_ACTIVITY) &&
	     ((si->ob->flags & CF_SHUTW) ||
	      ((si->ob->flags & CF_WAKE_WRITE) &&
	       (si->ob->prod->state != SI_ST_EST ||
	        (channel_is_empty(si->ob) && !si->ob->to_forward)))))) {
		if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
			task_wakeup(si->owner, TASK_WOKEN_IO);
	}
	if (si->ib->flags & CF_READ_ACTIVITY)
		si->ib->flags &= ~CF_READ_DONTWAIT;
}

/*
 * This function performs a shutdown-read on a stream interface attached to an
 * applet in a connected or init state (it does nothing for other states). It
 * either shuts the read side or marks itself as closed. The buffer flags are
 * updated to reflect the new state. If the stream interface has SI_FL_NOHALF,
 * we also forward the close to the write side. The owner task is woken up if
 * it exists.
 */
static void stream_int_shutr(struct stream_interface *si)
{
	si->ib->flags &= ~CF_SHUTR_NOW;
	if (si->ib->flags & CF_SHUTR)
		return;
	si->ib->flags |= CF_SHUTR;
	si->ib->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return;

	if (si->ob->flags & CF_SHUTW) {
		si->state = SI_ST_DIS;
		si->exp = TICK_ETERNITY;
		si_applet_release(si);
	}
	else if (si->flags & SI_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		return stream_int_shutw(si);
	}

	/* note that if the task exists, it must unregister itself once it runs */
	if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
		task_wakeup(si->owner, TASK_WOKEN_IO);
}

/*
 * This function performs a shutdown-write on a stream interface attached to an
 * applet in a connected or init state (it does nothing for other states). It
 * either shuts the write side or marks itself as closed. The buffer flags are
 * updated to reflect the new state. It does also close everything if the SI
 * was marked as being in error state. The owner task is woken up if it exists.
 */
static void stream_int_shutw(struct stream_interface *si)
{
	si->ob->flags &= ~CF_SHUTW_NOW;
	if (si->ob->flags & CF_SHUTW)
		return;
	si->ob->flags |= CF_SHUTW;
	si->ob->wex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_DATA;

	switch (si->state) {
	case SI_ST_EST:
		/* we have to shut before closing, otherwise some short messages
		 * may never leave the system, especially when there are remaining
		 * unread data in the socket input buffer, or when nolinger is set.
		 * However, if SI_FL_NOLINGER is explicitly set, we know there is
		 * no risk so we close both sides immediately.
		 */
		if (!(si->flags & (SI_FL_ERR | SI_FL_NOLINGER)) &&
		    !(si->ib->flags & (CF_SHUTR|CF_DONT_READ)))
			return;

		/* fall through */
	case SI_ST_CON:
	case SI_ST_CER:
	case SI_ST_QUE:
	case SI_ST_TAR:
		/* Note that none of these states may happen with applets */
		si->state = SI_ST_DIS;
		si_applet_release(si);
	default:
		si->flags &= ~(SI_FL_WAIT_ROOM | SI_FL_NOLINGER);
		si->ib->flags &= ~CF_SHUTR_NOW;
		si->ib->flags |= CF_SHUTR;
		si->ib->rex = TICK_ETERNITY;
		si->exp = TICK_ETERNITY;
	}

	/* note that if the task exists, it must unregister itself once it runs */
	if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
		task_wakeup(si->owner, TASK_WOKEN_IO);
}

/* default chk_rcv function for scheduled tasks */
static void stream_int_chk_rcv(struct stream_interface *si)
{
	struct channel *ib = si->ib;

	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (unlikely(si->state != SI_ST_EST || (ib->flags & (CF_SHUTR|CF_DONT_READ))))
		return;

	if (channel_full(ib)) {
		/* stop reading */
		si->flags |= SI_FL_WAIT_ROOM;
	}
	else {
		/* (re)start reading */
		si->flags &= ~SI_FL_WAIT_ROOM;
		if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
			task_wakeup(si->owner, TASK_WOKEN_IO);
	}
}

/* default chk_snd function for scheduled tasks */
static void stream_int_chk_snd(struct stream_interface *si)
{
	struct channel *ob = si->ob;

	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (unlikely(si->state != SI_ST_EST || (si->ob->flags & CF_SHUTW)))
		return;

	if (!(si->flags & SI_FL_WAIT_DATA) ||        /* not waiting for data */
	    channel_is_empty(ob))           /* called with nothing to send ! */
		return;

	/* Otherwise there are remaining data to be sent in the buffer,
	 * so we tell the handler.
	 */
	si->flags &= ~SI_FL_WAIT_DATA;
	if (!tick_isset(ob->wex))
		ob->wex = tick_add_ifset(now_ms, ob->wto);

	if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
		task_wakeup(si->owner, TASK_WOKEN_IO);
}

/* Register an applet to handle a stream_interface as part of the
 * stream interface's owner task. The SI will wake it up everytime it
 * is solicited.  The task's processing function must call the applet's
 * function before returning. It must be deleted by the task handler
 * using stream_int_unregister_handler(), possibly from within the
 * function itself. It also pre-initializes the applet's context and
 * returns it (or NULL in case it could not be allocated).
 */
struct appctx *stream_int_register_handler(struct stream_interface *si, struct si_applet *app)
{
	struct appctx *appctx;

	DPRINTF(stderr, "registering handler %p for si %p (was %p)\n", app, si, si->owner);

	appctx = si_alloc_appctx(si);
	if (!si)
		return NULL;

	appctx_set_applet(appctx, app);
	si->flags |= SI_FL_WAIT_DATA;
	return si_appctx(si);
}

/* Unregister a stream interface handler. This must be called by the handler task
 * itself when it detects that it is in the SI_ST_DIS state.
 */
void stream_int_unregister_handler(struct stream_interface *si)
{
	si_detach(si);
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

	if (!fd_send_ready(conn->t.sock.fd))
		goto out_wait;

	/* If we have a PROXY line to send, we'll use this to validate the
	 * connection, in which case the connection is validated only once
	 * we've sent the whole proxy line. Otherwise we use connect().
	 */
	while (conn->send_proxy_ofs) {
		int ret;

		/* The target server expects a PROXY line to be sent first.
		 * If the send_proxy_ofs is negative, it corresponds to the
		 * offset to start sending from then end of the proxy string
		 * (which is recomputed every time since it's constant). If
		 * it is positive, it means we have to send from the start.
		 * We can only send a "normal" PROXY line when the connection
		 * is attached to a stream interface. Otherwise we can only
		 * send a LOCAL line (eg: for use with health checks).
		 */
		if (conn->data == &si_conn_cb) {
			struct stream_interface *si = conn->owner;
			struct connection *remote = objt_conn(si->ob->prod->end);
			ret = make_proxy_line(trash.str, trash.size, objt_server(conn->target), remote);
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
		ret = send(conn->t.sock.fd, trash.str + ret + conn->send_proxy_ofs, -conn->send_proxy_ofs,
			   (conn->flags & CO_FL_DATA_WR_ENA) ? MSG_MORE : 0);

		if (ret == 0)
			goto out_wait;

		if (ret < 0) {
			if (errno == EAGAIN || errno == ENOTCONN)
				goto out_wait;
			if (errno == EINTR)
				continue;
			conn->flags |= CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			goto out_error;
		}

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
	fd_cant_send(conn->t.sock.fd);
	return 0;
}


/* Tiny I/O callback called on recv/send I/O events on idle connections.
 * It simply sets the CO_FL_SOCK_RD_SH flag so that si_idle_conn_wake_cb()
 * is notified and can kill the connection.
 */
static void si_idle_conn_null_cb(struct connection *conn)
{
	if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH))
		return;

	if (fdtab[conn->t.sock.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) {
		fdtab[conn->t.sock.fd].linger_risk = 0;
		conn->flags |= CO_FL_SOCK_RD_SH;
	}
	else {
		conn_drain(conn);
	}

	/* disable draining if we were called and have no drain function */
	if (!conn->ctrl->drain)
		__conn_data_stop_recv(conn);
}

/* Callback to be used by connection I/O handlers when some activity is detected
 * on an idle server connection. Its main purpose is to kill the connection once
 * a close was detected on it. It returns 0 if it did nothing serious, or -1 if
 * it killed the connection.
 */
static int si_idle_conn_wake_cb(struct connection *conn)
{
	struct stream_interface *si = conn->owner;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH)) {
		/* warning, we can't do anything on <conn> after this call ! */
		conn_force_close(conn);
		conn_free(conn);
		si->end = NULL;
		return -1;
	}
	return 0;
}

/* Callback to be used by connection I/O handlers upon completion. It differs from
 * the update function in that it is designed to be called by lower layers after I/O
 * events have been completed. It will also try to wake the associated task up if
 * an important event requires special handling. It relies on the connection handler
 * to commit any polling updates. The function always returns 0.
 */
static int si_conn_wake_cb(struct connection *conn)
{
	struct stream_interface *si = conn->owner;

	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (conn->flags & CO_FL_ERROR)
		si->flags |= SI_FL_ERR;

	/* check for recent connection establishment */
	if (unlikely(!(conn->flags & (CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN | CO_FL_CONNECTED)))) {
		si->exp = TICK_ETERNITY;
		si->ob->flags |= CF_WRITE_NULL;
	}

	/* process consumer side */
	if (channel_is_empty(si->ob)) {
		if (((si->ob->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW) &&
		    (si->state == SI_ST_EST))
			stream_int_shutw_conn(si);
		__conn_data_stop_send(conn);
		si->ob->wex = TICK_ETERNITY;
	}

	if ((si->ob->flags & (CF_SHUTW|CF_SHUTW_NOW)) == 0 && !channel_full(si->ob))
		si->flags |= SI_FL_WAIT_DATA;

	if (si->ob->flags & CF_WRITE_ACTIVITY) {
		/* update timeouts if we have written something */
		if ((si->ob->flags & (CF_SHUTW|CF_WRITE_PARTIAL)) == CF_WRITE_PARTIAL &&
		    !channel_is_empty(si->ob))
			if (tick_isset(si->ob->wex))
				si->ob->wex = tick_add_ifset(now_ms, si->ob->wto);

		if (!(si->flags & SI_FL_INDEP_STR))
			if (tick_isset(si->ib->rex))
				si->ib->rex = tick_add_ifset(now_ms, si->ib->rto);

		if (likely((si->ob->flags & (CF_SHUTW|CF_WRITE_PARTIAL|CF_DONT_READ)) == CF_WRITE_PARTIAL &&
			   !channel_full(si->ob) &&
			   (si->ob->prod->flags & SI_FL_WAIT_ROOM)))
			si_chk_rcv(si->ob->prod);
	}

	/* process producer side.
	 * We might have some data the consumer is waiting for.
	 * We can do fast-forwarding, but we avoid doing this for partial
	 * buffers, because it is very likely that it will be done again
	 * immediately afterwards once the following data is parsed (eg:
	 * HTTP chunking).
	 */
	if (((si->ib->flags & CF_READ_PARTIAL) && !channel_is_empty(si->ib)) &&
	    (si->ib->pipe /* always try to send spliced data */ ||
	     (si->ib->buf->i == 0 && (si->ib->cons->flags & SI_FL_WAIT_DATA)))) {
		int last_len = si->ib->pipe ? si->ib->pipe->data : 0;

		si_chk_snd(si->ib->cons);

		/* check if the consumer has freed some space either in the
		 * buffer or in the pipe.
		 */
		if (!channel_full(si->ib) &&
		    (!last_len || !si->ib->pipe || si->ib->pipe->data < last_len))
			si->flags &= ~SI_FL_WAIT_ROOM;
	}

	if (si->flags & SI_FL_WAIT_ROOM) {
		__conn_data_stop_recv(conn);
		si->ib->rex = TICK_ETERNITY;
	}
	else if ((si->ib->flags & (CF_SHUTR|CF_READ_PARTIAL|CF_DONT_READ)) == CF_READ_PARTIAL &&
		 !channel_full(si->ib)) {
		/* we must re-enable reading if si_chk_snd() has freed some space */
		__conn_data_want_recv(conn);
		if (!(si->ib->flags & CF_READ_NOEXP) && tick_isset(si->ib->rex))
			si->ib->rex = tick_add_ifset(now_ms, si->ib->rto);
	}

	/* wake the task up only when needed */
	if (/* changes on the production side */
	    (si->ib->flags & (CF_READ_NULL|CF_READ_ERROR)) ||
	    si->state != SI_ST_EST ||
	    (si->flags & SI_FL_ERR) ||
	    ((si->ib->flags & CF_READ_PARTIAL) &&
	     (!si->ib->to_forward || si->ib->cons->state != SI_ST_EST)) ||

	    /* changes on the consumption side */
	    (si->ob->flags & (CF_WRITE_NULL|CF_WRITE_ERROR)) ||
	    ((si->ob->flags & CF_WRITE_ACTIVITY) &&
	     ((si->ob->flags & CF_SHUTW) ||
	      ((si->ob->flags & CF_WAKE_WRITE) &&
	       (si->ob->prod->state != SI_ST_EST ||
	        (channel_is_empty(si->ob) && !si->ob->to_forward)))))) {
		task_wakeup(si->owner, TASK_WOKEN_IO);
	}
	if (si->ib->flags & CF_READ_ACTIVITY)
		si->ib->flags &= ~CF_READ_DONTWAIT;
	return 0;
}

/*
 * This function is called to send buffer data to a stream socket.
 * It calls the transport layer's snd_buf function. It relies on the
 * caller to commit polling changes. The caller should check conn->flags
 * for errors.
 */
static void si_conn_send(struct connection *conn)
{
	struct stream_interface *si = conn->owner;
	struct channel *chn = si->ob;
	int ret;

	if (chn->pipe && conn->xprt->snd_pipe) {
		ret = conn->xprt->snd_pipe(conn, chn->pipe);
		if (ret > 0)
			chn->flags |= CF_WRITE_PARTIAL;

		if (!chn->pipe->data) {
			put_pipe(chn->pipe);
			chn->pipe = NULL;
		}

		if (conn->flags & CO_FL_ERROR)
			return;
	}

	/* At this point, the pipe is empty, but we may still have data pending
	 * in the normal buffer.
	 */
	if (!chn->buf->o)
		return;

	/* when we're here, we already know that there is no spliced
	 * data left, and that there are sendable buffered data.
	 */
	if (!(conn->flags & (CO_FL_ERROR | CO_FL_SOCK_WR_SH | CO_FL_DATA_WR_SH | CO_FL_WAIT_DATA | CO_FL_HANDSHAKE))) {
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

		if ((!(chn->flags & (CF_NEVER_WAIT|CF_SEND_DONTWAIT)) &&
		     ((chn->to_forward && chn->to_forward != CHN_INFINITE_FORWARD) ||
		      (chn->flags & CF_EXPECT_MORE))) ||
		    ((chn->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW))
			send_flag |= CO_SFL_MSG_MORE;

		if (chn->flags & CF_STREAMER)
			send_flag |= CO_SFL_STREAMER;

		ret = conn->xprt->snd_buf(conn, chn->buf, send_flag);
		if (ret > 0) {
			chn->flags |= CF_WRITE_PARTIAL;

			if (!chn->buf->o) {
				/* Always clear both flags once everything has been sent, they're one-shot */
				chn->flags &= ~(CF_EXPECT_MORE | CF_SEND_DONTWAIT);
			}

			/* if some data remain in the buffer, it's only because the
			 * system buffers are full, we will try next time.
			 */
		}
	}

	return;
}


/* Updates the timers and flags of a stream interface attached to a connection,
 * depending on the buffers' flags. It should only be called once after the
 * buffer flags have settled down, and before they are cleared. It doesn't
 * harm to call it as often as desired (it just slightly hurts performance).
 * It is only meant to be called by upper layers after buffer flags have been
 * manipulated by analysers.
 */
void stream_int_update_conn(struct stream_interface *si)
{
	struct channel *ib = si->ib;
	struct channel *ob = si->ob;
	struct connection *conn = __objt_conn(si->end);

	/* Check if we need to close the read side */
	if (!(ib->flags & CF_SHUTR)) {
		/* Read not closed, update FD status and timeout for reads */
		if ((ib->flags & CF_DONT_READ) || channel_full(ib)) {
			/* stop reading */
			if (!(si->flags & SI_FL_WAIT_ROOM)) {
				if (!(ib->flags & CF_DONT_READ)) /* full */
					si->flags |= SI_FL_WAIT_ROOM;
				conn_data_stop_recv(conn);
				ib->rex = TICK_ETERNITY;
			}
		}
		else {
			/* (re)start reading and update timeout. Note: we don't recompute the timeout
			 * everytime we get here, otherwise it would risk never to expire. We only
			 * update it if is was not yet set. The stream socket handler will already
			 * have updated it if there has been a completed I/O.
			 */
			si->flags &= ~SI_FL_WAIT_ROOM;
			conn_data_want_recv(conn);
			if (!(ib->flags & (CF_READ_NOEXP|CF_DONT_READ)) && !tick_isset(ib->rex))
				ib->rex = tick_add_ifset(now_ms, ib->rto);
		}
	}

	/* Check if we need to close the write side */
	if (!(ob->flags & CF_SHUTW)) {
		/* Write not closed, update FD status and timeout for writes */
		if (channel_is_empty(ob)) {
			/* stop writing */
			if (!(si->flags & SI_FL_WAIT_DATA)) {
				if ((ob->flags & CF_SHUTW_NOW) == 0)
					si->flags |= SI_FL_WAIT_DATA;
				conn_data_stop_send(conn);
				ob->wex = TICK_ETERNITY;
			}
		}
		else {
			/* (re)start writing and update timeout. Note: we don't recompute the timeout
			 * everytime we get here, otherwise it would risk never to expire. We only
			 * update it if is was not yet set. The stream socket handler will already
			 * have updated it if there has been a completed I/O.
			 */
			si->flags &= ~SI_FL_WAIT_DATA;
			conn_data_want_send(conn);
			if (!tick_isset(ob->wex)) {
				ob->wex = tick_add_ifset(now_ms, ob->wto);
				if (tick_isset(ib->rex) && !(si->flags & SI_FL_INDEP_STR)) {
					/* Note: depending on the protocol, we don't know if we're waiting
					 * for incoming data or not. So in order to prevent the socket from
					 * expiring read timeouts during writes, we refresh the read timeout,
					 * except if it was already infinite or if we have explicitly setup
					 * independent streams.
					 */
					ib->rex = tick_add_ifset(now_ms, ib->rto);
				}
			}
		}
	}
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
	struct connection *conn = __objt_conn(si->end);

	si->ib->flags &= ~CF_SHUTR_NOW;
	if (si->ib->flags & CF_SHUTR)
		return;
	si->ib->flags |= CF_SHUTR;
	si->ib->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return;

	if (si->ob->flags & CF_SHUTW) {
		conn_full_close(conn);
		si->state = SI_ST_DIS;
		si->exp = TICK_ETERNITY;
	}
	else if (si->flags & SI_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		return stream_int_shutw_conn(si);
	}
	else if (conn->ctrl) {
		/* we want the caller to disable polling on this FD */
		conn_data_stop_recv(conn);
	}
}

/*
 * This function performs a shutdown-write on a stream interface attached to
 * a connection in a connected or init state (it does nothing for other
 * states). It either shuts the write side or marks itself as closed. The
 * buffer flags are updated to reflect the new state.  It does also close
 * everything if the SI was marked as being in error state. If there is a
 * data-layer shutdown, it is called. If a control layer is defined, then it is
 * supposed to be a socket layer and file descriptors are then shutdown or
 * closed accordingly. The function automatically disables polling if needed.
 * Note: at the moment, we continue to check conn->ctrl eventhough we *know* it
 * is valid. This will help selecting the proper shutdown() and setsockopt()
 * calls if/when we implement remote sockets later.
 */
static void stream_int_shutw_conn(struct stream_interface *si)
{
	struct connection *conn = __objt_conn(si->end);

	si->ob->flags &= ~CF_SHUTW_NOW;
	if (si->ob->flags & CF_SHUTW)
		return;
	si->ob->flags |= CF_SHUTW;
	si->ob->wex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_DATA;

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
			/* unclean data-layer shutdown */
			if (conn->xprt && conn->xprt->shutw)
				conn->xprt->shutw(conn, 0);
		}
		else {
			/* clean data-layer shutdown */
			if (conn->xprt && conn->xprt->shutw)
				conn->xprt->shutw(conn, 1);

			/* If the stream interface is configured to disable half-open
			 * connections, we'll skip the shutdown(), but only if the
			 * read size is already closed. Otherwise we can't support
			 * closed write with pending read (eg: abortonclose while
			 * waiting for the server).
			 */
			if (!(si->flags & SI_FL_NOHALF) || !(si->ib->flags & (CF_SHUTR|CF_DONT_READ))) {
				/* We shutdown transport layer */
				if (conn_ctrl_ready(conn))
					shutdown(conn->t.sock.fd, SHUT_WR);

				if (!(si->ib->flags & (CF_SHUTR|CF_DONT_READ))) {
					/* OK just a shutw, but we want the caller
					 * to disable polling on this FD if exists.
					 */
					if (conn->ctrl)
						conn_data_stop_send(conn);
					return;
				}
			}
		}

		/* fall through */
	case SI_ST_CON:
		/* we may have to close a pending connection, and mark the
		 * response buffer as shutr
		 */
		conn_full_close(conn);
		/* fall through */
	case SI_ST_CER:
	case SI_ST_QUE:
	case SI_ST_TAR:
		si->state = SI_ST_DIS;
		/* fall through */
	default:
		si->flags &= ~(SI_FL_WAIT_ROOM | SI_FL_NOLINGER);
		si->ib->flags &= ~CF_SHUTR_NOW;
		si->ib->flags |= CF_SHUTR;
		si->ib->rex = TICK_ETERNITY;
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
	struct channel *ib = si->ib;
	struct connection *conn = __objt_conn(si->end);

	if (unlikely(si->state > SI_ST_EST || (ib->flags & CF_SHUTR)))
		return;

	conn_refresh_polling_flags(conn);

	if ((ib->flags & CF_DONT_READ) || channel_full(ib)) {
		/* stop reading */
		if (!(ib->flags & CF_DONT_READ)) /* full */
			si->flags |= SI_FL_WAIT_ROOM;
		__conn_data_stop_recv(conn);
	}
	else {
		/* (re)start reading */
		si->flags &= ~SI_FL_WAIT_ROOM;
		__conn_data_want_recv(conn);
	}
	conn_cond_update_data_polling(conn);
}


/* This function is used for inter-stream-interface calls. It is called by the
 * producer to inform the consumer side that it may be interested in checking
 * for data in the buffer. Note that it intentionally does not update timeouts,
 * so that we can still check them later at wake-up.
 */
static void stream_int_chk_snd_conn(struct stream_interface *si)
{
	struct channel *ob = si->ob;
	struct connection *conn = __objt_conn(si->end);

	if (unlikely(si->state > SI_ST_EST || (ob->flags & CF_SHUTW)))
		return;

	if (unlikely(channel_is_empty(ob)))  /* called with nothing to send ! */
		return;

	if (!ob->pipe &&                          /* spliced data wants to be forwarded ASAP */
	    !(si->flags & SI_FL_WAIT_DATA))       /* not waiting for data */
		return;

	if (conn->flags & (CO_FL_DATA_WR_ENA|CO_FL_CURR_WR_ENA)) {
		/* already subscribed to write notifications, will be called
		 * anyway, so let's avoid calling it especially if the reader
		 * is not ready.
		 */
		return;
	}

	/* Before calling the data-level operations, we have to prepare
	 * the polling flags to ensure we properly detect changes.
	 */
	conn_refresh_polling_flags(conn);
	__conn_data_want_send(conn);

	if (!(conn->flags & (CO_FL_HANDSHAKE|CO_FL_WAIT_L4_CONN|CO_FL_WAIT_L6_CONN))) {
		si_conn_send(conn);
		if (conn->flags & CO_FL_ERROR) {
			/* Write error on the file descriptor */
			__conn_data_stop_both(conn);
			si->flags |= SI_FL_ERR;
			goto out_wakeup;
		}
	}

	/* OK, so now we know that some data might have been sent, and that we may
	 * have to poll first. We have to do that too if the buffer is not empty.
	 */
	if (channel_is_empty(ob)) {
		/* the connection is established but we can't write. Either the
		 * buffer is empty, or we just refrain from sending because the
		 * ->o limit was reached. Maybe we just wrote the last
		 * chunk and need to close.
		 */
		__conn_data_stop_send(conn);
		if (((ob->flags & (CF_SHUTW|CF_AUTO_CLOSE|CF_SHUTW_NOW)) ==
		     (CF_AUTO_CLOSE|CF_SHUTW_NOW)) &&
		    (si->state == SI_ST_EST)) {
			si_shutw(si);
			goto out_wakeup;
		}

		if ((ob->flags & (CF_SHUTW|CF_SHUTW_NOW)) == 0)
			si->flags |= SI_FL_WAIT_DATA;
		ob->wex = TICK_ETERNITY;
	}
	else {
		/* Otherwise there are remaining data to be sent in the buffer,
		 * which means we have to poll before doing so.
		 */
		__conn_data_want_send(conn);
		si->flags &= ~SI_FL_WAIT_DATA;
		if (!tick_isset(ob->wex))
			ob->wex = tick_add_ifset(now_ms, ob->wto);
	}

	if (likely(ob->flags & CF_WRITE_ACTIVITY)) {
		/* update timeout if we have written something */
		if ((ob->flags & (CF_SHUTW|CF_WRITE_PARTIAL)) == CF_WRITE_PARTIAL &&
		    !channel_is_empty(ob))
			ob->wex = tick_add_ifset(now_ms, ob->wto);

		if (tick_isset(si->ib->rex) && !(si->flags & SI_FL_INDEP_STR)) {
			/* Note: to prevent the client from expiring read timeouts
			 * during writes, we refresh it. We only do this if the
			 * interface is not configured for "independent streams",
			 * because for some applications it's better not to do this,
			 * for instance when continuously exchanging small amounts
			 * of data which can full the socket buffers long before a
			 * write timeout is detected.
			 */
			si->ib->rex = tick_add_ifset(now_ms, si->ib->rto);
		}
	}

	/* in case of special condition (error, shutdown, end of write...), we
	 * have to notify the task.
	 */
	if (likely((ob->flags & (CF_WRITE_NULL|CF_WRITE_ERROR|CF_SHUTW)) ||
	          ((ob->flags & CF_WAKE_WRITE) &&
	           ((channel_is_empty(si->ob) && !ob->to_forward) ||
	            si->state != SI_ST_EST)))) {
	out_wakeup:
		if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
			task_wakeup(si->owner, TASK_WOKEN_IO);
	}

	/* commit possible polling changes */
	conn_cond_update_polling(conn);
}

/*
 * This is the callback which is called by the connection layer to receive data
 * into the buffer from the connection. It iterates over the transport layer's
 * rcv_buf function.
 */
static void si_conn_recv_cb(struct connection *conn)
{
	struct stream_interface *si = conn->owner;
	struct channel *chn = si->ib;
	int ret, max, cur_read;
	int read_poll = MAX_READ_POLL_LOOPS;

	/* stop immediately on errors. Note that we DON'T want to stop on
	 * POLL_ERR, as the poller might report a write error while there
	 * are still data available in the recv buffer. This typically
	 * happens when we send too large a request to a backend server
	 * which rejects it before reading it all.
	 */
	if (conn->flags & CO_FL_ERROR)
		return;

	/* stop here if we reached the end of data */
	if (conn_data_read0_pending(conn))
		goto out_shutdown_r;

	/* maybe we were called immediately after an asynchronous shutr */
	if (chn->flags & CF_SHUTR)
		return;

	cur_read = 0;

	if ((chn->flags & (CF_STREAMER | CF_STREAMER_FAST)) && !chn->buf->o &&
	    global.tune.idle_timer &&
	    (unsigned short)(now_ms - chn->last_read) >= global.tune.idle_timer) {
		/* The buffer was empty and nothing was transferred for more
		 * than one second. This was caused by a pause and not by
		 * congestion. Reset any streaming mode to reduce latency.
		 */
		chn->xfer_small = 0;
		chn->xfer_large = 0;
		chn->flags &= ~(CF_STREAMER | CF_STREAMER_FAST);
	}

	/* First, let's see if we may splice data across the channel without
	 * using a buffer.
	 */
	if (conn->xprt->rcv_pipe &&
	    (chn->pipe || chn->to_forward >= MIN_SPLICE_FORWARD) &&
	    chn->flags & CF_KERN_SPLICING) {
		if (buffer_not_empty(chn->buf)) {
			/* We're embarrassed, there are already data pending in
			 * the buffer and we don't want to have them at two
			 * locations at a time. Let's indicate we need some
			 * place and ask the consumer to hurry.
			 */
			goto abort_splice;
		}

		if (unlikely(chn->pipe == NULL)) {
			if (pipes_used >= global.maxpipes || !(chn->pipe = get_pipe())) {
				chn->flags &= ~CF_KERN_SPLICING;
				goto abort_splice;
			}
		}

		ret = conn->xprt->rcv_pipe(conn, chn->pipe, chn->to_forward);
		if (ret < 0) {
			/* splice not supported on this end, let's disable it */
			chn->flags &= ~CF_KERN_SPLICING;
			goto abort_splice;
		}

		if (ret > 0) {
			if (chn->to_forward != CHN_INFINITE_FORWARD)
				chn->to_forward -= ret;
			chn->total += ret;
			cur_read += ret;
			chn->flags |= CF_READ_PARTIAL;
		}

		if (conn_data_read0_pending(conn))
			goto out_shutdown_r;

		if (conn->flags & CO_FL_ERROR)
			return;

		if (conn->flags & CO_FL_WAIT_ROOM) {
			/* the pipe is full or we have read enough data that it
			 * could soon be full. Let's stop before needing to poll.
			 */
			si->flags |= SI_FL_WAIT_ROOM;
			__conn_data_stop_recv(conn);
		}

		/* splice not possible (anymore), let's go on on standard copy */
	}

 abort_splice:
	if (chn->pipe && unlikely(!chn->pipe->data)) {
		put_pipe(chn->pipe);
		chn->pipe = NULL;
	}

	/* Important note : if we're called with POLL_IN|POLL_HUP, it means the read polling
	 * was enabled, which implies that the recv buffer was not full. So we have a guarantee
	 * that if such an event is not handled above in splice, it will be handled here by
	 * recv().
	 */
	while (!(conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_DATA_RD_SH | CO_FL_WAIT_ROOM | CO_FL_HANDSHAKE))) {
		max = bi_avail(chn);

		if (!max) {
			si->flags |= SI_FL_WAIT_ROOM;
			break;
		}

		ret = conn->xprt->rcv_buf(conn, chn->buf, max);
		if (ret <= 0)
			break;

		cur_read += ret;

		/* if we're allowed to directly forward data, we must update ->o */
		if (chn->to_forward && !(chn->flags & (CF_SHUTW|CF_SHUTW_NOW))) {
			unsigned long fwd = ret;
			if (chn->to_forward != CHN_INFINITE_FORWARD) {
				if (fwd > chn->to_forward)
					fwd = chn->to_forward;
				chn->to_forward -= fwd;
			}
			b_adv(chn->buf, fwd);
		}

		chn->flags |= CF_READ_PARTIAL;
		chn->total += ret;

		if (channel_full(chn)) {
			si->flags |= SI_FL_WAIT_ROOM;
			break;
		}

		if ((chn->flags & CF_READ_DONTWAIT) || --read_poll <= 0) {
			si->flags |= SI_FL_WAIT_ROOM;
			__conn_data_stop_recv(conn);
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
			if (chn->flags & CF_STREAMER)
				break;

			/* if we read a large block smaller than what we requested,
			 * it's almost certain we'll never get anything more.
			 */
			if (ret >= global.tune.recv_enough)
				break;
		}
	} /* while !flags */

	if (conn->flags & CO_FL_ERROR)
		return;

	if (cur_read) {
		if ((chn->flags & (CF_STREAMER | CF_STREAMER_FAST)) &&
		    (cur_read <= chn->buf->size / 2)) {
			chn->xfer_large = 0;
			chn->xfer_small++;
			if (chn->xfer_small >= 3) {
				/* we have read less than half of the buffer in
				 * one pass, and this happened at least 3 times.
				 * This is definitely not a streamer.
				 */
				chn->flags &= ~(CF_STREAMER | CF_STREAMER_FAST);
			}
			else if (chn->xfer_small >= 2) {
				/* if the buffer has been at least half full twice,
				 * we receive faster than we send, so at least it
				 * is not a "fast streamer".
				 */
				chn->flags &= ~CF_STREAMER_FAST;
			}
		}
		else if (!(chn->flags & CF_STREAMER_FAST) &&
			 (cur_read >= chn->buf->size - global.tune.maxrewrite)) {
			/* we read a full buffer at once */
			chn->xfer_small = 0;
			chn->xfer_large++;
			if (chn->xfer_large >= 3) {
				/* we call this buffer a fast streamer if it manages
				 * to be filled in one call 3 consecutive times.
				 */
				chn->flags |= (CF_STREAMER | CF_STREAMER_FAST);
			}
		}
		else {
			chn->xfer_small = 0;
			chn->xfer_large = 0;
		}
		chn->last_read = now_ms;
	}

	if (conn_data_read0_pending(conn))
		/* connection closed */
		goto out_shutdown_r;

	return;

 out_shutdown_r:
	/* we received a shutdown */
	chn->flags |= CF_READ_NULL;
	if (chn->flags & CF_AUTO_CLOSE)
		channel_shutw_now(chn);
	stream_sock_read0(si);
	conn_data_read0(conn);
	return;
}

/*
 * This is the callback which is called by the connection layer to send data
 * from the buffer to the connection. It iterates over the transport layer's
 * snd_buf function.
 */
static void si_conn_send_cb(struct connection *conn)
{
	struct stream_interface *si = conn->owner;
	struct channel *chn = si->ob;

	if (conn->flags & CO_FL_ERROR)
		return;

	if (conn->flags & CO_FL_HANDSHAKE)
		/* a handshake was requested */
		return;

	/* we might have been called just after an asynchronous shutw */
	if (chn->flags & CF_SHUTW)
		return;

	/* OK there are data waiting to be sent */
	si_conn_send(conn);

	/* OK all done */
	return;
}

/*
 * This function propagates a null read received on a socket-based connection.
 * It updates the stream interface. If the stream interface has SI_FL_NOHALF,
 * the close is also forwarded to the write side as an abort. This function is
 * still socket-specific as it handles a setsockopt() call to set the SO_LINGER
 * state on the socket.
 */
void stream_sock_read0(struct stream_interface *si)
{
	struct connection *conn = __objt_conn(si->end);

	si->ib->flags &= ~CF_SHUTR_NOW;
	if (si->ib->flags & CF_SHUTR)
		return;
	si->ib->flags |= CF_SHUTR;
	si->ib->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return;

	if (si->ob->flags & CF_SHUTW)
		goto do_close;

	if (si->flags & SI_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		/* force flag on ssl to keep session in cache */
		if (conn->xprt->shutw)
			conn->xprt->shutw(conn, 0);
		goto do_close;
	}

	/* otherwise that's just a normal read shutdown */
	if (conn_ctrl_ready(conn))
		fdtab[conn->t.sock.fd].linger_risk = 0;
	__conn_data_stop_recv(conn);
	return;

 do_close:
	/* OK we completely close the socket here just as if we went through si_shut[rw]() */
	conn_full_close(conn);

	si->ib->flags &= ~CF_SHUTR_NOW;
	si->ib->flags |= CF_SHUTR;
	si->ib->rex = TICK_ETERNITY;

	si->ob->flags &= ~CF_SHUTW_NOW;
	si->ob->flags |= CF_SHUTW;
	si->ob->wex = TICK_ETERNITY;

	si->flags &= ~(SI_FL_WAIT_DATA | SI_FL_WAIT_ROOM);

	si->state = SI_ST_DIS;
	si->exp = TICK_ETERNITY;
	return;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
