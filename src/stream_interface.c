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
#include <proto/frontend.h>
#include <proto/pipe.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

#include <types/pipe.h>

/* socket functions used when running a stream interface as a task */
static void stream_int_update(struct stream_interface *si);
static void stream_int_update_embedded(struct stream_interface *si);
static void stream_int_chk_rcv(struct stream_interface *si);
static void stream_int_chk_snd(struct stream_interface *si);
static void stream_int_update_conn(struct stream_interface *si);
static void stream_int_chk_rcv_conn(struct stream_interface *si);
static void stream_int_chk_snd_conn(struct stream_interface *si);

/* stream-interface operations for embedded tasks */
struct si_ops si_embedded_ops = {
	.update  = stream_int_update_embedded,
	.chk_rcv = stream_int_chk_rcv,
	.chk_snd = stream_int_chk_snd,
};

/* stream-interface operations for external tasks */
struct si_ops si_task_ops = {
	.update  = stream_int_update,
	.chk_rcv = stream_int_chk_rcv,
	.chk_snd = stream_int_chk_snd,
};

/* stream-interface operations for connections */
struct si_ops si_conn_ops = {
	.update  = stream_int_update_conn,
	.chk_rcv = stream_int_chk_rcv_conn,
	.chk_snd = stream_int_chk_snd_conn,
};

struct app_cb si_conn_cb = {
	.recv    = si_conn_recv_cb,
	.send    = si_conn_send_cb,
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

	si->ob->flags |= BF_WRITE_ERROR;
	si->ib->flags |= BF_READ_ERROR;
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
	buffer_auto_read(si->ib);
	buffer_abort(si->ib);
	buffer_auto_close(si->ib);
	buffer_erase(si->ib);

	bi_erase(si->ob);
	if (likely(msg && msg->len))
		bo_inject(si->ob, msg->str, msg->len);

	si->ob->wex = tick_add_ifset(now_ms, si->ob->wto);
	buffer_auto_read(si->ob);
	buffer_auto_close(si->ob);
	buffer_shutr_now(si->ob);
}

/* default update function for scheduled tasks, not used for embedded tasks */
static void stream_int_update(struct stream_interface *si)
{
	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
		task_wakeup(si->owner, TASK_WOKEN_IO);
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

	if ((si->ob->flags & (BF_SHUTW|BF_HIJACK|BF_SHUTW_NOW)) == BF_SHUTW_NOW &&
	    channel_is_empty(si->ob))
		si_shutw(si);

	if ((si->ob->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_HIJACK)) == 0 && !channel_full(si->ob))
		si->flags |= SI_FL_WAIT_DATA;

	/* we're almost sure that we need some space if the buffer is not
	 * empty, even if it's not full, because the applets can't fill it.
	 */
	if ((si->ib->flags & (BF_SHUTR|BF_DONT_READ)) == 0 && !channel_is_empty(si->ib))
		si->flags |= SI_FL_WAIT_ROOM;

	if (si->ob->flags & BF_WRITE_ACTIVITY) {
		if (tick_isset(si->ob->wex))
			si->ob->wex = tick_add_ifset(now_ms, si->ob->wto);
	}

	if (si->ib->flags & BF_READ_ACTIVITY ||
	    (si->ob->flags & BF_WRITE_ACTIVITY && !(si->flags & SI_FL_INDEP_STR))) {
		if (tick_isset(si->ib->rex))
			si->ib->rex = tick_add_ifset(now_ms, si->ib->rto);
	}

	/* save flags to detect changes */
	old_flags = si->flags;
	if (likely((si->ob->flags & (BF_SHUTW|BF_WRITE_PARTIAL|BF_DONT_READ)) == BF_WRITE_PARTIAL &&
		   !channel_full(si->ob) &&
		   (si->ob->prod->flags & SI_FL_WAIT_ROOM)))
		si_chk_rcv(si->ob->prod);

	if (((si->ib->flags & BF_READ_PARTIAL) && !channel_is_empty(si->ib)) &&
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
	    (si->ib->flags & (BF_READ_NULL|BF_READ_ERROR)) ||
	    si->state != SI_ST_EST ||
	    (si->flags & SI_FL_ERR) ||
	    ((si->ib->flags & BF_READ_PARTIAL) &&
	     (!si->ib->to_forward || si->ib->cons->state != SI_ST_EST)) ||

	    /* changes on the consumption side */
	    (si->ob->flags & (BF_WRITE_NULL|BF_WRITE_ERROR)) ||
	    ((si->ob->flags & BF_WRITE_ACTIVITY) &&
	     ((si->ob->flags & BF_SHUTW) ||
	      si->ob->prod->state != SI_ST_EST ||
	      (channel_is_empty(si->ob) && !si->ob->to_forward)))) {
		if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
			task_wakeup(si->owner, TASK_WOKEN_IO);
	}
	if (si->ib->flags & BF_READ_ACTIVITY)
		si->ib->flags &= ~BF_READ_DONTWAIT;
}

/*
 * This function performs a shutdown-read on a stream interface in a connected
 * or init state (it does nothing for other states). It either shuts the read
 * side or marks itself as closed. The buffer flags are updated to reflect the
 * new state. If the stream interface has SI_FL_NOHALF, we also forward the
 * close to the write side. If a control layer is defined, then it is supposed
 * to be a socket layer and file descriptors are then shutdown or closed
 * accordingly. If no control layer is defined, then the SI is supposed to be
 * an embedded one and the owner task is woken up if it exists. The function
 * does not disable polling on the FD by itself, it returns non-zero instead
 * if the caller needs to do so (except when the FD is deleted where this is
 * implicit).
 */
int stream_int_shutr(struct stream_interface *si)
{
	struct connection *conn = &si->conn;

	si->ib->flags &= ~BF_SHUTR_NOW;
	if (si->ib->flags & BF_SHUTR)
		return 0;
	si->ib->flags |= BF_SHUTR;
	si->ib->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return 0;

	if (si->ob->flags & BF_SHUTW) {
		conn_data_close(&si->conn);
		if (conn->ctrl)
			fd_delete(si_fd(si));
		si->state = SI_ST_DIS;
		si->exp = TICK_ETERNITY;

		if (si->release)
			si->release(si);
	}
	else if (si->flags & SI_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		return stream_int_shutw(si);
	}
	else if (conn->ctrl) {
		/* we want the caller to disable polling on this FD */
		return 1;
	}

	/* note that if the task exists, it must unregister itself once it runs */
	if (!conn->ctrl && !(si->flags & SI_FL_DONT_WAKE) && si->owner)
		task_wakeup(si->owner, TASK_WOKEN_IO);
	return 0;
}

/*
 * This function performs a shutdown-write on a stream interface in a connected or
 * init state (it does nothing for other states). It either shuts the write side
 * or marks itself as closed. The buffer flags are updated to reflect the new state.
 * It does also close everything if the SI was marked as being in error state. If
 * there is a data-layer shutdown, it is called. If a control layer is defined, then
 * it is supposed to be a socket layer and file descriptors are then shutdown or
 * closed accordingly. If no control layer is defined, then the SI is supposed to
 * be an embedded one and the owner task is woken up if it exists. The function
 * does not disable polling on the FD by itself, it returns non-zero instead if
 * the caller needs to do so (except when the FD is deleted where this is implicit).
 */
int stream_int_shutw(struct stream_interface *si)
{
	struct connection *conn = &si->conn;

	si->ob->flags &= ~BF_SHUTW_NOW;
	if (si->ob->flags & BF_SHUTW)
		return 0;
	si->ob->flags |= BF_SHUTW;
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
			/* quick close, the socket is already shut. Remove pending flags. */
			si->flags &= ~SI_FL_NOLINGER;
		} else if (si->flags & SI_FL_NOLINGER) {
			si->flags &= ~SI_FL_NOLINGER;
			if (conn->ctrl) {
				setsockopt(si_fd(si), SOL_SOCKET, SO_LINGER,
					   (struct linger *) &nolinger, sizeof(struct linger));
			}
			/* unclean data-layer shutdown */
			if (conn->data && conn->data->shutw)
				conn->data->shutw(conn, 0);
		} else {
			/* clean data-layer shutdown */
			if (conn->data && conn->data->shutw)
				conn->data->shutw(conn, 1);

			if (!(si->flags & SI_FL_NOHALF)) {
				/* We shutdown transport layer */
				if (conn->ctrl)
					shutdown(si_fd(si), SHUT_WR);

				if (!(si->ib->flags & (BF_SHUTR|BF_DONT_READ))) {
					/* OK just a shutw, but we want the caller
					 * to disable polling on this FD if exists.
					 */
					return !!conn->ctrl;
				}
			}
		}

		/* fall through */
	case SI_ST_CON:
		/* we may have to close a pending connection, and mark the
		 * response buffer as shutr
		 */
		conn_data_close(&si->conn);
		if (conn->ctrl)
			fd_delete(si_fd(si));
		/* fall through */
	case SI_ST_CER:
	case SI_ST_QUE:
	case SI_ST_TAR:
		si->state = SI_ST_DIS;

		if (si->release)
			si->release(si);
	default:
		si->flags &= ~SI_FL_WAIT_ROOM;
		si->ib->flags |= BF_SHUTR;
		si->ib->rex = TICK_ETERNITY;
		si->exp = TICK_ETERNITY;
	}

	/* note that if the task exists, it must unregister itself once it runs */
	if (!conn->ctrl && !(si->flags & SI_FL_DONT_WAKE) && si->owner)
		task_wakeup(si->owner, TASK_WOKEN_IO);
	return 0;
}

/* default chk_rcv function for scheduled tasks */
static void stream_int_chk_rcv(struct stream_interface *si)
{
	struct channel *ib = si->ib;

	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (unlikely(si->state != SI_ST_EST || (ib->flags & (BF_SHUTR|BF_HIJACK|BF_DONT_READ))))
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

	if (unlikely(si->state != SI_ST_EST || (si->ob->flags & BF_SHUTW)))
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

/* Register an applet to handle a stream_interface as part of the stream
 * interface's owner task, which is returned. The SI will wake it up everytime
 * it is solicited. The task's processing function must call the applet's
 * function before returning. It must be deleted by the task handler using
 * stream_int_unregister_handler(), possibly from within the function itself.
 * It also pre-initializes applet.state to zero and the connection context
 * to NULL.
 */
struct task *stream_int_register_handler(struct stream_interface *si, struct si_applet *app)
{
	DPRINTF(stderr, "registering handler %p for si %p (was %p)\n", app, si, si->owner);

	si_prepare_embedded(si);
	set_target_applet(&si->target, app);
	si->release   = app->release;
	si->flags |= SI_FL_WAIT_DATA;
	return si->owner;
}

/* Register a function to handle a stream_interface as a standalone task. The
 * new task itself is returned and is assigned as si->owner. The stream_interface
 * pointer will be pointed to by the task's context. The handler can be detached
 * by using stream_int_unregister_handler().
 * FIXME: the code should be updated to ensure that we don't change si->owner
 * anymore as this is not needed. However, process_session still relies on it.
 */
struct task *stream_int_register_handler_task(struct stream_interface *si,
					      struct task *(*fct)(struct task *))
{
	struct task *t;

	DPRINTF(stderr, "registering handler %p for si %p (was %p)\n", fct, si, si->owner);

	si_prepare_task(si);
	clear_target(&si->target);
	si->release   = NULL;
	si->flags |= SI_FL_WAIT_DATA;

	t = task_new();
	si->owner = t;
	if (!t)
		return t;

	set_target_task(&si->target, t);

	t->process = fct;
	t->context = si;
	task_wakeup(si->owner, TASK_WOKEN_INIT);

	return t;
}

/* Unregister a stream interface handler. This must be called by the handler task
 * itself when it detects that it is in the SI_ST_DIS state. This function can
 * both detach standalone handlers and embedded handlers.
 */
void stream_int_unregister_handler(struct stream_interface *si)
{
	if (si->target.type == TARG_TYPE_TASK) {
		/* external handler : kill the task */
		task_delete(si->target.ptr.t);
		task_free(si->target.ptr.t);
	}
	si->release   = NULL;
	si->owner = NULL;
	clear_target(&si->target);
}

/* This callback is used to send a valid PROXY protocol line to a socket being
 * established. It returns 0 if it fails in a fatal way or needs to poll to go
 * further, otherwise it returns non-zero and removes itself from the connection's
 * flags (the bit is provided in <flag> by the caller). It is designed to be
 * called by the connection handler and relies on it to commit polling changes.
 */
int conn_si_send_proxy(struct connection *conn, unsigned int flag)
{
	struct stream_interface *si = container_of(conn, struct stream_interface, conn);

	/* we might have been called just after an asynchronous shutw */
	if (conn->flags & CO_FL_SOCK_WR_SH)
		goto out_error;

	/* If we have a PROXY line to send, we'll use this to validate the
	 * connection, in which case the connection is validated only once
	 * we've sent the whole proxy line. Otherwise we use connect().
	 */
	if (si->send_proxy_ofs) {
		int ret;

		/* The target server expects a PROXY line to be sent first.
		 * If the send_proxy_ofs is negative, it corresponds to the
		 * offset to start sending from then end of the proxy string
		 * (which is recomputed every time since it's constant). If
		 * it is positive, it means we have to send from the start.
		 */
		ret = make_proxy_line(trash, trashlen, &si->ob->prod->addr.from, &si->ob->prod->addr.to);
		if (!ret)
			goto out_error;

		if (si->send_proxy_ofs > 0)
			si->send_proxy_ofs = -ret; /* first call */

		/* we have to send trash from (ret+sp for -sp bytes). If the
		 * data layer has a pending write, we'll also set MSG_MORE.
		 */
		ret = send(conn->t.sock.fd, trash + ret + si->send_proxy_ofs, -si->send_proxy_ofs,
			   (conn->flags & CO_FL_DATA_WR_ENA) ? MSG_MORE : 0);

		if (ret == 0)
			goto out_wait;

		if (ret < 0) {
			if (errno == EAGAIN)
				goto out_wait;
			goto out_error;
		}

		si->send_proxy_ofs += ret; /* becomes zero once complete */
		if (si->send_proxy_ofs != 0)
			goto out_wait;

		/* OK we've sent the whole line, we're connected */
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
	conn->flags &= ~flag;
	__conn_sock_stop_both(conn);
	return 0;

 out_wait:
	__conn_sock_stop_recv(conn);
	__conn_sock_poll_send(conn);
	return 0;
}

/* Callback to be used by connection I/O handlers upon completion. It differs from
 * the function below in that it is designed to be called by lower layers after I/O
 * events have been completed. It will also try to wake the associated task up if
 * an important event requires special handling. It relies on the connection handler
 * to commit any polling updates.
 */
void conn_notify_si(struct connection *conn)
{
	struct stream_interface *si = container_of(conn, struct stream_interface, conn);

	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (conn->flags & CO_FL_ERROR)
		si->flags |= SI_FL_ERR;

	/* check for recent connection establishment */
	if (unlikely(!(conn->flags & (CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN | CO_FL_CONNECTED)))) {
		si->exp = TICK_ETERNITY;
		si->ob->flags |= BF_WRITE_NULL;
	}

	/* process consumer side */
	if (channel_is_empty(si->ob)) {
		if (((si->ob->flags & (BF_SHUTW|BF_HIJACK|BF_SHUTW_NOW)) == BF_SHUTW_NOW) &&
		    (si->state == SI_ST_EST))
			stream_int_shutw(si);
		__conn_data_stop_send(conn);
		si->ob->wex = TICK_ETERNITY;
	}

	if ((si->ob->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_HIJACK)) == 0 && !channel_full(si->ob))
		si->flags |= SI_FL_WAIT_DATA;

	if (si->ob->flags & BF_WRITE_ACTIVITY) {
		/* update timeouts if we have written something */
		if ((si->ob->flags & (BF_SHUTW|BF_WRITE_PARTIAL)) == BF_WRITE_PARTIAL &&
		    !channel_is_empty(si->ob))
			if (tick_isset(si->ob->wex))
				si->ob->wex = tick_add_ifset(now_ms, si->ob->wto);

		if (!(si->flags & SI_FL_INDEP_STR))
			if (tick_isset(si->ib->rex))
				si->ib->rex = tick_add_ifset(now_ms, si->ib->rto);

		if (likely((si->ob->flags & (BF_SHUTW|BF_WRITE_PARTIAL|BF_DONT_READ)) == BF_WRITE_PARTIAL &&
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
	if (((si->ib->flags & BF_READ_PARTIAL) && !channel_is_empty(si->ib)) &&
	    (si->ib->pipe /* always try to send spliced data */ ||
	     (si->ib->buf.i == 0 && (si->ib->cons->flags & SI_FL_WAIT_DATA)))) {
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
	else if ((si->ib->flags & (BF_SHUTR|BF_READ_PARTIAL|BF_DONT_READ|BF_READ_NOEXP)) == BF_READ_PARTIAL &&
		 !channel_full(si->ib)) {
		if (tick_isset(si->ib->rex))
			si->ib->rex = tick_add_ifset(now_ms, si->ib->rto);
	}

	/* wake the task up only when needed */
	if (/* changes on the production side */
	    (si->ib->flags & (BF_READ_NULL|BF_READ_ERROR)) ||
	    si->state != SI_ST_EST ||
	    (si->flags & SI_FL_ERR) ||
	    ((si->ib->flags & BF_READ_PARTIAL) &&
	     (!si->ib->to_forward || si->ib->cons->state != SI_ST_EST)) ||

	    /* changes on the consumption side */
	    (si->ob->flags & (BF_WRITE_NULL|BF_WRITE_ERROR)) ||
	    ((si->ob->flags & BF_WRITE_ACTIVITY) &&
	     ((si->ob->flags & BF_SHUTW) ||
	      si->ob->prod->state != SI_ST_EST ||
	      (channel_is_empty(si->ob) && !si->ob->to_forward)))) {
		task_wakeup(si->owner, TASK_WOKEN_IO);
	}
	if (si->ib->flags & BF_READ_ACTIVITY)
		si->ib->flags &= ~BF_READ_DONTWAIT;
}

/*
 * This function is called to send buffer data to a stream socket.
 * It returns -1 in case of unrecoverable error, otherwise zero.
 * It iterates the data layer's snd_buf function. It relies on the
 * caller to commit polling changes.
 */
static int si_conn_send_loop(struct connection *conn)
{
	struct stream_interface *si = container_of(conn, struct stream_interface, conn);
	struct channel *b = si->ob;
	int write_poll = MAX_WRITE_POLL_LOOPS;
	int ret;

	conn->flags &= ~(CO_FL_WAIT_DATA | CO_FL_WAIT_ROOM);

	if (b->pipe && conn->data->snd_pipe) {
		ret = conn->data->snd_pipe(conn, b->pipe);
		if (ret > 0)
			b->flags |= BF_WRITE_PARTIAL;

		if (!b->pipe->data) {
			put_pipe(b->pipe);
			b->pipe = NULL;
		}

		if (conn->flags & CO_FL_ERROR)
			return -1;

		if (conn->flags & CO_FL_WAIT_ROOM) {
			__conn_data_poll_send(conn);
			return 0;
		}
	}

	/* At this point, the pipe is empty, but we may still have data pending
	 * in the normal buffer.
	 */
	if (!b->buf.o)
		return 0;

	/* when we're in this loop, we already know that there is no spliced
	 * data left, and that there are sendable buffered data.
	 */
	while (!(conn->flags & (CO_FL_ERROR | CO_FL_SOCK_WR_SH | CO_FL_DATA_WR_SH | CO_FL_WAIT_DATA | CO_FL_WAIT_ROOM | CO_FL_HANDSHAKE))) {
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
		unsigned int send_flag = MSG_DONTWAIT | MSG_NOSIGNAL;

		if ((!(b->flags & (BF_NEVER_WAIT|BF_SEND_DONTWAIT)) &&
		     ((b->to_forward && b->to_forward != BUF_INFINITE_FORWARD) ||
		      (b->flags & BF_EXPECT_MORE))) ||
		    ((b->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_HIJACK)) == BF_SHUTW_NOW))
			send_flag |= MSG_MORE;

		ret = conn->data->snd_buf(conn, &b->buf, send_flag);
		if (ret <= 0)
			break;

		if (si->conn.flags & CO_FL_WAIT_L4_CONN)
			si->conn.flags &= ~CO_FL_WAIT_L4_CONN;

		b->flags |= BF_WRITE_PARTIAL;

		if (likely(!channel_full(b)))
			b->flags &= ~BF_FULL;

		if (!b->buf.o) {
			/* Always clear both flags once everything has been sent, they're one-shot */
			b->flags &= ~(BF_EXPECT_MORE | BF_SEND_DONTWAIT);
			break;
		}

		if (--write_poll <= 0)
			break;
	} /* while */

	if (conn->flags & CO_FL_ERROR)
		return -1;

	if (conn->flags & CO_FL_WAIT_ROOM) {
		/* we need to poll before going on */
		__conn_data_poll_send(&si->conn);
		return 0;
	}
	return 0;
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

	if (si->conn.flags & CO_FL_HANDSHAKE) {
		/* a handshake is in progress */
		return;
	}

	/* Check if we need to close the read side */
	if (!(ib->flags & BF_SHUTR)) {
		/* Read not closed, update FD status and timeout for reads */
		if ((ib->flags & (BF_HIJACK|BF_DONT_READ)) || channel_full(ib)) {
			/* stop reading */
			if (!(si->flags & SI_FL_WAIT_ROOM)) {
				if (!(ib->flags & (BF_HIJACK|BF_DONT_READ))) /* full */
					si->flags |= SI_FL_WAIT_ROOM;
				conn_data_stop_recv(&si->conn);
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
			conn_data_want_recv(&si->conn);
			if (!(ib->flags & (BF_READ_NOEXP|BF_DONT_READ)) && !tick_isset(ib->rex))
				ib->rex = tick_add_ifset(now_ms, ib->rto);
		}
	}

	/* Check if we need to close the write side */
	if (!(ob->flags & BF_SHUTW)) {
		/* Write not closed, update FD status and timeout for writes */
		if (channel_is_empty(ob)) {
			/* stop writing */
			if (!(si->flags & SI_FL_WAIT_DATA)) {
				if ((ob->flags & (BF_HIJACK|BF_SHUTW_NOW)) == 0)
					si->flags |= SI_FL_WAIT_DATA;
				conn_data_stop_send(&si->conn);
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
			conn_data_want_send(&si->conn);
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

/* This function is used for inter-stream-interface calls. It is called by the
 * consumer to inform the producer side that it may be interested in checking
 * for free space in the buffer. Note that it intentionally does not update
 * timeouts, so that we can still check them later at wake-up. This function is
 * dedicated to connection-based stream interfaces.
 */
static void stream_int_chk_rcv_conn(struct stream_interface *si)
{
	struct channel *ib = si->ib;

	if (unlikely(si->state != SI_ST_EST || (ib->flags & BF_SHUTR)))
		return;

	if (si->conn.flags & CO_FL_HANDSHAKE) {
		/* a handshake is in progress */
		return;
	}

	if ((ib->flags & (BF_HIJACK|BF_DONT_READ)) || channel_full(ib)) {
		/* stop reading */
		if (!(ib->flags & (BF_HIJACK|BF_DONT_READ))) /* full */
			si->flags |= SI_FL_WAIT_ROOM;
		conn_data_stop_recv(&si->conn);
	}
	else {
		/* (re)start reading */
		si->flags &= ~SI_FL_WAIT_ROOM;
		conn_data_want_recv(&si->conn);
	}
}


/* This function is used for inter-stream-interface calls. It is called by the
 * producer to inform the consumer side that it may be interested in checking
 * for data in the buffer. Note that it intentionally does not update timeouts,
 * so that we can still check them later at wake-up.
 */
static void stream_int_chk_snd_conn(struct stream_interface *si)
{
	struct channel *ob = si->ob;

	if (unlikely(si->state != SI_ST_EST || (ob->flags & BF_SHUTW)))
		return;

	/* handshake running on producer */
	if (si->conn.flags & CO_FL_HANDSHAKE) {
		/* a handshake is in progress */
		return;
	}

	if (unlikely(channel_is_empty(ob)))  /* called with nothing to send ! */
		return;

	if (!ob->pipe &&                          /* spliced data wants to be forwarded ASAP */
	    (!(si->flags & SI_FL_WAIT_DATA) ||    /* not waiting for data */
	     (fdtab[si_fd(si)].ev & FD_POLL_OUT)))   /* we'll be called anyway */
		return;

	if (si_conn_send_loop(&si->conn) < 0) {
		/* Write error on the file descriptor. We mark the FD as STERROR so
		 * that we don't use it anymore and we notify the task.
		 */
		fdtab[si_fd(si)].ev &= ~FD_POLL_STICKY;
		__conn_data_stop_both(&si->conn);
		si->flags |= SI_FL_ERR;
		si->conn.flags |= CO_FL_ERROR;
		goto out_wakeup;
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
		if (((ob->flags & (BF_SHUTW|BF_HIJACK|BF_AUTO_CLOSE|BF_SHUTW_NOW)) ==
		     (BF_AUTO_CLOSE|BF_SHUTW_NOW)) &&
		    (si->state == SI_ST_EST)) {
			si_shutw(si);
			goto out_wakeup;
		}

		if ((ob->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_HIJACK)) == 0)
			si->flags |= SI_FL_WAIT_DATA;
		ob->wex = TICK_ETERNITY;
	}
	else {
		/* Otherwise there are remaining data to be sent in the buffer,
		 * which means we have to poll before doing so.
		 */
		__conn_data_want_send(&si->conn);
		si->flags &= ~SI_FL_WAIT_DATA;
		if (!tick_isset(ob->wex))
			ob->wex = tick_add_ifset(now_ms, ob->wto);
	}

	if (likely(ob->flags & BF_WRITE_ACTIVITY)) {
		/* update timeout if we have written something */
		if ((ob->flags & (BF_SHUTW|BF_WRITE_PARTIAL)) == BF_WRITE_PARTIAL &&
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
	if (likely((ob->flags & (BF_WRITE_NULL|BF_WRITE_ERROR|BF_SHUTW)) ||
		   (channel_is_empty(ob) && !ob->to_forward) ||
		   si->state != SI_ST_EST)) {
	out_wakeup:
		if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
			task_wakeup(si->owner, TASK_WOKEN_IO);
	}

	/* commit possible polling changes */
	conn_cond_update_polling(&si->conn);
}

/*
 * This is the callback which is called by the connection layer to receive data
 * into the buffer from the connection. It iterates over the data layer's rcv_buf
 * function.
 */
void si_conn_recv_cb(struct connection *conn)
{
	struct stream_interface *si = container_of(conn, struct stream_interface, conn);
	struct channel *b = si->ib;
	int ret, max, cur_read;
	int read_poll = MAX_READ_POLL_LOOPS;

	/* stop immediately on errors. Note that we DON'T want to stop on
	 * POLL_ERR, as the poller might report a write error while there
	 * are still data available in the recv buffer. This typically
	 * happens when we send too large a request to a backend server
	 * which rejects it before reading it all.
	 */
	if (conn->flags & CO_FL_ERROR)
		goto out_error;

	/* stop here if we reached the end of data */
	if (conn_data_read0_pending(conn))
		goto out_shutdown_r;

	/* maybe we were called immediately after an asynchronous shutr */
	if (b->flags & BF_SHUTR)
		return;

	cur_read = 0;
	conn->flags &= ~(CO_FL_WAIT_DATA | CO_FL_WAIT_ROOM);

	/* First, let's see if we may splice data across the channel without
	 * using a buffer.
	 */
	if (conn->data->rcv_pipe &&
	    b->to_forward >= MIN_SPLICE_FORWARD && b->flags & BF_KERN_SPLICING) {
		if (buffer_not_empty(&b->buf)) {
			/* We're embarrassed, there are already data pending in
			 * the buffer and we don't want to have them at two
			 * locations at a time. Let's indicate we need some
			 * place and ask the consumer to hurry.
			 */
			goto abort_splice;
		}

		if (unlikely(b->pipe == NULL)) {
			if (pipes_used >= global.maxpipes || !(b->pipe = get_pipe())) {
				b->flags &= ~BF_KERN_SPLICING;
				goto abort_splice;
			}
		}

		ret = conn->data->rcv_pipe(conn, b->pipe, b->to_forward);
		if (ret < 0) {
			/* splice not supported on this end, let's disable it */
			b->flags &= ~BF_KERN_SPLICING;
			si->flags &= ~SI_FL_CAP_SPLICE;
			goto abort_splice;
		}

		if (ret > 0) {
			if (b->to_forward != BUF_INFINITE_FORWARD)
				b->to_forward -= ret;
			b->total += ret;
			cur_read += ret;
			b->flags |= BF_READ_PARTIAL;
		}

		if (conn_data_read0_pending(conn))
			goto out_shutdown_r;

		if (conn->flags & CO_FL_ERROR)
			goto out_error;

		/* splice not possible (anymore), let's go on on standard copy */
	}

 abort_splice:
	/* release the pipe if we can, which is almost always the case */
	if (b->pipe && !b->pipe->data) {
		put_pipe(b->pipe);
		b->pipe = NULL;
	}

	while (!b->pipe && !(conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_DATA_RD_SH | CO_FL_WAIT_DATA | CO_FL_WAIT_ROOM | CO_FL_HANDSHAKE))) {
		max = bi_avail(b);

		if (!max) {
			b->flags |= BF_FULL;
			conn->flags |= CO_FL_WAIT_ROOM;
			break;
		}

		ret = conn->data->rcv_buf(conn, &b->buf, max);
		if (ret <= 0)
			break;

		cur_read += ret;

		/* if we're allowed to directly forward data, we must update ->o */
		if (b->to_forward && !(b->flags & (BF_SHUTW|BF_SHUTW_NOW))) {
			unsigned long fwd = ret;
			if (b->to_forward != BUF_INFINITE_FORWARD) {
				if (fwd > b->to_forward)
					fwd = b->to_forward;
				b->to_forward -= fwd;
			}
			b_adv(&b->buf, fwd);
		}

		if (conn->flags & CO_FL_WAIT_L4_CONN)
			conn->flags &= ~CO_FL_WAIT_L4_CONN;

		b->flags |= BF_READ_PARTIAL;
		b->total += ret;

		if (channel_full(b)) {
			/* The buffer is now full, there's no point in going through
			 * the loop again.
			 */
			if (!(b->flags & BF_STREAMER_FAST) && (cur_read == buffer_len(&b->buf))) {
				b->xfer_small = 0;
				b->xfer_large++;
				if (b->xfer_large >= 3) {
					/* we call this buffer a fast streamer if it manages
					 * to be filled in one call 3 consecutive times.
					 */
					b->flags |= (BF_STREAMER | BF_STREAMER_FAST);
					//fputc('+', stderr);
				}
			}
			else if ((b->flags & (BF_STREAMER | BF_STREAMER_FAST)) &&
				 (cur_read <= b->buf.size / 2)) {
				b->xfer_large = 0;
				b->xfer_small++;
				if (b->xfer_small >= 2) {
					/* if the buffer has been at least half full twice,
					 * we receive faster than we send, so at least it
					 * is not a "fast streamer".
					 */
					b->flags &= ~BF_STREAMER_FAST;
					//fputc('-', stderr);
				}
			}
			else {
				b->xfer_small = 0;
				b->xfer_large = 0;
			}

			b->flags |= BF_FULL;
			si->flags |= SI_FL_WAIT_ROOM;
			break;
		}

		if ((b->flags & BF_READ_DONTWAIT) || --read_poll <= 0)
			break;

		/* if too many bytes were missing from last read, it means that
		 * it's pointless trying to read again because the system does
		 * not have them in buffers.
		 */
		if (ret < max) {
			if ((b->flags & (BF_STREAMER | BF_STREAMER_FAST)) &&
			    (cur_read <= b->buf.size / 2)) {
				b->xfer_large = 0;
				b->xfer_small++;
				if (b->xfer_small >= 3) {
					/* we have read less than half of the buffer in
					 * one pass, and this happened at least 3 times.
					 * This is definitely not a streamer.
					 */
					b->flags &= ~(BF_STREAMER | BF_STREAMER_FAST);
					//fputc('!', stderr);
				}
			}

			/* if a streamer has read few data, it may be because we
			 * have exhausted system buffers. It's not worth trying
			 * again.
			 */
			if (b->flags & BF_STREAMER)
				break;

			/* if we read a large block smaller than what we requested,
			 * it's almost certain we'll never get anything more.
			 */
			if (ret >= global.tune.recv_enough)
				break;
		}
	} /* while !flags */

	if (conn->flags & CO_FL_ERROR)
		goto out_error;

	if (conn->flags & CO_FL_WAIT_ROOM) {
		si->flags |= SI_FL_WAIT_ROOM;
	}
	else if (conn->flags & CO_FL_WAIT_DATA) {
		/* we don't automatically ask for polling if we have
		 * read enough data, as it saves some syscalls with
		 * speculative pollers.
		 */
		if (cur_read < MIN_RET_FOR_READ_LOOP)
			__conn_data_poll_recv(conn);
		else
			__conn_data_want_recv(conn);
	}

	if (conn_data_read0_pending(conn))
		/* connection closed */
		goto out_shutdown_r;

	return;

 out_shutdown_r:
	/* we received a shutdown */
	b->flags |= BF_READ_NULL;
	if (b->flags & BF_AUTO_CLOSE)
		buffer_shutw_now(b);
	stream_sock_read0(si);
	conn_data_read0(conn);
	return;

 out_error:
	/* Read error on the connection, report the error and stop I/O */
	conn->flags |= CO_FL_ERROR;
	__conn_data_stop_both(conn);
}

/*
 * This is the callback which is called by the connection layer to send data
 * from the buffer to the connection. It iterates over the data layer's snd_buf
 * function.
 */
void si_conn_send_cb(struct connection *conn)
{
	struct stream_interface *si = container_of(conn, struct stream_interface, conn);
	struct channel *b = si->ob;

	if (conn->flags & CO_FL_ERROR)
		goto out_error;

	if (si->conn.flags & CO_FL_HANDSHAKE)
		/* a handshake was requested */
		return;

	/* we might have been called just after an asynchronous shutw */
	if (b->flags & BF_SHUTW)
		return;

	/* OK there are data waiting to be sent */
	if (si_conn_send_loop(conn) < 0)
		goto out_error;

	/* OK all done */
	return;

 out_error:
	/* Write error on the connection, report the error and stop I/O */
	conn->flags |= CO_FL_ERROR;
	__conn_data_stop_both(conn);
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
	si->ib->flags &= ~BF_SHUTR_NOW;
	if (si->ib->flags & BF_SHUTR)
		return;
	si->ib->flags |= BF_SHUTR;
	si->ib->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return;

	if (si->ob->flags & BF_SHUTW)
		goto do_close;

	if (si->flags & SI_FL_NOHALF) {
		/* we want to immediately forward this close to the write side */
		if (si->flags & SI_FL_NOLINGER) {
			si->flags &= ~SI_FL_NOLINGER;
			setsockopt(si_fd(si), SOL_SOCKET, SO_LINGER,
				   (struct linger *) &nolinger, sizeof(struct linger));
		}
		/* force flag on ssl to keep session in cache */
		if (si->conn.data->shutw)
			si->conn.data->shutw(&si->conn, 0);
		goto do_close;
	}

	/* otherwise that's just a normal read shutdown */
	__conn_data_stop_recv(&si->conn);
	return;

 do_close:
	conn_data_close(&si->conn);
	fd_delete(si_fd(si));
	si->state = SI_ST_DIS;
	si->exp = TICK_ETERNITY;
	if (si->release)
		si->release(si);
	return;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
