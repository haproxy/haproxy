/*
 * Functions managing stream_interface structures
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
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

#include <proto/buffers.h>
#include <proto/fd.h>
#include <proto/stream_interface.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

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
	if (likely(msg && msg->len))
		buffer_write(si->ob, msg->str, msg->len);

	si->ob->wex = tick_add_ifset(now_ms, si->ob->wto);
	buffer_auto_read(si->ob);
	buffer_auto_close(si->ob);
	buffer_shutr_now(si->ob);
}

/* default update function for scheduled tasks, not used for embedded tasks */
void stream_int_update(struct stream_interface *si)
{
	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
		task_wakeup(si->owner, TASK_WOKEN_IO);
}

/* default update function for embedded tasks, to be used at the end of the i/o handler */
void stream_int_update_embedded(struct stream_interface *si)
{
	int old_flags = si->flags;

	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (si->state != SI_ST_EST)
		return;

	if ((si->ob->flags & (BF_OUT_EMPTY|BF_SHUTW|BF_HIJACK|BF_SHUTW_NOW)) == (BF_OUT_EMPTY|BF_SHUTW_NOW))
		si->shutw(si);

	if ((si->ob->flags & (BF_FULL|BF_SHUTW|BF_SHUTW_NOW|BF_HIJACK)) == 0)
		si->flags |= SI_FL_WAIT_DATA;

	/* we're almost sure that we need some space if the buffer is not
	 * empty, even if it's not full, because the applets can't fill it.
	 */
	if ((si->ib->flags & (BF_SHUTR|BF_OUT_EMPTY|BF_DONT_READ)) == 0)
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
	if (likely((si->ob->flags & (BF_SHUTW|BF_WRITE_PARTIAL|BF_FULL|BF_DONT_READ)) == BF_WRITE_PARTIAL &&
		   (si->ob->prod->flags & SI_FL_WAIT_ROOM)))
		si->ob->prod->chk_rcv(si->ob->prod);

	if (((si->ib->flags & (BF_READ_PARTIAL|BF_OUT_EMPTY)) == BF_READ_PARTIAL) &&
	    (si->ib->cons->flags & SI_FL_WAIT_DATA)) {
		si->ib->cons->chk_snd(si->ib->cons);
		/* check if the consumer has freed some space */
		if (!(si->ib->flags & BF_FULL))
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
	      ((si->ob->flags & BF_OUT_EMPTY) && !si->ob->to_forward)))) {
		if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
			task_wakeup(si->owner, TASK_WOKEN_IO);
	}
	if (si->ib->flags & BF_READ_ACTIVITY)
		si->ib->flags &= ~BF_READ_DONTWAIT;
}

/* default shutr function for scheduled tasks */
void stream_int_shutr(struct stream_interface *si)
{
	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	si->ib->flags &= ~BF_SHUTR_NOW;
	if (si->ib->flags & BF_SHUTR)
		return;
	si->ib->flags |= BF_SHUTR;
	si->ib->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return;

	if (si->ob->flags & BF_SHUTW) {
		si->state = SI_ST_DIS;
		si->exp = TICK_ETERNITY;
	}

	if (si->release)
		si->release(si);

	/* note that if the task exist, it must unregister itself once it runs */
	if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
		task_wakeup(si->owner, TASK_WOKEN_IO);
}

/* default shutw function for scheduled tasks */
void stream_int_shutw(struct stream_interface *si)
{
	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	si->ob->flags &= ~BF_SHUTW_NOW;
	if (si->ob->flags & BF_SHUTW)
		return;
	si->ob->flags |= BF_SHUTW;
	si->ob->wex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_DATA;

	switch (si->state) {
	case SI_ST_EST:
		if (!(si->ib->flags & (BF_SHUTR|BF_DONT_READ)))
			break;

		/* fall through */
	case SI_ST_CON:
	case SI_ST_CER:
		si->state = SI_ST_DIS;
		/* fall through */
	default:
		si->flags &= ~SI_FL_WAIT_ROOM;
		si->ib->flags |= BF_SHUTR;
		si->ib->rex = TICK_ETERNITY;
		si->exp = TICK_ETERNITY;
	}

	if (si->release)
		si->release(si);

	/* note that if the task exist, it must unregister itself once it runs */
	if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
		task_wakeup(si->owner, TASK_WOKEN_IO);
}

/* default chk_rcv function for scheduled tasks */
void stream_int_chk_rcv(struct stream_interface *si)
{
	struct buffer *ib = si->ib;

	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (unlikely(si->state != SI_ST_EST || (ib->flags & BF_SHUTR)))
		return;

	if (ib->flags & (BF_FULL|BF_HIJACK|BF_DONT_READ)) {
		/* stop reading */
		if ((ib->flags & (BF_FULL|BF_HIJACK|BF_DONT_READ)) == BF_FULL)
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
void stream_int_chk_snd(struct stream_interface *si)
{
	struct buffer *ob = si->ob;

	DPRINTF(stderr, "%s: si=%p, si->state=%d ib->flags=%08x ob->flags=%08x\n",
		__FUNCTION__,
		si, si->state, si->ib->flags, si->ob->flags);

	if (unlikely(si->state != SI_ST_EST || (si->ob->flags & BF_SHUTW)))
		return;

	if (!(si->flags & SI_FL_WAIT_DATA) ||        /* not waiting for data */
	    (ob->flags & BF_OUT_EMPTY))              /* called with nothing to send ! */
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

/* Register a function to handle a stream_interface as part of the stream
 * interface's owner task, which is returned. The SI will wake it up everytime
 * it is solicited. The task's processing function must call the specified
 * function before returning. It must be deleted by the task handler using
 * stream_int_unregister_handler(), possibly from withing the function itself.
 */
struct task *stream_int_register_handler(struct stream_interface *si,
					 void (*fct)(struct stream_interface *))
{
	DPRINTF(stderr, "registering handler %p for si %p (was %p)\n", fct, si, si->owner);

	si->update  = stream_int_update_embedded;
	si->shutr   = stream_int_shutr;
	si->shutw   = stream_int_shutw;
	si->chk_rcv = stream_int_chk_rcv;
	si->chk_snd = stream_int_chk_snd;
	si->connect = NULL;
	si->iohandler = fct;
	si->release   = NULL;
	si->flags |= SI_FL_WAIT_DATA;
	return si->owner;
}

/* Register a function to handle a stream_interface as a standalone task. The
 * new task itself is returned and is assigned as si->owner. The stream_interface
 * pointer will be pointed to by the task's context. The handler can be detached
 * by using stream_int_unregister_handler().
 */
struct task *stream_int_register_handler_task(struct stream_interface *si,
					      struct task *(*fct)(struct task *))
{
	struct task *t;

	DPRINTF(stderr, "registering handler %p for si %p (was %p)\n", fct, si, si->owner);

	si->update  = stream_int_update;
	si->shutr   = stream_int_shutr;
	si->shutw   = stream_int_shutw;
	si->chk_rcv = stream_int_chk_rcv;
	si->chk_snd = stream_int_chk_snd;
	si->connect = NULL;
	si->iohandler = NULL; /* not used when running as an external task */
	si->release   = NULL;
	si->flags |= SI_FL_WAIT_DATA;

	t = task_new();
	si->owner = t;
	if (!t)
		return t;
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
	if (!si->iohandler && si->owner) {
		/* external handler : kill the task */
		task_delete(si->owner);
		task_free(si->owner);
	}
	si->iohandler = NULL;
	si->release   = NULL;
	si->owner = NULL;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
