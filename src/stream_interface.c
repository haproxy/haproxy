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

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/channel.h>
#include <haproxy/connection.h>
#include <haproxy/conn_stream.h>
#include <haproxy/cs_utils.h>
#include <haproxy/dynbuf.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/pipe-t.h>
#include <haproxy/pipe.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/stream-t.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>


DECLARE_POOL(pool_head_streaminterface, "stream_interface", sizeof(struct stream_interface));

/* last read notification */
static void cs_conn_read0(struct conn_stream *cs);

/* post-IO notification callback */
static void cs_notify(struct conn_stream *cs);

struct data_cb si_conn_cb = {
	.wake    = si_cs_process,
	.name    = "STRM",
};


struct data_cb cs_data_applet_cb = {
	.wake    = cs_applet_process,
	.name    = "STRM",
};

struct stream_interface *si_new(struct conn_stream *cs)
{
	struct stream_interface *si;

	si = pool_alloc(pool_head_streaminterface);
	if (unlikely(!si))
		return NULL;
	si->flags = SI_FL_NONE;
	if (si_init(si) < 0) {
		pool_free(pool_head_streaminterface, si);
		return NULL;
	}
	si->cs = cs;
	return si;
}

void si_free(struct stream_interface *si)
{
	if (!si)
		return;

	pool_free(pool_head_streaminterface, si);
}

/* This function is the equivalent to cs_update() except that it's
 * designed to be called from outside the stream handlers, typically the lower
 * layers (applets, connections) after I/O completion. After updating the stream
 * interface and timeouts, it will try to forward what can be forwarded, then to
 * wake the associated task up if an important event requires special handling.
 * It may update SI_FL_WAIT_DATA and/or SI_FL_RXBLK_ROOM, that the callers are
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
		cs->si->flags |= SI_FL_WAIT_DATA;
	else if ((oc->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW)
		cs->si->flags &= ~SI_FL_WAIT_DATA;

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
		si_rx_chan_blk(cso->si);
	else
		si_rx_chan_rdy(cso->si);

	/* Notify the other side when we've injected data into the IC that
	 * needs to be forwarded. We can do fast-forwarding as soon as there
	 * are output data, but we avoid doing this if some of the data are
	 * not yet scheduled for being forwarded, because it is very likely
	 * that it will be done again immediately afterwards once the following
	 * data are parsed (eg: HTTP chunking). We only SI_FL_RXBLK_ROOM once
	 * we've emptied *some* of the output buffer, and not just when there
	 * is available room, because applets are often forced to stop before
	 * the buffer is full. We must not stop based on input data alone because
	 * an HTTP parser might need more data to complete the parsing.
	 */
	if (!channel_is_empty(ic) &&
	    (cso->si->flags & SI_FL_WAIT_DATA) &&
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
			si_rx_room_rdy(cs->si);
	}

	if (!(ic->flags & CF_DONT_READ))
		si_rx_chan_rdy(cs->si);

	cs_chk_rcv(cs);
	cs_chk_rcv(cso);

	if (si_rx_blocked(cs->si)) {
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

/* Called by I/O handlers after completion.. It propagates
 * connection flags to the stream interface, updates the stream (which may or
 * may not take this opportunity to try to forward data), then update the
 * connection's polling based on the channels and stream interface's final
 * states. The function always returns 0.
 */
int si_cs_process(struct conn_stream *cs)
{
	struct connection *conn = __cs_conn(cs);
	struct stream_interface *si = cs_si(cs);
	struct channel *ic = si_ic(si);
	struct channel *oc = si_oc(si);

	BUG_ON(!conn);

	/* If we have data to send, try it now */
	if (!channel_is_empty(oc) && !(si->cs->wait_event.events & SUB_RETRY_SEND))
		si_cs_send(cs);

	/* First step, report to the conn-stream what was detected at the
	 * connection layer : errors and connection establishment.
	 * Only add CS_EP_ERROR if we're connected, or we're attempting to
	 * connect, we may get there because we got woken up, but only run
	 * after process_stream() noticed there were an error, and decided
	 * to retry to connect, the connection may still have CO_FL_ERROR,
	 * and we don't want to add CS_EP_ERROR back
	 *
	 * Note: This test is only required because si_cs_process is also the SI
	 *       wake callback. Otherwise si_cs_recv()/si_cs_send() already take
	 *       care of it.
	 */

	if (si->cs->state >= CS_ST_CON) {
		if (si_is_conn_error(si))
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
		task_wakeup(si_task(si), TASK_WOKEN_MSG);
	}

	if (!cs_state_in(si->cs->state, CS_SB_EST|CS_SB_DIS|CS_SB_CLO) &&
	    (conn->flags & CO_FL_WAIT_XPRT) == 0) {
		__cs_strm(cs)->conn_exp = TICK_ETERNITY;
		oc->flags |= CF_WRITE_NULL;
		if (si->cs->state == CS_ST_CON)
			si->cs->state = CS_ST_RDY;
	}

	/* Report EOS on the channel if it was reached from the mux point of
	 * view.
	 *
	 * Note: This test is only required because si_cs_process is also the SI
	 *       wake callback. Otherwise si_cs_recv()/si_cs_send() already take
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
	 * Note: This test is only required because si_cs_process is also the SI
	 *       wake callback. Otherwise si_cs_recv()/si_cs_send() already take
	 *       care of it.
	 */
	if ((cs->endp->flags & CS_EP_EOI) && !(ic->flags & CF_EOI))
		ic->flags |= (CF_EOI|CF_READ_PARTIAL);

	/* Second step : update the stream-int and channels, try to forward any
	 * pending data, then possibly wake the stream up based on the new
	 * stream-int status.
	 */
	cs_notify(cs);
	stream_release_buffers(si_strm(si));
	return 0;
}

/*
 * This function is called to send buffer data to a stream socket.
 * It calls the mux layer's snd_buf function. It relies on the
 * caller to commit polling changes. The caller should check conn->flags
 * for errors.
 */
int si_cs_send(struct conn_stream *cs)
{
	struct connection *conn = __cs_conn(cs);
	struct stream_interface *si = cs_si(cs);
	struct stream *s = si_strm(si);
	struct channel *oc = si_oc(si);
	int ret;
	int did_send = 0;

	if (cs->endp->flags & (CS_EP_ERROR|CS_EP_ERR_PENDING) || si_is_conn_error(si)) {
		/* We're probably there because the tasklet was woken up,
		 * but process_stream() ran before, detected there were an
		 * error and put the si back to CS_ST_TAR. There's still
		 * CO_FL_ERROR on the connection but we don't want to add
		 * CS_EP_ERROR back, so give up
		 */
		if (si->cs->state < CS_ST_CON)
			return 0;
		cs->endp->flags |= CS_EP_ERROR;
		return 1;
	}

	/* We're already waiting to be able to send, give up */
	if (si->cs->wait_event.events & SUB_RETRY_SEND)
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
		      (IS_HTX_STRM(si_strm(si)) &&
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
		if (si->cs->state == CS_ST_CON)
			si->cs->state = CS_ST_RDY;

		si_rx_room_rdy(si_opposite(si));
	}

	if (cs->endp->flags & (CS_EP_ERROR|CS_EP_ERR_PENDING)) {
		cs->endp->flags |= CS_EP_ERROR;
		return 1;
	}

	/* We couldn't send all of our data, let the mux know we'd like to send more */
	if (!channel_is_empty(oc))
		conn->mux->subscribe(cs, SUB_RETRY_SEND, &si->cs->wait_event);
	return did_send;
}

/* This is the ->process() function for any conn-stream's wait_event task.
 * It's assigned during the stream-interface's initialization, for any type of
 * stream interface. Thus it is always safe to perform a tasklet_wakeup() on a
 * stream interface, as the presence of the CS is checked there.
 */
struct task *si_cs_io_cb(struct task *t, void *ctx, unsigned int state)
{
	struct stream_interface *si = ctx;
	struct conn_stream *cs = si->cs;
	int ret = 0;

	if (!cs_conn(cs))
		return t;

	if (!(cs->wait_event.events & SUB_RETRY_SEND) && !channel_is_empty(si_oc(si)))
		ret = si_cs_send(cs);
	if (!(cs->wait_event.events & SUB_RETRY_RECV))
		ret |= si_cs_recv(cs);
	if (ret != 0)
		si_cs_process(cs);

	stream_release_buffers(si_strm(si));
	return t;
}

/* This tries to perform a synchronous receive on the stream interface to
 * try to collect last arrived data. In practice it's only implemented on
 * conn_streams. Returns 0 if nothing was done, non-zero if new data or a
 * shutdown were collected. This may result on some delayed receive calls
 * to be programmed and performed later, though it doesn't provide any
 * such guarantee.
 */
int si_sync_recv(struct stream_interface *si)
{
	if (!cs_state_in(si->cs->state, CS_SB_RDY|CS_SB_EST))
		return 0;

	if (!cs_conn_mux(si->cs))
		return 0; // only conn_streams are supported

	if (si->cs->wait_event.events & SUB_RETRY_RECV)
		return 0; // already subscribed

	if (!si_rx_endp_ready(si) || si_rx_blocked(si))
		return 0; // already failed

	return si_cs_recv(si->cs);
}

/* perform a synchronous send() for the stream interface. The CF_WRITE_NULL and
 * CF_WRITE_PARTIAL flags are cleared prior to the attempt, and will possibly
 * be updated in case of success.
 */
void si_sync_send(struct stream_interface *si)
{
	struct channel *oc = si_oc(si);

	oc->flags &= ~(CF_WRITE_NULL|CF_WRITE_PARTIAL);

	if (oc->flags & CF_SHUTW)
		return;

	if (channel_is_empty(oc))
		return;

	if (!cs_state_in(si->cs->state, CS_SB_CON|CS_SB_RDY|CS_SB_EST))
		return;

	if (!cs_conn_mux(si->cs))
		return;

	si_cs_send(si->cs);
}

/*
 * This is the callback which is called by the connection layer to receive data
 * into the buffer from the connection. It iterates over the mux layer's
 * rcv_buf function.
 */
int si_cs_recv(struct conn_stream *cs)
{
	struct connection *conn = __cs_conn(cs);
	struct stream_interface *si = cs_si(cs);
	struct channel *ic = si_ic(si);
	int ret, max, cur_read = 0;
	int read_poll = MAX_READ_POLL_LOOPS;
	int flags = 0;

	/* If not established yet, do nothing. */
	if (cs->state != CS_ST_EST)
		return 0;

	/* If another call to si_cs_recv() failed, and we subscribed to
	 * recv events already, give up now.
	 */
	if (si->cs->wait_event.events & SUB_RETRY_RECV)
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
			si_rx_room_blk(si);
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
	if (!si_alloc_ibuf(si, &(si_strm(si)->buffer_wait)))
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
	if (IS_HTX_STRM(si_strm(si)) && !co_data(ic)) {
		struct htx *htx = htxbuf(&ic->buf);

		if (htx_is_not_empty(htx) && ((htx->flags & HTX_FL_FRAGMENTED) || htx_space_wraps(htx)))
			htx_defrag(htxbuf(&ic->buf), NULL, 0);
	}

	/* Instruct the mux it must subscribed for read events */
	flags |= ((!conn_is_back(conn) && (si_strm(si)->be->options & PR_O_ABRT_CLOSE)) ? CO_RFL_KEEP_RECV : 0);

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

			si_rx_room_blk(si);
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
				si_rx_room_blk(si);
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
		 * important to break the loop to not block the SI because of
		 * the channel's policies.This way, we are still able to receive
		 * shutdowns.
		 */
		if (cs->endp->flags & CS_EP_EOI)
			break;

		if ((ic->flags & CF_READ_DONTWAIT) || --read_poll <= 0) {
			/* we're stopped by the channel's policy */
			si_rx_chan_blk(si);
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
				si_rx_chan_blk(si);
				break;
			}

			/* if we read a large block smaller than what we requested,
			 * it's almost certain we'll never get anything more.
			 */
			if (ret >= global.tune.recv_enough) {
				/* we're stopped by the channel's policy */
				si_rx_chan_blk(si);
				break;
			}
		}

		/* if we are waiting for more space, don't try to read more data
		 * right now.
		 */
		if (si_rx_blocked(si))
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
	else if (!si_rx_blocked(si)) {
		/* Subscribe to receive events if we're blocking on I/O */
		conn->mux->subscribe(cs, SUB_RETRY_RECV, &si->cs->wait_event);
		si_rx_endp_done(si);
	} else {
		si_rx_endp_more(si);
		ret = 1;
	}
	return ret;
}

/*
 * This function propagates a null read received on a socket-based connection.
 * It updates the stream interface. If the stream interface has CS_FL_NOHALF,
 * the close is also forwarded to the write side as an abort.
 */
static void cs_conn_read0(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);
	struct channel *oc = cs_oc(cs);

	BUG_ON(!cs_conn(cs));

	si_rx_shut_blk(cs->si);
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
	cs_conn_close(cs);

	oc->flags &= ~CF_SHUTW_NOW;
	oc->flags |= CF_SHUTW;
	oc->wex = TICK_ETERNITY;

	si_done_get(cs->si);

	cs->state = CS_ST_DIS;
	__cs_strm(cs)->conn_exp = TICK_ETERNITY;
	return;
}

/* Callback to be used by applet handlers upon completion. It updates the stream
 * (which may or may not take this opportunity to try to forward data), then
 * may re-enable the applet's based on the channels and stream interface's final
 * states.
 */
int cs_applet_process(struct conn_stream *cs)
{
	struct channel *ic = cs_ic(cs);

	BUG_ON(!cs_appctx(cs));

	/* If the applet wants to write and the channel is closed, it's a
	 * broken pipe and it must be reported.
	 */
	if (!(cs->si->flags & SI_FL_RX_WAIT_EP) && (ic->flags & CF_SHUTR))
		cs->endp->flags |= CS_EP_ERROR;

	/* automatically mark the applet having data available if it reported
	 * begin blocked by the channel.
	 */
	if (si_rx_blocked(cs->si))
		si_rx_endp_more(cs->si);

	/* update the stream-int, channels, and possibly wake the stream up */
	cs_notify(cs);
	stream_release_buffers(__cs_strm(cs));

	/* cs_notify may have passed through chk_snd and released some
	 * RXBLK flags. Process_stream will consider those flags to wake up the
	 * appctx but in the case the task is not in runqueue we may have to
	 * wakeup the appctx immediately.
	 */
	if ((si_rx_endp_ready(cs->si) && !si_rx_blocked(cs->si)) ||
	    (si_tx_endp_ready(cs->si) && !si_tx_blocked(cs->si)))
		appctx_wakeup(__cs_appctx(cs));
	return 0;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
