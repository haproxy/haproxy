/*
 * include/proto/stream_interface.h
 * This file contains stream_interface function prototypes
 *
 * Copyright (C) 2000-2014 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _PROTO_STREAM_INTERFACE_H
#define _PROTO_STREAM_INTERFACE_H

#include <stdlib.h>

#include <common/config.h>
#include <types/server.h>
#include <types/stream.h>
#include <types/stream_interface.h>
#include <proto/applet.h>
#include <proto/channel.h>
#include <proto/connection.h>


extern struct si_ops si_embedded_ops;
extern struct si_ops si_conn_ops;
extern struct si_ops si_applet_ops;
extern struct data_cb si_conn_cb;

/* main event functions used to move data between sockets and buffers */
int si_check_timeouts(struct stream_interface *si);
void si_report_error(struct stream_interface *si);
void si_retnclose(struct stream_interface *si, const struct buffer *msg);
int conn_si_send_proxy(struct connection *conn, unsigned int flag);
struct appctx *si_register_handler(struct stream_interface *si, struct applet *app);
void si_applet_wake_cb(struct stream_interface *si);
void si_update_rx(struct stream_interface *si);
void si_update_tx(struct stream_interface *si);
int si_cs_recv(struct conn_stream *cs);
struct task *si_cs_io_cb(struct task *t, void *ctx, unsigned short state);
void si_update_both(struct stream_interface *si_f, struct stream_interface *si_b);
void si_sync_send(struct stream_interface *si);

/* returns the channel which receives data from this stream interface (input channel) */
static inline struct channel *si_ic(struct stream_interface *si)
{
	if (si->flags & SI_FL_ISBACK)
		return &LIST_ELEM(si, struct stream *, si[1])->res;
	else
		return &LIST_ELEM(si, struct stream *, si[0])->req;
}

/* returns the channel which feeds data to this stream interface (output channel) */
static inline struct channel *si_oc(struct stream_interface *si)
{
	if (si->flags & SI_FL_ISBACK)
		return &LIST_ELEM(si, struct stream *, si[1])->req;
	else
		return &LIST_ELEM(si, struct stream *, si[0])->res;
}

/* returns the buffer which receives data from this stream interface (input channel's buffer) */
static inline struct buffer *si_ib(struct stream_interface *si)
{
	return &si_ic(si)->buf;
}

/* returns the buffer which feeds data to this stream interface (output channel's buffer) */
static inline struct buffer *si_ob(struct stream_interface *si)
{
	return &si_oc(si)->buf;
}

/* returns the stream associated to a stream interface */
static inline struct stream *si_strm(struct stream_interface *si)
{
	if (si->flags & SI_FL_ISBACK)
		return LIST_ELEM(si, struct stream *, si[1]);
	else
		return LIST_ELEM(si, struct stream *, si[0]);
}

/* returns the task associated to this stream interface */
static inline struct task *si_task(struct stream_interface *si)
{
	if (si->flags & SI_FL_ISBACK)
		return LIST_ELEM(si, struct stream *, si[1])->task;
	else
		return LIST_ELEM(si, struct stream *, si[0])->task;
}

/* returns the stream interface on the other side. Used during forwarding. */
static inline struct stream_interface *si_opposite(struct stream_interface *si)
{
	if (si->flags & SI_FL_ISBACK)
		return &LIST_ELEM(si, struct stream *, si[1])->si[0];
	else
		return &LIST_ELEM(si, struct stream *, si[0])->si[1];
}

/* initializes a stream interface in the SI_ST_INI state. It's detached from
 * any endpoint and only keeps its side which is expected to have already been
 * set.
 */
static inline int si_reset(struct stream_interface *si)
{
	si->err_type       = SI_ET_NONE;
	si->conn_retries   = 0;  /* used for logging too */
	si->exp            = TICK_ETERNITY;
	si->flags         &= SI_FL_ISBACK;
	si->end            = NULL;
	si->state          = si->prev_state = SI_ST_INI;
	si->ops            = &si_embedded_ops;
	si->wait_event.tasklet = tasklet_new();
	if (!si->wait_event.tasklet)
		return -1;
	si->wait_event.tasklet->process = si_cs_io_cb;
	si->wait_event.tasklet->context = si;
	si->wait_event.events = 0;
	return 0;
}

/* sets the current and previous state of a stream interface to <state>. This
 * is mainly used to create one in the established state on incoming
 * conncetions.
 */
static inline void si_set_state(struct stream_interface *si, int state)
{
	si->state = si->prev_state = state;
}

/* returns a bit for a stream-int state, to match against SI_SB_* */
static inline enum si_state_bit si_state_bit(enum si_state state)
{
	BUG_ON(state > SI_ST_CLO);
	return 1U << state;
}

/* returns true if <state> matches one of the SI_SB_* bits in <mask> */
static inline int si_state_in(enum si_state state, enum si_state_bit mask)
{
	BUG_ON(mask & ~SI_SB_ALL);
	return !!(si_state_bit(state) & mask);
}

/* only detaches the endpoint from the SI, which means that it's set to
 * NULL and that ->ops is mapped to si_embedded_ops. The previous endpoint
 * is returned.
 */
static inline enum obj_type *si_detach_endpoint(struct stream_interface *si)
{
	enum obj_type *prev = si->end;

	si->end = NULL;
	si->ops = &si_embedded_ops;
	return prev;
}

/* Release the endpoint if it's a connection or an applet, then nullify it.
 * Note: released connections are closed then freed.
 */
static inline void si_release_endpoint(struct stream_interface *si)
{
	struct connection *conn;
	struct conn_stream *cs;
	struct appctx *appctx;

	if (!si->end)
		return;

	if ((cs = objt_cs(si->end))) {
		if (si->wait_event.events != 0)
			cs->conn->mux->unsubscribe(cs, si->wait_event.events,
			    &si->wait_event);
		cs_destroy(cs);
	}
	else if ((appctx = objt_appctx(si->end))) {
		if (appctx->applet->release && !si_state_in(si->state, SI_SB_DIS|SI_SB_CLO))
			appctx->applet->release(appctx);
		appctx_free(appctx);
	} else if ((conn = objt_conn(si->end))) {
		conn_stop_tracking(conn);
		conn_full_close(conn);
		conn_free(conn);
	}
	si_detach_endpoint(si);
}

/* Attach conn_stream <cs> to the stream interface <si>. The stream interface
 * is configured to work with a connection and the connection it configured
 * with a stream interface data layer.
 */
static inline void si_attach_cs(struct stream_interface *si, struct conn_stream *cs)
{
	si->ops = &si_conn_ops;
	si->end = &cs->obj_type;
	cs_attach(cs, si, &si_conn_cb);
}

/* Returns true if a connection is attached to the stream interface <si> and
 * if this connection is ready.
 */
static inline int si_conn_ready(struct stream_interface *si)
{
	struct connection *conn = cs_conn(objt_cs(si->end));

	return conn && conn_ctrl_ready(conn) && conn_xprt_ready(conn);
}

/* Attach appctx <appctx> to the stream interface <si>. The stream interface
 * is configured to work with an applet context.
 */
static inline void si_attach_appctx(struct stream_interface *si, struct appctx *appctx)
{
	si->ops = &si_applet_ops;
	si->end = &appctx->obj_type;
	appctx->owner = si;
}

/* returns a pointer to the appctx being run in the SI, which must be valid */
static inline struct appctx *si_appctx(struct stream_interface *si)
{
	return __objt_appctx(si->end);
}

/* call the applet's release function if any. Needs to be called upon close() */
static inline void si_applet_release(struct stream_interface *si)
{
	struct appctx *appctx;

	appctx = objt_appctx(si->end);
	if (appctx && appctx->applet->release && !si_state_in(si->state, SI_SB_DIS|SI_SB_CLO))
		appctx->applet->release(appctx);
}

/* Returns non-zero if the stream interface's Rx path is blocked */
static inline int si_rx_blocked(const struct stream_interface *si)
{
	return !!(si->flags & SI_FL_RXBLK_ANY);
}

/* Returns non-zero if the stream interface's endpoint is ready to receive */
static inline int si_rx_endp_ready(const struct stream_interface *si)
{
	return !(si->flags & SI_FL_RX_WAIT_EP);
}

/* The stream interface announces it is ready to try to deliver more data to the input buffer */
static inline void si_rx_endp_more(struct stream_interface *si)
{
	si->flags &= ~SI_FL_RX_WAIT_EP;
}

/* The stream interface announces it doesn't have more data for the input buffer */
static inline void si_rx_endp_done(struct stream_interface *si)
{
	si->flags |=  SI_FL_RX_WAIT_EP;
}

/* Tell a stream interface the input channel is OK with it sending it some data */
static inline void si_rx_chan_rdy(struct stream_interface *si)
{
	si->flags &= ~SI_FL_RXBLK_CHAN;
}

/* Tell a stream interface the input channel is not OK with it sending it some data */
static inline void si_rx_chan_blk(struct stream_interface *si)
{
	si->flags |=  SI_FL_RXBLK_CHAN;
}

/* Tell a stream interface the other side is connected */
static inline void si_rx_conn_rdy(struct stream_interface *si)
{
	si->flags &= ~SI_FL_RXBLK_CONN;
}

/* Tell a stream interface it must wait for the other side to connect */
static inline void si_rx_conn_blk(struct stream_interface *si)
{
	si->flags |=  SI_FL_RXBLK_CONN;
}

/* The stream interface just got the input buffer it was waiting for */
static inline void si_rx_buff_rdy(struct stream_interface *si)
{
	si->flags &= ~SI_FL_RXBLK_BUFF;
}

/* The stream interface failed to get an input buffer and is waiting for it.
 * Since it indicates a willingness to deliver data to the buffer that will
 * have to be retried, we automatically clear RXBLK_ENDP to be called again
 * as soon as RXBLK_BUFF is cleared.
 */
static inline void si_rx_buff_blk(struct stream_interface *si)
{
	si->flags |=  SI_FL_RXBLK_BUFF;
}

/* Tell a stream interface some room was made in the input buffer */
static inline void si_rx_room_rdy(struct stream_interface *si)
{
	si->flags &= ~SI_FL_RXBLK_ROOM;
}

/* The stream interface announces it failed to put data into the input buffer
 * by lack of room. Since it indicates a willingness to deliver data to the
 * buffer that will have to be retried, we automatically clear RXBLK_ENDP to
 * be called again as soon as RXBLK_ROOM is cleared.
 */
static inline void si_rx_room_blk(struct stream_interface *si)
{
	si->flags |=  SI_FL_RXBLK_ROOM;
}

/* The stream interface announces it will never put new data into the input
 * buffer and that it's not waiting for its endpoint to deliver anything else.
 * This function obviously doesn't have a _rdy equivalent.
 */
static inline void si_rx_shut_blk(struct stream_interface *si)
{
	si->flags |=  SI_FL_RXBLK_SHUT;
}

/* Returns non-zero if the stream interface's Rx path is blocked */
static inline int si_tx_blocked(const struct stream_interface *si)
{
	return !!(si->flags & SI_FL_WAIT_DATA);
}

/* Returns non-zero if the stream interface's endpoint is ready to transmit */
static inline int si_tx_endp_ready(const struct stream_interface *si)
{
	return (si->flags & SI_FL_WANT_GET);
}

/* Report that a stream interface wants to get some data from the output buffer */
static inline void si_want_get(struct stream_interface *si)
{
	si->flags |= SI_FL_WANT_GET;
}

/* Report that a stream interface failed to get some data from the output buffer */
static inline void si_cant_get(struct stream_interface *si)
{
	si->flags |= SI_FL_WANT_GET | SI_FL_WAIT_DATA;
}

/* Report that a stream interface doesn't want to get data from the output buffer */
static inline void si_stop_get(struct stream_interface *si)
{
	si->flags &= ~SI_FL_WANT_GET;
}

/* Report that a stream interface won't get any more data from the output buffer */
static inline void si_done_get(struct stream_interface *si)
{
	si->flags &= ~(SI_FL_WANT_GET | SI_FL_WAIT_DATA);
}

/* Try to allocate a new conn_stream and assign it to the interface. If
 * an endpoint was previously allocated, it is released first. The newly
 * allocated conn_stream is initialized, assigned to the stream interface,
 * and returned.
 */
static inline struct conn_stream *si_alloc_cs(struct stream_interface *si, struct connection *conn)
{
	struct conn_stream *cs;

	si_release_endpoint(si);

	cs = cs_new(conn);
	if (cs)
		si_attach_cs(si, cs);

	return cs;
}

/* Try to allocate a buffer for the stream-int's input channel. It relies on
 * channel_alloc_buffer() for this so it abides by its rules. It returns 0 on
 * failure, non-zero otherwise. If no buffer is available, the requester,
 * represented by the <wait> pointer, will be added in the list of objects
 * waiting for an available buffer, and SI_FL_RXBLK_BUFF will be set on the
 * stream-int and SI_FL_RX_WAIT_EP cleared. The requester will be responsible
 * for calling this function to try again once woken up.
 */
static inline int si_alloc_ibuf(struct stream_interface *si, struct buffer_wait *wait)
{
	int ret;

	ret = channel_alloc_buffer(si_ic(si), wait);
	if (!ret)
		si_rx_buff_blk(si);
	return ret;
}

/* Release the interface's existing endpoint (connection or appctx) and
 * allocate then initialize a new appctx which is assigned to the interface
 * and returned. NULL may be returned upon memory shortage. Applet <applet>
 * is assigned to the appctx, but it may be NULL.
 */
static inline struct appctx *si_alloc_appctx(struct stream_interface *si, struct applet *applet)
{
	struct appctx *appctx;

	si_release_endpoint(si);
	appctx = appctx_new(applet, tid_bit);
	if (appctx) {
		si_attach_appctx(si, appctx);
		appctx->t->nice = si_strm(si)->task->nice;
	}

	return appctx;
}

/* Sends a shutr to the connection using the data layer */
static inline void si_shutr(struct stream_interface *si)
{
	si->ops->shutr(si);
}

/* Sends a shutw to the connection using the data layer */
static inline void si_shutw(struct stream_interface *si)
{
	si->ops->shutw(si);
}

/* Marks on the stream-interface that next shutw must kill the whole connection */
static inline void si_must_kill_conn(struct stream_interface *si)
{
	si->flags |= SI_FL_KILL_CONN;
}

/* This is to be used after making some room available in a channel. It will
 * return without doing anything if the stream interface's RX path is blocked.
 * It will automatically mark the stream interface as busy processing the end
 * point in order to avoid useless repeated wakeups.
 * It will then call ->chk_rcv() to enable receipt of new data.
 */
static inline void si_chk_rcv(struct stream_interface *si)
{
	if (si->flags & SI_FL_RXBLK_CONN && si_state_in(si_opposite(si)->state, SI_SB_RDY|SI_SB_EST|SI_SB_DIS|SI_SB_CLO))
		si_rx_conn_rdy(si);

	if (si_rx_blocked(si) || !si_rx_endp_ready(si))
		return;

	if (!si_state_in(si->state, SI_SB_RDY|SI_SB_EST))
		return;

	si->flags |= SI_FL_RX_WAIT_EP;
	si->ops->chk_rcv(si);
}

/* This tries to perform a synchronous receive on the stream interface to
 * try to collect last arrived data. In practice it's only implemented on
 * conn_streams. Returns 0 if nothing was done, non-zero if new data or a
 * shutdown were collected. This may result on some delayed receive calls
 * to be programmed and performed later, though it doesn't provide any
 * such guarantee.
 */
static inline int si_sync_recv(struct stream_interface *si)
{
	struct conn_stream *cs;

	if (!si_state_in(si->state, SI_SB_RDY|SI_SB_EST))
		return 0;

	cs = objt_cs(si->end);
	if (!cs)
		return 0; // only conn_streams are supported

	if (si->wait_event.events & SUB_RETRY_RECV)
		return 0; // already subscribed

	if (!si_rx_endp_ready(si) || si_rx_blocked(si))
		return 0; // already failed

	return si_cs_recv(cs);
}

/* Calls chk_snd on the connection using the data layer */
static inline void si_chk_snd(struct stream_interface *si)
{
	si->ops->chk_snd(si);
}

/* Calls chk_snd on the connection using the ctrl layer */
static inline int si_connect(struct stream_interface *si, struct connection *conn)
{
	int ret = SF_ERR_NONE;
	int conn_flags = 0;

	if (unlikely(!conn || !conn->ctrl || !conn->ctrl->connect))
		return SF_ERR_INTERNAL;

	if (!channel_is_empty(si_oc(si)))
		conn_flags |= CONNECT_HAS_DATA;
	if (si->conn_retries == si_strm(si)->be->conn_retries)
		conn_flags |= CONNECT_CAN_USE_TFO;
	if (!conn_ctrl_ready(conn) || !conn_xprt_ready(conn)) {
		ret = conn->ctrl->connect(conn, conn_flags);
		if (ret != SF_ERR_NONE)
			return ret;

		/* we're in the process of establishing a connection */
		si->state = SI_ST_CON;
	}
	else {
		/* try to reuse the existing connection, it will be
		 * confirmed once we can send on it.
		 */
		/* Is the connection really ready ? */
		if (conn->mux->ctl(conn, MUX_STATUS, NULL) & MUX_STATUS_READY)
			si->state = SI_ST_RDY;
		else
			si->state = SI_ST_CON;
	}

	/* needs src ip/port for logging */
	if (si->flags & SI_FL_SRC_ADDR)
		conn_get_src(conn);

	return ret;
}

/* Combines both si_update_rx() and si_update_tx() at once */
static inline void si_update(struct stream_interface *si)
{
	si_update_rx(si);
	si_update_tx(si);
}

/* Returns info about the conn_stream <cs>, if not NULL. It call the mux layer's
 * get_cs_info() function, if it exists. On success, it returns a cs_info
 * structure. Otherwise, on error, if the mux does not implement get_cs_info()
 * or if conn_stream is NULL, NULL is returned.
 */
static inline const struct cs_info *si_get_cs_info(struct conn_stream *cs)
{
	if (cs && cs->conn->mux->get_cs_info)
		return cs->conn->mux->get_cs_info(cs);
	return NULL;
}

/* for debugging, reports the stream interface state name */
static inline const char *si_state_str(int state)
{
	switch (state) {
	case SI_ST_INI: return "INI";
	case SI_ST_REQ: return "REQ";
	case SI_ST_QUE: return "QUE";
	case SI_ST_TAR: return "TAR";
	case SI_ST_ASS: return "ASS";
	case SI_ST_CON: return "CON";
	case SI_ST_CER: return "CER";
	case SI_ST_RDY: return "RDY";
	case SI_ST_EST: return "EST";
	case SI_ST_DIS: return "DIS";
	case SI_ST_CLO: return "CLO";
	default:        return "???";
	}
}

#endif /* _PROTO_STREAM_INTERFACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
