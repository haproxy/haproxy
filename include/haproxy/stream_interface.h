/*
 * include/haproxy/stream_interface.h
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

#ifndef _HAPROXY_STREAM_INTERFACE_H
#define _HAPROXY_STREAM_INTERFACE_H

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/channel.h>
#include <haproxy/connection.h>
#include <haproxy/conn_stream.h>
#include <haproxy/obj_type.h>

extern struct data_cb cs_data_conn_cb;
extern struct data_cb cs_data_applet_cb;
extern struct data_cb check_conn_cb;

struct stream_interface *si_new(struct conn_stream *cs);
void si_free(struct stream_interface *si);

/* main event functions used to move data between sockets and buffers */
int cs_applet_process(struct conn_stream *cs);
struct task *cs_conn_io_cb(struct task *t, void *ctx, unsigned int state);
int cs_conn_sync_recv(struct conn_stream *cs);
void cs_conn_sync_send(struct conn_stream *cs);

/* Functions used to communicate with a conn_stream. The first two may be used
 * directly, the last one is mostly a wake callback.
 */
int cs_conn_recv(struct conn_stream *cs);
int cs_conn_send(struct conn_stream *cs);
int cs_conn_process(struct conn_stream *cs);

/* initializes a stream interface and create the event
 * tasklet.
 */
static inline int si_init(struct stream_interface *si)
{
	si->flags         &= SI_FL_ISBACK;
	si->cs             = NULL;
	return 0;
}

/* Returns non-zero if the stream interface's Rx path is blocked */
static inline int si_rx_blocked(const struct stream_interface *si)
{
	return !!(si->flags & SI_FL_RXBLK_ANY);
}


/* Returns non-zero if the stream interface's Rx path is blocked because of lack
 * of room in the input buffer.
 */
static inline int si_rx_blocked_room(const struct stream_interface *si)
{
	return !!(si->flags & SI_FL_RXBLK_ROOM);
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

#endif /* _HAPROXY_STREAM_INTERFACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
