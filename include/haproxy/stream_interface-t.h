/*
 * include/haproxy/stream_interface-t.h
 * This file describes the stream_interface struct and associated constants.
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

#ifndef _HAPROXY_STREAM_INTERFACE_T_H
#define _HAPROXY_STREAM_INTERFACE_T_H

#include <haproxy/api-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/connection-t.h>

struct conn_stream;

/* flags set after I/O (32 bit) */
enum {
	SI_FL_NONE       = 0x00000000,  /* nothing */
	/* unused: 0x00000001, 0x00000002 */
	SI_FL_WAIT_DATA  = 0x00000008,  /* stream-int waits for more outgoing data to send */
	SI_FL_ISBACK     = 0x00000010,  /* 0 for front-side SI, 1 for back-side */
	/* unused: 0x00000200 */
	SI_FL_WANT_GET   = 0x00004000,  /* a stream-int would like to get some data from the buffer */

	SI_FL_RXBLK_CHAN = 0x00010000,  /* the channel doesn't want the stream-int to introduce data */
	SI_FL_RXBLK_BUFF = 0x00020000,  /* stream-int waits for a buffer allocation to complete */
	SI_FL_RXBLK_ROOM = 0x00040000,  /* stream-int waits for more buffer room to store incoming data */
	SI_FL_RXBLK_SHUT = 0x00080000,  /* input is now closed, nothing new will ever come */
	SI_FL_RXBLK_CONN = 0x00100000,  /* other side is not connected */
	SI_FL_RXBLK_ANY  = 0x001F0000,  /* any of the RXBLK flags above */
	SI_FL_RX_WAIT_EP = 0x00200000,  /* stream-int waits for more data from the end point */
};

/* A stream interface has 3 parts :
 *  - the buffer side, which interfaces to the buffers.
 *  - the remote side, which describes the state and address of the other side.
 *  - the functions, which are used by the buffer side to communicate with the
 *    remote side from the buffer side.
 */

/* Note that if an applet is registered, the update function will not be called
 * by the session handler, so it may be used to resync flags at the end of the
 * applet handler. See si_update() for reference.
 */
struct stream_interface {
	/* struct members used by the "buffer" side */
	/* 16-bit hole here */
	unsigned int flags;     /* SI_FL_* */
	struct conn_stream *cs; /* points to the conn-streams that owns the endpoint (connection or applet) */
	struct si_ops *ops;     /* general operations at the stream interface layer */

	struct wait_event wait_event; /* We're in a wait list */
};

/* operations available on a stream-interface */
struct si_ops {
	void (*chk_rcv)(struct stream_interface *); /* chk_rcv function, may not be null */
	void (*chk_snd)(struct stream_interface *); /* chk_snd function, may not be null */
	void (*shutr)(struct stream_interface *);   /* shut read function, may not be null */
	void (*shutw)(struct stream_interface *);   /* shut write function, may not be null */
};

#endif /* _HAPROXY_STREAM_INTERFACE_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
