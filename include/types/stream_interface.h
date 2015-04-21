/*
 * include/types/stream_interface.h
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

#ifndef _TYPES_STREAM_INTERFACE_H
#define _TYPES_STREAM_INTERFACE_H

#include <types/obj_type.h>
#include <common/config.h>

/* A stream interface must have its own errors independently of the buffer's,
 * so that applications can rely on what the buffer reports while the stream
 * interface is performing some retries (eg: connection error). Some states are
 * transient and do not last beyond process_session().
 */
enum si_state {
	SI_ST_INI = 0,           /* interface not sollicitated yet */
	SI_ST_REQ,               /* [transient] connection initiation desired and not started yet */
	SI_ST_QUE,               /* interface waiting in queue */
	SI_ST_TAR,               /* interface in turn-around state after failed connect attempt */
	SI_ST_ASS,               /* server just assigned to this interface */
	SI_ST_CON,               /* initiated connection request (resource exists) */
	SI_ST_CER,               /* [transient] previous connection attempt failed (resource released) */
	SI_ST_EST,               /* connection established (resource exists) */
	SI_ST_DIS,               /* [transient] disconnected from other side, but cleanup not done yet */
	SI_ST_CLO,               /* stream intf closed, might not existing anymore. Buffers shut. */
} __attribute__((packed));

/* error types reported on the streams interface for more accurate reporting */
enum {
	SI_ET_NONE       = 0x0000,  /* no error yet, leave it to zero */
	SI_ET_QUEUE_TO   = 0x0001,  /* queue timeout */
	SI_ET_QUEUE_ERR  = 0x0002,  /* queue error (eg: full) */
	SI_ET_QUEUE_ABRT = 0x0004,  /* aborted in queue by external cause */
	SI_ET_CONN_TO    = 0x0008,  /* connection timeout */
	SI_ET_CONN_ERR   = 0x0010,  /* connection error (eg: no server available) */
	SI_ET_CONN_ABRT  = 0x0020,  /* connection aborted by external cause (eg: abort) */
	SI_ET_CONN_RES   = 0x0040,  /* connection aborted due to lack of resources */
	SI_ET_CONN_OTHER = 0x0080,  /* connection aborted for other reason (eg: 500) */
	SI_ET_DATA_TO    = 0x0100,  /* timeout during data phase */
	SI_ET_DATA_ERR   = 0x0200,  /* error during data phase */
	SI_ET_DATA_ABRT  = 0x0400,  /* data phase aborted by external cause */
};

/* flags set after I/O (16 bit) */
enum {
	SI_FL_NONE       = 0x0000,  /* nothing */
	SI_FL_EXP        = 0x0001,  /* timeout has expired */
	SI_FL_ERR        = 0x0002,  /* a non-recoverable error has occurred */
	SI_FL_WAIT_ROOM  = 0x0004,  /* waiting for space to store incoming data */
	SI_FL_WAIT_DATA  = 0x0008,  /* waiting for more data to send */
	SI_FL_ISBACK     = 0x0010,  /* 0 for front-side SI, 1 for back-side */
	SI_FL_DONT_WAKE  = 0x0020,  /* resync in progress, don't wake up */
	SI_FL_INDEP_STR  = 0x0040,  /* independent streams = don't update rex on write */
	SI_FL_NOLINGER   = 0x0080,  /* may close without lingering. One-shot. */
	SI_FL_NOHALF     = 0x0100,  /* no half close, close both sides at once */
	SI_FL_SRC_ADDR   = 0x1000,  /* get the source ip/port with getsockname */
	SI_FL_WANT_PUT   = 0x2000,  /* an applet would like to put some data into the buffer */
	SI_FL_WANT_GET   = 0x4000,  /* an applet would like to get some data from the buffer */
};

/* A stream interface has 3 parts :
 *  - the buffer side, which interfaces to the buffers.
 *  - the remote side, which describes the state and address of the other side.
 *  - the functions, which are used by the buffer side to communicate with the
 *    remote side from the buffer side.
 */

/* Note that if an applet is registered, the update function will not be called
 * by the session handler, so it may be used to resync flags at the end of the
 * applet handler. See stream_int_update_embedded() for reference.
 */
struct stream_interface {
	/* struct members used by the "buffer" side */
	enum si_state state;     /* SI_ST* */
	enum si_state prev_state;/* SI_ST*, copy of previous state */
	unsigned short flags;    /* SI_FL_* */
	unsigned int exp;       /* wake up time for connect, queue, turn-around, ... */
	enum obj_type *end;     /* points to the end point (connection or appctx) */
	struct si_ops *ops;     /* general operations at the stream interface layer */

	/* struct members below are the "remote" part, as seen from the buffer side */
	unsigned int err_type;  /* first error detected, one of SI_ET_* */
	int conn_retries;	/* number of connect retries left */
};

/* operations available on a stream-interface */
struct si_ops {
	void (*update)(struct stream_interface *);  /* I/O update function */
	void (*chk_rcv)(struct stream_interface *); /* chk_rcv function */
	void (*chk_snd)(struct stream_interface *); /* chk_snd function */
	void (*shutr)(struct stream_interface *);   /* shut read function */
	void (*shutw)(struct stream_interface *);   /* shut write function */
};

#endif /* _TYPES_STREAM_INTERFACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
