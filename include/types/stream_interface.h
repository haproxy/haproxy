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
	SI_ST_RDY,               /* [transient] ready proven after I/O success during SI_ST_CON */
	SI_ST_EST,               /* connection established (resource exists) */
	SI_ST_DIS,               /* [transient] disconnected from other side, but cleanup not done yet */
	SI_ST_CLO,               /* stream intf closed, might not existing anymore. Buffers shut. */
} __attribute__((packed));

/* state bits for use with lists of states */
enum si_state_bit {
	SI_SB_NONE = 0,
	SI_SB_INI = 1U << SI_ST_INI,
	SI_SB_REQ = 1U << SI_ST_REQ,
	SI_SB_QUE = 1U << SI_ST_QUE,
	SI_SB_TAR = 1U << SI_ST_TAR,
	SI_SB_ASS = 1U << SI_ST_ASS,
	SI_SB_CON = 1U << SI_ST_CON,
	SI_SB_CER = 1U << SI_ST_CER,
	SI_SB_RDY = 1U << SI_ST_RDY,
	SI_SB_EST = 1U << SI_ST_EST,
	SI_SB_DIS = 1U << SI_ST_DIS,
	SI_SB_CLO = 1U << SI_ST_CLO,
	SI_SB_ALL = SI_SB_INI|SI_SB_REQ|SI_SB_QUE|SI_SB_TAR|SI_SB_ASS|SI_SB_CON|SI_SB_CER|SI_SB_RDY|SI_SB_EST|SI_SB_DIS|SI_SB_CLO,
};

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

/* flags set after I/O (32 bit) */
enum {
	SI_FL_NONE       = 0x00000000,  /* nothing */
	SI_FL_EXP        = 0x00000001,  /* timeout has expired */
	SI_FL_ERR        = 0x00000002,  /* a non-recoverable error has occurred */
	SI_FL_KILL_CONN  = 0x00000004,  /* next shutw must kill the whole conn, not just the stream */
	SI_FL_WAIT_DATA  = 0x00000008,  /* stream-int waits for more outgoing data to send */
	SI_FL_ISBACK     = 0x00000010,  /* 0 for front-side SI, 1 for back-side */
	SI_FL_DONT_WAKE  = 0x00000020,  /* resync in progress, don't wake up */
	SI_FL_INDEP_STR  = 0x00000040,  /* independent streams = don't update rex on write */
	SI_FL_NOLINGER   = 0x00000080,  /* may close without lingering. One-shot. */
	SI_FL_NOHALF     = 0x00000100,  /* no half close, close both sides at once */
	SI_FL_SRC_ADDR   = 0x00001000,  /* get the source ip/port with getsockname */
	/* unused: 0x00000200 */
	SI_FL_WANT_GET   = 0x00004000,  /* a stream-int would like to get some data from the buffer */
	SI_FL_CLEAN_ABRT = 0x00008000,  /* SI_FL_ERR is used to report aborts, and not SHUTR */

	SI_FL_RXBLK_CHAN = 0x00010000,  /* the channel doesn't want the stream-int to introduce data */
	SI_FL_RXBLK_BUFF = 0x00020000,  /* stream-int waits for a buffer allocation to complete */
	SI_FL_RXBLK_ROOM = 0x00040000,  /* stream-int waits for more buffer room to store incoming data */
	SI_FL_RXBLK_SHUT = 0x00080000,  /* input is now closed, nothing new will ever come */
	SI_FL_RXBLK_CONN = 0x00100000,  /* other side is not connected */
	SI_FL_RXBLK_ANY  = 0x001F0000,  /* any of the RXBLK flags above */
	SI_FL_RX_WAIT_EP = 0x00200000,  /* stream-int waits for more data from the end point */
	SI_FL_L7_RETRY   = 0x01000000,  /* The stream interface may attempt L7 retries */
	SI_FL_D_L7_RETRY = 0x02000000,  /* Disable L7 retries on this stream interface, even if configured to do it */
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
	enum si_state state;     /* SI_ST* */
	enum si_state prev_state;/* SI_ST*, copy of previous state */
	/* 16-bit hole here */
	unsigned int flags;     /* SI_FL_* */
	enum obj_type *end;     /* points to the end point (connection or appctx) */
	struct si_ops *ops;     /* general operations at the stream interface layer */
	unsigned int exp;       /* wake up time for connect, queue, turn-around, ... */

	/* struct members below are the "remote" part, as seen from the buffer side */
	unsigned int err_type;  /* first error detected, one of SI_ET_* */
	int conn_retries;	/* number of connect retries left */
	unsigned int hcto;      /* half-closed timeout (0 = unset) */
	struct wait_event wait_event; /* We're in a wait list */
	struct buffer l7_buffer; /* To store the data, in case we have to retry */
};

/* operations available on a stream-interface */
struct si_ops {
	void (*chk_rcv)(struct stream_interface *); /* chk_rcv function, may not be null */
	void (*chk_snd)(struct stream_interface *); /* chk_snd function, may not be null */
	void (*shutr)(struct stream_interface *);   /* shut read function, may not be null */
	void (*shutw)(struct stream_interface *);   /* shut write function, may not be null */
};

#endif /* _TYPES_STREAM_INTERFACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
