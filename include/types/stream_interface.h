/*
  include/types/stream_interface.h
  This file describes the stream_interface struct and associated constants.

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _TYPES_STREAM_INTERFACE_H
#define _TYPES_STREAM_INTERFACE_H

#include <stdlib.h>

#include <types/buffers.h>
#include <common/config.h>

/* A stream interface must have its own errors independantly of the buffer's,
 * so that applications can rely on what the buffer reports while the stream
 * interface is performing some retries (eg: connection error). Some states are
 * transient and do not last beyond process_session().
 */
enum {
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
	SI_ET_CONN_OTHER = 0x0040,  /* connection aborted for other reason (eg: 500) */
	SI_ET_DATA_TO    = 0x0080,  /* timeout during data phase */
	SI_ET_DATA_ERR   = 0x0100,  /* error during data phase */
	SI_ET_DATA_ABRT  = 0x0200,  /* data phase aborted by external cause */
};

/* flags set after I/O */
enum {
	SI_FL_NONE       = 0x0000,  /* nothing */
	SI_FL_EXP        = 0x0001,  /* timeout has expired */
	SI_FL_ERR        = 0x0002,  /* a non-recoverable error has occurred */
	SI_FL_WAIT_ROOM  = 0x0004,  /* waiting for space to store incoming data */
	SI_FL_WAIT_DATA  = 0x0008,  /* waiting for more data to send */
	SI_FL_CAP_SPLTCP = 0x0010,  /* splicing possible from/to TCP */
};

#define SI_FL_CAP_SPLICE (SI_FL_CAP_SPLTCP)

struct server;
struct proxy;

struct stream_interface {
	unsigned int state;     /* SI_ST* */
	unsigned int prev_state;/* SI_ST*, copy of previous state */
	void *owner;            /* generally a (struct task*) */
	int fd;                 /* file descriptor for a stream driver when known */
	unsigned int flags;
	unsigned int exp;       /* wake up time for connect, queue, turn-around, ... */
	int (*connect)(struct stream_interface *, struct proxy *, struct server *,
		       struct sockaddr *, struct sockaddr *); /* connect function if any */
	void (*shutr)(struct stream_interface *);  /* shutr function */
	void (*shutw)(struct stream_interface *);  /* shutw function */
	void (*chk_rcv)(struct stream_interface *);/* chk_rcv function */
	void (*chk_snd)(struct stream_interface *);/* chk_snd function */
	struct buffer *ib, *ob; /* input and output buffers */
	unsigned int err_type;  /* first error detected, one of SI_ET_* */
	void *err_loc;          /* commonly the server, NULL when SI_ET_NONE */
};


#endif /* _TYPES_STREAM_INTERFACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
