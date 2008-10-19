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

#include <common/config.h>

/* A stream interface must have its own errors independantly of the buffer's,
 * so that applications can rely on what the buffer reports while the stream
 * interface is performing some retries (eg: connection error).
 */
enum {
	SI_ST_INI = 0,           /* interface not initialized yet and might not exist */
	SI_ST_QUE,               /* interface waiting in queue */
	SI_ST_TAR,               /* interface in turn-around state after failed connect attempt */
	SI_ST_ASS,               /* server just assigned to this interface */
	SI_ST_CON,               /* initiated connection request (resource exists) */
	SI_ST_EST,               /* connection established (resource exists) */
	SI_ST_CLO,               /* stream interface closed, might not existing anymore */
};

/* error types reported on the streams interface for more accurate reporting */
enum {
	SI_ET_NONE = 0,         /* no error yet, leave it to zero */
	SI_ET_QUEUE_TO,         /* queue timeout */
	SI_ET_QUEUE_ERR,        /* queue error (eg: full) */
	SI_ET_QUEUE_ABRT,       /* aborted in queue by external cause */
	SI_ET_CONN_TO,          /* connection timeout */
	SI_ET_CONN_ERR,         /* connection error (eg: no server available) */
	SI_ET_CONN_ABRT,        /* connection aborted by external cause (eg: abort) */
	SI_ET_CONN_OTHER,       /* connection aborted for other reason (eg: 500) */
	SI_ET_DATA_TO,          /* timeout during data phase */
	SI_ET_DATA_ERR,         /* error during data phase */
	SI_ET_DATA_ABRT,        /* data phase aborted by external cause */
};

struct stream_interface {
	unsigned int state;     /* SI_ST* */
	int err_type;           /* first error detected, one of SI_ET_* */
	void *err_loc;          /* commonly the server, NULL when SI_ET_NONE */
	int fd;                 /* file descriptor for a stream driver when known */
};


#endif /* _TYPES_STREAM_INTERFACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
