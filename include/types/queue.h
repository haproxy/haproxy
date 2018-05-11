/*
  include/types/queue.h
  This file defines variables and structures needed for queues.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
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

#ifndef _TYPES_QUEUE_H
#define _TYPES_QUEUE_H

#include <common/config.h>
#include <common/mini-clist.h>
#include <common/hathreads.h>

#include <types/server.h>

struct stream;

struct pendconn {
	int            strm_flags; /* stream flags */
	unsigned int   queue_idx;  /* value of proxy/server queue_idx at time of enqueue */
	struct stream *strm;
	struct proxy  *px;
	struct server *srv;        /* the server we are waiting for, may be NULL if don't care */
	struct server *target;     /* the server that was assigned, = srv except if srv==NULL */
	struct eb32_node node;
};

#endif /* _TYPES_QUEUE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
