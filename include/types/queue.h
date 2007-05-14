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

#include <types/server.h>
#include <types/session.h>

struct pendconn {
	struct list list;		/* chaining ... */
	struct session *sess;		/* the session waiting for a connection */
	struct server *srv;		/* the server we are waiting for */
};

#endif /* _TYPES_QUEUE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
