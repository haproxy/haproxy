/*
  include/proto/port_range.h
  This file defines everything needed to manage port ranges

  Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu
  
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

#ifndef _PROTO_PORT_RANGE_H
#define _PROTO_PORT_RANGE_H

#include <types/port_range.h>

/* return an available port from range <range>, or zero if none is left */
static inline int port_range_alloc_port(struct port_range *range)
{
	int ret;

	if (!range->avail)
		return 0;
	ret = range->ports[range->get];
	range->get++;
	if (range->get >= range->size)
		range->get = 0;
	range->avail--;
	return ret;
}

/* release port <port> into port range <range>. Does nothing if <port> is zero
 * nor if <range> is null. The caller is responsible for marking the port
 * unused by either setting the port to zero or the range to NULL.
 */
static inline void port_range_release_port(struct port_range *range, int port)
{
	if (!port || !range)
		return;

	range->ports[range->put] = port;
	range->avail++;
	range->put++;
	if (range->put >= range->size)
		range->put = 0;
}

/* return a new initialized port range of N ports. The ports are not
 * filled in, it's up to the caller to do it.
 */
static inline struct port_range *port_range_alloc_range(int n)
{
	struct port_range *ret;
	ret = calloc(1, sizeof(struct port_range) +
		     n * sizeof(((struct port_range *)0)->ports[0]));
	ret->size = ret->avail = n;
	return ret;
}

#endif /* _PROTO_PORT_RANGE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
