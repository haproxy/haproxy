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

#define GET_NEXT_OFF(range, off) ((off) == (range)->size - 1 ? 0 : (off) + 1)

/* return an available port from range <range>, or zero if none is left */
static inline int port_range_alloc_port(struct port_range *range)
{
	int ret;
	int get;
	int put;

	get = _HA_ATOMIC_LOAD(&range->get);
	do {
		/* barrier ot make sure get is loaded before put */
		__ha_barrier_atomic_load();
		put = _HA_ATOMIC_LOAD(&range->put_t);
		if (unlikely(put == get))
			return 0;
		ret = range->ports[get];
	} while (!(_HA_ATOMIC_CAS(&range->get, &get, GET_NEXT_OFF(range, get))));
	return ret;
}

/* release port <port> into port range <range>. Does nothing if <port> is zero
 * nor if <range> is null. The caller is responsible for marking the port
 * unused by either setting the port to zero or the range to NULL.
 */
static inline void port_range_release_port(struct port_range *range, int port)
{
	int put;

	if (!port || !range)
		return;

	put = range->put_h;
	/* put_h is reserved for producers, so that they can each get a
	 * free slot, put_t is what is used by consumers to know if there's
	 * elements available or not
	 */
	/* First reserve or slot, we know the ring buffer can't be full,
	 * as we will only ever release port we allocated before
	 */
	while (!(_HA_ATOMIC_CAS(&range->put_h, &put, GET_NEXT_OFF(range, put))));
	_HA_ATOMIC_STORE(&range->ports[put], port);
	/* Barrier to make sure the new port is visible before we change put_t */
	__ha_barrier_atomic_store();
	/* Wait until all the threads that got a slot before us are done */
	while ((volatile int)range->put_t != put)
		__ha_compiler_barrier();
	/* Let the world know we're done, and any potential consumer they
	 * can use that port.
	 */
	_HA_ATOMIC_STORE(&range->put_t, GET_NEXT_OFF(range, put));
}

/* return a new initialized port range of N ports. The ports are not
 * filled in, it's up to the caller to do it.
 */
static inline struct port_range *port_range_alloc_range(int n)
{
	struct port_range *ret;
	ret = calloc(1, sizeof(struct port_range) +
		     (n + 1) * sizeof(((struct port_range *)0)->ports[0]));
	ret->size = n + 1;
	/* Start at the first free element */
	ret->put_h = ret->put_t = n;
	return ret;
}

#endif /* _PROTO_PORT_RANGE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
