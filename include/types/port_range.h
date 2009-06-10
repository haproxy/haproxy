/*
  include/types/port_range.h
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

#ifndef _TYPES_PORT_RANGE_H
#define _TYPES_PORT_RANGE_H

#include <netinet/in.h>

struct port_range {
	int size, get, put;		/* range size, and get/put positions */
	int avail;			/* number of available ports left */
	uint16_t ports[0];		/* array of <size> ports, in host byte order */
};

#endif /* _TYPES_PORT_RANGE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
