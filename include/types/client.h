/*
  include/types/client.h
  This file contains client-side definitions.

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

#ifndef _TYPES_CLIENT_H
#define _TYPES_CLIENT_H

/*
 * FIXME: break this into HTTP state and TCP socket state.
 * See server.h for the other end.
 */

/* different possible states for the client side */
#define CL_STHEADERS	0
#define CL_STDATA	1
#define CL_STSHUTR	2
#define CL_STSHUTW	3
#define CL_STCLOSE	4


#endif /* _TYPES_CLIENT_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
