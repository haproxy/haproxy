/*
  include/types/proto_http.h
  This file contains HTTP protocol definitions.

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

#ifndef _TYPES_PROTO_HTTP_H
#define _TYPES_PROTO_HTTP_H


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

/*
 * FIXME: break this into HTTP state and TCP socket state.
 * See client.h for the other end.
 */

/* different possible states for the server side */
#define SV_STIDLE	0
#define SV_STCONN	1
#define SV_STHEADERS	2
#define SV_STDATA	3
#define SV_STSHUTR	4
#define SV_STSHUTW	5
#define SV_STCLOSE	6


#endif /* _TYPES_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
