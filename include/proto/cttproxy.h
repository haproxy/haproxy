/*
  include/proto/cttproxy.h
  This file contains prototypes for Linux's cttproxy interface.
  This file should be included only if CTTPROXY is enabled.

  Copyright (C) 2000-2007 Willy Tarreau - w@1wt.eu
  
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

#ifndef _PROTO_CTTPROXY_H
#define _PROTO_CTTPROXY_H

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <common/config.h>
#include <import/ip_tproxy.h>

/*
 * Checks that CTTPROXY is available and in the right version.
 * Returns 0 if OK, -1 if wrong version, -2 if not available or other error.
 */
int check_cttproxy_version();


#endif /* _PROTO_CTTPROXY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
