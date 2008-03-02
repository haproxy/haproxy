/*
  include/proto/dumpstats.h
  This file contains definitions of some primitives to dedicated to
  statistics output.

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

#ifndef _PROTO_DUMPSTATS_H
#define _PROTO_DUMPSTATS_H

#include <common/config.h>
#include <types/buffers.h>
#include <types/session.h>

#define STAT_FMT_HTML  0x1
#define STAT_SHOW_STAT 0x2
#define STAT_SHOW_INFO 0x4

#define STATS_TYPE_FE  0
#define STATS_TYPE_BE  1
#define STATS_TYPE_SV  2

int stats_parse_global(const char **args, char *err, int errlen);
int stats_dump_raw(struct session *s, struct uri_auth *uri, int flags);
int stats_dump_http(struct session *s, struct uri_auth *uri, int flags);
int stats_dump_proxy(struct session *s, struct proxy *px, struct uri_auth *uri, int flags);


#endif /* _PROTO_DUMPSTATS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
