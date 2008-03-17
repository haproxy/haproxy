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

/* Flags for session->data_ctx.stats.flags */
#define STAT_FMT_CSV    0x00000001	/* dump the stats in CSV format instead of HTML */
#define STAT_SHOW_STAT  0x00000002	/* dump the stats part */
#define STAT_SHOW_INFO  0x00000004	/* dump the info part */
#define STAT_HIDE_DOWN  0x00000008	/* hide 'down' servers in the stats page */
#define STAT_NO_REFRESH 0x00000010	/* do not automatically refresh the stats page */

int stats_parse_global(const char **args, char *err, int errlen);
int stats_dump_raw(struct session *s, struct uri_auth *uri);
int stats_dump_http(struct session *s, struct uri_auth *uri);
int stats_dump_proxy(struct session *s, struct proxy *px, struct uri_auth *uri);


#endif /* _PROTO_DUMPSTATS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
