/*
 * include/proto/dumpstats.h
 * This file contains definitions of some primitives to dedicated to
 * statistics output.
 *
 * Copyright (C) 2000-2011 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _PROTO_DUMPSTATS_H
#define _PROTO_DUMPSTATS_H

#include <common/config.h>
#include <types/stream_interface.h>

/* Flags for applet.ctx.stats.flags */
#define STAT_FMT_HTML   0x00000001      /* dump the stats in HTML format */
#define STAT_HIDE_DOWN  0x00000008	/* hide 'down' servers in the stats page */
#define STAT_NO_REFRESH 0x00000010	/* do not automatically refresh the stats page */
#define STAT_ADMIN      0x00000020	/* indicate a stats admin level */
#define STAT_CHUNKED    0x00000040      /* use chunked encoding (HTTP/1.1) */
#define STAT_BOUND      0x00800000	/* bound statistics to selected proxies/types/services */

#define STATS_TYPE_FE  0
#define STATS_TYPE_BE  1
#define STATS_TYPE_SV  2
#define STATS_TYPE_SO  3

/* HTTP stats : applet.st0 */
enum {
	STAT_HTTP_DONE = 0,  /* finished */
	STAT_HTTP_HEAD,      /* send headers before dump */
	STAT_HTTP_DUMP,      /* dumping stats */
	STAT_HTTP_POST,      /* waiting post data */
	STAT_HTTP_LAST,      /* sending last chunk of response */
};

/* HTML form to limit output scope */
#define STAT_SCOPE_TXT_MAXLEN 20      /* max len for scope substring */
#define STAT_SCOPE_INPUT_NAME "scope" /* pattern form scope name <input> in html form */
#define STAT_SCOPE_PATTERN    "?" STAT_SCOPE_INPUT_NAME "="

extern struct si_applet http_stats_applet;

void stats_io_handler(struct stream_interface *si);


#endif /* _PROTO_DUMPSTATS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
