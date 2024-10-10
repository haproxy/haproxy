/*
 * include/haproxy/sink.h
 * This file provides declarations for event sinks management
 *
 * Copyright (C) 2000-2019 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_SINK_H
#define _HAPROXY_SINK_H

#include <sys/types.h>
#include <haproxy/sink-t.h>
#include <haproxy/thread.h>

extern struct list sink_list;

extern struct proxy *sink_proxies_list;

struct sink *sink_find(const char *name);
struct sink *sink_find_early(const char *name, const char *from, const char *file, int line);
struct sink *sink_new_fd(const char *name, const char *desc, enum log_fmt, int fd);
ssize_t __sink_write(struct sink *sink, struct log_header hdr, size_t maxlen,
                     const struct ist msg[], size_t nmsg);
int sink_announce_dropped(struct sink *sink, struct log_header hdr);


/* tries to send <nmsg> message parts from message array <msg> to sink <sink>.
 * Formatting according to the sink's preference is done here, unless sink->fmt
 * is unspecified, in which case the caller formatting will be used instead.
 *
 * It will stop writing at <maxlen> instead of sink->maxlen if <maxlen> is
 * positive and inferior to sink->maxlen.
 *
 * Lost messages are accounted for in the sink's counter. If there
 * were lost messages, an attempt is first made to indicate it.
 * The function returns the number of Bytes effectively sent or announced.
 * or <= 0 in other cases.
 */
static inline ssize_t sink_write(struct sink *sink, struct log_header hdr,
                                 size_t maxlen, const struct ist msg[], size_t nmsg)
{
	ssize_t sent = 0;

	if (unlikely(HA_ATOMIC_LOAD(&sink->ctx.dropped) > 0)) {
		sent = sink_announce_dropped(sink, hdr);

		if (!sent) {
			/* we failed, we don't try to send our log as if it
			 * would pass by chance, we'd get disordered events.
			 */
			goto fail;
		}
	}

	sent = __sink_write(sink, hdr, maxlen, msg, nmsg);

 fail:
	if (unlikely(sent <= 0))
		HA_ATOMIC_ADD(&sink->ctx.dropped, 2);

	return sent;
}

struct sink *sink_new_from_srv(struct server *srv, const char *from);
int sink_resolve_logger_buffer(struct logger *logger, char **msg);

#endif /* _HAPROXY_SINK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
