/*
 * include/proto/sink.h
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

#ifndef _PROTO_SINK_H
#define _PROTO_SINK_H

#include <common/mini-clist.h>
#include <types/sink.h>

extern struct list sink_list;

struct sink *sink_find(const char *name);
struct sink *sink_new_fd(const char *name, const char *desc, enum sink_fmt fmt, int fd);
ssize_t __sink_write(struct sink *sink, const struct ist msg[], size_t nmsg);
int sink_announce_dropped(struct sink *sink);


/* tries to send <nmsg> message parts (up to 8, ignored above) from message
 * array <msg> to sink <sink>. Formating according to the sink's preference is
 * done here. Lost messages are accounted for in the sink's counter. If there
 * were lost messages, an attempt is first made to indicate it.
 */
static inline void sink_write(struct sink *sink, const struct ist msg[], size_t nmsg)
{
	ssize_t sent;

	if (unlikely(sink->ctx.dropped > 0)) {
		/* We need to take an exclusive lock so that other producers
		 * don't do the same thing at the same time and above all we
		 * want to be sure others have finished sending their messages
		 * so that the dropped event arrives exactly at the right
		 * position.
		 */
		HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &sink->ctx.lock);
		sent = sink_announce_dropped(sink);
		HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &sink->ctx.lock);

		if (!sent) {
			/* we failed, we don't try to send our log as if it
			 * would pass by chance, we'd get disordered events.
			 */
			goto fail;
		}
	}

	HA_RWLOCK_RDLOCK(LOGSRV_LOCK, &sink->ctx.lock);
	sent = __sink_write(sink, msg, nmsg);
	HA_RWLOCK_RDUNLOCK(LOGSRV_LOCK, &sink->ctx.lock);

 fail:
	if (unlikely(sent <= 0))
		HA_ATOMIC_ADD(&sink->ctx.dropped, 1);
}

#endif /* _PROTO_SINK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
