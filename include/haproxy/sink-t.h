/*
 * include/haproxy/sink-t.h
 * This file provides definitions for event sinks
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

#ifndef _HAPROXY_SINK_T_H
#define _HAPROXY_SINK_T_H

#include <import/ist.h>
#include <haproxy/api-t.h>
#include <haproxy/log-t.h>

/* A sink may be of 4 distinct types :
 *   - file descriptor (such as stdout)
 *   - ring buffer, readable from CLI
 */
enum sink_type {
	SINK_TYPE_NEW,      // not yet initialized
	SINK_TYPE_FD,       // events sent to a file descriptor
	SINK_TYPE_BUFFER,   // events sent to a ring buffer
};

struct sink_forward_target {
	struct server *srv;    // used server
	struct appctx *appctx; // appctx of current session
	size_t ofs;            // ring buffer reader offset
	struct sink_forward_target *next;
	__decl_thread(HA_SPINLOCK_T lock); // lock to protect current struct
};

/* describes the configuration and current state of an event sink */
struct sink {
	struct list sink_list;     // position in the sink list
	char *name;                // sink name
	char *desc;                // sink description
	enum log_fmt fmt;          // format expected by the sink
	enum sink_type type;       // type of storage
	uint32_t maxlen;           // max message length (truncated above)
	struct proxy* forward_px;  // proxy used to forward
	struct sink_forward_target *sft; // sink forward targets
	struct task *forward_task; // task to handle forward targets conns
	struct sig_handler *forward_sighandler; /* signal handler */
	struct {
		struct ring *ring;    // used by ring buffer and STRM sender
		unsigned int dropped; // dropped events since last one.
		int fd;               // fd num for FD type sink
		__decl_thread(HA_RWLOCK_T lock); // shared/excl for dropped
	} ctx;
};

#endif /* _HAPROXY_SINK_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
