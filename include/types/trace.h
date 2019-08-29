/*
 * include/types/trace.h
 * This file provides definitions for runtime tracing
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

#ifndef _TYPES_TRACE_H
#define _TYPES_TRACE_H

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/mini-clist.h>
#include <types/sink.h>

/* the macros below define an optional type for each of the 4 args passed to
 * the trace() call. When such a type is set, the caller commits to exclusively
 * using a valid pointer when this argument is not null. This allows the trace()
 * function to automatically start or stop the lock-on mechanism when it detects
 * a type that it can dereference such as a connection or a stream. Each value
 * is represented as an exclusive bit and each arg is represented by a distinct
 * byte. The reason for using a single bit per value is to speed up tests using
 * bitmasks. Users must not declare args with multiple bits set for the same arg.
 * By default arguments are private, corresponding to value 0.
 */

/* for use only in macro definitions above */
#define TRC_ARG_PRIV  (0)
#define TRC_ARG_CONN  (1 << 0)
#define TRC_ARG_SESS  (1 << 1)
#define TRC_ARG_STRM  (1 << 2)

#define TRC_ARG1_PRIV (TRC_ARG_PRIV << 0)
#define TRC_ARG1_CONN (TRC_ARG_CONN << 0)
#define TRC_ARG1_SESS (TRC_ARG_SESS << 0)
#define TRC_ARG1_STRM (TRC_ARG_STRM << 0)

#define TRC_ARG2_PRIV (TRC_ARG_PRIV << 8)
#define TRC_ARG2_CONN (TRC_ARG_CONN << 8)
#define TRC_ARG2_SESS (TRC_ARG_SESS << 8)
#define TRC_ARG2_STRM (TRC_ARG_STRM << 8)

#define TRC_ARG3_PRIV (TRC_ARG_PRIV << 16)
#define TRC_ARG3_CONN (TRC_ARG_CONN << 16)
#define TRC_ARG3_SESS (TRC_ARG_SESS << 16)
#define TRC_ARG3_STRM (TRC_ARG_STRM << 16)

#define TRC_ARG4_PRIV (TRC_ARG_PRIV << 24)
#define TRC_ARG4_CONN (TRC_ARG_CONN << 24)
#define TRC_ARG4_SESS (TRC_ARG_SESS << 24)
#define TRC_ARG4_STRM (TRC_ARG_STRM << 24)

/* usable to detect the presence of any arg of the desired type */
#define TRC_ARGS_CONN (TRC_ARG_CONN * 0x01010101U)
#define TRC_ARGS_SESS (TRC_ARG_SESS * 0x01010101U)
#define TRC_ARGS_STRM (TRC_ARG_STRM * 0x01010101U)


enum trace_state {
	TRACE_STATE_STOPPED = 0,  // completely disabled
	TRACE_STATE_WAITING,      // waiting for the start condition to happen
	TRACE_STATE_RUNNING,      // waiting for the stop or pause conditions
};

/* trace levels, from least detailed to most detailed. Traces emitted at a
 * lower level are always reported at higher levels.
 */
enum trace_level {
	TRACE_LEVEL_USER = 0,     // info useful to the end user
	TRACE_LEVEL_PROTO,        // also report protocol-level updates
	TRACE_LEVEL_STATE,        // also report state changes
	TRACE_LEVEL_DATA,         // also report data exchanges
	TRACE_LEVEL_DEVELOPER,    // functions entry/exit and any other developer info
};

enum trace_lockon {
	TRACE_LOCKON_NOTHING = 0, // don't lock on anything
	TRACE_LOCKON_THREAD,      // lock on the thread that started the trace
	TRACE_LOCKON_LISTENER,    // lock on the listener that started the trace
	TRACE_LOCKON_FRONTEND,    // lock on the frontend that started the trace
	TRACE_LOCKON_BACKEND,     // lock on the backend that started the trace
	TRACE_LOCKON_SERVER,      // lock on the server that started the trace
	TRACE_LOCKON_CONNECTION,  // lock on the connection that started the trace
	TRACE_LOCKON_SESSION,     // lock on the session that started the trace
	TRACE_LOCKON_STREAM,      // lock on the stream that started the trace
	TRACE_LOCKON_ARG1,        // lock on arg1, totally source-dependent
	TRACE_LOCKON_ARG2,        // lock on arg2, totally source-dependent
	TRACE_LOCKON_ARG3,        // lock on arg3, totally source-dependent
	TRACE_LOCKON_ARG4,        // lock on arg4, totally source-dependent
};

/* Each trace event maps a name to a mask in an uint64_t. Multiple bits are
 * permitted to have composite events. This is supposed to be stored into an
 * array terminated by mask 0 (name and desc are then ignored). Names "now",
 * "any" and "none" are reserved by the CLI parser for start/pause/stop
 * operations..
 */
struct trace_event {
	uint64_t mask;
	const char *name;
	const char *desc;
};

/* Regarding the verbosity, if <decoding> is not NULL, it must point to a NULL-
 * terminated array of name:description, which will define verbosity levels
 * implemented by the decoding callback. The verbosity value will default to
 * 1. When verbosity levels are defined, levels 1 and above are described by
 * these levels. At level zero, the callback is never called.
 */
struct trace_source {
	/* source definition */
	const struct ist name;
	const char *desc;
	const struct trace_event *known_events;
	struct list source_link; // element in list of known trace sources
	void (*default_cb)(enum trace_level level, uint64_t mask,
	                   const struct trace_source *src,
	                   const struct ist where, const struct ist func,
	                   const void *a1, const void *a2, const void *a3, const void *a4);
	uint32_t arg_def;        // argument definitions (sum of TRC_ARG{1..4}_*)
	const struct name_desc *lockon_args; // must be 4 entries if not NULL
	const struct name_desc *decoding;    // null-terminated if not NULL
	/* trace configuration, adjusted by "trace <module>" on CLI */
	enum trace_lockon lockon;
	uint64_t start_events;   // what will start the trace. default: 0=nothing
	uint64_t pause_events;   // what will pause the trace. default: 0=nothing
	uint64_t stop_events;    // what will stop the trace. default: 0=nothing
	uint64_t report_events;  // mask of which events need to be reported.
	enum trace_level level;  // report traces up to this level of info
	unsigned int verbosity;  // decoder's level of detail among <decoding> (0=no cb)
	struct sink *sink;       // where to send the trace
	/* trace state part below */
	enum trace_state state;
	const void *lockon_ptr;  // what to lockon when lockon is set
};

#endif /* _TYPES_TRACE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
