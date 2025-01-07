/*
 * Runtime tracing API
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

#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/istbuf.h>
#include <haproxy/list.h>
#include <haproxy/log.h>
#include <haproxy/global.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/sink.h>
#include <haproxy/trace.h>

struct list trace_sources = LIST_HEAD_INIT(trace_sources);
THREAD_LOCAL struct buffer trace_buf = { };

/* allocates the trace buffers. Returns 0 in case of failure. It is safe to
 * call to call this function multiple times if the size changes.
 */
static int alloc_trace_buffers_per_thread()
{
	chunk_init(&trace_buf, my_realloc2(trace_buf.area, global.tune.bufsize), global.tune.bufsize);
	return !!trace_buf.area;
}

static void free_trace_buffers_per_thread()
{
	chunk_destroy(&trace_buf);
}

REGISTER_PER_THREAD_ALLOC(alloc_trace_buffers_per_thread);
REGISTER_PER_THREAD_FREE(free_trace_buffers_per_thread);

/* pick the lowest non-null argument with a non-null arg_def mask */
static inline const void *trace_pick_arg(uint32_t arg_def, const void *a1, const void *a2, const void *a3, const void *a4)
{
	if (arg_def & 0x0000FFFF) {
		if ((arg_def & 0x000000FF) && a1)
			return a1;
		if ((arg_def & 0x0000FF00) && a2)
			return a2;
	}

	if (arg_def & 0xFFFF0000) {
		if ((arg_def & 0x00FF0000) && a3)
			return a3;
		if ((arg_def & 0xFF000000) && a4)
			return a4;
	}

	return NULL;
}

/* Reports whether the trace is enabled for the specified arguments, needs to enable
 * or disable tracking. It gets the same API as __trace() except for <cb> and <msg>
 * which are not used and were dropped, and plockptr which is an optional pointer to
 * the lockptr to be updated (or NULL) for tracking. The function returns:
 *   0 if the trace is not enabled for the module or these values
 *  <0 if the trace matches some locking criteria but don't have the proper level.
 *     In this case the interested caller might have to consider disabling tracking.
 *  >0 if the trace is enabled for the given criteria.
 * In all cases, <plockptr> will only be set if non-null and if a locking criterion
 * matched. It will be up to the caller to enable tracking if desired. A casual
 * tester not interested in adjusting tracking (i.e. calling the function before
 * deciding so prepare a buffer to be dumped) will only need to pass 0 for plockptr
 * and check if the result is >0.
 */
int __trace_enabled(enum trace_level level, uint64_t mask, struct trace_source *src,
		    const struct ist where, const char *func,
		    const void *a1, const void *a2, const void *a3, const void *a4,
		    const void **plockptr)
{
	const void *lockon_ptr = NULL;
	const struct trace_source *origin = NULL;
	struct trace_ctx ctx = { };

	/* in case we also follow another one (e.g. session) */
	origin = HA_ATOMIC_LOAD(&src->follow);

	/* Trace can be temporarily disabled via trace_disable(). */
	if (likely(src->state == TRACE_STATE_STOPPED) && !origin)
		return 0;

	if (th_ctx->trc_disable_ctr)
		return 0;

	/* check that at least one action is interested by this event */
	if (((src->report_events | src->start_events | src->pause_events | src->stop_events) & mask) == 0)
		return 0;

	/* retrieve available information from the caller's arguments */
	if (src->arg_def & TRC_ARGS_CONN)
		ctx.conn = trace_pick_arg(src->arg_def & TRC_ARGS_CONN, a1, a2, a3, a4);

	if (src->arg_def & TRC_ARGS_SESS)
		ctx.sess = trace_pick_arg(src->arg_def & TRC_ARGS_SESS, a1, a2, a3, a4);

	if (src->arg_def & TRC_ARGS_STRM)
		ctx.strm = trace_pick_arg(src->arg_def & TRC_ARGS_STRM, a1, a2, a3, a4);

	if (src->arg_def & TRC_ARGS_CHK)
		ctx.check = trace_pick_arg(src->arg_def & TRC_ARGS_CHK, a1, a2, a3, a4);

	if (src->arg_def & TRC_ARGS_QCON)
		ctx.qc = trace_pick_arg(src->arg_def & TRC_ARGS_QCON, a1, a2, a3, a4);

	if (src->arg_def & TRC_ARGS_APPCTX)
		ctx.appctx = trace_pick_arg(src->arg_def & TRC_ARGS_APPCTX, a1, a2, a3, a4);

	if (src->fill_ctx)
		src->fill_ctx(&ctx, src, a1, a2, a3, a4);

#ifdef USE_QUIC
	if (ctx.qc && !ctx.conn)
		ctx.conn = ctx.qc->conn;
#endif
	if (!ctx.sess && ctx.strm)
		ctx.sess = ctx.strm->sess;
	else if (!ctx.sess && ctx.conn && LIST_INLIST(&ctx.conn->sess_el))
		ctx.sess = ctx.conn->owner;
	else if (!ctx.sess && ctx.check)
		ctx.sess = ctx.check->sess;
	else if (!ctx.sess && ctx.appctx)
		ctx.sess = ctx.appctx->sess;

	if (ctx.sess) {
		ctx.fe = ctx.sess->fe;
		ctx.li = ctx.sess->listener;
	}

	if (!ctx.li && ctx.conn)
		ctx.li = objt_listener(ctx.conn->target);

	if (ctx.li && !ctx.fe)
		ctx.fe = ctx.li->bind_conf->frontend;

	if (ctx.strm) {
		ctx.be = ctx.strm->be;
		ctx.srv = ctx.strm->srv_conn;
	}
	if (ctx.check) {
		ctx.srv = ctx.check->server;
		ctx.be = (ctx.srv ? ctx.srv->proxy : NULL);
	}

	if (!ctx.srv && ctx.conn)
		ctx.srv = objt_server(ctx.conn->target);

	if (ctx.srv && !ctx.be)
		ctx.be = ctx.srv->proxy;

	if (!ctx.be && ctx.conn)
		ctx.be = objt_proxy(ctx.conn->target);

	/* TODO: add handling of filters here, return if no match (not even update states) */

	/* check if we need to start the trace now */
	if (src->state == TRACE_STATE_WAITING) {
		if ((src->start_events & mask) == 0)
			return 0;

		/* TODO: add update of lockon+lockon_ptr here */
		HA_ATOMIC_STORE(&src->state, TRACE_STATE_RUNNING);
	}

	/* we may want to lock on a particular object */
	if (src->lockon != TRACE_LOCKON_NOTHING) {
		switch (src->lockon) {
		case TRACE_LOCKON_BACKEND:    lockon_ptr = ctx.be;     break;
		case TRACE_LOCKON_CONNECTION: lockon_ptr = ctx.conn;   break;
		case TRACE_LOCKON_FRONTEND:   lockon_ptr = ctx.fe;     break;
		case TRACE_LOCKON_LISTENER:   lockon_ptr = ctx.li;     break;
		case TRACE_LOCKON_SERVER:     lockon_ptr = ctx.srv;    break;
		case TRACE_LOCKON_SESSION:    lockon_ptr = ctx.sess;   break;
		case TRACE_LOCKON_STREAM:     lockon_ptr = ctx.strm;   break;
		case TRACE_LOCKON_CHECK:      lockon_ptr = ctx.check;  break;
		case TRACE_LOCKON_THREAD:     lockon_ptr = ti;         break;
		case TRACE_LOCKON_QCON:       lockon_ptr = ctx.qc;     break;
		case TRACE_LOCKON_APPCTX:     lockon_ptr = ctx.appctx; break;
		case TRACE_LOCKON_ARG1:       lockon_ptr = a1;         break;
		case TRACE_LOCKON_ARG2:       lockon_ptr = a2;         break;
		case TRACE_LOCKON_ARG3:       lockon_ptr = a3;         break;
		case TRACE_LOCKON_ARG4:       lockon_ptr = a4;         break;
		default: break; // silence stupid gcc -Wswitch
		}

		if (src->lockon_ptr && src->lockon_ptr != lockon_ptr)
			return 0;

		if (plockptr && !src->lockon_ptr && lockon_ptr && src->state == TRACE_STATE_RUNNING)
			*plockptr = lockon_ptr;
	}

	/* or we may also follow another source's locked pointer */
	if (origin) {
		if (!origin->lockon_ptr)
			return 0;

		switch (origin->lockon) {
		case TRACE_LOCKON_BACKEND:    lockon_ptr = ctx.be;     break;
		case TRACE_LOCKON_CONNECTION: lockon_ptr = ctx.conn;   break;
		case TRACE_LOCKON_FRONTEND:   lockon_ptr = ctx.fe;     break;
		case TRACE_LOCKON_LISTENER:   lockon_ptr = ctx.li;     break;
		case TRACE_LOCKON_SERVER:     lockon_ptr = ctx.srv;    break;
		case TRACE_LOCKON_SESSION:    lockon_ptr = ctx.sess;   break;
		case TRACE_LOCKON_STREAM:     lockon_ptr = ctx.strm;   break;
		case TRACE_LOCKON_CHECK:      lockon_ptr = ctx.check;  break;
		case TRACE_LOCKON_THREAD:     lockon_ptr = ti;         break;
		case TRACE_LOCKON_QCON:       lockon_ptr = ctx.qc;     break;
		case TRACE_LOCKON_APPCTX:     lockon_ptr = ctx.appctx; break;
		case TRACE_LOCKON_ARG1:       lockon_ptr = a1;         break;
		case TRACE_LOCKON_ARG2:       lockon_ptr = a2;         break;
		case TRACE_LOCKON_ARG3:       lockon_ptr = a3;         break;
		case TRACE_LOCKON_ARG4:       lockon_ptr = a4;         break;
		default: break; // silence stupid gcc -Wswitch
		}

		if (origin->lockon_ptr != lockon_ptr)
			return 0;
	}

	/* here the trace is running and is tracking a desired item */
	if ((src->report_events & mask) == 0 || level > src->level) {
		/* tracking did match, and might have to be disabled */
		return -1;
	}

	/* OK trace still enabled */
	return 1;
}

/* write a message for the given trace source */
void __trace(enum trace_level level, uint64_t mask, struct trace_source *src,
             const struct ist where, const char *func,
             const void *a1, const void *a2, const void *a3, const void *a4,
             void (*cb)(enum trace_level level, uint64_t mask, const struct trace_source *src,
                        const struct ist where, const struct ist func,
                        const void *a1, const void *a2, const void *a3, const void *a4),
             const struct ist msg)
{
	const void *lockon_ptr;
	struct ist ist_func = ist(func);
	char tnum[4];
	struct ist line[12];
	int words = 0;
	int ret;

	lockon_ptr = NULL;
	ret = __trace_enabled(level, mask, src, where, func, a1, a2, a3, a4, &lockon_ptr);
	if (lockon_ptr)
		HA_ATOMIC_STORE(&src->lockon_ptr, lockon_ptr);

	if (ret <= 0) {
		if (ret < 0) // may have to disable tracking
			goto end;
		return;
	}

	/* log the logging location truncated to 10 chars from the right so that
	 * the line number and the end of the file name are there.
	 */
	line[words++] = ist("[");
	tnum[0] = '0' + tid / 10;
	tnum[1] = '0' + tid % 10;
	tnum[2] = '|';
	tnum[3] = 0;
	line[words++] = ist(tnum);
	line[words++] = src->name;
	line[words++] = ist("|");
	line[words++] = ist2("012345" + level, 1); // "0" to "5"
	line[words++] = ist("|");
	line[words] = where;
	if (line[words].len > 13) {
		line[words].ptr += (line[words].len - 13);
		line[words].len = 13;
	}
	words++;
	line[words++] = ist("] ");

	if (isttest(ist_func)) {
		line[words++] = ist_func;
		line[words++] = ist("(): ");
	}

	if (!cb)
		cb = src->default_cb;

	if (cb && src->verbosity) {
		/* decode function passed, we want to pre-fill the
		 * buffer with the message and let the decode function
		 * do its job, possibly even overwriting it.
		 */
		b_reset(&trace_buf);
		b_istput(&trace_buf, msg);
		cb(level, mask, src, where, ist_func, a1, a2, a3, a4);
		line[words] = ist2(trace_buf.area, trace_buf.data);
		words++;
	}
	else {
		/* Note that here we could decide to print some args whose type
		 * is known, when verbosity is above the quiet level, and even
		 * to print the name and values of those which are declared for
		 * lock-on.
		 */
		line[words++] = msg;
	}

	if (src->sink)
		sink_write(src->sink, LOG_HEADER_NONE, 0, line, words);

 end:
	/* check if we need to stop the trace now */
	if ((src->stop_events & mask) != 0) {
		HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		HA_ATOMIC_STORE(&src->state, TRACE_STATE_STOPPED);
	}
	else if ((src->pause_events & mask) != 0) {
		HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		HA_ATOMIC_STORE(&src->state, TRACE_STATE_WAITING);
	}
}

/* this callback may be used when no output modification is desired */
void trace_no_cb(enum trace_level level, uint64_t mask, const struct trace_source *src,
		 const struct ist where, const struct ist func,
		 const void *a1, const void *a2, const void *a3, const void *a4)
{
	/* do nothing */
}

static void trace_source_reset(struct trace_source *source)
{
	source->lockon = TRACE_LOCKON_NOTHING;
	source->level = TRACE_LEVEL_USER;
	source->verbosity = 1;
	source->sink = NULL;
	source->state = TRACE_STATE_STOPPED;
	source->lockon_ptr = NULL;
	source->cmdline = 0;
}

/* registers trace source <source>. Modifies the list element!
 * The {start,pause,stop,report} events are not changed so the source may
 * preset them.
 */
void trace_register_source(struct trace_source *source)
{
	trace_source_reset(source);
	LIST_APPEND(&trace_sources, &source->source_link);
}

struct trace_source *trace_find_source(const char *name)
{
	struct trace_source *src;
	const struct ist iname = ist(name);

	list_for_each_entry(src, &trace_sources, source_link)
		if (isteq(src->name, iname))
			return src;
	return NULL;
}

const struct trace_event *trace_find_event(const struct trace_event *ev, const char *name)
{
	for (; ev && ev->mask; ev++)
		if (strcmp(ev->name, name) == 0)
			return ev;
	return NULL;
}

/* Returns the level value or a negative error code. */
static int trace_parse_level(const char *level)
{
	if (!level)
		return -1;

	if (strcmp(level, "error") == 0)
		return TRACE_LEVEL_ERROR;
	else if (strcmp(level, "user") == 0)
		return TRACE_LEVEL_USER;
	else if (strcmp(level, "proto") == 0)
		return TRACE_LEVEL_PROTO;
	else if (strcmp(level, "state") == 0)
		return TRACE_LEVEL_STATE;
	else if (strcmp(level, "data") == 0)
		return TRACE_LEVEL_DATA;
	else if (strcmp(level, "developer") == 0)
		return TRACE_LEVEL_DEVELOPER;
	else
		return -1;
}

/* Returns the verbosity value or a negative error code. */
static int trace_source_parse_verbosity(struct trace_source *src,
                                        const char *verbosity)
{
	const struct name_desc *nd;
	int ret;

	/* Only "quiet" is defined for all sources. Other identifiers are
	 * specific to trace source.
	 */
	if (strcmp(verbosity, "quiet") == 0) {
		ret = 0;
		goto end;
	}

	if (!src)
		return -1;

	if (!src->decoding || !src->decoding[0].name) {
		if (strcmp(verbosity, "default") != 0)
			return -1;

		ret = 1;
	}
	else {
		for (nd = src->decoding; nd->name && nd->desc; nd++)
			if (strcmp(verbosity, nd->name) == 0)
				break;

		if (!nd->name || !nd->desc)
			return -1;

		ret = nd - src->decoding + 1;
	}

 end:
	return ret;
}

/* helper to get trace source sink name. Behavior is different during parsing
 * time (<file> != NULL) and during runtime: this is to make sure that during
 * parsing time sink name is properly postresolved
 *
 * Returns the sink pointer on success and NULL on error. <msg> will be set
 * in case of error.
 */
static struct sink *_trace_get_sink(const char *name, char **msg,
                                    const char *file, int line)
{
	struct sink *sink = NULL;

	if (file) {
		/* only during parsing time */
		sink = sink_find_early(name, "traces", file, line);
		if (!sink) {
			memprintf(msg, "Memory error while setting up sink '%s' \n", name);
			return NULL;
		}
	} else {
		/* runtime */
		sink = sink_find(name);
		if (!sink) {
			memprintf(msg, "No such trace sink '%s' \n", name);
			return NULL;
		}
	}
	return sink;
}

/* Returns true if <src> trace source configuration can be changed. */
static int trace_enforce_origin_priority(const struct trace_source *src)
{
	/* Trace cannot be modified via configuration file (during startup) if
	 * already activated via -dt command line argument.
	 */
	return !src->cmdline || !(global.mode & MODE_STARTING);
}

/* Parse a "trace" statement. Returns a severity as a LOG_* level and a status
 * message that may be delivered to the user, in <msg>. The message will be
 * nulled first and msg must be an allocated pointer. A null status message output
 * indicates no error. Be careful not to use the return value as a boolean, as
 * LOG_* values are not ordered as one could imagine (LOG_EMERG is zero). The
 * function may/will use the trash buffer as the storage for the response
 * message so that the caller never needs to release anything.
 */
static int _trace_parse_statement(char **args, char **msg, const char *file, int line)
{
	struct trace_source *orig_src, *src;
	uint64_t *ev_ptr = NULL;
	int cur_arg;

	/* no error by default */
	*msg = NULL;

	if (!*args[1]) {
		/* no arg => report the list of supported sources as a warning */
		chunk_printf(&trash,
			     "Supported trace sources and states (.=stopped, w=waiting, R=running) :\n"
			     " [.] 0          : not a source, will immediately stop all traces\n"
			     " [.] all        : all sources below, only for 'sink', 'level' and 'follow'\n"
			     );

		list_for_each_entry(src, &trace_sources, source_link)
			chunk_appendf(&trash, " [%c] %-10s : %s\n", trace_state_char(src->state), src->name.ptr, src->desc);

		trash.area[trash.data] = 0;
		*msg = strdup(trash.area);
		return LOG_WARNING;
	}

	if (strcmp(args[1], "0") == 0) {
		/* emergency stop of all traces */
		list_for_each_entry(src, &trace_sources, source_link)
			HA_ATOMIC_STORE(&src->state, TRACE_STATE_STOPPED);
		*msg = strdup("All traces now stopped");
		return LOG_NOTICE;
	}

	if (strcmp(args[1], "all") == 0) {
		orig_src = NULL;
	}
	else {
		orig_src = trace_find_source(args[1]);
		if (!orig_src) {
			memprintf(msg, "No such trace source '%s'", args[1]);
			return LOG_ERR;
		}
	}

	cur_arg = 2;
	if (!*args[cur_arg]) {
		*msg =  "Supported commands:\n"
			"  event     : list/enable/disable source-specific event reporting\n"
			//"  filter    : list/enable/disable generic filters\n"
			"  level     : list/set trace reporting level\n"
			"  lock      : automatic lock on thread/connection/stream/...\n"
			"  follow    : passively follow another source's locked pointer (e.g. session)\n"
			"  pause     : pause and automatically restart after a specific event\n"
			"  sink      : list/set event sinks\n"
			"  start     : start immediately or after a specific event\n"
			"  stop      : stop immediately or after a specific event\n"
			"  verbosity : list/set trace output verbosity\n";
		*msg = strdup(*msg);
		return LOG_WARNING;
	}

  next_stmt:
	if (!*args[cur_arg])
		goto out;

	src = orig_src;
	if (src == NULL &&
	    strcmp(args[cur_arg], "follow") != 0 &&
	    strcmp(args[cur_arg], "sink") != 0 &&
	    strcmp(args[cur_arg], "level") != 0) {
		memprintf(msg, "'%s' not applicable to meta-source 'all'", args[cur_arg]);
		return LOG_ERR;
	}

	if (src && !trace_enforce_origin_priority(src))
		goto out;

	if (strcmp(args[cur_arg], "follow") == 0) {
		const struct trace_source *origin = src ? HA_ATOMIC_LOAD(&src->follow) : NULL;

		if (!*args[cur_arg+1]) {
			/* no arg => report the list of supported sources as a warning */
			if (origin)
				chunk_printf(&trash, "Currently following source '%s'.\n", origin->name.ptr);
			else if (src)
				chunk_printf(&trash, "Not currently following any other source.\n");
			else
				chunk_reset(&trash);

			chunk_appendf(&trash,
				     "Please specify another source to follow, among the following ones:\n"
				     " [.] none       : follow no other source\n"
				     );

			list_for_each_entry(origin, &trace_sources, source_link)
				chunk_appendf(&trash, " [%c] %-10s : %s\n", trace_state_char(origin->state), origin->name.ptr, origin->desc);

			trash.area[trash.data] = 0;
			*msg = strdup(trash.area);
			return LOG_WARNING;
		}

		origin = NULL;
		if (strcmp(args[cur_arg+1], "none") != 0) {
			origin = trace_find_source(args[cur_arg+1]);
			if (!origin) {
				memprintf(msg, "No such trace source '%s'", args[cur_arg+1]);
				return LOG_ERR;
			}
		}

		if (src) {
			HA_ATOMIC_STORE(&src->follow, origin);
		}
		else {
			list_for_each_entry(src, &trace_sources, source_link) {
				if (src != origin && trace_enforce_origin_priority(src))
					HA_ATOMIC_STORE(&src->follow, origin);
			}
		}
		cur_arg += 2;
		goto next_stmt;
	}
	else if ((strcmp(args[cur_arg], "event") == 0 && (ev_ptr = &src->report_events)) ||
	         (strcmp(args[cur_arg], "pause") == 0 && (ev_ptr = &src->pause_events)) ||
	         (strcmp(args[cur_arg], "start") == 0 && (ev_ptr = &src->start_events)) ||
	         (strcmp(args[cur_arg], "stop")  == 0 && (ev_ptr = &src->stop_events))) {
		const struct trace_event *ev;
		const char *name = args[cur_arg+1];
		int neg = 0;
		int i;

		/* skip prefix '!', '-', '+' and remind negation */
		while (*name) {
			if (*name == '!' || *name == '-')
				neg = 1;
			else if (*name == '+')
				neg = 0;
			else
				break;
			name++;
		}

		if (!*name) {
			chunk_printf(&trash, "Supported events for source %s (+=enabled, -=disabled):\n", src->name.ptr);
			if (ev_ptr != &src->report_events)
				chunk_appendf(&trash, "  - now          : don't wait for events, immediately change the state\n");
			chunk_appendf(&trash, "  - none         : disable all event types\n");
			chunk_appendf(&trash, "  - any          : enable all event types\n");
			for (i = 0; src->known_events && src->known_events[i].mask; i++) {
				chunk_appendf(&trash, "  %c %-12s : %s\n",
					      trace_event_char(*ev_ptr, src->known_events[i].mask),
					      src->known_events[i].name, src->known_events[i].desc);
			}
			trash.area[trash.data] = 0;
			*msg = strdup(trash.area);
			return LOG_WARNING;
		}

		/* state transitions:
		 *   - "start now" => TRACE_STATE_RUNNING
		 *   - "stop now"  => TRACE_STATE_STOPPED
		 *   - "pause now" => TRACE_STATE_WAITING
		 *   - "start <evt>" && STATE_STOPPED => TRACE_STATE_WAITING
		 */

		if (strcmp(name, "now") == 0 && ev_ptr != &src->report_events) {
			HA_ATOMIC_STORE(ev_ptr, 0);
			if (ev_ptr == &src->pause_events) {
				HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
				HA_ATOMIC_STORE(&src->state, TRACE_STATE_WAITING);
			}
			else if (ev_ptr == &src->start_events) {
				HA_ATOMIC_STORE(&src->state, TRACE_STATE_RUNNING);
			}
			else if (ev_ptr == &src->stop_events) {
				HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
				HA_ATOMIC_STORE(&src->state, TRACE_STATE_STOPPED);
			}
		}
		else if (strcmp(name, "none") == 0)
			HA_ATOMIC_STORE(ev_ptr, 0);
		else if (strcmp(name, "any") == 0) {
			enum trace_state old = TRACE_STATE_STOPPED;

			HA_ATOMIC_STORE(ev_ptr, ~0);
			if (ev_ptr == &src->start_events)
				HA_ATOMIC_CAS(&src->state, &old, TRACE_STATE_WAITING);
		}
		else {
			enum trace_state old = TRACE_STATE_STOPPED;

			ev = trace_find_event(src->known_events, name);
			if (!ev) {
				memprintf(msg, "No such trace event '%s'", name);
				return LOG_ERR;
			}

			if (!neg)
				HA_ATOMIC_OR(ev_ptr, ev->mask);
			else
				HA_ATOMIC_AND(ev_ptr, ~ev->mask);

			if (ev_ptr == &src->start_events && HA_ATOMIC_LOAD(ev_ptr) != 0)
				HA_ATOMIC_CAS(&src->state, &old, TRACE_STATE_WAITING);
		}

		cur_arg += 2;
		goto next_stmt;
	}
	else if (strcmp(args[cur_arg], "sink") == 0) {
		const char *name = args[cur_arg+1];
		struct sink *sink;

		if (!*name) {
			chunk_printf(&trash, "Supported sinks for source %s (*=current):\n", src ? src->name.ptr : "all");
			chunk_appendf(&trash, "  %c none       : no sink\n", src && src->sink ? ' ' : '*');
			list_for_each_entry(sink, &sink_list, sink_list) {
				chunk_appendf(&trash, "  %c %-10s : %s\n",
					      src && src->sink == sink ? '*' : ' ',
					      sink->name, sink->desc);
			}
			if (file)
				chunk_appendf(&trash, "(forward-declared sinks are not displayed here!)\n");
			trash.area[trash.data] = 0;
			*msg = strdup(trash.area);
			return LOG_WARNING;
		}

		if (strcmp(name, "none") == 0)
			sink = NULL;
		else {
			sink = _trace_get_sink(name, msg, file, line);
			if (!sink)
				return LOG_ERR;
		}

		if (src) {
			HA_ATOMIC_STORE(&src->sink, sink);
		}
		else {
			list_for_each_entry(src, &trace_sources, source_link) {
				if (trace_enforce_origin_priority(src))
					HA_ATOMIC_STORE(&src->sink, sink);
			}
		}

		cur_arg += 2;
		goto next_stmt;
	}
	else if (strcmp(args[cur_arg], "level") == 0) {
		const char *name = args[cur_arg+1];
		int level = -1;

		if (*name)
			level = trace_parse_level(name);

		if (level < 0) {
			chunk_reset(&trash);
			if (*name)
				chunk_appendf(&trash, "No such trace level '%s'. ", name);
			chunk_appendf(&trash, "Supported trace levels for source %s:\n", src ? src->name.ptr : "all");
			chunk_appendf(&trash, "  %c error      : report errors\n",
				      src && src->level == TRACE_LEVEL_ERROR ? '*' : ' ');
			chunk_appendf(&trash, "  %c user       : also information useful to the end user\n",
				      src && src->level == TRACE_LEVEL_USER ? '*' : ' ');
			chunk_appendf(&trash, "  %c proto      : also protocol-level updates\n",
				      src && src->level == TRACE_LEVEL_PROTO ? '*' : ' ');
			chunk_appendf(&trash, "  %c state      : also report internal state changes\n",
				      src && src->level == TRACE_LEVEL_STATE ? '*' : ' ');
			chunk_appendf(&trash, "  %c data       : also report data transfers\n",
				      src && src->level == TRACE_LEVEL_DATA ? '*' : ' ');
			chunk_appendf(&trash, "  %c developer  : also report information useful only to the developer\n",
				      src && src->level == TRACE_LEVEL_DEVELOPER ? '*' : ' ');
			trash.area[trash.data] = 0;
			*msg = strdup(trash.area);
			return *name ? LOG_ERR : LOG_WARNING;
		}

		if (src) {
			HA_ATOMIC_STORE(&src->level, level);
		}
		else {
			list_for_each_entry(src, &trace_sources, source_link) {
				if (trace_enforce_origin_priority(src))
					HA_ATOMIC_STORE(&src->level, level);
			}
		}

		cur_arg += 2;
		goto next_stmt;
	}
	else if (strcmp(args[cur_arg], "lock") == 0) {
		const char *name = args[cur_arg+1];

		if (!*name) {
			chunk_printf(&trash, "Supported lock-on criteria for source %s:\n", src->name.ptr);
			if (src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_STRM))
				chunk_appendf(&trash, "  %c backend    : lock on the backend that started the trace\n",
				              src->lockon == TRACE_LOCKON_BACKEND ? '*' : ' ');

			if (src->arg_def & TRC_ARGS_CHK)
				chunk_appendf(&trash, "  %c check      : lock on the check that started the trace\n",
				              src->lockon == TRACE_LOCKON_CHECK ? '*' : ' ');

			if (src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_QCON))
				chunk_appendf(&trash, "  %c connection : lock on the connection that started the trace\n",
				              src->lockon == TRACE_LOCKON_CONNECTION ? '*' : ' ');

			if (src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_QCON|TRC_ARGS_SESS|TRC_ARGS_STRM))
				chunk_appendf(&trash, "  %c frontend   : lock on the frontend that started the trace\n",
				              src->lockon == TRACE_LOCKON_FRONTEND ? '*' : ' ');

			if (src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_QCON|TRC_ARGS_SESS|TRC_ARGS_STRM))
				chunk_appendf(&trash, "  %c listener   : lock on the listener that started the trace\n",
				              src->lockon == TRACE_LOCKON_LISTENER ? '*' : ' ');

			chunk_appendf(&trash, "  %c nothing    : do not lock on anything\n",
				      src->lockon == TRACE_LOCKON_NOTHING ? '*' : ' ');

			if (src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_STRM))
				chunk_appendf(&trash, "  %c server     : lock on the server that started the trace\n",
				              src->lockon == TRACE_LOCKON_SERVER ? '*' : ' ');
#ifdef USE_QUIC
			if (src->arg_def & TRC_ARGS_QCON)
				chunk_appendf(&trash, "  %c qconn      : lock on the QUIC connection that started the trace\n",
				              src->lockon == TRACE_LOCKON_QCON ? '*' : ' ');
#endif
			if (src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_QCON|TRC_ARGS_SESS|TRC_ARGS_STRM))
				chunk_appendf(&trash, "  %c session    : lock on the session that started the trace\n",
				              src->lockon == TRACE_LOCKON_SESSION ? '*' : ' ');

			if (src->arg_def & TRC_ARGS_STRM)
				chunk_appendf(&trash, "  %c stream     : lock on the stream that started the trace\n",
				              src->lockon == TRACE_LOCKON_STREAM ? '*' : ' ');

			if (src->arg_def & TRC_ARGS_APPCTX)
				chunk_appendf(&trash, "  %c applet     : lock on the applet that started the trace\n",
				              src->lockon == TRACE_LOCKON_APPCTX ? '*' : ' ');

			chunk_appendf(&trash, "  %c thread     : lock on the thread that started the trace\n",
				      src->lockon == TRACE_LOCKON_THREAD ? '*' : ' ');

			if (src->lockon_args && src->lockon_args[0].name)
				chunk_appendf(&trash, "  %c %-10s : %s\n",
				              src->lockon == TRACE_LOCKON_ARG1 ? '*' : ' ',
				              src->lockon_args[0].name, src->lockon_args[0].desc);

			if (src->lockon_args && src->lockon_args[1].name)
				chunk_appendf(&trash, "  %c %-10s : %s\n",
				              src->lockon == TRACE_LOCKON_ARG2 ? '*' : ' ',
				              src->lockon_args[1].name, src->lockon_args[1].desc);

			if (src->lockon_args && src->lockon_args[2].name)
				chunk_appendf(&trash, "  %c %-10s : %s\n",
				              src->lockon == TRACE_LOCKON_ARG3 ? '*' : ' ',
				              src->lockon_args[2].name, src->lockon_args[2].desc);

			if (src->lockon_args && src->lockon_args[3].name)
				chunk_appendf(&trash, "  %c %-10s : %s\n",
				              src->lockon == TRACE_LOCKON_ARG4 ? '*' : ' ',
				              src->lockon_args[3].name, src->lockon_args[3].desc);

			trash.area[trash.data] = 0;
			*msg = strdup(trash.area);
			return LOG_WARNING;
		}
		else if ((src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_STRM)) && strcmp(name, "backend") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_BACKEND);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if ((src->arg_def & TRC_ARGS_CHK) && strcmp(name, "check") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_CHECK);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if ((src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_QCON)) && strcmp(name, "connection") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_CONNECTION);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if ((src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_QCON|TRC_ARGS_SESS|TRC_ARGS_STRM)) && strcmp(name, "frontend") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_FRONTEND);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if ((src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_QCON|TRC_ARGS_SESS|TRC_ARGS_STRM)) && strcmp(name, "listener") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_LISTENER);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if (strcmp(name, "nothing") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_NOTHING);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if ((src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_STRM)) && strcmp(name, "server") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_SERVER);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if ((src->arg_def & (TRC_ARGS_CONN|TRC_ARGS_QCON|TRC_ARGS_SESS|TRC_ARGS_STRM)) && strcmp(name, "session") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_SESSION);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if ((src->arg_def & TRC_ARGS_QCON) && strcmp(name, "qconn") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_QCON);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if ((src->arg_def & TRC_ARGS_STRM) && strcmp(name, "stream") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_STREAM);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if ((src->arg_def & TRC_ARGS_APPCTX) && strcmp(name, "appctx") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_APPCTX);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if (strcmp(name, "thread") == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_THREAD);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if (src->lockon_args && src->lockon_args[0].name && strcmp(name, src->lockon_args[0].name) == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_ARG1);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if (src->lockon_args && src->lockon_args[1].name && strcmp(name, src->lockon_args[1].name) == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_ARG2);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if (src->lockon_args && src->lockon_args[2].name && strcmp(name, src->lockon_args[2].name) == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_ARG3);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else if (src->lockon_args && src->lockon_args[3].name && strcmp(name, src->lockon_args[3].name) == 0) {
			HA_ATOMIC_STORE(&src->lockon, TRACE_LOCKON_ARG4);
			HA_ATOMIC_STORE(&src->lockon_ptr, NULL);
		}
		else {
			memprintf(msg, "Unsupported lock-on criterion '%s'", name);
			return LOG_ERR;
		}

		cur_arg += 2;
		goto next_stmt;
	}
	else if (strcmp(args[cur_arg], "verbosity") == 0) {
		const char *name = args[cur_arg+1];
		const struct name_desc *nd;
		int verbosity = -1;

		if (*name)
			verbosity = trace_source_parse_verbosity(src, name);

		if (verbosity < 0) {
			chunk_reset(&trash);
			if (*name)
				chunk_appendf(&trash, "No such verbosity level '%s'. ", name);
			chunk_appendf(&trash, "Supported trace verbosities for source %s:\n", src->name.ptr);
			chunk_appendf(&trash, "  %c quiet      : only report basic information with no decoding\n",
				      src->verbosity == 0 ? '*' : ' ');
			if (!src->decoding || !src->decoding[0].name) {
				chunk_appendf(&trash, "  %c default    : report extra information when available\n",
					      src->verbosity > 0 ? '*' : ' ');
			} else {
				for (nd = src->decoding; nd->name && nd->desc; nd++)
					chunk_appendf(&trash, "  %c %-10s : %s\n",
					              nd == (src->decoding + src->verbosity - 1) ? '*' : ' ',
						      nd->name, nd->desc);
			}
			trash.area[trash.data] = 0;
			*msg = strdup(trash.area);
			return *name ? LOG_ERR : LOG_WARNING;
		}

		HA_ATOMIC_STORE(&src->verbosity, verbosity);

		cur_arg += 2;
		goto next_stmt;
	}
	else {
		memprintf(msg, "Unknown trace keyword '%s'", args[cur_arg]);
		return LOG_ERR;
	}

  out:
	return 0;

}

/* same as _trace_parse_statement but when no file:line context is available
 * (during runtime)
 */
static int trace_parse_statement(char **args, char **msg)
{
	return _trace_parse_statement(args, msg, NULL, 0);
}

void _trace_parse_cmd(struct trace_source *src, int level, int verbosity)
{
	trace_source_reset(src);
	src->sink = sink_find("stderr");
	src->level = level >= 0 ? level : TRACE_LEVEL_ERROR;
	src->verbosity = verbosity >= 0 ? verbosity : 1;
	src->state = TRACE_STATE_RUNNING;
	src->cmdline = 1;
}

/* Parse a process argument specified via "-dt".
 *
 * Returns 0 on success else non-zero.
 */
int trace_parse_cmd(const char *arg_src, char **errmsg)
{
	char *str;
	char *arg, *oarg;
	char *saveptr;

	if (arg_src) {
		if (strcmp(arg_src, "help") == 0) {
			memprintf(errmsg,
			  "-dt activates traces on stderr output via the command-line.\n"
			  "Without argument, all registered trace sources are activated with error level as filter.\n"
			  "A list can be specified as argument to configure several trace sources with comma as separator.\n"
			  "Each entry can contains the trace name, a log level and a verbosity using colon as separator.\n"
			  "Every fields are optional and can be left empty, or with a colon to specify the next one.\n\n"
			  "An empty name or the alias 'all' will activate all registered sources.\n"
			  "Verbosity cannot be configured in this case except 'quiet' as their values are specific to each source.\n\n"
			  "Examples:\n"
			  "-dt           activate every sources on error level\n"
			  "-dt all:user  activate every sources on user level\n"
			  "-dt h1        activate HTTP/1 traces on error level\n"
			  "-dt h2:data   activate HTTP/2 traces on data level\n"
			  "-dt quic::clean,qmux::minimal\n    activate both QUIC transport and MUX traces on error level with their custom verbosity\n");
			return -1;
		}

		/* keep a copy of the ptr for strtok */
		oarg = arg = strdup(arg_src);
		if (!arg) {
			memprintf(errmsg, "Can't allocate !");
			return -2;
		}
	}

	if (!arg_src) {
		/* No trace specification, activate all sources on error level. */
		struct trace_source *src = NULL;

		list_for_each_entry(src, &trace_sources, source_link)
			_trace_parse_cmd(src, -1, -1);
		return 0;
	}

	while ((str = strtok_r(arg, ",", &saveptr))) {
		struct trace_source *src = NULL;
		char *field, *name;
		char *sep;
		int level = -1, verbosity = -1;

		/* 1. name */
		name = str;
		sep = strchr(str, ':');
		if (sep) {
			str = sep + 1;
			*sep = '\0';
		}
		else {
			str = NULL;
		}

		if (strlen(name) && strcmp(name, "all") != 0) {
			src = trace_find_source(name);
			if (!src) {
				memprintf(errmsg, "unknown trace source '%s'", name);
				ha_free(&oarg);
				return -2;
			}
		}

		if (!str || !strlen(str))
			goto parse;

		/* 2. level */
		field = str;
		sep = strchr(str, ':');
		if (sep) {
			str = sep + 1;
			*sep = '\0';
		}
		else {
			str = NULL;
		}

		if (strlen(field)) {
			level = trace_parse_level(field);
			if (level < 0) {
				memprintf(errmsg, "no such trace level '%s', available levels are 'error', 'user', 'proto', 'state', 'data', and 'developer'", field);
				ha_free(&oarg);
				return -2;
			}
		}

		if (!str || !strlen(str))
			goto parse;

		/* 3. verbosity */
		field = str;
		if (strchr(field, ':')) {
			memprintf(errmsg, "too many colon separators in trace definition");
			ha_free(&oarg);
			return -2;
		}

		verbosity = trace_source_parse_verbosity(src, field);
		if (verbosity < 0) {
			const struct name_desc *nd;

			if (!src) {
				memprintf(errmsg, "trace source must be specified for verbosity other than 'quiet'");
			}
			else {
				memprintf(errmsg, "no such trace verbosity '%s' for source '%s', available verbosities for this source are: 'quiet'", field, name);
				for (nd = src->decoding; nd->name && nd->desc; nd++)
					memprintf(errmsg, "%s, %s'%s'", *errmsg, (nd + 1)->name ? "" : "and ", nd->name);
			}

			ha_free(&oarg);
			return -2;
		}

 parse:
		if (src) {
			_trace_parse_cmd(src, level, verbosity);
		}
		else {
			list_for_each_entry(src, &trace_sources, source_link)
				_trace_parse_cmd(src, level, verbosity);
		}

		/* Reset arg to NULL for strtok. */
		arg = NULL;
	}
	ha_free(&oarg);
	return 0;
}

/* parse a "trace" statement in the "global" section, returns 1 if a message is returned, otherwise zero */
static int cfg_parse_trace(char **args, int section_type, struct proxy *curpx,
			   const struct proxy *defpx, const char *file, int line,
			   char **err)
{
	char *msg;
	int severity;

	severity = _trace_parse_statement(args, &msg, file, line);
	if (msg) {
		if (severity >= LOG_NOTICE)
			ha_notice("parsing [%s:%d] : '%s': %s\n", file, line, args[0], msg);
		else if (severity >= LOG_WARNING)
			ha_warning("parsing [%s:%d] : '%s': %s\n", file, line, args[0], msg);
		else {
			/* let the caller free the message */
			*err = msg;
			return -1;
		}
		ha_free(&msg);
	}

	return 0;
}

/*
 * parse a line in a <traces> section. Returns the error code, 0 if OK, or
 * any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int cfg_parse_traces(const char *file, int linenum, char **args, int inv)
{
	int err_code = 0;
	char *errmsg = NULL;

	if (strcmp(args[0], "traces") == 0) {  /* new section */
		/* no option, nothing special to do */
		alertif_too_many_args(0, file, linenum, args, &err_code);
		goto out;
	}
	else {
		struct cfg_kw_list *kwl;
		const char *best;
		int index;
		int rc;

		list_for_each_entry(kwl, &cfg_keywords.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if (kwl->kw[index].section != CFG_TRACES)
					continue;
				if (strcmp(kwl->kw[index].kw, args[0]) == 0) {
					if (check_kw_experimental(&kwl->kw[index], file, linenum, &errmsg)) {
						ha_alert("%s\n", errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}

					rc = kwl->kw[index].parse(args, CFG_TRACES, NULL, NULL, file, linenum, &errmsg);
					if (rc < 0) {
						ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_ALERT | ERR_FATAL;
					}
					else if (rc > 0) {
						ha_warning("parsing [%s:%d] : %s\n", file, linenum, errmsg);
						err_code |= ERR_WARN;
					}
					goto out;
				}
			}
		}

		best = cfg_find_best_match(args[0], &cfg_keywords.list, CFG_TRACES, NULL);
		if (best)
			ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section; did you mean '%s' maybe ?\n", file, linenum, args[0], cursection, best);
		else
			ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], "global");
		err_code |= ERR_ALERT | ERR_FATAL;
	}

  out:
	free(errmsg);
	return err_code;
}

/* parse the command, returns 1 if a message is returned, otherwise zero */
static int cli_parse_trace(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *msg;
	int severity;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	severity = trace_parse_statement(args, &msg);
	if (msg)
		return cli_dynmsg(appctx, severity, msg);

	/* total success */
	return 0;
}

/* parse the command, returns 1 if a message is returned, otherwise zero */
static int cli_parse_show_trace(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct trace_source *src;
	const struct sink *sink;
	int i;

	args++; // make args[1] the 1st arg

	if (!*args[1]) {
		/* no arg => report the list of supported sources */
		chunk_printf(&trash,
			     "Supported trace sources and states (.=stopped, w=waiting, R=running) :\n"
			     );

		list_for_each_entry(src, &trace_sources, source_link) {
			sink = src->sink;
			chunk_appendf(&trash, " [%c] %-10s -> %s [drp %u]  [%s]\n",
				      trace_state_char(src->state), src->name.ptr,
				      sink ? sink->name : "none",
				      sink ? sink->ctx.dropped : 0,
				      src->desc);
		}

		trash.area[trash.data] = 0;
		return cli_msg(appctx, LOG_INFO, trash.area);
	}

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	src = trace_find_source(args[1]);
	if (!src)
		return cli_err(appctx, "No such trace source");

	sink = src->sink;
	chunk_printf(&trash, "Trace status for %s:\n", src->name.ptr);
	chunk_appendf(&trash, "  - sink: %s [%u dropped]\n",
		      sink ? sink->name : "none", sink ? sink->ctx.dropped : 0);

	chunk_appendf(&trash, "  - event name   :     report    start    stop    pause\n");
	for (i = 0; src->known_events && src->known_events[i].mask; i++) {
		chunk_appendf(&trash, "    %-12s :        %c        %c        %c       %c\n",
			      src->known_events[i].name,
			      trace_event_char(src->report_events, src->known_events[i].mask),
			      trace_event_char(src->start_events, src->known_events[i].mask),
			      trace_event_char(src->stop_events, src->known_events[i].mask),
			      trace_event_char(src->pause_events, src->known_events[i].mask));
	}

	trash.area[trash.data] = 0;
	return cli_msg(appctx, LOG_WARNING, trash.area);
}

static struct cli_kw_list cli_kws = {{ },{
	{ { "trace", NULL },         "trace [<module>|0] [cmd [args...]]      : manage live tracing (empty to list, 0 to stop all)", cli_parse_trace, NULL, NULL },
	{ { "show", "trace", NULL }, "show trace [<module>]                   : show live tracing state",                            cli_parse_show_trace, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_TRACES, "trace", cfg_parse_trace },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
