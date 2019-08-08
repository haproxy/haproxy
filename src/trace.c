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

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/mini-clist.h>
#include <proto/cli.h>
#include <proto/log.h>
#include <proto/sink.h>
#include <proto/trace.h>

struct list trace_sources = LIST_HEAD_INIT(trace_sources);
THREAD_LOCAL struct buffer trace_buf = { };

/* allocates the trace buffers. Returns 0 in case of failure. It is safe to
 * call to call this function multiple times if the size changes.
 */
static int alloc_trace_buffers_per_thread()
{
	chunk_init(&trace_buf, my_realloc2(trace_buf.area, global.tune.bufsize), global.tune.bufsize);
	return !!trash.area;
}

static void free_trace_buffers_per_thread()
{
	chunk_destroy(&trace_buf);
}

REGISTER_PER_THREAD_ALLOC(alloc_trace_buffers_per_thread);
REGISTER_PER_THREAD_FREE(free_trace_buffers_per_thread);

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

/* parse the command, returns 1 if a message is returned, otherwise zero */
static int cli_parse_trace(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct trace_source *src;
	uint64_t *ev_ptr = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (!*args[1]) {
		/* no arg => report the list of supported sources as a warning */
		chunk_printf(&trash,
			     "Supported trace sources and states (.=stopped, w=waiting, R=running) :\n"
			     " [.] 0          : not a source, will immediately stop all traces\n"
			     );

		list_for_each_entry(src, &trace_sources, source_link)
			chunk_appendf(&trash, " [%c] %-10s : %s\n", trace_state_char(src->state), src->name.ptr, src->desc);

		trash.area[trash.data] = 0;
		return cli_msg(appctx, LOG_WARNING, trash.area);
	}

	if (strcmp(args[1], "0") == 0) {
		/* emergency stop of all traces */
		list_for_each_entry(src, &trace_sources, source_link)
			HA_ATOMIC_STORE(&src->state, TRACE_STATE_STOPPED);
		return cli_msg(appctx, LOG_NOTICE, "All traces now stopped");
	}

	src = trace_find_source(args[1]);
	if (!src)
		return cli_err(appctx, "No such trace source");

	if (!*args[2]) {
		return cli_msg(appctx, LOG_WARNING,
			       "Supported commands:\n"
			       "  event   : list/enable/disable source-specific event reporting\n"
			       //"  filter  : list/enable/disable generic filters\n"
			       //"  level   : list/set detail level\n"
			       //"  lock    : automatic lock on thread/connection/stream/...\n"
			       "  pause   : pause and automatically restart after a specific event\n"
			       "  sink    : list/set event sinks\n"
			       "  start   : start immediately or after a specific event\n"
			       "  stop    : stop immediately or after a specific event\n"
			       );
	}
	else if ((strcmp(args[2], "event") == 0 && (ev_ptr = &src->report_events)) ||
	         (strcmp(args[2], "pause") == 0 && (ev_ptr = &src->pause_events)) ||
	         (strcmp(args[2], "start") == 0 && (ev_ptr = &src->start_events)) ||
	         (strcmp(args[2], "stop")  == 0 && (ev_ptr = &src->stop_events))) {
		const struct trace_event *ev;
		const char *name = args[3];
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
				chunk_appendf(&trash, "  - now        : don't wait for events, immediately change the state\n");
			chunk_appendf(&trash, "  - none       : disable all event types\n");
			chunk_appendf(&trash, "  - any        : enable all event types\n");
			for (i = 0; src->known_events && src->known_events[i].mask; i++) {
				chunk_appendf(&trash, "  %c %-10s : %s\n",
					      trace_event_char(*ev_ptr, src->known_events[i].mask),
					      src->known_events[i].name, src->known_events[i].desc);
			}
			trash.area[trash.data] = 0;
			return cli_msg(appctx, LOG_WARNING, trash.area);
		}

		if (strcmp(name, "now") == 0 && ev_ptr != &src->report_events) {
			HA_ATOMIC_STORE(ev_ptr, 0);
			if (ev_ptr == &src->pause_events)
				HA_ATOMIC_STORE(&src->state, TRACE_STATE_WAITING);
			else if (ev_ptr == &src->start_events)
				HA_ATOMIC_STORE(&src->state, TRACE_STATE_RUNNING);
			else if (ev_ptr == &src->stop_events)
				HA_ATOMIC_STORE(&src->state, TRACE_STATE_STOPPED);
			return 0;
		}

		if (strcmp(name, "none") == 0)
			HA_ATOMIC_STORE(ev_ptr, 0);
		else if (strcmp(name, "any") == 0)
			HA_ATOMIC_STORE(ev_ptr, ~0);
		else {
			ev = trace_find_event(src->known_events, name);
			if (!ev)
				return cli_err(appctx, "No such trace event");

			if (!neg)
				HA_ATOMIC_OR(ev_ptr, ev->mask);
			else
				HA_ATOMIC_AND(ev_ptr, ~ev->mask);
		}
	}
	else if (strcmp(args[2], "sink") == 0) {
		const char *name = args[3];
		struct sink *sink;

		if (!*name) {
			chunk_printf(&trash, "Supported sinks for source %s (*=current):\n", src->name.ptr);
			chunk_appendf(&trash, "  %c none       : no sink\n", src->sink ? ' ' : '*');
			list_for_each_entry(sink, &sink_list, sink_list) {
				chunk_appendf(&trash, "  %c %-10s : %s\n",
					      src->sink == sink ? '*' : ' ',
					      sink->name, sink->desc);
			}
			trash.area[trash.data] = 0;
			return cli_msg(appctx, LOG_WARNING, trash.area);
		}

		if (strcmp(name, "none") == 0)
			sink = NULL;
		else {
			sink = sink_find(name);
			if (!sink)
				return cli_err(appctx, "No such sink");
		}

		HA_ATOMIC_STORE(&src->sink, sink);
	}
	else
		return cli_err(appctx, "Unknown trace keyword");

	return 0;
}

static struct cli_kw_list cli_kws = {{ },{
	{ { "trace", NULL }, "trace <module> [cmd [args...]] : manage live tracing", cli_parse_trace, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
