/*
 * Event sink management
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

#include <common/compat.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/mini-clist.h>
#include <common/time.h>
#include <proto/cli.h>
#include <proto/log.h>
#include <proto/ring.h>
#include <proto/sink.h>
#include <proto/stream_interface.h>

struct list sink_list = LIST_HEAD_INIT(sink_list);

struct sink *sink_find(const char *name)
{
	struct sink *sink;

	list_for_each_entry(sink, &sink_list, sink_list)
		if (strcmp(sink->name, name) == 0)
			return sink;
	return NULL;
}

/* creates a new sink and adds it to the list, it's still generic and not fully
 * initialized. Returns NULL on allocation failure. If another one already
 * exists with the same name, it will be returned. The caller can detect it as
 * a newly created one has type SINK_TYPE_NEW.
 */
static struct sink *__sink_new(const char *name, const char *desc, enum sink_fmt fmt)
{
	struct sink *sink;

	sink = sink_find(name);
	if (sink)
		goto end;

	sink = malloc(sizeof(*sink));
	if (!sink)
		goto end;

	sink->name = name;
	sink->desc = desc;
	sink->fmt  = fmt;
	sink->type = SINK_TYPE_NEW;
	/* set defaults for syslog ones */
	sink->syslog_facility = 0;
	sink->syslog_minlvl   = 0;
	sink->maxlen = BUFSIZE;
	/* address will be filled by the caller if needed */
	sink->ctx.fd = -1;
	sink->ctx.dropped = 0;
	HA_RWLOCK_INIT(&sink->ctx.lock);
	LIST_ADDQ(&sink_list, &sink->sink_list);
 end:
	return sink;
}

/* creates a sink called <name> of type FD associated to fd <fd>, format <fmt>,
 * and description <desc>. Returns NULL on allocation failure or conflict.
 * Perfect duplicates are merged (same type, fd, and name).
 */
struct sink *sink_new_fd(const char *name, const char *desc, enum sink_fmt fmt, int fd)
{
	struct sink *sink;

	sink = __sink_new(name, desc, fmt);
	if (!sink || (sink->type == SINK_TYPE_FD && sink->ctx.fd == fd))
		goto end;

	if (sink->type != SINK_TYPE_NEW) {
		sink = NULL;
		goto end;
	}

	sink->type = SINK_TYPE_FD;
	sink->ctx.fd = fd;
 end:
	return sink;
}

/* creates a sink called <name> of type BUF of size <size>, format <fmt>,
 * and description <desc>. Returns NULL on allocation failure or conflict.
 * Perfect duplicates are merged (same type and name). If sizes differ, the
 * largest one is kept.
 */
struct sink *sink_new_buf(const char *name, const char *desc, enum sink_fmt fmt, size_t size)
{
	struct sink *sink;

	sink = __sink_new(name, desc, fmt);
	if (!sink)
		goto fail;

	if (sink->type == SINK_TYPE_BUFFER) {
		/* such a buffer already exists, we may have to resize it */
		if (!ring_resize(sink->ctx.ring, size))
			goto fail;
		goto end;
	}

	if (sink->type != SINK_TYPE_NEW) {
		/* already exists of another type */
		goto fail;
	}

	sink->ctx.ring = ring_new(size);
	if (!sink->ctx.ring) {
		LIST_DEL(&sink->sink_list);
		free(sink);
		goto fail;
	}

	sink->type = SINK_TYPE_BUFFER;
 end:
	return sink;
 fail:
	return NULL;
}

/* tries to send <nmsg> message parts (up to 8, ignored above) from message
 * array <msg> to sink <sink>. Formating according to the sink's preference is
 * done here. Lost messages are NOT accounted for. It is preferable to call
 * sink_write() instead which will also try to emit the number of dropped
 * messages when there are any. It returns >0 if it could write anything,
 * <=0 otherwise.
 */
ssize_t __sink_write(struct sink *sink, const struct ist msg[], size_t nmsg)
{
	char short_hdr[4];
	struct ist pfx[4];
	size_t npfx = 0;

	if (sink->fmt == SINK_FMT_SHORT || sink->fmt == SINK_FMT_TIMED) {
		short_hdr[0] = '<';
		short_hdr[1] = '0' + sink->syslog_minlvl;
		short_hdr[2] = '>';

		pfx[npfx].ptr = short_hdr;
		pfx[npfx].len = 3;
		npfx++;
        }

	if (sink->fmt == SINK_FMT_ISO || sink->fmt == SINK_FMT_TIMED) {
		pfx[npfx].ptr = timeofday_as_iso_us(1);
		pfx[npfx].len = 27;
		npfx++;
        }

	if (sink->type == SINK_TYPE_FD) {
		return fd_write_frag_line(sink->ctx.fd, sink->maxlen, pfx, npfx, msg, nmsg, 1);
	}
	else if (sink->type == SINK_TYPE_BUFFER) {
		return ring_write(sink->ctx.ring, sink->maxlen, pfx, npfx, msg, nmsg);
	}
	return 0;
}

/* Tries to emit a message indicating the number of dropped events. In case of
 * success, the amount of drops is reduced by as much. It's supposed to be
 * called under an exclusive lock on the sink to avoid multiple produces doing
 * the same. On success, >0 is returned, otherwise <=0 on failure.
 */
int sink_announce_dropped(struct sink *sink)
{
	unsigned int dropped;
	struct buffer msg;
	struct ist msgvec[1];
	char logbuf[64];

	while (unlikely((dropped = sink->ctx.dropped) > 0)) {
		chunk_init(&msg, logbuf, sizeof(logbuf));
		chunk_printf(&msg, "%u event%s dropped", dropped, dropped > 1 ? "s" : "");
		msgvec[0] = ist2(msg.area, msg.data);
		if (__sink_write(sink, msgvec, 1) <= 0)
			return 0;
		/* success! */
		HA_ATOMIC_SUB(&sink->ctx.dropped, dropped);
	}
	return 1;
}

/* parse the "show events" command, returns 1 if a message is returned, otherwise zero */
static int cli_parse_show_events(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct sink *sink;
	int arg;

	args++; // make args[1] the 1st arg

	if (!*args[1]) {
		/* no arg => report the list of supported sink */
		chunk_printf(&trash, "Supported events sinks are listed below. Add -w(wait), -n(new). Any key to stop\n");
		list_for_each_entry(sink, &sink_list, sink_list) {
			chunk_appendf(&trash, "    %-10s : type=%s, %u dropped, %s\n",
				      sink->name,
				      sink->type == SINK_TYPE_NEW ? "init" :
				      sink->type == SINK_TYPE_FD ? "fd" :
				      sink->type == SINK_TYPE_BUFFER ? "buffer" : "?",
				      sink->ctx.dropped, sink->desc);
		}

		trash.area[trash.data] = 0;
		return cli_msg(appctx, LOG_WARNING, trash.area);
	}

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	sink = sink_find(args[1]);
	if (!sink)
		return cli_err(appctx, "No such event sink");

	if (sink->type != SINK_TYPE_BUFFER)
		return cli_msg(appctx, LOG_NOTICE, "Nothing to report for this sink");

	for (arg = 2; *args[arg]; arg++) {
		if (strcmp(args[arg], "-w") == 0)
			appctx->ctx.cli.i0 |= 1; // wait mode
		else if (strcmp(args[arg], "-n") == 0)
			appctx->ctx.cli.i0 |= 2; // seek to new
		else if (strcmp(args[arg], "-nw") == 0 || strcmp(args[arg], "-wn") == 0)
			appctx->ctx.cli.i0 |= 3; // seek to new + wait
		else
			return cli_err(appctx, "unknown option");
	}
	return ring_attach_cli(sink->ctx.ring, appctx);
}

static void sink_init()
{
	sink_new_fd("stdout", "standard output (fd#1)", SINK_FMT_RAW, 1);
	sink_new_fd("stderr", "standard output (fd#2)", SINK_FMT_RAW, 2);
	sink_new_buf("buf0",  "in-memory ring buffer", SINK_FMT_TIMED, 1048576);
}

static void sink_deinit()
{
	struct sink *sink, *sb;

	list_for_each_entry_safe(sink, sb, &sink_list, sink_list) {
		if (sink->type == SINK_TYPE_BUFFER)
			ring_free(sink->ctx.ring);
		LIST_DEL(&sink->sink_list);
		free(sink);
	}
}

INITCALL0(STG_REGISTER, sink_init);
REGISTER_POST_DEINIT(sink_deinit);

static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "events", NULL }, "show events [<sink>] : show event sink state", cli_parse_show_events, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
