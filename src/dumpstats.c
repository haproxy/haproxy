/*
 * Functions dedicated to statistics output
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/global.h>

#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/dumpstats.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/pipe.h>
#include <proto/proto_uxst.h>
#include <proto/session.h>
#include <proto/server.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

/* This function parses a "stats" statement in the "global" section. It returns
 * -1 if there is any error, otherwise zero. If it returns -1, it may write an
 * error message into ther <err> buffer, for at most <errlen> bytes, trailing
 * zero included. The trailing '\n' must not be written. The function must be
 * called with <args> pointing to the first word after "stats".
 */
static int stats_parse_global(char **args, int section_type, struct proxy *curpx,
			      struct proxy *defpx, char *err, int errlen)
{
	args++;
	if (!strcmp(args[0], "socket")) {
		struct sockaddr_un su;
		int cur_arg;

		if (*args[1] == 0) {
			snprintf(err, errlen, "'stats socket' in global section expects a path to a UNIX socket");
			return -1;
		}

		if (global.stats_sock.state != LI_NEW) {
			snprintf(err, errlen, "'stats socket' already specified in global section");
			return -1;
		}

		su.sun_family = AF_UNIX;
		strncpy(su.sun_path, args[1], sizeof(su.sun_path));
		su.sun_path[sizeof(su.sun_path) - 1] = 0;
		memcpy(&global.stats_sock.addr, &su, sizeof(su)); // guaranteed to fit

		global.stats_sock.state = LI_INIT;
		global.stats_sock.options = LI_O_NONE;
		global.stats_sock.accept = uxst_event_accept;
		global.stats_sock.handler = uxst_process_session;
		global.stats_sock.analysers = AN_REQ_UNIX_STATS;
		global.stats_sock.private = NULL;

		cur_arg = 2;
		while (*args[cur_arg]) {
			if (!strcmp(args[cur_arg], "uid")) {
				global.stats_sock.perm.ux.uid = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "gid")) {
				global.stats_sock.perm.ux.gid = atol(args[cur_arg + 1]);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "mode")) {
				global.stats_sock.perm.ux.mode = strtol(args[cur_arg + 1], NULL, 8);
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "user")) {
				struct passwd *user;
				user = getpwnam(args[cur_arg + 1]);
				if (!user) {
					snprintf(err, errlen, "unknown user '%s' in 'global' section ('stats user')",
						 args[cur_arg + 1]);
					return -1;
				}
				global.stats_sock.perm.ux.uid = user->pw_uid;
				cur_arg += 2;
			}
			else if (!strcmp(args[cur_arg], "group")) {
				struct group *group;
				group = getgrnam(args[cur_arg + 1]);
				if (!group) {
					snprintf(err, errlen, "unknown group '%s' in 'global' section ('stats group')",
						 args[cur_arg + 1]);
					return -1;
				}
				global.stats_sock.perm.ux.gid = group->gr_gid;
				cur_arg += 2;
			}
			else {
				snprintf(err, errlen, "'stats socket' only supports 'user', 'uid', 'group', 'gid', and 'mode'");
				return -1;
			}
		}

		uxst_add_listener(&global.stats_sock);
		global.maxsock++;
	}
	else if (!strcmp(args[0], "timeout")) {
		unsigned timeout;
		const char *res = parse_time_err(args[1], &timeout, TIME_UNIT_MS);

		if (res) {
			snprintf(err, errlen, "unexpected character '%c' in 'stats timeout' in 'global' section", *res);
			return -1;
		}

		if (!timeout) {
			snprintf(err, errlen, "a positive value is expected for 'stats timeout' in 'global section'");
			return -1;
		}
		global.stats_timeout = MS_TO_TICKS(timeout);
	}
	else if (!strcmp(args[0], "maxconn")) {
		int maxconn = atol(args[1]);

		if (maxconn <= 0) {
			snprintf(err, errlen, "a positive value is expected for 'stats maxconn' in 'global section'");
			return -1;
		}
		global.maxsock -= global.stats_sock.maxconn;
		global.stats_sock.maxconn = maxconn;
		global.maxsock += global.stats_sock.maxconn;
	}
	else {
		snprintf(err, errlen, "'stats' only supports 'socket', 'maxconn' and 'timeout' in 'global' section");
		return -1;
	}
	return 0;
}

int print_csv_header(struct chunk *msg, int size)
{
	return chunk_printf(msg, size,
			    "# pxname,svname,"
			    "qcur,qmax,"
			    "scur,smax,slim,stot,"
			    "bin,bout,"
			    "dreq,dresp,"
			    "ereq,econ,eresp,"
			    "wretr,wredis,"
			    "status,weight,act,bck,"
			    "chkfail,chkdown,lastchg,downtime,qlimit,"
			    "pid,iid,sid,throttle,lbtot,tracked,type,"
			    "rate,rate_lim,rate_max,"
			    "\n");
}

/*
 * Produces statistics data for the session <s>. Expects to be called with
 * client socket shut down on input. It *may* make use of informations from
 * <uri>. s->data_ctx must have been zeroed first, and the flags properly set.
 * It returns 0 if it had to stop writing data and an I/O is needed, 1 if the
 * dump is finished and the session must be closed, or -1 in case of any error.
 * It automatically clears the HIJACK bit from the response buffer.
 */
int stats_dump_raw(struct session *s, struct buffer *rep, struct uri_auth *uri)
{
	struct proxy *px;
	struct chunk msg;
	unsigned int up;

	msg.len = 0;
	msg.str = trash;

	switch (s->data_state) {
	case DATA_ST_INIT:
		/* the function had not been called yet, let's prepare the
		 * buffer for a response.
		 */
		stream_int_retnclose(rep->cons, &msg);
		s->data_state = DATA_ST_HEAD;
		/* fall through */

	case DATA_ST_HEAD:
		if (s->data_ctx.stats.flags & STAT_SHOW_STAT) {
			print_csv_header(&msg, sizeof(trash));
			if (buffer_write_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_state = DATA_ST_INFO;
		/* fall through */

	case DATA_ST_INFO:
		up = (now.tv_sec - start_date.tv_sec);
		if (s->data_ctx.stats.flags & STAT_SHOW_INFO) {
			chunk_printf(&msg, sizeof(trash),
				     "Name: " PRODUCT_NAME "\n"
				     "Version: " HAPROXY_VERSION "\n"
				     "Release_date: " HAPROXY_DATE "\n"
				     "Nbproc: %d\n"
				     "Process_num: %d\n"
				     "Pid: %d\n"
				     "Uptime: %dd %dh%02dm%02ds\n"
				     "Uptime_sec: %d\n"
				     "Memmax_MB: %d\n"
				     "Ulimit-n: %d\n"
				     "Maxsock: %d\n"
				     "Maxconn: %d\n"
				     "Maxpipes: %d\n"
				     "CurrConns: %d\n"
				     "PipesUsed: %d\n"
				     "PipesFree: %d\n"
				     "Tasks: %d\n"
				     "Run_queue: %d\n"
				     "node: %s\n"
				     "description: %s\n"
				     "",
				     global.nbproc,
				     relative_pid,
				     pid,
				     up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60),
				     up,
				     global.rlimit_memmax,
				     global.rlimit_nofile,
				     global.maxsock, global.maxconn, global.maxpipes,
				     actconn, pipes_used, pipes_free,
				     nb_tasks_cur, run_queue_cur,
				     global.node, global.desc?global.desc:""
				     );
			if (buffer_write_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.px = proxy;
		s->data_ctx.stats.px_st = DATA_ST_PX_INIT;

		s->data_ctx.stats.sv = NULL;
		s->data_ctx.stats.sv_st = 0;

		s->data_state = DATA_ST_LIST;
		/* fall through */

	case DATA_ST_LIST:
		/* dump proxies */
		if (s->data_ctx.stats.flags & STAT_SHOW_STAT) {
			while (s->data_ctx.stats.px) {
				px = s->data_ctx.stats.px;
				/* skip the disabled proxies and non-networked ones */
				if (px->state != PR_STSTOPPED &&
				    (px->cap & (PR_CAP_FE | PR_CAP_BE)))
					if (stats_dump_proxy(s, px, NULL) == 0)
						return 0;

				s->data_ctx.stats.px = px->next;
				s->data_ctx.stats.px_st = DATA_ST_PX_INIT;
			}
			/* here, we just have reached the last proxy */
		}

		s->data_state = DATA_ST_END;
		/* fall through */

	case DATA_ST_END:
		s->data_state = DATA_ST_FIN;
		/* fall through */

	case DATA_ST_FIN:
		buffer_stop_hijack(rep);
		return 1;

	default:
		/* unknown state ! */
		buffer_stop_hijack(rep);
		return -1;
	}
}


/* This function is called to send output to the response buffer. It simply
 * calls stats_dump_raw(), and releases the buffer's hijack bit when the dump
 * is finished.
 */
void stats_dump_raw_to_buffer(struct session *s, struct buffer *rep)
{
	if (s->ana_state != STATS_ST_REP)
		return;

	if (stats_dump_raw(s, rep, NULL) != 0)
		s->ana_state = STATS_ST_CLOSE;
	return;
}


/*
 * Produces statistics data for the session <s>. Expects to be called with
 * client socket shut down on input. It stops by itself by unsetting the
 * BF_HIJACK flag from the buffer, which it uses to keep on being called
 * when there is free space in the buffer, of simply by letting an empty buffer
 * upon return.s->data_ctx must have been zeroed before the first call, and the
 * flags set. It returns 0 if it had to stop writing data and an I/O is needed,
 * 1 if the dump is finished and the session must be closed, or -1 in case of
 * any error.
 */
int stats_dump_http(struct session *s, struct buffer *rep, struct uri_auth *uri)
{
	struct proxy *px;
	struct chunk msg;
	unsigned int up;

	msg.len = 0;
	msg.str = trash;

	switch (s->data_state) {
	case DATA_ST_INIT:
		chunk_printf(&msg, sizeof(trash),
			     "HTTP/1.0 200 OK\r\n"
			     "Cache-Control: no-cache\r\n"
			     "Connection: close\r\n"
			     "Content-Type: %s\r\n",
			     (s->data_ctx.stats.flags & STAT_FMT_CSV) ? "text/plain" : "text/html");

		if (uri->refresh > 0 && !(s->data_ctx.stats.flags & STAT_NO_REFRESH))
			chunk_printf(&msg, sizeof(trash), "Refresh: %d\r\n",
				     uri->refresh);

		chunk_printf(&msg, sizeof(trash), "\r\n");

		s->txn.status = 200;
		stream_int_retnclose(rep->cons, &msg); // send the start of the response.
		msg.len = 0;

		if (!(s->flags & SN_ERR_MASK))  // this is not really an error but it is
			s->flags |= SN_ERR_PRXCOND; // to mark that it comes from the proxy
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;

		if (s->txn.meth == HTTP_METH_HEAD) {
			/* that's all we return in case of HEAD request */
			s->data_state = DATA_ST_FIN;
			buffer_stop_hijack(rep);
			return 1;
		}

		s->data_state = DATA_ST_HEAD; /* let's start producing data */
		/* fall through */

	case DATA_ST_HEAD:
		if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
			/* WARNING! This must fit in the first buffer !!! */	    
			chunk_printf(&msg, sizeof(trash),
			     "<html><head><title>Statistics Report for " PRODUCT_NAME "%s%s</title>\n"
			     "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">\n"
			     "<style type=\"text/css\"><!--\n"
			     "body {"
			     " font-family: arial, helvetica, sans-serif;"
			     " font-size: 12px;"
			     " font-weight: normal;"
			     " color: black;"
			     " background: white;"
			     "}\n"
			     "th,td {"
			     " font-size: 10px;"
			     " align: center;"
			     "}\n"
			     "h1 {"
			     " font-size: x-large;"
			     " margin-bottom: 0.5em;"
			     "}\n"
			     "h2 {"
			     " font-family: helvetica, arial;"
			     " font-size: x-large;"
			     " font-weight: bold;"
			     " font-style: italic;"
			     " color: #6020a0;"
			     " margin-top: 0em;"
			     " margin-bottom: 0em;"
			     "}\n"
			     "h3 {"
			     " font-family: helvetica, arial;"
			     " font-size: 16px;"
			     " font-weight: bold;"
			     " color: #b00040;"
			     " background: #e8e8d0;"
			     " margin-top: 0em;"
			     " margin-bottom: 0em;"
			     "}\n"
			     "li {"
			     " margin-top: 0.25em;"
			     " margin-right: 2em;"
			     "}\n"
			     ".hr {margin-top: 0.25em;"
			     " border-color: black;"
			     " border-bottom-style: solid;"
			     "}\n"
			     ".titre	{background: #20D0D0;color: #000000; font-weight: bold;}\n"
			     ".total	{background: #20D0D0;color: #ffff80;}\n"
			     ".frontend	{background: #e8e8d0;}\n"
			     ".backend	{background: #e8e8d0;}\n"
			     ".active0	{background: #ff9090;}\n"
			     ".active1	{background: #ffd020;}\n"
			     ".active2	{background: #ffffa0;}\n"
			     ".active3	{background: #c0ffc0;}\n"
			     ".active4	{background: #ffffa0;}\n"  /* NOLB state shows same as going down */
			     ".active5	{background: #a0e0a0;}\n"  /* NOLB state shows darker than up */
			     ".active6	{background: #e0e0e0;}\n"
			     ".backup0	{background: #ff9090;}\n"
			     ".backup1	{background: #ff80ff;}\n"
			     ".backup2	{background: #c060ff;}\n"
			     ".backup3	{background: #b0d0ff;}\n"
			     ".backup4	{background: #c060ff;}\n"  /* NOLB state shows same as going down */
			     ".backup5	{background: #90b0e0;}\n"  /* NOLB state shows same as going down */
			     ".backup6	{background: #e0e0e0;}\n"
			     ".rls      {letter-spacing: 0.2em; margin-right: 1px;}\n" /* right letter spacing (used for grouping digits) */
			     "table.tbl { border-collapse: collapse; border-style: none;}\n"
			     "table.tbl td { border-width: 1px 1px 1px 1px; border-style: solid solid solid solid; padding: 2px 3px; border-color: gray;}\n"
			     "table.tbl th { border-width: 1px; border-style: solid solid solid solid; border-color: gray;}\n"
			     "table.tbl th.pxname {background: #b00040; color: #ffff40; font-weight: bold; border-style: solid solid none solid; padding: 2px 3px; white-space: nowrap;}\n"
			     "table.tbl th.empty { border-style: none; empty-cells: hide; background: white;}\n"
			     "table.tbl th.desc { background: white; border-style: solid solid none solid; text-align: left; padding: 2px 3px;}\n"
			     "table.lgd { border-collapse: collapse; border-width: 1px; border-style: none none none solid; border-color: black;}\n"
			     "table.lgd td { border-width: 1px; border-style: solid solid solid solid; border-color: gray; padding: 2px;}\n"
			     "table.lgd td.noborder { border-style: none; padding: 2px; white-space: nowrap;}\n"
			     "-->\n"
			     "</style></head>\n",
			     (uri->flags&ST_SHNODE) ? " on " : "",
			     (uri->flags&ST_SHNODE) ? (uri->node ? uri->node : global.node) : ""
			     );
		} else {
			print_csv_header(&msg, sizeof(trash));
		}
		if (buffer_write_chunk(rep, &msg) >= 0)
			return 0;

		s->data_state = DATA_ST_INFO;
		/* fall through */

	case DATA_ST_INFO:
		up = (now.tv_sec - start_date.tv_sec);

		/* WARNING! this has to fit the first packet too.
			 * We are around 3.5 kB, add adding entries will
			 * become tricky if we want to support 4kB buffers !
			 */
		if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
			chunk_printf(&msg, sizeof(trash),
			     "<body><h1><a href=\"" PRODUCT_URL "\" style=\"text-decoration: none;\">"
			     PRODUCT_NAME "%s</a></h1>\n"
			     "<h2>Statistics Report for pid %d%s%s%s%s</h2>\n"
			     "<hr width=\"100%%\" class=\"hr\">\n"
			     "<h3>&gt; General process information</h3>\n"
			     "<table border=0 cols=4><tr><td align=\"left\" nowrap width=\"1%%\">\n"
			     "<p><b>pid = </b> %d (process #%d, nbproc = %d)<br>\n"
			     "<b>uptime = </b> %dd %dh%02dm%02ds<br>\n"
			     "<b>system limits:</b> memmax = %s%s; ulimit-n = %d<br>\n"
			     "<b>maxsock = </b> %d; <b>maxconn = </b> %d; <b>maxpipes = </b> %d<br>\n"
			     "current conns = %d; current pipes = %d/%d<br>\n"
			     "Running tasks: %d/%d<br>\n"
			     "</td><td align=\"center\" nowrap>\n"
			     "<table class=\"lgd\"><tr>\n"
			     "<td class=\"active3\">&nbsp;</td><td class=\"noborder\">active UP </td>"
			     "<td class=\"backup3\">&nbsp;</td><td class=\"noborder\">backup UP </td>"
			     "</tr><tr>\n"
			     "<td class=\"active2\"></td><td class=\"noborder\">active UP, going down </td>"
			     "<td class=\"backup2\"></td><td class=\"noborder\">backup UP, going down </td>"
			     "</tr><tr>\n"
			     "<td class=\"active1\"></td><td class=\"noborder\">active DOWN, going up </td>"
			     "<td class=\"backup1\"></td><td class=\"noborder\">backup DOWN, going up </td>"
			     "</tr><tr>\n"
			     "<td class=\"active0\"></td><td class=\"noborder\">active or backup DOWN &nbsp;</td>"
			     "<td class=\"active6\"></td><td class=\"noborder\">not checked </td>"
			     "</tr></table>\n"
			     "Note: UP with load-balancing disabled is reported as \"NOLB\"."
			     "</td>"
			     "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
			     "<b>Display option:</b><ul style=\"margin-top: 0.25em;\">"
			     "",
			     (uri->flags&ST_HIDEVER)?"":(STATS_VERSION_STRING),
			     pid, (uri->flags&ST_SHNODE) ? " on " : "", (uri->flags&ST_SHNODE) ? (uri->node ? uri->node : global.node) : "",
			     (uri->flags&ST_SHDESC)? ": " : "", (uri->flags&ST_SHDESC) ? (uri->desc ? uri->desc : global.desc) : "",
			     pid, relative_pid, global.nbproc,
			     up / 86400, (up % 86400) / 3600,
			     (up % 3600) / 60, (up % 60),
			     global.rlimit_memmax ? ultoa(global.rlimit_memmax) : "unlimited",
			     global.rlimit_memmax ? " MB" : "",
			     global.rlimit_nofile,
			     global.maxsock, global.maxconn, global.maxpipes,
			     actconn, pipes_used, pipes_used+pipes_free,
			     run_queue_cur, nb_tasks_cur
			     );

			if (s->data_ctx.stats.flags & STAT_HIDE_DOWN)
				chunk_printf(&msg, sizeof(trash),
				     "<li><a href=\"%s%s%s\">Show all servers</a><br>\n",
				     uri->uri_prefix,
				     "",
				     (s->data_ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "");
			else
				chunk_printf(&msg, sizeof(trash),
				     "<li><a href=\"%s%s%s\">Hide 'DOWN' servers</a><br>\n",
				     uri->uri_prefix,
				     ";up",
				     (s->data_ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "");

			if (uri->refresh > 0) {
				if (s->data_ctx.stats.flags & STAT_NO_REFRESH)
					chunk_printf(&msg, sizeof(trash),
					     "<li><a href=\"%s%s%s\">Enable refresh</a><br>\n",
					     uri->uri_prefix,
					     (s->data_ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
					     "");
				else
					chunk_printf(&msg, sizeof(trash),
					     "<li><a href=\"%s%s%s\">Disable refresh</a><br>\n",
					     uri->uri_prefix,
					     (s->data_ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
					     ";norefresh");
			}

			chunk_printf(&msg, sizeof(trash),
			     "<li><a href=\"%s%s%s\">Refresh now</a><br>\n",
			     uri->uri_prefix,
			     (s->data_ctx.stats.flags & STAT_HIDE_DOWN) ? ";up" : "",
			     (s->data_ctx.stats.flags & STAT_NO_REFRESH) ? ";norefresh" : "");

			chunk_printf(&msg, sizeof(trash),
			     "<li><a href=\"%s;csv%s\">CSV export</a><br>\n",
			     uri->uri_prefix,
			     (uri->refresh > 0) ? ";norefresh" : "");

			chunk_printf(&msg, sizeof(trash),
			     "</td>"
			     "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
			     "<b>External ressources:</b><ul style=\"margin-top: 0.25em;\">\n"
			     "<li><a href=\"" PRODUCT_URL "\">Primary site</a><br>\n"
			     "<li><a href=\"" PRODUCT_URL_UPD "\">Updates (v" PRODUCT_BRANCH ")</a><br>\n"
			     "<li><a href=\"" PRODUCT_URL_DOC "\">Online manual</a><br>\n"
			     "</ul>"
			     "</td>"
			     "</tr></table>\n"
			     ""
			     );

			if (buffer_write_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.px = proxy;
		s->data_ctx.stats.px_st = DATA_ST_PX_INIT;
		s->data_state = DATA_ST_LIST;
		/* fall through */

	case DATA_ST_LIST:
		/* dump proxies */
		while (s->data_ctx.stats.px) {
			px = s->data_ctx.stats.px;
			/* skip the disabled proxies and non-networked ones */
			if (px->state != PR_STSTOPPED && (px->cap & (PR_CAP_FE | PR_CAP_BE)))
				if (stats_dump_proxy(s, px, uri) == 0)
					return 0;

			s->data_ctx.stats.px = px->next;
			s->data_ctx.stats.px_st = DATA_ST_PX_INIT;
		}
		/* here, we just have reached the last proxy */

		s->data_state = DATA_ST_END;
		/* fall through */

	case DATA_ST_END:
		if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
			chunk_printf(&msg, sizeof(trash), "</body></html>\n");
			if (buffer_write_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_state = DATA_ST_FIN;
		/* fall through */

	case DATA_ST_FIN:
		buffer_stop_hijack(rep);
		return 1;

	default:
		/* unknown state ! */
		buffer_stop_hijack(rep);
		return -1;
	}
}


/*
 * Dumps statistics for a proxy.
 * Returns 0 if it had to stop dumping data because of lack of buffer space,
 * ot non-zero if everything completed.
 */
int stats_dump_proxy(struct session *s, struct proxy *px, struct uri_auth *uri)
{
	struct buffer *rep = s->rep;
	struct server *sv, *svs;	/* server and server-state, server-state=server or server->tracked */
	struct chunk msg;

	msg.len = 0;
	msg.str = trash;

	switch (s->data_ctx.stats.px_st) {
	case DATA_ST_PX_INIT:
		/* we are on a new proxy */

		if (uri && uri->scope) {
			/* we have a limited scope, we have to check the proxy name */
			struct stat_scope *scope;
			int len;

			len = strlen(px->id);
			scope = uri->scope;

			while (scope) {
				/* match exact proxy name */
				if (scope->px_len == len && !memcmp(px->id, scope->px_id, len))
					break;

				/* match '.' which means 'self' proxy */
				if (!strcmp(scope->px_id, ".") && px == s->be)
					break;
				scope = scope->next;
			}

			/* proxy name not found : don't dump anything */
			if (scope == NULL)
				return 1;
		}

		if ((s->data_ctx.stats.flags & STAT_BOUND) && (s->data_ctx.stats.iid != -1) &&
			(px->uuid != s->data_ctx.stats.iid))
			return 1;

		s->data_ctx.stats.px_st = DATA_ST_PX_TH;
		/* fall through */

	case DATA_ST_PX_TH:
		if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
			/* print a new table */
			chunk_printf(&msg, sizeof(trash),
				     "<table class=\"tbl\" width=\"100%%\">\n"
				     "<tr align=\"center\" class=\"titre\">"
				     "<th class=\"pxname\" width=\"10%%\">%s</th>"
				     "<th class=\"%s\" width=\"90%%\">%s</th>"
				     "</tr>\n"
				     "</table>\n"
				     "<table cols=\"29\" class=\"tbl\" width=\"100%%\">\n"
				     "<tr align=\"center\" class=\"titre\">"
				     "<th rowspan=2></th>"
				     "<th colspan=3>Queue</th>"
				     "<th colspan=3>Session rate</th><th colspan=5>Sessions</th>"
				     "<th colspan=2>Bytes</th><th colspan=2>Denied</th>"
				     "<th colspan=3>Errors</th><th colspan=2>Warnings</th>"
				     "<th colspan=8>Server</th>"
				     "</tr>\n"
				     "<tr align=\"center\" class=\"titre\">"
				     "<th>Cur</th><th>Max</th><th>Limit</th>"
				     "<th>Cur</th><th>Max</th><th>Limit</th><th>Cur</th><th>Max</th>"
				     "<th>Limit</th><th>Total</th><th>LbTot</th><th>In</th><th>Out</th>"
				     "<th>Req</th><th>Resp</th><th>Req</th><th>Conn</th>"
				     "<th>Resp</th><th>Retr</th><th>Redis</th>"
				     "<th>Status</th><th>Wght</th><th>Act</th>"
				     "<th>Bck</th><th>Chk</th><th>Dwn</th><th>Dwntme</th>"
				     "<th>Thrtle</th>\n"
				     "</tr>",
				     px->id,
				     px->desc ? "desc" : "empty", px->desc ? px->desc : "");

			if (buffer_write_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.px_st = DATA_ST_PX_FE;
		/* fall through */

	case DATA_ST_PX_FE:
		/* print the frontend */
		if ((px->cap & PR_CAP_FE) &&
		    (!(s->data_ctx.stats.flags & STAT_BOUND) || (s->data_ctx.stats.type & (1 << STATS_TYPE_FE)))) {
			if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
				chunk_printf(&msg, sizeof(trash),
				     /* name, queue */
				     "<tr align=center class=\"frontend\"><td>Frontend</td><td colspan=3></td>"
				     /* sessions rate : current, max, limit */
				     "<td align=right>%s</td><td align=right>%s</td><td align=right>%s</td>"
				     /* sessions : current, max, limit, total, lbtot */
				     "<td align=right>%s</td><td align=right>%s</td><td align=right>%s</td>"
				     "<td align=right>%s</td><td align=right></td>"
				     /* bytes : in, out */
				     "<td align=right>%s</td><td align=right>%s</td>"
				     "",
				     U2H0(read_freq_ctr(&px->fe_sess_per_sec)),
				     U2H1(px->fe_sps_max), LIM2A2(px->fe_sps_lim, "-"),
				     U2H3(px->feconn), U2H4(px->feconn_max), U2H5(px->maxconn),
				     U2H6(px->cum_feconn), U2H7(px->bytes_in), U2H8(px->bytes_out));

				chunk_printf(&msg, sizeof(trash),
				     /* denied: req, resp */
				     "<td align=right>%s</td><td align=right>%s</td>"
				     /* errors : request, connect, response */
				     "<td align=right>%s</td><td align=right></td><td align=right></td>"
				     /* warnings: retries, redispatches */
				     "<td align=right></td><td align=right></td>"
				     /* server status : reflect frontend status */
				     "<td align=center>%s</td>"
				     /* rest of server: nothing */
				     "<td align=center colspan=7></td></tr>"
				     "",
				     U2H0(px->denied_req), U2H1(px->denied_resp),
				     U2H2(px->failed_req),
				     px->state == PR_STRUN ? "OPEN" :
				     px->state == PR_STIDLE ? "FULL" : "STOP");
			} else {
				chunk_printf(&msg, sizeof(trash),
				     /* pxid, name, queue cur, queue max, */
				     "%s,FRONTEND,,,"
				     /* sessions : current, max, limit, total */
				     "%d,%d,%d,%lld,"
				     /* bytes : in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     "%lld,%lld,"
				     /* errors : request, connect, response */
				     "%lld,,,"
				     /* warnings: retries, redispatches */
				     ",,"
				     /* server status : reflect frontend status */
				     "%s,"
				     /* rest of server: nothing */
				     ",,,,,,,,"
				     /* pid, iid, sid, throttle, lbtot, tracked, type */
				     "%d,%d,0,,,,%d,"
				     /* rate, rate_lim, rate_max, */
				     "%u,%u,%u,"
				     "\n",
				     px->id,
				     px->feconn, px->feconn_max, px->maxconn, px->cum_feconn,
				     px->bytes_in, px->bytes_out,
				     px->denied_req, px->denied_resp,
				     px->failed_req,
				     px->state == PR_STRUN ? "OPEN" :
				     px->state == PR_STIDLE ? "FULL" : "STOP",
				     relative_pid, px->uuid, STATS_TYPE_FE,
				     read_freq_ctr(&px->fe_sess_per_sec),
				     px->fe_sps_lim, px->fe_sps_max);
			}

			if (buffer_write_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.sv = px->srv; /* may be NULL */
		s->data_ctx.stats.px_st = DATA_ST_PX_SV;
		/* fall through */

	case DATA_ST_PX_SV:
		/* stats.sv has been initialized above */
		for (; s->data_ctx.stats.sv != NULL; s->data_ctx.stats.sv = sv->next) {

			int sv_state; /* 0=DOWN, 1=going up, 2=going down, 3=UP, 4,5=NOLB, 6=unchecked */

			sv = s->data_ctx.stats.sv;

			if (s->data_ctx.stats.flags & STAT_BOUND) {
				if (!(s->data_ctx.stats.type & (1 << STATS_TYPE_SV)))
					break;

				if (s->data_ctx.stats.sid != -1 && sv->puid != s->data_ctx.stats.sid)
					continue;
			}

			if (sv->tracked)
				svs = sv->tracked;
			else
				svs = sv;

			/* FIXME: produce some small strings for "UP/DOWN x/y &#xxxx;" */
			if (!(svs->state & SRV_CHECKED))
				sv_state = 6;
			else if (svs->state & SRV_RUNNING) {
				if (svs->health == svs->rise + svs->fall - 1)
					sv_state = 3; /* UP */
				else
					sv_state = 2; /* going down */

				if (svs->state & SRV_GOINGDOWN)
					sv_state += 2;
			}
			else
				if (svs->health)
					sv_state = 1; /* going up */
				else
					sv_state = 0; /* DOWN */

			if ((sv_state == 0) && (s->data_ctx.stats.flags & STAT_HIDE_DOWN)) {
				/* do not report servers which are DOWN */
				s->data_ctx.stats.sv = sv->next;
				continue;
			}

			if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
				static char *srv_hlt_st[7] = { "DOWN", "DN %d/%d &uarr;",
							       "UP %d/%d &darr;", "UP",
							       "NOLB %d/%d &darr;", "NOLB",
							       "<i>no check</i>" };
				chunk_printf(&msg, sizeof(trash),
				     /* name */
				     "<tr align=\"center\" class=\"%s%d\"><td>%s</td>"
				     /* queue : current, max, limit */
				     "<td align=right>%s</td><td align=right>%s</td><td align=right>%s</td>"
				     /* sessions rate : current, max, limit */
				     "<td align=right>%s</td><td align=right>%s</td><td align=right></td>"
				     /* sessions : current, max, limit, total, lbtot */
				     "<td align=right>%s</td><td align=right>%s</td><td align=right>%s</td>"
				     "<td align=right>%s</td><td align=right>%s</td>"
				     "",
				     (sv->state & SRV_BACKUP) ? "backup" : "active",
				     sv_state, sv->id,
				     U2H0(sv->nbpend), U2H1(sv->nbpend_max), LIM2A2(sv->maxqueue, "-"),
				     U2H3(read_freq_ctr(&sv->sess_per_sec)), U2H4(sv->sps_max),
				     U2H5(sv->cur_sess), U2H6(sv->cur_sess_max), LIM2A7(sv->maxconn, "-"),
				     U2H8(sv->cum_sess), U2H9(sv->cum_lbconn));

				chunk_printf(&msg, sizeof(trash),
				     /* bytes : in, out */
				     "<td align=right>%s</td><td align=right>%s</td>"
				     /* denied: req, resp */
				     "<td align=right></td><td align=right>%s</td>"
				     /* errors : request, connect, response */
				     "<td align=right></td><td align=right>%s</td><td align=right>%s</td>\n"
				     /* warnings: retries, redispatches */
				     "<td align=right>%lld</td><td align=right>%lld</td>"
				     "",
				     U2H0(sv->bytes_in), U2H1(sv->bytes_out),
				     U2H2(sv->failed_secu),
				     U2H3(sv->failed_conns), U2H4(sv->failed_resp),
				     sv->retries, sv->redispatches);

				/* status */
				chunk_printf(&msg, sizeof(trash), "<td nowrap>");

				if (sv->state & SRV_CHECKED)
					chunk_printf(&msg, sizeof(trash), "%s ",
						human_time(now.tv_sec - sv->last_change, 1));

				chunk_printf(&msg, sizeof(trash),
				     srv_hlt_st[sv_state],
				     (svs->state & SRV_RUNNING) ? (svs->health - svs->rise + 1) : (svs->health),
				     (svs->state & SRV_RUNNING) ? (svs->fall) : (svs->rise));

				chunk_printf(&msg, sizeof(trash),
				     /* weight */
				     "</td><td>%d</td>"
				     /* act, bck */
				     "<td>%s</td><td>%s</td>"
				     "",
				     (sv->eweight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     (sv->state & SRV_BACKUP) ? "-" : "Y",
				     (sv->state & SRV_BACKUP) ? "Y" : "-");

				/* check failures: unique, fatal, down time */
				if (sv->state & SRV_CHECKED)
					chunk_printf(&msg, sizeof(trash),
					     "<td align=right>%lld</td><td align=right>%lld</td>"
					     "<td nowrap align=right>%s</td>"
					     "",
					     svs->failed_checks, svs->down_trans,
					     human_time(srv_downtime(sv), 1));
				else if (sv != svs)
					chunk_printf(&msg, sizeof(trash),
					     "<td nowrap colspan=3>via %s/%s</td>", svs->proxy->id, svs->id);
				else
					chunk_printf(&msg, sizeof(trash),
					     "<td colspan=3></td>");

				/* throttle */
				if ((sv->state & SRV_WARMINGUP) &&
				    now.tv_sec < sv->last_change + sv->slowstart &&
				    now.tv_sec >= sv->last_change) {
					unsigned int ratio;
					ratio = MAX(1, 100 * (now.tv_sec - sv->last_change) / sv->slowstart);
					chunk_printf(&msg, sizeof(trash),
						     "<td>%d %%</td></tr>\n", ratio);
				} else {
					chunk_printf(&msg, sizeof(trash),
						     "<td>-</td></tr>\n");
				}
			} else {
				static char *srv_hlt_st[7] = { "DOWN,", "DOWN %d/%d,",
							       "UP %d/%d,", "UP,",
							       "NOLB %d/%d,", "NOLB,",
							       "no check," };
				chunk_printf(&msg, sizeof(trash),
				     /* pxid, name */
				     "%s,%s,"
				     /* queue : current, max */
				     "%d,%d,"
				     /* sessions : current, max, limit, total */
				     "%d,%d,%s,%lld,"
				     /* bytes : in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     ",%lld,"
				     /* errors : request, connect, response */
				     ",%lld,%lld,"
				     /* warnings: retries, redispatches */
				     "%lld,%lld,"
				     "",
				     px->id, sv->id,
				     sv->nbpend, sv->nbpend_max,
				     sv->cur_sess, sv->cur_sess_max, LIM2A0(sv->maxconn, ""), sv->cum_sess,
				     sv->bytes_in, sv->bytes_out,
				     sv->failed_secu,
				     sv->failed_conns, sv->failed_resp,
				     sv->retries, sv->redispatches);

				/* status */
				chunk_printf(&msg, sizeof(trash),
				     srv_hlt_st[sv_state],
				     (sv->state & SRV_RUNNING) ? (sv->health - sv->rise + 1) : (sv->health),
				     (sv->state & SRV_RUNNING) ? (sv->fall) : (sv->rise));

				chunk_printf(&msg, sizeof(trash),
				     /* weight, active, backup */
				     "%d,%d,%d,"
				     "",
				     (sv->eweight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     (sv->state & SRV_BACKUP) ? 0 : 1,
				     (sv->state & SRV_BACKUP) ? 1 : 0);

				/* check failures: unique, fatal; last change, total downtime */
				if (sv->state & SRV_CHECKED)
					chunk_printf(&msg, sizeof(trash),
					     "%lld,%lld,%d,%d,",
					     sv->failed_checks, sv->down_trans,
					     (int)(now.tv_sec - sv->last_change), srv_downtime(sv));
				else
					chunk_printf(&msg, sizeof(trash),
					     ",,,,");

				/* queue limit, pid, iid, sid, */
				chunk_printf(&msg, sizeof(trash),
				     "%s,"
				     "%d,%d,%d,",
				     LIM2A0(sv->maxqueue, ""),
				     relative_pid, px->uuid, sv->puid);

				/* throttle */
				if ((sv->state & SRV_WARMINGUP) &&
				    now.tv_sec < sv->last_change + sv->slowstart &&
				    now.tv_sec >= sv->last_change) {
					unsigned int ratio;
					ratio = MAX(1, 100 * (now.tv_sec - sv->last_change) / sv->slowstart);
					chunk_printf(&msg, sizeof(trash), "%d", ratio);
				}

				/* sessions: lbtot */
				chunk_printf(&msg, sizeof(trash), ",%lld,", sv->cum_lbconn);

				/* tracked */
				if (sv->tracked)
					chunk_printf(&msg, sizeof(trash), "%s/%s,",
						sv->tracked->proxy->id, sv->tracked->id);
				else
					chunk_printf(&msg, sizeof(trash), ",");

				/* type */
				chunk_printf(&msg, sizeof(trash), "%d,", STATS_TYPE_SV);

				/* rate */
				chunk_printf(&msg, sizeof(trash), "%u,,%u,",
					     read_freq_ctr(&sv->sess_per_sec),
					     sv->sps_max);

				/* finish with EOL */
				chunk_printf(&msg, sizeof(trash), "\n");
			}
			if (buffer_write_chunk(rep, &msg) >= 0)
				return 0;
		} /* for sv */

		s->data_ctx.stats.px_st = DATA_ST_PX_BE;
		/* fall through */

	case DATA_ST_PX_BE:
		/* print the backend */
		if ((px->cap & PR_CAP_BE) &&
		    (!(s->data_ctx.stats.flags & STAT_BOUND) || (s->data_ctx.stats.type & (1 << STATS_TYPE_BE)))) {
			if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
				chunk_printf(&msg, sizeof(trash),
				     /* name */
				     "<tr align=center class=\"backend\"><td>Backend</td>"
				     /* queue : current, max */
				     "<td align=right>%s</td><td align=right>%s</td><td></td>"
				     /* sessions rate : current, max, limit */
				     "<td align=right>%s</td><td align=right>%s</td><td align=right></td>"
				     "",
				     U2H0(px->nbpend) /* or px->totpend ? */, U2H1(px->nbpend_max),
				     U2H2(read_freq_ctr(&px->be_sess_per_sec)), U2H3(px->be_sps_max));

				chunk_printf(&msg, sizeof(trash),
				     /* sessions : current, max, limit, total, lbtot */
				     "<td align=right>%s</td><td align=right>%s</td><td align=right>%s</td>"
				     "<td align=right>%s</td><td align=right>%s</td>"
				     /* bytes : in, out */
				     "<td align=right>%s</td><td align=right>%s</td>"
				     "",
				     U2H2(px->beconn), U2H3(px->beconn_max), U2H4(px->fullconn),
				     U2H6(px->cum_beconn), U2H7(px->cum_lbconn),
				     U2H8(px->bytes_in), U2H9(px->bytes_out));

				chunk_printf(&msg, sizeof(trash),
				     /* denied: req, resp */
				     "<td align=right>%s</td><td align=right>%s</td>"
				     /* errors : request, connect, response */
				     "<td align=right></td><td align=right>%s</td><td align=right>%s</td>\n"
				     /* warnings: retries, redispatches */
				     "<td align=right>%lld</td><td align=right>%lld</td>"
				     /* backend status: reflect backend status (up/down): we display UP
				      * if the backend has known working servers or if it has no server at
				      * all (eg: for stats). Then we display the total weight, number of
				      * active and backups. */
				     "<td align=center nowrap>%s %s</td><td align=center>%d</td>"
				     "<td align=center>%d</td><td align=center>%d</td>"
				     "",
				     U2H0(px->denied_req), U2H1(px->denied_resp),
				     U2H2(px->failed_conns), U2H3(px->failed_resp),
				     px->retries, px->redispatches,
				     human_time(now.tv_sec - px->last_change, 1),
				     (px->lbprm.tot_weight > 0 || !px->srv) ? "UP" :
					     "<font color=\"red\"><b>DOWN</b></font>",
				     (px->lbprm.tot_weight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     px->srv_act, px->srv_bck);

				chunk_printf(&msg, sizeof(trash),
				     /* rest of backend: nothing, down transitions, total downtime, throttle */
				     "<td align=center>&nbsp;</td><td align=\"right\">%d</td>"
				     "<td align=\"right\" nowrap>%s</td>"
				     "<td></td>"
				     "</tr>",
				     px->down_trans,
				     px->srv?human_time(be_downtime(px), 1):"&nbsp;");
			} else {
				chunk_printf(&msg, sizeof(trash),
				     /* pxid, name */
				     "%s,BACKEND,"
				     /* queue : current, max */
				     "%d,%d,"
				     /* sessions : current, max, limit, total */
				     "%d,%d,%d,%lld,"
				     /* bytes : in, out */
				     "%lld,%lld,"
				     /* denied: req, resp */
				     "%lld,%lld,"
				     /* errors : request, connect, response */
				     ",%lld,%lld,"
				     /* warnings: retries, redispatches */
				     "%lld,%lld,"
				     /* backend status: reflect backend status (up/down): we display UP
				      * if the backend has known working servers or if it has no server at
				      * all (eg: for stats). Then we display the total weight, number of
				      * active and backups. */
				     "%s,"
				     "%d,%d,%d,"
				     /* rest of backend: nothing, down transitions, last change, total downtime */
				     ",%d,%d,%d,,"
				     /* pid, iid, sid, throttle, lbtot, tracked, type */
				     "%d,%d,0,,%lld,,%d,"
				     /* rate, rate_lim, rate_max, */
				     "%u,,%u,"
				     "\n",
				     px->id,
				     px->nbpend /* or px->totpend ? */, px->nbpend_max,
				     px->beconn, px->beconn_max, px->fullconn, px->cum_beconn,
				     px->bytes_in, px->bytes_out,
				     px->denied_req, px->denied_resp,
				     px->failed_conns, px->failed_resp,
				     px->retries, px->redispatches,
				     (px->lbprm.tot_weight > 0 || !px->srv) ? "UP" : "DOWN",
				     (px->lbprm.tot_weight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv,
				     px->srv_act, px->srv_bck,
				     px->down_trans, (int)(now.tv_sec - px->last_change),
				     px->srv?be_downtime(px):0,
				     relative_pid, px->uuid,
				     px->cum_lbconn, STATS_TYPE_BE,
				     read_freq_ctr(&px->be_sess_per_sec),
				     px->be_sps_max);
			}
			if (buffer_write_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.px_st = DATA_ST_PX_END;
		/* fall through */

	case DATA_ST_PX_END:
		if (!(s->data_ctx.stats.flags & STAT_FMT_CSV)) {
			chunk_printf(&msg, sizeof(trash), "</table><p>\n");

			if (buffer_write_chunk(rep, &msg) >= 0)
				return 0;
		}

		s->data_ctx.stats.px_st = DATA_ST_PX_FIN;
		/* fall through */

	case DATA_ST_PX_FIN:
		return 1;

	default:
		/* unknown state, we should put an abort() here ! */
		return 1;
	}
}


/* This function is called to send output to the response buffer.
 * It dumps the sessions states onto the output buffer <rep>.
 * Expects to be called with client socket shut down on input.
 * s->data_ctx must have been zeroed first, and the flags properly set.
 * It automatically clears the HIJACK bit from the response buffer.
 */
void stats_dump_sess_to_buffer(struct session *s, struct buffer *rep)
{
	struct chunk msg;

	if (unlikely(rep->flags & (BF_WRITE_ERROR|BF_SHUTW))) {
		/* If we're forced to shut down, we might have to remove our
		 * reference to the last session being dumped.
		 */
		if (s->data_state == DATA_ST_LIST) {
			if (!LIST_ISEMPTY(&s->data_ctx.sess.bref.users)) {
				LIST_DEL(&s->data_ctx.sess.bref.users);
				LIST_INIT(&s->data_ctx.sess.bref.users);
			}
		}
		s->data_state = DATA_ST_FIN;
		buffer_stop_hijack(rep);
		s->ana_state = STATS_ST_CLOSE;
		return;
	}

	if (s->ana_state != STATS_ST_REP)
		return;

	msg.len = 0;
	msg.str = trash;

	switch (s->data_state) {
	case DATA_ST_INIT:
		/* the function had not been called yet, let's prepare the
		 * buffer for a response. We initialize the current session
		 * pointer to the first in the global list. When a target
		 * session is being destroyed, it is responsible for updating
		 * this pointer. We know we have reached the end when this
		 * pointer points back to the head of the sessions list.
		 */
		stream_int_retnclose(rep->cons, &msg);
		LIST_INIT(&s->data_ctx.sess.bref.users);
		s->data_ctx.sess.bref.ref = sessions.n;
		s->data_state = DATA_ST_LIST;
		/* fall through */

	case DATA_ST_LIST:
		/* first, let's detach the back-ref from a possible previous session */
		if (!LIST_ISEMPTY(&s->data_ctx.sess.bref.users)) {
			LIST_DEL(&s->data_ctx.sess.bref.users);
			LIST_INIT(&s->data_ctx.sess.bref.users);
		}

		/* and start from where we stopped */
		while (s->data_ctx.sess.bref.ref != &sessions) {
			char pn[INET6_ADDRSTRLEN + strlen(":65535")];
			struct session *curr_sess;

			curr_sess = LIST_ELEM(s->data_ctx.sess.bref.ref, struct session *, list);

			chunk_printf(&msg, sizeof(trash),
				     "%p: proto=%s",
				     curr_sess,
				     curr_sess->listener->proto->name);

			switch (curr_sess->listener->proto->sock_family) {
			case AF_INET:
				inet_ntop(AF_INET,
					  (const void *)&((struct sockaddr_in *)&curr_sess->cli_addr)->sin_addr,
					  pn, sizeof(pn));

				chunk_printf(&msg, sizeof(trash),
					     " src=%s:%d fe=%s be=%s srv=%s",
					     pn,
					     ntohs(((struct sockaddr_in *)&curr_sess->cli_addr)->sin_port),
					     curr_sess->fe->id,
					     curr_sess->be->id,
					     curr_sess->srv ? curr_sess->srv->id : "<none>"
					     );
				break;
			case AF_INET6:
				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(&curr_sess->cli_addr))->sin6_addr,
					  pn, sizeof(pn));

				chunk_printf(&msg, sizeof(trash),
					     " src=%s:%d fe=%s be=%s srv=%s",
					     pn,
					     ntohs(((struct sockaddr_in6 *)&curr_sess->cli_addr)->sin6_port),
					     curr_sess->fe->id,
					     curr_sess->be->id,
					     curr_sess->srv ? curr_sess->srv->id : "<none>"
					     );

				break;
			case AF_UNIX:
				/* no more information to print right now */
				break;
			}

			chunk_printf(&msg, sizeof(trash),
				     " as=%d ts=%02x age=%s calls=%d",
				     curr_sess->ana_state, curr_sess->task->state,
				     human_time(now.tv_sec - curr_sess->logs.tv_accept.tv_sec, 1),
				     curr_sess->task->calls);

			chunk_printf(&msg, sizeof(trash),
				     " rq[f=%06xh,l=%d,an=%02xh,rx=%s",
				     curr_sess->req->flags,
				     curr_sess->req->l,
				     curr_sess->req->analysers,
				     curr_sess->req->rex ?
				     human_time(TICKS_TO_MS(curr_sess->req->rex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg, sizeof(trash),
				     ",wx=%s",
				     curr_sess->req->wex ?
				     human_time(TICKS_TO_MS(curr_sess->req->wex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg, sizeof(trash),
				     ",ax=%s]",
				     curr_sess->req->analyse_exp ?
				     human_time(TICKS_TO_MS(curr_sess->req->analyse_exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg, sizeof(trash),
				     " rp[f=%06xh,l=%d,an=%02xh,rx=%s",
				     curr_sess->rep->flags,
				     curr_sess->rep->l,
				     curr_sess->rep->analysers,
				     curr_sess->rep->rex ?
				     human_time(TICKS_TO_MS(curr_sess->rep->rex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg, sizeof(trash),
				     ",wx=%s",
				     curr_sess->rep->wex ?
				     human_time(TICKS_TO_MS(curr_sess->rep->wex - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg, sizeof(trash),
				     ",ax=%s]",
				     curr_sess->rep->analyse_exp ?
				     human_time(TICKS_TO_MS(curr_sess->rep->analyse_exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg, sizeof(trash),
				     " s0=[%d,%1xh,fd=%d,ex=%s]",
				     curr_sess->si[0].state,
				     curr_sess->si[0].flags,
				     curr_sess->si[0].fd,
				     curr_sess->si[0].exp ?
				     human_time(TICKS_TO_MS(curr_sess->si[0].exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg, sizeof(trash),
				     " s1=[%d,%1xh,fd=%d,ex=%s]",
				     curr_sess->si[1].state,
				     curr_sess->si[1].flags,
				     curr_sess->si[1].fd,
				     curr_sess->si[1].exp ?
				     human_time(TICKS_TO_MS(curr_sess->si[1].exp - now_ms),
						TICKS_TO_MS(1000)) : "");

			chunk_printf(&msg, sizeof(trash),
				     " exp=%s",
				     curr_sess->task->expire ?
				     human_time(TICKS_TO_MS(curr_sess->task->expire - now_ms),
						TICKS_TO_MS(1000)) : "");
			if (task_in_rq(curr_sess->task))
				chunk_printf(&msg, sizeof(trash), " run(nice=%d)", curr_sess->task->nice);

			chunk_printf(&msg, sizeof(trash), "\n");

			if (buffer_write_chunk(rep, &msg) >= 0) {
				/* let's try again later from this session. We add ourselves into
				 * this session's users so that it can remove us upon termination.
				 */
				LIST_ADDQ(&curr_sess->back_refs, &s->data_ctx.sess.bref.users);
				return;
			}

			s->data_ctx.sess.bref.ref = curr_sess->list.n;
		}
		s->data_state = DATA_ST_FIN;
		/* fall through */

	default:
		s->data_state = DATA_ST_FIN;
		buffer_stop_hijack(rep);
		s->ana_state = STATS_ST_CLOSE;
		return;
	}
}

/* print a line of error buffer (limited to 70 bytes) to <out>. The format is :
 * <2 spaces> <offset=5 digits> <space or plus> <space> <70 chars max> <\n>
 * which is 60 chars per line. Non-printable chars \t, \n, \r and \e are
 * encoded in C format. Other non-printable chars are encoded "\xHH". Original
 * lines are respected within the limit of 70 output chars. Lines that are
 * continuation of a previous truncated line begin with "+" instead of " "
 * after the offset. The new pointer is returned.
 */
static int dump_error_line(struct chunk *out, int size,
                          struct error_snapshot *err, int *line, int ptr)
{
	int end;
	unsigned char c;

	end = out->len + 80;
	if (end > size)
		return ptr;

	chunk_printf(out, size, "  %05d%c ", ptr, (ptr == *line) ? ' ' : '+');

	while (ptr < err->len) {
		c = err->buf[ptr];
		if (isprint(c) && isascii(c) && c != '\\') {
			if (out->len > end - 2)
				break;
			out->str[out->len++] = c;
		} else if (c == '\t' || c == '\n' || c == '\r' || c == '\e' || c == '\\') {
			if (out->len > end - 3)
				break;
			out->str[out->len++] = '\\';
			switch (c) {
			case '\t': c = 't'; break;
			case '\n': c = 'n'; break;
			case '\r': c = 'r'; break;
			case '\e': c = 'e'; break;
			case '\\': c = '\\'; break;
			}
			out->str[out->len++] = c;
		} else {
			if (out->len > end - 5)
				break;
			out->str[out->len++] = '\\';
			out->str[out->len++] = 'x';
			out->str[out->len++] = hextab[(c >> 4) & 0xF];
			out->str[out->len++] = hextab[c & 0xF];
		}
		if (err->buf[ptr++] == '\n') {
			/* we had a line break, let's return now */
			out->str[out->len++] = '\n';
			*line = ptr;
			return ptr;
		}
	}
	/* we have an incomplete line, we return it as-is */
	out->str[out->len++] = '\n';
	return ptr;
}

/* This function is called to send output to the response buffer.
 * It dumps the errors logged in proxies onto the output buffer <rep>.
 * Expects to be called with client socket shut down on input.
 * s->data_ctx must have been zeroed first, and the flags properly set.
 * It automatically clears the HIJACK bit from the response buffer.
 */
void stats_dump_errors_to_buffer(struct session *s, struct buffer *rep)
{
	extern const char *monthname[12];
	struct chunk msg;

	if (unlikely(rep->flags & (BF_WRITE_ERROR|BF_SHUTW))) {
		s->data_state = DATA_ST_FIN;
		buffer_stop_hijack(rep);
		s->ana_state = STATS_ST_CLOSE;
		return;
	}

	if (s->ana_state != STATS_ST_REP)
		return;

	msg.len = 0;
	msg.str = trash;

	if (!s->data_ctx.errors.px) {
		/* the function had not been called yet, let's prepare the
		 * buffer for a response.
		 */
		stream_int_retnclose(rep->cons, &msg);
		s->data_ctx.errors.px = proxy;
		s->data_ctx.errors.buf = 0;
		s->data_ctx.errors.bol = 0;
		s->data_ctx.errors.ptr = -1;
	}

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	while (s->data_ctx.errors.px) {
		struct error_snapshot *es;

		if (s->data_ctx.errors.buf == 0)
			es = &s->data_ctx.errors.px->invalid_req;
		else
			es = &s->data_ctx.errors.px->invalid_rep;

		if (!es->when.tv_sec)
			goto next;

		if (s->data_ctx.errors.iid >= 0 &&
		    s->data_ctx.errors.px->uuid != s->data_ctx.errors.iid &&
		    es->oe->uuid != s->data_ctx.errors.iid)
			goto next;

		if (s->data_ctx.errors.ptr < 0) {
			/* just print headers now */

			char pn[INET6_ADDRSTRLEN];
			struct tm tm;

			get_localtime(es->when.tv_sec, &tm);
			chunk_printf(&msg, sizeof(trash), "\n[%02d/%s/%04d:%02d:%02d:%02d.%03d]",
				     tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
				     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(es->when.tv_usec/1000));


			if (es->src.ss_family == AF_INET)
				inet_ntop(AF_INET,
					  (const void *)&((struct sockaddr_in *)&es->src)->sin_addr,
					  pn, sizeof(pn));
			else
				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(&es->src))->sin6_addr,
					  pn, sizeof(pn));

			switch (s->data_ctx.errors.buf) {
			case 0:
				chunk_printf(&msg, sizeof(trash),
					     " frontend %s (#%d): invalid request\n"
					     "  src %s, session #%d, backend %s (#%d), server %s (#%d)\n"
					     "  request length %d bytes, error at position %d:\n\n",
					     s->data_ctx.errors.px->id, s->data_ctx.errors.px->uuid,
					     pn, es->sid, es->oe->id, es->oe->uuid,
					     es->srv ? es->srv->id : "<NONE>",
					     es->srv ? es->srv->puid : -1,
					     es->len, es->pos);
				break;
			case 1:
				chunk_printf(&msg, sizeof(trash),
					     " backend %s (#%d) : invalid response\n"
					     "  src %s, session #%d, frontend %s (#%d), server %s (#%d)\n"
					     "  response length %d bytes, error at position %d:\n\n",
					     s->data_ctx.errors.px->id, s->data_ctx.errors.px->uuid,
					     pn, es->sid, es->oe->id, es->oe->uuid,
					     es->srv ? es->srv->id : "<NONE>",
					     es->srv ? es->srv->puid : -1,
					     es->len, es->pos);
				break;
			}

			if (buffer_write_chunk(rep, &msg) >= 0) {
				/* Socket buffer full. Let's try again later from the same point */
				return;
			}
			s->data_ctx.errors.ptr = 0;
			s->data_ctx.errors.sid = es->sid;
		}

		if (s->data_ctx.errors.sid != es->sid) {
			/* the snapshot changed while we were dumping it */
			chunk_printf(&msg, sizeof(trash),
				     "  WARNING! update detected on this snapshot, dump interrupted. Please re-check!\n");
			if (buffer_write_chunk(rep, &msg) >= 0)
				return;
			goto next;
		}

		/* OK, ptr >= 0, so we have to dump the current line */
		while (s->data_ctx.errors.ptr < es->len) {
			int newptr;
			int newline;

			newline = s->data_ctx.errors.bol;
			newptr = dump_error_line(&msg, sizeof(trash), es, &newline, s->data_ctx.errors.ptr);
			if (newptr == s->data_ctx.errors.ptr)
				return;

			if (buffer_write_chunk(rep, &msg) >= 0) {
				/* Socket buffer full. Let's try again later from the same point */
				return;
			}
			s->data_ctx.errors.ptr = newptr;
			s->data_ctx.errors.bol = newline;
		};
	next:
		s->data_ctx.errors.bol = 0;
		s->data_ctx.errors.ptr = -1;
		s->data_ctx.errors.buf++;
		if (s->data_ctx.errors.buf > 1) {
			s->data_ctx.errors.buf = 0;
			s->data_ctx.errors.px = s->data_ctx.errors.px->next;
		}
	}

	/* dump complete */
	buffer_stop_hijack(rep);
	s->ana_state = STATS_ST_CLOSE;
}


static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "stats", stats_parse_global },
	{ 0, NULL, NULL },
}};

__attribute__((constructor))
static void __dumpstats_module_init(void)
{
	cfg_register_keywords(&cfg_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
