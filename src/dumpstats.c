/*
 * Functions dedicated to statistics output
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
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
#include <time.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/client.h>
#include <types/global.h>
#include <types/polling.h>
#include <types/proxy.h>
#include <types/server.h>

#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/dumpstats.h>
#include <proto/fd.h>
#include <proto/senddata.h>
#include <proto/session.h>

/*
 * Produces statistics data for the session <s>. Expects to be called with
 * s->cli_state == CL_STSHUTR. It stops by itself by unsetting the SN_SELF_GEN
 * flag from the session, which it uses to keep on being called when there is
 * free space in the buffer, of simply by letting an empty buffer upon return.
 * It returns 0 if it had to stop writing data and an I/O is needed, 1 if the
 * dump is finished and the session must be closed, or -1 in case of any error.
 */
int stats_dump_http(struct session *s, struct uri_auth *uri, int flags)
{
	struct buffer *rep = s->rep;
	struct proxy *px;
	struct chunk msg;
	unsigned int up;

	msg.len = 0;
	msg.str = trash;

	switch (s->data_state) {
	case DATA_ST_INIT:
		/* the function had not been called yet */
		s->flags |= SN_SELF_GEN;  // more data will follow

		chunk_printf(&msg, sizeof(trash),
			     "HTTP/1.0 200 OK\r\n"
			     "Cache-Control: no-cache\r\n"
			     "Connection: close\r\n"
			     "Content-Type: text/html\r\n");

		if (uri->refresh > 0 && !(s->flags & SN_STAT_NORFRSH))
			chunk_printf(&msg, sizeof(trash), "Refresh: %d\r\n",
				     uri->refresh);

		chunk_printf(&msg, sizeof(trash), "\r\n");

		s->txn.status = 200;
		client_retnclose(s, &msg); // send the start of the response.
		msg.len = 0;

		if (!(s->flags & SN_ERR_MASK))  // this is not really an error but it is
			s->flags |= SN_ERR_PRXCOND; // to mark that it comes from the proxy
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;

		if (s->txn.meth == HTTP_METH_HEAD) {
			/* that's all we return in case of HEAD request */
			s->data_state = DATA_ST_FIN;
			s->flags &= ~SN_SELF_GEN;
			return 1;
		}

		s->data_state = DATA_ST_HEAD; /* let's start producing data */
		/* fall through */

	case DATA_ST_HEAD:
		/* WARNING! This must fit in the first buffer !!! */	    
		chunk_printf(&msg, sizeof(trash),
			     "<html><head><title>Statistics Report for " PRODUCT_NAME "</title>\n"
			     "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">\n"
			     "<style type=\"text/css\"><!--\n"
			     "body {"
			     " font-family: helvetica, arial;"
			     " font-size: 12px;"
			     " font-weight: normal;"
			     " color: black;"
			     " background: white;"
			     "}\n"
			     "th,td {"
			     " font-size: 0.8em;"
			     " align: center;"
			     "}\n"
			     "h1 {"
			     " font-size: xx-large;"
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
			     ".pxname	{background: #b00040;color: #ffff40;font-weight: bold;}\n"
			     ".titre	{background: #20D0D0;color: #000000;font-weight: bold;}\n"
			     ".total	{background: #20D0D0;color: #ffff80;}\n"
			     ".frontend	{background: #e8e8d0;}\n"
			     ".backend	{background: #e8e8d0;}\n"
			     ".active0	{background: #ff9090;}\n"
			     ".active1	{background: #ffd020;}\n"
			     ".active2	{background: #ffffa0;}\n"
			     ".active3	{background: #c0ffc0;}\n"
			     ".active4	{background: #e0e0e0;}\n"
			     ".backup0	{background: #ff9090;}\n"
			     ".backup1	{background: #ff80ff;}\n"
			     ".backup2	{background: #c060ff;}\n"
			     ".backup3	{background: #b0d0ff;}\n"
			     ".backup4	{background: #e0e0e0;}\n"
			     "table.tbl { border-collapse: collapse; border-style: none;}\n"
			     "table.tbl td { border-width: 1px 1px 1px 1px; border-style: solid solid solid solid; padding: 2px 3px; border-color: gray;}\n"
			     "table.tbl th { border-width: 1px; border-style: solid solid solid solid; border-color: gray;}\n"
			     "table.tbl th.empty { border-style: none; empty-cells: hide;}\n"
			     "table.lgd { border-collapse: collapse; border-width: 1px; border-style: none none none solid; border-color: black;}\n"
			     "table.lgd td { border-width: 1px; border-style: solid solid solid solid; border-color: gray; padding: 2px;}\n"
			     "table.lgd td.noborder { border-style: none; padding: 2px; white-space: nowrap;}\n"
			     "-->\n"
			     "</style></head>\n");
			
		if (buffer_write_chunk(rep, &msg) != 0)
			return 0;

		s->data_state = DATA_ST_INFO;
		/* fall through */

	case DATA_ST_INFO:
		up = (now.tv_sec - start_date.tv_sec);

		/* WARNING! this has to fit the first packet too.
			 * We are around 3.5 kB, add adding entries will
			 * become tricky if we want to support 4kB buffers !
			 */
		chunk_printf(&msg, sizeof(trash),
			     "<body><h1><a href=\"" PRODUCT_URL "\" style=\"text-decoration: none;\">"
			     PRODUCT_NAME "%s</a></h1>\n"
			     "<h2>Statistics Report for pid %d</h2>\n"
			     "<hr width=\"100%%\" class=\"hr\">\n"
			     "<h3>&gt; General process information</h3>\n"
			     "<table border=0 cols=4><tr><td align=\"left\" nowrap width=\"1%%\">\n"
			     "<p><b>pid = </b> %d (nbproc = %d)<br>\n"
			     "<b>uptime = </b> %dd %dh%02dm%02ds<br>\n"
			     "<b>system limits :</b> memmax = %s%s ; ulimit-n = %d<br>\n"
			     "<b>maxsock = </b> %d<br>\n"
			     "<b>maxconn = </b> %d (current conns = %d)<br>\n"
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
			     "<td class=\"active4\"></td><td class=\"noborder\">not checked </td>"
			     "</tr></table>\n"
			     "</td>"
			     "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
			     "<b>Display option:</b><ul style=\"margin-top: 0.25em;\">"
			     "",
			     (uri->flags&ST_HIDEVER)?"":(STATS_VERSION_STRING),
			     pid, pid, global.nbproc,
			     up / 86400, (up % 86400) / 3600,
			     (up % 3600) / 60, (up % 60),
			     global.rlimit_memmax ? ultoa(global.rlimit_memmax) : "unlimited",
			     global.rlimit_memmax ? " MB" : "",
			     global.rlimit_nofile,
			     global.maxsock,
			     global.maxconn,
			     actconn
			     );
	    
		if (s->flags & SN_STAT_HIDEDWN)
			chunk_printf(&msg, sizeof(trash),
				     "<li><a href=\"%s%s%s\">Show all servers</a><br>\n",
				     uri->uri_prefix,
				     "",
				     (s->flags & SN_STAT_NORFRSH) ? ";norefresh" : "");
		else
			chunk_printf(&msg, sizeof(trash),
				     "<li><a href=\"%s%s%s\">Hide 'DOWN' servers</a><br>\n",
				     uri->uri_prefix,
				     ";up",
				     (s->flags & SN_STAT_NORFRSH) ? ";norefresh" : "");

		if (uri->refresh > 0) {
			if (s->flags & SN_STAT_NORFRSH)
				chunk_printf(&msg, sizeof(trash),
					     "<li><a href=\"%s%s%s\">Enable refresh</a><br>\n",
					     uri->uri_prefix,
					     (s->flags & SN_STAT_HIDEDWN) ? ";up" : "",
					     "");
			else
				chunk_printf(&msg, sizeof(trash),
					     "<li><a href=\"%s%s%s\">Disable refresh</a><br>\n",
					     uri->uri_prefix,
					     (s->flags & SN_STAT_HIDEDWN) ? ";up" : "",
					     ";norefresh");
		}

		chunk_printf(&msg, sizeof(trash),
			     "<li><a href=\"%s%s%s\">Refresh now</a><br>\n",
			     uri->uri_prefix,
			     (s->flags & SN_STAT_HIDEDWN) ? ";up" : "",
			     (s->flags & SN_STAT_NORFRSH) ? ";norefresh" : "");

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
	    
		if (buffer_write_chunk(rep, &msg) != 0)
			return 0;

		memset(&s->data_ctx, 0, sizeof(s->data_ctx));

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
				if (stats_dump_proxy(s, px, uri, flags) == 0)
					return 0;

			s->data_ctx.stats.px = px->next;
			s->data_ctx.stats.px_st = DATA_ST_PX_INIT;
		}
		/* here, we just have reached the last proxy */

		s->data_state = DATA_ST_END;
		/* fall through */

	case DATA_ST_END:
		chunk_printf(&msg, sizeof(trash), "</body></html>\n");
		if (buffer_write_chunk(rep, &msg) != 0)
			return 0;

		s->data_state = DATA_ST_FIN;
		/* fall through */

	case DATA_ST_FIN:
		s->flags &= ~SN_SELF_GEN;
		return 1;

	default:
		/* unknown state ! */
		s->flags &= ~SN_SELF_GEN;
		return -1;
	}
}


/*
 * Dumps statistics for a proxy.
 * Returns 0 if it had to stop dumping data because of lack of buffer space,
 * ot non-zero if everything completed.
 */
int stats_dump_proxy(struct session *s, struct proxy *px, struct uri_auth *uri, int flags)
{
	struct buffer *rep = s->rep;
	struct server *sv;
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
				if (!strcmp(scope->px_id, ".") && px == s->fe)
					break;
				scope = scope->next;
			}

			/* proxy name not found : don't dump anything */
			if (scope == NULL)
				return 1;
		}

		s->data_ctx.stats.px_st = DATA_ST_PX_TH;
		/* fall through */

	case DATA_ST_PX_TH:
		/* print a new table */
		chunk_printf(&msg, sizeof(trash),
			     "<table cols=\"20\" class=\"tbl\" width=\"100%%\">\n"
			     "<tr align=\"center\" class=\"titre\">"
			     "<th colspan=2 class=\"pxname\">%s</th>"
			     "<th colspan=18 class=\"empty\"></th>"
			     "</tr>\n"
			     "<tr align=\"center\" class=\"titre\">"
			     "<th rowspan=2></th>"
			     "<th colspan=2>Queue</th><th colspan=4>Sessions</th>"
			     "<th colspan=2>Bytes</th><th colspan=2>Denied</th>"
			     "<th colspan=3>Errors</th><th colspan=6>Server</th>"
			     "</tr>\n"
			     "<tr align=\"center\" class=\"titre\">"
			     "<th>Cur</th><th>Max</th><th>Cur</th><th>Max</th>"
			     "<th>Limit</th><th>Cumul</th><th>In</th><th>Out</th>"
			     "<th>Req</th><th>Resp</th><th>Req</th><th>Conn</th>"
			     "<th>Resp</th><th>Status</th><th>Weight</th><th>Act</th>"
			     "<th>Bck</th><th>Check</th><th>Down</th></tr>\n"
			     "",
			     px->id);
		
		if (buffer_write_chunk(rep, &msg) != 0)
			return 0;

		s->data_ctx.stats.px_st = DATA_ST_PX_FE;
		/* fall through */

	case DATA_ST_PX_FE:
		/* print the frontend */
		if (px->cap & PR_CAP_FE) {
			chunk_printf(&msg, sizeof(trash),
				     /* name, queue */
				     "<tr align=center class=\"frontend\"><td>Frontend</td><td colspan=2></td>"
				     /* sessions : current, max, limit, cumul. */
				     "<td align=right>%d</td><td align=right>%d</td><td align=right>%d</td><td align=right>%d</td>"
				     /* bytes : in, out */
				     "<td align=right>%lld</td><td align=right>%lld</td>"
				     /* denied: req, resp */
				     "<td align=right>%d</td><td align=right>%d</td>"
				     /* errors : request, connect, response */
				     "<td align=right>%d</td><td align=right></td><td align=right></td>"
				     /* server status : reflect backend status */
				     "<td align=center>%s</td>"
				     /* rest of server: nothing */
				     "<td align=center colspan=5></td></tr>"
				     "",
				     px->feconn, px->feconn_max, px->maxconn, px->cum_feconn,
				     px->bytes_in, px->bytes_out,
				     px->denied_req, px->denied_resp,
				     px->failed_req,
				     px->state == PR_STRUN ? "OPEN" :
				     px->state == PR_STIDLE ? "FULL" : "STOP");

			if (buffer_write_chunk(rep, &msg) != 0)
				return 0;
		}

		s->data_ctx.stats.sv = px->srv; /* may be NULL */
		s->data_ctx.stats.px_st = DATA_ST_PX_SV;
		/* fall through */

	case DATA_ST_PX_SV:
		/* stats.sv has been initialized above */
		while (s->data_ctx.stats.sv != NULL) {
			static char *srv_hlt_st[5] = { "DOWN", "DN %d/%d &uarr;", "UP %d/%d &darr;", "UP", "<i>no check</i>" };
			int sv_state; /* 0=DOWN, 1=going up, 2=going down, 3=UP, 4=unchecked */

			sv = s->data_ctx.stats.sv;

			/* FIXME: produce some small strings for "UP/DOWN x/y &#xxxx;" */
			if (!(sv->state & SRV_CHECKED))
				sv_state = 4;
			else if (sv->state & SRV_RUNNING)
				if (sv->health == sv->rise + sv->fall - 1)
					sv_state = 3; /* UP */
				else
					sv_state = 2; /* going down */
			else
				if (sv->health)
					sv_state = 1; /* going up */
				else
					sv_state = 0; /* DOWN */

			if ((sv_state == 0) && (s->flags & SN_STAT_HIDEDWN)) {
				/* do not report servers which are DOWN */
				s->data_ctx.stats.sv = sv->next;
				continue;
			}

			chunk_printf(&msg, sizeof(trash),
				     /* name */
				     "<tr align=\"center\" class=\"%s%d\"><td>%s</td>"
				     /* queue : current, max */
				     "<td align=right>%d</td><td align=right>%d</td>"
				     /* sessions : current, max, limit, cumul */
				     "<td align=right>%d</td><td align=right>%d</td><td align=right>%s</td><td align=right>%d</td>"
				     /* bytes : in, out */
				     "<td align=right>%lld</td><td align=right>%lld</td>"
				     /* denied: req, resp */
				     "<td align=right></td><td align=right>%d</td>"
				     /* errors : request, connect, response */
				     "<td align=right></td><td align=right>%d</td><td align=right>%d</td>\n"
				     "",
				     (sv->state & SRV_BACKUP) ? "backup" : "active",
				     sv_state, sv->id,
				     sv->nbpend, sv->nbpend_max,
				     sv->cur_sess, sv->cur_sess_max, sv->maxconn ? ultoa(sv->maxconn) : "-", sv->cum_sess,
				     sv->bytes_in, sv->bytes_out,
				     sv->failed_secu,
				     sv->failed_conns, sv->failed_resp);
				     
			/* status */
			chunk_printf(&msg, sizeof(trash), "<td nowrap>");
			chunk_printf(&msg, sizeof(trash),
				     srv_hlt_st[sv_state],
				     (sv->state & SRV_RUNNING) ? (sv->health - sv->rise + 1) : (sv->health),
				     (sv->state & SRV_RUNNING) ? (sv->fall) : (sv->rise));

			chunk_printf(&msg, sizeof(trash),
				     /* weight */
				     "</td><td>%d</td>"
				     /* act, bck */
				     "<td>%s</td><td>%s</td>"
				     "",
				     sv->uweight,
				     (sv->state & SRV_BACKUP) ? "-" : "Y",
				     (sv->state & SRV_BACKUP) ? "Y" : "-");

			/* check failures : unique, fatal */
			if (sv->state & SRV_CHECKED)
				chunk_printf(&msg, sizeof(trash),
					     "<td align=right>%d</td><td align=right>%d</td></tr>\n",
					     sv->failed_checks, sv->down_trans);
			else
				chunk_printf(&msg, sizeof(trash),
					     "<td colspan=2></td></tr>\n");

			if (buffer_write_chunk(rep, &msg) != 0)
				return 0;

			s->data_ctx.stats.sv = sv->next;
		} /* while sv */

		s->data_ctx.stats.px_st = DATA_ST_PX_BE;
		/* fall through */

	case DATA_ST_PX_BE:
		/* print the backend */
		if (px->cap & PR_CAP_BE) {
			int gcd = 1;

			if (px->map_state & PR_MAP_RECALC)
				recalc_server_map(px);

			/* The GCD which was computed causes the total effective
			 * weight to appear lower than all weights. Let's
			 * recompute it.
			 */
			if (px->srv && px->srv->eweight)
				gcd = px->srv->uweight / px->srv->eweight;

			chunk_printf(&msg, sizeof(trash),
				     /* name */
				     "<tr align=center class=\"backend\"><td>Backend</td>"
				     /* queue : current, max */
				     "<td align=right>%d</td><td align=right>%d</td>"
				     /* sessions : current, max, limit, cumul. */
				     "<td align=right>%d</td><td align=right>%d</td><td align=right>%d</td><td align=right>%d</td>"
				     /* bytes : in, out */
				     "<td align=right>%lld</td><td align=right>%lld</td>"
				     /* denied: req, resp */
				     "<td align=right>%d</td><td align=right>%d</td>"
				     /* errors : request, connect, response */
				     "<td align=right></td><td align=right>%d</td><td align=right>%d</td>\n"
				     /* server status : reflect backend status (up/down) : we display UP
				      * if the backend has known working servers or if it has no server at
				      * all (eg: for stats). Tthen we display the total weight, number of
				      * active and backups. */
				     "<td align=center>%s</td><td align=center>%d</td>"
				     "<td align=center>%d</td><td align=center>%d</td>"
				     /* rest of server: nothing */
				     "<td align=center colspan=2></td></tr>"
				     "",
				     px->nbpend /* or px->totpend ? */, px->nbpend_max,
				     px->beconn, px->beconn_max, px->fullconn, px->cum_beconn,
				     px->bytes_in, px->bytes_out,
				     px->denied_req, px->denied_resp,
				     px->failed_conns, px->failed_resp,
				     (px->srv_map_sz > 0 || !px->srv) ? "UP" : "DOWN",
				     px->srv_map_sz * gcd, px->srv_act, px->srv_bck);

			if (buffer_write_chunk(rep, &msg) != 0)
				return 0;
		}
		
		s->data_ctx.stats.px_st = DATA_ST_PX_END;
		/* fall through */

	case DATA_ST_PX_END:
		chunk_printf(&msg, sizeof(trash), "</table><p>\n");

		if (buffer_write_chunk(rep, &msg) != 0)
			return 0;

		s->data_ctx.stats.px_st = DATA_ST_PX_FIN;
		/* fall through */

	case DATA_ST_PX_FIN:
		return 1;

	default:
		/* unknown state, we should put an abort() here ! */
		return 1;
	}
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
