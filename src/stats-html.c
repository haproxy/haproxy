#include <haproxy/stats-html.h>

#include <string.h>

#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/clock.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/pipe.h>
#include <haproxy/proxy.h>
#include <haproxy/stats.h>
#include <haproxy/stconn.h>
#include <haproxy/server.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tinfo.h>
#include <haproxy/tools.h>
#include <haproxy/uri_auth-t.h>
#include <haproxy/version.h>

static const char *field_to_html_str(const struct field *f)
{
	switch (field_format(f, 0)) {
	case FF_S32: return U2H(f->u.s32);
	case FF_S64: return U2H(f->u.s64);
	case FF_U64: return U2H(f->u.u64);
	case FF_U32: return U2H(f->u.u32);
	case FF_FLT: return F2H(f->u.flt);
	case FF_STR: return field_str(f, 0);
	case FF_EMPTY:
	default:
		return "";
	}
}

/* Dumps the HTTP stats head block to chunk ctx buffer and uses the per-uri
 * parameters from the parent proxy. The caller is responsible for clearing
 * chunk ctx buffer if needed.
 */
void stats_dump_html_head(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;
	struct uri_auth *uri;

	BUG_ON(!ctx->http_px);
	uri = ctx->http_px->uri_auth;

	/* WARNING! This must fit in the first buffer !!! */
	chunk_appendf(chk,
	              "<!DOCTYPE html>\n"
	              "<html lang=\"en\"><head><title>Statistics Report for " PRODUCT_NAME "%s%s</title>\n"
	              "<link rel=\"icon\" href=\"data:,\">\n"
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
	              ".titre	{background: #20D0D0;color: #000000; font-weight: bold; text-align: center;}\n"
	              ".total	{background: #20D0D0;color: #ffff80;}\n"
	              ".frontend	{background: #e8e8d0;}\n"
	              ".socket	{background: #d0d0d0;}\n"
	              ".backend	{background: #e8e8d0;}\n"
	              ".active_down		{background: #ff9090;}\n"
	              ".active_going_up		{background: #ffd020;}\n"
	              ".active_going_down	{background: #ffffa0;}\n"
	              ".active_up		{background: #c0ffc0;}\n"
	              ".active_nolb		{background: #20a0ff;}\n"
	              ".active_draining		{background: #20a0FF;}\n"
	              ".active_no_check		{background: #e0e0e0;}\n"
	              ".backup_down		{background: #ff9090;}\n"
	              ".backup_going_up		{background: #ff80ff;}\n"
	              ".backup_going_down	{background: #c060ff;}\n"
	              ".backup_up		{background: #b0d0ff;}\n"
	              ".backup_nolb		{background: #90b0e0;}\n"
	              ".backup_draining		{background: #cc9900;}\n"
	              ".backup_no_check		{background: #e0e0e0;}\n"
	              ".maintain	{background: #c07820;}\n"
	              ".rls      {letter-spacing: 0.2em; margin-right: 1px;}\n" /* right letter spacing (used for grouping digits) */
	              "\n"
	              "a.px:link {color: #ffff40; text-decoration: none;}"
	              "a.px:visited {color: #ffff40; text-decoration: none;}"
	              "a.px:hover {color: #ffffff; text-decoration: none;}"
	              "a.lfsb:link {color: #000000; text-decoration: none;}"
	              "a.lfsb:visited {color: #000000; text-decoration: none;}"
	              "a.lfsb:hover {color: #505050; text-decoration: none;}"
	              "\n"
	              "table.tbl { border-collapse: collapse; border-style: none;}\n"
	              "table.tbl td { text-align: right; border-width: 1px 1px 1px 1px; border-style: solid solid solid solid; padding: 2px 3px; border-color: gray; white-space: nowrap;}\n"
	              "table.tbl td.ac { text-align: center;}\n"
	              "table.tbl th { border-width: 1px; border-style: solid solid solid solid; border-color: gray;}\n"
	              "table.tbl th.pxname { background: #b00040; color: #ffff40; font-weight: bold; border-style: solid solid none solid; padding: 2px 3px; white-space: nowrap;}\n"
	              "table.tbl th.empty { border-style: none; empty-cells: hide; background: white;}\n"
	              "table.tbl th.desc { background: white; border-style: solid solid none solid; text-align: left; padding: 2px 3px;}\n"
	              "\n"
	              "table.lgd { border-collapse: collapse; border-width: 1px; border-style: none none none solid; border-color: black;}\n"
	              "table.lgd td { border-width: 1px; border-style: solid solid solid solid; border-color: gray; padding: 2px;}\n"
	              "table.lgd td.noborder { border-style: none; padding: 2px; white-space: nowrap;}\n"
	              "table.det { border-collapse: collapse; border-style: none; }\n"
	              "table.det th { text-align: left; border-width: 0px; padding: 0px 1px 0px 0px; font-style:normal;font-size:11px;font-weight:bold;font-family: sans-serif;}\n"
	              "table.det td { text-align: right; border-width: 0px; padding: 0px 0px 0px 4px; white-space: nowrap; font-style:normal;font-size:11px;font-weight:normal;}\n"
	              "u {text-decoration:none; border-bottom: 1px dotted black;}\n"
	              "div.tips {\n"
	              " display:block;\n"
	              " visibility:hidden;\n"
	              " z-index:2147483647;\n"
	              " position:absolute;\n"
	              " padding:2px 4px 3px;\n"
	              " background:#f0f060; color:#000000;\n"
	              " border:1px solid #7040c0;\n"
	              " white-space:nowrap;\n"
	              " font-style:normal;font-size:11px;font-weight:normal;\n"
	              " -moz-border-radius:3px;-webkit-border-radius:3px;border-radius:3px;\n"
	              " -moz-box-shadow:gray 2px 2px 3px;-webkit-box-shadow:gray 2px 2px 3px;box-shadow:gray 2px 2px 3px;\n"
	              "}\n"
	              "u:hover div.tips {visibility:visible;}\n"
	              "@media (prefers-color-scheme: dark) {\n"
	              " body { font-family: arial, helvetica, sans-serif; font-size: 12px; font-weight: normal; color: #e8e6e3; background: #131516;}\n"
	              " h1 { color: #a265e0!important; }\n"
	              " h2 { color: #a265e0; }\n"
	              " h3 { color: #ff5190; background-color: #3e3e1f; }\n"
	              " a { color: #3391ff; }\n"
	              " input { background-color: #2f3437; color: #e8e6e3; }\n"
	              " .hr { border-color: #8c8273; }\n"
	              " .titre { background-color: #1aa6a6; color: #e8e6e3; }\n"
	              " .frontend {background: #2f3437;}\n"
	              " .socket	{background: #2a2d2f;}\n"
	              " .backend {background: #2f3437;}\n"
	              " .active_down {background: #760000;}\n"
	              " .active_going_up {background: #b99200;}\n"
	              " .active_going_down {background: #6c6c00;}\n"
	              " .active_up {background: #165900;}\n"
	              " .active_nolb {background: #006ab9;}\n"
	              " .active_draining {background: #006ab9;}\n"
	              " .active_no_check {background: #2a2d2f;}\n"
	              " .backup_down {background: #760000;}\n"
	              " .backup_going_up {background: #7f007f;}\n"
	              " .backup_going_down {background: #580092;}\n"
	              " .backup_up {background: #2e3234;}\n"
	              " .backup_nolb {background: #1e3c6a;}\n"
	              " .backup_draining {background: #a37a00;}\n"
	              " .backup_no_check {background: #2a2d2f;}\n"
	              " .maintain {background: #9a601a;}\n"
	              " a.px:link {color: #d8d83b; text-decoration: none;}\n"
	              " a.px:visited {color: #d8d83b; text-decoration: none;}\n"
	              " a.px:hover {color: #ffffff; text-decoration: none;}\n"
	              " a.lfsb:link {color: #e8e6e3; text-decoration: none;}\n"
	              " a.lfsb:visited {color: #e8e6e3; text-decoration: none;}\n"
	              " a.lfsb:hover {color: #b5afa6; text-decoration: none;}\n"
	              " table.tbl th.empty { background-color: #181a1b; }\n"
	              " table.tbl th.desc { background: #181a1b; }\n"
	              " table.tbl th.pxname { background-color: #8d0033; color: #ffff46; }\n"
	              " table.tbl th { border-color: #808080; }\n"
	              " table.tbl td { border-color: #808080; }\n"
	              " u {text-decoration:none; border-bottom: 1px dotted #e8e6e3;}\n"
	              " div.tips {\n"
	              "  background:#8e8e0d;\n"
	              "  color:#e8e6e3;\n"
	              "  border-color: #4e2c86;\n"
	              "  -moz-box-shadow: #60686c 2px 2px 3px;\n"
	              "  -webkit-box-shadow: #60686c 2px 2px 3px;\n"
	              "  box-shadow: #60686c 2px 2px 3px;\n"
	              " }\n"
	              "}\n"
	              "-->\n"
	              "</style></head>\n",
	              (ctx->flags & STAT_F_SHNODE) ? " on " : "",
	              (ctx->flags & STAT_F_SHNODE) ? (uri && uri->node ? uri->node : global.node) : ""
	              );
}

/* Dumps the HTML stats information block to chunk ctx buffer and uses the
 * state from stream connector <sc> and per-uri parameter from the parent
 * proxy. The caller is responsible for clearing chunk ctx buffer if needed.
 */
void stats_dump_html_info(struct stconn *sc)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;
	unsigned int up = ns_to_sec(now_ns - start_time_ns);
	char scope_txt[STAT_SCOPE_TXT_MAXLEN + sizeof STAT_SCOPE_PATTERN];
	const char *scope_ptr = stats_scope_ptr(appctx);
	struct uri_auth *uri;
	unsigned long long bps;
	int thr;

	BUG_ON(!ctx->http_px);
	uri = ctx->http_px->uri_auth;
	for (bps = thr = 0; thr < global.nbthread; thr++)
		bps += 32ULL * read_freq_ctr(&ha_thread_ctx[thr].out_32bps);

	/* Turn the bytes per second to bits per second and take care of the
	 * usual ethernet overhead in order to help figure how far we are from
	 * interface saturation since it's the only case which usually matters.
	 * For this we count the total size of an Ethernet frame on the wire
	 * including preamble and IFG (1538) for the largest TCP segment it
	 * transports (1448 with TCP timestamps). This is not valid for smaller
	 * packets (under-estimated), but it gives a reasonably accurate
	 * estimation of how far we are from uplink saturation.
	 */
	bps = bps * 8 * 1538 / 1448;

	/* WARNING! this has to fit the first packet too.
	 * We are around 3.5 kB, add adding entries will
	 * become tricky if we want to support 4kB buffers !
	 */
	chunk_appendf(chk,
	              "<body><h1><a href=\"" PRODUCT_URL "\" style=\"text-decoration: none;\">"
	              PRODUCT_NAME "%s</a></h1>\n"
	              "<h2>Statistics Report for pid %d%s%s%s%s</h2>\n"
	              "<hr width=\"100%%\" class=\"hr\">\n"
	              "<h3>&gt; General process information</h3>\n"
	              "<table border=0><tr><td align=\"left\" nowrap width=\"1%%\">\n"
	              "<p><b>pid = </b> %d (process #%d, nbproc = %d, nbthread = %d)<br>\n"
	              "<b>uptime = </b> %dd %dh%02dm%02ds; warnings = %u<br>\n"
	              "<b>system limits:</b> memmax = %s%s; ulimit-n = %d<br>\n"
	              "<b>maxsock = </b> %d; <b>maxconn = </b> %d; <b>reached = </b> %llu; <b>maxpipes = </b> %d<br>\n"
	              "current conns = %d; current pipes = %d/%d; conn rate = %d/sec; bit rate = %.3f %cbps<br>\n"
	              "Running tasks: %d/%d (%d niced); idle = %d %%<br>\n"
	              "</td><td align=\"center\" nowrap>\n"
	              "<table class=\"lgd\"><tr>\n"
	              "<td class=\"active_up\">&nbsp;</td><td class=\"noborder\">active UP </td>"
	              "<td class=\"backup_up\">&nbsp;</td><td class=\"noborder\">backup UP </td>"
	              "</tr><tr>\n"
	              "<td class=\"active_going_down\"></td><td class=\"noborder\">active UP, going down </td>"
	              "<td class=\"backup_going_down\"></td><td class=\"noborder\">backup UP, going down </td>"
	              "</tr><tr>\n"
	              "<td class=\"active_going_up\"></td><td class=\"noborder\">active DOWN, going up </td>"
	              "<td class=\"backup_going_up\"></td><td class=\"noborder\">backup DOWN, going up </td>"
	              "</tr><tr>\n"
	              "<td class=\"active_down\"></td><td class=\"noborder\">active or backup DOWN &nbsp;</td>"
	              "<td class=\"active_no_check\"></td><td class=\"noborder\">not checked </td>"
	              "</tr><tr>\n"
	              "<td class=\"maintain\"></td><td class=\"noborder\" colspan=\"3\">active or backup DOWN for maintenance (MAINT) &nbsp;</td>"
	              "</tr><tr>\n"
	              "<td class=\"active_draining\"></td><td class=\"noborder\" colspan=\"3\">active or backup SOFT STOPPED for maintenance &nbsp;</td>"
	              "</tr></table>\n"
	              "Note: \"NOLB\"/\"DRAIN\" = UP with load-balancing disabled."
	              "</td>"
	              "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
	              "<b>Display option:</b><ul style=\"margin-top: 0.25em;\">"
	              "",
	              (ctx->flags & STAT_F_HIDEVER) ? "" : (stats_version_string),
	              pid, (ctx->flags & STAT_F_SHNODE) ? " on " : "",
		      (ctx->flags & STAT_F_SHNODE) ? (uri->node ? uri->node : global.node) : "",
	              (ctx->flags & STAT_F_SHDESC) ? ": " : "",
		      (ctx->flags & STAT_F_SHDESC) ? (uri->desc ? uri->desc : global.desc) : "",
	              pid, 1, 1, global.nbthread,
	              up / 86400, (up % 86400) / 3600,
	              (up % 3600) / 60, (up % 60),
	              HA_ATOMIC_LOAD(&tot_warnings),
	              global.rlimit_memmax ? ultoa(global.rlimit_memmax) : "unlimited",
	              global.rlimit_memmax ? " MB" : "",
	              global.rlimit_nofile,
	              global.maxsock, global.maxconn, HA_ATOMIC_LOAD(&maxconn_reached), global.maxpipes,
	              actconn, pipes_used, pipes_used+pipes_free, read_freq_ctr(&global.conn_per_sec),
		      bps >= 1000000000UL ? (bps / 1000000000.0) : bps >= 1000000UL ? (bps / 1000000.0) : (bps / 1000.0),
		      bps >= 1000000000UL ? 'G' : bps >= 1000000UL ? 'M' : 'k',
	              total_run_queues(), total_allocated_tasks(), total_niced_running_tasks(), clock_report_idle());

	/* scope_txt = search query, ctx->scope_len is always <= STAT_SCOPE_TXT_MAXLEN */
	memcpy(scope_txt, scope_ptr, ctx->scope_len);
	scope_txt[ctx->scope_len] = '\0';

	chunk_appendf(chk,
		      "<li><form method=\"GET\">Scope : <input value=\"%s\" name=\"" STAT_SCOPE_INPUT_NAME "\" size=\"8\" maxlength=\"%d\" tabindex=\"1\"/></form>\n",
		      (ctx->scope_len > 0) ? scope_txt : "",
		      STAT_SCOPE_TXT_MAXLEN);

	/* scope_txt = search pattern + search query, ctx->scope_len is always <= STAT_SCOPE_TXT_MAXLEN */
	scope_txt[0] = 0;
	if (ctx->scope_len) {
		strlcpy2(scope_txt, STAT_SCOPE_PATTERN, sizeof(scope_txt));
		memcpy(scope_txt + strlen(STAT_SCOPE_PATTERN), scope_ptr, ctx->scope_len);
		scope_txt[strlen(STAT_SCOPE_PATTERN) + ctx->scope_len] = 0;
	}

	if (ctx->flags & STAT_F_HIDE_DOWN)
		chunk_appendf(chk,
		              "<li><a href=\"%s%s%s%s\">Show all servers</a><br>\n",
		              uri->uri_prefix,
		              "",
		              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
			      scope_txt);
	else
		chunk_appendf(chk,
		              "<li><a href=\"%s%s%s%s\">Hide 'DOWN' servers</a><br>\n",
		              uri->uri_prefix,
		              ";up",
		              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
			      scope_txt);

	if (uri->refresh > 0) {
		if (ctx->flags & STAT_F_NO_REFRESH)
			chunk_appendf(chk,
			              "<li><a href=\"%s%s%s%s\">Enable refresh</a><br>\n",
			              uri->uri_prefix,
			              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
			              "",
				      scope_txt);
		else
			chunk_appendf(chk,
			              "<li><a href=\"%s%s%s%s\">Disable refresh</a><br>\n",
			              uri->uri_prefix,
			              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
			              ";norefresh",
				      scope_txt);
	}

	chunk_appendf(chk,
	              "<li><a href=\"%s%s%s%s\">Refresh now</a><br>\n",
	              uri->uri_prefix,
	              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
	              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
		      scope_txt);

	chunk_appendf(chk,
	              "<li><a href=\"%s;csv%s%s\">CSV export</a><br>\n",
	              uri->uri_prefix,
	              (uri->refresh > 0) ? ";norefresh" : "",
		      scope_txt);

	chunk_appendf(chk,
	              "<li><a href=\"%s;json%s%s\">JSON export</a> (<a href=\"%s;json-schema\">schema</a>)<br>\n",
	              uri->uri_prefix,
	              (uri->refresh > 0) ? ";norefresh" : "",
		      scope_txt, uri->uri_prefix);

	chunk_appendf(chk,
	              "</ul></td>"
	              "<td align=\"left\" valign=\"top\" nowrap width=\"1%%\">"
	              "<b>External resources:</b><ul style=\"margin-top: 0.25em;\">\n"
	              "<li><a href=\"" PRODUCT_URL "\">Primary site</a><br>\n"
	              "<li><a href=\"" PRODUCT_URL_UPD "\">Updates (v" PRODUCT_BRANCH ")</a><br>\n"
	              "<li><a href=\"" PRODUCT_URL_DOC "\">Online manual</a><br>\n"
	              "</ul>"
	              "</td>"
	              "</tr></table>\n"
	              ""
	              );

	if (ctx->st_code) {
		switch (ctx->st_code) {
		case STAT_STATUS_DONE:
			chunk_appendf(chk,
			              "<p><div class=active_up>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "Action processed successfully."
			              "</div>\n", uri->uri_prefix,
			              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
			              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_NONE:
			chunk_appendf(chk,
			              "<p><div class=active_going_down>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "Nothing has changed."
			              "</div>\n", uri->uri_prefix,
			              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
			              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_PART:
			chunk_appendf(chk,
			              "<p><div class=active_going_down>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "Action partially processed.<br>"
			              "Some server names are probably unknown or ambiguous (duplicated names in the backend)."
			              "</div>\n", uri->uri_prefix,
			              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
			              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_ERRP:
			chunk_appendf(chk,
			              "<p><div class=active_down>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "Action not processed because of invalid parameters."
			              "<ul>"
			              "<li>The action is maybe unknown.</li>"
				      "<li>Invalid key parameter (empty or too long).</li>"
			              "<li>The backend name is probably unknown or ambiguous (duplicated names).</li>"
			              "<li>Some server names are probably unknown or ambiguous (duplicated names in the backend).</li>"
			              "</ul>"
			              "</div>\n", uri->uri_prefix,
			              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
			              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_EXCD:
			chunk_appendf(chk,
			              "<p><div class=active_down>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "<b>Action not processed : the buffer couldn't store all the data.<br>"
			              "You should retry with less servers at a time.</b>"
			              "</div>\n", uri->uri_prefix,
			              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
			              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_DENY:
			chunk_appendf(chk,
			              "<p><div class=active_down>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "<b>Action denied.</b>"
			              "</div>\n", uri->uri_prefix,
			              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
			              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		case STAT_STATUS_IVAL:
			chunk_appendf(chk,
			              "<p><div class=active_down>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "<b>Invalid requests (unsupported method or chunked encoded request).</b>"
			              "</div>\n", uri->uri_prefix,
			              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
			              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
			break;
		default:
			chunk_appendf(chk,
			              "<p><div class=active_no_check>"
			              "<a class=lfsb href=\"%s%s%s%s\" title=\"Remove this message\">[X]</a> "
			              "Unexpected result."
			              "</div>\n", uri->uri_prefix,
			              (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
			              (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
			              scope_txt);
		}
		chunk_appendf(chk, "<p>\n");
	}
}

/* Dump all fields from <stats> into <out> using the HTML format. A column is
 * reserved for the checkbox is STAT_F_ADMIN is set in <flags>. Some extra info
 * are provided if STAT_F_SHLGNDS is present in <flags>. The statistics from
 * extra modules are displayed at the end of the lines if STAT_F_SHMODULES is
 * present in <flags>.
 */
int stats_dump_fields_html(struct buffer *out,
                           const struct field *stats,
                           struct show_stat_ctx *ctx)
{
	struct buffer src;
	struct stats_module *mod;
	int flags = ctx->flags;
	int i = 0, j = 0;

	if (stats[ST_I_PX_TYPE].u.u32 == STATS_TYPE_FE) {
		chunk_appendf(out,
		              /* name, queue */
		              "<tr class=\"frontend\">");

		if (flags & STAT_F_ADMIN) {
			/* Column sub-heading for Enable or Disable server */
			chunk_appendf(out, "<td></td>");
		}

		chunk_appendf(out,
		              "<td class=ac>"
		              "<a name=\"%s/Frontend\"></a>"
		              "<a class=lfsb href=\"#%s/Frontend\">Frontend</a></td>"
		              "<td colspan=3></td>"
		              "",
		              field_str(stats, ST_I_PX_PXNAME), field_str(stats, ST_I_PX_PXNAME));

		chunk_appendf(out,
		              /* sessions rate : current */
		              "<td><u>%s<div class=tips><table class=det>"
		              "<tr><th>Current connection rate:</th><td>%s/s</td></tr>"
		              "<tr><th>Current session rate:</th><td>%s/s</td></tr>"
		              "",
		              U2H(stats[ST_I_PX_RATE].u.u32),
		              U2H(stats[ST_I_PX_CONN_RATE].u.u32),
		              U2H(stats[ST_I_PX_RATE].u.u32));

		if (strcmp(field_str(stats, ST_I_PX_MODE), "http") == 0)
			chunk_appendf(out,
			              "<tr><th>Current request rate:</th><td>%s/s</td></tr>",
			              U2H(stats[ST_I_PX_REQ_RATE].u.u32));

		chunk_appendf(out,
		              "</table></div></u></td>"
		              /* sessions rate : max */
		              "<td><u>%s<div class=tips><table class=det>"
		              "<tr><th>Max connection rate:</th><td>%s/s</td></tr>"
		              "<tr><th>Max session rate:</th><td>%s/s</td></tr>"
		              "",
		              U2H(stats[ST_I_PX_RATE_MAX].u.u32),
		              U2H(stats[ST_I_PX_CONN_RATE_MAX].u.u32),
		              U2H(stats[ST_I_PX_RATE_MAX].u.u32));

		if (strcmp(field_str(stats, ST_I_PX_MODE), "http") == 0)
			chunk_appendf(out,
			              "<tr><th>Max request rate:</th><td>%s/s</td></tr>",
			              U2H(stats[ST_I_PX_REQ_RATE_MAX].u.u32));

		chunk_appendf(out,
		              "</table></div></u></td>"
		              /* sessions rate : limit */
		              "<td>%s</td>",
		              LIM2A(stats[ST_I_PX_RATE_LIM].u.u32, "-"));

		chunk_appendf(out,
		              /* sessions: current, max, limit, total */
		              "<td>%s</td><td>%s</td><td>%s</td>"
		              "<td><u>%s<div class=tips><table class=det>"
		              "<tr><th>Cum. connections:</th><td>%s</td></tr>"
		              "<tr><th>Cum. sessions:</th><td>%s</td></tr>"
		              "",
		              U2H(stats[ST_I_PX_SCUR].u.u32), U2H(stats[ST_I_PX_SMAX].u.u32), U2H(stats[ST_I_PX_SLIM].u.u32),
		              U2H(stats[ST_I_PX_STOT].u.u64),
		              U2H(stats[ST_I_PX_CONN_TOT].u.u64),
		              U2H(stats[ST_I_PX_STOT].u.u64));

		/* http response (via hover): 1xx, 2xx, 3xx, 4xx, 5xx, other */
		if (strcmp(field_str(stats, ST_I_PX_MODE), "http") == 0) {
			chunk_appendf(out,
			              "<tr><th>- HTTP/1 sessions:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP/2 sessions:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP/3 sessions:</th><td>%s</td></tr>"
			              "<tr><th>- other sessions:</th><td>%s</td></tr>"
			              "<tr><th>Cum. HTTP requests:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP/1 requests:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP/2 requests:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP/3 requests:</th><td>%s</td></tr>"
			              "<tr><th>- other requests:</th><td>%s</td></tr>"
			              "",
			              U2H(stats[ST_I_PX_H1SESS].u.u64),
			              U2H(stats[ST_I_PX_H2SESS].u.u64),
			              U2H(stats[ST_I_PX_H3SESS].u.u64),
			              U2H(stats[ST_I_PX_SESS_OTHER].u.u64),
			              U2H(stats[ST_I_PX_REQ_TOT].u.u64),
			              U2H(stats[ST_I_PX_H1REQ].u.u64),
			              U2H(stats[ST_I_PX_H2REQ].u.u64),
			              U2H(stats[ST_I_PX_H3REQ].u.u64),
			              U2H(stats[ST_I_PX_REQ_OTHER].u.u64));

			chunk_appendf(out,
			              "<tr><th>- HTTP 1xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 2xx responses:</th><td>%s</td></tr>"
			              "<tr><th>&nbsp;&nbsp;Compressed 2xx:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 3xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 4xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 5xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- other responses:</th><td>%s</td></tr>"
			              "",
			              U2H(stats[ST_I_PX_HRSP_1XX].u.u64),
			              U2H(stats[ST_I_PX_HRSP_2XX].u.u64),
			              U2H(stats[ST_I_PX_COMP_RSP].u.u64),
			              stats[ST_I_PX_HRSP_2XX].u.u64 ?
			              (int)(100 * stats[ST_I_PX_COMP_RSP].u.u64 / stats[ST_I_PX_HRSP_2XX].u.u64) : 0,
			              U2H(stats[ST_I_PX_HRSP_3XX].u.u64),
			              U2H(stats[ST_I_PX_HRSP_4XX].u.u64),
			              U2H(stats[ST_I_PX_HRSP_5XX].u.u64),
			              U2H(stats[ST_I_PX_HRSP_OTHER].u.u64));

			chunk_appendf(out,
			              "<tr><th>Intercepted requests:</th><td>%s</td></tr>"
			              "<tr><th>Cache lookups:</th><td>%s</td></tr>"
			              "<tr><th>Cache hits:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>Failed hdr rewrites:</th><td>%s</td></tr>"
			              "<tr><th>Internal errors:</th><td>%s</td></tr>"
			              "",
			              U2H(stats[ST_I_PX_INTERCEPTED].u.u64),
			              U2H(stats[ST_I_PX_CACHE_LOOKUPS].u.u64),
			              U2H(stats[ST_I_PX_CACHE_HITS].u.u64),
			              stats[ST_I_PX_CACHE_LOOKUPS].u.u64 ?
			              (int)(100 * stats[ST_I_PX_CACHE_HITS].u.u64 / stats[ST_I_PX_CACHE_LOOKUPS].u.u64) : 0,
			              U2H(stats[ST_I_PX_WREW].u.u64),
			              U2H(stats[ST_I_PX_EINT].u.u64));
		}

		chunk_appendf(out,
		              "</table></div></u></td>"
		              /* sessions: lbtot, lastsess */
		              "<td></td><td></td>"
		              /* bytes : in */
		              "<td>%s</td>"
		              "",
		              U2H(stats[ST_I_PX_BIN].u.u64));

		chunk_appendf(out,
			      /* bytes:out + compression stats (via hover): comp_in, comp_out, comp_byp */
		              "<td>%s%s<div class=tips><table class=det>"
			      "<tr><th>Response bytes in:</th><td>%s</td></tr>"
			      "<tr><th>Compression in:</th><td>%s</td></tr>"
			      "<tr><th>Compression out:</th><td>%s</td><td>(%d%%)</td></tr>"
			      "<tr><th>Compression bypass:</th><td>%s</td></tr>"
			      "<tr><th>Total bytes saved:</th><td>%s</td><td>(%d%%)</td></tr>"
			      "</table></div>%s</td>",
		              (stats[ST_I_PX_COMP_IN].u.u64 || stats[ST_I_PX_COMP_BYP].u.u64) ? "<u>":"",
		              U2H(stats[ST_I_PX_BOUT].u.u64),
		              U2H(stats[ST_I_PX_BOUT].u.u64),
		              U2H(stats[ST_I_PX_COMP_IN].u.u64),
			      U2H(stats[ST_I_PX_COMP_OUT].u.u64),
			      stats[ST_I_PX_COMP_IN].u.u64 ? (int)(stats[ST_I_PX_COMP_OUT].u.u64 * 100 / stats[ST_I_PX_COMP_IN].u.u64) : 0,
			      U2H(stats[ST_I_PX_COMP_BYP].u.u64),
			      U2H(stats[ST_I_PX_COMP_IN].u.u64 - stats[ST_I_PX_COMP_OUT].u.u64),
			      stats[ST_I_PX_BOUT].u.u64 ? (int)((stats[ST_I_PX_COMP_IN].u.u64 - stats[ST_I_PX_COMP_OUT].u.u64) * 100 / stats[ST_I_PX_BOUT].u.u64) : 0,
		              (stats[ST_I_PX_COMP_IN].u.u64 || stats[ST_I_PX_COMP_BYP].u.u64) ? "</u>":"");

		chunk_appendf(out,
		              /* denied: req, resp */
		              "<td>%s</td><td>%s</td>"
		              /* errors : request, connect, response */
		              "<td>%s</td><td></td><td></td>"
		              /* warnings: retries, redispatches */
		              "<td></td><td></td>"
		              /* server status : reflect frontend status */
		              "<td class=ac>%s</td>"
		              /* rest of server: nothing */
		              "<td class=ac colspan=8></td>"
		              "",
		              U2H(stats[ST_I_PX_DREQ].u.u64), U2H(stats[ST_I_PX_DRESP].u.u64),
		              U2H(stats[ST_I_PX_EREQ].u.u64),
		              field_str(stats, ST_I_PX_STATUS));

		if (flags & STAT_F_SHMODULES) {
			list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
				chunk_appendf(out, "<td>");

				if (stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_FE) {
					chunk_appendf(out,
					              "<u>%s<div class=tips><table class=det>",
					              mod->name);
					for (j = 0; j < mod->stats_count; ++j) {
						chunk_appendf(out,
						              "<tr><th>%s</th><td>%s</td></tr>",
						              mod->stats[j].desc, field_to_html_str(&stats[ST_I_PX_MAX + i]));
						++i;
					}
					chunk_appendf(out, "</table></div></u>");
				} else {
					i += mod->stats_count;
				}

				chunk_appendf(out, "</td>");
			}
		}

		chunk_appendf(out, "</tr>");
	}
	else if (stats[ST_I_PX_TYPE].u.u32 == STATS_TYPE_SO) {
		chunk_appendf(out, "<tr class=socket>");
		if (flags & STAT_F_ADMIN) {
			/* Column sub-heading for Enable or Disable server */
			chunk_appendf(out, "<td></td>");
		}

		chunk_appendf(out,
		              /* frontend name, listener name */
		              "<td class=ac><a name=\"%s/+%s\"></a>%s"
		              "<a class=lfsb href=\"#%s/+%s\">%s</a>"
		              "",
		              field_str(stats, ST_I_PX_PXNAME), field_str(stats, ST_I_PX_SVNAME),
		              (flags & STAT_F_SHLGNDS)?"<u>":"",
		              field_str(stats, ST_I_PX_PXNAME), field_str(stats, ST_I_PX_SVNAME), field_str(stats, ST_I_PX_SVNAME));

		if (flags & STAT_F_SHLGNDS) {
			chunk_appendf(out, "<div class=tips>");

			if (isdigit((unsigned char)*field_str(stats, ST_I_PX_ADDR)))
				chunk_appendf(out, "IPv4: %s, ", field_str(stats, ST_I_PX_ADDR));
			else if (*field_str(stats, ST_I_PX_ADDR) == '[')
				chunk_appendf(out, "IPv6: %s, ", field_str(stats, ST_I_PX_ADDR));
			else if (*field_str(stats, ST_I_PX_ADDR))
				chunk_appendf(out, "%s, ", field_str(stats, ST_I_PX_ADDR));

			chunk_appendf(out, "proto=%s, ", field_str(stats, ST_I_PX_PROTO));

			/* id */
			chunk_appendf(out, "id: %d</div>", stats[ST_I_PX_SID].u.u32);
		}

		chunk_appendf(out,
			      /* queue */
		              "%s</td><td colspan=3></td>"
		              /* sessions rate: current, max, limit */
		              "<td colspan=3>&nbsp;</td>"
		              /* sessions: current, max, limit, total, lbtot, lastsess */
		              "<td>%s</td><td>%s</td><td>%s</td>"
		              "<td>%s</td><td>&nbsp;</td><td>&nbsp;</td>"
		              /* bytes: in, out */
		              "<td>%s</td><td>%s</td>"
		              "",
		              (flags & STAT_F_SHLGNDS)?"</u>":"",
		              U2H(stats[ST_I_PX_SCUR].u.u32), U2H(stats[ST_I_PX_SMAX].u.u32), U2H(stats[ST_I_PX_SLIM].u.u32),
		              U2H(stats[ST_I_PX_STOT].u.u64), U2H(stats[ST_I_PX_BIN].u.u64), U2H(stats[ST_I_PX_BOUT].u.u64));

		chunk_appendf(out,
		              /* denied: req, resp */
		              "<td>%s</td><td>%s</td>"
		              /* errors: request, connect, response */
		              "<td>%s</td><td></td><td></td>"
		              /* warnings: retries, redispatches */
		              "<td></td><td></td>"
		              /* server status: reflect listener status */
		              "<td class=ac>%s</td>"
		              /* rest of server: nothing */
		              "<td class=ac colspan=8></td>"
		              "",
		              U2H(stats[ST_I_PX_DREQ].u.u64), U2H(stats[ST_I_PX_DRESP].u.u64),
		              U2H(stats[ST_I_PX_EREQ].u.u64),
		              field_str(stats, ST_I_PX_STATUS));

		if (flags & STAT_F_SHMODULES) {
			list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
				chunk_appendf(out, "<td>");

				if (stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_LI) {
					chunk_appendf(out,
					              "<u>%s<div class=tips><table class=det>",
					              mod->name);
					for (j = 0; j < mod->stats_count; ++j) {
						chunk_appendf(out,
						              "<tr><th>%s</th><td>%s</td></tr>",
						              mod->stats[j].desc, field_to_html_str(&stats[ST_I_PX_MAX + i]));
						++i;
					}
					chunk_appendf(out, "</table></div></u>");
				} else {
					i += mod->stats_count;
				}

				chunk_appendf(out, "</td>");
			}
		}

		chunk_appendf(out, "</tr>");
	}
	else if (stats[ST_I_PX_TYPE].u.u32 == STATS_TYPE_SV) {
		const char *style;

		/* determine the style to use depending on the server's state,
		 * its health and weight. There isn't a 1-to-1 mapping between
		 * state and styles for the cases where the server is (still)
		 * up. The reason is that we don't want to report nolb and
		 * drain with the same color.
		 */

		if (strcmp(field_str(stats, ST_I_PX_STATUS), "DOWN") == 0 ||
		    strcmp(field_str(stats, ST_I_PX_STATUS), "DOWN (agent)") == 0) {
			style = "down";
		}
		else if (strncmp(field_str(stats, ST_I_PX_STATUS), "DOWN ", strlen("DOWN ")) == 0) {
			style = "going_up";
		}
		else if (strcmp(field_str(stats, ST_I_PX_STATUS), "DRAIN") == 0) {
			style = "draining";
		}
		else if (strncmp(field_str(stats, ST_I_PX_STATUS), "NOLB ", strlen("NOLB ")) == 0) {
			style = "going_down";
		}
		else if (strcmp(field_str(stats, ST_I_PX_STATUS), "NOLB") == 0) {
			style = "nolb";
		}
		else if (strcmp(field_str(stats, ST_I_PX_STATUS), "no check") == 0) {
			style = "no_check";
		}
		else if (!stats[ST_I_PX_CHKFAIL].type ||
			 stats[ST_I_PX_CHECK_HEALTH].u.u32 == stats[ST_I_PX_CHECK_RISE].u.u32 + stats[ST_I_PX_CHECK_FALL].u.u32 - 1) {
			/* no check or max health = UP */
			if (stats[ST_I_PX_WEIGHT].u.u32)
				style = "up";
			else
				style = "draining";
		}
		else {
			style = "going_down";
		}

		if (strncmp(field_str(stats, ST_I_PX_STATUS), "MAINT", 5) == 0)
			chunk_appendf(out, "<tr class=\"maintain\">");
		else
			chunk_appendf(out,
			              "<tr class=\"%s_%s\">",
			              (stats[ST_I_PX_BCK].u.u32) ? "backup" : "active", style);


		if (flags & STAT_F_ADMIN)
			chunk_appendf(out,
			              "<td><input class='%s-checkbox' type=\"checkbox\" name=\"s\" value=\"%s\"></td>",
			              field_str(stats, ST_I_PX_PXNAME),
			              field_str(stats, ST_I_PX_SVNAME));

		chunk_appendf(out,
		              "<td class=ac><a name=\"%s/%s\"></a>%s"
		              "<a class=lfsb href=\"#%s/%s\">%s</a>"
		              "",
		              field_str(stats, ST_I_PX_PXNAME), field_str(stats, ST_I_PX_SVNAME),
		              (flags & STAT_F_SHLGNDS) ? "<u>" : "",
		              field_str(stats, ST_I_PX_PXNAME), field_str(stats, ST_I_PX_SVNAME), field_str(stats, ST_I_PX_SVNAME));

		if (flags & STAT_F_SHLGNDS) {
			chunk_appendf(out, "<div class=tips>");

			if (isdigit((unsigned char)*field_str(stats, ST_I_PX_ADDR)))
				chunk_appendf(out, "IPv4: %s, ", field_str(stats, ST_I_PX_ADDR));
			else if (*field_str(stats, ST_I_PX_ADDR) == '[')
				chunk_appendf(out, "IPv6: %s, ", field_str(stats, ST_I_PX_ADDR));
			else if (*field_str(stats, ST_I_PX_ADDR))
				chunk_appendf(out, "%s, ", field_str(stats, ST_I_PX_ADDR));

			/* id */
			chunk_appendf(out, "id: %d, rid: %d", stats[ST_I_PX_SID].u.u32, stats[ST_I_PX_SRID].u.u32);

			/* cookie */
			if (stats[ST_I_PX_COOKIE].type) {
				chunk_appendf(out, ", cookie: '");
				chunk_initstr(&src, field_str(stats, ST_I_PX_COOKIE));
				chunk_htmlencode(out, &src);
				chunk_appendf(out, "'");
			}

			chunk_appendf(out, "</div>");
		}

		chunk_appendf(out,
		              /* queue : current, max, limit */
		              "%s</td><td>%s</td><td>%s</td><td>%s</td>"
		              /* sessions rate : current, max, limit */
		              "<td>%s</td><td>%s</td><td></td>"
		              "",
		              (flags & STAT_F_SHLGNDS) ? "</u>" : "",
		              U2H(stats[ST_I_PX_QCUR].u.u32), U2H(stats[ST_I_PX_QMAX].u.u32), LIM2A(stats[ST_I_PX_QLIMIT].u.u32, "-"),
		              U2H(stats[ST_I_PX_RATE].u.u32), U2H(stats[ST_I_PX_RATE_MAX].u.u32));

		chunk_appendf(out,
		              /* sessions: current, max, limit, total */
		              "<td><u>%s<div class=tips>"
			        "<table class=det>"
		                "<tr><th>Current active connections:</th><td>%s</td></tr>"
		                "<tr><th>Current used connections:</th><td>%s</td></tr>"
		                "<tr><th>Current idle connections:</th><td>%s</td></tr>"
		                "<tr><th>- unsafe:</th><td>%s</td></tr>"
		                "<tr><th>- safe:</th><td>%s</td></tr>"
		                "<tr><th>Estimated need of connections:</th><td>%s</td></tr>"
		                "<tr><th>Active connections limit:</th><td>%s</td></tr>"
		                "<tr><th>Idle connections limit:</th><td>%s</td></tr>"
			        "</table></div></u>"
			      "</td><td>%s</td><td>%s</td>"
		              "<td><u>%s<div class=tips><table class=det>"
		              "<tr><th>Cum. sessions:</th><td>%s</td></tr>"
		              "",
		              U2H(stats[ST_I_PX_SCUR].u.u32),
			      U2H(stats[ST_I_PX_SCUR].u.u32),
			      U2H(stats[ST_I_PX_USED_CONN_CUR].u.u32),
			      U2H(stats[ST_I_PX_SRV_ICUR].u.u32),
			      U2H(stats[ST_I_PX_IDLE_CONN_CUR].u.u32),
			      U2H(stats[ST_I_PX_SAFE_CONN_CUR].u.u32),
			      U2H(stats[ST_I_PX_NEED_CONN_EST].u.u32),

			        LIM2A(stats[ST_I_PX_SLIM].u.u32, "-"),
		                stats[ST_I_PX_SRV_ILIM].type ? U2H(stats[ST_I_PX_SRV_ILIM].u.u32) : "-",
			      U2H(stats[ST_I_PX_SMAX].u.u32), LIM2A(stats[ST_I_PX_SLIM].u.u32, "-"),
		              U2H(stats[ST_I_PX_STOT].u.u64),
		              U2H(stats[ST_I_PX_STOT].u.u64));

		/* http response (via hover): 1xx, 2xx, 3xx, 4xx, 5xx, other */
		if (strcmp(field_str(stats, ST_I_PX_MODE), "http") == 0) {
			chunk_appendf(out,
			              "<tr><th>New connections:</th><td>%s</td></tr>"
			              "<tr><th>Reused connections:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>Cum. HTTP requests:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 1xx responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 2xx responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 3xx responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 4xx responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 5xx responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- other responses:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>Failed hdr rewrites:</th><td>%s</td></tr>"
			              "<tr><th>Internal error:</th><td>%s</td></tr>"
			              "",
			              U2H(stats[ST_I_PX_CONNECT].u.u64),
			              U2H(stats[ST_I_PX_REUSE].u.u64),
			              (stats[ST_I_PX_CONNECT].u.u64 + stats[ST_I_PX_REUSE].u.u64) ?
			              (int)(100 * stats[ST_I_PX_REUSE].u.u64 / (stats[ST_I_PX_CONNECT].u.u64 + stats[ST_I_PX_REUSE].u.u64)) : 0,
			              U2H(stats[ST_I_PX_REQ_TOT].u.u64),
			              U2H(stats[ST_I_PX_HRSP_1XX].u.u64), stats[ST_I_PX_REQ_TOT].u.u64 ?
			              (int)(100 * stats[ST_I_PX_HRSP_1XX].u.u64 / stats[ST_I_PX_REQ_TOT].u.u64) : 0,
			              U2H(stats[ST_I_PX_HRSP_2XX].u.u64), stats[ST_I_PX_REQ_TOT].u.u64 ?
			              (int)(100 * stats[ST_I_PX_HRSP_2XX].u.u64 / stats[ST_I_PX_REQ_TOT].u.u64) : 0,
			              U2H(stats[ST_I_PX_HRSP_3XX].u.u64), stats[ST_I_PX_REQ_TOT].u.u64 ?
			              (int)(100 * stats[ST_I_PX_HRSP_3XX].u.u64 / stats[ST_I_PX_REQ_TOT].u.u64) : 0,
			              U2H(stats[ST_I_PX_HRSP_4XX].u.u64), stats[ST_I_PX_REQ_TOT].u.u64 ?
			              (int)(100 * stats[ST_I_PX_HRSP_4XX].u.u64 / stats[ST_I_PX_REQ_TOT].u.u64) : 0,
			              U2H(stats[ST_I_PX_HRSP_5XX].u.u64), stats[ST_I_PX_REQ_TOT].u.u64 ?
			              (int)(100 * stats[ST_I_PX_HRSP_5XX].u.u64 / stats[ST_I_PX_REQ_TOT].u.u64) : 0,
			              U2H(stats[ST_I_PX_HRSP_OTHER].u.u64), stats[ST_I_PX_REQ_TOT].u.u64 ?
			              (int)(100 * stats[ST_I_PX_HRSP_OTHER].u.u64 / stats[ST_I_PX_REQ_TOT].u.u64) : 0,
			              U2H(stats[ST_I_PX_WREW].u.u64),
			              U2H(stats[ST_I_PX_EINT].u.u64));
		}
		else if (strcmp(field_str(stats, ST_I_PX_MODE), "spop") == 0) {
			chunk_appendf(out,
			              "<tr><th>New connections:</th><td>%s</td></tr>"
			              "<tr><th>Reused connections:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "",
			              U2H(stats[ST_I_PX_CONNECT].u.u64),
			              U2H(stats[ST_I_PX_REUSE].u.u64),
			              (stats[ST_I_PX_CONNECT].u.u64 + stats[ST_I_PX_REUSE].u.u64) ?
			              (int)(100 * stats[ST_I_PX_REUSE].u.u64 / (stats[ST_I_PX_CONNECT].u.u64 + stats[ST_I_PX_REUSE].u.u64)) : 0);
		}

		chunk_appendf(out, "<tr><th colspan=3>Max / Avg over last 1024 success. conn.</th></tr>");
		chunk_appendf(out, "<tr><th>- Queue time:</th><td>%s / %s</td><td>ms</td></tr>",
			      U2H(stats[ST_I_PX_QT_MAX].u.u32), U2H(stats[ST_I_PX_QTIME].u.u32));
		chunk_appendf(out, "<tr><th>- Connect time:</th><td>%s / %s</td><td>ms</td></tr>",
			      U2H(stats[ST_I_PX_CT_MAX].u.u32), U2H(stats[ST_I_PX_CTIME].u.u32));
		if (strcmp(field_str(stats, ST_I_PX_MODE), "http") == 0)
			chunk_appendf(out, "<tr><th>- Responses time:</th><td>%s / %s</td><td>ms</td></tr>",
				      U2H(stats[ST_I_PX_RT_MAX].u.u32), U2H(stats[ST_I_PX_RTIME].u.u32));
		chunk_appendf(out, "<tr><th>- Total time:</th><td>%s / %s</td><td>ms</td></tr>",
			      U2H(stats[ST_I_PX_TT_MAX].u.u32), U2H(stats[ST_I_PX_TTIME].u.u32));

		chunk_appendf(out,
		              "</table></div></u></td>"
		              /* sessions: lbtot, last */
		              "<td>%s</td><td>%s</td>",
		              U2H(stats[ST_I_PX_LBTOT].u.u64),
		              human_time(stats[ST_I_PX_LASTSESS].u.s32, 1));

		chunk_appendf(out,
		              /* bytes : in, out */
		              "<td>%s</td><td>%s</td>"
		              /* denied: req, resp */
		              "<td></td><td>%s</td>"
		              /* errors : request, connect */
		              "<td></td><td>%s</td>"
		              /* errors : response */
		              "<td><u>%s<div class=tips>Connection resets during transfers: %lld client, %lld server</div></u></td>"
		              /* warnings: retries, redispatches */
		              "<td>%lld</td><td>%lld</td>"
		              "",
		              U2H(stats[ST_I_PX_BIN].u.u64), U2H(stats[ST_I_PX_BOUT].u.u64),
		              U2H(stats[ST_I_PX_DRESP].u.u64),
		              U2H(stats[ST_I_PX_ECON].u.u64),
		              U2H(stats[ST_I_PX_ERESP].u.u64),
		              (long long)stats[ST_I_PX_CLI_ABRT].u.u64,
		              (long long)stats[ST_I_PX_SRV_ABRT].u.u64,
		              (long long)stats[ST_I_PX_WRETR].u.u64,
			      (long long)stats[ST_I_PX_WREDIS].u.u64);

		/* status, last change */
		chunk_appendf(out, "<td class=ac>");

		/* FIXME!!!!
		 *   LASTCHG should contain the last change for *this* server and must be computed
		 * properly above, as was done below, ie: this server if maint, otherwise ref server
		 * if tracking. Note that ref is either local or remote depending on tracking.
		 */


		if (strncmp(field_str(stats, ST_I_PX_STATUS), "MAINT", 5) == 0) {
			chunk_appendf(out, "%s MAINT", human_time(stats[ST_I_PX_LASTCHG].u.u32, 1));
		}
		else if (strcmp(field_str(stats, ST_I_PX_STATUS), "no check") == 0) {
			chunk_strcat(out, "<i>no check</i>");
		}
		else {
			chunk_appendf(out, "%s %s", human_time(stats[ST_I_PX_LASTCHG].u.u32, 1), field_str(stats, ST_I_PX_STATUS));
			if (strncmp(field_str(stats, ST_I_PX_STATUS), "DOWN", 4) == 0) {
				if (stats[ST_I_PX_CHECK_HEALTH].u.u32)
					chunk_strcat(out, " &uarr;");
			}
			else if (stats[ST_I_PX_CHECK_HEALTH].u.u32 < stats[ST_I_PX_CHECK_RISE].u.u32 + stats[ST_I_PX_CHECK_FALL].u.u32 - 1)
				chunk_strcat(out, " &darr;");
		}

		if (strncmp(field_str(stats, ST_I_PX_STATUS), "DOWN", 4) == 0 &&
		    stats[ST_I_PX_AGENT_STATUS].type && !stats[ST_I_PX_AGENT_HEALTH].u.u32) {
			chunk_appendf(out,
			              "</td><td class=ac><u> %s",
			              field_str(stats, ST_I_PX_AGENT_STATUS));

			if (stats[ST_I_PX_AGENT_CODE].type)
				chunk_appendf(out, "/%d", stats[ST_I_PX_AGENT_CODE].u.u32);

			if (stats[ST_I_PX_AGENT_DURATION].type)
				chunk_appendf(out, " in %lums", (long)stats[ST_I_PX_AGENT_DURATION].u.u64);

			chunk_appendf(out, "<div class=tips>%s", field_str(stats, ST_I_PX_AGENT_DESC));

			if (*field_str(stats, ST_I_PX_LAST_AGT)) {
				chunk_appendf(out, ": ");
				chunk_initstr(&src, field_str(stats, ST_I_PX_LAST_AGT));
				chunk_htmlencode(out, &src);
			}
			chunk_appendf(out, "</div></u>");
		}
		else if (stats[ST_I_PX_CHECK_STATUS].type) {
			chunk_appendf(out,
			              "</td><td class=ac><u> %s",
			              field_str(stats, ST_I_PX_CHECK_STATUS));

			if (stats[ST_I_PX_CHECK_CODE].type)
				chunk_appendf(out, "/%d", stats[ST_I_PX_CHECK_CODE].u.u32);

			if (stats[ST_I_PX_CHECK_DURATION].type)
				chunk_appendf(out, " in %lums", (long)stats[ST_I_PX_CHECK_DURATION].u.u64);

			chunk_appendf(out, "<div class=tips>%s", field_str(stats, ST_I_PX_CHECK_DESC));

			if (*field_str(stats, ST_I_PX_LAST_CHK)) {
				chunk_appendf(out, ": ");
				chunk_initstr(&src, field_str(stats, ST_I_PX_LAST_CHK));
				chunk_htmlencode(out, &src);
			}
			chunk_appendf(out, "</div></u>");
		}
		else
			chunk_appendf(out, "</td><td>");

		chunk_appendf(out,
		              /* weight / uweight */
		              "</td><td class=ac>%d/%d</td>"
		              /* act, bck */
		              "<td class=ac>%s</td><td class=ac>%s</td>"
		              "",
		              stats[ST_I_PX_WEIGHT].u.u32, stats[ST_I_PX_UWEIGHT].u.u32,
		              stats[ST_I_PX_BCK].u.u32 ? "-" : "Y",
		              stats[ST_I_PX_BCK].u.u32 ? "Y" : "-");

		/* check failures: unique, fatal, down time */
		if (strcmp(field_str(stats, ST_I_PX_STATUS), "MAINT (resolution)") == 0) {
			chunk_appendf(out, "<td class=ac colspan=3>resolution</td>");
		}
		else if (stats[ST_I_PX_CHKFAIL].type) {
			chunk_appendf(out, "<td><u>%lld", (long long)stats[ST_I_PX_CHKFAIL].u.u64);

			if (stats[ST_I_PX_HANAFAIL].type)
				chunk_appendf(out, "/%lld", (long long)stats[ST_I_PX_HANAFAIL].u.u64);

			chunk_appendf(out,
			              "<div class=tips>Failed Health Checks%s</div></u></td>"
			              "<td>%lld</td><td>%s</td>"
			              "",
			              stats[ST_I_PX_HANAFAIL].type ? "/Health Analyses" : "",
			              (long long)stats[ST_I_PX_CHKDOWN].u.u64, human_time(stats[ST_I_PX_DOWNTIME].u.u32, 1));
		}
		else if (strcmp(field_str(stats, ST_I_PX_STATUS), "MAINT") != 0 && field_format(stats, ST_I_PX_TRACKED) == FF_STR) {
			/* tracking a server (hence inherited maint would appear as "MAINT (via...)" */
			chunk_appendf(out,
			              "<td class=ac colspan=3><a class=lfsb href=\"#%s\">via %s</a></td>",
			              field_str(stats, ST_I_PX_TRACKED), field_str(stats, ST_I_PX_TRACKED));
		}
		else
			chunk_appendf(out, "<td colspan=3></td>");

		/* throttle */
		if (stats[ST_I_PX_THROTTLE].type)
			chunk_appendf(out, "<td class=ac>%d %%</td>\n", stats[ST_I_PX_THROTTLE].u.u32);
		else
			chunk_appendf(out, "<td class=ac>-</td>");

		if (flags & STAT_F_SHMODULES) {
			list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
				chunk_appendf(out, "<td>");

				if (stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_SRV) {
					chunk_appendf(out,
					              "<u>%s<div class=tips><table class=det>",
					              mod->name);
					for (j = 0; j < mod->stats_count; ++j) {
						chunk_appendf(out,
						              "<tr><th>%s</th><td>%s</td></tr>",
						              mod->stats[j].desc, field_to_html_str(&stats[ST_I_PX_MAX + i]));
						++i;
					}
					chunk_appendf(out, "</table></div></u>");
				} else {
					i += mod->stats_count;
				}

				chunk_appendf(out, "</td>");
			}
		}

		chunk_appendf(out, "</tr>\n");
	}
	else if (stats[ST_I_PX_TYPE].u.u32 == STATS_TYPE_BE) {
		chunk_appendf(out, "<tr class=\"backend\">");
		if (flags & STAT_F_ADMIN) {
			/* Column sub-heading for Enable or Disable server */
			chunk_appendf(out, "<td></td>");
		}
		chunk_appendf(out,
		              "<td class=ac>"
		              /* name */
		              "%s<a name=\"%s/Backend\"></a>"
		              "<a class=lfsb href=\"#%s/Backend\">Backend</a>"
		              "",
		              (flags & STAT_F_SHLGNDS)?"<u>":"",
		              field_str(stats, ST_I_PX_PXNAME), field_str(stats, ST_I_PX_PXNAME));

		if (flags & STAT_F_SHLGNDS) {
			/* balancing */
			chunk_appendf(out, "<div class=tips>balancing: %s",
			              field_str(stats, ST_I_PX_ALGO));

			/* cookie */
			if (stats[ST_I_PX_COOKIE].type) {
				chunk_appendf(out, ", cookie: '");
				chunk_initstr(&src, field_str(stats, ST_I_PX_COOKIE));
				chunk_htmlencode(out, &src);
				chunk_appendf(out, "'");
			}
			chunk_appendf(out, "</div>");
		}

		chunk_appendf(out,
		              "%s</td>"
		              /* queue : current, max */
		              "<td>%s</td><td>%s</td><td></td>"
		              /* sessions rate : current, max, limit */
		              "<td>%s</td><td>%s</td><td></td>"
		              "",
		              (flags & STAT_F_SHLGNDS)?"</u>":"",
		              U2H(stats[ST_I_PX_QCUR].u.u32), U2H(stats[ST_I_PX_QMAX].u.u32),
		              U2H(stats[ST_I_PX_RATE].u.u32), U2H(stats[ST_I_PX_RATE_MAX].u.u32));

		chunk_appendf(out,
		              /* sessions: current, max, limit, total */
		              "<td>%s</td><td>%s</td><td>%s</td>"
		              "<td><u>%s<div class=tips><table class=det>"
		              "<tr><th>Cum. sessions:</th><td>%s</td></tr>"
		              "",
		              U2H(stats[ST_I_PX_SCUR].u.u32), U2H(stats[ST_I_PX_SMAX].u.u32), U2H(stats[ST_I_PX_SLIM].u.u32),
		              U2H(stats[ST_I_PX_STOT].u.u64),
		              U2H(stats[ST_I_PX_STOT].u.u64));

		/* http response (via hover): 1xx, 2xx, 3xx, 4xx, 5xx, other */
		if (strcmp(field_str(stats, ST_I_PX_MODE), "http") == 0) {
			chunk_appendf(out,
			              "<tr><th>New connections:</th><td>%s</td></tr>"
			              "<tr><th>Reused connections:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>Cum. HTTP requests:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 1xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 2xx responses:</th><td>%s</td></tr>"
			              "<tr><th>&nbsp;&nbsp;Compressed 2xx:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>- HTTP 3xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 4xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- HTTP 5xx responses:</th><td>%s</td></tr>"
			              "<tr><th>- other responses:</th><td>%s</td></tr>"
			              "<tr><th>Cache lookups:</th><td>%s</td></tr>"
			              "<tr><th>Cache hits:</th><td>%s</td><td>(%d%%)</td></tr>"
			              "<tr><th>Failed hdr rewrites:</th><td>%s</td></tr>"
			              "<tr><th>Internal errors:</th><td>%s</td></tr>"
				      "",
			              U2H(stats[ST_I_PX_CONNECT].u.u64),
			              U2H(stats[ST_I_PX_REUSE].u.u64),
			              (stats[ST_I_PX_CONNECT].u.u64 + stats[ST_I_PX_REUSE].u.u64) ?
			              (int)(100 * stats[ST_I_PX_REUSE].u.u64 / (stats[ST_I_PX_CONNECT].u.u64 + stats[ST_I_PX_REUSE].u.u64)) : 0,
			              U2H(stats[ST_I_PX_REQ_TOT].u.u64),
			              U2H(stats[ST_I_PX_HRSP_1XX].u.u64),
			              U2H(stats[ST_I_PX_HRSP_2XX].u.u64),
			              U2H(stats[ST_I_PX_COMP_RSP].u.u64),
			              stats[ST_I_PX_HRSP_2XX].u.u64 ?
			              (int)(100 * stats[ST_I_PX_COMP_RSP].u.u64 / stats[ST_I_PX_HRSP_2XX].u.u64) : 0,
			              U2H(stats[ST_I_PX_HRSP_3XX].u.u64),
			              U2H(stats[ST_I_PX_HRSP_4XX].u.u64),
			              U2H(stats[ST_I_PX_HRSP_5XX].u.u64),
			              U2H(stats[ST_I_PX_HRSP_OTHER].u.u64),
			              U2H(stats[ST_I_PX_CACHE_LOOKUPS].u.u64),
			              U2H(stats[ST_I_PX_CACHE_HITS].u.u64),
			              stats[ST_I_PX_CACHE_LOOKUPS].u.u64 ?
			              (int)(100 * stats[ST_I_PX_CACHE_HITS].u.u64 / stats[ST_I_PX_CACHE_LOOKUPS].u.u64) : 0,
			              U2H(stats[ST_I_PX_WREW].u.u64),
			              U2H(stats[ST_I_PX_EINT].u.u64));
		}
		else if (strcmp(field_str(stats, ST_I_PX_MODE), "spop") == 0) {
			chunk_appendf(out,
			              "<tr><th>New connections:</th><td>%s</td></tr>"
			              "<tr><th>Reused connections:</th><td>%s</td><td>(%d%%)</td></tr>"
				      "",
			              U2H(stats[ST_I_PX_CONNECT].u.u64),
			              U2H(stats[ST_I_PX_REUSE].u.u64),
			              (stats[ST_I_PX_CONNECT].u.u64 + stats[ST_I_PX_REUSE].u.u64) ?
			              (int)(100 * stats[ST_I_PX_REUSE].u.u64 / (stats[ST_I_PX_CONNECT].u.u64 + stats[ST_I_PX_REUSE].u.u64)) : 0);
		}

		chunk_appendf(out, "<tr><th colspan=3>Max / Avg over last 1024 success. conn.</th></tr>");
		chunk_appendf(out, "<tr><th>- Queue time:</th><td>%s / %s</td><td>ms</td></tr>",
			      U2H(stats[ST_I_PX_QT_MAX].u.u32), U2H(stats[ST_I_PX_QTIME].u.u32));
		chunk_appendf(out, "<tr><th>- Connect time:</th><td>%s / %s</td><td>ms</td></tr>",
			      U2H(stats[ST_I_PX_CT_MAX].u.u32), U2H(stats[ST_I_PX_CTIME].u.u32));
		if (strcmp(field_str(stats, ST_I_PX_MODE), "http") == 0)
			chunk_appendf(out, "<tr><th>- Responses time:</th><td>%s / %s</td><td>ms</td></tr>",
				      U2H(stats[ST_I_PX_RT_MAX].u.u32), U2H(stats[ST_I_PX_RTIME].u.u32));
		chunk_appendf(out, "<tr><th>- Total time:</th><td>%s / %s</td><td>ms</td></tr>",
			      U2H(stats[ST_I_PX_TT_MAX].u.u32), U2H(stats[ST_I_PX_TTIME].u.u32));

		chunk_appendf(out,
		              "</table></div></u></td>"
		              /* sessions: lbtot, last */
		              "<td>%s</td><td>%s</td>"
		              /* bytes: in */
		              "<td>%s</td>"
		              "",
		              U2H(stats[ST_I_PX_LBTOT].u.u64),
		              human_time(stats[ST_I_PX_LASTSESS].u.s32, 1),
		              U2H(stats[ST_I_PX_BIN].u.u64));

		chunk_appendf(out,
			      /* bytes:out + compression stats (via hover): comp_in, comp_out, comp_byp */
		              "<td>%s%s<div class=tips><table class=det>"
			      "<tr><th>Response bytes in:</th><td>%s</td></tr>"
			      "<tr><th>Compression in:</th><td>%s</td></tr>"
			      "<tr><th>Compression out:</th><td>%s</td><td>(%d%%)</td></tr>"
			      "<tr><th>Compression bypass:</th><td>%s</td></tr>"
			      "<tr><th>Total bytes saved:</th><td>%s</td><td>(%d%%)</td></tr>"
			      "</table></div>%s</td>",
		              (stats[ST_I_PX_COMP_IN].u.u64 || stats[ST_I_PX_COMP_BYP].u.u64) ? "<u>":"",
		              U2H(stats[ST_I_PX_BOUT].u.u64),
		              U2H(stats[ST_I_PX_BOUT].u.u64),
		              U2H(stats[ST_I_PX_COMP_IN].u.u64),
			      U2H(stats[ST_I_PX_COMP_OUT].u.u64),
			      stats[ST_I_PX_COMP_IN].u.u64 ? (int)(stats[ST_I_PX_COMP_OUT].u.u64 * 100 / stats[ST_I_PX_COMP_IN].u.u64) : 0,
			      U2H(stats[ST_I_PX_COMP_BYP].u.u64),
			      U2H(stats[ST_I_PX_COMP_IN].u.u64 - stats[ST_I_PX_COMP_OUT].u.u64),
			      stats[ST_I_PX_BOUT].u.u64 ? (int)((stats[ST_I_PX_COMP_IN].u.u64 - stats[ST_I_PX_COMP_OUT].u.u64) * 100 / stats[ST_I_PX_BOUT].u.u64) : 0,
		              (stats[ST_I_PX_COMP_IN].u.u64 || stats[ST_I_PX_COMP_BYP].u.u64) ? "</u>":"");

		chunk_appendf(out,
		              /* denied: req, resp */
		              "<td>%s</td><td>%s</td>"
		              /* errors : request, connect */
		              "<td></td><td>%s</td>"
		              /* errors : response */
		              "<td><u>%s<div class=tips>Connection resets during transfers: %lld client, %lld server</div></u></td>"
		              /* warnings: retries, redispatches */
		              "<td>%lld</td><td>%lld</td>"
		              /* backend status: reflect backend status (up/down): we display UP
		               * if the backend has known working servers or if it has no server at
		               * all (eg: for stats). Then we display the total weight, number of
		               * active and backups. */
		              "<td class=ac>%s %s</td><td class=ac>&nbsp;</td><td class=ac>%d/%d</td>"
		              "<td class=ac>%d</td><td class=ac>%d</td>"
		              "",
		              U2H(stats[ST_I_PX_DREQ].u.u64), U2H(stats[ST_I_PX_DRESP].u.u64),
		              U2H(stats[ST_I_PX_ECON].u.u64),
		              U2H(stats[ST_I_PX_ERESP].u.u64),
		              (long long)stats[ST_I_PX_CLI_ABRT].u.u64,
		              (long long)stats[ST_I_PX_SRV_ABRT].u.u64,
		              (long long)stats[ST_I_PX_WRETR].u.u64, (long long)stats[ST_I_PX_WREDIS].u.u64,
		              human_time(stats[ST_I_PX_LASTCHG].u.u32, 1),
		              strcmp(field_str(stats, ST_I_PX_STATUS), "DOWN") ? field_str(stats, ST_I_PX_STATUS) : "<font color=\"red\"><b>DOWN</b></font>",
		              stats[ST_I_PX_WEIGHT].u.u32, stats[ST_I_PX_UWEIGHT].u.u32,
		              stats[ST_I_PX_ACT].u.u32, stats[ST_I_PX_BCK].u.u32);

		chunk_appendf(out,
		              /* rest of backend: nothing, down transitions, total downtime, throttle */
		              "<td class=ac>&nbsp;</td><td>%d</td>"
		              "<td>%s</td>"
		              "<td></td>",
		              stats[ST_I_PX_CHKDOWN].u.u32,
		              stats[ST_I_PX_DOWNTIME].type ? human_time(stats[ST_I_PX_DOWNTIME].u.u32, 1) : "&nbsp;");

		if (flags & STAT_F_SHMODULES) {
			list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
				chunk_appendf(out, "<td>");

				if (stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_BE) {
					chunk_appendf(out,
					              "<u>%s<div class=tips><table class=det>",
					              mod->name);
					for (j = 0; j < mod->stats_count; ++j) {
						chunk_appendf(out,
						              "<tr><th>%s</th><td>%s</td></tr>",
						              mod->stats[j].desc, field_to_html_str(&stats[ST_I_PX_MAX + i]));
						++i;
					}
					chunk_appendf(out, "</table></div></u>");
				} else {
					i += mod->stats_count;
				}

				chunk_appendf(out, "</td>");
			}
		}

		chunk_appendf(out, "</tr>");
	}

	return 1;
}

/* Dumps the HTML table header for proxy <px> to chunk ctx buffer and uses the
 * state from stream connector <sc>. The caller is responsible for clearing
 * chunk ctx buffer if needed.
 */
void stats_dump_html_px_hdr(struct stconn *sc, struct proxy *px)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;
	char scope_txt[STAT_SCOPE_TXT_MAXLEN + sizeof STAT_SCOPE_PATTERN];
	struct stats_module *mod;
	int stats_module_len = 0;

	if (px->cap & PR_CAP_BE && px->srv && (ctx->flags & STAT_F_ADMIN)) {
		/* A form to enable/disable this proxy servers */

		/* scope_txt = search pattern + search query, ctx->scope_len is always <= STAT_SCOPE_TXT_MAXLEN */
		scope_txt[0] = 0;
		if (ctx->scope_len) {
			const char *scope_ptr = stats_scope_ptr(appctx);

			strlcpy2(scope_txt, STAT_SCOPE_PATTERN, sizeof(scope_txt));
			memcpy(scope_txt + strlen(STAT_SCOPE_PATTERN), scope_ptr, ctx->scope_len);
			scope_txt[strlen(STAT_SCOPE_PATTERN) + ctx->scope_len] = 0;
		}

		chunk_appendf(chk,
			      "<form method=\"post\">");
	}

	/* print a new table */
	chunk_appendf(chk,
		      "<table class=\"tbl\" width=\"100%%\">\n"
		      "<tr class=\"titre\">"
		      "<th class=\"pxname\" width=\"10%%\">");

	chunk_appendf(chk,
	              "<a name=\"%s\"></a>%s"
	              "<a class=px href=\"#%s\">%s</a>",
	              px->id,
	              (ctx->flags & STAT_F_SHLGNDS) ? "<u>":"",
	              px->id, px->id);

	if (ctx->flags & STAT_F_SHLGNDS) {
		/* cap, mode, id */
		chunk_appendf(chk, "<div class=tips>cap: %s, mode: %s, id: %d",
		              proxy_cap_str(px->cap), proxy_mode_str(px->mode),
		              px->uuid);
		chunk_appendf(chk, "</div>");
	}

	chunk_appendf(chk,
	              "%s</th>"
	              "<th class=\"%s\" width=\"90%%\">%s</th>"
	              "</tr>\n"
	              "</table>\n"
	              "<table class=\"tbl\" width=\"100%%\">\n"
	              "<tr class=\"titre\">",
	              (ctx->flags & STAT_F_SHLGNDS) ? "</u>":"",
	              px->desc ? "desc" : "empty", px->desc ? px->desc : "");

	if (ctx->flags & STAT_F_ADMIN) {
		/* Column heading for Enable or Disable server */
		if ((px->cap & PR_CAP_BE) && px->srv)
			chunk_appendf(chk,
				      "<th rowspan=2 width=1><input type=\"checkbox\" "
				      "onclick=\"for(c in document.getElementsByClassName('%s-checkbox')) "
				      "document.getElementsByClassName('%s-checkbox').item(c).checked = this.checked\"></th>",
				      px->id,
				      px->id);
		else
			chunk_appendf(chk, "<th rowspan=2></th>");
	}

	chunk_appendf(chk,
	              "<th rowspan=2></th>"
	              "<th colspan=3>Queue</th>"
	              "<th colspan=3>Session rate</th><th colspan=6>Sessions</th>"
	              "<th colspan=2>Bytes</th><th colspan=2>Denied</th>"
	              "<th colspan=3>Errors</th><th colspan=2>Warnings</th>"
	              "<th colspan=9>Server</th>");

	if (ctx->flags & STAT_F_SHMODULES) {
		// calculate the count of module for colspan attribute
		list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
			++stats_module_len;
		}
		chunk_appendf(chk, "<th colspan=%d>Extra modules</th>",
		              stats_module_len);
	}

	chunk_appendf(chk,
	              "</tr>\n"
	              "<tr class=\"titre\">"
	              "<th>Cur</th><th>Max</th><th>Limit</th>"
	              "<th>Cur</th><th>Max</th><th>Limit</th><th>Cur</th><th>Max</th>"
	              "<th>Limit</th><th>Total</th><th>LbTot</th><th>Last</th><th>In</th><th>Out</th>"
	              "<th>Req</th><th>Resp</th><th>Req</th><th>Conn</th>"
	              "<th>Resp</th><th>Retr</th><th>Redis</th>"
	              "<th>Status</th><th>LastChk</th><th>Wght</th><th>Act</th>"
	              "<th>Bck</th><th>Chk</th><th>Dwn</th><th>Dwntme</th>"
	              "<th>Thrtle</th>\n");

	if (ctx->flags & STAT_F_SHMODULES) {
		list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
			chunk_appendf(chk, "<th>%s</th>", mod->name);
		}
	}

	chunk_appendf(chk, "</tr>");
}

/* Dumps the HTML table trailer for proxy <px> to chunk ctx buffer and uses the
 * state from stream connector <sc>. The caller is responsible for clearing
 * chunk ctx buffer if needed.
 */
void stats_dump_html_px_end(struct stconn *sc, struct proxy *px)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;

	chunk_appendf(chk, "</table>");

	if ((px->cap & PR_CAP_BE) && px->srv && (ctx->flags & STAT_F_ADMIN)) {
		/* close the form used to enable/disable this proxy servers */
		chunk_appendf(chk,
			      "Choose the action to perform on the checked servers : "
			      "<select name=action>"
			      "<option value=\"\"></option>"
			      "<option value=\"ready\">Set state to READY</option>"
			      "<option value=\"drain\">Set state to DRAIN</option>"
			      "<option value=\"maint\">Set state to MAINT</option>"
			      "<option value=\"dhlth\">Health: disable checks</option>"
			      "<option value=\"ehlth\">Health: enable checks</option>"
			      "<option value=\"hrunn\">Health: force UP</option>"
			      "<option value=\"hnolb\">Health: force NOLB</option>"
			      "<option value=\"hdown\">Health: force DOWN</option>"
			      "<option value=\"dagent\">Agent: disable checks</option>"
			      "<option value=\"eagent\">Agent: enable checks</option>"
			      "<option value=\"arunn\">Agent: force UP</option>"
			      "<option value=\"adown\">Agent: force DOWN</option>"
			      "<option value=\"shutdown\">Kill Sessions</option>"
			      "</select>"
			      "<input type=\"hidden\" name=\"b\" value=\"#%d\">"
			      "&nbsp;<input type=\"submit\" value=\"Apply\">"
			      "</form>",
			      px->uuid);
	}

	chunk_appendf(chk, "<p>\n");
}

/* Dumps the HTML stats trailer block to <out> buffer. The caller is
 * responsible for clearing it if needed.
 */
void stats_dump_html_end(struct buffer *out)
{
	chunk_appendf(out, "</body></html>\n");
}


static int stats_send_http_headers(struct stconn *sc, struct htx *htx)
{
	struct uri_auth *uri;
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct htx_sl *sl;
	unsigned int flags;

	BUG_ON(!ctx->http_px);
	uri = ctx->http_px->uri_auth;

	flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_ENC|HTX_SL_F_XFER_LEN|HTX_SL_F_CHNK);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), ist("200"), ist("OK"));
	if (!sl)
		goto full;
	sl->info.res.status = 200;

	if (!htx_add_header(htx, ist("Cache-Control"), ist("no-cache")))
		goto full;
	if (ctx->flags & STAT_F_FMT_HTML) {
		if (!htx_add_header(htx, ist("Content-Type"), ist("text/html")))
			goto full;
	}
	else if (ctx->flags & (STAT_F_FMT_JSON|STAT_F_JSON_SCHM)) {
		if (!htx_add_header(htx, ist("Content-Type"), ist("application/json")))
			goto full;
	}
	else {
		if (!htx_add_header(htx, ist("Content-Type"), ist("text/plain")))
			goto full;
	}

	if (uri->refresh > 0 && !(ctx->flags & STAT_F_NO_REFRESH)) {
		const char *refresh = U2A(uri->refresh);
		if (!htx_add_header(htx, ist("Refresh"), ist(refresh)))
			goto full;
	}

	if (ctx->flags & STAT_F_CHUNKED) {
		if (!htx_add_header(htx, ist("Transfer-Encoding"), ist("chunked")))
			goto full;
	}

	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto full;
	return 1;

  full:
	htx_reset(htx);
	applet_set_eos(appctx);
	applet_set_error(appctx);
	return 0;
}

static int stats_send_http_redirect(struct stconn *sc, struct htx *htx)
{
	char scope_txt[STAT_SCOPE_TXT_MAXLEN + sizeof STAT_SCOPE_PATTERN];
	struct uri_auth *uri;
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct htx_sl *sl;
	unsigned int flags;

	BUG_ON(!ctx->http_px);
	uri = ctx->http_px->uri_auth;

	/* scope_txt = search pattern + search query, ctx->scope_len is always <= STAT_SCOPE_TXT_MAXLEN */
	scope_txt[0] = 0;
	if (ctx->scope_len) {
		const char *scope_ptr = stats_scope_ptr(appctx);

		strlcpy2(scope_txt, STAT_SCOPE_PATTERN, sizeof(scope_txt));
		memcpy(scope_txt + strlen(STAT_SCOPE_PATTERN), scope_ptr, ctx->scope_len);
		scope_txt[strlen(STAT_SCOPE_PATTERN) + ctx->scope_len] = 0;
	}

	/* We don't want to land on the posted stats page because a refresh will
	 * repost the data. We don't want this to happen on accident so we redirect
	 * the browse to the stats page with a GET.
	 */
	chunk_printf(&trash, "%s;st=%s%s%s%s",
		     uri->uri_prefix,
		     ((ctx->st_code > STAT_STATUS_INIT) &&
		      (ctx->st_code < STAT_STATUS_SIZE) &&
		      stat_status_codes[ctx->st_code]) ?
		     stat_status_codes[ctx->st_code] :
		     stat_status_codes[STAT_STATUS_UNKN],
		     (ctx->flags & STAT_F_HIDE_DOWN) ? ";up" : "",
		     (ctx->flags & STAT_F_NO_REFRESH) ? ";norefresh" : "",
		     scope_txt);

	flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN|HTX_SL_F_CLEN|HTX_SL_F_BODYLESS);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), ist("303"), ist("See Other"));
	if (!sl)
		goto full;
	sl->info.res.status = 303;

	if (!htx_add_header(htx, ist("Cache-Control"), ist("no-cache")) ||
	    !htx_add_header(htx, ist("Content-Type"), ist("text/plain")) ||
	    !htx_add_header(htx, ist("Content-Length"), ist("0")) ||
	    !htx_add_header(htx, ist("Location"), ist2(trash.area, trash.data)))
		goto full;

	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto full;

	return 1;

  full:
	htx_reset(htx);
	applet_set_eos(appctx);
	applet_set_error(appctx);
	return 0;
}

/* We reached the stats page through a POST request. The appctx is
 * expected to have already been allocated by the caller.
 * Parse the posted data and enable/disable servers if necessary.
 * Returns 1 if request was parsed or zero if it needs more data.
 */
static int stats_process_http_post(struct stconn *sc)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;

	struct proxy *px = NULL;
	struct server *sv = NULL;

	char key[LINESIZE];
	int action = ST_ADM_ACTION_NONE;
	int reprocess = 0;

	int total_servers = 0;
	int altered_servers = 0;

	char *first_param, *cur_param, *next_param, *end_params;
	char *st_cur_param = NULL;
	char *st_next_param = NULL;

	struct buffer *temp = get_trash_chunk();

	struct htx *htx = htxbuf(&appctx->inbuf);
	struct htx_blk *blk;

	/*  we need more data */
	if (!(htx->flags & HTX_FL_EOM)) {
		/* check if we can receive more */
		if (applet_fl_test(appctx, APPCTX_FL_INBLK_FULL)) {
			ctx->st_code = STAT_STATUS_EXCD;
			goto out;
		}
		goto  wait;
	}

	/* The request was fully received. Copy data */
	blk = htx_get_head_blk(htx);
	while (blk) {
		enum htx_blk_type type = htx_get_blk_type(blk);

		if (type == HTX_BLK_TLR || type == HTX_BLK_EOT)
			break;
		if (type == HTX_BLK_DATA) {
			struct ist v = htx_get_blk_value(htx, blk);

			if (!chunk_memcat(temp, v.ptr, v.len)) {
				ctx->st_code = STAT_STATUS_EXCD;
				goto out;
			}
		}
		blk = htx_get_next_blk(htx, blk);
	}

	first_param = temp->area;
	end_params  = temp->area + temp->data;
	cur_param = next_param = end_params;
	*end_params = '\0';

	ctx->st_code = STAT_STATUS_NONE;

	/*
	 * Parse the parameters in reverse order to only store the last value.
	 * From the html form, the backend and the action are at the end.
	 */
	while (cur_param > first_param) {
		char *value;
		int poffset, plen;

		cur_param--;

		if ((*cur_param == '&') || (cur_param == first_param)) {
		reprocess_servers:
			/* Parse the key */
			poffset = (cur_param != first_param ? 1 : 0);
			plen = next_param - cur_param + (cur_param == first_param ? 1 : 0);
			if ((plen > 0) && (plen <= sizeof(key))) {
				strncpy(key, cur_param + poffset, plen);
				key[plen - 1] = '\0';
			} else {
				ctx->st_code = STAT_STATUS_ERRP;
				goto out;
			}

			/* Parse the value */
			value = key;
			while (*value != '\0' && *value != '=') {
				value++;
			}
			if (*value == '=') {
				/* Ok, a value is found, we can mark the end of the key */
				*value++ = '\0';
			}
			if (url_decode(key, 1) < 0 || url_decode(value, 1) < 0)
				break;

			/* Now we can check the key to see what to do */
			if (!px && (strcmp(key, "b") == 0)) {
				if ((px = proxy_be_by_name(value)) == NULL) {
					/* the backend name is unknown or ambiguous (duplicate names) */
					ctx->st_code = STAT_STATUS_ERRP;
					goto out;
				}
			}
			else if (!action && (strcmp(key, "action") == 0)) {
				if (strcmp(value, "ready") == 0) {
					action = ST_ADM_ACTION_READY;
				}
				else if (strcmp(value, "drain") == 0) {
					action = ST_ADM_ACTION_DRAIN;
				}
				else if (strcmp(value, "maint") == 0) {
					action = ST_ADM_ACTION_MAINT;
				}
				else if (strcmp(value, "shutdown") == 0) {
					action = ST_ADM_ACTION_SHUTDOWN;
				}
				else if (strcmp(value, "dhlth") == 0) {
					action = ST_ADM_ACTION_DHLTH;
				}
				else if (strcmp(value, "ehlth") == 0) {
					action = ST_ADM_ACTION_EHLTH;
				}
				else if (strcmp(value, "hrunn") == 0) {
					action = ST_ADM_ACTION_HRUNN;
				}
				else if (strcmp(value, "hnolb") == 0) {
					action = ST_ADM_ACTION_HNOLB;
				}
				else if (strcmp(value, "hdown") == 0) {
					action = ST_ADM_ACTION_HDOWN;
				}
				else if (strcmp(value, "dagent") == 0) {
					action = ST_ADM_ACTION_DAGENT;
				}
				else if (strcmp(value, "eagent") == 0) {
					action = ST_ADM_ACTION_EAGENT;
				}
				else if (strcmp(value, "arunn") == 0) {
					action = ST_ADM_ACTION_ARUNN;
				}
				else if (strcmp(value, "adown") == 0) {
					action = ST_ADM_ACTION_ADOWN;
				}
				/* else these are the old supported methods */
				else if (strcmp(value, "disable") == 0) {
					action = ST_ADM_ACTION_DISABLE;
				}
				else if (strcmp(value, "enable") == 0) {
					action = ST_ADM_ACTION_ENABLE;
				}
				else if (strcmp(value, "stop") == 0) {
					action = ST_ADM_ACTION_STOP;
				}
				else if (strcmp(value, "start") == 0) {
					action = ST_ADM_ACTION_START;
				}
				else {
					ctx->st_code = STAT_STATUS_ERRP;
					goto out;
				}
			}
			else if (strcmp(key, "s") == 0) {
				if (!(px && action)) {
					/*
					 * Indicates that we'll need to reprocess the parameters
					 * as soon as backend and action are known
					 */
					if (!reprocess) {
						st_cur_param  = cur_param;
						st_next_param = next_param;
					}
					reprocess = 1;
				}
				else if ((sv = findserver(px, value)) != NULL) {
					HA_SPIN_LOCK(SERVER_LOCK, &sv->lock);
					switch (action) {
					case ST_ADM_ACTION_DISABLE:
						if (!(sv->cur_admin & SRV_ADMF_FMAINT)) {
							altered_servers++;
							total_servers++;
							srv_set_admin_flag(sv, SRV_ADMF_FMAINT, SRV_ADM_STCHGC_STATS_DISABLE);
						}
						break;
					case ST_ADM_ACTION_ENABLE:
						if (sv->cur_admin & SRV_ADMF_FMAINT) {
							altered_servers++;
							total_servers++;
							srv_clr_admin_flag(sv, SRV_ADMF_FMAINT);
						}
						break;
					case ST_ADM_ACTION_STOP:
						if (!(sv->cur_admin & SRV_ADMF_FDRAIN)) {
							srv_set_admin_flag(sv, SRV_ADMF_FDRAIN, SRV_ADM_STCHGC_STATS_STOP);
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_START:
						if (sv->cur_admin & SRV_ADMF_FDRAIN) {
							srv_clr_admin_flag(sv, SRV_ADMF_FDRAIN);
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_DHLTH:
						if (sv->check.state & CHK_ST_CONFIGURED) {
							sv->check.state &= ~CHK_ST_ENABLED;
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_EHLTH:
						if (sv->check.state & CHK_ST_CONFIGURED) {
							sv->check.state |= CHK_ST_ENABLED;
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_HRUNN:
						if (!(sv->track)) {
							sv->check.health = sv->check.rise + sv->check.fall - 1;
							srv_set_running(sv, SRV_OP_STCHGC_STATS_WEB);
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_HNOLB:
						if (!(sv->track)) {
							sv->check.health = sv->check.rise + sv->check.fall - 1;
							srv_set_stopping(sv, SRV_OP_STCHGC_STATS_WEB);
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_HDOWN:
						if (!(sv->track)) {
							sv->check.health = 0;
							srv_set_stopped(sv, SRV_OP_STCHGC_STATS_WEB);
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_DAGENT:
						if (sv->agent.state & CHK_ST_CONFIGURED) {
							sv->agent.state &= ~CHK_ST_ENABLED;
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_EAGENT:
						if (sv->agent.state & CHK_ST_CONFIGURED) {
							sv->agent.state |= CHK_ST_ENABLED;
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_ARUNN:
						if (sv->agent.state & CHK_ST_ENABLED) {
							sv->agent.health = sv->agent.rise + sv->agent.fall - 1;
							srv_set_running(sv, SRV_OP_STCHGC_STATS_WEB);
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_ADOWN:
						if (sv->agent.state & CHK_ST_ENABLED) {
							sv->agent.health = 0;
							srv_set_stopped(sv, SRV_OP_STCHGC_STATS_WEB);
							altered_servers++;
							total_servers++;
						}
						break;
					case ST_ADM_ACTION_READY:
						srv_adm_set_ready(sv);
						altered_servers++;
						total_servers++;
						break;
					case ST_ADM_ACTION_DRAIN:
						srv_adm_set_drain(sv);
						altered_servers++;
						total_servers++;
						break;
					case ST_ADM_ACTION_MAINT:
						srv_adm_set_maint(sv);
						altered_servers++;
						total_servers++;
						break;
					case ST_ADM_ACTION_SHUTDOWN:
						if (!(px->flags & (PR_FL_DISABLED|PR_FL_STOPPED))) {
							srv_shutdown_streams(sv, SF_ERR_KILLED);
							altered_servers++;
							total_servers++;
						}
						break;
					}
					HA_SPIN_UNLOCK(SERVER_LOCK, &sv->lock);
				} else {
					/* the server name is unknown or ambiguous (duplicate names) */
					total_servers++;
				}
			}
			if (reprocess && px && action) {
				/* Now, we know the backend and the action chosen by the user.
				 * We can safely restart from the first server parameter
				 * to reprocess them
				 */
				cur_param  = st_cur_param;
				next_param = st_next_param;
				reprocess = 0;
				goto reprocess_servers;
			}

			next_param = cur_param;
		}
	}

	if (total_servers == 0) {
		ctx->st_code = STAT_STATUS_NONE;
	}
	else if (altered_servers == 0) {
		ctx->st_code = STAT_STATUS_ERRP;
	}
	else if (altered_servers == total_servers) {
		ctx->st_code = STAT_STATUS_DONE;
	}
	else {
		ctx->st_code = STAT_STATUS_PART;
	}
 out:
	return 1;
 wait:
	ctx->st_code = STAT_STATUS_NONE;
	return 0;
}

/* This I/O handler runs as an applet embedded in a stream connector. It is
 * used to send HTTP stats over a TCP socket. The mechanism is very simple.
 * appctx->st0 contains the operation in progress (dump, done). The handler
 * automatically unregisters itself once transfer is complete.
 */
static void http_stats_io_handler(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct stconn *sc = appctx_sc(appctx);
	struct htx *res_htx = NULL;

	/* only proxy stats are available via http */
	ctx->domain = STATS_DOMAIN_PROXY;

	if (applet_fl_test(appctx, APPCTX_FL_INBLK_ALLOC|APPCTX_FL_OUTBLK_ALLOC|APPCTX_FL_OUTBLK_FULL))
		goto out;

	if (applet_fl_test(appctx, APPCTX_FL_FASTFWD) && se_fl_test(appctx->sedesc, SE_FL_MAY_FASTFWD_PROD))
		goto out;

	if (appctx->st0 != STAT_HTTP_END) {
		if (!appctx_get_buf(appctx, &appctx->inbuf) || htx_is_empty(htxbuf(&appctx->inbuf)))
			goto wait_request;
	}

	if (!appctx_get_buf(appctx, &appctx->outbuf)) {
		goto out;
	}

	res_htx = htx_from_buf(&appctx->outbuf);

	if (unlikely(applet_fl_test(appctx, APPCTX_FL_EOS|APPCTX_FL_ERROR))) {
		appctx->st0 = STAT_HTTP_END;
		goto out;
	}

	/* all states are processed in sequence */
	if (appctx->st0 == STAT_HTTP_HEAD) {
		if (stats_send_http_headers(sc, res_htx)) {
			struct ist meth = htx_sl_req_meth(http_get_stline(htxbuf(&appctx->inbuf)));

			if (find_http_meth(istptr(meth), istlen(meth)) == HTTP_METH_HEAD)
				appctx->st0 = STAT_HTTP_DONE;
			else {
				if (!(global.tune.no_zero_copy_fwd & NO_ZERO_COPY_FWD_APPLET))
					se_fl_set(appctx->sedesc, SE_FL_MAY_FASTFWD_PROD);
				appctx->st0 = STAT_HTTP_DUMP;
			}
		}
	}

	if (appctx->st0 == STAT_HTTP_DUMP) {
		ctx->chunk = b_make(trash.area, appctx->outbuf.size, 0, 0);
		/* adjust buffer size to take htx overhead into account,
		 * make sure to perform this call on an empty buffer
		 */
		ctx->chunk.size = buf_room_for_htx_data(&ctx->chunk);
		if (stats_dump_stat_to_buffer(sc, NULL, res_htx))
			appctx->st0 = STAT_HTTP_DONE;
	}

	if (appctx->st0 == STAT_HTTP_POST) {
		if (stats_process_http_post(sc))
			appctx->st0 = STAT_HTTP_LAST;
	}

	if (appctx->st0 == STAT_HTTP_LAST) {
		if (stats_send_http_redirect(sc, res_htx))
			appctx->st0 = STAT_HTTP_DONE;
	}

	if (appctx->st0 == STAT_HTTP_DONE) {
		/* no more data are expected. If the response buffer is empty,
		 * be sure to add something (EOT block in this case) to have
		 * something to send. It is important to be sure the EOM flags
		 * will be handled by the endpoint.
		 */
		if (htx_is_empty(res_htx)) {
			if (!htx_add_endof(res_htx, HTX_BLK_EOT)) {
				applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
				goto out;
			}
		}
		res_htx->flags |= HTX_FL_EOM;
		applet_set_eoi(appctx);
		se_fl_clr(appctx->sedesc, SE_FL_MAY_FASTFWD_PROD);
		applet_fl_clr(appctx, APPCTX_FL_FASTFWD);
		appctx->st0 = STAT_HTTP_END;
	}

	if (appctx->st0 == STAT_HTTP_END) {
		applet_set_eos(appctx);
		applet_will_consume(appctx);
	}

 out:
	/* we have left the request in the buffer for the case where we
	 * process a POST, and this automatically re-enables activity on
	 * read. It's better to indicate that we want to stop reading when
	 * we're sending, so that we know there's at most one direction
	 * deciding to wake the applet up. It saves it from looping when
	 * emitting large blocks into small TCP windows.
	 */
	if (res_htx)
		htx_to_buf(res_htx, &appctx->outbuf);

	if (appctx->st0 == STAT_HTTP_END) {
		/* eat the whole request */
		b_reset(&appctx->inbuf);
		applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);
		appctx->sedesc->iobuf.flags &= ~IOBUF_FL_FF_BLOCKED;
	}
	else if (applet_fl_test(appctx, APPCTX_FL_OUTBLK_FULL))
		applet_wont_consume(appctx);
	return;

  wait_request:
	/* Wait for the request before starting to deliver the response */
	applet_need_more_data(appctx);
	return;

}

static size_t http_stats_fastfwd(struct appctx *appctx, struct buffer *buf,
                                 size_t count, unsigned int flags)
{
	struct stconn *sc = appctx_sc(appctx);
	struct buffer outbuf;
	size_t ret;

	outbuf = b_make(b_tail(buf), MIN(count, b_contig_space(buf)), 0, 0);
	if (stats_dump_stat_to_buffer(sc, &outbuf, NULL)) {
		se_fl_clr(appctx->sedesc, SE_FL_MAY_FASTFWD_PROD);
		applet_fl_clr(appctx, APPCTX_FL_FASTFWD);
		appctx->st0 = STAT_HTTP_DONE;
	}
	ret = b_data(&outbuf);
	b_add(buf, ret);
	return ret;
}

static void http_stats_release(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	if (ctx->px_st == STAT_PX_ST_SV && ctx->obj2)
		watcher_detach(&ctx->srv_watch);
}

struct applet http_stats_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<STATS>", /* used for logging */
	.fct = http_stats_io_handler,
	.rcv_buf = appctx_htx_rcv_buf,
	.snd_buf = appctx_htx_snd_buf,
	.fastfwd = http_stats_fastfwd,
	.release = http_stats_release,
};
