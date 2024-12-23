/*
 * Functions dedicated to statistics output and the stats socket
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2009 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <import/ebsttree.h>
#include <haproxy/api.h>
#include <haproxy/activity.h>
#include <haproxy/applet.h>
#include <haproxy/base64.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/cli.h>
#include <haproxy/clock.h>
#include <haproxy/compression.h>
#include <haproxy/debug.h>
#include <haproxy/errors.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/map-t.h>
#include <haproxy/pattern-t.h>
#include <haproxy/pipe.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/resolvers.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/stats.h>
#include <haproxy/stats-file.h>
#include <haproxy/stats-html.h>
#include <haproxy/stats-json.h>
#include <haproxy/stats-proxy.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/stress.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/uri_auth-t.h>
#include <haproxy/version.h>

/* Convert stat_col <col> to old-style <name> as name_desc. */
static void stcol2ndesc(struct name_desc *name, const struct stat_col *col)
{
        name->name = col->name;
        name->desc = col->desc;
}


/* status codes available for the stats admin page (strictly 4 chars length) */
const char *stat_status_codes[STAT_STATUS_SIZE] = {
	[STAT_STATUS_DENY] = "DENY",
	[STAT_STATUS_DONE] = "DONE",
	[STAT_STATUS_ERRP] = "ERRP",
	[STAT_STATUS_EXCD] = "EXCD",
	[STAT_STATUS_NONE] = "NONE",
	[STAT_STATUS_PART] = "PART",
	[STAT_STATUS_UNKN] = "UNKN",
	[STAT_STATUS_IVAL] = "IVAL",
};

/* These are the column names for each ST_I_INF_* field position. Please pay attention
 * to always use the exact same name except that the strings for new names must
 * be lower case or CamelCase while the enum entries must be upper case.
 */
const struct name_desc stat_cols_info[ST_I_INF_MAX] = {
	[ST_I_INF_NAME]                           = { .name = "Name",                        .desc = "Product name" },
	[ST_I_INF_VERSION]                        = { .name = "Version",                     .desc = "Product version" },
	[ST_I_INF_RELEASE_DATE]                   = { .name = "Release_date",                .desc = "Date of latest source code update" },
	[ST_I_INF_NBTHREAD]                       = { .name = "Nbthread",                    .desc = "Number of started threads (global.nbthread)" },
	[ST_I_INF_NBPROC]                         = { .name = "Nbproc",                      .desc = "Number of started worker processes (historical, always 1)" },
	[ST_I_INF_PROCESS_NUM]                    = { .name = "Process_num",                 .desc = "Relative worker process number (1)" },
	[ST_I_INF_PID]                            = { .name = "Pid",                         .desc = "This worker process identifier for the system" },
	[ST_I_INF_UPTIME]                         = { .name = "Uptime",                      .desc = "How long ago this worker process was started (days+hours+minutes+seconds)" },
	[ST_I_INF_UPTIME_SEC]                     = { .name = "Uptime_sec",                  .desc = "How long ago this worker process was started (seconds)" },
	[ST_I_INF_START_TIME_SEC]                 = { .name = "Start_time_sec",              .desc = "Start time in seconds" },
	[ST_I_INF_MEMMAX_MB]                      = { .name = "Memmax_MB",                   .desc = "Worker process's hard limit on memory usage in MB (-m on command line)" },
	[ST_I_INF_MEMMAX_BYTES]                   = { .name = "Memmax_bytes",                .desc = "Worker process's hard limit on memory usage in byes (-m on command line)" },
	[ST_I_INF_POOL_ALLOC_MB]                  = { .name = "PoolAlloc_MB",                .desc = "Amount of memory allocated in pools (in MB)" },
	[ST_I_INF_POOL_ALLOC_BYTES]               = { .name = "PoolAlloc_bytes",             .desc = "Amount of memory allocated in pools (in bytes)" },
	[ST_I_INF_POOL_USED_MB]                   = { .name = "PoolUsed_MB",                 .desc = "Amount of pool memory currently used (in MB)" },
	[ST_I_INF_POOL_USED_BYTES]                = { .name = "PoolUsed_bytes",              .desc = "Amount of pool memory currently used (in bytes)" },
	[ST_I_INF_POOL_FAILED]                    = { .name = "PoolFailed",                  .desc = "Number of failed pool allocations since this worker was started" },
	[ST_I_INF_ULIMIT_N]                       = { .name = "Ulimit-n",                    .desc = "Hard limit on the number of per-process file descriptors" },
	[ST_I_INF_MAXSOCK]                        = { .name = "Maxsock",                     .desc = "Hard limit on the number of per-process sockets" },
	[ST_I_INF_MAXCONN]                        = { .name = "Maxconn",                     .desc = "Hard limit on the number of per-process connections (configured or imposed by Ulimit-n)" },
	[ST_I_INF_HARD_MAXCONN]                   = { .name = "Hard_maxconn",                .desc = "Hard limit on the number of per-process connections (imposed by Memmax_MB or Ulimit-n)" },
	[ST_I_INF_CURR_CONN]                      = { .name = "CurrConns",                   .desc = "Current number of connections on this worker process" },
	[ST_I_INF_CUM_CONN]                       = { .name = "CumConns",                    .desc = "Total number of connections on this worker process since started" },
	[ST_I_INF_CUM_REQ]                        = { .name = "CumReq",                      .desc = "Total number of requests on this worker process since started" },
	[ST_I_INF_MAX_SSL_CONNS]                  = { .name = "MaxSslConns",                 .desc = "Hard limit on the number of per-process SSL endpoints (front+back), 0=unlimited" },
	[ST_I_INF_CURR_SSL_CONNS]                 = { .name = "CurrSslConns",                .desc = "Current number of SSL endpoints on this worker process (front+back)" },
	[ST_I_INF_CUM_SSL_CONNS]                  = { .name = "CumSslConns",                 .desc = "Total number of SSL endpoints on this worker process since started (front+back)" },
	[ST_I_INF_MAXPIPES]                       = { .name = "Maxpipes",                    .desc = "Hard limit on the number of pipes for splicing, 0=unlimited" },
	[ST_I_INF_PIPES_USED]                     = { .name = "PipesUsed",                   .desc = "Current number of pipes in use in this worker process" },
	[ST_I_INF_PIPES_FREE]                     = { .name = "PipesFree",                   .desc = "Current number of allocated and available pipes in this worker process" },
	[ST_I_INF_CONN_RATE]                      = { .name = "ConnRate",                    .desc = "Number of front connections created on this worker process over the last second" },
	[ST_I_INF_CONN_RATE_LIMIT]                = { .name = "ConnRateLimit",               .desc = "Hard limit for ConnRate (global.maxconnrate)" },
	[ST_I_INF_MAX_CONN_RATE]                  = { .name = "MaxConnRate",                 .desc = "Highest ConnRate reached on this worker process since started (in connections per second)" },
	[ST_I_INF_SESS_RATE]                      = { .name = "SessRate",                    .desc = "Number of sessions created on this worker process over the last second" },
	[ST_I_INF_SESS_RATE_LIMIT]                = { .name = "SessRateLimit",               .desc = "Hard limit for SessRate (global.maxsessrate)" },
	[ST_I_INF_MAX_SESS_RATE]                  = { .name = "MaxSessRate",                 .desc = "Highest SessRate reached on this worker process since started (in sessions per second)" },
	[ST_I_INF_SSL_RATE]                       = { .name = "SslRate",                     .desc = "Number of SSL connections created on this worker process over the last second" },
	[ST_I_INF_SSL_RATE_LIMIT]                 = { .name = "SslRateLimit",                .desc = "Hard limit for SslRate (global.maxsslrate)" },
	[ST_I_INF_MAX_SSL_RATE]                   = { .name = "MaxSslRate",                  .desc = "Highest SslRate reached on this worker process since started (in connections per second)" },
	[ST_I_INF_SSL_FRONTEND_KEY_RATE]          = { .name = "SslFrontendKeyRate",          .desc = "Number of SSL keys created on frontends in this worker process over the last second" },
	[ST_I_INF_SSL_FRONTEND_MAX_KEY_RATE]      = { .name = "SslFrontendMaxKeyRate",       .desc = "Highest SslFrontendKeyRate reached on this worker process since started (in SSL keys per second)" },
	[ST_I_INF_SSL_FRONTEND_SESSION_REUSE_PCT] = { .name = "SslFrontendSessionReuse_pct", .desc = "Percent of frontend SSL connections which did not require a new key" },
	[ST_I_INF_SSL_BACKEND_KEY_RATE]           = { .name = "SslBackendKeyRate",           .desc = "Number of SSL keys created on backends in this worker process over the last second" },
	[ST_I_INF_SSL_BACKEND_MAX_KEY_RATE]       = { .name = "SslBackendMaxKeyRate",        .desc = "Highest SslBackendKeyRate reached on this worker process since started (in SSL keys per second)" },
	[ST_I_INF_SSL_CACHE_LOOKUPS]              = { .name = "SslCacheLookups",             .desc = "Total number of SSL session ID lookups in the SSL session cache on this worker since started" },
	[ST_I_INF_SSL_CACHE_MISSES]               = { .name = "SslCacheMisses",              .desc = "Total number of SSL session ID lookups that didn't find a session in the SSL session cache on this worker since started" },
	[ST_I_INF_COMPRESS_BPS_IN]                = { .name = "CompressBpsIn",               .desc = "Number of bytes submitted to the HTTP compressor in this worker process over the last second" },
	[ST_I_INF_COMPRESS_BPS_OUT]               = { .name = "CompressBpsOut",              .desc = "Number of bytes emitted by the HTTP compressor in this worker process over the last second" },
	[ST_I_INF_COMPRESS_BPS_RATE_LIM]          = { .name = "CompressBpsRateLim",          .desc = "Limit of CompressBpsOut beyond which HTTP compression is automatically disabled" },
	[ST_I_INF_ZLIB_MEM_USAGE]                 = { .name = "ZlibMemUsage",                .desc = "Amount of memory currently used by HTTP compression on the current worker process (in bytes)" },
	[ST_I_INF_MAX_ZLIB_MEM_USAGE]             = { .name = "MaxZlibMemUsage",             .desc = "Limit on the amount of memory used by HTTP compression above which it is automatically disabled (in bytes, see global.maxzlibmem)" },
	[ST_I_INF_TASKS]                          = { .name = "Tasks",                       .desc = "Total number of tasks in the current worker process (active + sleeping)" },
	[ST_I_INF_RUN_QUEUE]                      = { .name = "Run_queue",                   .desc = "Total number of active tasks+tasklets in the current worker process" },
	[ST_I_INF_IDLE_PCT]                       = { .name = "Idle_pct",                    .desc = "Percentage of last second spent waiting in the current worker thread" },
	[ST_I_INF_NODE]                           = { .name = "node",                        .desc = "Node name (global.node)" },
	[ST_I_INF_DESCRIPTION]                    = { .name = "description",                 .desc = "Node description (global.description)" },
	[ST_I_INF_STOPPING]                       = { .name = "Stopping",                    .desc = "1 if the worker process is currently stopping, otherwise zero" },
	[ST_I_INF_JOBS]                           = { .name = "Jobs",                        .desc = "Current number of active jobs on the current worker process (frontend connections, master connections, listeners)" },
	[ST_I_INF_UNSTOPPABLE_JOBS]               = { .name = "Unstoppable Jobs",            .desc = "Current number of unstoppable jobs on the current worker process (master connections)" },
	[ST_I_INF_LISTENERS]                      = { .name = "Listeners",                   .desc = "Current number of active listeners on the current worker process" },
	[ST_I_INF_ACTIVE_PEERS]                   = { .name = "ActivePeers",                 .desc = "Current number of verified active peers connections on the current worker process" },
	[ST_I_INF_CONNECTED_PEERS]                = { .name = "ConnectedPeers",              .desc = "Current number of peers having passed the connection step on the current worker process" },
	[ST_I_INF_DROPPED_LOGS]                   = { .name = "DroppedLogs",                 .desc = "Total number of dropped logs for current worker process since started" },
	[ST_I_INF_BUSY_POLLING]                   = { .name = "BusyPolling",                 .desc = "1 if busy-polling is currently in use on the worker process, otherwise zero (config.busy-polling)" },
	[ST_I_INF_FAILED_RESOLUTIONS]             = { .name = "FailedResolutions",           .desc = "Total number of failed DNS resolutions in current worker process since started" },
	[ST_I_INF_TOTAL_BYTES_OUT]                = { .name = "TotalBytesOut",               .desc = "Total number of bytes emitted by current worker process since started" },
	[ST_I_INF_TOTAL_SPLICED_BYTES_OUT]        = { .name = "TotalSplicedBytesOut",        .desc = "Total number of bytes emitted by current worker process through a kernel pipe since started" },
	[ST_I_INF_BYTES_OUT_RATE]                 = { .name = "BytesOutRate",                .desc = "Number of bytes emitted by current worker process over the last second" },
	[ST_I_INF_DEBUG_COMMANDS_ISSUED]          = { .name = "DebugCommandsIssued",         .desc = "Number of debug commands issued on this process (anything > 0 is unsafe)" },
	[ST_I_INF_CUM_LOG_MSGS]                   = { .name = "CumRecvLogs",                 .desc = "Total number of log messages received by log-forwarding listeners on this worker process since started" },
	[ST_I_INF_BUILD_INFO]                     = { .name = "Build info",                  .desc = "Build info" },
	[ST_I_INF_TAINTED]                        = { .name = "Tainted",                     .desc = "Experimental features used" },
	[ST_I_INF_WARNINGS]                       = { .name = "TotalWarnings",               .desc = "Total warnings issued" },
	[ST_I_INF_MAXCONN_REACHED]                = { .name = "MaxconnReached",              .desc = "Number of times an accepted connection resulted in Maxconn being reached" },
	[ST_I_INF_BOOTTIME_MS]                    = { .name = "BootTime_ms",                 .desc = "How long ago it took to parse and process the config before being ready (milliseconds)" },
	[ST_I_INF_NICED_TASKS]                    = { .name = "Niced_tasks",                 .desc = "Total number of active tasks+tasklets in the current worker process (Run_queue) that are niced" },
	[ST_I_INF_CURR_STRM]                      = { .name = "CurrStreams",                 .desc = "Current number of streams on this worker process" },
	[ST_I_INF_CUM_STRM]                       = { .name = "CumStreams",                  .desc = "Total number of streams created on this worker process since started" },
	[ST_I_INF_WARN_BLOCKED]                   = { .name = "BlockedTrafficWarnings",      .desc = "Total number of warnings issued about traffic being blocked by too slow a task" },
};

/* one line of info */
THREAD_LOCAL struct field stat_line_info[ST_I_INF_MAX];

/* one line for stats */
THREAD_LOCAL struct field *stat_lines[STATS_DOMAIN_COUNT];

/* Unified storage for statistics from all module
 * TODO merge info stats into it as global statistic domain.
 */
struct name_desc *stat_cols[STATS_DOMAIN_COUNT];
size_t stat_cols_len[STATS_DOMAIN_COUNT];

/* list of all registered stats module */
struct list stats_module_list[STATS_DOMAIN_COUNT] = {
	LIST_HEAD_INIT(stats_module_list[STATS_DOMAIN_PROXY]),
	LIST_HEAD_INIT(stats_module_list[STATS_DOMAIN_RESOLVERS]),
};

THREAD_LOCAL void *trash_counters;

/* Insert <cols> generic stat columns into <st_tree> indexed by their name. */
int generate_stat_tree(struct eb_root *st_tree, const struct stat_col cols[])
{
	const struct stat_col *col;
	struct stcol_node *node;
	size_t len;
	int i;

	for (i = 0; i < ST_I_PX_MAX; ++i) {
		col = &cols[i];

		if (stcol_is_generic(col)) {
			len = strlen(col->name);
			node = malloc(sizeof(struct stcol_node) + len + 1);
			if (!node)
				goto err;

			node->col = col;
			memcpy(node->name.key, col->name, len);
			node->name.key[len] = '\0';

			ebst_insert(st_tree, &node->name);
		}
	}

	return 0;

 err:
	return 1;
}


int stats_putchk(struct appctx *appctx, struct buffer *buf, struct htx *htx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;

	if (htx) {
		if (STRESS_RUN1(!htx_is_empty(htx),
		                b_data(chk) > htx_free_data_space(htx))) {
			applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
			return 0;
		}
		if (!htx_add_data_atonce(htx, ist2(b_orig(chk), b_data(chk)))) {
			applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
			return 0;
		}
		chunk_reset(chk);
	}
	else if (buf) {
		if (STRESS_RUN1(b_data(buf), b_data(chk) > b_room(buf))) {
			se_fl_set(appctx->sedesc, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
			return 0;
		}
		b_putblk(buf, b_head(chk), b_data(chk));
		chunk_reset(chk);
	}
	else {
		if (STRESS_RUN1(applet_putchk_stress(appctx, chk) == -1,
		                applet_putchk(appctx, chk) == -1)) {
			return 0;
		}
	}
	return 1;
}

int stats_is_full(struct appctx *appctx, struct buffer *buf, struct htx *htx)
{
	if (htx) {
		if (STRESS_RUN1(!htx_is_empty(htx), htx_almost_full(htx))) {
			applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
			goto full;
		}
	}
	else if (buf) {
		if (STRESS_RUN1(b_data(buf), buffer_almost_full(buf))) {
			se_fl_set(appctx->sedesc, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
			goto full;
		}
	}
	else {
		if (STRESS_RUN1(b_data(&appctx->outbuf),
		                buffer_almost_full(&appctx->outbuf))) {
			applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
			goto full;
		}
	}
	return 0;
full:
	return 1;
}

const char *stats_scope_ptr(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct htx *htx = htxbuf(&appctx->inbuf);
	struct htx_blk *blk;
	struct ist uri;

	blk = ASSUME_NONNULL(htx_get_head_blk(htx));
	BUG_ON(htx_get_blk_type(blk) != HTX_BLK_REQ_SL);
	uri = htx_sl_req_uri(htx_get_blk_ptr(htx, blk));
	return uri.ptr + ctx->scope_str;
}

/*
 * http_stats_io_handler()
 *     -> stats_dump_stat_to_buffer()     // same as above, but used for CSV or HTML
 *        -> stats_dump_csv_header()      // emits the CSV headers (same as above)
 *        -> stats_dump_json_header()     // emits the JSON headers (same as above)
 *        -> stats_dump_html_head()       // emits the HTML headers
 *        -> stats_dump_html_info()       // emits the equivalent of "show info" at the top
 *        -> stats_dump_proxy_to_buffer() // same as above, valid for CSV and HTML
 *           -> stats_dump_html_px_hdr()
 *           -> stats_dump_fe_line()
 *           -> stats_dump_li_line()
 *           -> stats_dump_sv_line()
 *           -> stats_dump_be_line()
 *           -> stats_dump_html_px_end()
 *        -> stats_dump_html_end()       // emits HTML trailer
 *        -> stats_dump_json_end()       // emits JSON trailer
 */


/* Dumps the stats CSV header to <out> buffer. The caller is responsible for
 * clearing it if needed.
 *
 * NOTE: Some tools happen to rely on the field position instead of its name,
 *       so please only append new fields at the end, never in the middle.
 */
static void stats_dump_csv_header(enum stats_domain domain, struct buffer *out)
{
	int i;

	chunk_appendf(out, "# ");
	if (stat_cols[domain]) {
		for (i = 0; i < stat_cols_len[domain]; ++i) {
			chunk_appendf(out, "%s,", stat_cols[domain][i].name);

			/* print special delimiter on proxy stats to mark end of
			   static fields */
			if (domain == STATS_DOMAIN_PROXY && i + 1 == ST_I_PX_MAX)
				chunk_appendf(out, "-,");
		}
	}

	chunk_appendf(out, "\n");
}

/* Emits a stats field without any surrounding element and properly encoded to
 * resist CSV output. Returns non-zero on success, 0 if the buffer is full.
 */
int stats_emit_raw_data_field(struct buffer *out, const struct field *f)
{
	switch (field_format(f, 0)) {
	case FF_EMPTY: return 1;
	case FF_S32:   return chunk_appendf(out, "%d", f->u.s32);
	case FF_U32:   return chunk_appendf(out, "%u", f->u.u32);
	case FF_S64:   return chunk_appendf(out, "%lld", (long long)f->u.s64);
	case FF_U64:   return chunk_appendf(out, "%llu", (unsigned long long)f->u.u64);
	case FF_FLT:   {
		size_t prev_data = out->data;
		out->data = flt_trim(out->area, prev_data, chunk_appendf(out, "%f", f->u.flt));
		return out->data;
	}
	case FF_STR:   return csv_enc_append(field_str(f, 0), 1, 2, out) != NULL;
	default:       return chunk_appendf(out, "[INCORRECT_FIELD_TYPE_%08x]", f->type);
	}
}

/* Emits a stats field prefixed with its type. No CSV encoding is prepared, the
 * output is supposed to be used on its own line. Returns non-zero on success, 0
 * if the buffer is full.
 */
int stats_emit_typed_data_field(struct buffer *out, const struct field *f)
{
	switch (field_format(f, 0)) {
	case FF_EMPTY: return 1;
	case FF_S32:   return chunk_appendf(out, "s32:%d", f->u.s32);
	case FF_U32:   return chunk_appendf(out, "u32:%u", f->u.u32);
	case FF_S64:   return chunk_appendf(out, "s64:%lld", (long long)f->u.s64);
	case FF_U64:   return chunk_appendf(out, "u64:%llu", (unsigned long long)f->u.u64);
	case FF_FLT:   {
		size_t prev_data = out->data;
		out->data = flt_trim(out->area, prev_data, chunk_appendf(out, "flt:%f", f->u.flt));
		return out->data;
	}
	case FF_STR:   return chunk_appendf(out, "str:%s", field_str(f, 0));
	default:       return chunk_appendf(out, "%08x:?", f->type);
	}
}

/* Emits an encoding of the field type on 3 characters followed by a delimiter.
 * Returns non-zero on success, 0 if the buffer is full.
 */
int stats_emit_field_tags(struct buffer *out, const struct field *f,
			  char delim)
{
	char origin, nature, scope;

	switch (field_origin(f, 0)) {
	case FO_METRIC:  origin = 'M'; break;
	case FO_STATUS:  origin = 'S'; break;
	case FO_KEY:     origin = 'K'; break;
	case FO_CONFIG:  origin = 'C'; break;
	case FO_PRODUCT: origin = 'P'; break;
	default:         origin = '?'; break;
	}

	switch (field_nature(f, 0)) {
	case FN_GAUGE:    nature = 'G'; break;
	case FN_LIMIT:    nature = 'L'; break;
	case FN_MIN:      nature = 'm'; break;
	case FN_MAX:      nature = 'M'; break;
	case FN_RATE:     nature = 'R'; break;
	case FN_COUNTER:  nature = 'C'; break;
	case FN_DURATION: nature = 'D'; break;
	case FN_AGE:      nature = 'A'; break;
	case FN_TIME:     nature = 'T'; break;
	case FN_NAME:     nature = 'N'; break;
	case FN_OUTPUT:   nature = 'O'; break;
	case FN_AVG:      nature = 'a'; break;
	default:          nature = '?'; break;
	}

	switch (field_scope(f, 0)) {
	case FS_PROCESS: scope = 'P'; break;
	case FS_SERVICE: scope = 'S'; break;
	case FS_SYSTEM:  scope = 's'; break;
	case FS_CLUSTER: scope = 'C'; break;
	default:         scope = '?'; break;
	}

	return chunk_appendf(out, "%c%c%c%c", origin, nature, scope, delim);
}

/* Dump all fields from <line> into <out> using CSV format */
static int stats_dump_fields_csv(struct buffer *out,
                                 const struct field *line, size_t stats_count,
                                 struct show_stat_ctx *ctx)
{
	int domain = ctx->domain;
	int i;

	for (i = 0; i < stats_count; ++i) {
		if (!stats_emit_raw_data_field(out, &line[i]))
			return 0;
		if (!chunk_strcat(out, ","))
			return 0;

		/* print special delimiter on proxy stats to mark end of
		   static fields */
		if (domain == STATS_DOMAIN_PROXY && i + 1 == ST_I_PX_MAX) {
			if (!chunk_strcat(out, "-,"))
				return 0;
		}
	}

	chunk_strcat(out, "\n");
	return 1;
}

/* Dump all fields from <line> into <out> using a typed "field:desc:type:value" format */
static int stats_dump_fields_typed(struct buffer *out,
                                   const struct field *line,
                                   size_t stats_count,
                                   struct show_stat_ctx * ctx)
{
	int flags = ctx->flags;
	int domain = ctx->domain;
	int i;

	for (i = 0; i < stats_count; ++i) {
		if (!line[i].type)
			continue;

		switch (domain) {
		case STATS_DOMAIN_PROXY:
			chunk_appendf(out, "%c.%u.%u.%d.%s.%u:",
			              line[ST_I_PX_TYPE].u.u32 == STATS_TYPE_FE ? 'F' :
			              line[ST_I_PX_TYPE].u.u32 == STATS_TYPE_BE ? 'B' :
			              line[ST_I_PX_TYPE].u.u32 == STATS_TYPE_SO ? 'L' :
			              line[ST_I_PX_TYPE].u.u32 == STATS_TYPE_SV ? 'S' :
			              '?',
			              line[ST_I_PX_IID].u.u32, line[ST_I_PX_SID].u.u32,
			              i,
			              stat_cols[domain][i].name,
			              line[ST_I_PX_PID].u.u32);
			break;

		case STATS_DOMAIN_RESOLVERS:
			chunk_appendf(out, "N.%d.%s:", i,
			              stat_cols[domain][i].name);
			break;

		default:
			break;
		}

		if (!stats_emit_field_tags(out, &line[i], ':'))
			return 0;
		if (!stats_emit_typed_data_field(out, &line[i]))
			return 0;

		if (flags & STAT_F_SHOW_FDESC &&
		    !chunk_appendf(out, ":\"%s\"", stat_cols[domain][i].desc)) {
			return 0;
		}

		if (!chunk_strcat(out, "\n"))
			return 0;
	}
	return 1;
}


int stats_dump_one_line(const struct field *line, size_t stats_count,
                        struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;
	int ret;

	if (ctx->flags & STAT_F_FMT_HTML)
		ret = stats_dump_fields_html(chk, line, ctx);
	else if (ctx->flags & STAT_F_FMT_TYPED)
		ret = stats_dump_fields_typed(chk, line, stats_count, ctx);
	else if (ctx->flags & STAT_F_FMT_JSON)
		ret = stats_dump_fields_json(chk, line, stats_count, ctx);
	else if (ctx->flags & STAT_F_FMT_FILE)
		ret = stats_dump_fields_file(chk, line, stats_count, ctx);
	else
		ret = stats_dump_fields_csv(chk, line, stats_count, ctx);

	return ret;
}

/* This function dumps statistics onto the stream connector's read buffer in
 * either CSV or HTML format. It returns 0 if it had to stop writing data and
 * an I/O is needed, 1 if the dump is finished and the stream must be closed,
 * or -1 in case of any error. This function is used by both the CLI and the
 * HTTP handlers.
 */
int stats_dump_stat_to_buffer(struct stconn *sc, struct buffer *buf, struct htx *htx)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	enum stats_domain domain = ctx->domain;
	struct buffer *chk = &ctx->chunk;

	chunk_reset(chk);

	switch (ctx->state) {
	case STAT_STATE_INIT:
		ctx->state = STAT_STATE_HEAD; /* let's start producing data */
		__fallthrough;

	case STAT_STATE_HEAD:
		if (ctx->flags & STAT_F_FMT_HTML)
			stats_dump_html_head(appctx);
		else if (ctx->flags & STAT_F_JSON_SCHM)
			stats_dump_json_schema(chk);
		else if (ctx->flags & STAT_F_FMT_JSON)
			stats_dump_json_header(chk);
		else if (ctx->flags & STAT_F_FMT_FILE)
			stats_dump_file_header(ctx->type, chk);
		else if (!(ctx->flags & STAT_F_FMT_TYPED))
			stats_dump_csv_header(ctx->domain, chk);

		if (!stats_putchk(appctx, buf, htx))
			goto full;

		if (ctx->flags & STAT_F_JSON_SCHM) {
			ctx->state = STAT_STATE_FIN;
			return 1;
		}
		ctx->state = STAT_STATE_INFO;
		__fallthrough;

	case STAT_STATE_INFO:
		if (ctx->flags & STAT_F_FMT_HTML) {
			stats_dump_html_info(sc);
			if (!stats_putchk(appctx, buf, htx))
				goto full;
		}

		if (domain == STATS_DOMAIN_PROXY)
			ctx->obj1 = proxies_list;

		ctx->px_st = STAT_PX_ST_INIT;
		ctx->field = 0;
		ctx->state = STAT_STATE_LIST;
		__fallthrough;

	case STAT_STATE_LIST:
		switch (domain) {
		case STATS_DOMAIN_RESOLVERS:
			if (!stats_dump_resolvers(sc, stat_lines[domain],
			                          stat_cols_len[domain],
			                          &stats_module_list[domain])) {
				return 0;
			}
			break;

		case STATS_DOMAIN_PROXY:
		default:
			/* dump proxies */
			if (!stats_dump_proxies(sc, buf, htx))
				return 0;
			break;
		}

		ctx->state = STAT_STATE_END;
		__fallthrough;

	case STAT_STATE_END:
		if (ctx->flags & (STAT_F_FMT_HTML|STAT_F_FMT_JSON)) {
			if (ctx->flags & STAT_F_FMT_HTML)
				stats_dump_html_end(chk);
			else
				stats_dump_json_end(chk);
			if (!stats_putchk(appctx, buf, htx))
				goto full;
		}

		ctx->state = STAT_STATE_FIN;
		__fallthrough;

	case STAT_STATE_FIN:
		return 1;

	default:
		/* unknown state ! */
		ctx->state = STAT_STATE_FIN;
		return -1;
	}

  full:
	return 0;

}

/* Dump all fields from <info_fields> into <out> using the "show info" format (name: value) */
static int stats_dump_info_fields(struct buffer *out,
                                  const struct field *line,
                                  struct show_stat_ctx *ctx)
{
	int flags = ctx->flags;
	int i;

	for (i = 0; i < ST_I_INF_MAX; i++) {
		if (!field_format(line, i))
			continue;

		if (!chunk_appendf(out, "%s: ", stat_cols_info[i].name))
			return 0;
		if (!stats_emit_raw_data_field(out, &line[i]))
			return 0;
		if ((flags & STAT_F_SHOW_FDESC) && !chunk_appendf(out, ":\"%s\"", stat_cols_info[i].desc))
			return 0;
		if (!chunk_strcat(out, "\n"))
			return 0;
	}
	return 1;
}

/* Dump all fields from <line> into <out> using the "show info typed" format */
static int stats_dump_typed_info_fields(struct buffer *out,
                                        const struct field *line,
                                        struct show_stat_ctx *ctx)
{
	int flags = ctx->flags;
	int i;

	for (i = 0; i < ST_I_INF_MAX; i++) {
		if (!field_format(line, i))
			continue;

		if (!chunk_appendf(out, "%d.%s.%u:", i, stat_cols_info[i].name,
		                   line[ST_I_INF_PROCESS_NUM].u.u32)) {
			return 0;
		}
		if (!stats_emit_field_tags(out, &line[i], ':'))
			return 0;
		if (!stats_emit_typed_data_field(out, &line[i]))
			return 0;
		if ((flags & STAT_F_SHOW_FDESC) && !chunk_appendf(out, ":\"%s\"", stat_cols_info[i].desc))
			return 0;
		if (!chunk_strcat(out, "\n"))
			return 0;
	}
	return 1;
}

/* Fill <info> with HAProxy global info. <info> is preallocated array of length
 * <len>. The length of the array must be ST_I_INF_MAX. If this length is
 * less then this value, the function returns 0, otherwise, it returns 1. Some
 * fields' presence or precision may depend on some of the STAT_F_* flags present
 * in <flags>.
 */
int stats_fill_info(struct field *line, int len, uint flags)
{
	struct buffer *out = get_trash_chunk();
	uint64_t glob_out_bytes, glob_spl_bytes, glob_out_b32, glob_curr_strms, glob_cum_strms;
	uint up_sec, up_usec;
	ullong up;
	ulong boot;
	int thr;

#ifdef USE_OPENSSL
	double ssl_sess_rate = read_freq_ctr_flt(&global.ssl_per_sec);
	double ssl_key_rate  = read_freq_ctr_flt(&global.ssl_fe_keys_per_sec);
	double ssl_reuse = 0;

	if (ssl_key_rate < ssl_sess_rate)
		ssl_reuse = 100.0 * (1.0 - ssl_key_rate / ssl_sess_rate);
#endif

	/* sum certain per-thread totals (mostly byte counts) */
	glob_out_bytes = glob_spl_bytes = glob_out_b32 = glob_curr_strms = glob_cum_strms = 0;
	for (thr = 0; thr < global.nbthread; thr++) {
		glob_out_bytes += HA_ATOMIC_LOAD(&ha_thread_ctx[thr].out_bytes);
		glob_spl_bytes += HA_ATOMIC_LOAD(&ha_thread_ctx[thr].spliced_out_bytes);
		glob_out_b32   += read_freq_ctr(&ha_thread_ctx[thr].out_32bps);
		glob_curr_strms+= HA_ATOMIC_LOAD(&ha_thread_ctx[thr].stream_cnt);
		glob_cum_strms += HA_ATOMIC_LOAD(&ha_thread_ctx[thr].total_streams);
	}
	glob_out_b32 *= 32; // values are 32-byte units

	up = now_ns - start_time_ns;
	up_sec = ns_to_sec(up);
	up_usec = (up / 1000U) % 1000000U;

	boot = tv_ms_remain(&start_date, &ready_date);

	if (len < ST_I_INF_MAX)
		return 0;

	chunk_reset(out);
	memset(line, 0, sizeof(*line) * len);

	line[ST_I_INF_NAME]                           = mkf_str(FO_PRODUCT|FN_OUTPUT|FS_SERVICE, PRODUCT_NAME);
	line[ST_I_INF_VERSION]                        = mkf_str(FO_PRODUCT|FN_OUTPUT|FS_SERVICE, haproxy_version);
	line[ST_I_INF_BUILD_INFO]                     = mkf_str(FO_PRODUCT|FN_OUTPUT|FS_SERVICE, haproxy_version);
	line[ST_I_INF_RELEASE_DATE]                   = mkf_str(FO_PRODUCT|FN_OUTPUT|FS_SERVICE, haproxy_date);

	line[ST_I_INF_NBTHREAD]                       = mkf_u32(FO_CONFIG|FS_SERVICE, global.nbthread);
	line[ST_I_INF_NBPROC]                         = mkf_u32(FO_CONFIG|FS_SERVICE, 1);
	line[ST_I_INF_PROCESS_NUM]                    = mkf_u32(FO_KEY, 1);
	line[ST_I_INF_PID]                            = mkf_u32(FO_STATUS, pid);

	line[ST_I_INF_UPTIME]                         = mkf_str(FN_DURATION, chunk_newstr(out));
	chunk_appendf(out, "%ud %uh%02um%02us", up_sec / 86400, (up_sec % 86400) / 3600, (up_sec % 3600) / 60, (up_sec % 60));

	line[ST_I_INF_UPTIME_SEC]                     = (flags & STAT_F_USE_FLOAT) ? mkf_flt(FN_DURATION, up_sec + up_usec / 1000000.0) : mkf_u32(FN_DURATION, up_sec);
	line[ST_I_INF_START_TIME_SEC]                 = (flags & STAT_F_USE_FLOAT) ? mkf_flt(FN_DURATION, start_date.tv_sec + start_date.tv_usec / 1000000.0) : mkf_u32(FN_DURATION, start_date.tv_sec);
	line[ST_I_INF_MEMMAX_MB]                      = mkf_u32(FO_CONFIG|FN_LIMIT, global.rlimit_memmax);
	line[ST_I_INF_MEMMAX_BYTES]                   = mkf_u32(FO_CONFIG|FN_LIMIT, global.rlimit_memmax * 1048576L);
	line[ST_I_INF_POOL_ALLOC_MB]                  = mkf_u32(0, (unsigned)(pool_total_allocated() / 1048576L));
	line[ST_I_INF_POOL_ALLOC_BYTES]               = mkf_u64(0, pool_total_allocated());
	line[ST_I_INF_POOL_USED_MB]                   = mkf_u32(0, (unsigned)(pool_total_used() / 1048576L));
	line[ST_I_INF_POOL_USED_BYTES]                = mkf_u64(0, pool_total_used());
	line[ST_I_INF_POOL_FAILED]                    = mkf_u32(FN_COUNTER, pool_total_failures());
	line[ST_I_INF_ULIMIT_N]                       = mkf_u32(FO_CONFIG|FN_LIMIT, global.rlimit_nofile);
	line[ST_I_INF_MAXSOCK]                        = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxsock);
	line[ST_I_INF_MAXCONN]                        = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxconn);
	line[ST_I_INF_HARD_MAXCONN]                   = mkf_u32(FO_CONFIG|FN_LIMIT, global.hardmaxconn);
	line[ST_I_INF_CURR_CONN]                      = mkf_u32(0, actconn);
	line[ST_I_INF_CUM_CONN]                       = mkf_u32(FN_COUNTER, totalconn);
	line[ST_I_INF_CUM_REQ]                        = mkf_u32(FN_COUNTER, global.req_count);
#ifdef USE_OPENSSL
	line[ST_I_INF_MAX_SSL_CONNS]                  = mkf_u32(FN_MAX, global.maxsslconn);
	line[ST_I_INF_CURR_SSL_CONNS]                 = mkf_u32(0, global.sslconns);
	line[ST_I_INF_CUM_SSL_CONNS]                  = mkf_u32(FN_COUNTER, global.totalsslconns);
#endif
	line[ST_I_INF_MAXPIPES]                       = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxpipes);
	line[ST_I_INF_PIPES_USED]                     = mkf_u32(0, pipes_used);
	line[ST_I_INF_PIPES_FREE]                     = mkf_u32(0, pipes_free);
	line[ST_I_INF_CONN_RATE]                      = (flags & STAT_F_USE_FLOAT) ? mkf_flt(FN_RATE, read_freq_ctr_flt(&global.conn_per_sec)) : mkf_u32(FN_RATE, read_freq_ctr(&global.conn_per_sec));
	line[ST_I_INF_CONN_RATE_LIMIT]                = mkf_u32(FO_CONFIG|FN_LIMIT, global.cps_lim);
	line[ST_I_INF_MAX_CONN_RATE]                  = mkf_u32(FN_MAX, global.cps_max);
	line[ST_I_INF_SESS_RATE]                      = (flags & STAT_F_USE_FLOAT) ? mkf_flt(FN_RATE, read_freq_ctr_flt(&global.sess_per_sec)) : mkf_u32(FN_RATE, read_freq_ctr(&global.sess_per_sec));
	line[ST_I_INF_SESS_RATE_LIMIT]                = mkf_u32(FO_CONFIG|FN_LIMIT, global.sps_lim);
	line[ST_I_INF_MAX_SESS_RATE]                  = mkf_u32(FN_RATE, global.sps_max);

#ifdef USE_OPENSSL
	line[ST_I_INF_SSL_RATE]                       = (flags & STAT_F_USE_FLOAT) ? mkf_flt(FN_RATE, ssl_sess_rate) : mkf_u32(FN_RATE, ssl_sess_rate);
	line[ST_I_INF_SSL_RATE_LIMIT]                 = mkf_u32(FO_CONFIG|FN_LIMIT, global.ssl_lim);
	line[ST_I_INF_MAX_SSL_RATE]                   = mkf_u32(FN_MAX, global.ssl_max);
	line[ST_I_INF_SSL_FRONTEND_KEY_RATE]          = (flags & STAT_F_USE_FLOAT) ? mkf_flt(FN_RATE, ssl_key_rate) : mkf_u32(0, ssl_key_rate);
	line[ST_I_INF_SSL_FRONTEND_MAX_KEY_RATE]      = mkf_u32(FN_MAX, global.ssl_fe_keys_max);
	line[ST_I_INF_SSL_FRONTEND_SESSION_REUSE_PCT] = (flags & STAT_F_USE_FLOAT) ? mkf_flt(FN_RATE, ssl_reuse) : mkf_u32(0, ssl_reuse);
	line[ST_I_INF_SSL_BACKEND_KEY_RATE]           = (flags & STAT_F_USE_FLOAT) ? mkf_flt(FN_RATE, read_freq_ctr_flt(&global.ssl_be_keys_per_sec)) : mkf_u32(FN_RATE, read_freq_ctr(&global.ssl_be_keys_per_sec));
	line[ST_I_INF_SSL_BACKEND_MAX_KEY_RATE]       = mkf_u32(FN_MAX, global.ssl_be_keys_max);
	line[ST_I_INF_SSL_CACHE_LOOKUPS]              = mkf_u32(FN_COUNTER, global.shctx_lookups);
	line[ST_I_INF_SSL_CACHE_MISSES]               = mkf_u32(FN_COUNTER, global.shctx_misses);
#endif
	line[ST_I_INF_COMPRESS_BPS_IN]                = (flags & STAT_F_USE_FLOAT) ? mkf_flt(FN_RATE, read_freq_ctr_flt(&global.comp_bps_in)) : mkf_u32(FN_RATE, read_freq_ctr(&global.comp_bps_in));
	line[ST_I_INF_COMPRESS_BPS_OUT]               = (flags & STAT_F_USE_FLOAT) ? mkf_flt(FN_RATE, read_freq_ctr_flt(&global.comp_bps_out)) : mkf_u32(FN_RATE, read_freq_ctr(&global.comp_bps_out));
	line[ST_I_INF_COMPRESS_BPS_RATE_LIM]          = mkf_u32(FO_CONFIG|FN_LIMIT, global.comp_rate_lim);
#ifdef USE_ZLIB
	line[ST_I_INF_ZLIB_MEM_USAGE]                 = mkf_u32(0, zlib_used_memory);
	line[ST_I_INF_MAX_ZLIB_MEM_USAGE]             = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxzlibmem);
#endif
	line[ST_I_INF_TASKS]                          = mkf_u32(0, total_allocated_tasks());
	line[ST_I_INF_RUN_QUEUE]                      = mkf_u32(0, total_run_queues());
	line[ST_I_INF_IDLE_PCT]                       = mkf_u32(FN_AVG, clock_report_idle());
	line[ST_I_INF_NODE]                           = mkf_str(FO_CONFIG|FN_OUTPUT|FS_SERVICE, global.node);
	if (global.desc)
		line[ST_I_INF_DESCRIPTION]            = mkf_str(FO_CONFIG|FN_OUTPUT|FS_SERVICE, global.desc);
	line[ST_I_INF_STOPPING]                       = mkf_u32(0, stopping);
	line[ST_I_INF_JOBS]                           = mkf_u32(0, jobs);
	line[ST_I_INF_UNSTOPPABLE_JOBS]               = mkf_u32(0, unstoppable_jobs);
	line[ST_I_INF_LISTENERS]                      = mkf_u32(0, listeners);
	line[ST_I_INF_ACTIVE_PEERS]                   = mkf_u32(0, active_peers);
	line[ST_I_INF_CONNECTED_PEERS]                = mkf_u32(0, connected_peers);
	line[ST_I_INF_DROPPED_LOGS]                   = mkf_u32(0, dropped_logs);
	line[ST_I_INF_BUSY_POLLING]                   = mkf_u32(0, !!(global.tune.options & GTUNE_BUSY_POLLING));
	line[ST_I_INF_FAILED_RESOLUTIONS]             = mkf_u32(0, resolv_failed_resolutions);
	line[ST_I_INF_TOTAL_BYTES_OUT]                = mkf_u64(0, glob_out_bytes);
	line[ST_I_INF_TOTAL_SPLICED_BYTES_OUT]        = mkf_u64(0, glob_spl_bytes);
	line[ST_I_INF_BYTES_OUT_RATE]                 = mkf_u64(FN_RATE, glob_out_b32);
	line[ST_I_INF_DEBUG_COMMANDS_ISSUED]          = mkf_u32(0, debug_commands_issued);
	line[ST_I_INF_CUM_LOG_MSGS]                   = mkf_u32(FN_COUNTER, cum_log_messages);

	line[ST_I_INF_TAINTED]                        = mkf_str(FO_STATUS, chunk_newstr(out));
	chunk_appendf(out, "%#x", get_tainted());
	line[ST_I_INF_WARNINGS]                       = mkf_u32(FN_COUNTER, HA_ATOMIC_LOAD(&tot_warnings));
	line[ST_I_INF_MAXCONN_REACHED]                = mkf_u32(FN_COUNTER, HA_ATOMIC_LOAD(&maxconn_reached));
	line[ST_I_INF_BOOTTIME_MS]                    = mkf_u32(FN_DURATION, boot);
	line[ST_I_INF_NICED_TASKS]                    = mkf_u32(0, total_niced_running_tasks());
	line[ST_I_INF_CURR_STRM]                      = mkf_u64(0, glob_curr_strms);
	line[ST_I_INF_CUM_STRM]                       = mkf_u64(0, glob_cum_strms);
	line[ST_I_INF_WARN_BLOCKED]                   = mkf_u32(0, warn_blocked_issued);

	return 1;
}

/* This function dumps information onto the stream connector's read buffer.
 * It returns 0 as long as it does not complete, non-zero upon completion.
 * No state is used.
 */
static int stats_dump_info_to_buffer(struct stconn *sc)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;
	int ret;
	int current_field;

	if (!stats_fill_info(stat_line_info, ST_I_INF_MAX, ctx->flags))
		return 0;

	chunk_reset(chk);
more:
	current_field = ctx->field;

	if (ctx->flags & STAT_F_FMT_TYPED)
		ret = stats_dump_typed_info_fields(chk, stat_line_info, ctx);
	else if (ctx->flags & STAT_F_FMT_JSON)
		ret = stats_dump_json_info_fields(chk, stat_line_info, ctx);
	else
		ret = stats_dump_info_fields(chk, stat_line_info, ctx);

	if (applet_putchk(appctx, chk) == -1) {
		/* restore previous field */
		ctx->field = current_field;
		return 0;
	}
	if (ret && ctx->field) {
		/* partial dump */
		goto more;
	}
	ctx->field = 0;
	return 1;
}

static int cli_parse_clear_counters(char **args, char *payload, struct appctx *appctx, void *private)
{
	int clrall = 0;

	if (strcmp(args[2], "all") == 0)
		clrall = 1;

	/* check permissions */
	if (!cli_has_level(appctx, ACCESS_LVL_OPER) ||
	    (clrall && !cli_has_level(appctx, ACCESS_LVL_ADMIN)))
		return 1;

	global.cps_max = 0;
	global.sps_max = 0;
	global.ssl_max = 0;
	global.ssl_fe_keys_max = 0;
	global.ssl_be_keys_max = 0;

	proxy_stats_clear_counters(clrall, &stats_module_list[STATS_DOMAIN_PROXY]);

	resolv_stats_clear_counters(clrall, &stats_module_list[STATS_DOMAIN_RESOLVERS]);

	memset(activity, 0, sizeof(activity));
	return 1;
}


static int cli_parse_show_info(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_stat_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int arg = 2;

	ctx->scope_str = 0;
	ctx->scope_len = 0;
	ctx->flags = 0;
	ctx->field = 0; /* explicit default value */

	while (*args[arg]) {
		if (strcmp(args[arg], "typed") == 0)
			ctx->flags = (ctx->flags & ~STAT_F_FMT_MASK) | STAT_F_FMT_TYPED;
		else if (strcmp(args[arg], "json") == 0)
			ctx->flags = (ctx->flags & ~STAT_F_FMT_MASK) | STAT_F_FMT_JSON;
		else if (strcmp(args[arg], "desc") == 0)
			ctx->flags |= STAT_F_SHOW_FDESC;
		else if (strcmp(args[arg], "float") == 0)
			ctx->flags |= STAT_F_USE_FLOAT;
		arg++;
	}
	return 0;
}


static int cli_parse_show_stat(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_stat_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int arg = 2;

	ctx->scope_str = 0;
	ctx->scope_len = 0;
	ctx->http_px = NULL; // not under http context
	ctx->flags = STAT_F_SHNODE | STAT_F_SHDESC;
	watcher_init(&ctx->srv_watch, &ctx->obj2, offsetof(struct server, watcher_list));

	if ((strm_li(appctx_strm(appctx))->bind_conf->level & ACCESS_LVL_MASK) >= ACCESS_LVL_OPER)
		ctx->flags |= STAT_F_SHLGNDS;

	/* proxy is the default domain */
	ctx->domain = STATS_DOMAIN_PROXY;
	if (strcmp(args[arg], "domain") == 0) {
		++args;

		if (strcmp(args[arg], "proxy") == 0) {
			++args;
		} else if (strcmp(args[arg], "resolvers") == 0) {
			ctx->domain = STATS_DOMAIN_RESOLVERS;
			++args;
		} else {
			return cli_err(appctx, "Invalid statistics domain.\n");
		}
	}

	if (ctx->domain == STATS_DOMAIN_PROXY
	    && *args[arg] && *args[arg+1] && *args[arg+2]) {
		struct proxy *px;

		px = proxy_find_by_name(args[arg], 0, 0);
		if (px)
			ctx->iid = px->uuid;
		else
			ctx->iid = atoi(args[arg]);

		if (!ctx->iid)
			return cli_err(appctx, "No such proxy.\n");

		ctx->flags |= STAT_F_BOUND;
		ctx->type = atoi(args[arg+1]);
		ctx->sid = atoi(args[arg+2]);
		arg += 3;
	}

	while (*args[arg]) {
		if (strcmp(args[arg], "typed") == 0)
			ctx->flags = (ctx->flags & ~STAT_F_FMT_MASK) | STAT_F_FMT_TYPED;
		else if (strcmp(args[arg], "json") == 0)
			ctx->flags = (ctx->flags & ~STAT_F_FMT_MASK) | STAT_F_FMT_JSON;
		else if (strcmp(args[arg], "desc") == 0)
			ctx->flags |= STAT_F_SHOW_FDESC;
		else if (strcmp(args[arg], "no-maint") == 0)
			ctx->flags |= STAT_F_HIDE_MAINT;
		else if (strcmp(args[arg], "up") == 0)
			ctx->flags |= STAT_F_HIDE_DOWN;
		arg++;
	}

	return 0;
}

static int cli_parse_show_schema_json(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_stat_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	/* ctx is allocated, nothing else to do */
	return 0;
}

static int cli_io_handler_dump_info(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	ctx->chunk = b_make(trash.area, trash.size, 0, 0);
	return stats_dump_info_to_buffer(appctx_sc(appctx));
}

/* This I/O handler runs as an applet embedded in a stream connector. It is
 * used to send raw stats over a socket.
 */
static int cli_io_handler_dump_stat(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	ctx->chunk = b_make(trash.area, trash.size, 0, 0);
	return stats_dump_stat_to_buffer(appctx_sc(appctx), NULL, NULL);
}

static void cli_io_handler_release_stat(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	if (ctx->px_st == STAT_PX_ST_SV && ctx->obj2)
		watcher_detach(&ctx->srv_watch);
}

static int cli_io_handler_dump_json_schema(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	ctx->chunk = b_make(trash.area, trash.size, 0, 0);
	return stats_dump_json_schema_to_buffer(appctx);
}

static int cli_parse_dump_stat_file(char **args, char *payload,
                                    struct appctx *appctx, void *private)
{
	struct show_stat_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	ctx->chunk = b_make(trash.area, trash.size, 0, 0);
	ctx->domain = STATS_DOMAIN_PROXY;
	ctx->flags |= STAT_F_FMT_FILE;
	watcher_init(&ctx->srv_watch, &ctx->obj2, offsetof(struct server, watcher_list));

	return 0;
}

/* Returns 1 on completion else 0. */
static int cli_io_handler_dump_stat_file(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	int ret;

	/* Frontend and backend sides are outputted separately on stats-file.
	 * As such, use STAT_F_BOUND to restrict proxies looping over frontend
	 * side first before first stats_dump_stat_to_buffer(). A second
	 * iteration is conducted for backend side after.
	 */
	ctx->flags |= STAT_F_BOUND;

	if (!(ctx->type & (1 << STATS_TYPE_BE))) {
		/* Restrict to frontend side. */
		ctx->type = (1 << STATS_TYPE_FE) | (1 << STATS_TYPE_SO);
		ctx->iid = ctx->sid = -1;

		ret = stats_dump_stat_to_buffer(appctx_sc(appctx), NULL, NULL);
		if (!ret)
			return 0;

		chunk_strcat(&ctx->chunk, "\n");
		if (!stats_putchk(appctx, NULL, NULL))
			return 0;

		/* Switch to backend side. */
		ctx->state = STAT_STATE_INIT;
		ctx->type = (1 << STATS_TYPE_BE) | (1 << STATS_TYPE_SV);
	}

	return stats_dump_stat_to_buffer(appctx_sc(appctx), NULL, NULL);
}

static void cli_io_handler_release_dump_stat_file(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	if (ctx->px_st == STAT_PX_ST_SV && ctx->obj2)
		watcher_detach(&ctx->srv_watch);
}

int stats_allocate_proxy_counters_internal(struct extra_counters **counters,
                                           int type, int px_cap)
{
	struct stats_module *mod;

	EXTRA_COUNTERS_REGISTER(counters, type, alloc_failed);

	list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		if (!(stats_px_get_cap(mod->domain_flags) & px_cap))
			continue;

		EXTRA_COUNTERS_ADD(mod, *counters, mod->counters, mod->counters_size);
	}

	EXTRA_COUNTERS_ALLOC(*counters, alloc_failed);

	list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		if (!(stats_px_get_cap(mod->domain_flags) & px_cap))
			continue;

		EXTRA_COUNTERS_INIT(*counters, mod, mod->counters, mod->counters_size);
	}

	return 1;

  alloc_failed:
	return 0;
}

/* Initialize and allocate all extra counters for a proxy and its attached
 * servers/listeners with all already registered stats module
 */
int stats_allocate_proxy_counters(struct proxy *px)
{
	struct server *sv;
	struct listener *li;

	if (px->cap & PR_CAP_FE) {
		if (!stats_allocate_proxy_counters_internal(&px->extra_counters_fe,
		                                            COUNTERS_FE,
		                                            STATS_PX_CAP_FE)) {
			return 0;
		}
	}

	if (px->cap & PR_CAP_BE) {
		if (!stats_allocate_proxy_counters_internal(&px->extra_counters_be,
		                                            COUNTERS_BE,
		                                            STATS_PX_CAP_BE)) {
			return 0;
		}
	}

	for (sv = px->srv; sv; sv = sv->next) {
		if (!stats_allocate_proxy_counters_internal(&sv->extra_counters,
		                                            COUNTERS_SV,
		                                            STATS_PX_CAP_SRV)) {
			return 0;
		}
	}

	list_for_each_entry(li, &px->conf.listeners, by_fe) {
		if (!stats_allocate_proxy_counters_internal(&li->extra_counters,
		                                            COUNTERS_LI,
		                                            STATS_PX_CAP_LI)) {
			return 0;
		}
	}

	return 1;
}

void stats_register_module(struct stats_module *m)
{
	const uint8_t domain = stats_get_domain(m->domain_flags);

	LIST_APPEND(&stats_module_list[domain], &m->list);
	stat_cols_len[domain] += m->stats_count;
}


static int allocate_stats_px_postcheck(void)
{
	struct stats_module *mod;
	size_t i = ST_I_PX_MAX, offset;
	int err_code = 0;
	struct proxy *px;

	stat_cols_len[STATS_DOMAIN_PROXY] += ST_I_PX_MAX;

	stat_cols[STATS_DOMAIN_PROXY] = malloc(stat_cols_len[STATS_DOMAIN_PROXY] * sizeof(struct name_desc));
	if (!stat_cols[STATS_DOMAIN_PROXY]) {
		ha_alert("stats: cannot allocate all fields for proxy statistics\n");
		err_code |= ERR_ALERT | ERR_FATAL;
		return err_code;
	}

	for (i = 0; i < ST_I_PX_MAX; ++i)
		stcol2ndesc(&stat_cols[STATS_DOMAIN_PROXY][i], &stat_cols_px[i]);

	list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		for (offset = i, i = 0; i < mod->stats_count; ++i) {
			stcol2ndesc(&stat_cols[STATS_DOMAIN_PROXY][offset + i],
			            &mod->stats[i]);
		}
		i += offset;
	}

	for (px = proxies_list; px; px = px->next) {
		if (!stats_allocate_proxy_counters(px)) {
			ha_alert("stats: cannot allocate all counters for proxy statistics\n");
			err_code |= ERR_ALERT | ERR_FATAL;
			return err_code;
		}
	}

	/* wait per-thread alloc to perform corresponding stat_lines allocation */

	return err_code;
}

REGISTER_CONFIG_POSTPARSER("allocate-stats-px", allocate_stats_px_postcheck);

static int allocate_stats_rslv_postcheck(void)
{
	struct stats_module *mod;
	size_t i = 0, offset;
	int err_code = 0;

	stat_cols[STATS_DOMAIN_RESOLVERS] = malloc(stat_cols_len[STATS_DOMAIN_RESOLVERS] * sizeof(struct name_desc));
	if (!stat_cols[STATS_DOMAIN_RESOLVERS]) {
		ha_alert("stats: cannot allocate all fields for resolver statistics\n");
		err_code |= ERR_ALERT | ERR_FATAL;
		return err_code;
	}

	list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_RESOLVERS], list) {
		for (offset = i, i = 0; i < mod->stats_count; ++i) {
			stcol2ndesc(&stat_cols[STATS_DOMAIN_RESOLVERS][offset + i],
			            &mod->stats[i]);
		}
		i += offset;
	}

	if (!resolv_allocate_counters(&stats_module_list[STATS_DOMAIN_RESOLVERS])) {
		ha_alert("stats: cannot allocate all counters for resolver statistics\n");
		err_code |= ERR_ALERT | ERR_FATAL;
		return err_code;
	}

	/* wait per-thread alloc to perform corresponding stat_lines allocation */

	return err_code;
}

REGISTER_CONFIG_POSTPARSER("allocate-stats-resolver", allocate_stats_rslv_postcheck);

static int allocate_stat_lines_per_thread(void)
{
	int domains[] = { STATS_DOMAIN_PROXY, STATS_DOMAIN_RESOLVERS }, i;

	for (i = 0; i < STATS_DOMAIN_COUNT; ++i) {
		const int domain = domains[i];

		stat_lines[domain] = malloc(stat_cols_len[domain] * sizeof(struct field));
		if (!stat_lines[domain])
			return 0;
	}
	return 1;
}

REGISTER_PER_THREAD_ALLOC(allocate_stat_lines_per_thread);

static int allocate_trash_counters(void)
{
	struct stats_module *mod;
	int domains[] = { STATS_DOMAIN_PROXY, STATS_DOMAIN_RESOLVERS }, i;
	size_t max_counters_size = 0;

	/* calculate the greatest counters used by any stats modules */
	for (i = 0; i < STATS_DOMAIN_COUNT; ++i) {
		list_for_each_entry(mod, &stats_module_list[domains[i]], list) {
			max_counters_size = mod->counters_size > max_counters_size ?
			                    mod->counters_size : max_counters_size;
		}
	}

	/* allocate the trash with the size of the greatest counters */
	if (max_counters_size) {
		trash_counters = malloc(max_counters_size);
		if (!trash_counters) {
			ha_alert("stats: cannot allocate trash counters for statistics\n");
			return 0;
		}
	}

	return 1;
}

REGISTER_PER_THREAD_ALLOC(allocate_trash_counters);

static void deinit_stat_lines_per_thread(void)
{
	int domains[] = { STATS_DOMAIN_PROXY, STATS_DOMAIN_RESOLVERS }, i;

	for (i = 0; i < STATS_DOMAIN_COUNT; ++i) {
		const int domain = domains[i];

		ha_free(&stat_lines[domain]);
	}
}


REGISTER_PER_THREAD_FREE(deinit_stat_lines_per_thread);

static void deinit_stats(void)
{
	int domains[] = { STATS_DOMAIN_PROXY, STATS_DOMAIN_RESOLVERS }, i;

	for (i = 0; i < STATS_DOMAIN_COUNT; ++i) {
		const int domain = domains[i];

		if (stat_cols[domain])
			free(stat_cols[domain]);
	}
}

REGISTER_POST_DEINIT(deinit_stats);

static void free_trash_counters(void)
{
	if (trash_counters)
		free(trash_counters);
}

REGISTER_PER_THREAD_FREE(free_trash_counters);

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "clear", "counters",  NULL },      "clear counters [all]                    : clear max statistics counters (or all counters)", cli_parse_clear_counters, NULL, NULL },
	{ { "show", "info",  NULL },           "show info [desc|json|typed|float]*      : report information about the running process",    cli_parse_show_info, cli_io_handler_dump_info, NULL },
	{ { "show", "stat",  NULL },           "show stat [desc|json|no-maint|typed|up]*: report counters for each proxy and server",       cli_parse_show_stat, cli_io_handler_dump_stat, cli_io_handler_release_stat },
	{ { "show", "schema",  "json", NULL }, "show schema json                        : report schema used for stats",                    cli_parse_show_schema_json, cli_io_handler_dump_json_schema, NULL },
	{ { "dump", "stats-file", NULL },      "dump stats-file                         : dump stats for restore",                          cli_parse_dump_stat_file, cli_io_handler_dump_stat_file, cli_io_handler_release_dump_stat_file },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
