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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <haproxy/api.h>
#include <haproxy/activity.h>
#include <haproxy/applet.h>
#include <haproxy/backend.h>
#include <haproxy/base64.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/cli.h>
#include <haproxy/clock.h>
#include <haproxy/compression.h>
#include <haproxy/debug.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/frontend.h>
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
#include <haproxy/stats-html.h>
#include <haproxy/stats-json.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/uri_auth-t.h>
#include <haproxy/version.h>

/* Define a new metric for both frontend and backend sides. */
#define ME_NEW_PX(name_f, nature, format, offset_f, cap_f, desc_f)            \
  { .name = (name_f), .desc = (desc_f), .type = (nature)|(format),            \
    .metric.offset[0] = offsetof(struct fe_counters, offset_f),               \
    .metric.offset[1] = offsetof(struct be_counters, offset_f),               \
    .cap = (cap_f),                                                           \
  }

/* Define a new metric for frontend side only. */
#define ME_NEW_FE(name_f, nature, format, offset_f, cap_f, desc_f)            \
  { .name = (name_f), .desc = (desc_f), .type = (nature)|(format),            \
    .metric.offset[0] = offsetof(struct fe_counters, offset_f),               \
    .cap = (cap_f),                                                           \
  }

/* Define a new metric for backend side only. */
#define ME_NEW_BE(name_f, nature, format, offset_f, cap_f, desc_f)            \
  { .name = (name_f), .desc = (desc_f), .type = (nature)|(format),            \
    .metric.offset[1] = offsetof(struct be_counters, offset_f),               \
    .cap = (cap_f),                                                           \
  }

/* Returns true if <col> is fully defined, false if only used as name-desc. */
static int stcol_is_generic(const struct stat_col *col)
{
	return !!(col->cap);
}

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
};

/* one line of info */
THREAD_LOCAL struct field stat_line_info[ST_I_INF_MAX];

const struct stat_col stat_cols_px[ST_I_PX_MAX] = {
	[ST_I_PX_PXNAME]                        = { .name = "pxname",                      .desc = "Proxy name" },
	[ST_I_PX_SVNAME]                        = { .name = "svname",                      .desc = "Server name" },
	[ST_I_PX_QCUR]                          = { .name = "qcur",                        .desc = "Number of current queued connections" },
	[ST_I_PX_QMAX]                          = { .name = "qmax",                        .desc = "Highest value of queued connections encountered since process started" },
	[ST_I_PX_SCUR]                          = { .name = "scur",                        .desc = "Number of current sessions on the frontend, backend or server" },
	[ST_I_PX_SMAX]                          = { .name = "smax",                        .desc = "Highest value of current sessions encountered since process started" },
	[ST_I_PX_SLIM]                          = { .name = "slim",                        .desc = "Frontend/listener/server's maxconn, backend's fullconn" },
	[ST_I_PX_STOT]          = ME_NEW_PX("stot",          FN_COUNTER, FF_U64, cum_sess,               STATS_PX_CAP_LFBS, "Total number of sessions since process started"),
	[ST_I_PX_BIN]           = ME_NEW_PX("bin",           FN_COUNTER, FF_U64, bytes_in,               STATS_PX_CAP_LFBS, "Total number of request bytes since process started"),
	[ST_I_PX_BOUT]          = ME_NEW_PX("bout",          FN_COUNTER, FF_U64, bytes_out,              STATS_PX_CAP_LFBS, "Total number of response bytes since process started"),
	[ST_I_PX_DREQ]          = ME_NEW_PX("dreq",          FN_COUNTER, FF_U64, denied_req,             STATS_PX_CAP_LFB_, "Total number of denied requests since process started"),
	[ST_I_PX_DRESP]         = ME_NEW_PX("dresp",         FN_COUNTER, FF_U64, denied_resp,            STATS_PX_CAP_LFBS, "Total number of denied responses since process started"),
	[ST_I_PX_EREQ]          = ME_NEW_FE("ereq",          FN_COUNTER, FF_U64, failed_req,             STATS_PX_CAP_LF__, "Total number of invalid requests since process started"),
	[ST_I_PX_ECON]          = ME_NEW_BE("econ",          FN_COUNTER, FF_U64, failed_conns,           STATS_PX_CAP___BS, "Total number of failed connections to server since the worker process started"),
	[ST_I_PX_ERESP]         = ME_NEW_BE("eresp",         FN_COUNTER, FF_U64, failed_resp,            STATS_PX_CAP___BS, "Total number of invalid responses since the worker process started"),
	[ST_I_PX_WRETR]         = ME_NEW_BE("wretr",         FN_COUNTER, FF_U64, retries,                STATS_PX_CAP___BS, "Total number of server connection retries since the worker process started"),
	[ST_I_PX_WREDIS]        = ME_NEW_BE("wredis",        FN_COUNTER, FF_U64, redispatches,           STATS_PX_CAP___BS, "Total number of server redispatches due to connection failures since the worker process started"),
	[ST_I_PX_STATUS]                        = { .name = "status",                      .desc = "Frontend/listen status: OPEN/WAITING/FULL/STOP; backend: UP/DOWN; server: last check status" },
	[ST_I_PX_WEIGHT]                        = { .name = "weight",                      .desc = "Server's effective weight, or sum of active servers' effective weights for a backend" },
	[ST_I_PX_ACT]                           = { .name = "act",                         .desc = "Total number of active UP servers with a non-zero weight" },
	[ST_I_PX_BCK]                           = { .name = "bck",                         .desc = "Total number of backup UP servers with a non-zero weight" },
	[ST_I_PX_CHKFAIL]       = ME_NEW_BE("chkfail",       FN_COUNTER, FF_U64, failed_checks,          STATS_PX_CAP____S, "Total number of failed individual health checks per server/backend, since the worker process started"),
	[ST_I_PX_CHKDOWN]       = ME_NEW_BE("chkdown",       FN_COUNTER, FF_U64, down_trans,             STATS_PX_CAP___BS, "Total number of failed checks causing UP to DOWN server transitions, per server/backend, since the worker process started"),
	[ST_I_PX_LASTCHG]                       = { .name = "lastchg",                     .desc = "How long ago the last server state changed, in seconds" },
	[ST_I_PX_DOWNTIME]                      = { .name = "downtime",                    .desc = "Total time spent in DOWN state, for server or backend" },
	[ST_I_PX_QLIMIT]                        = { .name = "qlimit",                      .desc = "Limit on the number of connections in queue, for servers only (maxqueue argument)" },
	[ST_I_PX_PID]                           = { .name = "pid",                         .desc = "Relative worker process number (1)" },
	[ST_I_PX_IID]                           = { .name = "iid",                         .desc = "Frontend or Backend numeric identifier ('id' setting)" },
	[ST_I_PX_SID]                           = { .name = "sid",                         .desc = "Server numeric identifier ('id' setting)" },
	[ST_I_PX_THROTTLE]                      = { .name = "throttle",                    .desc = "Throttling ratio applied to a server's maxconn and weight during the slowstart period (0 to 100%)" },
	[ST_I_PX_LBTOT]         = ME_NEW_BE("lbtot",         FN_COUNTER, FF_U64, cum_lbconn,             STATS_PX_CAP_LFBS, "Total number of requests routed by load balancing since the worker process started (ignores queue pop and stickiness)"),
	[ST_I_PX_TRACKED]                       = { .name = "tracked",                     .desc = "Name of the other server this server tracks for its state" },
	[ST_I_PX_TYPE]                          = { .name = "type",                        .desc = "Type of the object (Listener, Frontend, Backend, Server)" },
	[ST_I_PX_RATE]                          = { .name = "rate",                        .desc = "Total number of sessions processed by this object over the last second (sessions for listeners/frontends, requests for backends/servers)" },
	[ST_I_PX_RATE_LIM]                      = { .name = "rate_lim",                    .desc = "Limit on the number of sessions accepted in a second (frontend only, 'rate-limit sessions' setting)" },
	[ST_I_PX_RATE_MAX]                      = { .name = "rate_max",                    .desc = "Highest value of sessions per second observed since the worker process started" },
	[ST_I_PX_CHECK_STATUS]                  = { .name = "check_status",                .desc = "Status report of the server's latest health check, prefixed with '*' if a check is currently in progress" },
	[ST_I_PX_CHECK_CODE]                    = { .name = "check_code",                  .desc = "HTTP/SMTP/LDAP status code reported by the latest server health check" },
	[ST_I_PX_CHECK_DURATION]                = { .name = "check_duration",              .desc = "Total duration of the latest server health check, in milliseconds" },
	[ST_I_PX_HRSP_1XX]      = ME_NEW_PX("hrsp_1xx",      FN_COUNTER, FF_U64, p.http.rsp[1],          STATS_PX_CAP__FBS, "Total number of HTTP responses with status 100-199 returned by this object since the worker process started"),
	[ST_I_PX_HRSP_2XX]      = ME_NEW_PX("hrsp_2xx",      FN_COUNTER, FF_U64, p.http.rsp[2],          STATS_PX_CAP__FBS, "Total number of HTTP responses with status 200-299 returned by this object since the worker process started"),
	[ST_I_PX_HRSP_3XX]      = ME_NEW_PX("hrsp_3xx",      FN_COUNTER, FF_U64, p.http.rsp[3],          STATS_PX_CAP__FBS, "Total number of HTTP responses with status 300-399 returned by this object since the worker process started"),
	[ST_I_PX_HRSP_4XX]      = ME_NEW_PX("hrsp_4xx",      FN_COUNTER, FF_U64, p.http.rsp[4],          STATS_PX_CAP__FBS, "Total number of HTTP responses with status 400-499 returned by this object since the worker process started"),
	[ST_I_PX_HRSP_5XX]      = ME_NEW_PX("hrsp_5xx",      FN_COUNTER, FF_U64, p.http.rsp[5],          STATS_PX_CAP__FBS, "Total number of HTTP responses with status 500-599 returned by this object since the worker process started"),
	[ST_I_PX_HRSP_OTHER]    = ME_NEW_PX("hrsp_other",    FN_COUNTER, FF_U64, p.http.rsp[0],          STATS_PX_CAP__FBS, "Total number of HTTP responses with status <100, >599 returned by this object since the worker process started (error -1 included)"),
	[ST_I_PX_HANAFAIL]      = ME_NEW_BE("hanafail",      FN_COUNTER, FF_U64, failed_hana,            STATS_PX_CAP_SRV, "Total number of failed checks caused by an 'on-error' directive after an 'observe' condition matched"),
	[ST_I_PX_REQ_RATE]                      = { .name = "req_rate",                    .desc = "Number of HTTP requests processed over the last second on this object" },
	[ST_I_PX_REQ_RATE_MAX]                  = { .name = "req_rate_max",                .desc = "Highest value of http requests observed since the worker process started" },
	[ST_I_PX_REQ_TOT]                       = { .name = "req_tot",                     .desc = "Total number of HTTP requests processed by this object since the worker process started" },
	[ST_I_PX_CLI_ABRT]      = ME_NEW_BE("cli_abrt",      FN_COUNTER, FF_U64, cli_aborts,             STATS_PX_CAP_LFBS, "Total number of requests or connections aborted by the client since the worker process started"),
	[ST_I_PX_SRV_ABRT]      = ME_NEW_BE("srv_abrt",      FN_COUNTER, FF_U64, srv_aborts,             STATS_PX_CAP_LFBS, "Total number of requests or connections aborted by the server since the worker process started"),
	[ST_I_PX_COMP_IN]       = ME_NEW_PX("comp_in",       FN_COUNTER, FF_U64, comp_in[COMP_DIR_RES],  STATS_PX_CAP__FB_, "Total number of bytes submitted to the HTTP compressor for this object since the worker process started"),
	[ST_I_PX_COMP_OUT]      = ME_NEW_PX("comp_out",      FN_COUNTER, FF_U64, comp_out[COMP_DIR_RES], STATS_PX_CAP__FB_, "Total number of bytes emitted by the HTTP compressor for this object since the worker process started"),
	[ST_I_PX_COMP_BYP]      = ME_NEW_PX("comp_byp",      FN_COUNTER, FF_U64, comp_byp[COMP_DIR_RES], STATS_PX_CAP__FB_, "Total number of bytes that bypassed HTTP compression for this object since the worker process started (CPU/memory/bandwidth limitation)"),
	[ST_I_PX_COMP_RSP]      = ME_NEW_PX("comp_rsp",      FN_COUNTER, FF_U64, p.http.comp_rsp,        STATS_PX_CAP__FB_, "Total number of HTTP responses that were compressed for this object since the worker process started"),
	[ST_I_PX_LASTSESS]                      = { .name = "lastsess",                    .desc = "How long ago some traffic was seen on this object on this worker process, in seconds" },
	[ST_I_PX_LAST_CHK]                      = { .name = "last_chk",                    .desc = "Short description of the latest health check report for this server (see also check_desc)" },
	[ST_I_PX_LAST_AGT]                      = { .name = "last_agt",                    .desc = "Short description of the latest agent check report for this server (see also agent_desc)" },
	[ST_I_PX_QTIME]                         = { .name = "qtime",                       .desc = "Time spent in the queue, in milliseconds, averaged over the 1024 last requests (backend/server)" },
	[ST_I_PX_CTIME]                         = { .name = "ctime",                       .desc = "Time spent waiting for a connection to complete, in milliseconds, averaged over the 1024 last requests (backend/server)" },
	[ST_I_PX_RTIME]                         = { .name = "rtime",                       .desc = "Time spent waiting for a server response, in milliseconds, averaged over the 1024 last requests (backend/server)" },
	[ST_I_PX_TTIME]                         = { .name = "ttime",                       .desc = "Total request+response time (request+queue+connect+response+processing), in milliseconds, averaged over the 1024 last requests (backend/server)" },
	[ST_I_PX_AGENT_STATUS]                  = { .name = "agent_status",                .desc = "Status report of the server's latest agent check, prefixed with '*' if a check is currently in progress" },
	[ST_I_PX_AGENT_CODE]                    = { .name = "agent_code",                  .desc = "Status code reported by the latest server agent check" },
	[ST_I_PX_AGENT_DURATION]                = { .name = "agent_duration",              .desc = "Total duration of the latest server agent check, in milliseconds" },
	[ST_I_PX_CHECK_DESC]                    = { .name = "check_desc",                  .desc = "Textual description of the latest health check report for this server" },
	[ST_I_PX_AGENT_DESC]                    = { .name = "agent_desc",                  .desc = "Textual description of the latest agent check report for this server" },
	[ST_I_PX_CHECK_RISE]                    = { .name = "check_rise",                  .desc = "Number of successful health checks before declaring a server UP (server 'rise' setting)" },
	[ST_I_PX_CHECK_FALL]                    = { .name = "check_fall",                  .desc = "Number of failed health checks before declaring a server DOWN (server 'fall' setting)" },
	[ST_I_PX_CHECK_HEALTH]                  = { .name = "check_health",                .desc = "Current server health check level (0..fall-1=DOWN, fall..rise-1=UP)" },
	[ST_I_PX_AGENT_RISE]                    = { .name = "agent_rise",                  .desc = "Number of successful agent checks before declaring a server UP (server 'rise' setting)" },
	[ST_I_PX_AGENT_FALL]                    = { .name = "agent_fall",                  .desc = "Number of failed agent checks before declaring a server DOWN (server 'fall' setting)" },
	[ST_I_PX_AGENT_HEALTH]                  = { .name = "agent_health",                .desc = "Current server agent check level (0..fall-1=DOWN, fall..rise-1=UP)" },
	[ST_I_PX_ADDR]                          = { .name = "addr",                        .desc = "Server's address:port, shown only if show-legends is set, or at levels oper/admin for the CLI" },
	[ST_I_PX_COOKIE]                        = { .name = "cookie",                      .desc = "Backend's cookie name or Server's cookie value, shown only if show-legends is set, or at levels oper/admin for the CLI" },
	[ST_I_PX_MODE]                          = { .name = "mode",                        .desc = "'mode' setting (tcp/http/health/cli)" },
	[ST_I_PX_ALGO]                          = { .name = "algo",                        .desc = "Backend's load balancing algorithm, shown only if show-legends is set, or at levels oper/admin for the CLI" },
	[ST_I_PX_CONN_RATE]                     = { .name = "conn_rate",                   .desc = "Number of new connections accepted over the last second on the frontend for this worker process" },
	[ST_I_PX_CONN_RATE_MAX]                 = { .name = "conn_rate_max",               .desc = "Highest value of connections per second observed since the worker process started" },
	[ST_I_PX_CONN_TOT]      = ME_NEW_FE("conn_tot",      FN_COUNTER, FF_U64, cum_conn,               STATS_PX_CAP_LF__, "Total number of new connections accepted on this frontend since the worker process started"),
	[ST_I_PX_INTERCEPTED]   = ME_NEW_FE("intercepted",   FN_COUNTER, FF_U64, intercepted_req,        STATS_PX_CAP__F__, "Total number of HTTP requests intercepted on the frontend (redirects/stats/services) since the worker process started"),
	[ST_I_PX_DCON]          = ME_NEW_FE("dcon",          FN_COUNTER, FF_U64, denied_conn,            STATS_PX_CAP_LF__, "Total number of incoming connections blocked on a listener/frontend by a tcp-request connection rule since the worker process started"),
	[ST_I_PX_DSES]          = ME_NEW_FE("dses",          FN_COUNTER, FF_U64, denied_sess,            STATS_PX_CAP_LF__, "Total number of incoming sessions blocked on a listener/frontend by a tcp-request connection rule since the worker process started"),
	[ST_I_PX_WREW]          = ME_NEW_PX("wrew",          FN_COUNTER, FF_U64, failed_rewrites,        STATS_PX_CAP_LFBS, "Total number of failed HTTP header rewrites since the worker process started"),
	[ST_I_PX_CONNECT]       = ME_NEW_BE("connect",       FN_COUNTER, FF_U64, connect,                STATS_PX_CAP___BS, "Total number of outgoing connection attempts on this backend/server since the worker process started"),
	[ST_I_PX_REUSE]         = ME_NEW_BE("reuse",         FN_COUNTER, FF_U64, reuse,                  STATS_PX_CAP___BS, "Total number of reused connection on this backend/server since the worker process started"),
	[ST_I_PX_CACHE_LOOKUPS] = ME_NEW_PX("cache_lookups", FN_COUNTER, FF_U64, p.http.cache_lookups,   STATS_PX_CAP__FB_, "Total number of HTTP requests looked up in the cache on this frontend/backend since the worker process started"),
	[ST_I_PX_CACHE_HITS]    = ME_NEW_PX("cache_hits",    FN_COUNTER, FF_U64, p.http.cache_hits,      STATS_PX_CAP__FB_, "Total number of HTTP requests not found in the cache on this frontend/backend since the worker process started"),
	[ST_I_PX_SRV_ICUR]                      = { .name = "srv_icur",                    .desc = "Current number of idle connections available for reuse on this server" },
	[ST_I_PX_SRV_ILIM]                      = { .name = "src_ilim",                    .desc = "Limit on the number of available idle connections on this server (server 'pool_max_conn' directive)" },
	[ST_I_PX_QT_MAX]                        = { .name = "qtime_max",                   .desc = "Maximum observed time spent in the queue, in milliseconds (backend/server)" },
	[ST_I_PX_CT_MAX]                        = { .name = "ctime_max",                   .desc = "Maximum observed time spent waiting for a connection to complete, in milliseconds (backend/server)" },
	[ST_I_PX_RT_MAX]                        = { .name = "rtime_max",                   .desc = "Maximum observed time spent waiting for a server response, in milliseconds (backend/server)" },
	[ST_I_PX_TT_MAX]                        = { .name = "ttime_max",                   .desc = "Maximum observed total request+response time (request+queue+connect+response+processing), in milliseconds (backend/server)" },
	[ST_I_PX_EINT]          = ME_NEW_PX("eint",          FN_COUNTER, FF_U64, internal_errors,        STATS_PX_CAP_LFBS, "Total number of internal errors since process started"),
	[ST_I_PX_IDLE_CONN_CUR]                 = { .name = "idle_conn_cur",               .desc = "Current number of unsafe idle connections"},
	[ST_I_PX_SAFE_CONN_CUR]                 = { .name = "safe_conn_cur",               .desc = "Current number of safe idle connections"},
	[ST_I_PX_USED_CONN_CUR]                 = { .name = "used_conn_cur",               .desc = "Current number of connections in use"},
	[ST_I_PX_NEED_CONN_EST]                 = { .name = "need_conn_est",               .desc = "Estimated needed number of connections"},
	[ST_I_PX_UWEIGHT]                       = { .name = "uweight",                     .desc = "Server's user weight, or sum of active servers' user weights for a backend" },
	[ST_I_PX_AGG_SRV_CHECK_STATUS]          = { .name = "agg_server_check_status",     .desc = "[DEPRECATED] Backend's aggregated gauge of servers' status" },
	[ST_I_PX_AGG_SRV_STATUS ]               = { .name = "agg_server_status",           .desc = "Backend's aggregated gauge of servers' status" },
	[ST_I_PX_AGG_CHECK_STATUS]              = { .name = "agg_check_status",            .desc = "Backend's aggregated gauge of servers' state check status" },
	[ST_I_PX_SRID]                          = { .name = "srid",                        .desc = "Server id revision, to prevent server id reuse mixups" },
	[ST_I_PX_SESS_OTHER]                    = { .name = "sess_other",                  .desc = "Total number of sessions other than HTTP since process started" },
	[ST_I_PX_H1SESS]        = ME_NEW_FE("h1sess",        FN_COUNTER, FF_U64, cum_sess_ver[0],        STATS_PX_CAP__F__, "Total number of HTTP/1 sessions since process started"),
	[ST_I_PX_H2SESS]        = ME_NEW_FE("h2sess",        FN_COUNTER, FF_U64, cum_sess_ver[1],        STATS_PX_CAP__F__, "Total number of HTTP/2 sessions since process started"),
	[ST_I_PX_H3SESS]        = ME_NEW_FE("h3sess",        FN_COUNTER, FF_U64, cum_sess_ver[2],        STATS_PX_CAP__F__, "Total number of HTTP/3 sessions since process started"),
	[ST_I_PX_REQ_OTHER]     = ME_NEW_FE("req_other",     FN_COUNTER, FF_U64, p.http.cum_req[0],      STATS_PX_CAP__F__, "Total number of sessions other than HTTP processed by this object since the worker process started"),
	[ST_I_PX_H1REQ]         = ME_NEW_FE("h1req",         FN_COUNTER, FF_U64, p.http.cum_req[1],      STATS_PX_CAP__F__, "Total number of HTTP/1 sessions processed by this object since the worker process started"),
	[ST_I_PX_H2REQ]         = ME_NEW_FE("h2req",         FN_COUNTER, FF_U64, p.http.cum_req[2],      STATS_PX_CAP__F__, "Total number of hTTP/2 sessions processed by this object since the worker process started"),
	[ST_I_PX_H3REQ]         = ME_NEW_FE("h3req",         FN_COUNTER, FF_U64, p.http.cum_req[3],      STATS_PX_CAP__F__, "Total number of HTTP/3 sessions processed by this object since the worker process started"),
	[ST_I_PX_PROTO]                         = { .name = "proto",                       .desc = "Protocol" },
};

/* one line for stats */
THREAD_LOCAL struct field *stat_lines[STATS_DOMAIN_COUNT];

/* Unified storage for statistics from all module
 * TODO merge info stats into it as global statistic domain.
 */
struct name_desc *stat_cols[STATS_DOMAIN_COUNT];
static size_t stat_cols_len[STATS_DOMAIN_COUNT];

/* list of all registered stats module */
struct list stats_module_list[STATS_DOMAIN_COUNT] = {
	LIST_HEAD_INIT(stats_module_list[STATS_DOMAIN_PROXY]),
	LIST_HEAD_INIT(stats_module_list[STATS_DOMAIN_RESOLVERS]),
};

THREAD_LOCAL void *trash_counters;


int stats_putchk(struct appctx *appctx, struct buffer *buf, struct htx *htx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;

	if (htx) {
		if (b_data(chk) > htx_free_data_space(htx)) {
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
		if (b_data(chk) > b_room(buf)) {
			se_fl_set(appctx->sedesc, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
			return 0;
		}
		b_putblk(buf, b_head(chk), b_data(chk));
		chunk_reset(chk);
	}
	else {
		if (applet_putchk(appctx, chk) == -1)
			return 0;
	}
	return 1;
}


int stats_is_full(struct appctx *appctx, struct buffer *buf, struct htx *htx)
{
	if (htx) {
		if (htx_almost_full(htx)) {
			applet_fl_set(appctx, APPCTX_FL_OUTBLK_FULL);
			goto full;
		}
	}
	else if (buf) {
		if (buffer_almost_full(buf)) {
			se_fl_set(appctx->sedesc, SE_FL_RCV_MORE | SE_FL_WANT_ROOM);
			goto full;
		}
	}
	else {
		if (buffer_almost_full(&appctx->outbuf))  {
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

	blk = htx_get_head_blk(htx);
	BUG_ON(!blk || htx_get_blk_type(blk) != HTX_BLK_REQ_SL);
	ALREADY_CHECKED(blk);
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
	else
		ret = stats_dump_fields_csv(chk, line, stats_count, ctx);

	return ret;
}

/* Returns true if column at <idx> should be hidden.
 * This may depends on various <objt> internal status.
 */
static int stcol_hide(enum stat_idx_px idx, enum obj_type *objt)
{
	struct proxy *px;
	struct server *srv = NULL, *ref;
	struct listener *li = NULL;

	switch (obj_type(objt)) {
	case OBJ_TYPE_PROXY:
		px = __objt_proxy(objt);
		break;
	case OBJ_TYPE_SERVER:
		srv = __objt_server(objt);
		px = srv->proxy;
		break;
	case OBJ_TYPE_LISTENER:
		li = __objt_listener(objt);
		px = li->bind_conf->frontend;
		break;
	default:
		ABORT_NOW();
		return 0;
	}

	switch (idx) {
	case ST_I_PX_HRSP_1XX:
	case ST_I_PX_HRSP_2XX:
	case ST_I_PX_HRSP_3XX:
	case ST_I_PX_HRSP_4XX:
	case ST_I_PX_HRSP_5XX:
	case ST_I_PX_INTERCEPTED:
	case ST_I_PX_CACHE_LOOKUPS:
	case ST_I_PX_CACHE_HITS:
		return px->mode != PR_MODE_HTTP;

	case ST_I_PX_CHKFAIL:
	case ST_I_PX_CHKDOWN:
		return srv && !(srv->check.state & CHK_ST_ENABLED);

	case ST_I_PX_HANAFAIL:
		BUG_ON(!srv); /* HANAFAIL is only defined for server scope */

		ref = srv->track ? srv->track : srv;
		while (ref->track)
			ref = ref->track;
		return !ref->observe;

	default:
		return 0;
	}
}

/* Generate if possible a metric value from <col>. <cap> must be set to one of
 * STATS_PX_CAP_* values to check if the metric is available for this object
 * type. <stat_file> must be set when dumping stats-file. Metric value will be
 * extracted from <counters>.
 *
 * Returns a field metric.
 */
static struct field me_generate_field(const struct stat_col *col,
                                      enum stat_idx_px idx, enum obj_type *objt,
                                      const void *counters, uint8_t cap,
                                      int stat_file)
{
	struct field value;
	void *counter = NULL;
	int wrong_side = 0;

	/* Only generic stat column must be used as input. */
	BUG_ON(!stcol_is_generic(col));

	switch (cap) {
	case STATS_PX_CAP_FE:
	case STATS_PX_CAP_LI:
		counter = (char *)counters + col->metric.offset[0];
		wrong_side = !(col->cap & (STATS_PX_CAP_FE|STATS_PX_CAP_LI));
		break;

	case STATS_PX_CAP_BE:
	case STATS_PX_CAP_SRV:
		counter = (char *)counters + col->metric.offset[1];
		wrong_side = !(col->cap & (STATS_PX_CAP_BE|STATS_PX_CAP_SRV));
		break;

	default:
		/* invalid cap requested */
		ABORT_NOW();
	}

	if (stat_file) {
		/* stats-file emits separately frontend and backend stats.
		 * Skip metric if not defined for any object on the cap side.
		 */
		if (wrong_side)
			return (struct field){ .type = FF_EMPTY };
	}
	else {
		/* Ensure metric is defined for the current cap. */
		if (!(col->cap & cap) || stcol_hide(idx, objt))
			return (struct field){ .type = FF_EMPTY };
	}

	switch (stcol_format(col)) {
	case FF_U64:
		value = mkf_u64(stcol_nature(col), *(uint64_t *)counter);
		break;
	default:
		/* only FF_U64 counters currently use generic metric calculation */
		ABORT_NOW();
	}

	return value;
}

/* Fill <line> with the frontend statistics. <line> is preallocated array of
 * length <len>. If <index> is != NULL, only fill this one. The length
 * of the array must be at least ST_I_PX_MAX. If this length is less than
 * this value, or if the selected field is not implemented for frontends, the
 * function returns 0, otherwise, it returns 1.
 */
int stats_fill_fe_line(struct proxy *px, int flags, struct field *line, int len,
                       enum stat_idx_px *index)
{
	enum stat_idx_px i = index ? *index : 0;

	if (len < ST_I_PX_MAX)
		return 0;

	for (; i < ST_I_PX_MAX; i++) {
		const struct stat_col *col = &stat_cols_px[i];
		struct field field = { 0 };

		if (stcol_is_generic(col)) {
			field = me_generate_field(col, i, &px->obj_type,
			                          &px->fe_counters, STATS_PX_CAP_FE,
			                          flags & STAT_F_FMT_FILE);
		}
		else if (!(flags & STAT_F_FMT_FILE)) {
			switch (i) {
			case ST_I_PX_PXNAME:
				field = mkf_str(FO_KEY|FN_NAME|FS_SERVICE, px->id);
				break;
			case ST_I_PX_SVNAME:
				field = mkf_str(FO_KEY|FN_NAME|FS_SERVICE, "FRONTEND");
				break;
			case ST_I_PX_MODE:
				field = mkf_str(FO_CONFIG|FS_SERVICE, proxy_mode_str(px->mode));
				break;
			case ST_I_PX_SCUR:
				field = mkf_u32(0, px->feconn);
				break;
			case ST_I_PX_SMAX:
				field = mkf_u32(FN_MAX, px->fe_counters.conn_max);
				break;
			case ST_I_PX_SLIM:
				field = mkf_u32(FO_CONFIG|FN_LIMIT, px->maxconn);
				break;
			case ST_I_PX_STATUS: {
				const char *state;

				if (px->flags & (PR_FL_DISABLED|PR_FL_STOPPED))
					state = "STOP";
				else if (px->flags & PR_FL_PAUSED)
					state = "PAUSED";
				else
					state = "OPEN";
				field = mkf_str(FO_STATUS, state);
				break;
			}
			case ST_I_PX_PID:
				field = mkf_u32(FO_KEY, 1);
				break;
			case ST_I_PX_IID:
				field = mkf_u32(FO_KEY|FS_SERVICE, px->uuid);
				break;
			case ST_I_PX_SID:
				field = mkf_u32(FO_KEY|FS_SERVICE, 0);
				break;
			case ST_I_PX_TYPE:
				field = mkf_u32(FO_CONFIG|FS_SERVICE, STATS_TYPE_FE);
				break;
			case ST_I_PX_RATE:
				field = mkf_u32(FN_RATE, read_freq_ctr(&px->fe_sess_per_sec));
				break;
			case ST_I_PX_RATE_LIM:
				field = mkf_u32(FO_CONFIG|FN_LIMIT, px->fe_sps_lim);
				break;
			case ST_I_PX_RATE_MAX:
				field = mkf_u32(FN_MAX, px->fe_counters.sps_max);
				break;
			case ST_I_PX_REQ_RATE:
				field = mkf_u32(FN_RATE, read_freq_ctr(&px->fe_req_per_sec));
				break;
			case ST_I_PX_REQ_RATE_MAX:
				field = mkf_u32(FN_MAX, px->fe_counters.p.http.rps_max);
				break;
			case ST_I_PX_REQ_TOT: {
				int i;
				uint64_t total_req;
				size_t nb_reqs =
					sizeof(px->fe_counters.p.http.cum_req) / sizeof(*px->fe_counters.p.http.cum_req);

				total_req = 0;
				for (i = 0; i < nb_reqs; i++)
					total_req += px->fe_counters.p.http.cum_req[i];
				field = mkf_u64(FN_COUNTER, total_req);
				break;
			}
			case ST_I_PX_CONN_RATE:
				field = mkf_u32(FN_RATE, read_freq_ctr(&px->fe_conn_per_sec));
				break;
			case ST_I_PX_CONN_RATE_MAX:
				field = mkf_u32(FN_MAX, px->fe_counters.cps_max);
				break;
			case ST_I_PX_SESS_OTHER: {
				int i;
				uint64_t total_sess;
				size_t nb_sess =
					sizeof(px->fe_counters.cum_sess_ver) / sizeof(*px->fe_counters.cum_sess_ver);

				total_sess = px->fe_counters.cum_sess;
				for (i = 0; i < nb_sess; i++)
					total_sess -= px->fe_counters.cum_sess_ver[i];
				total_sess = (int64_t)total_sess < 0 ? 0 : total_sess;
				field = mkf_u64(FN_COUNTER, total_sess);
				break;
			}
			default:
				/* not used for frontends. If a specific field
				 * is requested, return an error. Otherwise continue.
				 */
				if (index)
					return 0;
				continue;
			}
		}
		line[i] = field;
		if (index)
			break;
	}
	return 1;
}

/* Dumps a frontend's line to chunk ctx buffer for the current proxy <px> and
 * uses the state from stream connector <sc>. The caller is responsible for
 * clearing chunk ctx buffer if needed. Returns non-zero if it emits anything,
 * zero otherwise.
 */
static int stats_dump_fe_line(struct stconn *sc, struct proxy *px)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct field *line = stat_lines[STATS_DOMAIN_PROXY];
	struct stats_module *mod;
	size_t stats_count = ST_I_PX_MAX;

	if (!(px->cap & PR_CAP_FE))
		return 0;

	if ((ctx->flags & STAT_F_BOUND) && !(ctx->type & (1 << STATS_TYPE_FE)))
		return 0;

	memset(line, 0, sizeof(struct field) * stat_cols_len[STATS_DOMAIN_PROXY]);

	if (!stats_fill_fe_line(px, ctx->flags, line, ST_I_PX_MAX, NULL))
		return 0;

	list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		void *counters;

		if (!(stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_FE)) {
			stats_count += mod->stats_count;
			continue;
		}

		counters = EXTRA_COUNTERS_GET(px->extra_counters_fe, mod);
		if (!mod->fill_stats(counters, line + stats_count, NULL))
			continue;
		stats_count += mod->stats_count;
	}

	return stats_dump_one_line(line, stats_count, appctx);
}

/* Fill <line> with the listener statistics. <line> is preallocated array of
 * length <len>. The length of the array must be at least ST_I_PX_MAX. If
 * this length is less then this value, the function returns 0, otherwise, it
 * returns 1.  If selected_field is != NULL, only fill this one. <flags> can
 * take the value STAT_F_SHLGNDS.
 */
int stats_fill_li_line(struct proxy *px, struct listener *l, int flags,
                       struct field *line, int len, enum stat_idx_px *selected_field)
{
	enum stat_idx_px i = (selected_field != NULL ? *selected_field : 0);
	struct buffer *out = get_trash_chunk();

	if (len < ST_I_PX_MAX)
		return 0;

	if (!l->counters)
		return 0;

	chunk_reset(out);

	for (; i < ST_I_PX_MAX; i++) {
		const struct stat_col *col = &stat_cols_px[i];
		struct field field = { 0 };

		if (stcol_is_generic(col)) {
			field = me_generate_field(col, i, &l->obj_type,
			                          l->counters, STATS_PX_CAP_LI,
			                          flags & STAT_F_FMT_FILE);
		}
		else if (!(flags & STAT_F_FMT_FILE)) {
			switch (i) {
			case ST_I_PX_PXNAME:
				field = mkf_str(FO_KEY|FN_NAME|FS_SERVICE, px->id);
				break;
			case ST_I_PX_SVNAME:
				field = mkf_str(FO_KEY|FN_NAME|FS_SERVICE, l->name);
				break;
			case ST_I_PX_MODE:
				field = mkf_str(FO_CONFIG|FS_SERVICE, proxy_mode_str(px->mode));
				break;
			case ST_I_PX_SCUR:
				field = mkf_u32(0, l->nbconn);
				break;
			case ST_I_PX_SMAX:
				field = mkf_u32(FN_MAX, l->counters->conn_max);
				break;
			case ST_I_PX_SLIM:
				field = mkf_u32(FO_CONFIG|FN_LIMIT, l->bind_conf->maxconn);
				break;
			case ST_I_PX_STATUS:
				field = mkf_str(FO_STATUS, li_status_st[get_li_status(l)]);
				break;
			case ST_I_PX_PID:
				field = mkf_u32(FO_KEY, 1);
				break;
			case ST_I_PX_IID:
				field = mkf_u32(FO_KEY|FS_SERVICE, px->uuid);
				break;
			case ST_I_PX_SID:
				field = mkf_u32(FO_KEY|FS_SERVICE, l->luid);
				break;
			case ST_I_PX_TYPE:
				field = mkf_u32(FO_CONFIG|FS_SERVICE, STATS_TYPE_SO);
				break;
			case ST_I_PX_ADDR:
				if (flags & STAT_F_SHLGNDS) {
					char str[INET6_ADDRSTRLEN];
					int port;

					port = get_host_port(&l->rx.addr);
					switch (addr_to_str(&l->rx.addr, str, sizeof(str))) {
					case AF_INET:
						field = mkf_str(FO_CONFIG|FS_SERVICE, chunk_newstr(out));
						chunk_appendf(out, "%s:%d", str, port);
						break;
					case AF_INET6:
						field = mkf_str(FO_CONFIG|FS_SERVICE, chunk_newstr(out));
						chunk_appendf(out, "[%s]:%d", str, port);
						break;
					case AF_UNIX:
						field = mkf_str(FO_CONFIG|FS_SERVICE, "unix");
						break;
					case -1:
						field = mkf_str(FO_CONFIG|FS_SERVICE, chunk_newstr(out));
						chunk_strcat(out, strerror(errno));
						break;
					default: /* address family not supported */
						break;
					}
				}
				break;
			case ST_I_PX_PROTO:
				field = mkf_str(FO_STATUS, l->rx.proto->name);
				break;
			default:
				/* not used for listen. If a specific field
				 * is requested, return an error. Otherwise continue.
				 */
				if (selected_field != NULL)
					return 0;
				continue;
			}
		}
		line[i] = field;
		if (selected_field != NULL)
			break;
	}
	return 1;
}

/* Dumps a line for listener <l> and proxy <px> to chunk ctx buffer and uses
 * the state from stream connector <sc>. The caller is responsible for clearing
 * chunk ctx buffer if needed. Returns non-zero if it emits anything, zero
 * otherwise.
 */
static int stats_dump_li_line(struct stconn *sc, struct proxy *px, struct listener *l)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct field *line = stat_lines[STATS_DOMAIN_PROXY];
	struct stats_module *mod;
	size_t stats_count = ST_I_PX_MAX;

	memset(line, 0, sizeof(struct field) * stat_cols_len[STATS_DOMAIN_PROXY]);

	if (!stats_fill_li_line(px, l, ctx->flags, line,
	                        ST_I_PX_MAX, NULL))
		return 0;

	list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		void *counters;

		if (!(stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_LI)) {
			stats_count += mod->stats_count;
			continue;
		}

		counters = EXTRA_COUNTERS_GET(l->extra_counters, mod);
		if (!mod->fill_stats(counters, line + stats_count, NULL))
			continue;
		stats_count += mod->stats_count;
	}

	return stats_dump_one_line(line, stats_count, appctx);
}

enum srv_stats_state {
	SRV_STATS_STATE_DOWN = 0,
	SRV_STATS_STATE_DOWN_AGENT,
	SRV_STATS_STATE_GOING_UP,
	SRV_STATS_STATE_UP_GOING_DOWN,
	SRV_STATS_STATE_UP,
	SRV_STATS_STATE_NOLB_GOING_DOWN,
	SRV_STATS_STATE_NOLB,
	SRV_STATS_STATE_DRAIN_GOING_DOWN,
	SRV_STATS_STATE_DRAIN,
	SRV_STATS_STATE_DRAIN_AGENT,
	SRV_STATS_STATE_NO_CHECK,

	SRV_STATS_STATE_COUNT, /* Must be last */
};

static const char *srv_hlt_st[SRV_STATS_STATE_COUNT] = {
	[SRV_STATS_STATE_DOWN]			= "DOWN",
	[SRV_STATS_STATE_DOWN_AGENT]		= "DOWN (agent)",
	[SRV_STATS_STATE_GOING_UP]		= "DOWN %d/%d",
	[SRV_STATS_STATE_UP_GOING_DOWN]		= "UP %d/%d",
	[SRV_STATS_STATE_UP]			= "UP",
	[SRV_STATS_STATE_NOLB_GOING_DOWN]	= "NOLB %d/%d",
	[SRV_STATS_STATE_NOLB]			= "NOLB",
	[SRV_STATS_STATE_DRAIN_GOING_DOWN]	= "DRAIN %d/%d",
	[SRV_STATS_STATE_DRAIN]			= "DRAIN",
	[SRV_STATS_STATE_DRAIN_AGENT]		= "DRAIN (agent)",
	[SRV_STATS_STATE_NO_CHECK]		= "no check"
};

/* Compute server state helper
 */
static void stats_fill_sv_computestate(struct server *sv, struct server *ref,
                                       enum srv_stats_state *state)
{
	if (sv->cur_state == SRV_ST_RUNNING || sv->cur_state == SRV_ST_STARTING) {
		if ((ref->check.state & CHK_ST_ENABLED) &&
		    (ref->check.health < ref->check.rise + ref->check.fall - 1)) {
			*state = SRV_STATS_STATE_UP_GOING_DOWN;
		} else {
			*state = SRV_STATS_STATE_UP;
		}

		if (sv->cur_admin & SRV_ADMF_DRAIN) {
			if (ref->agent.state & CHK_ST_ENABLED)
				*state = SRV_STATS_STATE_DRAIN_AGENT;
			else if (*state == SRV_STATS_STATE_UP_GOING_DOWN)
				*state = SRV_STATS_STATE_DRAIN_GOING_DOWN;
			else
				*state = SRV_STATS_STATE_DRAIN;
		}

		if (*state == SRV_STATS_STATE_UP && !(ref->check.state & CHK_ST_ENABLED)) {
			*state = SRV_STATS_STATE_NO_CHECK;
		}
	}
	else if (sv->cur_state == SRV_ST_STOPPING) {
		if ((!(sv->check.state & CHK_ST_ENABLED) && !sv->track) ||
		    (ref->check.health == ref->check.rise + ref->check.fall - 1)) {
			*state = SRV_STATS_STATE_NOLB;
		} else {
			*state = SRV_STATS_STATE_NOLB_GOING_DOWN;
		}
	}
	else {	/* stopped */
		if ((ref->agent.state & CHK_ST_ENABLED) && !ref->agent.health) {
			*state = SRV_STATS_STATE_DOWN_AGENT;
		} else if ((ref->check.state & CHK_ST_ENABLED) && !ref->check.health) {
			*state = SRV_STATS_STATE_DOWN; /* DOWN */
		} else if ((ref->agent.state & CHK_ST_ENABLED) || (ref->check.state & CHK_ST_ENABLED)) {
			*state = SRV_STATS_STATE_GOING_UP;
		} else {
			*state = SRV_STATS_STATE_DOWN; /* DOWN, unchecked */
		}
	}
}

/* Fill <line> with the backend statistics. <line> is preallocated array of
 * length <len>. If <selected_field> is != NULL, only fill this one. The length
 * of the array must be at least ST_I_PX_MAX. If this length is less than
 * this value, or if the selected field is not implemented for servers, the
 * function returns 0, otherwise, it returns 1. <flags> can take the value
 * STAT_F_SHLGNDS.
 */
int stats_fill_sv_line(struct proxy *px, struct server *sv, int flags,
                       struct field *line, int len,
                       enum stat_idx_px *index)
{
	enum stat_idx_px i = index ? *index : 0;
	struct server *via = sv->track ? sv->track : sv;
	struct server *ref = via;
	enum srv_stats_state state = 0;
	char str[INET6_ADDRSTRLEN];
	struct buffer *out = get_trash_chunk();
	char *fld_status;
	long long srv_samples_counter;
	unsigned int srv_samples_window = TIME_STATS_SAMPLES;

	if (len < ST_I_PX_MAX)
		return 0;

	chunk_reset(out);

	/* compute state for later use */
	if (!index || *index == ST_I_PX_STATUS ||
	    *index == ST_I_PX_CHECK_RISE || *index == ST_I_PX_CHECK_FALL ||
	    *index == ST_I_PX_CHECK_HEALTH || *index == ST_I_PX_HANAFAIL) {
		/* we have "via" which is the tracked server as described in the configuration,
		 * and "ref" which is the checked server and the end of the chain.
		 */
		while (ref->track)
			ref = ref->track;
		stats_fill_sv_computestate(sv, ref, &state);
	}

	/* compue time values for later use */
	if (index == NULL || *index == ST_I_PX_QTIME ||
	    *index == ST_I_PX_CTIME || *index == ST_I_PX_RTIME ||
	    *index == ST_I_PX_TTIME) {
		srv_samples_counter = (px->mode == PR_MODE_HTTP) ? sv->counters.p.http.cum_req : sv->counters.cum_lbconn;
		if (srv_samples_counter < TIME_STATS_SAMPLES && srv_samples_counter > 0)
			srv_samples_window = srv_samples_counter;
	}

	for (; i < ST_I_PX_MAX; i++) {
		const struct stat_col *col = &stat_cols_px[i];
		struct field field = { 0 };

		if (stcol_is_generic(col)) {
			field = me_generate_field(col, i, &sv->obj_type,
			                          &sv->counters, STATS_PX_CAP_SRV,
			                          flags & STAT_F_FMT_FILE);
		}
		else if (!(flags & STAT_F_FMT_FILE)) {
			switch (i) {
			case ST_I_PX_PXNAME:
				field = mkf_str(FO_KEY|FN_NAME|FS_SERVICE, px->id);
				break;
			case ST_I_PX_SVNAME:
				field = mkf_str(FO_KEY|FN_NAME|FS_SERVICE, sv->id);
				break;
			case ST_I_PX_MODE:
				field = mkf_str(FO_CONFIG|FS_SERVICE, proxy_mode_str(px->mode));
				break;
			case ST_I_PX_QCUR:
				field = mkf_u32(0, sv->queue.length);
				break;
			case ST_I_PX_QMAX:
				field = mkf_u32(FN_MAX, sv->counters.nbpend_max);
				break;
			case ST_I_PX_SCUR:
				field = mkf_u32(0, sv->cur_sess);
				break;
			case ST_I_PX_SMAX:
				field = mkf_u32(FN_MAX, sv->counters.cur_sess_max);
				break;
			case ST_I_PX_SLIM:
				if (sv->maxconn)
					field = mkf_u32(FO_CONFIG|FN_LIMIT, sv->maxconn);
				break;
			case ST_I_PX_SRV_ICUR:
				field = mkf_u32(0, sv->curr_idle_conns);
				break;
			case ST_I_PX_SRV_ILIM:
				if (sv->max_idle_conns != -1)
					field = mkf_u32(FO_CONFIG|FN_LIMIT, sv->max_idle_conns);
				break;
			case ST_I_PX_IDLE_CONN_CUR:
				field = mkf_u32(0, sv->curr_idle_nb);
				break;
			case ST_I_PX_SAFE_CONN_CUR:
				field = mkf_u32(0, sv->curr_safe_nb);
				break;
			case ST_I_PX_USED_CONN_CUR:
				field = mkf_u32(0, sv->curr_used_conns);
				break;
			case ST_I_PX_NEED_CONN_EST:
				field = mkf_u32(0, sv->est_need_conns);
				break;
			case ST_I_PX_STATUS:
				fld_status = chunk_newstr(out);
				if (sv->cur_admin & SRV_ADMF_RMAINT)
					chunk_appendf(out, "MAINT (resolution)");
				else if (sv->cur_admin & SRV_ADMF_IMAINT)
					chunk_appendf(out, "MAINT (via %s/%s)", via->proxy->id, via->id);
				else if (sv->cur_admin & SRV_ADMF_MAINT)
					chunk_appendf(out, "MAINT");
				else
					chunk_appendf(out,
						      srv_hlt_st[state],
						      (ref->cur_state != SRV_ST_STOPPED) ? (ref->check.health - ref->check.rise + 1) : (ref->check.health),
						      (ref->cur_state != SRV_ST_STOPPED) ? (ref->check.fall) : (ref->check.rise));

				field = mkf_str(FO_STATUS, fld_status);
				break;
			case ST_I_PX_LASTCHG:
				field = mkf_u32(FN_AGE, ns_to_sec(now_ns) - sv->last_change);
				break;
			case ST_I_PX_WEIGHT:
				field = mkf_u32(FN_AVG, (sv->cur_eweight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv);
				break;
			case ST_I_PX_UWEIGHT:
				field = mkf_u32(FN_AVG, sv->uweight);
				break;
			case ST_I_PX_ACT:
				field = mkf_u32(FO_STATUS, (sv->flags & SRV_F_BACKUP) ? 0 : 1);
				break;
			case ST_I_PX_BCK:
				field = mkf_u32(FO_STATUS, (sv->flags & SRV_F_BACKUP) ? 1 : 0);
				break;
			case ST_I_PX_DOWNTIME:
				if (sv->check.state & CHK_ST_ENABLED)
					field = mkf_u32(FN_COUNTER, srv_downtime(sv));
				break;
			case ST_I_PX_QLIMIT:
				if (sv->maxqueue)
					field = mkf_u32(FO_CONFIG|FS_SERVICE, sv->maxqueue);
				break;
			case ST_I_PX_PID:
				field = mkf_u32(FO_KEY, 1);
				break;
			case ST_I_PX_IID:
				field = mkf_u32(FO_KEY|FS_SERVICE, px->uuid);
				break;
			case ST_I_PX_SID:
				field = mkf_u32(FO_KEY|FS_SERVICE, sv->puid);
				break;
			case ST_I_PX_SRID:
				field = mkf_u32(FN_COUNTER, sv->rid);
				break;
			case ST_I_PX_THROTTLE:
				if (sv->cur_state == SRV_ST_STARTING && !server_is_draining(sv))
					field = mkf_u32(FN_AVG, server_throttle_rate(sv));
				break;
			case ST_I_PX_TRACKED:
				if (sv->track) {
					char *fld_track = chunk_newstr(out);
					chunk_appendf(out, "%s/%s", sv->track->proxy->id, sv->track->id);
					field = mkf_str(FO_CONFIG|FN_NAME|FS_SERVICE, fld_track);
				}
				break;
			case ST_I_PX_TYPE:
				field = mkf_u32(FO_CONFIG|FS_SERVICE, STATS_TYPE_SV);
				break;
			case ST_I_PX_RATE:
				field = mkf_u32(FN_RATE, read_freq_ctr(&sv->sess_per_sec));
				break;
			case ST_I_PX_RATE_MAX:
				field = mkf_u32(FN_MAX, sv->counters.sps_max);
				break;
			case ST_I_PX_CHECK_STATUS:
				if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED) {
					const char *fld_chksts;

					fld_chksts = chunk_newstr(out);
					chunk_strcat(out, "* "); // for check in progress
					chunk_strcat(out, get_check_status_info(sv->check.status));
					if (!(sv->check.state & CHK_ST_INPROGRESS))
						fld_chksts += 2; // skip "* "
					field = mkf_str(FN_OUTPUT, fld_chksts);
				}
				break;
			case ST_I_PX_CHECK_CODE:
				if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED &&
					sv->check.status >= HCHK_STATUS_L57DATA)
					field = mkf_u32(FN_OUTPUT, sv->check.code);
				break;
			case ST_I_PX_CHECK_DURATION:
				if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED &&
					sv->check.status >= HCHK_STATUS_CHECKED)
					field = mkf_u64(FN_DURATION, MAX(sv->check.duration, 0));
				break;
			case ST_I_PX_CHECK_DESC:
				if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_str(FN_OUTPUT, get_check_status_description(sv->check.status));
				break;
			case ST_I_PX_LAST_CHK:
				if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_str(FN_OUTPUT, sv->check.desc);
				break;
			case ST_I_PX_CHECK_RISE:
				if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_u32(FO_CONFIG|FS_SERVICE, ref->check.rise);
				break;
			case ST_I_PX_CHECK_FALL:
				if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_u32(FO_CONFIG|FS_SERVICE, ref->check.fall);
				break;
			case ST_I_PX_CHECK_HEALTH:
				if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_u32(FO_CONFIG|FS_SERVICE, ref->check.health);
				break;
			case ST_I_PX_AGENT_STATUS:
				if  ((sv->agent.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED) {
					const char *fld_chksts;

					fld_chksts = chunk_newstr(out);
					chunk_strcat(out, "* "); // for check in progress
					chunk_strcat(out, get_check_status_info(sv->agent.status));
					if (!(sv->agent.state & CHK_ST_INPROGRESS))
						fld_chksts += 2; // skip "* "
					field = mkf_str(FN_OUTPUT, fld_chksts);
				}
				break;
			case ST_I_PX_AGENT_CODE:
				if  ((sv->agent.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED &&
				     (sv->agent.status >= HCHK_STATUS_L57DATA))
					field = mkf_u32(FN_OUTPUT, sv->agent.code);
				break;
			case ST_I_PX_AGENT_DURATION:
				if ((sv->agent.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_u64(FN_DURATION, sv->agent.duration);
				break;
			case ST_I_PX_AGENT_DESC:
				if ((sv->agent.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_str(FN_OUTPUT, get_check_status_description(sv->agent.status));
				break;
			case ST_I_PX_LAST_AGT:
				if ((sv->agent.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_str(FN_OUTPUT, sv->agent.desc);
				break;
			case ST_I_PX_AGENT_RISE:
				if ((sv->agent.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_u32(FO_CONFIG|FS_SERVICE, sv->agent.rise);
				break;
			case ST_I_PX_AGENT_FALL:
				if ((sv->agent.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_u32(FO_CONFIG|FS_SERVICE, sv->agent.fall);
				break;
			case ST_I_PX_AGENT_HEALTH:
				if ((sv->agent.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED)
					field = mkf_u32(FO_CONFIG|FS_SERVICE, sv->agent.health);
				break;
			case ST_I_PX_REQ_TOT:
				if (px->mode == PR_MODE_HTTP)
					field = mkf_u64(FN_COUNTER, sv->counters.p.http.cum_req);
				break;
			case ST_I_PX_LASTSESS:
				field = mkf_s32(FN_AGE, srv_lastsession(sv));
				break;
			case ST_I_PX_QTIME:
				field = mkf_u32(FN_AVG, swrate_avg(sv->counters.q_time, srv_samples_window));
				break;
			case ST_I_PX_CTIME:
				field = mkf_u32(FN_AVG, swrate_avg(sv->counters.c_time, srv_samples_window));
				break;
			case ST_I_PX_RTIME:
				field = mkf_u32(FN_AVG, swrate_avg(sv->counters.d_time, srv_samples_window));
				break;
			case ST_I_PX_TTIME:
				field = mkf_u32(FN_AVG, swrate_avg(sv->counters.t_time, srv_samples_window));
				break;
			case ST_I_PX_QT_MAX:
				field = mkf_u32(FN_MAX, sv->counters.qtime_max);
				break;
			case ST_I_PX_CT_MAX:
				field = mkf_u32(FN_MAX, sv->counters.ctime_max);
				break;
			case ST_I_PX_RT_MAX:
				field = mkf_u32(FN_MAX, sv->counters.dtime_max);
				break;
			case ST_I_PX_TT_MAX:
				field = mkf_u32(FN_MAX, sv->counters.ttime_max);
				break;
			case ST_I_PX_ADDR:
				if (flags & STAT_F_SHLGNDS) {
					switch (addr_to_str(&sv->addr, str, sizeof(str))) {
						case AF_INET:
							field = mkf_str(FO_CONFIG|FS_SERVICE, chunk_newstr(out));
							chunk_appendf(out, "%s:%d", str, sv->svc_port);
							break;
						case AF_INET6:
							field = mkf_str(FO_CONFIG|FS_SERVICE, chunk_newstr(out));
							chunk_appendf(out, "[%s]:%d", str, sv->svc_port);
							break;
						case AF_UNIX:
							field = mkf_str(FO_CONFIG|FS_SERVICE, "unix");
							break;
						case -1:
							field = mkf_str(FO_CONFIG|FS_SERVICE, chunk_newstr(out));
							chunk_strcat(out, strerror(errno));
							break;
						default: /* address family not supported */
							break;
					}
				}
				break;
			case ST_I_PX_COOKIE:
				if (flags & STAT_F_SHLGNDS && sv->cookie)
					field = mkf_str(FO_CONFIG|FN_NAME|FS_SERVICE, sv->cookie);
				break;
			default:
				/* not used for servers. If a specific field
				 * is requested, return an error. Otherwise continue.
				 */
				if (index)
					return 0;
				continue;
			}
		}
		line[i] = field;
		if (index)
			break;
	}
	return 1;
}

/* Dumps a line for server <sv> and proxy <px> to chunk ctx buffer and uses the
 * state from stream connector <sc>, and server state <state>. The caller is
 * responsible for clearing the chunk ctx buffer if needed. Returns non-zero if
 * it emits anything, zero otherwise.
 */
static int stats_dump_sv_line(struct stconn *sc, struct proxy *px, struct server *sv)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct stats_module *mod;
	struct field *line = stat_lines[STATS_DOMAIN_PROXY];
	size_t stats_count = ST_I_PX_MAX;

	memset(line, 0, sizeof(struct field) * stat_cols_len[STATS_DOMAIN_PROXY]);

	if (!stats_fill_sv_line(px, sv, ctx->flags, line,
	                        ST_I_PX_MAX, NULL))
		return 0;

	list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		void *counters;

		if (stats_get_domain(mod->domain_flags) != STATS_DOMAIN_PROXY)
			continue;

		if (!(stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_SRV)) {
			stats_count += mod->stats_count;
			continue;
		}

		counters = EXTRA_COUNTERS_GET(sv->extra_counters, mod);
		if (!mod->fill_stats(counters, line + stats_count, NULL))
			continue;
		stats_count += mod->stats_count;
	}

	return stats_dump_one_line(line, stats_count, appctx);
}

/* Helper to compute srv values for a given backend
 */
static void stats_fill_be_computesrv(struct proxy *px, int *nbup, int *nbsrv, int *totuw)
{
	int nbup_tmp, nbsrv_tmp, totuw_tmp;
	const struct server *srv;

	nbup_tmp = nbsrv_tmp = totuw_tmp = 0;
	for (srv = px->srv; srv; srv = srv->next) {
		if (srv->cur_state != SRV_ST_STOPPED) {
			nbup_tmp++;
			if (srv_currently_usable(srv) &&
			    (!px->srv_act ^ !(srv->flags & SRV_F_BACKUP)))
				totuw_tmp += srv->uweight;
		}
		nbsrv_tmp++;
	}

	HA_RWLOCK_RDLOCK(LBPRM_LOCK, &px->lbprm.lock);
	if (!px->srv_act && px->lbprm.fbck)
		totuw_tmp = px->lbprm.fbck->uweight;
	HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &px->lbprm.lock);

	/* use tmp variable then assign result to make gcc happy */
	*nbup = nbup_tmp;
	*nbsrv = nbsrv_tmp;
	*totuw = totuw_tmp;
}

/* Fill <line> with the backend statistics. <line> is preallocated array of
 * length <len>. If <index> is != NULL, only fill this one. The length
 * of the array must be at least ST_I_PX_MAX. If this length is less than
 * this value, or if the selected field is not implemented for backends, the
 * function returns 0, otherwise, it returns 1. <flags> can take the value
 * STAT_F_SHLGNDS.
 */
int stats_fill_be_line(struct proxy *px, int flags, struct field *line, int len,
                       enum stat_idx_px *index)
{
	enum stat_idx_px i = index ? *index : 0;
	long long be_samples_counter;
	unsigned int be_samples_window = TIME_STATS_SAMPLES;
	struct buffer *out = get_trash_chunk();
	int nbup, nbsrv, totuw;
	char *fld;

	if (len < ST_I_PX_MAX)
		return 0;

	nbup = nbsrv = totuw = 0;
	/* some srv values compute for later if we either select all fields or
	 * need them for one of the mentioned ones */
	if (!index || *index == ST_I_PX_STATUS ||
	    *index == ST_I_PX_UWEIGHT)
		stats_fill_be_computesrv(px, &nbup, &nbsrv, &totuw);

	/* same here but specific to time fields */
	if (!index || *index == ST_I_PX_QTIME ||
	    *index == ST_I_PX_CTIME || *index == ST_I_PX_RTIME ||
	    *index == ST_I_PX_TTIME) {
		be_samples_counter = (px->mode == PR_MODE_HTTP) ? px->be_counters.p.http.cum_req : px->be_counters.cum_lbconn;
		if (be_samples_counter < TIME_STATS_SAMPLES && be_samples_counter > 0)
			be_samples_window = be_samples_counter;
	}

	for (; i < ST_I_PX_MAX; i++) {
		const struct stat_col *col = &stat_cols_px[i];
		struct field field = { 0 };

		if (stcol_is_generic(col)) {
			field = me_generate_field(col, i, &px->obj_type,
			                          &px->be_counters, STATS_PX_CAP_BE,
			                          flags & STAT_F_FMT_FILE);
		}
		else if (!(flags & STAT_F_FMT_FILE)) {
			switch (i) {
			case ST_I_PX_PXNAME:
				field = mkf_str(FO_KEY|FN_NAME|FS_SERVICE, px->id);
				break;
			case ST_I_PX_SVNAME:
				field = mkf_str(FO_KEY|FN_NAME|FS_SERVICE, "BACKEND");
				break;
			case ST_I_PX_MODE:
				field = mkf_str(FO_CONFIG|FS_SERVICE, proxy_mode_str(px->mode));
				break;
			case ST_I_PX_QCUR:
				field = mkf_u32(0, px->queue.length);
				break;
			case ST_I_PX_QMAX:
				field = mkf_u32(FN_MAX, px->be_counters.nbpend_max);
				break;
			case ST_I_PX_SCUR:
				field = mkf_u32(0, px->beconn);
				break;
			case ST_I_PX_SMAX:
				field = mkf_u32(FN_MAX, px->be_counters.conn_max);
				break;
			case ST_I_PX_SLIM:
				field = mkf_u32(FO_CONFIG|FN_LIMIT, px->fullconn);
				break;
			case ST_I_PX_STATUS:
				fld = chunk_newstr(out);
				chunk_appendf(out, "%s", (px->lbprm.tot_weight > 0 || !px->srv) ? "UP" : "DOWN");
				if (flags & (STAT_F_HIDE_MAINT|STAT_F_HIDE_DOWN))
					chunk_appendf(out, " (%d/%d)", nbup, nbsrv);
				field = mkf_str(FO_STATUS, fld);
				break;
			case ST_I_PX_AGG_SRV_CHECK_STATUS:   // DEPRECATED
			case ST_I_PX_AGG_SRV_STATUS:
				field = mkf_u32(FN_GAUGE, 0);
				break;
			case ST_I_PX_AGG_CHECK_STATUS:
				field = mkf_u32(FN_GAUGE, 0);
				break;
			case ST_I_PX_WEIGHT:
				field = mkf_u32(FN_AVG, (px->lbprm.tot_weight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv);
				break;
			case ST_I_PX_UWEIGHT:
				field = mkf_u32(FN_AVG, totuw);
				break;
			case ST_I_PX_ACT:
				field = mkf_u32(0, px->srv_act);
				break;
			case ST_I_PX_BCK:
				field = mkf_u32(0, px->srv_bck);
				break;
			case ST_I_PX_LASTCHG:
				field = mkf_u32(FN_AGE, ns_to_sec(now_ns) - px->last_change);
				break;
			case ST_I_PX_DOWNTIME:
				if (px->srv)
					field = mkf_u32(FN_COUNTER, be_downtime(px));
				break;
			case ST_I_PX_PID:
				field = mkf_u32(FO_KEY, 1);
				break;
			case ST_I_PX_IID:
				field = mkf_u32(FO_KEY|FS_SERVICE, px->uuid);
				break;
			case ST_I_PX_SID:
				field = mkf_u32(FO_KEY|FS_SERVICE, 0);
				break;
			case ST_I_PX_TYPE:
				field = mkf_u32(FO_CONFIG|FS_SERVICE, STATS_TYPE_BE);
				break;
			case ST_I_PX_RATE:
				field = mkf_u32(0, read_freq_ctr(&px->be_sess_per_sec));
				break;
			case ST_I_PX_RATE_MAX:
				field = mkf_u32(0, px->be_counters.sps_max);
				break;
			case ST_I_PX_COOKIE:
				if (flags & STAT_F_SHLGNDS && px->cookie_name)
					field = mkf_str(FO_CONFIG|FN_NAME|FS_SERVICE, px->cookie_name);
				break;
			case ST_I_PX_ALGO:
				if (flags & STAT_F_SHLGNDS)
					field = mkf_str(FO_CONFIG|FS_SERVICE, backend_lb_algo_str(px->lbprm.algo & BE_LB_ALGO));
				break;
			case ST_I_PX_REQ_TOT:
				if (px->mode == PR_MODE_HTTP)
					field = mkf_u64(FN_COUNTER, px->be_counters.p.http.cum_req);
				break;
			case ST_I_PX_LASTSESS:
				field = mkf_s32(FN_AGE, be_lastsession(px));
				break;
			case ST_I_PX_QTIME:
				field = mkf_u32(FN_AVG, swrate_avg(px->be_counters.q_time, be_samples_window));
				break;
			case ST_I_PX_CTIME:
				field = mkf_u32(FN_AVG, swrate_avg(px->be_counters.c_time, be_samples_window));
				break;
			case ST_I_PX_RTIME:
				field = mkf_u32(FN_AVG, swrate_avg(px->be_counters.d_time, be_samples_window));
				break;
			case ST_I_PX_TTIME:
				field = mkf_u32(FN_AVG, swrate_avg(px->be_counters.t_time, be_samples_window));
				break;
			case ST_I_PX_QT_MAX:
				field = mkf_u32(FN_MAX, px->be_counters.qtime_max);
				break;
			case ST_I_PX_CT_MAX:
				field = mkf_u32(FN_MAX, px->be_counters.ctime_max);
				break;
			case ST_I_PX_RT_MAX:
				field = mkf_u32(FN_MAX, px->be_counters.dtime_max);
				break;
			case ST_I_PX_TT_MAX:
				field = mkf_u32(FN_MAX, px->be_counters.ttime_max);
				break;
			default:
				/* not used for backends. If a specific field
				 * is requested, return an error. Otherwise continue.
				 */
				if (index)
					return 0;
				continue;
			}
		}
		line[i] = field;
		if (index)
			break;
	}
	return 1;
}

/* Dumps a line for backend <px> to chunk ctx buffer and uses the state from
 * stream interface <si>. The caller is responsible for clearing chunk buffer
 * if needed. Returns non-zero if it emits anything, zero otherwise.
 */
static int stats_dump_be_line(struct stconn *sc, struct proxy *px)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct field *line = stat_lines[STATS_DOMAIN_PROXY];
	struct stats_module *mod;
	size_t stats_count = ST_I_PX_MAX;

	if (!(px->cap & PR_CAP_BE))
		return 0;

	if ((ctx->flags & STAT_F_BOUND) && !(ctx->type & (1 << STATS_TYPE_BE)))
		return 0;

	memset(line, 0, sizeof(struct field) * stat_cols_len[STATS_DOMAIN_PROXY]);

	if (!stats_fill_be_line(px, ctx->flags, line, ST_I_PX_MAX, NULL))
		return 0;

	list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		struct extra_counters *counters;

		if (stats_get_domain(mod->domain_flags) != STATS_DOMAIN_PROXY)
			continue;

		if (!(stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_BE)) {
			stats_count += mod->stats_count;
			continue;
		}

		counters = EXTRA_COUNTERS_GET(px->extra_counters_be, mod);
		if (!mod->fill_stats(counters, line + stats_count, NULL))
			continue;
		stats_count += mod->stats_count;
	}

	return stats_dump_one_line(line, stats_count, appctx);
}

/*
 * Dumps statistics for a proxy. The output is sent to the stream connector's
 * input buffer. Returns 0 if it had to stop dumping data because of lack of
 * buffer space, or non-zero if everything completed. This function is used
 * both by the CLI and the HTTP entry points, and is able to dump the output
 * in HTML or CSV formats.
 */
int stats_dump_proxy_to_buffer(struct stconn *sc, struct buffer *buf, struct htx *htx,
			       struct proxy *px)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;
	struct server *sv, *svs;	/* server and server-state, server-state=server or server->track */
	struct listener *l;
	struct uri_auth *uri = NULL;
	int current_field;
	int px_st = ctx->px_st;

	if (ctx->http_px)
		uri = ctx->http_px->uri_auth;
	chunk_reset(chk);
more:
	current_field = ctx->field;

	switch (ctx->px_st) {
	case STAT_PX_ST_INIT:
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
				if (strcmp(scope->px_id, ".") == 0 && px == ctx->http_px)
					break;
				scope = scope->next;
			}

			/* proxy name not found : don't dump anything */
			if (scope == NULL)
				return 1;
		}

		/* if the user has requested a limited output and the proxy
		 * name does not match, skip it.
		 */
		if (ctx->scope_len) {
			const char *scope_ptr = stats_scope_ptr(appctx);

			if (strnistr(px->id, strlen(px->id), scope_ptr, ctx->scope_len) == NULL)
				return 1;
		}

		if ((ctx->flags & STAT_F_BOUND) &&
		    (ctx->iid != -1) &&
		    (px->uuid != ctx->iid))
			return 1;

		ctx->px_st = STAT_PX_ST_TH;
		__fallthrough;

	case STAT_PX_ST_TH:
		if (ctx->flags & STAT_F_FMT_HTML) {
			stats_dump_html_px_hdr(sc, px);
			if (!stats_putchk(appctx, buf, htx))
				goto full;
		}

		ctx->px_st = STAT_PX_ST_FE;
		__fallthrough;

	case STAT_PX_ST_FE:
		/* print the frontend */
		if (stats_dump_fe_line(sc, px)) {
			if (!stats_putchk(appctx, buf, htx))
				goto full;
			ctx->flags |= STAT_F_STARTED;
			if (ctx->field)
				goto more;
		}

		current_field = 0;
		ctx->obj2 = px->conf.listeners.n;
		ctx->px_st = STAT_PX_ST_LI;
		__fallthrough;

	case STAT_PX_ST_LI:
		/* obj2 points to listeners list as initialized above */
		for (; ctx->obj2 != &px->conf.listeners; ctx->obj2 = l->by_fe.n) {
			if (stats_is_full(appctx, buf, htx))
				goto full;

			l = LIST_ELEM(ctx->obj2, struct listener *, by_fe);
			if (!l->counters)
				continue;

			if (ctx->flags & STAT_F_BOUND) {
				if (!(ctx->type & (1 << STATS_TYPE_SO)))
					break;

				if (ctx->sid != -1 && l->luid != ctx->sid)
					continue;
			}

			/* print the frontend */
			if (stats_dump_li_line(sc, px, l)) {
				if (!stats_putchk(appctx, buf, htx))
					goto full;
				ctx->flags |= STAT_F_STARTED;
				if (ctx->field)
					goto more;
			}
			current_field = 0;
		}

		ctx->obj2 = px->srv; /* may be NULL */
		ctx->px_st = STAT_PX_ST_SV;
		__fallthrough;

	case STAT_PX_ST_SV:
		/* check for dump resumption */
		if (px_st == STAT_PX_ST_SV) {
			struct server *cur = ctx->obj2;

			/* re-entrant dump */
			BUG_ON(!cur);
			if (cur->flags & SRV_F_DELETED) {
				/* the server could have been marked as deleted
				 * between two dumping attempts, skip it.
				 */
				cur = cur->next;
			}
			srv_drop(ctx->obj2); /* drop old srv taken on last dumping attempt */
			ctx->obj2 = cur; /* could be NULL */
			/* back to normal */
		}

		/* obj2 points to servers list as initialized above.
		 *
		 * A server may be removed during the stats dumping.
		 * Temporarily increment its refcount to prevent its
		 * anticipated cleaning. Call srv_drop() to release it.
		 */
		for (; ctx->obj2 != NULL;
		       ctx->obj2 = srv_drop(sv)) {

			sv = ctx->obj2;
			srv_take(sv);

			if (stats_is_full(appctx, buf, htx))
				goto full;

			if (ctx->flags & STAT_F_BOUND) {
				if (!(ctx->type & (1 << STATS_TYPE_SV))) {
					srv_drop(sv);
					break;
				}

				if (ctx->sid != -1 && sv->puid != ctx->sid)
					continue;
			}

			/* do not report disabled servers */
			if (ctx->flags & STAT_F_HIDE_MAINT &&
			    sv->cur_admin & SRV_ADMF_MAINT) {
				continue;
			}

			svs = sv;
			while (svs->track)
				svs = svs->track;

			/* do not report servers which are DOWN and not changing state */
			if ((ctx->flags & STAT_F_HIDE_DOWN) &&
			    ((sv->cur_admin & SRV_ADMF_MAINT) || /* server is in maintenance */
			     (sv->cur_state == SRV_ST_STOPPED && /* server is down */
			      (!((svs->agent.state | svs->check.state) & CHK_ST_ENABLED) ||
			       ((svs->agent.state & CHK_ST_ENABLED) && !svs->agent.health) ||
			       ((svs->check.state & CHK_ST_ENABLED) && !svs->check.health))))) {
				continue;
			}

			if (stats_dump_sv_line(sc, px, sv)) {
				if (!stats_putchk(appctx, buf, htx))
					goto full;
				ctx->flags |= STAT_F_STARTED;
				if (ctx->field)
					goto more;
			}
			current_field = 0;
		} /* for sv */

		ctx->px_st = STAT_PX_ST_BE;
		__fallthrough;

	case STAT_PX_ST_BE:
		/* print the backend */
		if (stats_dump_be_line(sc, px)) {
			if (!stats_putchk(appctx, buf, htx))
				goto full;
			ctx->flags |= STAT_F_STARTED;
			if (ctx->field)
				goto more;
		}

		current_field = 0;
		ctx->px_st = STAT_PX_ST_END;
		__fallthrough;

	case STAT_PX_ST_END:
		if (ctx->flags & STAT_F_FMT_HTML) {
			stats_dump_html_px_end(sc, px);
			if (!stats_putchk(appctx, buf, htx))
				goto full;
		}

		ctx->px_st = STAT_PX_ST_FIN;
		__fallthrough;

	case STAT_PX_ST_FIN:
		return 1;

	default:
		/* unknown state, we should put an abort() here ! */
		return 1;
	}

  full:
	/* restore previous field */
	ctx->field = current_field;
	return 0;
}

/* Uses <appctx.ctx.stats.obj1> as a pointer to the current proxy and <obj2> as
 * a pointer to the current server/listener.
 */
static int stats_dump_proxies(struct stconn *sc, struct buffer *buf,
                              struct htx *htx)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct proxy *px;

	/* dump proxies */
	while (ctx->obj1) {
		if (stats_is_full(appctx, buf, htx))
			goto full;

		px = ctx->obj1;
		/* Skip the global frontend proxies and non-networked ones.
		 * Also skip proxies that were disabled in the configuration
		 * This change allows retrieving stats from "old" proxies after a reload.
		 */
		if (!(px->flags & PR_FL_DISABLED) && px->uuid > 0 &&
		    (px->cap & (PR_CAP_FE | PR_CAP_BE)) && !(px->cap & PR_CAP_INT)) {
			if (stats_dump_proxy_to_buffer(sc, buf, htx, px) == 0)
				return 0;
		}

		ctx->obj1 = px->next;
		ctx->px_st = STAT_PX_ST_INIT;
		ctx->field = 0;
	}

	return 1;

  full:
	return 0;
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
	uint64_t glob_out_bytes, glob_spl_bytes, glob_out_b32;
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
	glob_out_bytes = glob_spl_bytes = glob_out_b32 = 0;
	for (thr = 0; thr < global.nbthread; thr++) {
		glob_out_bytes += HA_ATOMIC_LOAD(&ha_thread_ctx[thr].out_bytes);
		glob_spl_bytes += HA_ATOMIC_LOAD(&ha_thread_ctx[thr].spliced_out_bytes);
		glob_out_b32   += read_freq_ctr(&ha_thread_ctx[thr].out_32bps);
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
	struct proxy *px;
	struct server *sv;
	struct listener *li;
	struct stats_module *mod;
	int clrall = 0;

	if (strcmp(args[2], "all") == 0)
		clrall = 1;

	/* check permissions */
	if (!cli_has_level(appctx, ACCESS_LVL_OPER) ||
	    (clrall && !cli_has_level(appctx, ACCESS_LVL_ADMIN)))
		return 1;

	for (px = proxies_list; px; px = px->next) {
		if (clrall) {
			memset(&px->be_counters, 0, sizeof(px->be_counters));
			memset(&px->fe_counters, 0, sizeof(px->fe_counters));
		}
		else {
			px->be_counters.conn_max = 0;
			px->be_counters.p.http.rps_max = 0;
			px->be_counters.sps_max = 0;
			px->be_counters.cps_max = 0;
			px->be_counters.nbpend_max = 0;
			px->be_counters.qtime_max = 0;
			px->be_counters.ctime_max = 0;
			px->be_counters.dtime_max = 0;
			px->be_counters.ttime_max = 0;

			px->fe_counters.conn_max = 0;
			px->fe_counters.p.http.rps_max = 0;
			px->fe_counters.sps_max = 0;
			px->fe_counters.cps_max = 0;
		}

		for (sv = px->srv; sv; sv = sv->next)
			if (clrall)
				memset(&sv->counters, 0, sizeof(sv->counters));
			else {
				sv->counters.cur_sess_max = 0;
				sv->counters.nbpend_max = 0;
				sv->counters.sps_max = 0;
				sv->counters.qtime_max = 0;
				sv->counters.ctime_max = 0;
				sv->counters.dtime_max = 0;
				sv->counters.ttime_max = 0;
			}

		list_for_each_entry(li, &px->conf.listeners, by_fe)
			if (li->counters) {
				if (clrall)
					memset(li->counters, 0, sizeof(*li->counters));
				else
					li->counters->conn_max = 0;
			}
	}

	global.cps_max = 0;
	global.sps_max = 0;
	global.ssl_max = 0;
	global.ssl_fe_keys_max = 0;
	global.ssl_be_keys_max = 0;

	list_for_each_entry(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		if (!mod->clearable && !clrall)
			continue;

		for (px = proxies_list; px; px = px->next) {
			enum stats_domain_px_cap mod_cap = stats_px_get_cap(mod->domain_flags);

			if (px->cap & PR_CAP_FE && mod_cap & STATS_PX_CAP_FE) {
				EXTRA_COUNTERS_INIT(px->extra_counters_fe,
				                    mod,
				                    mod->counters,
				                    mod->counters_size);
			}

			if (px->cap & PR_CAP_BE && mod_cap & STATS_PX_CAP_BE) {
				EXTRA_COUNTERS_INIT(px->extra_counters_be,
				                    mod,
				                    mod->counters,
				                    mod->counters_size);
			}

			if (mod_cap & STATS_PX_CAP_SRV) {
				for (sv = px->srv; sv; sv = sv->next) {
					EXTRA_COUNTERS_INIT(sv->extra_counters,
				                            mod,
					                    mod->counters,
					                    mod->counters_size);
				}
			}

			if (mod_cap & STATS_PX_CAP_LI) {
				list_for_each_entry(li, &px->conf.listeners, by_fe) {
					EXTRA_COUNTERS_INIT(li->extra_counters,
				                            mod,
					                    mod->counters,
					                    mod->counters_size);
				}
			}
		}
	}

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

	if (ctx->px_st == STAT_PX_ST_SV)
		srv_drop(ctx->obj2);
}

static int cli_io_handler_dump_json_schema(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	ctx->chunk = b_make(trash.area, trash.size, 0, 0);
	return stats_dump_json_schema_to_buffer(appctx);
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
	{ { "show", "schema",  "json", NULL }, "show schema json                        : report schema used for stats",                    NULL, cli_io_handler_dump_json_schema, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
