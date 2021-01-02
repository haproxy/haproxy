/*
 * Promex is a Prometheus exporter for HAProxy
 *
 * It is highly inspired by the official Prometheus exporter.
 * See: https://github.com/prometheus/haproxy_exporter
 *
 * Copyright 2019 Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/action-t.h>
#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/backend.h>
#include <haproxy/cfgparse.h>
#include <haproxy/compression.h>
#include <haproxy/dns.h>
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/pipe.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stats.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>

/* Prometheus exporter applet states (appctx->st0) */
enum {
        PROMEX_ST_INIT = 0,  /* initialized */
        PROMEX_ST_HEAD,      /* send headers before dump */
        PROMEX_ST_DUMP,      /* dumping stats */
        PROMEX_ST_DONE,      /* finished */
        PROMEX_ST_END,       /* treatment terminated */
};

/* Prometheus exporter dumper states (appctx->st1) */
enum {
        PROMEX_DUMPER_INIT = 0, /* initialized */
        PROMEX_DUMPER_GLOBAL,   /* dump metrics of globals */
        PROMEX_DUMPER_FRONT,    /* dump metrics of frontend proxies */
        PROMEX_DUMPER_BACK,     /* dump metrics of backend proxies */
        PROMEX_DUMPER_LI,       /* dump metrics of listeners */
        PROMEX_DUMPER_SRV,      /* dump metrics of servers */
	PROMEX_DUMPER_DONE,     /* finished */
};

/* Prometheus exporter flags (appctx->ctx.stats.flags) */
#define PROMEX_FL_METRIC_HDR    0x00000001
#define PROMEX_FL_INFO_METRIC   0x00000002
#define PROMEX_FL_STATS_METRIC  0x00000004
#define PROMEX_FL_SCOPE_GLOBAL  0x00000008
#define PROMEX_FL_SCOPE_FRONT   0x00000010
#define PROMEX_FL_SCOPE_BACK    0x00000020
#define PROMEX_FL_SCOPE_SERVER  0x00000040
#define PROMEX_FL_NO_MAINT_SRV  0x00000080

#define PROMEX_FL_SCOPE_ALL (PROMEX_FL_SCOPE_GLOBAL|PROMEX_FL_SCOPE_FRONT|PROMEX_FL_SCOPE_BACK|PROMEX_FL_SCOPE_SERVER)

/* The max length for metrics name. It is a hard limit but it should be
 * enough.
 */
#define PROMEX_MAX_NAME_LEN 128

/* The expected max length for a metric dump, including its header lines. It is
 * just a soft limit to avoid extra work. We don't try to dump a metric if less
 * than this size is available in the HTX.
 */
#define PROMEX_MAX_METRIC_LENGTH 512

/* Matrix used to dump global metrics. Each metric points to the next one to be
 * processed or 0 to stop the dump. */
const int promex_global_metrics[INF_TOTAL_FIELDS] = {
	[INF_NAME]                           = INF_NBTHREAD,
	[INF_VERSION]                        = 0,
	[INF_RELEASE_DATE]                   = 0,
	[INF_NBTHREAD]                       = INF_NBPROC,
	[INF_NBPROC]                         = INF_PROCESS_NUM,
	[INF_PROCESS_NUM]                    = INF_UPTIME_SEC,
	[INF_PID]                            = 0,
	[INF_UPTIME]                         = 0,
	[INF_UPTIME_SEC]                     = INF_MEMMAX_MB,
	[INF_MEMMAX_MB]                      = INF_POOL_ALLOC_MB,
	[INF_POOL_ALLOC_MB]                  = INF_POOL_USED_MB,
	[INF_POOL_USED_MB]                   = INF_POOL_FAILED,
	[INF_POOL_FAILED]                    = INF_ULIMIT_N,
	[INF_ULIMIT_N]                       = INF_MAXSOCK,
	[INF_MAXSOCK]                        = INF_MAXCONN,
	[INF_MAXCONN]                        = INF_HARD_MAXCONN,
	[INF_HARD_MAXCONN]                   = INF_CURR_CONN,
	[INF_CURR_CONN]                      = INF_CUM_CONN,
	[INF_CUM_CONN]                       = INF_CUM_REQ,
	[INF_CUM_REQ]                        = INF_MAX_SSL_CONNS,
	[INF_MAX_SSL_CONNS]                  = INF_CURR_SSL_CONNS,
	[INF_CURR_SSL_CONNS]                 = INF_CUM_SSL_CONNS,
	[INF_CUM_SSL_CONNS]                  = INF_MAXPIPES,
	[INF_MAXPIPES]                       = INF_PIPES_USED,
	[INF_PIPES_USED]                     = INF_PIPES_FREE,
	[INF_PIPES_FREE]                     = INF_CONN_RATE,
	[INF_CONN_RATE]                      = INF_CONN_RATE_LIMIT,
	[INF_CONN_RATE_LIMIT]                = INF_MAX_CONN_RATE,
	[INF_MAX_CONN_RATE]                  = INF_SESS_RATE,
	[INF_SESS_RATE]                      = INF_SESS_RATE_LIMIT,
	[INF_SESS_RATE_LIMIT]                = INF_MAX_SESS_RATE,
	[INF_MAX_SESS_RATE]                  = INF_SSL_RATE,
	[INF_SSL_RATE]                       = INF_SSL_RATE_LIMIT,
	[INF_SSL_RATE_LIMIT]                 = INF_MAX_SSL_RATE,
	[INF_MAX_SSL_RATE]                   = INF_SSL_FRONTEND_KEY_RATE,
	[INF_SSL_FRONTEND_KEY_RATE]          = INF_SSL_FRONTEND_MAX_KEY_RATE,
	[INF_SSL_FRONTEND_MAX_KEY_RATE]      = INF_SSL_FRONTEND_SESSION_REUSE_PCT,
	[INF_SSL_FRONTEND_SESSION_REUSE_PCT] = INF_SSL_BACKEND_KEY_RATE,
	[INF_SSL_BACKEND_KEY_RATE]           = INF_SSL_BACKEND_MAX_KEY_RATE,
	[INF_SSL_BACKEND_MAX_KEY_RATE]       = INF_SSL_CACHE_LOOKUPS,
	[INF_SSL_CACHE_LOOKUPS]              = INF_SSL_CACHE_MISSES,
	[INF_SSL_CACHE_MISSES]               = INF_COMPRESS_BPS_IN,
	[INF_COMPRESS_BPS_IN]                = INF_COMPRESS_BPS_OUT,
	[INF_COMPRESS_BPS_OUT]               = INF_COMPRESS_BPS_RATE_LIM,
	[INF_COMPRESS_BPS_RATE_LIM]          = INF_ZLIB_MEM_USAGE,
	[INF_ZLIB_MEM_USAGE]                 = INF_MAX_ZLIB_MEM_USAGE,
	[INF_MAX_ZLIB_MEM_USAGE]             = INF_TASKS,
	[INF_TASKS]                          = INF_RUN_QUEUE,
	[INF_RUN_QUEUE]                      = INF_IDLE_PCT,
	[INF_IDLE_PCT]                       = INF_STOPPING,
	[INF_NODE]                           = 0,
	[INF_DESCRIPTION]                    = 0,
	[INF_STOPPING]                       = INF_JOBS,
	[INF_JOBS]                           = INF_UNSTOPPABLE_JOBS,
	[INF_UNSTOPPABLE_JOBS]               = INF_LISTENERS,
	[INF_LISTENERS]                      = INF_ACTIVE_PEERS,
	[INF_ACTIVE_PEERS]                   = INF_CONNECTED_PEERS,
	[INF_CONNECTED_PEERS]                = INF_DROPPED_LOGS,
	[INF_DROPPED_LOGS]                   = INF_BUSY_POLLING,
	[INF_BUSY_POLLING]                   = INF_FAILED_RESOLUTIONS,
	[INF_FAILED_RESOLUTIONS]             = INF_TOTAL_BYTES_OUT,
	[INF_TOTAL_BYTES_OUT]                = INF_TOTAL_SPLICED_BYTES_OUT,
	[INF_TOTAL_SPLICED_BYTES_OUT]        = INF_BYTES_OUT_RATE,
	[INF_BYTES_OUT_RATE]                 = 0,
	[INF_DEBUG_COMMANDS_ISSUED]          = 0,
};

/* Matrix used to dump frontend metrics. Each metric points to the next one to be
 * processed or 0 to stop the dump. */
const int promex_front_metrics[ST_F_TOTAL_FIELDS] = {
	[ST_F_PXNAME]         = ST_F_STATUS,
	[ST_F_SVNAME]         = 0,
	[ST_F_QCUR]           = 0,
	[ST_F_QMAX]           = 0,
	[ST_F_SCUR]           = ST_F_SMAX,
	[ST_F_SMAX]           = ST_F_SLIM,
	[ST_F_SLIM]           = ST_F_STOT,
	[ST_F_STOT]           = ST_F_RATE_LIM,
	[ST_F_BIN]            = ST_F_BOUT,
	[ST_F_BOUT]           = ST_F_DREQ,
	[ST_F_DREQ]           = ST_F_DRESP,
	[ST_F_DRESP]          = ST_F_EREQ,
	[ST_F_EREQ]           = ST_F_DCON,
	[ST_F_ECON]           = 0,
	[ST_F_ERESP]          = 0,
	[ST_F_WRETR]          = 0,
	[ST_F_WREDIS]         = 0,
	[ST_F_STATUS]         = ST_F_SCUR,
	[ST_F_WEIGHT]         = 0,
	[ST_F_ACT]            = 0,
	[ST_F_BCK]            = 0,
	[ST_F_CHKFAIL]        = 0,
	[ST_F_CHKDOWN]        = 0,
	[ST_F_LASTCHG]        = 0,
	[ST_F_DOWNTIME]       = 0,
	[ST_F_QLIMIT]         = 0,
	[ST_F_PID]            = 0,
	[ST_F_IID]            = 0,
	[ST_F_SID]            = 0,
	[ST_F_THROTTLE]       = 0,
	[ST_F_LBTOT]          = 0,
	[ST_F_TRACKED]        = 0,
	[ST_F_TYPE]           = 0,
	[ST_F_RATE]           = 0,
	[ST_F_RATE_LIM]       = ST_F_RATE_MAX,
	[ST_F_RATE_MAX]       = ST_F_CONN_RATE_MAX,
	[ST_F_CHECK_STATUS]   = 0,
	[ST_F_CHECK_CODE]     = 0,
	[ST_F_CHECK_DURATION] = 0,
	[ST_F_HRSP_1XX]       = ST_F_HRSP_2XX,
	[ST_F_HRSP_2XX]       = ST_F_HRSP_3XX,
	[ST_F_HRSP_3XX]       = ST_F_HRSP_4XX,
	[ST_F_HRSP_4XX]       = ST_F_HRSP_5XX,
	[ST_F_HRSP_5XX]       = ST_F_HRSP_OTHER,
	[ST_F_HRSP_OTHER]     = ST_F_INTERCEPTED,
	[ST_F_HANAFAIL]       = 0,
	[ST_F_REQ_RATE]       = 0,
	[ST_F_REQ_RATE_MAX]   = ST_F_REQ_TOT,
	[ST_F_REQ_TOT]        = ST_F_HRSP_1XX,
	[ST_F_CLI_ABRT]       = 0,
	[ST_F_SRV_ABRT]       = 0,
	[ST_F_COMP_IN]        = ST_F_COMP_OUT,
	[ST_F_COMP_OUT]       = ST_F_COMP_BYP,
	[ST_F_COMP_BYP]       = ST_F_COMP_RSP,
	[ST_F_COMP_RSP]       = 0,
	[ST_F_LASTSESS]       = 0,
	[ST_F_LAST_CHK]       = 0,
	[ST_F_LAST_AGT]       = 0,
	[ST_F_QTIME]          = 0,
	[ST_F_CTIME]          = 0,
	[ST_F_RTIME]          = 0,
	[ST_F_TTIME]          = 0,
	[ST_F_AGENT_STATUS]   = 0,
	[ST_F_AGENT_CODE]     = 0,
	[ST_F_AGENT_DURATION] = 0,
	[ST_F_CHECK_DESC]     = 0,
	[ST_F_AGENT_DESC]     = 0,
	[ST_F_CHECK_RISE]     = 0,
	[ST_F_CHECK_FALL]     = 0,
	[ST_F_CHECK_HEALTH]   = 0,
	[ST_F_AGENT_RISE]     = 0,
	[ST_F_AGENT_FALL]     = 0,
	[ST_F_AGENT_HEALTH]   = 0,
	[ST_F_ADDR]           = 0,
	[ST_F_COOKIE]         = 0,
	[ST_F_MODE]           = 0,
	[ST_F_ALGO]           = 0,
	[ST_F_CONN_RATE]      = 0,
	[ST_F_CONN_RATE_MAX]  = ST_F_CONN_TOT,
	[ST_F_CONN_TOT]       = ST_F_BIN,
	[ST_F_INTERCEPTED]    = ST_F_CACHE_LOOKUPS,
	[ST_F_DCON]           = ST_F_DSES,
	[ST_F_DSES]           = ST_F_WREW,
	[ST_F_WREW]           = ST_F_EINT,
	[ST_F_CONNECT]        = 0,
	[ST_F_REUSE]          = 0,
	[ST_F_CACHE_LOOKUPS]  = ST_F_CACHE_HITS,
	[ST_F_CACHE_HITS]     = ST_F_COMP_IN,
	[ST_F_SRV_ICUR]       = 0,
	[ST_F_SRV_ILIM]       = 0,
	[ST_F_QT_MAX]         = 0,
	[ST_F_CT_MAX]         = 0,
	[ST_F_RT_MAX]         = 0,
	[ST_F_TT_MAX]         = 0,
	[ST_F_EINT]           = ST_F_REQ_RATE_MAX,
	[ST_F_IDLE_CONN_CUR]  = 0,
	[ST_F_SAFE_CONN_CUR]  = 0,
	[ST_F_USED_CONN_CUR]  = 0,
	[ST_F_NEED_CONN_EST]  = 0,
};

/* Matrix used to dump backend metrics. Each metric points to the next one to be
 * processed or 0 to stop the dump. */
const int promex_back_metrics[ST_F_TOTAL_FIELDS] = {
	[ST_F_PXNAME]         = ST_F_STATUS,
	[ST_F_SVNAME]         = 0,
	[ST_F_QCUR]           = ST_F_QMAX,
	[ST_F_QMAX]           = ST_F_CONNECT,
	[ST_F_SCUR]           = ST_F_SMAX,
	[ST_F_SMAX]           = ST_F_SLIM,
	[ST_F_SLIM]           = ST_F_STOT,
	[ST_F_STOT]           = ST_F_RATE_MAX,
	[ST_F_BIN]            = ST_F_BOUT,
	[ST_F_BOUT]           = ST_F_QTIME,
	[ST_F_DREQ]           = ST_F_DRESP,
	[ST_F_DRESP]          = ST_F_ECON,
	[ST_F_EREQ]           = 0,
	[ST_F_ECON]           = ST_F_ERESP,
	[ST_F_ERESP]          = ST_F_WRETR,
	[ST_F_WRETR]          = ST_F_WREDIS,
	[ST_F_WREDIS]         = ST_F_WREW,
	[ST_F_STATUS]         = ST_F_SCUR,
	[ST_F_WEIGHT]         = ST_F_ACT,
	[ST_F_ACT]            = ST_F_BCK,
	[ST_F_BCK]            = ST_F_CHKDOWN,
	[ST_F_CHKFAIL]        = 0,
	[ST_F_CHKDOWN]        = ST_F_LASTCHG,
	[ST_F_LASTCHG]        = ST_F_DOWNTIME,
	[ST_F_DOWNTIME]       = ST_F_LBTOT,
	[ST_F_QLIMIT]         = 0,
	[ST_F_PID]            = 0,
	[ST_F_IID]            = 0,
	[ST_F_SID]            = 0,
	[ST_F_THROTTLE]       = 0,
	[ST_F_LBTOT]          = ST_F_REQ_TOT,
	[ST_F_TRACKED]        = 9,
	[ST_F_TYPE]           = 0,
	[ST_F_RATE]           = 0,
	[ST_F_RATE_LIM]       = 0,
	[ST_F_RATE_MAX]       = ST_F_LASTSESS,
	[ST_F_CHECK_STATUS]   = 0,
	[ST_F_CHECK_CODE]     = 0,
	[ST_F_CHECK_DURATION] = 0,
	[ST_F_HRSP_1XX]       = ST_F_HRSP_2XX,
	[ST_F_HRSP_2XX]       = ST_F_HRSP_3XX,
	[ST_F_HRSP_3XX]       = ST_F_HRSP_4XX,
	[ST_F_HRSP_4XX]       = ST_F_HRSP_5XX,
	[ST_F_HRSP_5XX]       = ST_F_HRSP_OTHER,
	[ST_F_HRSP_OTHER]     = ST_F_CACHE_LOOKUPS,
	[ST_F_HANAFAIL]       = 0,
	[ST_F_REQ_RATE]       = 0,
	[ST_F_REQ_RATE_MAX]   = 0,
	[ST_F_REQ_TOT]        = ST_F_HRSP_1XX,
	[ST_F_CLI_ABRT]       = ST_F_SRV_ABRT,
	[ST_F_SRV_ABRT]       = ST_F_WEIGHT,
	[ST_F_COMP_IN]        = ST_F_COMP_OUT,
	[ST_F_COMP_OUT]       = ST_F_COMP_BYP,
	[ST_F_COMP_BYP]       = ST_F_COMP_RSP,
	[ST_F_COMP_RSP]       = 0,
	[ST_F_LASTSESS]       = ST_F_QCUR,
	[ST_F_LAST_CHK]       = 0,
	[ST_F_LAST_AGT]       = 0,
	[ST_F_QTIME]          = ST_F_CTIME,
	[ST_F_CTIME]          = ST_F_RTIME,
	[ST_F_RTIME]          = ST_F_TTIME,
	[ST_F_TTIME]          = ST_F_QT_MAX,
	[ST_F_AGENT_STATUS]   = 0,
	[ST_F_AGENT_CODE]     = 0,
	[ST_F_AGENT_DURATION] = 0,
	[ST_F_CHECK_DESC]     = 0,
	[ST_F_AGENT_DESC]     = 0,
	[ST_F_CHECK_RISE]     = 0,
	[ST_F_CHECK_FALL]     = 0,
	[ST_F_CHECK_HEALTH]   = 0,
	[ST_F_AGENT_RISE]     = 0,
	[ST_F_AGENT_FALL]     = 0,
	[ST_F_AGENT_HEALTH]   = 0,
	[ST_F_ADDR]           = 0,
	[ST_F_COOKIE]         = 0,
	[ST_F_MODE]           = 0,
	[ST_F_ALGO]           = 0,
	[ST_F_CONN_RATE]      = 0,
	[ST_F_CONN_RATE_MAX]  = 0,
	[ST_F_CONN_TOT]       = 0,
	[ST_F_INTERCEPTED]    = 0,
	[ST_F_DCON]           = 0,
	[ST_F_DSES]           = 0,
	[ST_F_WREW]           = ST_F_EINT,
	[ST_F_CONNECT]        = ST_F_REUSE,
	[ST_F_REUSE]          = ST_F_BIN,
	[ST_F_CACHE_LOOKUPS]  = ST_F_CACHE_HITS,
	[ST_F_CACHE_HITS]     = ST_F_COMP_IN,
	[ST_F_SRV_ICUR]       = 0,
	[ST_F_SRV_ILIM]       = 0,
	[ST_F_QT_MAX]         = ST_F_CT_MAX,
	[ST_F_CT_MAX]         = ST_F_RT_MAX,
	[ST_F_RT_MAX]         = ST_F_TT_MAX,
	[ST_F_TT_MAX]         = ST_F_DREQ,
	[ST_F_EINT]           = ST_F_CLI_ABRT,
	[ST_F_IDLE_CONN_CUR]  = 0,
	[ST_F_SAFE_CONN_CUR]  = 0,
	[ST_F_USED_CONN_CUR]  = 0,
	[ST_F_NEED_CONN_EST]  = 0,
};

/* Matrix used to dump server metrics. Each metric points to the next one to be
 * processed or 0 to stop the dump. */
const int promex_srv_metrics[ST_F_TOTAL_FIELDS] = {
	[ST_F_PXNAME]         = ST_F_STATUS,
	[ST_F_SVNAME]         = 0,
	[ST_F_QCUR]           = ST_F_QMAX,
	[ST_F_QMAX]           = ST_F_QLIMIT,
	[ST_F_SCUR]           = ST_F_SMAX,
	[ST_F_SMAX]           = ST_F_SLIM,
	[ST_F_SLIM]           = ST_F_STOT,
	[ST_F_STOT]           = ST_F_RATE_MAX,
	[ST_F_BIN]            = ST_F_BOUT,
	[ST_F_BOUT]           = ST_F_QTIME,
	[ST_F_DREQ]           = 0,
	[ST_F_DRESP]          = ST_F_ECON,
	[ST_F_EREQ]           = 0,
	[ST_F_ECON]           = ST_F_ERESP,
	[ST_F_ERESP]          = ST_F_WRETR,
	[ST_F_WRETR]          = ST_F_WREDIS,
	[ST_F_WREDIS]         = ST_F_WREW,
	[ST_F_STATUS]         = ST_F_SCUR,
	[ST_F_WEIGHT]         = ST_F_CHECK_STATUS,
	[ST_F_ACT]            = 0,
	[ST_F_BCK]            = 0,
	[ST_F_CHKFAIL]        = ST_F_CHKDOWN,
	[ST_F_CHKDOWN]        = ST_F_DOWNTIME,
	[ST_F_LASTCHG]        = ST_F_THROTTLE,
	[ST_F_DOWNTIME]       = ST_F_LASTCHG,
	[ST_F_QLIMIT]         = ST_F_BIN,
	[ST_F_PID]            = 0,
	[ST_F_IID]            = 0,
	[ST_F_SID]            = 0,
	[ST_F_THROTTLE]       = ST_F_LBTOT,
	[ST_F_LBTOT]          = ST_F_HRSP_1XX,
	[ST_F_TRACKED]        = 0,
	[ST_F_TYPE]           = 0,
	[ST_F_RATE]           = 0,
	[ST_F_RATE_LIM]       = 0,
	[ST_F_RATE_MAX]       = ST_F_LASTSESS,
	[ST_F_CHECK_STATUS]   = ST_F_CHECK_CODE,
	[ST_F_CHECK_CODE]     = ST_F_CHECK_DURATION,
	[ST_F_CHECK_DURATION] = ST_F_CHKFAIL,
	[ST_F_HRSP_1XX]       = ST_F_HRSP_2XX,
	[ST_F_HRSP_2XX]       = ST_F_HRSP_3XX,
	[ST_F_HRSP_3XX]       = ST_F_HRSP_4XX,
	[ST_F_HRSP_4XX]       = ST_F_HRSP_5XX,
	[ST_F_HRSP_5XX]       = ST_F_HRSP_OTHER,
	[ST_F_HRSP_OTHER]     = ST_F_SRV_ICUR,
	[ST_F_HANAFAIL]       = 0,
	[ST_F_REQ_RATE]       = 0,
	[ST_F_REQ_RATE_MAX]   = 0,
	[ST_F_REQ_TOT]        = 0,
	[ST_F_CLI_ABRT]       = ST_F_SRV_ABRT,
	[ST_F_SRV_ABRT]       = ST_F_WEIGHT,
	[ST_F_COMP_IN]        = 0,
	[ST_F_COMP_OUT]       = 0,
	[ST_F_COMP_BYP]       = 0,
	[ST_F_COMP_RSP]       = 0,
	[ST_F_LASTSESS]       = ST_F_QCUR,
	[ST_F_LAST_CHK]       = 0,
	[ST_F_LAST_AGT]       = 0,
	[ST_F_QTIME]          = ST_F_CTIME,
	[ST_F_CTIME]          = ST_F_RTIME,
	[ST_F_RTIME]          = ST_F_TTIME,
	[ST_F_TTIME]          = ST_F_QT_MAX,
	[ST_F_AGENT_STATUS]   = 0,
	[ST_F_AGENT_CODE]     = 0,
	[ST_F_AGENT_DURATION] = 0,
	[ST_F_CHECK_DESC]     = 0,
	[ST_F_AGENT_DESC]     = 0,
	[ST_F_CHECK_RISE]     = 0,
	[ST_F_CHECK_FALL]     = 0,
	[ST_F_CHECK_HEALTH]   = 0,
	[ST_F_AGENT_RISE]     = 0,
	[ST_F_AGENT_FALL]     = 0,
	[ST_F_AGENT_HEALTH]   = 0,
	[ST_F_ADDR]           = 0,
	[ST_F_COOKIE]         = 0,
	[ST_F_MODE]           = 0,
	[ST_F_ALGO]           = 0,
	[ST_F_CONN_RATE]      = 0,
	[ST_F_CONN_RATE_MAX]  = 0,
	[ST_F_CONN_TOT]       = 0,
	[ST_F_INTERCEPTED]    = 0,
	[ST_F_DCON]           = 0,
	[ST_F_DSES]           = 0,
	[ST_F_WREW]           = ST_F_EINT,
	[ST_F_CONNECT]        = ST_F_REUSE,
	[ST_F_REUSE]          = ST_F_DRESP,
	[ST_F_CACHE_LOOKUPS]  = 0,
	[ST_F_CACHE_HITS]     = 0,
	[ST_F_SRV_ICUR]       = ST_F_SRV_ILIM,
	[ST_F_SRV_ILIM]       = ST_F_IDLE_CONN_CUR,
	[ST_F_QT_MAX]         = ST_F_CT_MAX,
	[ST_F_CT_MAX]         = ST_F_RT_MAX,
	[ST_F_RT_MAX]         = ST_F_TT_MAX,
	[ST_F_TT_MAX]         = ST_F_CONNECT,
	[ST_F_EINT]           = ST_F_CLI_ABRT,
	[ST_F_IDLE_CONN_CUR]  = ST_F_SAFE_CONN_CUR,
	[ST_F_SAFE_CONN_CUR]  = ST_F_USED_CONN_CUR,
	[ST_F_USED_CONN_CUR]  = ST_F_NEED_CONN_EST,
	[ST_F_NEED_CONN_EST]  = 0,
};

/* Name of all info fields */
const struct ist promex_inf_metric_names[INF_TOTAL_FIELDS] = {
	[INF_NAME]                           = IST("name"),
	[INF_VERSION]                        = IST("version"),
	[INF_RELEASE_DATE]                   = IST("release_date"),
	[INF_NBTHREAD]                       = IST("nbthread"),
	[INF_NBPROC]                         = IST("nbproc"),
	[INF_PROCESS_NUM]                    = IST("relative_process_id"),
	[INF_PID]                            = IST("pid"),
	[INF_UPTIME]                         = IST("uptime"),
	[INF_UPTIME_SEC]                     = IST("start_time_seconds"),
	[INF_MEMMAX_MB]                      = IST("max_memory_bytes"),
	[INF_POOL_ALLOC_MB]                  = IST("pool_allocated_bytes"),
	[INF_POOL_USED_MB]                   = IST("pool_used_bytes"),
	[INF_POOL_FAILED]                    = IST("pool_failures_total"),
	[INF_ULIMIT_N]                       = IST("max_fds"),
	[INF_MAXSOCK]                        = IST("max_sockets"),
	[INF_MAXCONN]                        = IST("max_connections"),
	[INF_HARD_MAXCONN]                   = IST("hard_max_connections"),
	[INF_CURR_CONN]                      = IST("current_connections"),
	[INF_CUM_CONN]                       = IST("connections_total"),
	[INF_CUM_REQ]                        = IST("requests_total"),
	[INF_MAX_SSL_CONNS]                  = IST("max_ssl_connections"),
	[INF_CURR_SSL_CONNS]                 = IST("current_ssl_connections"),
	[INF_CUM_SSL_CONNS]                  = IST("ssl_connections_total"),
	[INF_MAXPIPES]                       = IST("max_pipes"),
	[INF_PIPES_USED]                     = IST("pipes_used_total"),
	[INF_PIPES_FREE]                     = IST("pipes_free_total"),
	[INF_CONN_RATE]                      = IST("current_connection_rate"),
	[INF_CONN_RATE_LIMIT]                = IST("limit_connection_rate"),
	[INF_MAX_CONN_RATE]                  = IST("max_connection_rate"),
	[INF_SESS_RATE]                      = IST("current_session_rate"),
	[INF_SESS_RATE_LIMIT]                = IST("limit_session_rate"),
	[INF_MAX_SESS_RATE]                  = IST("max_session_rate"),
	[INF_SSL_RATE]                       = IST("current_ssl_rate"),
	[INF_SSL_RATE_LIMIT]                 = IST("limit_ssl_rate"),
	[INF_MAX_SSL_RATE]                   = IST("max_ssl_rate"),
	[INF_SSL_FRONTEND_KEY_RATE]          = IST("current_frontend_ssl_key_rate"),
	[INF_SSL_FRONTEND_MAX_KEY_RATE]      = IST("max_frontend_ssl_key_rate"),
	[INF_SSL_FRONTEND_SESSION_REUSE_PCT] = IST("frontend_ssl_reuse"),
	[INF_SSL_BACKEND_KEY_RATE]           = IST("current_backend_ssl_key_rate"),
	[INF_SSL_BACKEND_MAX_KEY_RATE]       = IST("max_backend_ssl_key_rate"),
	[INF_SSL_CACHE_LOOKUPS]              = IST("ssl_cache_lookups_total"),
	[INF_SSL_CACHE_MISSES]               = IST("ssl_cache_misses_total"),
	[INF_COMPRESS_BPS_IN]                = IST("http_comp_bytes_in_total"),
	[INF_COMPRESS_BPS_OUT]               = IST("http_comp_bytes_out_total"),
	[INF_COMPRESS_BPS_RATE_LIM]          = IST("limit_http_comp"),
	[INF_ZLIB_MEM_USAGE]                 = IST("current_zlib_memory"),
	[INF_MAX_ZLIB_MEM_USAGE]             = IST("max_zlib_memory"),
	[INF_TASKS]                          = IST("current_tasks"),
	[INF_RUN_QUEUE]                      = IST("current_run_queue"),
	[INF_IDLE_PCT]                       = IST("idle_time_percent"),
	[INF_NODE]                           = IST("node"),
	[INF_DESCRIPTION]                    = IST("description"),
	[INF_STOPPING]                       = IST("stopping"),
	[INF_JOBS]                           = IST("jobs"),
	[INF_UNSTOPPABLE_JOBS]               = IST("unstoppable_jobs"),
	[INF_LISTENERS]                      = IST("listeners"),
	[INF_ACTIVE_PEERS]                   = IST("active_peers"),
	[INF_CONNECTED_PEERS]                = IST("connected_peers"),
	[INF_DROPPED_LOGS]                   = IST("dropped_logs_total"),
	[INF_BUSY_POLLING]                   = IST("busy_polling_enabled"),
	[INF_FAILED_RESOLUTIONS]             = IST("failed_resolutions"),
	[INF_TOTAL_BYTES_OUT]                = IST("bytes_out_total"),
	[INF_TOTAL_SPLICED_BYTES_OUT]        = IST("spliced_bytes_out_total"),
	[INF_BYTES_OUT_RATE]                 = IST("bytes_out_rate"),
	[INF_DEBUG_COMMANDS_ISSUED]          = IST("debug_commands_issued"),
};

/* Name of all stats fields */
const struct ist promex_st_metric_names[ST_F_TOTAL_FIELDS] = {
	[ST_F_PXNAME]         = IST("proxy_name"),
	[ST_F_SVNAME]         = IST("service_name"),
	[ST_F_QCUR]           = IST("current_queue"),
	[ST_F_QMAX]           = IST("max_queue"),
	[ST_F_SCUR]           = IST("current_sessions"),
	[ST_F_SMAX]           = IST("max_sessions"),
	[ST_F_SLIM]           = IST("limit_sessions"),
	[ST_F_STOT]           = IST("sessions_total"),
	[ST_F_BIN]            = IST("bytes_in_total"),
	[ST_F_BOUT]           = IST("bytes_out_total"),
	[ST_F_DREQ]           = IST("requests_denied_total"),
	[ST_F_DRESP]          = IST("responses_denied_total"),
	[ST_F_EREQ]           = IST("request_errors_total"),
	[ST_F_ECON]           = IST("connection_errors_total"),
	[ST_F_ERESP]          = IST("response_errors_total"),
	[ST_F_WRETR]          = IST("retry_warnings_total"),
	[ST_F_WREDIS]         = IST("redispatch_warnings_total"),
	[ST_F_STATUS]         = IST("status"),
	[ST_F_WEIGHT]         = IST("weight"),
	[ST_F_ACT]            = IST("active_servers"),
	[ST_F_BCK]            = IST("backup_servers"),
	[ST_F_CHKFAIL]        = IST("check_failures_total"),
	[ST_F_CHKDOWN]        = IST("check_up_down_total"),
	[ST_F_LASTCHG]        = IST("check_last_change_seconds"),
	[ST_F_DOWNTIME]       = IST("downtime_seconds_total"),
	[ST_F_QLIMIT]         = IST("queue_limit"),
	[ST_F_PID]            = IST("pid"),
	[ST_F_IID]            = IST("proxy_id"),
	[ST_F_SID]            = IST("server_id"),
	[ST_F_THROTTLE]       = IST("current_throttle"),
	[ST_F_LBTOT]          = IST("loadbalanced_total"),
	[ST_F_TRACKED]        = IST("tracked"),
	[ST_F_TYPE]           = IST("type"),
	[ST_F_RATE]           = IST("current_session_rate"),
	[ST_F_RATE_LIM]       = IST("limit_session_rate"),
	[ST_F_RATE_MAX]       = IST("max_session_rate"),
	[ST_F_CHECK_STATUS]   = IST("check_status"),
	[ST_F_CHECK_CODE]     = IST("check_code"),
	[ST_F_CHECK_DURATION] = IST("check_duration_seconds"),
	[ST_F_HRSP_1XX]       = IST("http_responses_total"),
	[ST_F_HRSP_2XX]       = IST("http_responses_total"),
	[ST_F_HRSP_3XX]       = IST("http_responses_total"),
	[ST_F_HRSP_4XX]       = IST("http_responses_total"),
	[ST_F_HRSP_5XX]       = IST("http_responses_total"),
	[ST_F_HRSP_OTHER]     = IST("http_responses_total"),
	[ST_F_HANAFAIL]       = IST("check_analyses_failures_total"),
	[ST_F_REQ_RATE]       = IST("http_requests_rate_current"),
	[ST_F_REQ_RATE_MAX]   = IST("http_requests_rate_max"),
	[ST_F_REQ_TOT]        = IST("http_requests_total"),
	[ST_F_CLI_ABRT]       = IST("client_aborts_total"),
	[ST_F_SRV_ABRT]       = IST("server_aborts_total"),
	[ST_F_COMP_IN]        = IST("http_comp_bytes_in_total"),
	[ST_F_COMP_OUT]       = IST("http_comp_bytes_out_total"),
	[ST_F_COMP_BYP]       = IST("http_comp_bytes_bypassed_total"),
	[ST_F_COMP_RSP]       = IST("http_comp_responses_total"),
	[ST_F_LASTSESS]       = IST("last_session_seconds"),
	[ST_F_LAST_CHK]       = IST("check_last_content"),
	[ST_F_LAST_AGT]       = IST("agentcheck_last_content"),
	[ST_F_QTIME]          = IST("queue_time_average_seconds"),
	[ST_F_CTIME]          = IST("connect_time_average_seconds"),
	[ST_F_RTIME]          = IST("response_time_average_seconds"),
	[ST_F_TTIME]          = IST("total_time_average_seconds"),
	[ST_F_AGENT_STATUS]   = IST("agentcheck_status"),
	[ST_F_AGENT_CODE]     = IST("agentcheck_code"),
	[ST_F_AGENT_DURATION] = IST("agentcheck_duration_milliseconds"),
	[ST_F_CHECK_DESC]     = IST("check_description"),
	[ST_F_AGENT_DESC]     = IST("agentcheck_description"),
	[ST_F_CHECK_RISE]     = IST("check_rise"),
	[ST_F_CHECK_FALL]     = IST("check_fall"),
	[ST_F_CHECK_HEALTH]   = IST("check_value"),
	[ST_F_AGENT_RISE]     = IST("agentcheck_rise"),
	[ST_F_AGENT_FALL]     = IST("agentcheck_fall"),
	[ST_F_AGENT_HEALTH]   = IST("agentcheck_value"),
	[ST_F_ADDR]           = IST("address"),
	[ST_F_COOKIE]         = IST("cookie"),
	[ST_F_MODE]           = IST("mode"),
	[ST_F_ALGO]           = IST("loadbalance_algorithm"),
	[ST_F_CONN_RATE]      = IST("connections_rate_current"),
	[ST_F_CONN_RATE_MAX]  = IST("connections_rate_max"),
	[ST_F_CONN_TOT]       = IST("connections_total"),
	[ST_F_INTERCEPTED]    = IST("intercepted_requests_total"),
	[ST_F_DCON]           = IST("denied_connections_total"),
	[ST_F_DSES]           = IST("denied_sessions_total"),
	[ST_F_WREW]           = IST("failed_header_rewriting_total"),
	[ST_F_CONNECT]        = IST("connection_attempts_total"),
	[ST_F_REUSE]          = IST("connection_reuses_total"),
	[ST_F_CACHE_LOOKUPS]  = IST("http_cache_lookups_total"),
	[ST_F_CACHE_HITS]     = IST("http_cache_hits_total"),
	[ST_F_SRV_ICUR]       = IST("idle_connections_current"),
	[ST_F_SRV_ILIM]       = IST("idle_connections_limit"),
	[ST_F_QT_MAX]         = IST("max_queue_time_seconds"),
	[ST_F_CT_MAX]         = IST("max_connect_time_seconds"),
	[ST_F_RT_MAX]         = IST("max_response_time_seconds"),
	[ST_F_TT_MAX]         = IST("max_total_time_seconds"),
	[ST_F_EINT]           = IST("internal_errors_total"),
	[ST_F_IDLE_CONN_CUR]  = IST("unsafe_idle_connections_current"),
	[ST_F_SAFE_CONN_CUR]  = IST("safe_idle_connections_current"),
	[ST_F_USED_CONN_CUR]  = IST("used_connections_current"),
	[ST_F_NEED_CONN_EST]  = IST("need_connections_current"),
};

/* Description of all info fields */
const struct ist promex_inf_metric_desc[INF_TOTAL_FIELDS] = {
	[INF_NAME]                           = IST("Product name."),
	[INF_VERSION]                        = IST("HAProxy version."),
	[INF_RELEASE_DATE]                   = IST("HAProxy release date."),
	[INF_NBTHREAD]                       = IST("Configured number of threads."),
	[INF_NBPROC]                         = IST("Configured number of processes."),
	[INF_PROCESS_NUM]                    = IST("Relative process id, starting at 1."),
	[INF_PID]                            = IST("HAProxy PID."),
	[INF_UPTIME]                         = IST("Uptime in a human readable format."),
	[INF_UPTIME_SEC]                     = IST("Start time in seconds."),
	[INF_MEMMAX_MB]                      = IST("Per-process memory limit (in bytes); 0=unset."),
	[INF_POOL_ALLOC_MB]                  = IST("Total amount of memory allocated in pools (in bytes)."),
	[INF_POOL_USED_MB]                   = IST("Total amount of memory used in pools (in bytes)."),
	[INF_POOL_FAILED]                    = IST("Total number of failed pool allocations."),
	[INF_ULIMIT_N]                       = IST("Maximum number of open file descriptors; 0=unset."),
	[INF_MAXSOCK]                        = IST("Maximum number of open sockets."),
	[INF_MAXCONN]                        = IST("Maximum number of concurrent connections."),
	[INF_HARD_MAXCONN]                   = IST("Initial Maximum number of concurrent connections."),
	[INF_CURR_CONN]                      = IST("Number of active sessions."),
	[INF_CUM_CONN]                       = IST("Total number of created sessions."),
	[INF_CUM_REQ]                        = IST("Total number of requests (TCP or HTTP)."),
	[INF_MAX_SSL_CONNS]                  = IST("Configured maximum number of concurrent SSL connections."),
	[INF_CURR_SSL_CONNS]                 = IST("Number of opened SSL connections."),
	[INF_CUM_SSL_CONNS]                  = IST("Total number of opened SSL connections."),
	[INF_MAXPIPES]                       = IST("Configured maximum number of pipes."),
	[INF_PIPES_USED]                     = IST("Number of pipes in used."),
	[INF_PIPES_FREE]                     = IST("Number of pipes unused."),
	[INF_CONN_RATE]                      = IST("Current number of connections per second over last elapsed second."),
	[INF_CONN_RATE_LIMIT]                = IST("Configured maximum number of connections per second."),
	[INF_MAX_CONN_RATE]                  = IST("Maximum observed number of connections per second."),
	[INF_SESS_RATE]                      = IST("Current number of sessions per second over last elapsed second."),
	[INF_SESS_RATE_LIMIT]                = IST("Configured maximum number of sessions per second."),
	[INF_MAX_SESS_RATE]                  = IST("Maximum observed number of sessions per second."),
	[INF_SSL_RATE]                       = IST("Current number of SSL sessions per second over last elapsed second."),
	[INF_SSL_RATE_LIMIT]                 = IST("Configured maximum number of SSL sessions per second."),
	[INF_MAX_SSL_RATE]                   = IST("Maximum observed number of SSL sessions per second."),
	[INF_SSL_FRONTEND_KEY_RATE]          = IST("Current frontend SSL Key computation per second over last elapsed second."),
	[INF_SSL_FRONTEND_MAX_KEY_RATE]      = IST("Maximum observed frontend SSL Key computation per second."),
	[INF_SSL_FRONTEND_SESSION_REUSE_PCT] = IST("SSL session reuse ratio (percent)."),
	[INF_SSL_BACKEND_KEY_RATE]           = IST("Current backend SSL Key computation per second over last elapsed second."),
	[INF_SSL_BACKEND_MAX_KEY_RATE]       = IST("Maximum observed backend SSL Key computation per second."),
	[INF_SSL_CACHE_LOOKUPS]              = IST("Total number of SSL session cache lookups."),
	[INF_SSL_CACHE_MISSES]               = IST("Total number of SSL session cache misses."),
	[INF_COMPRESS_BPS_IN]                = IST("Number of bytes per second over last elapsed second, before http compression."),
	[INF_COMPRESS_BPS_OUT]               = IST("Number of bytes per second over last elapsed second, after http compression."),
	[INF_COMPRESS_BPS_RATE_LIM]          = IST("Configured maximum input compression rate in bytes."),
	[INF_ZLIB_MEM_USAGE]                 = IST("Current memory used for zlib in bytes."),
	[INF_MAX_ZLIB_MEM_USAGE]             = IST("Configured maximum amount of memory for zlib in bytes."),
	[INF_TASKS]                          = IST("Current number of tasks."),
	[INF_RUN_QUEUE]                      = IST("Current number of tasks in the run-queue."),
	[INF_IDLE_PCT]                       = IST("Idle to total ratio over last sample (percent)."),
	[INF_NODE]                           = IST("Node name."),
	[INF_DESCRIPTION]                    = IST("Node description."),
	[INF_STOPPING]                       = IST("Non zero means stopping in progress."),
	[INF_JOBS]                           = IST("Current number of active jobs (listeners, sessions, open devices)."),
	[INF_UNSTOPPABLE_JOBS]               = IST("Current number of active jobs that can't be stopped during a soft stop."),
	[INF_LISTENERS]                      = IST("Current number of active listeners."),
	[INF_ACTIVE_PEERS]                   = IST("Current number of active peers."),
	[INF_CONNECTED_PEERS]                = IST("Current number of connected peers."),
	[INF_DROPPED_LOGS]                   = IST("Total number of dropped logs."),
	[INF_BUSY_POLLING]                   = IST("Non zero if the busy polling is enabled."),
	[INF_FAILED_RESOLUTIONS]             = IST("Total number of failed DNS resolutions."),
	[INF_TOTAL_BYTES_OUT]                = IST("Total number of bytes emitted."),
	[INF_TOTAL_SPLICED_BYTES_OUT]        = IST("Total number of bytes emitted through a kernel pipe."),
	[INF_BYTES_OUT_RATE]                 = IST("Number of bytes emitted over the last elapsed second."),
	[INF_DEBUG_COMMANDS_ISSUED]          = IST("Number of debug commands issued on this process (anything > 0 is unsafe)."),
};

/* Description of all stats fields */
const struct ist promex_st_metric_desc[ST_F_TOTAL_FIELDS] = {
	[ST_F_PXNAME]         = IST("The proxy name."),
	[ST_F_SVNAME]         = IST("The service name (FRONTEND for frontend, BACKEND for backend, any name for server/listener)."),
	[ST_F_QCUR]           = IST("Current number of queued requests."),
	[ST_F_QMAX]           = IST("Maximum observed number of queued requests."),
	[ST_F_SCUR]           = IST("Current number of active sessions."),
	[ST_F_SMAX]           = IST("Maximum observed number of active sessions."),
	[ST_F_SLIM]           = IST("Configured session limit."),
	[ST_F_STOT]           = IST("Total number of sessions."),
	[ST_F_BIN]            = IST("Current total of incoming bytes."),
	[ST_F_BOUT]           = IST("Current total of outgoing bytes."),
	[ST_F_DREQ]           = IST("Total number of denied requests."),
	[ST_F_DRESP]          = IST("Total number of denied responses."),
	[ST_F_EREQ]           = IST("Total number of request errors."),
	[ST_F_ECON]           = IST("Total number of connection errors."),
	[ST_F_ERESP]          = IST("Total number of response errors."),
	[ST_F_WRETR]          = IST("Total number of retry warnings."),
	[ST_F_WREDIS]         = IST("Total number of redispatch warnings."),
	[ST_F_STATUS]         = IST("Current status of the service (frontend: 0=STOP, 1=UP - backend: 0=DOWN, 1=UP - server: 0=DOWN, 1=UP, 2=MAINT, 3=DRAIN, 4=NOLB)."),
	[ST_F_WEIGHT]         = IST("Service weight."),
	[ST_F_ACT]            = IST("Current number of active servers."),
	[ST_F_BCK]            = IST("Current number of backup servers."),
	[ST_F_CHKFAIL]        = IST("Total number of failed check (Only counts checks failed when the server is up)."),
	[ST_F_CHKDOWN]        = IST("Total number of UP->DOWN transitions."),
	[ST_F_LASTCHG]        = IST("Number of seconds since the last UP<->DOWN transition."),
	[ST_F_DOWNTIME]       = IST("Total downtime (in seconds) for the service."),
	[ST_F_QLIMIT]         = IST("Configured maxqueue for the server (0 meaning no limit)."),
	[ST_F_PID]            = IST("Process id (0 for first instance, 1 for second, ...)"),
	[ST_F_IID]            = IST("Unique proxy id."),
	[ST_F_SID]            = IST("Server id (unique inside a proxy)."),
	[ST_F_THROTTLE]       = IST("Current throttle percentage for the server, when slowstart is active, or no value if not in slowstart."),
	[ST_F_LBTOT]          = IST("Total number of times a service was selected, either for new sessions, or when redispatching."),
	[ST_F_TRACKED]        = IST("Id of proxy/server if tracking is enabled."),
	[ST_F_TYPE]           = IST("Service type (0=frontend, 1=backend, 2=server, 3=socket/listener)."),
	[ST_F_RATE]           = IST("Current number of sessions per second over last elapsed second."),
	[ST_F_RATE_LIM]       = IST("Configured limit on new sessions per second."),
	[ST_F_RATE_MAX]       = IST("Maximum observed number of sessions per second."),
	[ST_F_CHECK_STATUS]   = IST("Status of last health check (HCHK_STATUS_* values)."),
	[ST_F_CHECK_CODE]     = IST("layer5-7 code, if available of the last health check."),
	[ST_F_CHECK_DURATION] = IST("Total duration of the latest server health check, in seconds."),
	[ST_F_HRSP_1XX]       = IST("Total number of HTTP responses."),
	[ST_F_HRSP_2XX]       = IST("Total number of HTTP responses."),
	[ST_F_HRSP_3XX]       = IST("Total number of HTTP responses."),
	[ST_F_HRSP_4XX]       = IST("Total number of HTTP responses."),
	[ST_F_HRSP_5XX]       = IST("Total number of HTTP responses."),
	[ST_F_HRSP_OTHER]     = IST("Total number of HTTP responses."),
	[ST_F_HANAFAIL]       = IST("Total number of failed health checks."),
	[ST_F_REQ_RATE]       = IST("Current number of HTTP requests per second over last elapsed second."),
	[ST_F_REQ_RATE_MAX]   = IST("Maximum observed number of HTTP requests per second."),
	[ST_F_REQ_TOT]        = IST("Total number of HTTP requests received."),
	[ST_F_CLI_ABRT]       = IST("Total number of data transfers aborted by the client."),
	[ST_F_SRV_ABRT]       = IST("Total number of data transfers aborted by the server."),
	[ST_F_COMP_IN]        = IST("Total number of HTTP response bytes fed to the compressor."),
	[ST_F_COMP_OUT]       = IST("Total number of HTTP response bytes emitted by the compressor."),
	[ST_F_COMP_BYP]       = IST("Total number of bytes that bypassed the HTTP compressor (CPU/BW limit)."),
	[ST_F_COMP_RSP]       = IST("Total number of HTTP responses that were compressed."),
	[ST_F_LASTSESS]       = IST("Number of seconds since last session assigned to server/backend."),
	[ST_F_LAST_CHK]       = IST("Last health check contents or textual error"),
	[ST_F_LAST_AGT]       = IST("Last agent check contents or textual error"),
	[ST_F_QTIME]          = IST("Avg. queue time for last 1024 successful connections."),
	[ST_F_CTIME]          = IST("Avg. connect time for last 1024 successful connections."),
	[ST_F_RTIME]          = IST("Avg. response time for last 1024 successful connections."),
	[ST_F_TTIME]          = IST("Avg. total time for last 1024 successful connections."),
	[ST_F_AGENT_STATUS]   = IST("Status of last agent check."),
	[ST_F_AGENT_CODE]     = IST("Numeric code reported by agent if any (unused for now)."),
	[ST_F_AGENT_DURATION] = IST("Time in ms taken to finish last agent check."),
	[ST_F_CHECK_DESC]     = IST("Short human-readable description of the last health status."),
	[ST_F_AGENT_DESC]     = IST("Short human-readable description of the last agent status."),
	[ST_F_CHECK_RISE]     = IST("Server's \"rise\" parameter used by health checks"),
	[ST_F_CHECK_FALL]     = IST("Server's \"fall\" parameter used by health checks"),
	[ST_F_CHECK_HEALTH]   = IST("Server's health check value between 0 and rise+fall-1"),
	[ST_F_AGENT_RISE]     = IST("Agent's \"rise\" parameter, normally 1."),
	[ST_F_AGENT_FALL]     = IST("Agent's \"fall\" parameter, normally 1."),
	[ST_F_AGENT_HEALTH]   = IST("Agent's health parameter, between 0 and rise+fall-1"),
	[ST_F_ADDR]           = IST("address:port or \"unix\". IPv6 has brackets around the address."),
	[ST_F_COOKIE]         = IST("Server's cookie value or backend's cookie name."),
	[ST_F_MODE]           = IST("Proxy mode (tcp, http, health, unknown)."),
	[ST_F_ALGO]           = IST("Load balancing algorithm."),
	[ST_F_CONN_RATE]      = IST("Current number of connections per second over the last elapsed second."),
	[ST_F_CONN_RATE_MAX]  = IST("Maximum observed number of connections per second."),
	[ST_F_CONN_TOT]       = IST("Total number of connections."),
	[ST_F_INTERCEPTED]    = IST("Total number of intercepted HTTP requests."),
	[ST_F_DCON]           = IST("Total number of requests denied by \"tcp-request connection\" rules."),
	[ST_F_DSES]           = IST("Total number of requests denied by \"tcp-request session\" rules."),
	[ST_F_WREW]           = IST("Total number of failed header rewriting warnings."),
	[ST_F_CONNECT]        = IST("Total number of connection establishment attempts."),
	[ST_F_REUSE]          = IST("Total number of connection reuses."),
	[ST_F_CACHE_LOOKUPS]  = IST("Total number of HTTP cache lookups."),
	[ST_F_CACHE_HITS]     = IST("Total number of HTTP cache hits."),
	[ST_F_SRV_ICUR]       = IST("Current number of idle connections available for reuse"),
	[ST_F_SRV_ILIM]       = IST("Limit on the number of available idle connections"),
	[ST_F_QT_MAX]         = IST("Maximum observed time spent in the queue"),
	[ST_F_CT_MAX]         = IST("Maximum observed time spent waiting for a connection to complete"),
	[ST_F_RT_MAX]         = IST("Maximum observed time spent waiting for a server response"),
	[ST_F_TT_MAX]         = IST("Maximum observed total request+response time (request+queue+connect+response+processing)"),
	[ST_F_EINT]           = IST("Total number of internal errors."),
	[ST_F_IDLE_CONN_CUR]  = IST("Current number of unsafe idle connections."),
	[ST_F_SAFE_CONN_CUR]  = IST("Current number of safe idle connections."),
	[ST_F_USED_CONN_CUR]  = IST("Current number of connections in use."),
	[ST_F_NEED_CONN_EST]  = IST("Estimated needed number of connections."),
};

/* Specific labels for all info fields. Empty by default. */
const struct ist promex_inf_metric_labels[INF_TOTAL_FIELDS] = {
	[INF_NAME]                           = IST(""),
	[INF_VERSION]                        = IST(""),
	[INF_RELEASE_DATE]                   = IST(""),
	[INF_NBTHREAD]                       = IST(""),
	[INF_NBPROC]                         = IST(""),
	[INF_PROCESS_NUM]                    = IST(""),
	[INF_PID]                            = IST(""),
	[INF_UPTIME]                         = IST(""),
	[INF_UPTIME_SEC]                     = IST(""),
	[INF_MEMMAX_MB]                      = IST(""),
	[INF_POOL_ALLOC_MB]                  = IST(""),
	[INF_POOL_USED_MB]                   = IST(""),
	[INF_POOL_FAILED]                    = IST(""),
	[INF_ULIMIT_N]                       = IST(""),
	[INF_MAXSOCK]                        = IST(""),
	[INF_MAXCONN]                        = IST(""),
	[INF_HARD_MAXCONN]                   = IST(""),
	[INF_CURR_CONN]                      = IST(""),
	[INF_CUM_CONN]                       = IST(""),
	[INF_CUM_REQ]                        = IST(""),
	[INF_MAX_SSL_CONNS]                  = IST(""),
	[INF_CURR_SSL_CONNS]                 = IST(""),
	[INF_CUM_SSL_CONNS]                  = IST(""),
	[INF_MAXPIPES]                       = IST(""),
	[INF_PIPES_USED]                     = IST(""),
	[INF_PIPES_FREE]                     = IST(""),
	[INF_CONN_RATE]                      = IST(""),
	[INF_CONN_RATE_LIMIT]                = IST(""),
	[INF_MAX_CONN_RATE]                  = IST(""),
	[INF_SESS_RATE]                      = IST(""),
	[INF_SESS_RATE_LIMIT]                = IST(""),
	[INF_MAX_SESS_RATE]                  = IST(""),
	[INF_SSL_RATE]                       = IST(""),
	[INF_SSL_RATE_LIMIT]                 = IST(""),
	[INF_MAX_SSL_RATE]                   = IST(""),
	[INF_SSL_FRONTEND_KEY_RATE]          = IST(""),
	[INF_SSL_FRONTEND_MAX_KEY_RATE]      = IST(""),
	[INF_SSL_FRONTEND_SESSION_REUSE_PCT] = IST(""),
	[INF_SSL_BACKEND_KEY_RATE]           = IST(""),
	[INF_SSL_BACKEND_MAX_KEY_RATE]       = IST(""),
	[INF_SSL_CACHE_LOOKUPS]              = IST(""),
	[INF_SSL_CACHE_MISSES]               = IST(""),
	[INF_COMPRESS_BPS_IN]                = IST(""),
	[INF_COMPRESS_BPS_OUT]               = IST(""),
	[INF_COMPRESS_BPS_RATE_LIM]          = IST(""),
	[INF_ZLIB_MEM_USAGE]                 = IST(""),
	[INF_MAX_ZLIB_MEM_USAGE]             = IST(""),
	[INF_TASKS]                          = IST(""),
	[INF_RUN_QUEUE]                      = IST(""),
	[INF_IDLE_PCT]                       = IST(""),
	[INF_NODE]                           = IST(""),
	[INF_DESCRIPTION]                    = IST(""),
	[INF_STOPPING]                       = IST(""),
	[INF_JOBS]                           = IST(""),
	[INF_UNSTOPPABLE_JOBS]               = IST(""),
	[INF_LISTENERS]                      = IST(""),
	[INF_ACTIVE_PEERS]                   = IST(""),
	[INF_CONNECTED_PEERS]                = IST(""),
	[INF_DROPPED_LOGS]                   = IST(""),
	[INF_BUSY_POLLING]                   = IST(""),
	[INF_FAILED_RESOLUTIONS]             = IST(""),
	[INF_TOTAL_BYTES_OUT]                = IST(""),
	[INF_TOTAL_SPLICED_BYTES_OUT]        = IST(""),
	[INF_BYTES_OUT_RATE]                 = IST(""),
	[INF_DEBUG_COMMANDS_ISSUED]          = IST(""),
};

/* Specific labels for all stats fields. Empty by default. */
const struct ist promex_st_metric_labels[ST_F_TOTAL_FIELDS] = {
	[ST_F_PXNAME]         = IST(""),
	[ST_F_SVNAME]         = IST(""),
	[ST_F_QCUR]           = IST(""),
	[ST_F_QMAX]           = IST(""),
	[ST_F_SCUR]           = IST(""),
	[ST_F_SMAX]           = IST(""),
	[ST_F_SLIM]           = IST(""),
	[ST_F_STOT]           = IST(""),
	[ST_F_BIN]            = IST(""),
	[ST_F_BOUT]           = IST(""),
	[ST_F_DREQ]           = IST(""),
	[ST_F_DRESP]          = IST(""),
	[ST_F_EREQ]           = IST(""),
	[ST_F_ECON]           = IST(""),
	[ST_F_ERESP]          = IST(""),
	[ST_F_WRETR]          = IST(""),
	[ST_F_WREDIS]         = IST(""),
	[ST_F_STATUS]         = IST(""),
	[ST_F_WEIGHT]         = IST(""),
	[ST_F_ACT]            = IST(""),
	[ST_F_BCK]            = IST(""),
	[ST_F_CHKFAIL]        = IST(""),
	[ST_F_CHKDOWN]        = IST(""),
	[ST_F_LASTCHG]        = IST(""),
	[ST_F_DOWNTIME]       = IST(""),
	[ST_F_QLIMIT]         = IST(""),
	[ST_F_PID]            = IST(""),
	[ST_F_IID]            = IST(""),
	[ST_F_SID]            = IST(""),
	[ST_F_THROTTLE]       = IST(""),
	[ST_F_LBTOT]          = IST(""),
	[ST_F_TRACKED]        = IST(""),
	[ST_F_TYPE]           = IST(""),
	[ST_F_RATE]           = IST(""),
	[ST_F_RATE_LIM]       = IST(""),
	[ST_F_RATE_MAX]       = IST(""),
	[ST_F_CHECK_STATUS]   = IST(""),
	[ST_F_CHECK_CODE]     = IST(""),
	[ST_F_CHECK_DURATION] = IST(""),
	[ST_F_HRSP_1XX]       = IST("code=\"1xx\""),
	[ST_F_HRSP_2XX]       = IST("code=\"2xx\""),
	[ST_F_HRSP_3XX]       = IST("code=\"3xx\""),
	[ST_F_HRSP_4XX]       = IST("code=\"4xx\""),
	[ST_F_HRSP_5XX]       = IST("code=\"5xx\""),
	[ST_F_HRSP_OTHER]     = IST("code=\"other\""),
	[ST_F_HANAFAIL]       = IST(""),
	[ST_F_REQ_RATE]       = IST(""),
	[ST_F_REQ_RATE_MAX]   = IST(""),
	[ST_F_REQ_TOT]        = IST(""),
	[ST_F_CLI_ABRT]       = IST(""),
	[ST_F_SRV_ABRT]       = IST(""),
	[ST_F_COMP_IN]        = IST(""),
	[ST_F_COMP_OUT]       = IST(""),
	[ST_F_COMP_BYP]       = IST(""),
	[ST_F_COMP_RSP]       = IST(""),
	[ST_F_LASTSESS]       = IST(""),
	[ST_F_LAST_CHK]       = IST(""),
	[ST_F_LAST_AGT]       = IST(""),
	[ST_F_QTIME]          = IST(""),
	[ST_F_CTIME]          = IST(""),
	[ST_F_RTIME]          = IST(""),
	[ST_F_TTIME]          = IST(""),
	[ST_F_AGENT_STATUS]   = IST(""),
	[ST_F_AGENT_CODE]     = IST(""),
	[ST_F_AGENT_DURATION] = IST(""),
	[ST_F_CHECK_DESC]     = IST(""),
	[ST_F_AGENT_DESC]     = IST(""),
	[ST_F_CHECK_RISE]     = IST(""),
	[ST_F_CHECK_FALL]     = IST(""),
	[ST_F_CHECK_HEALTH]   = IST(""),
	[ST_F_AGENT_RISE]     = IST(""),
	[ST_F_AGENT_FALL]     = IST(""),
	[ST_F_AGENT_HEALTH]   = IST(""),
	[ST_F_ADDR]           = IST(""),
	[ST_F_COOKIE]         = IST(""),
	[ST_F_MODE]           = IST(""),
	[ST_F_ALGO]           = IST(""),
	[ST_F_CONN_RATE]      = IST(""),
	[ST_F_CONN_RATE_MAX]  = IST(""),
	[ST_F_CONN_TOT]       = IST(""),
	[ST_F_INTERCEPTED]    = IST(""),
	[ST_F_DCON]           = IST(""),
	[ST_F_DSES]           = IST(""),
	[ST_F_WREW]           = IST(""),
	[ST_F_CONNECT]        = IST(""),
	[ST_F_REUSE]          = IST(""),
	[ST_F_CACHE_LOOKUPS]  = IST(""),
	[ST_F_CACHE_HITS]     = IST(""),
	[ST_F_IDLE_CONN_CUR]  = IST(""),
	[ST_F_SAFE_CONN_CUR]  = IST(""),
	[ST_F_USED_CONN_CUR]  = IST(""),
	[ST_F_NEED_CONN_EST]  = IST(""),
};

/* Type for all info fields. "untyped" is used for unsupported field. */
const struct ist promex_inf_metric_types[INF_TOTAL_FIELDS] = {
	[INF_NAME]                           = IST("untyped"),
	[INF_VERSION]                        = IST("untyped"),
	[INF_RELEASE_DATE]                   = IST("untyped"),
	[INF_NBTHREAD]                       = IST("gauge"),
	[INF_NBPROC]                         = IST("gauge"),
	[INF_PROCESS_NUM]                    = IST("gauge"),
	[INF_PID]                            = IST("untyped"),
	[INF_UPTIME]                         = IST("untyped"),
	[INF_UPTIME_SEC]                     = IST("gauge"),
	[INF_MEMMAX_MB]                      = IST("gauge"),
	[INF_POOL_ALLOC_MB]                  = IST("gauge"),
	[INF_POOL_USED_MB]                   = IST("gauge"),
	[INF_POOL_FAILED]                    = IST("counter"),
	[INF_ULIMIT_N]                       = IST("gauge"),
	[INF_MAXSOCK]                        = IST("gauge"),
	[INF_MAXCONN]                        = IST("gauge"),
	[INF_HARD_MAXCONN]                   = IST("gauge"),
	[INF_CURR_CONN]                      = IST("gauge"),
	[INF_CUM_CONN]                       = IST("counter"),
	[INF_CUM_REQ]                        = IST("counter"),
	[INF_MAX_SSL_CONNS]                  = IST("gauge"),
	[INF_CURR_SSL_CONNS]                 = IST("gauge"),
	[INF_CUM_SSL_CONNS]                  = IST("counter"),
	[INF_MAXPIPES]                       = IST("gauge"),
	[INF_PIPES_USED]                     = IST("counter"),
	[INF_PIPES_FREE]                     = IST("counter"),
	[INF_CONN_RATE]                      = IST("gauge"),
	[INF_CONN_RATE_LIMIT]                = IST("gauge"),
	[INF_MAX_CONN_RATE]                  = IST("gauge"),
	[INF_SESS_RATE]                      = IST("gauge"),
	[INF_SESS_RATE_LIMIT]                = IST("gauge"),
	[INF_MAX_SESS_RATE]                  = IST("gauge"),
	[INF_SSL_RATE]                       = IST("gauge"),
	[INF_SSL_RATE_LIMIT]                 = IST("gauge"),
	[INF_MAX_SSL_RATE]                   = IST("gauge"),
	[INF_SSL_FRONTEND_KEY_RATE]          = IST("gauge"),
	[INF_SSL_FRONTEND_MAX_KEY_RATE]      = IST("gauge"),
	[INF_SSL_FRONTEND_SESSION_REUSE_PCT] = IST("gauge"),
	[INF_SSL_BACKEND_KEY_RATE]           = IST("gauge"),
	[INF_SSL_BACKEND_MAX_KEY_RATE]       = IST("gauge"),
	[INF_SSL_CACHE_LOOKUPS]              = IST("counter"),
	[INF_SSL_CACHE_MISSES]               = IST("counter"),
	[INF_COMPRESS_BPS_IN]                = IST("counter"),
	[INF_COMPRESS_BPS_OUT]               = IST("counter"),
	[INF_COMPRESS_BPS_RATE_LIM]          = IST("gauge"),
	[INF_ZLIB_MEM_USAGE]                 = IST("gauge"),
	[INF_MAX_ZLIB_MEM_USAGE]             = IST("gauge"),
	[INF_TASKS]                          = IST("gauge"),
	[INF_RUN_QUEUE]                      = IST("gauge"),
	[INF_IDLE_PCT]                       = IST("gauge"),
	[INF_NODE]                           = IST("untyped"),
	[INF_DESCRIPTION]                    = IST("untyped"),
	[INF_STOPPING]                       = IST("gauge"),
	[INF_JOBS]                           = IST("gauge"),
	[INF_UNSTOPPABLE_JOBS]               = IST("gauge"),
	[INF_LISTENERS]                      = IST("gauge"),
	[INF_ACTIVE_PEERS]                   = IST("gauge"),
	[INF_CONNECTED_PEERS]                = IST("gauge"),
	[INF_DROPPED_LOGS]                   = IST("counter"),
	[INF_BUSY_POLLING]                   = IST("gauge"),
	[INF_FAILED_RESOLUTIONS]             = IST("counter"),
	[INF_TOTAL_BYTES_OUT]                = IST("counter"),
	[INF_TOTAL_SPLICED_BYTES_OUT]        = IST("counter"),
	[INF_BYTES_OUT_RATE]                 = IST("gauge"),
	[INF_DEBUG_COMMANDS_ISSUED]          = IST(""),
};

/* Type for all stats fields. "untyped" is used for unsupported field. */
const struct ist promex_st_metric_types[ST_F_TOTAL_FIELDS] = {
	[ST_F_PXNAME]         = IST("untyped"),
	[ST_F_SVNAME]         = IST("untyped"),
	[ST_F_QCUR]           = IST("gauge"),
	[ST_F_QMAX]           = IST("gauge"),
	[ST_F_SCUR]           = IST("gauge"),
	[ST_F_SMAX]           = IST("gauge"),
	[ST_F_SLIM]           = IST("gauge"),
	[ST_F_STOT]           = IST("counter"),
	[ST_F_BIN]            = IST("counter"),
	[ST_F_BOUT]           = IST("counter"),
	[ST_F_DREQ]           = IST("counter"),
	[ST_F_DRESP]          = IST("counter"),
	[ST_F_EREQ]           = IST("counter"),
	[ST_F_ECON]           = IST("counter"),
	[ST_F_ERESP]          = IST("counter"),
	[ST_F_WRETR]          = IST("counter"),
	[ST_F_WREDIS]         = IST("counter"),
	[ST_F_STATUS]         = IST("gauge"),
	[ST_F_WEIGHT]         = IST("gauge"),
	[ST_F_ACT]            = IST("gauge"),
	[ST_F_BCK]            = IST("gauge"),
	[ST_F_CHKFAIL]        = IST("counter"),
	[ST_F_CHKDOWN]        = IST("counter"),
	[ST_F_LASTCHG]        = IST("gauge"),
	[ST_F_DOWNTIME]       = IST("counter"),
	[ST_F_QLIMIT]         = IST("gauge"),
	[ST_F_PID]            = IST("untyped"),
	[ST_F_IID]            = IST("untyped"),
	[ST_F_SID]            = IST("untyped"),
	[ST_F_THROTTLE]       = IST("gauge"),
	[ST_F_LBTOT]          = IST("counter"),
	[ST_F_TRACKED]        = IST("untyped"),
	[ST_F_TYPE]           = IST("untyped"),
	[ST_F_RATE]           = IST("untyped"),
	[ST_F_RATE_LIM]       = IST("gauge"),
	[ST_F_RATE_MAX]       = IST("gauge"),
	[ST_F_CHECK_STATUS]   = IST("gauge"),
	[ST_F_CHECK_CODE]     = IST("gauge"),
	[ST_F_CHECK_DURATION] = IST("gauge"),
	[ST_F_HRSP_1XX]       = IST("counter"),
	[ST_F_HRSP_2XX]       = IST("counter"),
	[ST_F_HRSP_3XX]       = IST("counter"),
	[ST_F_HRSP_4XX]       = IST("counter"),
	[ST_F_HRSP_5XX]       = IST("counter"),
	[ST_F_HRSP_OTHER]     = IST("counter"),
	[ST_F_HANAFAIL]       = IST("counter"),
	[ST_F_REQ_RATE]       = IST("untyped"),
	[ST_F_REQ_RATE_MAX]   = IST("gauge"),
	[ST_F_REQ_TOT]        = IST("counter"),
	[ST_F_CLI_ABRT]       = IST("counter"),
	[ST_F_SRV_ABRT]       = IST("counter"),
	[ST_F_COMP_IN]        = IST("counter"),
	[ST_F_COMP_OUT]       = IST("counter"),
	[ST_F_COMP_BYP]       = IST("counter"),
	[ST_F_COMP_RSP]       = IST("counter"),
	[ST_F_LASTSESS]       = IST("gauge"),
	[ST_F_LAST_CHK]       = IST("untyped"),
	[ST_F_LAST_AGT]       = IST("untyped"),
	[ST_F_QTIME]          = IST("gauge"),
	[ST_F_CTIME]          = IST("gauge"),
	[ST_F_RTIME]          = IST("gauge"),
	[ST_F_TTIME]          = IST("gauge"),
	[ST_F_AGENT_STATUS]   = IST("untyped"),
	[ST_F_AGENT_CODE]     = IST("untyped"),
	[ST_F_AGENT_DURATION] = IST("gauge"),
	[ST_F_CHECK_DESC]     = IST("untyped"),
	[ST_F_AGENT_DESC]     = IST("untyped"),
	[ST_F_CHECK_RISE]     = IST("gauge"),
	[ST_F_CHECK_FALL]     = IST("gauge"),
	[ST_F_CHECK_HEALTH]   = IST("gauge"),
	[ST_F_AGENT_RISE]     = IST("gauge"),
	[ST_F_AGENT_FALL]     = IST("gauge"),
	[ST_F_AGENT_HEALTH]   = IST("gauge"),
	[ST_F_ADDR]           = IST("untyped"),
	[ST_F_COOKIE]         = IST("untyped"),
	[ST_F_MODE]           = IST("untyped"),
	[ST_F_ALGO]           = IST("untyped"),
	[ST_F_CONN_RATE]      = IST("untyped"),
	[ST_F_CONN_RATE_MAX]  = IST("gauge"),
	[ST_F_CONN_TOT]       = IST("counter"),
	[ST_F_INTERCEPTED]    = IST("counter"),
	[ST_F_DCON]           = IST("counter"),
	[ST_F_DSES]           = IST("counter"),
	[ST_F_WREW]           = IST("counter"),
	[ST_F_CONNECT]        = IST("counter"),
	[ST_F_REUSE]          = IST("counter"),
	[ST_F_CACHE_LOOKUPS]  = IST("counter"),
	[ST_F_CACHE_HITS]     = IST("counter"),
	[ST_F_SRV_ICUR]       = IST("gauge"),
	[ST_F_SRV_ILIM]       = IST("gauge"),
	[ST_F_QT_MAX]         = IST("gauge"),
	[ST_F_CT_MAX]         = IST("gauge"),
	[ST_F_RT_MAX]         = IST("gauge"),
	[ST_F_TT_MAX]         = IST("gauge"),
	[ST_F_EINT]           = IST("counter"),
	[ST_F_IDLE_CONN_CUR]  = IST("gauge"),
	[ST_F_SAFE_CONN_CUR]  = IST("gauge"),
	[ST_F_USED_CONN_CUR]  = IST("gauge"),
	[ST_F_NEED_CONN_EST]  = IST("gauge"),
};

/* Return the server status: 0=DOWN, 1=UP, 2=MAINT, 3=DRAIN, 4=NOLB. */
static int promex_srv_status(struct server *sv)
{
	int state = 0;

	if (sv->cur_state == SRV_ST_RUNNING || sv->cur_state == SRV_ST_STARTING) {
		state = 1;
		if (sv->cur_admin & SRV_ADMF_DRAIN)
			state = 3;
	}
	else if (sv->cur_state == SRV_ST_STOPPING)
		state = 4;

	if (sv->cur_admin & SRV_ADMF_MAINT)
		state = 2;

	return state;
}

/* Convert a field to its string representation and write it in <out>, followed
 * by a newline, if there is enough space. non-numeric value are converted in
 * "Nan" because Prometheus only support numerical values (but it is unexepceted
 * to process this kind of value). It returns 1 on success. Otherwise, it
 * returns 0. The buffer's length must not exceed <max> value.
 */
static int promex_metric_to_str(struct buffer *out, struct field *f, size_t max)
{
	int ret = 0;

	switch (field_format(f, 0)) {
		case FF_EMPTY: ret = chunk_strcat(out,  "Nan\n"); break;
		case FF_S32:   ret = chunk_appendf(out, "%d\n", f->u.s32); break;
		case FF_U32:   ret = chunk_appendf(out, "%u\n", f->u.u32); break;
		case FF_S64:   ret = chunk_appendf(out, "%lld\n", (long long)f->u.s64); break;
		case FF_U64:   ret = chunk_appendf(out, "%llu\n", (unsigned long long)f->u.u64); break;
		case FF_FLT:   ret = chunk_appendf(out, "%f\n", f->u.flt); break;
		case FF_STR:   ret = chunk_strcat(out,  "Nan\n"); break;
		default:       ret = chunk_strcat(out,  "Nan\n"); break;
	}
	if (!ret || out->data > max)
		return 0;
	return 1;
}

/* Concatenate the <prefix> with the field name using the array
 * <promex_st_metric_names> and store it in <name>. The field type is in
 * <appctx->st2>. This function never fails but relies on
 * <PROMEX_MAX_NAME_LEN>. So by sure the result is small enough to be copied in
 * <name>
 */
static void promex_metric_name(struct appctx *appctx, struct ist *name, const struct ist prefix)
{
	const struct ist *names;

	names = ((appctx->ctx.stats.flags & PROMEX_FL_INFO_METRIC)
		 ? promex_inf_metric_names
		 : promex_st_metric_names);

	istcat(name, prefix, PROMEX_MAX_NAME_LEN);
	istcat(name, names[appctx->st2],  PROMEX_MAX_NAME_LEN);
}

/* Dump the header lines for <metric>. It is its #HELP and #TYPE strings. It
 * returns 1 on success. Otherwise, if <out> length exceeds <max>, it returns 0.
 */
static int promex_dump_metric_header(struct appctx *appctx, struct htx *htx,
				     const struct ist name, struct ist *out, size_t max)
{
	const struct ist *desc, *types;

	if (appctx->ctx.stats.flags & PROMEX_FL_INFO_METRIC) {
		desc  = promex_inf_metric_desc;
		types = promex_inf_metric_types;
	}
	else {
		desc  = promex_st_metric_desc;
		types = promex_st_metric_types;
	}

	if (istcat(out, ist("# HELP "), max) == -1 ||
	    istcat(out, name, max) == -1 ||
	    istcat(out, ist(" "), max) == -1 ||
	    istcat(out, desc[appctx->st2], max) == -1 ||
	    istcat(out, ist("\n# TYPE "), max) == -1 ||
	    istcat(out, name, max) == -1 ||
	    istcat(out, ist(" "), max) == -1 ||
	    istcat(out, types[appctx->st2], max) == -1 ||
	    istcat(out, ist("\n"), max) == -1)
		goto full;

	return 1;

  full:
	return 0;
}

/* Dump the line for <metric>. It starts by the metric name followed by its
 * labels (proxy name, server name...) between braces and finally its value. If
 * not already done, the header lines are dumped first. It returns 1 on
 * success. Otherwise if <out> length exceeds <max>, it returns 0.
 */
static int promex_dump_metric(struct appctx *appctx, struct htx *htx,
			      const struct ist prefix, struct field *metric,
			      struct ist *out, size_t max)
{
	struct ist name = { .ptr = (char[PROMEX_MAX_NAME_LEN]){ 0 }, .len = 0 };
	size_t len = out->len;

	if (out->len + PROMEX_MAX_METRIC_LENGTH > max)
		return 0;

	promex_metric_name(appctx, &name, prefix);
	if ((appctx->ctx.stats.flags & PROMEX_FL_METRIC_HDR) &&
	    !promex_dump_metric_header(appctx, htx, name, out, max))
		goto full;

	if (appctx->ctx.stats.flags & PROMEX_FL_INFO_METRIC) {
		const struct ist label = promex_inf_metric_labels[appctx->st2];

		if (istcat(out, name, max) == -1 ||
		    (label.len && istcat(out, ist("{"), max) == -1) ||
		    (label.len && istcat(out, label, max) == -1) ||
		    (label.len && istcat(out, ist("}"), max) == -1) ||
		    istcat(out, ist(" "), max) == -1)
			goto full;
	}
	else {
		struct proxy *px = appctx->ctx.stats.obj1;
		struct server *srv = appctx->ctx.stats.obj2;
		const struct ist label = promex_st_metric_labels[appctx->st2];

		if (istcat(out, name, max) == -1 ||
		    istcat(out, ist("{proxy=\""), max) == -1 ||
		    istcat(out, ist2(px->id, strlen(px->id)), max) == -1 ||
		    istcat(out, ist("\""), max) == -1 ||
		    (srv && istcat(out, ist(",server=\""), max) == -1) ||
		    (srv && istcat(out, ist2(srv->id, strlen(srv->id)), max) == -1) ||
		    (srv && istcat(out, ist("\""), max) == -1) ||
		    (label.len && istcat(out, ist(","), max) == -1) ||
		    (label.len && istcat(out, label, max) == -1) ||
		    istcat(out, ist("} "), max) == -1)
			goto full;
	}

	trash.data = out->len;
	if (!promex_metric_to_str(&trash, metric, max))
		goto full;
	out->len = trash.data;

	appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
	return 1;
  full:
	// Restore previous length
	out->len = len;
	return 0;

}


/* Dump global metrics (prefixed by "haproxy_process_"). It returns 1 on success,
 * 0 if <htx> is full and -1 in case of any error. */
static int promex_dump_global_metrics(struct appctx *appctx, struct htx *htx)
{
	static struct ist prefix = IST("haproxy_process_");
	struct field metric;
	struct channel *chn = si_ic(appctx->owner);
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	int ret = 1;

#ifdef USE_OPENSSL
	int ssl_sess_rate = read_freq_ctr(&global.ssl_per_sec);
	int ssl_key_rate = read_freq_ctr(&global.ssl_fe_keys_per_sec);
	int ssl_reuse = 0;

	if (ssl_key_rate < ssl_sess_rate) {
		/* count the ssl reuse ratio and avoid overflows in both directions */
		ssl_reuse = 100 - (100 * ssl_key_rate + (ssl_sess_rate - 1) / 2) / ssl_sess_rate;
	}
#endif
	while (appctx->st2 && appctx->st2 < INF_TOTAL_FIELDS) {
		switch (appctx->st2) {
			case INF_NBTHREAD:
				metric = mkf_u32(FO_CONFIG|FS_SERVICE, global.nbthread);
				break;
			case INF_NBPROC:
				metric = mkf_u32(FO_CONFIG|FS_SERVICE, global.nbproc);
				break;
			case INF_PROCESS_NUM:
				metric = mkf_u32(FO_KEY, relative_pid);
				break;
			case INF_UPTIME_SEC:
				metric = mkf_u32(FN_DURATION, start_date.tv_sec);
				break;
			case INF_MEMMAX_MB:
				metric = mkf_u64(FO_CONFIG|FN_LIMIT, global.rlimit_memmax * 1048576L);
				break;
			case INF_POOL_ALLOC_MB:
				metric = mkf_u64(0, pool_total_allocated());
				break;
			case INF_POOL_USED_MB:
				metric = mkf_u64(0, pool_total_used());
				break;
			case INF_POOL_FAILED:
				metric = mkf_u32(FN_COUNTER, pool_total_failures());
				break;
			case INF_ULIMIT_N:
				metric = mkf_u32(FO_CONFIG|FN_LIMIT, global.rlimit_nofile);
				break;
			case INF_MAXSOCK:
				metric = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxsock);
				break;
			case INF_MAXCONN:
				metric = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxconn);
				break;
			case INF_HARD_MAXCONN:
				metric = mkf_u32(FO_CONFIG|FN_LIMIT, global.hardmaxconn);
				break;
			case INF_CURR_CONN:
				metric = mkf_u32(0, actconn);
				break;
			case INF_CUM_CONN:
				metric = mkf_u32(FN_COUNTER, totalconn);
				break;
			case INF_CUM_REQ:
				metric = mkf_u32(FN_COUNTER, global.req_count);
				break;
#ifdef USE_OPENSSL
			case INF_MAX_SSL_CONNS:
				metric = mkf_u32(FN_MAX, global.maxsslconn);
				break;
			case INF_CURR_SSL_CONNS:
				metric = mkf_u32(0, sslconns);
				break;
			case INF_CUM_SSL_CONNS:
				metric = mkf_u32(FN_COUNTER, totalsslconns);
				break;
#endif
			case INF_MAXPIPES:
				metric = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxpipes);
				break;
			case INF_PIPES_USED:
				metric = mkf_u32(0, pipes_used);
				break;
			case INF_PIPES_FREE:
				metric = mkf_u32(0, pipes_free);
				break;
			case INF_CONN_RATE:
				metric = mkf_u32(FN_RATE, read_freq_ctr(&global.conn_per_sec));
				break;
			case INF_CONN_RATE_LIMIT:
				metric = mkf_u32(FO_CONFIG|FN_LIMIT, global.cps_lim);
				break;
			case INF_MAX_CONN_RATE:
				metric = mkf_u32(FN_MAX, global.cps_max);
				break;
			case INF_SESS_RATE:
				metric = mkf_u32(FN_RATE, read_freq_ctr(&global.sess_per_sec));
				break;
			case INF_SESS_RATE_LIMIT:
				metric = mkf_u32(FO_CONFIG|FN_LIMIT, global.sps_lim);
				break;
			case INF_MAX_SESS_RATE:
				metric = mkf_u32(FN_RATE, global.sps_max);
				break;
#ifdef USE_OPENSSL
			case INF_SSL_RATE:
				metric = mkf_u32(FN_RATE, ssl_sess_rate);
				break;
			case INF_SSL_RATE_LIMIT:
				metric = mkf_u32(FO_CONFIG|FN_LIMIT, global.ssl_lim);
				break;
			case INF_MAX_SSL_RATE:
				metric = mkf_u32(FN_MAX, global.ssl_max);
				break;
			case INF_SSL_FRONTEND_KEY_RATE:
				metric = mkf_u32(0, ssl_key_rate);
				break;
			case INF_SSL_FRONTEND_MAX_KEY_RATE:
				metric = mkf_u32(FN_MAX, global.ssl_fe_keys_max);
				break;
			case INF_SSL_FRONTEND_SESSION_REUSE_PCT:
				metric = mkf_u32(0, ssl_reuse);
				break;
			case INF_SSL_BACKEND_KEY_RATE:
				metric = mkf_u32(FN_RATE, read_freq_ctr(&global.ssl_be_keys_per_sec));
				break;
			case INF_SSL_BACKEND_MAX_KEY_RATE:
				metric = mkf_u32(FN_MAX, global.ssl_be_keys_max);
				break;
			case INF_SSL_CACHE_LOOKUPS:
				metric = mkf_u32(FN_COUNTER, global.shctx_lookups);
				break;
			case INF_SSL_CACHE_MISSES:
				metric = mkf_u32(FN_COUNTER, global.shctx_misses);
				break;
#endif
			case INF_COMPRESS_BPS_IN:
				metric = mkf_u32(FN_RATE, read_freq_ctr(&global.comp_bps_in));
				break;
			case INF_COMPRESS_BPS_OUT:
				metric = mkf_u32(FN_RATE, read_freq_ctr(&global.comp_bps_out));
				break;
			case INF_COMPRESS_BPS_RATE_LIM:
				metric = mkf_u32(FO_CONFIG|FN_LIMIT, global.comp_rate_lim);
				break;
#ifdef USE_ZLIB
			case INF_ZLIB_MEM_USAGE:
				metric = mkf_u32(0, zlib_used_memory);
				break;
			case INF_MAX_ZLIB_MEM_USAGE:
				metric = mkf_u32(FO_CONFIG|FN_LIMIT, global.maxzlibmem);
				break;
#endif
			case INF_TASKS:
				metric = mkf_u32(0, nb_tasks_cur);
				break;
			case INF_RUN_QUEUE:
				metric = mkf_u32(0, tasks_run_queue_cur);
				break;
			case INF_IDLE_PCT:
				metric = mkf_u32(FN_AVG, ti->idle_pct);
				break;
			case INF_STOPPING:
				metric = mkf_u32(0, stopping);
				break;
			case INF_JOBS:
				metric = mkf_u32(0, jobs);
				break;
			case INF_UNSTOPPABLE_JOBS:
				metric = mkf_u32(0, unstoppable_jobs);
				break;
			case INF_LISTENERS:
				metric = mkf_u32(0, listeners);
				break;
			case INF_ACTIVE_PEERS:
				metric = mkf_u32(0, active_peers);
				break;
			case INF_CONNECTED_PEERS:
				metric = mkf_u32(0, connected_peers);
				break;
			case INF_DROPPED_LOGS:
				metric = mkf_u32(0, dropped_logs);
				break;
			case INF_BUSY_POLLING:
				metric = mkf_u32(0, !!(global.tune.options & GTUNE_BUSY_POLLING));
				break;
			case INF_FAILED_RESOLUTIONS:
				metric = mkf_u32(0, dns_failed_resolutions);
				break;
			case INF_TOTAL_BYTES_OUT:
				metric = mkf_u64(0, global.out_bytes);
				break;
			case INF_TOTAL_SPLICED_BYTES_OUT:
				metric = mkf_u64(0, global.spliced_out_bytes);
				break;
			case INF_BYTES_OUT_RATE:
				metric = mkf_u64(FN_RATE, (unsigned long long)read_freq_ctr(&global.out_32bps) * 32);
				break;

			default:
				goto next_metric;
		}

		if (!promex_dump_metric(appctx, htx, prefix, &metric, &out, max))
			goto full;

	   next_metric:
		appctx->ctx.stats.flags |= PROMEX_FL_METRIC_HDR;
		appctx->st2 = promex_global_metrics[appctx->st2];
	}

  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}
	return ret;
  full:
	ret = 0;
	goto end;
}

/* Dump frontends metrics (prefixed by "haproxy_frontend_"). It returns 1 on success,
 * 0 if <htx> is full and -1 in case of any error. */
static int promex_dump_front_metrics(struct appctx *appctx, struct htx *htx)
{
	static struct ist prefix = IST("haproxy_frontend_");
	struct proxy *px;
	struct field metric;
	struct channel *chn = si_ic(appctx->owner);
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	int ret = 1;

	while (appctx->st2 && appctx->st2 < ST_F_TOTAL_FIELDS) {
		while (appctx->ctx.stats.obj1) {
			px = appctx->ctx.stats.obj1;

			/* skip the disabled proxies, global frontend and non-networked ones */
			if (px->disabled || px->uuid <= 0 || !(px->cap & PR_CAP_FE))
				goto next_px;

			switch (appctx->st2) {
				case ST_F_STATUS:
					metric = mkf_u32(FO_STATUS, !px->disabled);
					break;
				case ST_F_SCUR:
					metric = mkf_u32(0, px->feconn);
					break;
				case ST_F_SMAX:
					metric = mkf_u32(FN_MAX, px->fe_counters.conn_max);
					break;
				case ST_F_SLIM:
					metric = mkf_u32(FO_CONFIG|FN_LIMIT, px->maxconn);
					break;
				case ST_F_STOT:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.cum_sess);
					break;
				case ST_F_RATE_LIM:
					metric = mkf_u32(FO_CONFIG|FN_LIMIT, px->fe_sps_lim);
					break;
				case ST_F_RATE_MAX:
					metric = mkf_u32(FN_MAX, px->fe_counters.sps_max);
					break;
				case ST_F_CONN_RATE_MAX:
					metric = mkf_u32(FN_MAX, px->fe_counters.cps_max);
					break;
				case ST_F_CONN_TOT:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.cum_conn);
					break;
				case ST_F_BIN:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.bytes_in);
					break;
				case ST_F_BOUT:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.bytes_out);
					break;
				case ST_F_DREQ:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.denied_req);
					break;
				case ST_F_DRESP:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.denied_resp);
					break;
				case ST_F_EREQ:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.failed_req);
					break;
				case ST_F_DCON:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.denied_conn);
					break;
				case ST_F_DSES:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.denied_sess);
					break;
				case ST_F_WREW:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.failed_rewrites);
					break;
				case ST_F_EINT:
					metric = mkf_u64(FN_COUNTER, px->fe_counters.internal_errors);
					break;
				case ST_F_REQ_RATE_MAX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u32(FN_MAX, px->fe_counters.p.http.rps_max);
					break;
				case ST_F_REQ_TOT:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.p.http.cum_req);
					break;
				case ST_F_HRSP_1XX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.p.http.rsp[1]);
					break;
				case ST_F_HRSP_2XX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.p.http.rsp[2]);
					break;
				case ST_F_HRSP_3XX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.p.http.rsp[3]);
					break;
				case ST_F_HRSP_4XX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.p.http.rsp[4]);
					break;
				case ST_F_HRSP_5XX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.p.http.rsp[5]);
					break;
				case ST_F_HRSP_OTHER:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.p.http.rsp[0]);
					break;
				case ST_F_INTERCEPTED:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.intercepted_req);
					break;
				case ST_F_CACHE_LOOKUPS:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.p.http.cache_lookups);
					break;
				case ST_F_CACHE_HITS:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.p.http.cache_hits);
					break;
				case ST_F_COMP_IN:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.comp_in);
					break;
				case ST_F_COMP_OUT:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.comp_out);
					break;
				case ST_F_COMP_BYP:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.comp_byp);
					break;
				case ST_F_COMP_RSP:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->fe_counters.p.http.comp_rsp);
					break;

				default:
					goto next_metric;
			}

			if (!promex_dump_metric(appctx, htx, prefix, &metric, &out, max))
				goto full;
		  next_px:
			appctx->ctx.stats.obj1 = px->next;
		}
	  next_metric:
		appctx->ctx.stats.flags |= PROMEX_FL_METRIC_HDR;
		appctx->ctx.stats.obj1 = proxies_list;
		appctx->st2 = promex_front_metrics[appctx->st2];
	}

  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}
	return ret;
  full:
	ret = 0;
	goto end;
}

/* Dump backends metrics (prefixed by "haproxy_backend_"). It returns 1 on success,
 * 0 if <htx> is full and -1 in case of any error. */
static int promex_dump_back_metrics(struct appctx *appctx, struct htx *htx)
{
	static struct ist prefix = IST("haproxy_backend_");
	struct proxy *px;
	struct field metric;
	struct channel *chn = si_ic(appctx->owner);
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	int ret = 1;
	uint32_t weight;
	double secs;

	while (appctx->st2 && appctx->st2 < ST_F_TOTAL_FIELDS) {
		while (appctx->ctx.stats.obj1) {
			px = appctx->ctx.stats.obj1;

			/* skip the disabled proxies, global frontend and non-networked ones */
			if (px->disabled || px->uuid <= 0 || !(px->cap & PR_CAP_BE))
				goto next_px;

			switch (appctx->st2) {
				case ST_F_STATUS:
					metric = mkf_u32(FO_STATUS, (px->lbprm.tot_weight > 0 || !px->srv) ? 1 : 0);
					break;
				case ST_F_SCUR:
					metric = mkf_u32(0, px->beconn);
					break;
				case ST_F_SMAX:
					metric = mkf_u32(FN_MAX, px->be_counters.conn_max);
					break;
				case ST_F_SLIM:
					metric = mkf_u32(FO_CONFIG|FN_LIMIT, px->fullconn);
					break;
				case ST_F_STOT:
					metric = mkf_u64(FN_COUNTER, px->be_counters.cum_conn);
					break;
				case ST_F_RATE_MAX:
					metric = mkf_u32(0, px->be_counters.sps_max);
					break;
				case ST_F_LASTSESS:
					metric = mkf_s32(FN_AGE, be_lastsession(px));
					break;
				case ST_F_QCUR:
					metric = mkf_u32(0, px->nbpend);
					break;
				case ST_F_QMAX:
					metric = mkf_u32(FN_MAX, px->be_counters.nbpend_max);
					break;
				case ST_F_CONNECT:
					metric = mkf_u64(FN_COUNTER, px->be_counters.connect);
					break;
				case ST_F_REUSE:
					metric = mkf_u64(FN_COUNTER, px->be_counters.reuse);
					break;
				case ST_F_BIN:
					metric = mkf_u64(FN_COUNTER, px->be_counters.bytes_in);
					break;
				case ST_F_BOUT:
					metric = mkf_u64(FN_COUNTER, px->be_counters.bytes_out);
					break;
				case ST_F_QTIME:
					secs = (double)swrate_avg(px->be_counters.q_time, TIME_STATS_SAMPLES) / 1000.0;
					metric = mkf_flt(FN_AVG, secs);
					break;
				case ST_F_CTIME:
					secs = (double)swrate_avg(px->be_counters.c_time, TIME_STATS_SAMPLES) / 1000.0;
					metric = mkf_flt(FN_AVG, secs);
					break;
				case ST_F_RTIME:
					secs = (double)swrate_avg(px->be_counters.d_time, TIME_STATS_SAMPLES) / 1000.0;
					metric = mkf_flt(FN_AVG, secs);
					break;
				case ST_F_TTIME:
					secs = (double)swrate_avg(px->be_counters.t_time, TIME_STATS_SAMPLES) / 1000.0;
					metric = mkf_flt(FN_AVG, secs);
					break;
				case ST_F_QT_MAX:
					secs = (double)px->be_counters.qtime_max / 1000.0;
					metric = mkf_flt(FN_MAX, secs);
					break;
				case ST_F_CT_MAX:
					secs = (double)px->be_counters.ctime_max / 1000.0;
					metric = mkf_flt(FN_MAX, secs);
					break;
				case ST_F_RT_MAX:
					secs = (double)px->be_counters.dtime_max / 1000.0;
					metric = mkf_flt(FN_MAX, secs);
					break;
				case ST_F_TT_MAX:
					secs = (double)px->be_counters.ttime_max / 1000.0;
					metric = mkf_flt(FN_MAX, secs);
					break;
				case ST_F_DREQ:
					metric = mkf_u64(FN_COUNTER, px->be_counters.denied_req);
					break;
				case ST_F_DRESP:
					metric = mkf_u64(FN_COUNTER, px->be_counters.denied_resp);
					break;
				case ST_F_ECON:
					metric = mkf_u64(FN_COUNTER, px->be_counters.failed_conns);
					break;
				case ST_F_ERESP:
					metric = mkf_u64(FN_COUNTER, px->be_counters.failed_resp);
					break;
				case ST_F_WRETR:
					metric = mkf_u64(FN_COUNTER, px->be_counters.retries);
					break;
				case ST_F_WREDIS:
					metric = mkf_u64(FN_COUNTER, px->be_counters.redispatches);
					break;
				case ST_F_WREW:
					metric = mkf_u64(FN_COUNTER, px->be_counters.failed_rewrites);
					break;
				case ST_F_EINT:
					metric = mkf_u64(FN_COUNTER, px->be_counters.internal_errors);
					break;
				case ST_F_CLI_ABRT:
					metric = mkf_u64(FN_COUNTER, px->be_counters.cli_aborts);
					break;
				case ST_F_SRV_ABRT:
					metric = mkf_u64(FN_COUNTER, px->be_counters.srv_aborts);
					break;
				case ST_F_WEIGHT:
					weight = (px->lbprm.tot_weight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv;
					metric = mkf_u32(FN_AVG, weight);
					break;
				case ST_F_ACT:
					metric = mkf_u32(0, px->srv_act);
					break;
				case ST_F_BCK:
					metric = mkf_u32(0, px->srv_bck);
					break;
				case ST_F_CHKDOWN:
					metric = mkf_u64(FN_COUNTER, px->down_trans);
					break;
				case ST_F_LASTCHG:
					metric = mkf_u32(FN_AGE, now.tv_sec - px->last_change);
					break;
				case ST_F_DOWNTIME:
					metric = mkf_u32(FN_COUNTER, be_downtime(px));
					break;
				case ST_F_LBTOT:
					metric = mkf_u64(FN_COUNTER, px->be_counters.cum_lbconn);
					break;
				case ST_F_REQ_TOT:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->be_counters.p.http.cum_req);
					break;
				case ST_F_HRSP_1XX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->be_counters.p.http.rsp[1]);
					break;
				case ST_F_HRSP_2XX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
					metric = mkf_u64(FN_COUNTER, px->be_counters.p.http.rsp[2]);
					break;
				case ST_F_HRSP_3XX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
					metric = mkf_u64(FN_COUNTER, px->be_counters.p.http.rsp[3]);
					break;
				case ST_F_HRSP_4XX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
					metric = mkf_u64(FN_COUNTER, px->be_counters.p.http.rsp[4]);
					break;
				case ST_F_HRSP_5XX:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
					metric = mkf_u64(FN_COUNTER, px->be_counters.p.http.rsp[5]);
					break;
				case ST_F_HRSP_OTHER:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
					metric = mkf_u64(FN_COUNTER, px->be_counters.p.http.rsp[0]);
					break;
				case ST_F_CACHE_LOOKUPS:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->be_counters.p.http.cache_lookups);
					break;
				case ST_F_CACHE_HITS:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->be_counters.p.http.cache_hits);
					break;
				case ST_F_COMP_IN:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->be_counters.comp_in);
					break;
				case ST_F_COMP_OUT:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->be_counters.comp_out);
					break;
				case ST_F_COMP_BYP:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->be_counters.comp_byp);
					break;
				case ST_F_COMP_RSP:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					metric = mkf_u64(FN_COUNTER, px->be_counters.p.http.comp_rsp);
					break;

				default:
					goto next_metric;
			}

			if (!promex_dump_metric(appctx, htx, prefix, &metric, &out, max))
				goto full;
		  next_px:
			appctx->ctx.stats.obj1 = px->next;
		}
	  next_metric:
		appctx->ctx.stats.flags |= PROMEX_FL_METRIC_HDR;
		appctx->ctx.stats.obj1 = proxies_list;
		appctx->st2 = promex_back_metrics[appctx->st2];
	}

  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}
	return ret;
  full:
	ret = 0;
	goto end;
}

/* Dump servers metrics (prefixed by "haproxy_server_"). It returns 1 on success,
 * 0 if <htx> is full and -1 in case of any error. */
static int promex_dump_srv_metrics(struct appctx *appctx, struct htx *htx)
{
	static struct ist prefix = IST("haproxy_server_");
	struct proxy *px;
	struct server *sv;
	struct field metric;
	struct channel *chn = si_ic(appctx->owner);
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	int ret = 1;
	uint32_t weight;
	double secs;

	while (appctx->st2 && appctx->st2 < ST_F_TOTAL_FIELDS) {
		while (appctx->ctx.stats.obj1) {
			px = appctx->ctx.stats.obj1;

			/* skip the disabled proxies, global frontend and non-networked ones */
			if (px->disabled || px->uuid <= 0 || !(px->cap & PR_CAP_BE))
				goto next_px;

			while (appctx->ctx.stats.obj2) {
				sv = appctx->ctx.stats.obj2;

				if ((appctx->ctx.stats.flags & PROMEX_FL_NO_MAINT_SRV) && (sv->cur_admin & SRV_ADMF_MAINT))
					goto next_sv;

				switch (appctx->st2) {
					case ST_F_STATUS:
						metric = mkf_u32(FO_STATUS, promex_srv_status(sv));
						break;
					case ST_F_SCUR:
						metric = mkf_u32(0, sv->cur_sess);
						break;
					case ST_F_SMAX:
						metric = mkf_u32(FN_MAX, sv->counters.cur_sess_max);
						break;
					case ST_F_SLIM:
						metric = mkf_u32(FO_CONFIG|FN_LIMIT, sv->maxconn);
						break;
					case ST_F_STOT:
						metric = mkf_u64(FN_COUNTER, sv->counters.cum_sess);
						break;
					case ST_F_RATE_MAX:
						metric = mkf_u32(FN_MAX, sv->counters.sps_max);
						break;
					case ST_F_LASTSESS:
						metric = mkf_s32(FN_AGE, srv_lastsession(sv));
						break;
					case ST_F_QCUR:
						metric = mkf_u32(0, sv->nbpend);
						break;
					case ST_F_QMAX:
						metric = mkf_u32(FN_MAX, sv->counters.nbpend_max);
						break;
					case ST_F_QLIMIT:
						metric = mkf_u32(FO_CONFIG|FS_SERVICE, sv->maxqueue);
						break;
					case ST_F_BIN:
						metric = mkf_u64(FN_COUNTER, sv->counters.bytes_in);
						break;
					case ST_F_BOUT:
						metric = mkf_u64(FN_COUNTER, sv->counters.bytes_out);
						break;
					case ST_F_QTIME:
						secs = (double)swrate_avg(sv->counters.q_time, TIME_STATS_SAMPLES) / 1000.0;
						metric = mkf_flt(FN_AVG, secs);
						break;
					case ST_F_CTIME:
						secs = (double)swrate_avg(sv->counters.c_time, TIME_STATS_SAMPLES) / 1000.0;
						metric = mkf_flt(FN_AVG, secs);
						break;
					case ST_F_RTIME:
						secs = (double)swrate_avg(sv->counters.d_time, TIME_STATS_SAMPLES) / 1000.0;
						metric = mkf_flt(FN_AVG, secs);
						break;
					case ST_F_TTIME:
						secs = (double)swrate_avg(sv->counters.t_time, TIME_STATS_SAMPLES) / 1000.0;
						metric = mkf_flt(FN_AVG, secs);
						break;
					case ST_F_QT_MAX:
						secs = (double)sv->counters.qtime_max / 1000.0;
						metric = mkf_flt(FN_MAX, secs);
						break;
					case ST_F_CT_MAX:
						secs = (double)sv->counters.ctime_max / 1000.0;
						metric = mkf_flt(FN_MAX, secs);
						break;
					case ST_F_RT_MAX:
						secs = (double)sv->counters.dtime_max / 1000.0;
						metric = mkf_flt(FN_MAX, secs);
						break;
					case ST_F_TT_MAX:
						secs = (double)sv->counters.ttime_max / 1000.0;
						metric = mkf_flt(FN_MAX, secs);
						break;
					case ST_F_CONNECT:
						metric = mkf_u64(FN_COUNTER, sv->counters.connect);
						break;
					case ST_F_REUSE:
						metric = mkf_u64(FN_COUNTER, sv->counters.reuse);
						break;
					case ST_F_DRESP:
						metric = mkf_u64(FN_COUNTER, sv->counters.denied_resp);
						break;
					case ST_F_ECON:
						metric = mkf_u64(FN_COUNTER, sv->counters.failed_conns);
						break;
					case ST_F_ERESP:
						metric = mkf_u64(FN_COUNTER, sv->counters.failed_resp);
						break;
					case ST_F_WRETR:
						metric = mkf_u64(FN_COUNTER, sv->counters.retries);
						break;
					case ST_F_WREDIS:
						metric = mkf_u64(FN_COUNTER, sv->counters.redispatches);
						break;
					case ST_F_WREW:
						metric = mkf_u64(FN_COUNTER, sv->counters.failed_rewrites);
						break;
					case ST_F_EINT:
						metric = mkf_u64(FN_COUNTER, sv->counters.internal_errors);
						break;
					case ST_F_CLI_ABRT:
						metric = mkf_u64(FN_COUNTER, sv->counters.cli_aborts);
						break;
					case ST_F_SRV_ABRT:
						metric = mkf_u64(FN_COUNTER, sv->counters.srv_aborts);
						break;
					case ST_F_WEIGHT:
						weight = (sv->cur_eweight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv;
						metric = mkf_u32(FN_AVG, weight);
						break;
					case ST_F_CHECK_STATUS:
						if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) != CHK_ST_ENABLED)
							goto next_sv;
						metric = mkf_u32(FN_OUTPUT, sv->check.status);
						break;
					case ST_F_CHECK_CODE:
						if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) != CHK_ST_ENABLED)
							goto next_sv;
						metric = mkf_u32(FN_OUTPUT, (sv->check.status < HCHK_STATUS_L57DATA) ? 0 : sv->check.code);
						break;
					case ST_F_CHECK_DURATION:
						if (sv->check.status < HCHK_STATUS_CHECKED)
						    goto next_sv;
						secs = (double)sv->check.duration / 1000.0;
						metric = mkf_flt(FN_DURATION, secs);
						break;
					case ST_F_CHKFAIL:
						metric = mkf_u64(FN_COUNTER, sv->counters.failed_checks);
						break;
					case ST_F_CHKDOWN:
						metric = mkf_u64(FN_COUNTER, sv->counters.down_trans);
						break;
					case ST_F_DOWNTIME:
						metric = mkf_u32(FN_COUNTER, srv_downtime(sv));
						break;
					case ST_F_LASTCHG:
						metric = mkf_u32(FN_AGE, now.tv_sec - sv->last_change);
						break;
					case ST_F_THROTTLE:
						metric = mkf_u32(FN_AVG, server_throttle_rate(sv));
						break;
					case ST_F_LBTOT:
						metric = mkf_u64(FN_COUNTER, sv->counters.cum_lbconn);
						break;
					case ST_F_REQ_TOT:
						if (px->mode != PR_MODE_HTTP)
							goto next_px;
						metric = mkf_u64(FN_COUNTER, sv->counters.p.http.cum_req);
						break;
					case ST_F_HRSP_1XX:
						if (px->mode != PR_MODE_HTTP)
							goto next_px;
						metric = mkf_u64(FN_COUNTER, sv->counters.p.http.rsp[1]);
						break;
					case ST_F_HRSP_2XX:
						if (px->mode != PR_MODE_HTTP)
							goto next_px;
						appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
						metric = mkf_u64(FN_COUNTER, sv->counters.p.http.rsp[2]);
						break;
					case ST_F_HRSP_3XX:
						if (px->mode != PR_MODE_HTTP)
							goto next_px;
						appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
						metric = mkf_u64(FN_COUNTER, sv->counters.p.http.rsp[3]);
						break;
					case ST_F_HRSP_4XX:
						if (px->mode != PR_MODE_HTTP)
							goto next_px;
						appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
						metric = mkf_u64(FN_COUNTER, sv->counters.p.http.rsp[4]);
						break;
					case ST_F_HRSP_5XX:
						if (px->mode != PR_MODE_HTTP)
							goto next_px;
						appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
						metric = mkf_u64(FN_COUNTER, sv->counters.p.http.rsp[5]);
						break;
					case ST_F_HRSP_OTHER:
						if (px->mode != PR_MODE_HTTP)
							goto next_px;
						appctx->ctx.stats.flags &= ~PROMEX_FL_METRIC_HDR;
						metric = mkf_u64(FN_COUNTER, sv->counters.p.http.rsp[0]);
						break;
					case ST_F_SRV_ICUR:
						metric = mkf_u32(0, sv->curr_idle_conns);
						break;
					case ST_F_SRV_ILIM:
						metric = mkf_u32(FO_CONFIG|FN_LIMIT, (sv->max_idle_conns == -1) ? 0 : sv->max_idle_conns);
						break;
					case ST_F_IDLE_CONN_CUR:
						metric = mkf_u32(0, sv->curr_idle_nb);
						break;
					case ST_F_SAFE_CONN_CUR:
						metric = mkf_u32(0, sv->curr_safe_nb);
						break;
					case ST_F_USED_CONN_CUR:
						metric = mkf_u32(0, sv->curr_used_conns);
						break;
					case ST_F_NEED_CONN_EST:
						metric = mkf_u32(0, sv->est_need_conns);
						break;

					default:
						goto next_metric;
				}

				if (!promex_dump_metric(appctx, htx, prefix, &metric, &out, max))
					goto full;

			  next_sv:
				appctx->ctx.stats.obj2 = sv->next;
			}

		  next_px:
			appctx->ctx.stats.obj1 = px->next;
			appctx->ctx.stats.obj2 = (appctx->ctx.stats.obj1 ? ((struct proxy *)appctx->ctx.stats.obj1)->srv : NULL);
		}
	  next_metric:
		appctx->ctx.stats.flags |= PROMEX_FL_METRIC_HDR;
		appctx->ctx.stats.obj1 = proxies_list;
		appctx->ctx.stats.obj2 = (appctx->ctx.stats.obj1 ? ((struct proxy *)appctx->ctx.stats.obj1)->srv : NULL);
		appctx->st2 = promex_srv_metrics[appctx->st2];
	}


  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}
	return ret;
  full:
	ret = 0;
	goto end;
}

/* Dump all metrics (global, frontends, backends and servers) depending on the
 * dumper state (appctx->st1). It returns 1 on success, 0 if <htx> is full and
 * -1 in case of any error.
 * Uses <appctx.ctx.stats.obj1> as a pointer to the current proxy and <obj2> as
 * a pointer to the current server/listener. */
static int promex_dump_metrics(struct appctx *appctx, struct stream_interface *si, struct htx *htx)
{
	int ret;

	switch (appctx->st1) {
		case PROMEX_DUMPER_INIT:
			appctx->ctx.stats.obj1 = NULL;
			appctx->ctx.stats.obj2 = NULL;
			appctx->ctx.stats.flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_INFO_METRIC);
			appctx->st2 = promex_global_metrics[INF_NAME];
			appctx->st1 = PROMEX_DUMPER_GLOBAL;
			/* fall through */

		case PROMEX_DUMPER_GLOBAL:
			if (appctx->ctx.stats.flags & PROMEX_FL_SCOPE_GLOBAL) {
				ret = promex_dump_global_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			appctx->ctx.stats.obj1 = proxies_list;
			appctx->ctx.stats.obj2 = NULL;
			appctx->ctx.stats.flags &= ~PROMEX_FL_INFO_METRIC;
			appctx->ctx.stats.flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_STATS_METRIC);
			appctx->st2 = promex_front_metrics[ST_F_PXNAME];
			appctx->st1 = PROMEX_DUMPER_FRONT;
			/* fall through */

		case PROMEX_DUMPER_FRONT:
			if (appctx->ctx.stats.flags & PROMEX_FL_SCOPE_FRONT) {
				ret = promex_dump_front_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			appctx->ctx.stats.obj1 = proxies_list;
			appctx->ctx.stats.obj2 = NULL;
			appctx->ctx.stats.flags |= PROMEX_FL_METRIC_HDR;
			appctx->st2 = promex_back_metrics[ST_F_PXNAME];
			appctx->st1 = PROMEX_DUMPER_BACK;
			/* fall through */

		case PROMEX_DUMPER_BACK:
			if (appctx->ctx.stats.flags & PROMEX_FL_SCOPE_BACK) {
				ret = promex_dump_back_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			appctx->ctx.stats.obj1 = proxies_list;
			appctx->ctx.stats.obj2 = (appctx->ctx.stats.obj1 ? ((struct proxy *)appctx->ctx.stats.obj1)->srv : NULL);
			appctx->ctx.stats.flags |= PROMEX_FL_METRIC_HDR;
			appctx->st2 = promex_srv_metrics[ST_F_PXNAME];
			appctx->st1 = PROMEX_DUMPER_SRV;
			/* fall through */

		case PROMEX_DUMPER_SRV:
			if (appctx->ctx.stats.flags & PROMEX_FL_SCOPE_SERVER) {
				ret = promex_dump_srv_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			appctx->ctx.stats.obj1 = NULL;
			appctx->ctx.stats.obj2 = NULL;
			appctx->ctx.stats.flags &= ~(PROMEX_FL_METRIC_HDR|PROMEX_FL_INFO_METRIC|PROMEX_FL_STATS_METRIC);
			appctx->st2 = 0;
			appctx->st1 = PROMEX_DUMPER_DONE;
			/* fall through */

		case PROMEX_DUMPER_DONE:
		default:
			break;
	}

	return 1;

  full:
	si_rx_room_blk(si);
	return 0;
  error:
	/* unrecoverable error */
	appctx->ctx.stats.obj1 = NULL;
	appctx->ctx.stats.obj2 = NULL;
	appctx->ctx.stats.flags = 0;
	appctx->st2 = 0;
	appctx->st1 = PROMEX_DUMPER_DONE;
	return -1;
}

/* Parse the query string of request URI to filter the metrics. It returns 1 on
 * success and -1 on error. */
static int promex_parse_uri(struct appctx *appctx, struct stream_interface *si)
{
	struct channel *req = si_oc(si);
	struct channel *res = si_ic(si);
	struct htx *req_htx, *res_htx;
	struct htx_sl *sl;
	char *p, *key, *value;
	const char *end;
	struct buffer *err;
	int default_scopes = PROMEX_FL_SCOPE_ALL;
	int len;

	/* Get the query-string */
	req_htx = htxbuf(&req->buf);
	sl = http_get_stline(req_htx);
	if (!sl)
		goto error;
	p = http_find_param_list(HTX_SL_REQ_UPTR(sl), HTX_SL_REQ_ULEN(sl), '?');
	if (!p)
		goto end;
	end = HTX_SL_REQ_UPTR(sl) + HTX_SL_REQ_ULEN(sl);

	/* copy the query-string */
	len = end - p;
	chunk_reset(&trash);
	memcpy(trash.area, p, len);
	trash.area[len] = 0;
	p = trash.area;
	end = trash.area + len;

	/* Parse the query-string */
	while (p < end && *p && *p != '#') {
		value = NULL;

		/* decode parameter name */
		key = p;
		while (p < end && *p != '=' && *p != '&' && *p != '#')
			++p;
		/* found a value */
		if (*p == '=') {
			*(p++) = 0;
			value = p;
		}
		else if (*p == '&')
			*(p++) = 0;
		else if (*p == '#')
			*p = 0;
		len = url_decode(key, 1);
		if (len == -1)
			goto error;

		/* decode value */
		if (value) {
			while (p < end && *p != '=' && *p != '&' && *p != '#')
				++p;
			if (*p == '=')
				goto error;
			if (*p == '&')
				*(p++) = 0;
			else if (*p == '#')
				*p = 0;
			len = url_decode(value, 1);
			if (len == -1)
				goto error;
		}

		if (strcmp(key, "scope") == 0) {
			default_scopes = 0; /* at least a scope defined, unset default scopes */
			if (!value)
				goto error;
			else if (*value == 0)
				appctx->ctx.stats.flags &= ~PROMEX_FL_SCOPE_ALL;
			else if (*value == '*')
				appctx->ctx.stats.flags |= PROMEX_FL_SCOPE_ALL;
			else if (strcmp(value, "global") == 0)
				appctx->ctx.stats.flags |= PROMEX_FL_SCOPE_GLOBAL;
			else if (strcmp(value, "server") == 0)
				appctx->ctx.stats.flags |= PROMEX_FL_SCOPE_SERVER;
			else if (strcmp(value, "backend") == 0)
				appctx->ctx.stats.flags |= PROMEX_FL_SCOPE_BACK;
			else if (strcmp(value, "frontend") == 0)
				appctx->ctx.stats.flags |= PROMEX_FL_SCOPE_FRONT;
			else
				goto error;
		}
		else if (strcmp(key, "no-maint") == 0)
			appctx->ctx.stats.flags |= PROMEX_FL_NO_MAINT_SRV;
	}

  end:
	appctx->ctx.stats.flags |= default_scopes;
	return 1;

  error:
	err = &http_err_chunks[HTTP_ERR_400];
	channel_erase(res);
	res->buf.data = b_data(err);
	memcpy(res->buf.area, b_head(err), b_data(err));
	res_htx = htx_from_buf(&res->buf);
	channel_add_input(res, res_htx->data);
	appctx->st0 = PROMEX_ST_END;
	return -1;
}

/* Send HTTP headers of the response. It returns 1 on success and 0 if <htx> is
 * full. */
static int promex_send_headers(struct appctx *appctx, struct stream_interface *si, struct htx *htx)
{
	struct channel *chn = si_ic(appctx->owner);
	struct htx_sl *sl;
	unsigned int flags;

	flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_ENC|HTX_SL_F_XFER_LEN|HTX_SL_F_CHNK);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), ist("200"), ist("OK"));
	if (!sl)
		goto full;
	sl->info.res.status = 200;
	if (!htx_add_header(htx, ist("Cache-Control"), ist("no-cache")) ||
	    !htx_add_header(htx, ist("Connection"), ist("close")) ||
	    !htx_add_header(htx, ist("Content-Type"), ist("text/plain; version=0.0.4")) ||
	    !htx_add_header(htx, ist("Transfer-Encoding"), ist("chunked")) ||
	    !htx_add_endof(htx, HTX_BLK_EOH))
		goto full;

	channel_add_input(chn, htx->data);
	return 1;
  full:
	htx_reset(htx);
	si_rx_room_blk(si);
	return 0;
}

/* The function returns 1 if the initialisation is complete, 0 if
 * an errors occurs and -1 if more data are required for initializing
 * the applet.
 */
static int promex_appctx_init(struct appctx *appctx, struct proxy *px, struct stream *strm)
{
	appctx->st0 = PROMEX_ST_INIT;
	return 1;
}

/* The main I/O handler for the promex applet. */
static void promex_appctx_handle_io(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);
	struct channel *req = si_oc(si);
	struct channel *res = si_ic(si);
	struct htx *req_htx, *res_htx;
	int ret;

	res_htx = htx_from_buf(&res->buf);
	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		goto out;

	/* Check if the input buffer is available. */
	if (!b_size(&res->buf)) {
		si_rx_room_blk(si);
		goto out;
	}

	switch (appctx->st0) {
		case PROMEX_ST_INIT:
			ret = promex_parse_uri(appctx, si);
			if (ret <= 0) {
				if (ret == -1)
					goto error;
				goto out;
			}
			appctx->st0 = PROMEX_ST_HEAD;
			appctx->st1 = PROMEX_DUMPER_INIT;
			/* fall through */

		case PROMEX_ST_HEAD:
			if (!promex_send_headers(appctx, si, res_htx))
				goto out;
			appctx->st0 = ((s->txn->meth == HTTP_METH_HEAD) ? PROMEX_ST_DONE : PROMEX_ST_DUMP);
			/* fall through */

		case PROMEX_ST_DUMP:
			ret = promex_dump_metrics(appctx, si, res_htx);
			if (ret <= 0) {
				if (ret == -1)
					goto error;
				goto out;
			}
			appctx->st0 = PROMEX_ST_DONE;
			/* fall through */

		case PROMEX_ST_DONE:
			/* Don't add TLR because mux-h1 will take care of it */
			res_htx->flags |= HTX_FL_EOI; /* no more data are expected. Only EOM remains to add now */
			if (!htx_add_endof(res_htx, HTX_BLK_EOM)) {
				si_rx_room_blk(si);
				goto out;
			}
			channel_add_input(res, 1);
			appctx->st0 = PROMEX_ST_END;
			/* fall through */

		case PROMEX_ST_END:
			if (!(res->flags & CF_SHUTR)) {
				res->flags |= CF_READ_NULL;
				si_shutr(si);
			}
	}

  out:
	htx_to_buf(res_htx, &res->buf);

	/* eat the whole request */
	if (co_data(req)) {
		req_htx = htx_from_buf(&req->buf);
		co_htx_skip(req, req_htx, co_data(req));
	}
	return;

  error:
	res->flags |= CF_READ_NULL;
	si_shutr(si);
	si_shutw(si);
}

struct applet promex_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<PROMEX>", /* used for logging */
	.init = promex_appctx_init,
	.fct = promex_appctx_handle_io,
};

static enum act_parse_ret service_parse_prometheus_exporter(const char **args, int *cur_arg, struct proxy *px,
							    struct act_rule *rule, char **err)
{
	/* Prometheus exporter service is only available on "http-request" rulesets */
	if (rule->from != ACT_F_HTTP_REQ) {
		memprintf(err, "Prometheus exporter service only available on 'http-request' rulesets");
		return ACT_RET_PRS_ERR;
	}

	/* Add applet pointer in the rule. */
	rule->applet = promex_applet;

	return ACT_RET_PRS_OK;
}
static void promex_register_build_options(void)
{
        char *ptr = NULL;

        memprintf(&ptr, "Built with the Prometheus exporter as a service");
        hap_register_build_opts(ptr, 1);
}


static struct action_kw_list service_actions = { ILH, {
	{ "prometheus-exporter", service_parse_prometheus_exporter },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, service_keywords_register, &service_actions);
INITCALL0(STG_REGISTER, promex_register_build_options);
