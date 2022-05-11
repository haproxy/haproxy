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
#include <haproxy/check.h>
#include <haproxy/conn_stream.h>
#include <haproxy/cs_utils.h>
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/stats.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>

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
	PROMEX_DUMPER_INIT = 0,   /* initialized */
	PROMEX_DUMPER_GLOBAL,     /* dump metrics of globals */
	PROMEX_DUMPER_FRONT,      /* dump metrics of frontend proxies */
	PROMEX_DUMPER_BACK,       /* dump metrics of backend proxies */
	PROMEX_DUMPER_LI,         /* dump metrics of listeners */
	PROMEX_DUMPER_SRV,        /* dump metrics of servers */
	PROMEX_DUMPER_STICKTABLE, /* dump metrics of stick tables */
	PROMEX_DUMPER_DONE,       /* finished */
};

/* Prometheus exporter flags (ctx->flags) */
#define PROMEX_FL_METRIC_HDR        0x00000001
#define PROMEX_FL_INFO_METRIC       0x00000002
#define PROMEX_FL_FRONT_METRIC      0x00000004
#define PROMEX_FL_BACK_METRIC       0x00000008
#define PROMEX_FL_SRV_METRIC        0x00000010
#define PROMEX_FL_LI_METRIC         0x00000020
#define PROMEX_FL_STICKTABLE_METRIC 0x00000040
#define PROMEX_FL_SCOPE_GLOBAL      0x00000080
#define PROMEX_FL_SCOPE_FRONT       0x00000100
#define PROMEX_FL_SCOPE_BACK        0x00000200
#define PROMEX_FL_SCOPE_SERVER      0x00000400
#define PROMEX_FL_SCOPE_LI          0x00000800
#define PROMEX_FL_SCOPE_STICKTABLE  0x00001000
#define PROMEX_FL_NO_MAINT_SRV      0x00002000

#define PROMEX_FL_SCOPE_ALL (PROMEX_FL_SCOPE_GLOBAL | PROMEX_FL_SCOPE_FRONT | \
			     PROMEX_FL_SCOPE_LI | PROMEX_FL_SCOPE_BACK | \
			     PROMEX_FL_SCOPE_SERVER | PROMEX_FL_SCOPE_STICKTABLE)

/* the context of the applet */
struct promex_ctx {
	struct proxy *px;          /* current proxy */
	struct stktable *st;       /* current table */
	struct listener *li;       /* current listener */
	struct server *sv;         /* current server */
	unsigned int flags;	   /* PROMEX_FL_* */
	unsigned field_num;        /* current field number (ST_F_* etc) */
	int obj_state;             /* current state among PROMEX_{FRONT|BACK|SRV|LI}_STATE_* */
};

/* Promtheus metric type (gauge or counter) */
enum promex_mt_type {
	PROMEX_MT_GAUGE   = 1,
	PROMEX_MT_COUNTER = 2,
};

/* The max length for metrics name. It is a hard limit but it should be
 * enough.
 */
#define PROMEX_MAX_NAME_LEN 128

/* The expected max length for a metric dump, including its header lines. It is
 * just a soft limit to avoid extra work. We don't try to dump a metric if less
 * than this size is available in the HTX.
 */
#define PROMEX_MAX_METRIC_LENGTH 512

/* The max number of labels per metric */
#define PROMEX_MAX_LABELS 8

/* Describe a prometheus metric */
struct promex_metric {
	const struct ist    n;      /* The metric name */
	enum promex_mt_type type;   /* The metric type (gauge or counter) */
	unsigned int        flags;  /* PROMEX_FL_* flags */
};

/* Describe a prometheus metric label. It is just a key/value pair */
struct promex_label {
	struct ist name;
	struct ist value;
};

/* Global metrics  */
const struct promex_metric promex_global_metrics[INF_TOTAL_FIELDS] = {
	//[INF_NAME]                           ignored
	//[INF_VERSION],                       ignored
	//[INF_RELEASE_DATE]                   ignored
	[INF_NBTHREAD]                       = { .n = IST("nbthread"),                      .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_NBPROC]                         = { .n = IST("nbproc"),                        .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_PROCESS_NUM]                    = { .n = IST("relative_process_id"),           .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[INF_PID]                            ignored
	//[INF_UPTIME]                         ignored
	[INF_UPTIME_SEC]                     = { .n = IST("uptime_seconds"),                .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_START_TIME_SEC]                 = { .n = IST("start_time_seconds"),            .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[INF_MEMMAX_MB]                      ignored
	[INF_MEMMAX_BYTES]                   = { .n = IST("max_memory_bytes"),              .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[INF_POOL_ALLOC_MB]                  ignored
	[INF_POOL_ALLOC_BYTES]               = { .n = IST("pool_allocated_bytes"),          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[INF_POOL_USED_MB]                   ignored
	[INF_POOL_USED_BYTES]                = { .n = IST("pool_used_bytes"),               .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_POOL_FAILED]                    = { .n = IST("pool_failures_total"),           .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_ULIMIT_N]                       = { .n = IST("max_fds"),                       .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_MAXSOCK]                        = { .n = IST("max_sockets"),                   .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_MAXCONN]                        = { .n = IST("max_connections"),               .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_HARD_MAXCONN]                   = { .n = IST("hard_max_connections"),          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_CURR_CONN]                      = { .n = IST("current_connections"),           .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_CUM_CONN]                       = { .n = IST("connections_total"),             .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_CUM_REQ]                        = { .n = IST("requests_total"),                .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_MAX_SSL_CONNS]                  = { .n = IST("max_ssl_connections"),           .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_CURR_SSL_CONNS]                 = { .n = IST("current_ssl_connections"),       .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_CUM_SSL_CONNS]                  = { .n = IST("ssl_connections_total"),         .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_MAXPIPES]                       = { .n = IST("max_pipes"),                     .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_PIPES_USED]                     = { .n = IST("pipes_used_total"),              .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_PIPES_FREE]                     = { .n = IST("pipes_free_total"),              .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_CONN_RATE]                      = { .n = IST("current_connection_rate"),       .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_CONN_RATE_LIMIT]                = { .n = IST("limit_connection_rate"),         .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_MAX_CONN_RATE]                  = { .n = IST("max_connection_rate"),           .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_SESS_RATE]                      = { .n = IST("current_session_rate"),          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_SESS_RATE_LIMIT]                = { .n = IST("limit_session_rate"),            .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_MAX_SESS_RATE]                  = { .n = IST("max_session_rate"),              .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_SSL_RATE]                       = { .n = IST("current_ssl_rate"),              .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_SSL_RATE_LIMIT]                 = { .n = IST("limit_ssl_rate"),                .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_MAX_SSL_RATE]                   = { .n = IST("max_ssl_rate"),                  .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_SSL_FRONTEND_KEY_RATE]          = { .n = IST("current_frontend_ssl_key_rate"), .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_SSL_FRONTEND_MAX_KEY_RATE]      = { .n = IST("max_frontend_ssl_key_rate"),     .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_SSL_FRONTEND_SESSION_REUSE_PCT] = { .n = IST("frontend_ssl_reuse"),            .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_SSL_BACKEND_KEY_RATE]           = { .n = IST("current_backend_ssl_key_rate"),  .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_SSL_BACKEND_MAX_KEY_RATE]       = { .n = IST("max_backend_ssl_key_rate"),      .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_SSL_CACHE_LOOKUPS]              = { .n = IST("ssl_cache_lookups_total"),       .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_SSL_CACHE_MISSES]               = { .n = IST("ssl_cache_misses_total"),        .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_COMPRESS_BPS_IN]                = { .n = IST("http_comp_bytes_in_total"),      .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_COMPRESS_BPS_OUT]               = { .n = IST("http_comp_bytes_out_total"),     .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_COMPRESS_BPS_RATE_LIM]          = { .n = IST("limit_http_comp"),               .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_ZLIB_MEM_USAGE]                 = { .n = IST("current_zlib_memory"),           .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_MAX_ZLIB_MEM_USAGE]             = { .n = IST("max_zlib_memory"),               .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_TASKS]                          = { .n = IST("current_tasks"),                 .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_RUN_QUEUE]                      = { .n = IST("current_run_queue"),             .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_IDLE_PCT]                       = { .n = IST("idle_time_percent"),             .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[INF_NODE]                           ignored
	//[INF_DESCRIPTION]                    ignored
	[INF_STOPPING]                       = { .n = IST("stopping"),                      .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_JOBS]                           = { .n = IST("jobs"),                          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_UNSTOPPABLE_JOBS]               = { .n = IST("unstoppable_jobs"),              .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_LISTENERS]                      = { .n = IST("listeners"),                     .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_ACTIVE_PEERS]                   = { .n = IST("active_peers"),                  .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_CONNECTED_PEERS]                = { .n = IST("connected_peers"),               .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_DROPPED_LOGS]                   = { .n = IST("dropped_logs_total"),            .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_BUSY_POLLING]                   = { .n = IST("busy_polling_enabled"),          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[INF_FAILED_RESOLUTIONS]             = { .n = IST("failed_resolutions"),            .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_TOTAL_BYTES_OUT]                = { .n = IST("bytes_out_total"),               .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_TOTAL_SPLICED_BYTES_OUT]        = { .n = IST("spliced_bytes_out_total"),       .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_BYTES_OUT_RATE]                 = { .n = IST("bytes_out_rate"),                .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[INF_DEBUG_COMMANDS_ISSUED]          ignored
	[INF_CUM_LOG_MSGS]                   = { .n = IST("recv_logs_total"),               .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[INF_BUILD_INFO]                     = { .n = IST("build_info"),                    .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
};

/* frontend/backend/server fields */
const struct promex_metric promex_st_metrics[ST_F_TOTAL_FIELDS] = {
	//[ST_F_PXNAME]               ignored
	//[ST_F_SVNAME]               ignored
	[ST_F_QCUR]                 = { .n = IST("current_queue"),                    .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_QMAX]                 = { .n = IST("max_queue"),                        .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_SCUR]                 = { .n = IST("current_sessions"),                 .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_SMAX]                 = { .n = IST("max_sessions"),                     .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_SLIM]                 = { .n = IST("limit_sessions"),                   .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_STOT]                 = { .n = IST("sessions_total"),                   .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_BIN]                  = { .n = IST("bytes_in_total"),                   .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_BOUT]                 = { .n = IST("bytes_out_total"),                  .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_DREQ]                 = { .n = IST("requests_denied_total"),            .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC                       ) },
	[ST_F_DRESP]                = { .n = IST("responses_denied_total"),           .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_EREQ]                 = { .n = IST("request_errors_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC                                               ) },
	[ST_F_ECON]                 = { .n = IST("connection_errors_total"),          .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_ERESP]                = { .n = IST("response_errors_total"),            .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_WRETR]                = { .n = IST("retry_warnings_total"),             .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_WREDIS]               = { .n = IST("redispatch_warnings_total"),        .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_STATUS]               = { .n = IST("status"),                           .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_WEIGHT]               = { .n = IST("weight"),                           .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_ACT]                  = { .n = IST("active_servers"),                   .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC                       ) },
	[ST_F_BCK]                  = { .n = IST("backup_servers"),                   .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC                       ) },
	[ST_F_CHKFAIL]              = { .n = IST("check_failures_total"),             .type = PROMEX_MT_COUNTER,  .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_CHKDOWN]              = { .n = IST("check_up_down_total"),              .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_LASTCHG]              = { .n = IST("check_last_change_seconds"),        .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_DOWNTIME]             = { .n = IST("downtime_seconds_total"),           .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_QLIMIT]               = { .n = IST("queue_limit"),                      .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	//[ST_F_PID]                  ignored
	//[ST_F_IID]                  ignored
	//[ST_F_SID]                  ignored
	[ST_F_THROTTLE]             = { .n = IST("current_throttle"),                 .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_LBTOT]                = { .n = IST("loadbalanced_total"),               .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	//[ST_F_TRACKED]              ignored
	//[ST_F_TYPE]                 ignored
	//[ST_F_RATE]                 ignored
	[ST_F_RATE_LIM]             = { .n = IST("limit_session_rate"),               .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC                                                                     ) },
	[ST_F_RATE_MAX]             = { .n = IST("max_session_rate"),                 .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_CHECK_STATUS]         = { .n = IST("check_status"),                     .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_CHECK_CODE]           = { .n = IST("check_code"),                       .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_CHECK_DURATION]       = { .n = IST("check_duration_seconds"),           .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_HRSP_1XX]             = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_HRSP_2XX]             = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_HRSP_3XX]             = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_HRSP_4XX]             = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_HRSP_5XX]             = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_HRSP_OTHER]           = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	//[ST_F_HANAFAIL]             ignored
	//[ST_F_REQ_RATE]             ignored
	[ST_F_REQ_RATE_MAX]         = { .n = IST("http_requests_rate_max"),           .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC                                                                     ) },
	[ST_F_REQ_TOT]              = { .n = IST("http_requests_total"),              .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_F_CLI_ABRT]             = { .n = IST("client_aborts_total"),              .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_SRV_ABRT]             = { .n = IST("server_aborts_total"),              .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_COMP_IN]              = { .n = IST("http_comp_bytes_in_total"),         .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_F_COMP_OUT]             = { .n = IST("http_comp_bytes_out_total"),        .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_F_COMP_BYP]             = { .n = IST("http_comp_bytes_bypassed_total"),   .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_F_COMP_RSP]             = { .n = IST("http_comp_responses_total"),        .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_F_LASTSESS]             = { .n = IST("last_session_seconds"),             .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	//[ST_F_LAST_CHK]             ignored
	//[ST_F_LAST_AGT]             ignored
	[ST_F_QTIME]                = { .n = IST("queue_time_average_seconds"),       .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_CTIME]                = { .n = IST("connect_time_average_seconds"),     .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_RTIME]                = { .n = IST("response_time_average_seconds"),    .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_TTIME]                = { .n = IST("total_time_average_seconds"),       .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	//[ST_F_AGENT_STATUS]         ignored
	//[ST_F_AGENT_CODE]           ignored
	//[ST_F_AGENT_DURATION]       ignored
	//[ST_F_CHECK_DESC]           ignored
	//[ST_F_AGENT_DESC]           ignored
	//[ST_F_CHECK_RISE]           ignored
	//[ST_F_CHECK_FALL]           ignored
	//[ST_F_CHECK_HEALTH]         ignored
	//[ST_F_AGENT_RISE]           ignored
	//[ST_F_AGENT_FALL]           ignored
	//[ST_F_AGENT_HEALTH]         ignored
	//[ST_F_ADDR]                 ignored
	//[ST_F_COOKIE]               ignored
	//[ST_F_MODE]                 ignored
	//[ST_F_ALGO]                 ignored
	//[ST_F_CONN_RATE]            ignored
	[ST_F_CONN_RATE_MAX]        = { .n = IST("connections_rate_max"),             .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC                                                                     ) },
	[ST_F_CONN_TOT]             = { .n = IST("connections_total"),                .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC                                                                     ) },
	[ST_F_INTERCEPTED]          = { .n = IST("intercepted_requests_total"),       .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC                                                                     ) },
	[ST_F_DCON]                 = { .n = IST("denied_connections_total"),         .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC                                               ) },
	[ST_F_DSES]                 = { .n = IST("denied_sessions_total"),            .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC                                               ) },
	[ST_F_WREW]                 = { .n = IST("failed_header_rewriting_total"),    .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_CONNECT]              = { .n = IST("connection_attempts_total"),        .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_REUSE]                = { .n = IST("connection_reuses_total"),          .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_CACHE_LOOKUPS]        = { .n = IST("http_cache_lookups_total"),         .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_F_CACHE_HITS]           = { .n = IST("http_cache_hits_total"),            .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_F_SRV_ICUR]             = { .n = IST("idle_connections_current"),         .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_SRV_ILIM]             = { .n = IST("idle_connections_limit"),           .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_QT_MAX]               = { .n = IST("max_queue_time_seconds"),           .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_CT_MAX]               = { .n = IST("max_connect_time_seconds"),         .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_RT_MAX]               = { .n = IST("max_response_time_seconds"),        .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_TT_MAX]               = { .n = IST("max_total_time_seconds"),           .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_EINT]                 = { .n = IST("internal_errors_total"),            .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_IDLE_CONN_CUR]        = { .n = IST("unsafe_idle_connections_current"),  .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_SAFE_CONN_CUR]        = { .n = IST("safe_idle_connections_current"),    .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_USED_CONN_CUR]        = { .n = IST("used_connections_current"),         .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_NEED_CONN_EST]        = { .n = IST("need_connections_current"),         .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_F_UWEIGHT]              = { .n = IST("uweight"),                          .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_F_AGG_SRV_CHECK_STATUS] = { .n = IST("agg_server_check_status"),	      .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC                       ) },
};

/* Description of overridden stats fields */
const struct ist promex_st_metric_desc[ST_F_TOTAL_FIELDS] = {
	[ST_F_STATUS]         = IST("Current status of the service, per state label value."),
	[ST_F_CHECK_STATUS]   = IST("Status of last health check, per state label value."),
	[ST_F_CHECK_CODE]     = IST("layer5-7 code, if available of the last health check."),
	[ST_F_CHECK_DURATION] = IST("Total duration of the latest server health check, in seconds."),
	[ST_F_QTIME]          = IST("Avg. queue time for last 1024 successful connections."),
	[ST_F_CTIME]          = IST("Avg. connect time for last 1024 successful connections."),
	[ST_F_RTIME]          = IST("Avg. response time for last 1024 successful connections."),
	[ST_F_TTIME]          = IST("Avg. total time for last 1024 successful connections."),
	[ST_F_QT_MAX]         = IST("Maximum observed time spent in the queue"),
	[ST_F_CT_MAX]         = IST("Maximum observed time spent waiting for a connection to complete"),
	[ST_F_RT_MAX]         = IST("Maximum observed time spent waiting for a server response"),
	[ST_F_TT_MAX]         = IST("Maximum observed total request+response time (request+queue+connect+response+processing)"),
};

/* stick table base fields */
enum sticktable_field {
	STICKTABLE_SIZE = 0,
	STICKTABLE_USED,
	/* must always be the last one */
	STICKTABLE_TOTAL_FIELDS
};

const struct promex_metric promex_sticktable_metrics[STICKTABLE_TOTAL_FIELDS] = {
	[STICKTABLE_SIZE] = { .n = IST("size"), .type = PROMEX_MT_GAUGE, .flags = PROMEX_FL_STICKTABLE_METRIC },
	[STICKTABLE_USED] = { .n = IST("used"), .type = PROMEX_MT_GAUGE, .flags = PROMEX_FL_STICKTABLE_METRIC },
};

/* stick table base description */
const struct ist promex_sticktable_metric_desc[STICKTABLE_TOTAL_FIELDS] = {
	[STICKTABLE_SIZE] = IST("Stick table size."),
	[STICKTABLE_USED] = IST("Number of entries used in this stick table."),
};

/* Specific labels for all ST_F_HRSP_* fields */
const struct ist promex_hrsp_code[1 + ST_F_HRSP_OTHER - ST_F_HRSP_1XX] = {
	[ST_F_HRSP_1XX - ST_F_HRSP_1XX]   = IST("1xx"),
	[ST_F_HRSP_2XX - ST_F_HRSP_1XX]   = IST("2xx"),
	[ST_F_HRSP_3XX - ST_F_HRSP_1XX]   = IST("3xx"),
	[ST_F_HRSP_4XX - ST_F_HRSP_1XX]   = IST("4xx"),
	[ST_F_HRSP_5XX - ST_F_HRSP_1XX]   = IST("5xx"),
	[ST_F_HRSP_OTHER - ST_F_HRSP_1XX] = IST("other"),
};

enum promex_front_state {
	PROMEX_FRONT_STATE_DOWN = 0,
	PROMEX_FRONT_STATE_UP,

	PROMEX_FRONT_STATE_COUNT /* must be last */
};

const struct ist promex_front_st[PROMEX_FRONT_STATE_COUNT] = {
	[PROMEX_FRONT_STATE_DOWN] = IST("DOWN"),
	[PROMEX_FRONT_STATE_UP]   = IST("UP"),
};

enum promex_back_state {
	PROMEX_BACK_STATE_DOWN = 0,
	PROMEX_BACK_STATE_UP,

	PROMEX_BACK_STATE_COUNT /* must be last */
};

const struct ist promex_back_st[PROMEX_BACK_STATE_COUNT] = {
	[PROMEX_BACK_STATE_DOWN] = IST("DOWN"),
	[PROMEX_BACK_STATE_UP]   = IST("UP"),
};

enum promex_srv_state {
	PROMEX_SRV_STATE_DOWN = 0,
	PROMEX_SRV_STATE_UP,
	PROMEX_SRV_STATE_MAINT,
	PROMEX_SRV_STATE_DRAIN,
	PROMEX_SRV_STATE_NOLB,

	PROMEX_SRV_STATE_COUNT /* must be last */
};

const struct ist promex_srv_st[PROMEX_SRV_STATE_COUNT] = {
	[PROMEX_SRV_STATE_DOWN]  = IST("DOWN"),
	[PROMEX_SRV_STATE_UP]    = IST("UP"),
	[PROMEX_SRV_STATE_MAINT] = IST("MAINT"),
	[PROMEX_SRV_STATE_DRAIN] = IST("DRAIN"),
	[PROMEX_SRV_STATE_NOLB]  = IST("NOLB"),
};

/* Return the server status. */
enum promex_srv_state promex_srv_status(struct server *sv)
{
	int state = PROMEX_SRV_STATE_DOWN;

	if (sv->cur_state == SRV_ST_RUNNING || sv->cur_state == SRV_ST_STARTING) {
		state = PROMEX_SRV_STATE_UP;
		if (sv->cur_admin & SRV_ADMF_DRAIN)
			state = PROMEX_SRV_STATE_DRAIN;
	}
	else if (sv->cur_state == SRV_ST_STOPPING)
		state = PROMEX_SRV_STATE_NOLB;

	if (sv->cur_admin & SRV_ADMF_MAINT)
		state = PROMEX_SRV_STATE_MAINT;

	return state;
}

/* Convert a field to its string representation and write it in <out>, followed
 * by a newline, if there is enough space. non-numeric value are converted in
 * "NaN" because Prometheus only support numerical values (but it is unexepceted
 * to process this kind of value). It returns 1 on success. Otherwise, it
 * returns 0. The buffer's length must not exceed <max> value.
 */
static int promex_metric_to_str(struct buffer *out, struct field *f, size_t max)
{
	int ret = 0;

	switch (field_format(f, 0)) {
		case FF_EMPTY: ret = chunk_strcat(out,  "NaN\n"); break;
		case FF_S32:   ret = chunk_appendf(out, "%d\n", f->u.s32); break;
		case FF_U32:   ret = chunk_appendf(out, "%u\n", f->u.u32); break;
		case FF_S64:   ret = chunk_appendf(out, "%lld\n", (long long)f->u.s64); break;
		case FF_U64:   ret = chunk_appendf(out, "%llu\n", (unsigned long long)f->u.u64); break;
		case FF_FLT:   ret = chunk_appendf(out, "%f\n", f->u.flt); break;
		case FF_STR:   ret = chunk_strcat(out,  "NaN\n"); break;
		default:       ret = chunk_strcat(out,  "NaN\n"); break;
	}
	if (!ret || out->data > max)
		return 0;
	return 1;
}

/* Dump the header lines for <metric>. It is its #HELP and #TYPE strings. It
 * returns 1 on success. Otherwise, if <out> length exceeds <max>, it returns 0.
 */
static int promex_dump_metric_header(struct appctx *appctx, struct htx *htx,
				     const struct promex_metric *metric, const struct ist name,
				     struct ist *out, size_t max)
{
	struct promex_ctx *ctx = appctx->svcctx;
	struct ist type;
	struct ist desc;

	switch (metric->type) {
		case PROMEX_MT_COUNTER:
			type = ist("counter");
			break;
		default:
			type = ist("gauge");
	}

	if (istcat(out, ist("# HELP "), max) == -1 ||
	    istcat(out, name, max) == -1 ||
	    istcat(out, ist(" "), max) == -1)
		goto full;

	if (metric->flags & PROMEX_FL_INFO_METRIC)
		desc = ist(info_fields[ctx->field_num].desc);
	else if (metric->flags & PROMEX_FL_STICKTABLE_METRIC)
		desc = promex_sticktable_metric_desc[ctx->field_num];
	else if (!isttest(promex_st_metric_desc[ctx->field_num]))
		desc = ist(stat_fields[ctx->field_num].desc);
	else
		desc = promex_st_metric_desc[ctx->field_num];

	if (istcat(out, desc, max) == -1 ||
	    istcat(out, ist("\n# TYPE "), max) == -1 ||
	    istcat(out, name, max) == -1 ||
	    istcat(out, ist(" "), max) == -1 ||
	    istcat(out, type, max) == -1 ||
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
static int promex_dump_metric(struct appctx *appctx, struct htx *htx, struct ist prefix,
			      const  struct promex_metric *metric, struct field *val,
			      struct promex_label *labels, struct ist *out, size_t max)
{
	struct ist name = { .ptr = (char[PROMEX_MAX_NAME_LEN]){ 0 }, .len = 0 };
	struct promex_ctx *ctx = appctx->svcctx;
	size_t len = out->len;

	if (out->len + PROMEX_MAX_METRIC_LENGTH > max)
		return 0;

	/* Fill the metric name */
	istcat(&name, prefix, PROMEX_MAX_NAME_LEN);
	istcat(&name, metric->n, PROMEX_MAX_NAME_LEN);


	if ((ctx->flags & PROMEX_FL_METRIC_HDR) &&
	    !promex_dump_metric_header(appctx, htx, metric, name, out, max))
		goto full;

	if (istcat(out, name, max) == -1)
		goto full;

	if (isttest(labels[0].name)) {
		int i;

		if (istcat(out, ist("{"), max) == -1)
			goto full;

		for (i = 0; isttest(labels[i].name); i++) {
			if (!isttest(labels[i].value))
				continue;

			if ((i && istcat(out, ist(","), max) == -1) ||
			    istcat(out, labels[i].name, max) == -1 ||
			    istcat(out, ist("=\""), max) == -1 ||
			    istcat(out, labels[i].value, max) == -1 ||
			    istcat(out, ist("\""), max) == -1)
				goto full;
		}

		if (istcat(out, ist("}"), max) == -1)
			goto full;

	}

	if (istcat(out, ist(" "), max) == -1)
		goto full;

	trash.data = out->len;
	if (!promex_metric_to_str(&trash, val, max))
		goto full;
	out->len = trash.data;

	ctx->flags &= ~PROMEX_FL_METRIC_HDR;
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
	struct promex_ctx *ctx = appctx->svcctx;
	struct field val;
	struct channel *chn = cs_ic(appctx_cs(appctx));
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	int ret = 1;

	if (!stats_fill_info(info, INF_TOTAL_FIELDS, 0))
		return -1;

	for (; ctx->field_num < INF_TOTAL_FIELDS; ctx->field_num++) {
		struct promex_label labels[PROMEX_MAX_LABELS-1] = {};

		if (!(promex_global_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		switch (ctx->field_num) {
			case INF_BUILD_INFO:
				labels[0].name  = ist("version");
				labels[0].value = ist(HAPROXY_VERSION);
				val = mkf_u32(FN_GAUGE, 1);
				break;

			default:
				val = info[ctx->field_num];
		}

		if (!promex_dump_metric(appctx, htx, prefix, &promex_global_metrics[ctx->field_num],
					&val, labels, &out, max))
			goto full;

		ctx->flags |= PROMEX_FL_METRIC_HDR;
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
	struct promex_ctx *ctx = appctx->svcctx;
	struct proxy *px;
	struct field val;
	struct channel *chn = cs_ic(appctx_cs(appctx));
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	struct field *stats = stat_l[STATS_DOMAIN_PROXY];
	int ret = 1;
	enum promex_front_state state;

	for (;ctx->field_num < ST_F_TOTAL_FIELDS; ctx->field_num++) {
		if (!(promex_st_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		while (ctx->px) {
			struct promex_label labels[PROMEX_MAX_LABELS-1] = {};

			px = ctx->px;

			labels[0].name  = ist("proxy");
			labels[0].value = ist2(px->id, strlen(px->id));

			/* skip the disabled proxies, global frontend and non-networked ones */
			if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_FE))
				goto next_px;

			if (!stats_fill_fe_stats(px, stats, ST_F_TOTAL_FIELDS, &(ctx->field_num)))
				return -1;

			switch (ctx->field_num) {
				case ST_F_STATUS:
					state = !(px->flags & PR_FL_STOPPED);
					for (; ctx->obj_state < PROMEX_FRONT_STATE_COUNT; ctx->obj_state++) {
						labels[1].name = ist("state");
						labels[1].value = promex_front_st[ctx->obj_state];
						val = mkf_u32(FO_STATUS, state == ctx->obj_state);
						if (!promex_dump_metric(appctx, htx, prefix, &promex_st_metrics[ctx->field_num],
									&val, labels, &out, max))
							goto full;
					}
					ctx->obj_state = 0;
					goto next_px;
				case ST_F_REQ_RATE_MAX:
				case ST_F_REQ_TOT:
				case ST_F_INTERCEPTED:
				case ST_F_CACHE_LOOKUPS:
				case ST_F_CACHE_HITS:
				case ST_F_COMP_IN:
				case ST_F_COMP_OUT:
				case ST_F_COMP_BYP:
				case ST_F_COMP_RSP:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					val = stats[ctx->field_num];
					break;
				case ST_F_HRSP_1XX:
				case ST_F_HRSP_2XX:
				case ST_F_HRSP_3XX:
				case ST_F_HRSP_4XX:
				case ST_F_HRSP_5XX:
				case ST_F_HRSP_OTHER:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					if (ctx->field_num != ST_F_HRSP_1XX)
						ctx->flags &= ~PROMEX_FL_METRIC_HDR;
					labels[1].name = ist("code");
					labels[1].value = promex_hrsp_code[ctx->field_num - ST_F_HRSP_1XX];
					val = stats[ctx->field_num];
					break;

				default:
					val = stats[ctx->field_num];
			}

			if (!promex_dump_metric(appctx, htx, prefix, &promex_st_metrics[ctx->field_num],
						&val, labels, &out, max))
				goto full;
		  next_px:
			ctx->px = px->next;
		}
		ctx->flags |= PROMEX_FL_METRIC_HDR;
		ctx->px = proxies_list;
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

/* Dump listener metrics (prefixed by "haproxy_listen_"). It returns 1 on
 * success, 0 if <htx> is full and -1 in case of any error. */
static int promex_dump_listener_metrics(struct appctx *appctx, struct htx *htx)
{
	static struct ist prefix = IST("haproxy_listener_");
	struct promex_ctx *ctx = appctx->svcctx;
	struct proxy *px;
	struct field val;
	struct channel *chn = cs_ic(appctx_cs(appctx));
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	struct field *stats = stat_l[STATS_DOMAIN_PROXY];
	struct listener *li;
	int ret = 1;
	enum li_status status;

	for (;ctx->field_num < ST_F_TOTAL_FIELDS; ctx->field_num++) {
		if (!(promex_st_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		while (ctx->px) {
			struct promex_label labels[PROMEX_MAX_LABELS-1] = {};

			px = ctx->px;

			labels[0].name  = ist("proxy");
			labels[0].value = ist2(px->id, strlen(px->id));

			/* skip the disabled proxies, global frontend and non-networked ones */
			if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_FE))
				goto next_px;

			li = ctx->li;
			list_for_each_entry_from(li, &px->conf.listeners, by_fe) {

				if (!li->counters)
					continue;

				labels[1].name  = ist("listener");
				labels[1].value = ist2(li->name, strlen(li->name));

				if (!stats_fill_li_stats(px, li, 0, stats,
							 ST_F_TOTAL_FIELDS, &(ctx->field_num)))
					return -1;

				switch (ctx->field_num) {
					case ST_F_STATUS:
						status = get_li_status(li);
						for (; ctx->obj_state < LI_STATE_COUNT; ctx->obj_state++) {
							val = mkf_u32(FO_STATUS, status == ctx->obj_state);
							labels[2].name = ist("state");
							labels[2].value = ist(li_status_st[ctx->obj_state]);
							if (!promex_dump_metric(appctx, htx, prefix, &promex_st_metrics[ctx->field_num],
										&val, labels, &out, max))
								goto full;
						}
						ctx->obj_state = 0;
						continue;
					default:
						val = stats[ctx->field_num];
				}

				if (!promex_dump_metric(appctx, htx, prefix,
							&promex_st_metrics[ctx->field_num],
							&val, labels, &out, max))
					goto full;
			}

		  next_px:
			px = px->next;
			ctx->px = px;
			ctx->li = (px ? LIST_NEXT(&px->conf.listeners, struct listener *, by_fe) : NULL);
		}
		ctx->flags |= PROMEX_FL_METRIC_HDR;
		ctx->px = proxies_list;
		ctx->li =  LIST_NEXT(&proxies_list->conf.listeners, struct listener *, by_fe);
	}

  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}
	return ret;
  full:
	ctx->li = li;
	ret = 0;
	goto end;
}

/* Dump backends metrics (prefixed by "haproxy_backend_"). It returns 1 on success,
 * 0 if <htx> is full and -1 in case of any error. */
static int promex_dump_back_metrics(struct appctx *appctx, struct htx *htx)
{
	static struct ist prefix = IST("haproxy_backend_");
	struct promex_ctx *ctx = appctx->svcctx;
	struct proxy *px;
	struct server *sv;
	struct field val;
	struct channel *chn = cs_ic(appctx_cs(appctx));
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	struct field *stats = stat_l[STATS_DOMAIN_PROXY];
	int ret = 1;
	double secs;
	enum promex_back_state bkd_state;
	enum promex_srv_state srv_state;

	for (;ctx->field_num < ST_F_TOTAL_FIELDS; ctx->field_num++) {
		if (!(promex_st_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		while (ctx->px) {
			struct promex_label labels[PROMEX_MAX_LABELS-1] = {};
			unsigned int srv_state_count[PROMEX_SRV_STATE_COUNT] = { 0 };

			px = ctx->px;

			labels[0].name  = ist("proxy");
			labels[0].value = ist2(px->id, strlen(px->id));

			/* skip the disabled proxies, global frontend and non-networked ones */
			if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_BE))
				goto next_px;

			if (!stats_fill_be_stats(px, 0, stats, ST_F_TOTAL_FIELDS, &(ctx->field_num)))
				return -1;

			switch (ctx->field_num) {
				case ST_F_AGG_SRV_CHECK_STATUS:
					if (!px->srv)
						goto next_px;
					sv = px->srv;
					while (sv) {
						srv_state = promex_srv_status(sv);
						srv_state_count[srv_state] += 1;
						sv = sv->next;
					}
					for (; ctx->obj_state < PROMEX_SRV_STATE_COUNT; ctx->obj_state++) {
						val = mkf_u32(FN_GAUGE, srv_state_count[ctx->obj_state]);
						labels[1].name = ist("state");
						labels[1].value = promex_srv_st[ctx->obj_state];
						if (!promex_dump_metric(appctx, htx, prefix, &promex_st_metrics[ctx->field_num],
									&val, labels, &out, max))
							goto full;
					}
					ctx->obj_state = 0;
					goto next_px;
				case ST_F_STATUS:
					bkd_state = ((px->lbprm.tot_weight > 0 || !px->srv) ? 1 : 0);
					for (; ctx->obj_state < PROMEX_BACK_STATE_COUNT; ctx->obj_state++) {
						labels[1].name = ist("state");
						labels[1].value = promex_back_st[ctx->obj_state];
						val = mkf_u32(FO_STATUS, bkd_state == ctx->obj_state);
						if (!promex_dump_metric(appctx, htx, prefix, &promex_st_metrics[ctx->field_num],
									&val, labels, &out, max))
							goto full;
					}
					ctx->obj_state = 0;
					goto next_px;
				case ST_F_QTIME:
					secs = (double)swrate_avg(px->be_counters.q_time, TIME_STATS_SAMPLES) / 1000.0;
					val = mkf_flt(FN_AVG, secs);
					break;
				case ST_F_CTIME:
					secs = (double)swrate_avg(px->be_counters.c_time, TIME_STATS_SAMPLES) / 1000.0;
					val = mkf_flt(FN_AVG, secs);
					break;
				case ST_F_RTIME:
					secs = (double)swrate_avg(px->be_counters.d_time, TIME_STATS_SAMPLES) / 1000.0;
					val = mkf_flt(FN_AVG, secs);
					break;
				case ST_F_TTIME:
					secs = (double)swrate_avg(px->be_counters.t_time, TIME_STATS_SAMPLES) / 1000.0;
					val = mkf_flt(FN_AVG, secs);
					break;
				case ST_F_QT_MAX:
					secs = (double)px->be_counters.qtime_max / 1000.0;
					val = mkf_flt(FN_MAX, secs);
					break;
				case ST_F_CT_MAX:
					secs = (double)px->be_counters.ctime_max / 1000.0;
					val = mkf_flt(FN_MAX, secs);
					break;
				case ST_F_RT_MAX:
					secs = (double)px->be_counters.dtime_max / 1000.0;
					val = mkf_flt(FN_MAX, secs);
					break;
				case ST_F_TT_MAX:
					secs = (double)px->be_counters.ttime_max / 1000.0;
					val = mkf_flt(FN_MAX, secs);
					break;
				case ST_F_REQ_TOT:
				case ST_F_CACHE_LOOKUPS:
				case ST_F_CACHE_HITS:
				case ST_F_COMP_IN:
				case ST_F_COMP_OUT:
				case ST_F_COMP_BYP:
				case ST_F_COMP_RSP:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					val = stats[ctx->field_num];
					break;
				case ST_F_HRSP_1XX:
				case ST_F_HRSP_2XX:
				case ST_F_HRSP_3XX:
				case ST_F_HRSP_4XX:
				case ST_F_HRSP_5XX:
				case ST_F_HRSP_OTHER:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					if (ctx->field_num != ST_F_HRSP_1XX)
						ctx->flags &= ~PROMEX_FL_METRIC_HDR;
					labels[1].name = ist("code");
					labels[1].value = promex_hrsp_code[ctx->field_num - ST_F_HRSP_1XX];
					val = stats[ctx->field_num];
					break;

				default:
					val = stats[ctx->field_num];
			}

			if (!promex_dump_metric(appctx, htx, prefix, &promex_st_metrics[ctx->field_num],
						&val, labels, &out, max))
				goto full;
		  next_px:
			ctx->px = px->next;
		}
		ctx->flags |= PROMEX_FL_METRIC_HDR;
		ctx->px = proxies_list;
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
	struct promex_ctx *ctx = appctx->svcctx;
	struct proxy *px;
	struct server *sv;
	struct field val;
	struct channel *chn = cs_ic(appctx_cs(appctx));
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	struct field *stats = stat_l[STATS_DOMAIN_PROXY];
	int ret = 1;
	double secs;
	enum promex_srv_state state;
	const char *check_state;

	for (;ctx->field_num < ST_F_TOTAL_FIELDS; ctx->field_num++) {
		if (!(promex_st_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		while (ctx->px) {
			struct promex_label labels[PROMEX_MAX_LABELS-1] = {};

			px = ctx->px;

			labels[0].name  = ist("proxy");
			labels[0].value = ist2(px->id, strlen(px->id));

			/* skip the disabled proxies, global frontend and non-networked ones */
			if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_BE))
				goto next_px;

			while (ctx->sv) {
				sv = ctx->sv;

				labels[1].name  = ist("server");
				labels[1].value = ist2(sv->id, strlen(sv->id));

				if (!stats_fill_sv_stats(px, sv, 0, stats, ST_F_TOTAL_FIELDS, &(ctx->field_num)))
					return -1;

				if ((ctx->flags & PROMEX_FL_NO_MAINT_SRV) && (sv->cur_admin & SRV_ADMF_MAINT))
					goto next_sv;

				switch (ctx->field_num) {
					case ST_F_STATUS:
						state = promex_srv_status(sv);
						for (; ctx->obj_state < PROMEX_SRV_STATE_COUNT; ctx->obj_state++) {
							val = mkf_u32(FO_STATUS, state == ctx->obj_state);
							labels[2].name = ist("state");
							labels[2].value = promex_srv_st[ctx->obj_state];
							if (!promex_dump_metric(appctx, htx, prefix, &promex_st_metrics[ctx->field_num],
										&val, labels, &out, max))
								goto full;
						}
						ctx->obj_state = 0;
						goto next_sv;
					case ST_F_QTIME:
						secs = (double)swrate_avg(sv->counters.q_time, TIME_STATS_SAMPLES) / 1000.0;
						val = mkf_flt(FN_AVG, secs);
						break;
					case ST_F_CTIME:
						secs = (double)swrate_avg(sv->counters.c_time, TIME_STATS_SAMPLES) / 1000.0;
						val = mkf_flt(FN_AVG, secs);
						break;
					case ST_F_RTIME:
						secs = (double)swrate_avg(sv->counters.d_time, TIME_STATS_SAMPLES) / 1000.0;
						val = mkf_flt(FN_AVG, secs);
						break;
					case ST_F_TTIME:
						secs = (double)swrate_avg(sv->counters.t_time, TIME_STATS_SAMPLES) / 1000.0;
						val = mkf_flt(FN_AVG, secs);
						break;
					case ST_F_QT_MAX:
						secs = (double)sv->counters.qtime_max / 1000.0;
						val = mkf_flt(FN_MAX, secs);
						break;
					case ST_F_CT_MAX:
						secs = (double)sv->counters.ctime_max / 1000.0;
						val = mkf_flt(FN_MAX, secs);
						break;
					case ST_F_RT_MAX:
						secs = (double)sv->counters.dtime_max / 1000.0;
						val = mkf_flt(FN_MAX, secs);
						break;
					case ST_F_TT_MAX:
						secs = (double)sv->counters.ttime_max / 1000.0;
						val = mkf_flt(FN_MAX, secs);
						break;
					case ST_F_CHECK_STATUS:
						if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) != CHK_ST_ENABLED)
							goto next_sv;

						for (; ctx->obj_state < HCHK_STATUS_SIZE; ctx->obj_state++) {
							if (get_check_status_result(ctx->obj_state) < CHK_RES_FAILED)
								continue;
							val = mkf_u32(FO_STATUS, sv->check.status == ctx->obj_state);
							check_state = get_check_status_info(ctx->obj_state);
							labels[2].name = ist("state");
							labels[2].value = ist(check_state);
							if (!promex_dump_metric(appctx, htx, prefix, &promex_st_metrics[ctx->field_num],
										&val, labels, &out, max))
								goto full;
						}
						ctx->obj_state = 0;
						goto next_sv;
					case ST_F_CHECK_CODE:
						if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) != CHK_ST_ENABLED)
							goto next_sv;
						val = mkf_u32(FN_OUTPUT, (sv->check.status < HCHK_STATUS_L57DATA) ? 0 : sv->check.code);
						break;
					case ST_F_CHECK_DURATION:
						if (sv->check.status < HCHK_STATUS_CHECKED)
						    goto next_sv;
						secs = (double)sv->check.duration / 1000.0;
						val = mkf_flt(FN_DURATION, secs);
						break;
					case ST_F_REQ_TOT:
						if (px->mode != PR_MODE_HTTP)
							goto next_px;
						val = stats[ctx->field_num];
						break;
					case ST_F_HRSP_1XX:
					case ST_F_HRSP_2XX:
					case ST_F_HRSP_3XX:
					case ST_F_HRSP_4XX:
					case ST_F_HRSP_5XX:
					case ST_F_HRSP_OTHER:
						if (px->mode != PR_MODE_HTTP)
							goto next_px;
						if (ctx->field_num != ST_F_HRSP_1XX)
							ctx->flags &= ~PROMEX_FL_METRIC_HDR;
						labels[2].name = ist("code");
						labels[2].value = promex_hrsp_code[ctx->field_num - ST_F_HRSP_1XX];
						val = stats[ctx->field_num];
						break;

					default:
						val = stats[ctx->field_num];
				}

				if (!promex_dump_metric(appctx, htx, prefix, &promex_st_metrics[ctx->field_num],
							&val, labels, &out, max))
					goto full;
			  next_sv:
				ctx->sv = sv->next;
			}

		  next_px:
			ctx->px = px->next;
			ctx->sv = (ctx->px ? ctx->px->srv : NULL);
		}
		ctx->flags |= PROMEX_FL_METRIC_HDR;
		ctx->px = proxies_list;
		ctx->sv = (ctx->px ? ctx->px->srv : NULL);
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

/* Dump stick table metrics (prefixed by "haproxy_sticktable_"). It returns 1 on success,
 * 0 if <htx> is full and -1 in case of any error. */
static int promex_dump_sticktable_metrics(struct appctx *appctx, struct htx *htx)
{
	static struct ist prefix = IST("haproxy_sticktable_");
	struct promex_ctx *ctx = appctx->svcctx;
	struct field val;
	struct channel *chn = cs_ic(appctx_cs(appctx));
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	int ret = 1;
	struct stktable *t;

	for (; ctx->field_num < STICKTABLE_TOTAL_FIELDS; ctx->field_num++) {
		if (!(promex_sticktable_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		while (ctx->st) {
			struct promex_label labels[PROMEX_MAX_LABELS - 1] = {};

			t = ctx->st;
			if (!t->size)
				goto next_px;

			labels[0].name  = ist("name");
			labels[0].value = ist2(t->id, strlen(t->id));
			labels[1].name  = ist("type");
			labels[1].value = ist2(stktable_types[t->type].kw, strlen(stktable_types[t->type].kw));
			switch (ctx->field_num) {
				case STICKTABLE_SIZE:
					val = mkf_u32(FN_GAUGE, t->size);
					break;
				case STICKTABLE_USED:
					val = mkf_u32(FN_GAUGE, t->current);
					break;
				default:
					goto next_px;
			}

			if (!promex_dump_metric(appctx, htx, prefix,
						&promex_sticktable_metrics[ctx->field_num],
						&val, labels, &out, max))
				goto full;

		  next_px:
			ctx->st = t->next;
		}
		ctx->flags |= PROMEX_FL_METRIC_HDR;
		ctx->st = stktables_list;
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
 * Uses <appctx.ctx.stats.px> as a pointer to the current proxy and <sv>/<li>
 * as pointers to the current server/listener respectively.
 */
static int promex_dump_metrics(struct appctx *appctx, struct conn_stream *cs, struct htx *htx)
{
	struct promex_ctx *ctx = appctx->svcctx;
	int ret;

	switch (appctx->st1) {
		case PROMEX_DUMPER_INIT:
			ctx->px = NULL;
			ctx->st = NULL;
			ctx->li = NULL;
			ctx->sv = NULL;
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_INFO_METRIC);
			ctx->obj_state = 0;
			ctx->field_num = INF_NAME;
			appctx->st1 = PROMEX_DUMPER_GLOBAL;
			/* fall through */

		case PROMEX_DUMPER_GLOBAL:
			if (ctx->flags & PROMEX_FL_SCOPE_GLOBAL) {
				ret = promex_dump_global_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->px = proxies_list;
			ctx->st = NULL;
			ctx->li = NULL;
			ctx->sv = NULL;
			ctx->flags &= ~PROMEX_FL_INFO_METRIC;
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_FRONT_METRIC);
			ctx->obj_state = 0;
			ctx->field_num = ST_F_PXNAME;
			appctx->st1 = PROMEX_DUMPER_FRONT;
			/* fall through */

		case PROMEX_DUMPER_FRONT:
			if (ctx->flags & PROMEX_FL_SCOPE_FRONT) {
				ret = promex_dump_front_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->px = proxies_list;
			ctx->st = NULL;
			ctx->li = LIST_NEXT(&proxies_list->conf.listeners, struct listener *, by_fe);
			ctx->sv = NULL;
			ctx->flags &= ~PROMEX_FL_FRONT_METRIC;
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_LI_METRIC);
			ctx->obj_state = 0;
			ctx->field_num = ST_F_PXNAME;
			appctx->st1 = PROMEX_DUMPER_LI;
			/* fall through */

		case PROMEX_DUMPER_LI:
			if (ctx->flags & PROMEX_FL_SCOPE_LI) {
				ret = promex_dump_listener_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->px = proxies_list;
			ctx->st = NULL;
			ctx->li = NULL;
			ctx->sv = NULL;
			ctx->flags &= ~PROMEX_FL_LI_METRIC;
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_BACK_METRIC);
			ctx->obj_state = 0;
			ctx->field_num = ST_F_PXNAME;
			appctx->st1 = PROMEX_DUMPER_BACK;
			/* fall through */

		case PROMEX_DUMPER_BACK:
			if (ctx->flags & PROMEX_FL_SCOPE_BACK) {
				ret = promex_dump_back_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->px = proxies_list;
			ctx->st = NULL;
			ctx->li = NULL;
			ctx->sv = ctx->px ? ctx->px->srv : NULL;
			ctx->flags &= ~PROMEX_FL_BACK_METRIC;
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_SRV_METRIC);
			ctx->obj_state = 0;
			ctx->field_num = ST_F_PXNAME;
			appctx->st1 = PROMEX_DUMPER_SRV;
			/* fall through */

		case PROMEX_DUMPER_SRV:
			if (ctx->flags & PROMEX_FL_SCOPE_SERVER) {
				ret = promex_dump_srv_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->px = NULL;
			ctx->st = stktables_list;
			ctx->li = NULL;
			ctx->sv = NULL;
			ctx->flags &= ~(PROMEX_FL_METRIC_HDR|PROMEX_FL_SRV_METRIC);
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_STICKTABLE_METRIC);
			ctx->field_num = STICKTABLE_SIZE;
			appctx->st1 = PROMEX_DUMPER_STICKTABLE;
			/* fall through */

		case PROMEX_DUMPER_STICKTABLE:
			if (ctx->flags & PROMEX_FL_SCOPE_STICKTABLE) {
				ret = promex_dump_sticktable_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->px = NULL;
			ctx->st = NULL;
			ctx->li = NULL;
			ctx->sv = NULL;
			ctx->flags &= ~(PROMEX_FL_METRIC_HDR|PROMEX_FL_STICKTABLE_METRIC);
			ctx->field_num = 0;
			appctx->st1 = PROMEX_DUMPER_DONE;
			/* fall through */

		case PROMEX_DUMPER_DONE:
		default:
			break;
	}

	return 1;

  full:
	cs_rx_room_blk(cs);
	return 0;
  error:
	/* unrecoverable error */
	ctx->px = NULL;
	ctx->st = NULL;
	ctx->li = NULL;
	ctx->sv = NULL;
	ctx->flags = 0;
	ctx->field_num = 0;
	appctx->st1 = PROMEX_DUMPER_DONE;
	return -1;
}

/* Parse the query string of request URI to filter the metrics. It returns 1 on
 * success and -1 on error. */
static int promex_parse_uri(struct appctx *appctx, struct conn_stream *cs)
{
	struct promex_ctx *ctx = appctx->svcctx;
	struct channel *req = cs_oc(cs);
	struct channel *res = cs_ic(cs);
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
				ctx->flags &= ~PROMEX_FL_SCOPE_ALL;
			else if (*value == '*')
				ctx->flags |= PROMEX_FL_SCOPE_ALL;
			else if (strcmp(value, "global") == 0)
				ctx->flags |= PROMEX_FL_SCOPE_GLOBAL;
			else if (strcmp(value, "server") == 0)
				ctx->flags |= PROMEX_FL_SCOPE_SERVER;
			else if (strcmp(value, "backend") == 0)
				ctx->flags |= PROMEX_FL_SCOPE_BACK;
			else if (strcmp(value, "frontend") == 0)
				ctx->flags |= PROMEX_FL_SCOPE_FRONT;
			else if (strcmp(value, "listener") == 0)
				ctx->flags |= PROMEX_FL_SCOPE_LI;
			else if (strcmp(value, "sticktable") == 0)
				ctx->flags |= PROMEX_FL_SCOPE_STICKTABLE;
			else
				goto error;
		}
		else if (strcmp(key, "no-maint") == 0)
			ctx->flags |= PROMEX_FL_NO_MAINT_SRV;
	}

  end:
	ctx->flags |= default_scopes;
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
static int promex_send_headers(struct appctx *appctx, struct conn_stream *cs, struct htx *htx)
{
	struct channel *chn = cs_ic(cs);
	struct htx_sl *sl;
	unsigned int flags;

	flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_ENC|HTX_SL_F_XFER_LEN|HTX_SL_F_CHNK);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), ist("200"), ist("OK"));
	if (!sl)
		goto full;
	sl->info.res.status = 200;
	if (!htx_add_header(htx, ist("Cache-Control"), ist("no-cache")) ||
	    !htx_add_header(htx, ist("Content-Type"), ist("text/plain; version=0.0.4")) ||
	    !htx_add_header(htx, ist("Transfer-Encoding"), ist("chunked")) ||
	    !htx_add_endof(htx, HTX_BLK_EOH))
		goto full;

	channel_add_input(chn, htx->data);
	return 1;
  full:
	htx_reset(htx);
	cs_rx_room_blk(cs);
	return 0;
}

/* The function returns 1 if the initialisation is complete, 0 if
 * an errors occurs and -1 if more data are required for initializing
 * the applet.
 */
static int promex_appctx_init(struct appctx *appctx)
{
	applet_reserve_svcctx(appctx, sizeof(struct promex_ctx));
	appctx->st0 = PROMEX_ST_INIT;
	return 1;
}

/* The main I/O handler for the promex applet. */
static void promex_appctx_handle_io(struct appctx *appctx)
{
	struct conn_stream *cs = appctx_cs(appctx);
	struct stream *s = __cs_strm(cs);
	struct channel *req = cs_oc(cs);
	struct channel *res = cs_ic(cs);
	struct htx *req_htx, *res_htx;
	int ret;

	res_htx = htx_from_buf(&res->buf);
	if (unlikely(cs->state == CS_ST_DIS || cs->state == CS_ST_CLO))
		goto out;

	/* Check if the input buffer is available. */
	if (!b_size(&res->buf)) {
		cs_rx_room_blk(cs);
		goto out;
	}

	switch (appctx->st0) {
		case PROMEX_ST_INIT:
			ret = promex_parse_uri(appctx, cs);
			if (ret <= 0) {
				if (ret == -1)
					goto error;
				goto out;
			}
			appctx->st0 = PROMEX_ST_HEAD;
			appctx->st1 = PROMEX_DUMPER_INIT;
			/* fall through */

		case PROMEX_ST_HEAD:
			if (!promex_send_headers(appctx, cs, res_htx))
				goto out;
			appctx->st0 = ((s->txn->meth == HTTP_METH_HEAD) ? PROMEX_ST_DONE : PROMEX_ST_DUMP);
			/* fall through */

		case PROMEX_ST_DUMP:
			ret = promex_dump_metrics(appctx, cs, res_htx);
			if (ret <= 0) {
				if (ret == -1)
					goto error;
				goto out;
			}
			appctx->st0 = PROMEX_ST_DONE;
			/* fall through */

		case PROMEX_ST_DONE:
			/* no more data are expected. If the response buffer is
			 * empty, be sure to add something (EOT block in this
			 * case) to have something to send. It is important to
			 * be sure the EOM flags will be handled by the
			 * endpoint.
			 */
			if (htx_is_empty(res_htx)) {
				if (!htx_add_endof(res_htx, HTX_BLK_EOT)) {
					cs_rx_room_blk(cs);
					goto out;
				}
				channel_add_input(res, 1);
			}
		        res_htx->flags |= HTX_FL_EOM;
			res->flags |= CF_EOI;
			appctx->endp->flags |= CS_EP_EOI;
			appctx->st0 = PROMEX_ST_END;
			/* fall through */

		case PROMEX_ST_END:
			if (!(res->flags & CF_SHUTR)) {
				res->flags |= CF_READ_NULL;
				cs_shutr(cs);
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
	cs_shutr(cs);
	cs_shutw(cs);
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
