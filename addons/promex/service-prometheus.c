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
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/stats.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>
#include <haproxy/xxhash.h>

#include <promex/promex.h>

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
	PROMEX_DUMPER_MODULES,    /* dump metrics of modules */
	PROMEX_DUMPER_DONE,       /* finished */
};

struct promex_module_ref {
	struct promex_module *mod;
	struct list list;
};

/* An entry in a headers map */
struct promex_metric_filter  {
	int exclude;
        struct eb32_node node;
};

/* the context of the applet */
struct promex_ctx {
	void *p[4];                /* generic pointers used to save context  */
	unsigned int flags;	   /* PROMEX_FL_* */
	unsigned field_num;        /* current field number (ST_I_PX_* etc) */
	unsigned mod_field_num;    /* first field number of the current module (ST_I_PX_* etc) */
	int obj_state;             /* current state among PROMEX_{FRONT|BACK|SRV|LI}_STATE_* */
	struct list modules;       /* list of promex modules to export */
	struct eb_root filters;    /* list of filters to apply on metrics name */
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

/* Global metrics  */
const struct promex_metric promex_global_metrics[ST_I_INF_MAX] = {
	//[ST_I_INF_NAME]                           ignored
	//[ST_I_INF_VERSION],                       ignored
	//[ST_I_INF_RELEASE_DATE]                   ignored
	[ST_I_INF_NBTHREAD]                       = { .n = IST("nbthread"),                      .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_NBPROC]                         = { .n = IST("nbproc"),                        .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_PROCESS_NUM]                    = { .n = IST("relative_process_id"),           .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[ST_I_INF_PID]                            ignored
	//[ST_I_INF_UPTIME]                         ignored
	[ST_I_INF_UPTIME_SEC]                     = { .n = IST("uptime_seconds"),                .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_START_TIME_SEC]                 = { .n = IST("start_time_seconds"),            .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[ST_I_INF_MEMMAX_MB]                      ignored
	[ST_I_INF_MEMMAX_BYTES]                   = { .n = IST("max_memory_bytes"),              .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[ST_I_INF_POOL_ALLOC_MB]                  ignored
	[ST_I_INF_POOL_ALLOC_BYTES]               = { .n = IST("pool_allocated_bytes"),          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[ST_I_INF_POOL_USED_MB]                   ignored
	[ST_I_INF_POOL_USED_BYTES]                = { .n = IST("pool_used_bytes"),               .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_POOL_FAILED]                    = { .n = IST("pool_failures_total"),           .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_ULIMIT_N]                       = { .n = IST("max_fds"),                       .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_MAXSOCK]                        = { .n = IST("max_sockets"),                   .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_MAXCONN]                        = { .n = IST("max_connections"),               .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_HARD_MAXCONN]                   = { .n = IST("hard_max_connections"),          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_CURR_CONN]                      = { .n = IST("current_connections"),           .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_CUM_CONN]                       = { .n = IST("connections_total"),             .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_CUM_REQ]                        = { .n = IST("requests_total"),                .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_MAX_SSL_CONNS]                  = { .n = IST("max_ssl_connections"),           .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_CURR_SSL_CONNS]                 = { .n = IST("current_ssl_connections"),       .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_CUM_SSL_CONNS]                  = { .n = IST("ssl_connections_total"),         .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_MAXPIPES]                       = { .n = IST("max_pipes"),                     .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_PIPES_USED]                     = { .n = IST("pipes_used_total"),              .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_PIPES_FREE]                     = { .n = IST("pipes_free_total"),              .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_CONN_RATE]                      = { .n = IST("current_connection_rate"),       .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_CONN_RATE_LIMIT]                = { .n = IST("limit_connection_rate"),         .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_MAX_CONN_RATE]                  = { .n = IST("max_connection_rate"),           .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SESS_RATE]                      = { .n = IST("current_session_rate"),          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SESS_RATE_LIMIT]                = { .n = IST("limit_session_rate"),            .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_MAX_SESS_RATE]                  = { .n = IST("max_session_rate"),              .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SSL_RATE]                       = { .n = IST("current_ssl_rate"),              .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SSL_RATE_LIMIT]                 = { .n = IST("limit_ssl_rate"),                .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_MAX_SSL_RATE]                   = { .n = IST("max_ssl_rate"),                  .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SSL_FRONTEND_KEY_RATE]          = { .n = IST("current_frontend_ssl_key_rate"), .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SSL_FRONTEND_MAX_KEY_RATE]      = { .n = IST("max_frontend_ssl_key_rate"),     .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SSL_FRONTEND_SESSION_REUSE_PCT] = { .n = IST("frontend_ssl_reuse"),            .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SSL_BACKEND_KEY_RATE]           = { .n = IST("current_backend_ssl_key_rate"),  .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SSL_BACKEND_MAX_KEY_RATE]       = { .n = IST("max_backend_ssl_key_rate"),      .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SSL_CACHE_LOOKUPS]              = { .n = IST("ssl_cache_lookups_total"),       .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_SSL_CACHE_MISSES]               = { .n = IST("ssl_cache_misses_total"),        .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_COMPRESS_BPS_IN]                = { .n = IST("http_comp_bytes_in_total"),      .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_COMPRESS_BPS_OUT]               = { .n = IST("http_comp_bytes_out_total"),     .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_COMPRESS_BPS_RATE_LIM]          = { .n = IST("limit_http_comp"),               .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_ZLIB_MEM_USAGE]                 = { .n = IST("current_zlib_memory"),           .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_MAX_ZLIB_MEM_USAGE]             = { .n = IST("max_zlib_memory"),               .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_TASKS]                          = { .n = IST("current_tasks"),                 .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_RUN_QUEUE]                      = { .n = IST("current_run_queue"),             .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_IDLE_PCT]                       = { .n = IST("idle_time_percent"),             .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_NODE]                           = { .n = IST("node"),                          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_DESCRIPTION]                    = { .n = IST("description"),                   .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_STOPPING]                       = { .n = IST("stopping"),                      .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_JOBS]                           = { .n = IST("jobs"),                          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_UNSTOPPABLE_JOBS]               = { .n = IST("unstoppable_jobs"),              .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_LISTENERS]                      = { .n = IST("listeners"),                     .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_ACTIVE_PEERS]                   = { .n = IST("active_peers"),                  .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_CONNECTED_PEERS]                = { .n = IST("connected_peers"),               .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_DROPPED_LOGS]                   = { .n = IST("dropped_logs_total"),            .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_BUSY_POLLING]                   = { .n = IST("busy_polling_enabled"),          .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_FAILED_RESOLUTIONS]             = { .n = IST("failed_resolutions"),            .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_TOTAL_BYTES_OUT]                = { .n = IST("bytes_out_total"),               .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_TOTAL_SPLICED_BYTES_OUT]        = { .n = IST("spliced_bytes_out_total"),       .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_BYTES_OUT_RATE]                 = { .n = IST("bytes_out_rate"),                .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
	//[ST_I_INF_DEBUG_COMMANDS_ISSUED]          ignored
	[ST_I_INF_CUM_LOG_MSGS]                   = { .n = IST("recv_logs_total"),               .type = PROMEX_MT_COUNTER, .flags = PROMEX_FL_INFO_METRIC },
	[ST_I_INF_BUILD_INFO]                     = { .n = IST("build_info"),                    .type = PROMEX_MT_GAUGE,   .flags = PROMEX_FL_INFO_METRIC },
};

/* frontend/backend/server fields */
const struct promex_metric promex_st_metrics[ST_I_PX_MAX] = {
	//[ST_I_PX_PXNAME]               ignored
	//[ST_I_PX_SVNAME]               ignored
	[ST_I_PX_QCUR]                 = { .n = IST("current_queue"),                    .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_QMAX]                 = { .n = IST("max_queue"),                        .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_SCUR]                 = { .n = IST("current_sessions"),                 .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_SMAX]                 = { .n = IST("max_sessions"),                     .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_SLIM]                 = { .n = IST("limit_sessions"),                   .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_STOT]                 = { .n = IST("sessions_total"),                   .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_BIN]                  = { .n = IST("bytes_in_total"),                   .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_BOUT]                 = { .n = IST("bytes_out_total"),                  .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_DREQ]                 = { .n = IST("requests_denied_total"),            .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC                       ) },
	[ST_I_PX_DRESP]                = { .n = IST("responses_denied_total"),           .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_EREQ]                 = { .n = IST("request_errors_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC                                               ) },
	[ST_I_PX_ECON]                 = { .n = IST("connection_errors_total"),          .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_ERESP]                = { .n = IST("response_errors_total"),            .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_WRETR]                = { .n = IST("retry_warnings_total"),             .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_WREDIS]               = { .n = IST("redispatch_warnings_total"),        .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_STATUS]               = { .n = IST("status"),                           .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_WEIGHT]               = { .n = IST("weight"),                           .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_ACT]                  = { .n = IST("active_servers"),                   .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_BCK]                  = { .n = IST("backup_servers"),                   .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_CHKFAIL]              = { .n = IST("check_failures_total"),             .type = PROMEX_MT_COUNTER,  .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_CHKDOWN]              = { .n = IST("check_up_down_total"),              .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_LASTCHG]              = { .n = IST("check_last_change_seconds"),        .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_DOWNTIME]             = { .n = IST("downtime_seconds_total"),           .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_QLIMIT]               = { .n = IST("queue_limit"),                      .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	//[ST_I_PX_PID]                  ignored
	//[ST_I_PX_IID]                  ignored
	//[ST_I_PX_SID]                  ignored
	[ST_I_PX_THROTTLE]             = { .n = IST("current_throttle"),                 .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_LBTOT]                = { .n = IST("loadbalanced_total"),               .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	//[ST_I_PX_TRACKED]              ignored
	//[ST_I_PX_TYPE]                 ignored
	//[ST_I_PX_RATE]                 ignored
	[ST_I_PX_RATE_LIM]             = { .n = IST("limit_session_rate"),               .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC                                                                     ) },
	[ST_I_PX_RATE_MAX]             = { .n = IST("max_session_rate"),                 .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_CHECK_STATUS]         = { .n = IST("check_status"),                     .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_CHECK_CODE]           = { .n = IST("check_code"),                       .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_CHECK_DURATION]       = { .n = IST("check_duration_seconds"),           .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_HRSP_1XX]             = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_HRSP_2XX]             = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_HRSP_3XX]             = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_HRSP_4XX]             = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_HRSP_5XX]             = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_HRSP_OTHER]           = { .n = IST("http_responses_total"),             .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	//[ST_I_PX_HANAFAIL]             ignored
	//[ST_I_PX_REQ_RATE]             ignored
	[ST_I_PX_REQ_RATE_MAX]         = { .n = IST("http_requests_rate_max"),           .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC                                                                     ) },
	[ST_I_PX_REQ_TOT]              = { .n = IST("http_requests_total"),              .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_I_PX_CLI_ABRT]             = { .n = IST("client_aborts_total"),              .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_SRV_ABRT]             = { .n = IST("server_aborts_total"),              .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_COMP_IN]              = { .n = IST("http_comp_bytes_in_total"),         .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_I_PX_COMP_OUT]             = { .n = IST("http_comp_bytes_out_total"),        .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_I_PX_COMP_BYP]             = { .n = IST("http_comp_bytes_bypassed_total"),   .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_I_PX_COMP_RSP]             = { .n = IST("http_comp_responses_total"),        .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_I_PX_LASTSESS]             = { .n = IST("last_session_seconds"),             .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	//[ST_I_PX_LAST_CHK]             ignored
	//[ST_I_PX_LAST_AGT]             ignored
	[ST_I_PX_QTIME]                = { .n = IST("queue_time_average_seconds"),       .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_CTIME]                = { .n = IST("connect_time_average_seconds"),     .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_RTIME]                = { .n = IST("response_time_average_seconds"),    .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_TTIME]                = { .n = IST("total_time_average_seconds"),       .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	//[ST_I_PX_AGENT_STATUS]         ignored
	//[ST_I_PX_AGENT_CODE]           ignored
	//[ST_I_PX_AGENT_DURATION]       ignored
	//[ST_I_PX_CHECK_DESC]           ignored
	//[ST_I_PX_AGENT_DESC]           ignored
	//[ST_I_PX_CHECK_RISE]           ignored
	//[ST_I_PX_CHECK_FALL]           ignored
	//[ST_I_PX_CHECK_HEALTH]         ignored
	//[ST_I_PX_AGENT_RISE]           ignored
	//[ST_I_PX_AGENT_FALL]           ignored
	//[ST_I_PX_AGENT_HEALTH]         ignored
	//[ST_I_PX_ADDR]                 ignored
	//[ST_I_PX_COOKIE]               ignored
	//[ST_I_PX_MODE]                 ignored
	//[ST_I_PX_ALGO]                 ignored
	//[ST_I_PX_CONN_RATE]            ignored
	[ST_I_PX_CONN_RATE_MAX]        = { .n = IST("connections_rate_max"),             .type = PROMEX_MT_GAUGE,    .flags = (PROMEX_FL_FRONT_METRIC                                                                     ) },
	[ST_I_PX_CONN_TOT]             = { .n = IST("connections_total"),                .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC                                                                     ) },
	[ST_I_PX_INTERCEPTED]          = { .n = IST("intercepted_requests_total"),       .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC                                                                     ) },
	[ST_I_PX_DCON]                 = { .n = IST("denied_connections_total"),         .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC                                               ) },
	[ST_I_PX_DSES]                 = { .n = IST("denied_sessions_total"),            .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC                                               ) },
	[ST_I_PX_WREW]                 = { .n = IST("failed_header_rewriting_total"),    .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_CONNECT]              = { .n = IST("connection_attempts_total"),        .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_REUSE]                = { .n = IST("connection_reuses_total"),          .type = PROMEX_MT_COUNTER,  .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_CACHE_LOOKUPS]        = { .n = IST("http_cache_lookups_total"),         .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_I_PX_CACHE_HITS]           = { .n = IST("http_cache_hits_total"),            .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC |                       PROMEX_FL_BACK_METRIC                       ) },
	[ST_I_PX_SRV_ICUR]             = { .n = IST("idle_connections_current"),         .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_SRV_ILIM]             = { .n = IST("idle_connections_limit"),           .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_QT_MAX]               = { .n = IST("max_queue_time_seconds"),           .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_CT_MAX]               = { .n = IST("max_connect_time_seconds"),         .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_RT_MAX]               = { .n = IST("max_response_time_seconds"),        .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_TT_MAX]               = { .n = IST("max_total_time_seconds"),           .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_EINT]                 = { .n = IST("internal_errors_total"),            .type = PROMEX_MT_COUNTER,  .flags = (PROMEX_FL_FRONT_METRIC | PROMEX_FL_LI_METRIC | PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_IDLE_CONN_CUR]        = { .n = IST("unsafe_idle_connections_current"),  .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_SAFE_CONN_CUR]        = { .n = IST("safe_idle_connections_current"),    .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_USED_CONN_CUR]        = { .n = IST("used_connections_current"),         .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_NEED_CONN_EST]        = { .n = IST("need_connections_current"),         .type = PROMEX_MT_GAUGE,    .flags = (                                                                       PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_UWEIGHT]              = { .n = IST("uweight"),                          .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC | PROMEX_FL_SRV_METRIC) },
	[ST_I_PX_AGG_SRV_CHECK_STATUS] = { .n = IST("agg_server_check_status"),	      .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC                       ) },
	[ST_I_PX_AGG_SRV_STATUS ]      = { .n = IST("agg_server_status"),	              .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC                       ) },
	[ST_I_PX_AGG_CHECK_STATUS]     = { .n = IST("agg_check_status"),	              .type = PROMEX_MT_GAUGE,    .flags = (                                               PROMEX_FL_BACK_METRIC                       ) },
};

/* Specialized frontend metric names, to override default ones */
const struct ist promex_st_front_metrics_names[ST_I_PX_MAX] = {
};

/* Specialized backend metric names, to override default ones */
const struct ist promex_st_back_metrics_names[ST_I_PX_MAX] = {
};

/* Specialized listener metric names, to override default ones */
const struct ist promex_st_li_metrics_names[ST_I_PX_MAX] = {
};

/* Specialized server metric names, to override default ones */
const struct ist promex_st_srv_metrics_names[ST_I_PX_MAX] = {
	[ST_I_PX_ACT] = IST("active"),
	[ST_I_PX_BCK] = IST("backup"),
};

/* Description of overridden stats fields */
const struct ist promex_st_metric_desc[ST_I_PX_MAX] = {
	[ST_I_PX_STATUS]         = IST("Current status of the service, per state label value."),
	[ST_I_PX_CHECK_STATUS]   = IST("Status of last health check, per state label value."),
	[ST_I_PX_CHECK_CODE]     = IST("layer5-7 code, if available of the last health check."),
	[ST_I_PX_CHECK_DURATION] = IST("Total duration of the latest server health check, in seconds."),
	[ST_I_PX_QTIME]          = IST("Avg. queue time for last 1024 successful connections."),
	[ST_I_PX_CTIME]          = IST("Avg. connect time for last 1024 successful connections."),
	[ST_I_PX_RTIME]          = IST("Avg. response time for last 1024 successful connections."),
	[ST_I_PX_TTIME]          = IST("Avg. total time for last 1024 successful connections."),
	[ST_I_PX_QT_MAX]         = IST("Maximum observed time spent in the queue"),
	[ST_I_PX_CT_MAX]         = IST("Maximum observed time spent waiting for a connection to complete"),
	[ST_I_PX_RT_MAX]         = IST("Maximum observed time spent waiting for a server response"),
	[ST_I_PX_TT_MAX]         = IST("Maximum observed total request+response time (request+queue+connect+response+processing)"),
};

/* Specific labels for all ST_I_PX_HRSP_* fields */
const struct ist promex_hrsp_code[1 + ST_I_PX_HRSP_OTHER - ST_I_PX_HRSP_1XX] = {
	[ST_I_PX_HRSP_1XX - ST_I_PX_HRSP_1XX]   = IST("1xx"),
	[ST_I_PX_HRSP_2XX - ST_I_PX_HRSP_1XX]   = IST("2xx"),
	[ST_I_PX_HRSP_3XX - ST_I_PX_HRSP_1XX]   = IST("3xx"),
	[ST_I_PX_HRSP_4XX - ST_I_PX_HRSP_1XX]   = IST("4xx"),
	[ST_I_PX_HRSP_5XX - ST_I_PX_HRSP_1XX]   = IST("5xx"),
	[ST_I_PX_HRSP_OTHER - ST_I_PX_HRSP_1XX] = IST("other"),
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

struct list promex_module_list = LIST_HEAD_INIT(promex_module_list);


void promex_register_module(struct promex_module *m)
{
	LIST_APPEND(&promex_module_list, &m->list);
}

/* Pools used to allocate ref on Promex modules and filters */
DECLARE_STATIC_POOL(pool_head_promex_mod_ref,    "promex_module_ref",  sizeof(struct promex_module_ref));
DECLARE_STATIC_POOL(pool_head_promex_metric_flt, "promex_metric_filter", sizeof(struct promex_metric_filter));

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
static int promex_ts_val_to_str(struct buffer *out, struct field *f, size_t max)
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

/* Dump the time series header lines for the metric <name>. It is its #HELP and #TYPE
 * strings. It returns 1 on success. Otherwise, if <out> length exceeds <max>,
 * it returns 0.
 */
static int promex_dump_ts_header(const struct ist name, const struct ist desc, enum promex_mt_type type,
				 struct ist *out, size_t max)
{
	struct ist t;

	switch (type) {
		case PROMEX_MT_COUNTER:
			t = ist("counter");
			break;
		default:
			t = ist("gauge");
	}

	if (istcat(out, ist("# HELP "), max) == -1 ||
	    istcat(out, name, max) == -1 ||
	    istcat(out, ist(" "), max) == -1 ||
	    istcat(out, desc, max) == -1)
		goto full;

	if (istcat(out, ist("\n# TYPE "), max) == -1 ||
	    istcat(out, name, max) == -1 ||
	    istcat(out, ist(" "), max) == -1 ||
	    istcat(out, t, max) == -1 ||
	    istcat(out, ist("\n"), max) == -1)
		goto full;

	return 1;

  full:
	return 0;
}

/* Dump the time series for the metric <name>. It starts by the metric name followed by
 * its labels (proxy name, server name...) between braces and finally its
 * value. If not already done, the header lines are dumped first. It returns 1
 * on success. Otherwise if <out> length exceeds <max>, it returns 0.
 */
static int promex_dump_ts(struct appctx *appctx, struct ist prefix,
			  const struct ist name, const  struct ist desc, enum promex_mt_type type,
			  struct field *val, struct promex_label *labels, struct ist *out, size_t max)
{
	struct ist n = { .ptr = (char[PROMEX_MAX_NAME_LEN]){ 0 }, .len = 0 };
	struct promex_ctx *ctx = appctx->svcctx;
	size_t len = out->len;

	if (out->len + PROMEX_MAX_METRIC_LENGTH > max)
		return 0;


	/* Fill the metric name */
	istcat(&n, prefix, PROMEX_MAX_NAME_LEN);
	istcat(&n, name, PROMEX_MAX_NAME_LEN);

	if ((ctx->flags & PROMEX_FL_METRIC_HDR) &&
	    !promex_dump_ts_header(n, desc, type, out, max))
		goto full;

	if (istcat(out, n, max) == -1)
		goto full;

	if (isttest(labels[0].name)) {
		int i;

		if (istcat(out, ist("{"), max) == -1)
			goto full;

		for (i = 0; i < PROMEX_MAX_LABELS && isttest(labels[i].name); i++) {
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
	if (!promex_ts_val_to_str(&trash, val, max))
		goto full;
	out->len = trash.data;

	ctx->flags &= ~PROMEX_FL_METRIC_HDR;
	return 1;
  full:
	// Restore previous length
	out->len = len;
	return 0;

}

static int promex_filter_metric(struct appctx *appctx, struct ist prefix, struct ist name)
{
	struct promex_ctx *ctx = appctx->svcctx;
	struct eb32_node *node;
	struct promex_metric_filter *flt;
	unsigned int hash;
	XXH32_state_t state;

	if (!eb_is_empty(&ctx->filters)) {
		XXH32_reset(&state, 0);
		XXH32_update(&state, istptr(prefix), istlen(prefix));
		XXH32_update(&state, istptr(name), istlen(name));
		hash = XXH32_digest(&state);

		node = eb32_lookup(&ctx->filters, hash);
		if (node) {
			flt = container_of(node, typeof(*flt), node);
			if (flt->exclude)
				return 1;
		}
		else if (!(ctx->flags & PROMEX_FL_INC_METRIC_BY_DEFAULT))
			return 1;
	}

	return 0;
}

/* Dump global metrics (prefixed by "haproxy_process_"). It returns 1 on success,
 * 0 if <htx> is full and -1 in case of any error. */
static int promex_dump_global_metrics(struct appctx *appctx, struct htx *htx)
{
	static struct ist prefix = IST("haproxy_process_");
	struct promex_ctx *ctx = appctx->svcctx;
	struct field val;
	struct channel *chn = sc_ic(appctx_sc(appctx));
	struct ist name, desc, out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	int ret = 1;

	if (!stats_fill_info(stat_line_info, ST_I_INF_MAX, 0))
		return -1;

	for (; ctx->field_num < ST_I_INF_MAX; ctx->field_num++) {
		struct promex_label labels[PROMEX_MAX_LABELS-1] = {};
		int lb_idx = 0;

		if (!(promex_global_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		name = promex_global_metrics[ctx->field_num].n;
		desc = ist(stat_cols_info[ctx->field_num].desc);

		if (promex_filter_metric(appctx, prefix, name))
			continue;

		switch (ctx->field_num) {
			case ST_I_INF_NODE:
				labels[lb_idx].name  = ist("node");
				labels[lb_idx].value = ist(global.node);
				lb_idx++;
				val = mkf_u32(FN_GAUGE, 1);
				break;

			case ST_I_INF_DESCRIPTION:
				if (!global.desc)
					continue;
				val = mkf_u32(FN_GAUGE, 1);
				break;

			case ST_I_INF_BUILD_INFO:
				labels[lb_idx].name  = ist("version");
				labels[lb_idx].value = ist(HAPROXY_VERSION);
				lb_idx++;
				val = mkf_u32(FN_GAUGE, 1);
				break;

			default:
				val = stat_line_info[ctx->field_num];
		}

		if (global.desc && ((ctx->field_num == ST_I_INF_DESCRIPTION) || (ctx->flags & PROMEX_FL_DESC_LABELS))) {
			labels[lb_idx].name  = ist("desc");
			labels[lb_idx].value = ist(global.desc);
			lb_idx++;
		}

		if (!promex_dump_ts(appctx, prefix, name, desc,
				    promex_global_metrics[ctx->field_num].type,
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
	struct proxy *px = ctx->p[0];
	struct stats_module *mod = ctx->p[1];
	struct field val;
	struct channel *chn = sc_ic(appctx_sc(appctx));
	struct ist name, desc, out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	struct field *stats = stat_lines[STATS_DOMAIN_PROXY];
	int ret = 1;
	enum promex_front_state state;

	for (;ctx->field_num < ST_I_PX_MAX; ctx->field_num++) {
		if (!(promex_st_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		name = promex_st_front_metrics_names[ctx->field_num];
		desc = promex_st_metric_desc[ctx->field_num];

		if (!isttest(name))
			name = promex_st_metrics[ctx->field_num].n;
		if (!isttest(desc))
			desc = ist(stat_cols_px[ctx->field_num].desc);

		if (promex_filter_metric(appctx, prefix, name))
			continue;

		if (!px)
			px = proxies_list;

		while (px) {
			struct promex_label labels[PROMEX_MAX_LABELS-1] = {};
			int lb_idx = 0;

			labels[lb_idx].name  = ist("proxy");
			labels[lb_idx].value = ist2(px->id, strlen(px->id));
			lb_idx++;

			if ((ctx->flags & PROMEX_FL_DESC_LABELS) && px->desc) {
				labels[lb_idx].name  = ist("desc");
				labels[lb_idx].value = ist(px->desc);
				lb_idx++;
			}

			/* skip the disabled proxies, global frontend and non-networked ones */
			if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_FE))
				goto next_px;

			if (!stats_fill_fe_line(px, 0, stats, ST_I_PX_MAX, &(ctx->field_num)))
				return -1;

			switch (ctx->field_num) {
				case ST_I_PX_STATUS:
					state = !(px->flags & PR_FL_STOPPED);
					for (; ctx->obj_state < PROMEX_FRONT_STATE_COUNT; ctx->obj_state++) {
						labels[lb_idx].name = ist("state");
						labels[lb_idx].value = promex_front_st[ctx->obj_state];
						val = mkf_u32(FO_STATUS, state == ctx->obj_state);

						if (!promex_dump_ts(appctx, prefix, name, desc,
								    promex_st_metrics[ctx->field_num].type,
								    &val, labels, &out, max))
							goto full;
					}
					ctx->obj_state = 0;
					goto next_px;
				case ST_I_PX_REQ_RATE_MAX:
				case ST_I_PX_REQ_TOT:
				case ST_I_PX_INTERCEPTED:
				case ST_I_PX_CACHE_LOOKUPS:
				case ST_I_PX_CACHE_HITS:
				case ST_I_PX_COMP_IN:
				case ST_I_PX_COMP_OUT:
				case ST_I_PX_COMP_BYP:
				case ST_I_PX_COMP_RSP:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					val = stats[ctx->field_num];
					break;
				case ST_I_PX_HRSP_1XX:
				case ST_I_PX_HRSP_2XX:
				case ST_I_PX_HRSP_3XX:
				case ST_I_PX_HRSP_4XX:
				case ST_I_PX_HRSP_5XX:
				case ST_I_PX_HRSP_OTHER:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					if (ctx->field_num != ST_I_PX_HRSP_1XX)
						ctx->flags &= ~PROMEX_FL_METRIC_HDR;
					labels[lb_idx].name = ist("code");
					labels[lb_idx].value = promex_hrsp_code[ctx->field_num - ST_I_PX_HRSP_1XX];
					val = stats[ctx->field_num];
					break;

				default:
					val = stats[ctx->field_num];
			}

			if (!promex_dump_ts(appctx, prefix, name, desc,
					    promex_st_metrics[ctx->field_num].type,
					    &val, labels, &out, max))
				goto full;
		  next_px:
			px = px->next;
		}
		ctx->flags |= PROMEX_FL_METRIC_HDR;
	}

	/* Skip extra counters */
	if (!(ctx->flags & PROMEX_FL_EXTRA_COUNTERS))
		goto end;

	if (!mod) {
		mod = LIST_NEXT(&stats_module_list[STATS_DOMAIN_PROXY], typeof(mod), list);
		ctx->mod_field_num = 0;
	}

	list_for_each_entry_from(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		void *counters;

		if (!(stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_FE))
			continue;

		for (;ctx->mod_field_num < mod->stats_count; ctx->mod_field_num++) {
			name = ist2(mod->stats[ctx->mod_field_num].name, strlen(mod->stats[ctx->mod_field_num].name));
			desc = ist2(mod->stats[ctx->mod_field_num].desc, strlen(mod->stats[ctx->mod_field_num].desc));

			if (promex_filter_metric(appctx, prefix, name))
				continue;

			if (!px)
				px = proxies_list;

			while (px) {
				struct promex_label labels[PROMEX_MAX_LABELS-1] = {};
				struct promex_metric metric;
				int lb_idx = 0;

				labels[lb_idx].name  = ist("proxy");
				labels[lb_idx].value = ist2(px->id, strlen(px->id));
				lb_idx++;

				labels[lb_idx].name  = ist("mod");
				labels[lb_idx].value = ist2(mod->name, strlen(mod->name));
				lb_idx++;

				if ((ctx->flags & PROMEX_FL_DESC_LABELS) && px->desc) {
					labels[lb_idx].name  = ist("desc");
					labels[lb_idx].value = ist(px->desc);
					lb_idx++;
				}

				/* skip the disabled proxies, global frontend and non-networked ones */
				if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_FE))
					goto next_px2;

				counters = EXTRA_COUNTERS_GET(px->extra_counters_fe, mod);
				if (!mod->fill_stats(counters, stats + ctx->field_num, &ctx->mod_field_num))
					return -1;

				val = stats[ctx->field_num + ctx->mod_field_num];
				metric.type = ((val.type == FN_GAUGE) ? PROMEX_MT_GAUGE : PROMEX_MT_COUNTER);

				if (!promex_dump_ts(appctx, prefix, name, desc, metric.type,
						    &val, labels, &out, max))
					goto full;

			next_px2:
				px = px->next;
			}
			ctx->flags |= PROMEX_FL_METRIC_HDR;
		}

		ctx->field_num += mod->stats_count;
		ctx->mod_field_num = 0;
	}

	px = NULL;
	mod = NULL;

  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}

	/* Save pointers (0=current proxy, 1=current stats module) of the current context */
	ctx->p[0] = px;
	ctx->p[1] = mod;
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
	struct proxy *px = ctx->p[0];
	struct listener *li = ctx->p[1];
	struct stats_module *mod = ctx->p[2];
	struct field val;
	struct channel *chn = sc_ic(appctx_sc(appctx));
	struct ist name, desc, out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	struct field *stats = stat_lines[STATS_DOMAIN_PROXY];
	int ret = 1;
	enum li_status status;

	for (;ctx->field_num < ST_I_PX_MAX; ctx->field_num++) {
		if (!(promex_st_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		name = promex_st_li_metrics_names[ctx->field_num];
		desc = promex_st_metric_desc[ctx->field_num];

		if (!isttest(name))
			name = promex_st_metrics[ctx->field_num].n;
		if (!isttest(desc))
			desc = ist(stat_cols_px[ctx->field_num].desc);

		if (promex_filter_metric(appctx, prefix, name))
			continue;

		if (!px)
			px = proxies_list;

		while (px) {
			struct promex_label labels[PROMEX_MAX_LABELS-1] = {};
			int lb_idx = 0;

			labels[lb_idx].name  = ist("proxy");
			labels[lb_idx].value = ist2(px->id, strlen(px->id));
			lb_idx++;


			if ((ctx->flags & PROMEX_FL_DESC_LABELS) && px->desc) {
				labels[lb_idx].name  = ist("desc");
				labels[lb_idx].value = ist(px->desc);
				lb_idx++;
			}

			/* skip the disabled proxies, global frontend and non-networked ones */
			if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_FE))
				goto next_px;

			if (!li)
				li = LIST_NEXT(&px->conf.listeners, struct listener *, by_fe);

			list_for_each_entry_from(li, &px->conf.listeners, by_fe) {
				if (!li->counters)
					continue;

				labels[lb_idx].name  = ist("listener");
				labels[lb_idx].value = ist2(li->name, strlen(li->name));

				if (!stats_fill_li_line(px, li, 0, stats,
				                        ST_I_PX_MAX, &(ctx->field_num)))
					return -1;

				switch (ctx->field_num) {
					case ST_I_PX_STATUS:
						status = get_li_status(li);
						for (; ctx->obj_state < LI_STATE_COUNT; ctx->obj_state++) {
							val = mkf_u32(FO_STATUS, status == ctx->obj_state);
							labels[lb_idx+1].name = ist("state");
							labels[lb_idx+1].value = ist(li_status_st[ctx->obj_state]);
							if (!promex_dump_ts(appctx, prefix, name, desc,
									    promex_st_metrics[ctx->field_num].type,
									    &val, labels, &out, max))
								goto full;
						}
						ctx->obj_state = 0;
						continue;
					default:
						val = stats[ctx->field_num];
				}

				if (!promex_dump_ts(appctx, prefix, name, desc,
						    promex_st_metrics[ctx->field_num].type,
						    &val, labels, &out, max))
					goto full;
			}
			li = NULL;

		  next_px:
			px = px->next;
		}
		ctx->flags |= PROMEX_FL_METRIC_HDR;
	}

	/* Skip extra counters */
	if (!(ctx->flags & PROMEX_FL_EXTRA_COUNTERS))
		goto end;

	if (!mod) {
		mod = LIST_NEXT(&stats_module_list[STATS_DOMAIN_PROXY], typeof(mod), list);
		ctx->mod_field_num = 0;
	}

	list_for_each_entry_from(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		void *counters;

		if (!(stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_LI))
			continue;

		for (;ctx->mod_field_num < mod->stats_count; ctx->mod_field_num++) {
			name = ist2(mod->stats[ctx->mod_field_num].name, strlen(mod->stats[ctx->mod_field_num].name));
			desc = ist2(mod->stats[ctx->mod_field_num].desc, strlen(mod->stats[ctx->mod_field_num].desc));

			if (promex_filter_metric(appctx, prefix, name))
				continue;

			if (!px)
				px = proxies_list;

			while (px) {
				struct promex_label labels[PROMEX_MAX_LABELS-1] = {};
				struct promex_metric metric;
				int lb_idx = 0;

				labels[lb_idx].name  = ist("proxy");
				labels[lb_idx].value = ist2(px->id, strlen(px->id));
				lb_idx++;

				if ((ctx->flags & PROMEX_FL_DESC_LABELS) && px->desc) {
					labels[lb_idx].name  = ist("desc");
					labels[lb_idx].value = ist(px->desc);
					lb_idx++;
				}

				/* skip the disabled proxies, global frontend and non-networked ones */
				if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_FE))
					goto next_px2;

				if (!li)
					li = LIST_NEXT(&px->conf.listeners, struct listener *, by_fe);

				list_for_each_entry_from(li, &px->conf.listeners, by_fe) {
					if (!li->counters)
						continue;

					labels[lb_idx].name  = ist("listener");
					labels[lb_idx].value = ist2(li->name, strlen(li->name));

					labels[lb_idx+1].name  = ist("mod");
					labels[lb_idx+1].value = ist2(mod->name, strlen(mod->name));

					counters = EXTRA_COUNTERS_GET(li->extra_counters, mod);
					if (!mod->fill_stats(counters, stats + ctx->field_num, &ctx->mod_field_num))
						return -1;

					val = stats[ctx->field_num + ctx->mod_field_num];
					metric.type = ((val.type == FN_GAUGE) ? PROMEX_MT_GAUGE : PROMEX_MT_COUNTER);

					if (!promex_dump_ts(appctx, prefix, name, desc, metric.type,
							    &val, labels, &out, max))
						goto full;
				}
				li = NULL;

			next_px2:
				px = px->next;
			}
			ctx->flags |= PROMEX_FL_METRIC_HDR;
		}

		ctx->field_num += mod->stats_count;
		ctx->mod_field_num = 0;
	}

	px = NULL;
	li = NULL;
	mod = NULL;

  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}
	/* Save pointers (0=current proxy, 1=current listener, 2=current stats module) of the current context */
	ctx->p[0] = px;
	ctx->p[1] = li;
	ctx->p[2] = mod;
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
	struct promex_ctx *ctx = appctx->svcctx;
	struct proxy *px = ctx->p[0];
	struct stats_module *mod = ctx->p[1];
	struct server *sv;
	struct field val;
	struct channel *chn = sc_ic(appctx_sc(appctx));
	struct ist name, desc, out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	struct field *stats = stat_lines[STATS_DOMAIN_PROXY];
	int ret = 1;
	double secs;
	enum promex_back_state bkd_state;
	enum promex_srv_state srv_state;
	enum healthcheck_status srv_check_status;

	for (;ctx->field_num < ST_I_PX_MAX; ctx->field_num++) {
		if (!(promex_st_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		name = promex_st_back_metrics_names[ctx->field_num];
		desc = promex_st_metric_desc[ctx->field_num];

		if (!isttest(name))
			name = promex_st_metrics[ctx->field_num].n;
		if (!isttest(desc))
			desc = ist(stat_cols_px[ctx->field_num].desc);

		if (promex_filter_metric(appctx, prefix, name))
			continue;

		if (!px)
			px = proxies_list;

		while (px) {
			struct promex_label labels[PROMEX_MAX_LABELS-1] = {};
			unsigned int srv_state_count[PROMEX_SRV_STATE_COUNT] = { 0 };
			unsigned int srv_check_count[HCHK_STATUS_SIZE] = { 0 };
			const char *check_state;
			int lb_idx = 0;

			labels[lb_idx].name  = ist("proxy");
			labels[lb_idx].value = ist2(px->id, strlen(px->id));
			lb_idx++;

			if ((ctx->flags & PROMEX_FL_DESC_LABELS) && px->desc) {
				labels[lb_idx].name  = ist("desc");
				labels[lb_idx].value = ist(px->desc);
				lb_idx++;
			}


			/* skip the disabled proxies, global frontend and non-networked ones */
			if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_BE))
				goto next_px;

			if (!stats_fill_be_line(px, 0, stats, ST_I_PX_MAX, &(ctx->field_num)))
				return -1;

			switch (ctx->field_num) {
				case ST_I_PX_AGG_SRV_CHECK_STATUS: // DEPRECATED
				case ST_I_PX_AGG_SRV_STATUS:
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
						labels[lb_idx].name = ist("state");
						labels[lb_idx].value = promex_srv_st[ctx->obj_state];
						if (!promex_dump_ts(appctx, prefix, name, desc,
								    promex_st_metrics[ctx->field_num].type,
								    &val, labels, &out, max))
							goto full;
					}
					ctx->obj_state = 0;
					goto next_px;
				case ST_I_PX_AGG_CHECK_STATUS:
					if (!px->srv)
						goto next_px;
					sv = px->srv;
					while (sv) {
						if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) == CHK_ST_ENABLED) {
							srv_check_status = sv->check.status;
							srv_check_count[srv_check_status] += 1;
						}
						sv = sv->next;
					}
					for (; ctx->obj_state < HCHK_STATUS_SIZE; ctx->obj_state++) {
						if (get_check_status_result(ctx->obj_state) < CHK_RES_FAILED)
								continue;
						val = mkf_u32(FO_STATUS, srv_check_count[ctx->obj_state]);
						check_state = get_check_status_info(ctx->obj_state);
						labels[lb_idx].name = ist("state");
						labels[lb_idx].value = ist(check_state);
						if (!promex_dump_ts(appctx, prefix, name, desc,
								    promex_st_metrics[ctx->field_num].type,
								    &val, labels, &out, max))
							goto full;
					}
					ctx->obj_state = 0;
					goto next_px;
				case ST_I_PX_STATUS:
					bkd_state = ((px->lbprm.tot_weight > 0 || !px->srv) ? 1 : 0);
					for (; ctx->obj_state < PROMEX_BACK_STATE_COUNT; ctx->obj_state++) {
						labels[lb_idx].name = ist("state");
						labels[lb_idx].value = promex_back_st[ctx->obj_state];
						val = mkf_u32(FO_STATUS, bkd_state == ctx->obj_state);
						if (!promex_dump_ts(appctx, prefix, name, desc,
								    promex_st_metrics[ctx->field_num].type,
								    &val, labels, &out, max))
							goto full;
					}
					ctx->obj_state = 0;
					goto next_px;
				case ST_I_PX_QTIME:
					secs = (double)swrate_avg(px->be_counters.q_time, TIME_STATS_SAMPLES) / 1000.0;
					val = mkf_flt(FN_AVG, secs);
					break;
				case ST_I_PX_CTIME:
					secs = (double)swrate_avg(px->be_counters.c_time, TIME_STATS_SAMPLES) / 1000.0;
					val = mkf_flt(FN_AVG, secs);
					break;
				case ST_I_PX_RTIME:
					secs = (double)swrate_avg(px->be_counters.d_time, TIME_STATS_SAMPLES) / 1000.0;
					val = mkf_flt(FN_AVG, secs);
					break;
				case ST_I_PX_TTIME:
					secs = (double)swrate_avg(px->be_counters.t_time, TIME_STATS_SAMPLES) / 1000.0;
					val = mkf_flt(FN_AVG, secs);
					break;
				case ST_I_PX_QT_MAX:
					secs = (double)px->be_counters.qtime_max / 1000.0;
					val = mkf_flt(FN_MAX, secs);
					break;
				case ST_I_PX_CT_MAX:
					secs = (double)px->be_counters.ctime_max / 1000.0;
					val = mkf_flt(FN_MAX, secs);
					break;
				case ST_I_PX_RT_MAX:
					secs = (double)px->be_counters.dtime_max / 1000.0;
					val = mkf_flt(FN_MAX, secs);
					break;
				case ST_I_PX_TT_MAX:
					secs = (double)px->be_counters.ttime_max / 1000.0;
					val = mkf_flt(FN_MAX, secs);
					break;
				case ST_I_PX_REQ_TOT:
				case ST_I_PX_CACHE_LOOKUPS:
				case ST_I_PX_CACHE_HITS:
				case ST_I_PX_COMP_IN:
				case ST_I_PX_COMP_OUT:
				case ST_I_PX_COMP_BYP:
				case ST_I_PX_COMP_RSP:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					val = stats[ctx->field_num];
					break;
				case ST_I_PX_HRSP_1XX:
				case ST_I_PX_HRSP_2XX:
				case ST_I_PX_HRSP_3XX:
				case ST_I_PX_HRSP_4XX:
				case ST_I_PX_HRSP_5XX:
				case ST_I_PX_HRSP_OTHER:
					if (px->mode != PR_MODE_HTTP)
						goto next_px;
					if (ctx->field_num != ST_I_PX_HRSP_1XX)
						ctx->flags &= ~PROMEX_FL_METRIC_HDR;
					labels[lb_idx].name = ist("code");
					labels[lb_idx].value = promex_hrsp_code[ctx->field_num - ST_I_PX_HRSP_1XX];
					val = stats[ctx->field_num];
					break;

				default:
					val = stats[ctx->field_num];
			}

			if (!promex_dump_ts(appctx, prefix, name, desc,
					    promex_st_metrics[ctx->field_num].type,
					    &val, labels, &out, max))
				goto full;
		  next_px:
			px = px->next;
		}
		ctx->flags |= PROMEX_FL_METRIC_HDR;
	}

	/* Skip extra counters */
	if (!(ctx->flags & PROMEX_FL_EXTRA_COUNTERS))
		goto end;

	if (!mod) {
		mod = LIST_NEXT(&stats_module_list[STATS_DOMAIN_PROXY], typeof(mod), list);
		ctx->mod_field_num = 0;
	}

	list_for_each_entry_from(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		void *counters;

		if (!(stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_BE))
			continue;

		for (;ctx->mod_field_num < mod->stats_count; ctx->mod_field_num++) {
			name = ist2(mod->stats[ctx->mod_field_num].name, strlen(mod->stats[ctx->mod_field_num].name));
			desc = ist2(mod->stats[ctx->mod_field_num].desc, strlen(mod->stats[ctx->mod_field_num].desc));

			if (promex_filter_metric(appctx, prefix, name))
				continue;

			if (!px)
				px = proxies_list;

			while (px) {
				struct promex_label labels[PROMEX_MAX_LABELS-1] = {};
				struct promex_metric metric;
				int lb_idx = 0;

				labels[lb_idx].name  = ist("proxy");
				labels[lb_idx].value = ist2(px->id, strlen(px->id));
				lb_idx++;

				labels[lb_idx].name  = ist("mod");
				labels[lb_idx].value = ist2(mod->name, strlen(mod->name));
				lb_idx++;

				if ((ctx->flags & PROMEX_FL_DESC_LABELS) && px->desc) {
					labels[lb_idx].name  = ist("desc");
					labels[lb_idx].value = ist(px->desc);
					lb_idx++;
				}

				/* skip the disabled proxies, global frontend and non-networked ones */
				if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_BE))
					goto next_px2;

				counters = EXTRA_COUNTERS_GET(px->extra_counters_be, mod);
				if (!mod->fill_stats(counters, stats + ctx->field_num, &ctx->mod_field_num))
					return -1;

				val = stats[ctx->field_num + ctx->mod_field_num];
				metric.type = ((val.type == FN_GAUGE) ? PROMEX_MT_GAUGE : PROMEX_MT_COUNTER);

				if (!promex_dump_ts(appctx, prefix, name, desc, metric.type,
						    &val, labels, &out, max))
					goto full;

			next_px2:
				px = px->next;
			}
			ctx->flags |= PROMEX_FL_METRIC_HDR;
		}

		ctx->field_num += mod->stats_count;
		ctx->mod_field_num = 0;
	}

	px = NULL;
	mod = NULL;

  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}
	/* Save pointers (0=current proxy, 1=current stats module) of the current context */
	ctx->p[0] = px;
	ctx->p[1] = mod;
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
	struct proxy *px = ctx->p[0];
	struct server *sv = ctx->p[1];
	struct stats_module *mod = ctx->p[2];
	struct field val;
	struct channel *chn = sc_ic(appctx_sc(appctx));
	struct ist name, desc, out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	struct field *stats = stat_lines[STATS_DOMAIN_PROXY];
	int ret = 1;
	double secs;
	enum promex_srv_state state;
	const char *check_state;

	for (;ctx->field_num < ST_I_PX_MAX; ctx->field_num++) {
		if (!(promex_st_metrics[ctx->field_num].flags & ctx->flags))
			continue;

		name = promex_st_srv_metrics_names[ctx->field_num];
		desc = promex_st_metric_desc[ctx->field_num];

		if (!isttest(name))
			name = promex_st_metrics[ctx->field_num].n;
		if (!isttest(desc))
			desc = ist(stat_cols_px[ctx->field_num].desc);

		if (promex_filter_metric(appctx, prefix, name))
			continue;

		if (!px)
			px = proxies_list;

		while (px) {
			struct promex_label labels[PROMEX_MAX_LABELS-1] = {};
			int lb_idx = 0;

			labels[lb_idx].name  = ist("proxy");
			labels[lb_idx].value = ist2(px->id, strlen(px->id));
			lb_idx++;

			if ((ctx->flags & PROMEX_FL_DESC_LABELS) && px->desc) {
				labels[lb_idx].name  = ist("desc");
				labels[lb_idx].value = ist(px->desc);
				lb_idx++;
			}

			/* skip the disabled proxies, global frontend and non-networked ones */
			if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_BE))
				goto next_px;

			if (!sv)
				sv = px->srv;

			while (sv) {
				labels[lb_idx].name  = ist("server");
				labels[lb_idx].value = ist2(sv->id, strlen(sv->id));

				if (!stats_fill_sv_line(px, sv, 0, stats, ST_I_PX_MAX, &(ctx->field_num)))
					return -1;

				if ((ctx->flags & PROMEX_FL_NO_MAINT_SRV) && (sv->cur_admin & SRV_ADMF_MAINT))
					goto next_sv;

				switch (ctx->field_num) {
					case ST_I_PX_STATUS:
						state = promex_srv_status(sv);
						for (; ctx->obj_state < PROMEX_SRV_STATE_COUNT; ctx->obj_state++) {
							val = mkf_u32(FO_STATUS, state == ctx->obj_state);
							labels[lb_idx+1].name = ist("state");
							labels[lb_idx+1].value = promex_srv_st[ctx->obj_state];
							if (!promex_dump_ts(appctx, prefix, name, desc,
									    promex_st_metrics[ctx->field_num].type,
									    &val, labels, &out, max))
								goto full;
						}
						ctx->obj_state = 0;
						goto next_sv;
					case ST_I_PX_QTIME:
						secs = (double)swrate_avg(sv->counters.q_time, TIME_STATS_SAMPLES) / 1000.0;
						val = mkf_flt(FN_AVG, secs);
						break;
					case ST_I_PX_CTIME:
						secs = (double)swrate_avg(sv->counters.c_time, TIME_STATS_SAMPLES) / 1000.0;
						val = mkf_flt(FN_AVG, secs);
						break;
					case ST_I_PX_RTIME:
						secs = (double)swrate_avg(sv->counters.d_time, TIME_STATS_SAMPLES) / 1000.0;
						val = mkf_flt(FN_AVG, secs);
						break;
					case ST_I_PX_TTIME:
						secs = (double)swrate_avg(sv->counters.t_time, TIME_STATS_SAMPLES) / 1000.0;
						val = mkf_flt(FN_AVG, secs);
						break;
					case ST_I_PX_QT_MAX:
						secs = (double)sv->counters.qtime_max / 1000.0;
						val = mkf_flt(FN_MAX, secs);
						break;
					case ST_I_PX_CT_MAX:
						secs = (double)sv->counters.ctime_max / 1000.0;
						val = mkf_flt(FN_MAX, secs);
						break;
					case ST_I_PX_RT_MAX:
						secs = (double)sv->counters.dtime_max / 1000.0;
						val = mkf_flt(FN_MAX, secs);
						break;
					case ST_I_PX_TT_MAX:
						secs = (double)sv->counters.ttime_max / 1000.0;
						val = mkf_flt(FN_MAX, secs);
						break;
					case ST_I_PX_CHECK_STATUS:
						if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) != CHK_ST_ENABLED)
							goto next_sv;

						for (; ctx->obj_state < HCHK_STATUS_SIZE; ctx->obj_state++) {
							if (get_check_status_result(ctx->obj_state) < CHK_RES_FAILED)
								continue;
							val = mkf_u32(FO_STATUS, sv->check.status == ctx->obj_state);
							check_state = get_check_status_info(ctx->obj_state);
							labels[lb_idx+1].name = ist("state");
							labels[lb_idx+1].value = ist(check_state);
							if (!promex_dump_ts(appctx, prefix, name, desc,
									    promex_st_metrics[ctx->field_num].type,
									    &val, labels, &out, max))
								goto full;
						}
						ctx->obj_state = 0;
						goto next_sv;
					case ST_I_PX_CHECK_CODE:
						if ((sv->check.state & (CHK_ST_ENABLED|CHK_ST_PAUSED)) != CHK_ST_ENABLED)
							goto next_sv;
						val = mkf_u32(FN_OUTPUT, (sv->check.status < HCHK_STATUS_L57DATA) ? 0 : sv->check.code);
						break;
					case ST_I_PX_CHECK_DURATION:
						if (sv->check.status < HCHK_STATUS_CHECKED)
						    goto next_sv;
						secs = (double)sv->check.duration / 1000.0;
						val = mkf_flt(FN_DURATION, secs);
						break;
					case ST_I_PX_REQ_TOT:
						if (px->mode != PR_MODE_HTTP) {
							sv = NULL;
							goto next_px;
						}
						val = stats[ctx->field_num];
						break;
					case ST_I_PX_HRSP_1XX:
					case ST_I_PX_HRSP_2XX:
					case ST_I_PX_HRSP_3XX:
					case ST_I_PX_HRSP_4XX:
					case ST_I_PX_HRSP_5XX:
					case ST_I_PX_HRSP_OTHER:
						if (px->mode != PR_MODE_HTTP) {
							sv = NULL;
							goto next_px;
						}
						if (ctx->field_num != ST_I_PX_HRSP_1XX)
							ctx->flags &= ~PROMEX_FL_METRIC_HDR;
						labels[lb_idx+1].name = ist("code");
						labels[lb_idx+1].value = promex_hrsp_code[ctx->field_num - ST_I_PX_HRSP_1XX];
						val = stats[ctx->field_num];
						break;

					default:
						val = stats[ctx->field_num];
				}

				if (!promex_dump_ts(appctx, prefix, name, desc,
						    promex_st_metrics[ctx->field_num].type,
						    &val, labels, &out, max))
					goto full;
			  next_sv:
				sv = sv->next;
			}

		  next_px:
			px = px->next;
		}
		ctx->flags |= PROMEX_FL_METRIC_HDR;
	}

	/* Skip extra counters */
	if (!(ctx->flags & PROMEX_FL_EXTRA_COUNTERS))
		goto end;

	if (!mod) {
		mod = LIST_NEXT(&stats_module_list[STATS_DOMAIN_PROXY], typeof(mod), list);
		ctx->mod_field_num = 0;
	}

	list_for_each_entry_from(mod, &stats_module_list[STATS_DOMAIN_PROXY], list) {
		void *counters;

		if (!(stats_px_get_cap(mod->domain_flags) & STATS_PX_CAP_SRV))
			continue;

		for (;ctx->mod_field_num < mod->stats_count; ctx->mod_field_num++) {
			name = ist2(mod->stats[ctx->mod_field_num].name, strlen(mod->stats[ctx->mod_field_num].name));
			desc = ist2(mod->stats[ctx->mod_field_num].desc, strlen(mod->stats[ctx->mod_field_num].desc));

			if (promex_filter_metric(appctx, prefix, name))
				continue;

			if (!px)
				px = proxies_list;

			while (px) {
				struct promex_label labels[PROMEX_MAX_LABELS-1] = {};
				struct promex_metric metric;
				int lb_idx = 0;

				labels[lb_idx].name  = ist("proxy");
				labels[lb_idx].value = ist2(px->id, strlen(px->id));
				lb_idx++;

				if ((ctx->flags & PROMEX_FL_DESC_LABELS) && px->desc) {
					labels[lb_idx].name  = ist("desc");
					labels[lb_idx].value = ist(px->desc);
					lb_idx++;
				}


				/* skip the disabled proxies, global frontend and non-networked ones */
				if ((px->flags & PR_FL_DISABLED) || px->uuid <= 0 || !(px->cap & PR_CAP_BE))
					goto next_px2;

				if (!sv)
					sv = px->srv;

				while (sv) {
					labels[lb_idx].name  = ist("server");
					labels[lb_idx].value = ist2(sv->id, strlen(sv->id));

					labels[lb_idx+1].name  = ist("mod");
					labels[lb_idx+1].value = ist2(mod->name, strlen(mod->name));

					if ((ctx->flags & PROMEX_FL_NO_MAINT_SRV) && (sv->cur_admin & SRV_ADMF_MAINT))
						goto next_sv2;


					counters = EXTRA_COUNTERS_GET(sv->extra_counters, mod);
					if (!mod->fill_stats(counters, stats + ctx->field_num, &ctx->mod_field_num))
						return -1;

					val = stats[ctx->field_num + ctx->mod_field_num];
					metric.type = ((val.type == FN_GAUGE) ? PROMEX_MT_GAUGE : PROMEX_MT_COUNTER);

					if (!promex_dump_ts(appctx, prefix, name, desc, metric.type,
							    &val, labels, &out, max))
						goto full;

				  next_sv2:
					sv = sv->next;
				}

			  next_px2:
				px = px->next;
			}
			ctx->flags |= PROMEX_FL_METRIC_HDR;
		}

		ctx->field_num += mod->stats_count;
		ctx->mod_field_num = 0;
	}

	px = NULL;
	sv = NULL;
	mod = NULL;

  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}

	/* Decrement server refcount if it was saved through ctx.p[1]. */
	srv_drop(ctx->p[1]);
	if (sv)
		srv_take(sv);

	/* Save pointers (0=current proxy, 1=current server, 2=current stats module) of the current context */
	ctx->p[0] = px;
	ctx->p[1] = sv;
	ctx->p[2] = mod;
	return ret;
  full:
	ret = 0;
	goto end;
}

/* Dump metrics of module <mod>. It returns 1 on success, 0 if <out> is full and
 * -1 on error. */
static int promex_dump_module_metrics(struct appctx *appctx, struct promex_module *mod,
				      struct ist *out, size_t max)
{
	struct ist prefix = { .ptr = (char[PROMEX_MAX_NAME_LEN]){ 0 }, .len = 0 };
	struct promex_ctx *ctx = appctx->svcctx;
	int ret = 1;

	istcat(&prefix, ist("haproxy_"), PROMEX_MAX_NAME_LEN);
	istcat(&prefix, mod->name, PROMEX_MAX_NAME_LEN);
	istcat(&prefix, ist("_"), PROMEX_MAX_NAME_LEN);

	if (!ctx->p[1] && mod->start_metrics_dump) {
		ctx->p[1] = mod->start_metrics_dump();
		if (!ctx->p[1])
			goto end;
	}

	for (; ctx->mod_field_num < mod->nb_metrics; ctx->mod_field_num++) {
		struct promex_metric metric;
		struct ist desc;


		ret = mod->metric_info(ctx->mod_field_num, &metric, &desc);
		if (!ret)
			continue;
		if (ret < 0)
			goto error;

		if (promex_filter_metric(appctx, prefix, metric.n))
			continue;

		if (!ctx->p[2])
			ctx->p[2] = mod->start_ts(ctx->p[1], ctx->mod_field_num);

		while (ctx->p[2]) {
			struct promex_label labels[PROMEX_MAX_LABELS - 1] = {};
			struct field val;

			ret = mod->fill_ts(ctx->p[1], ctx->p[2], ctx->mod_field_num, labels, &val);
			if (!ret)
				continue;
			if (ret < 0)
				goto error;

			if (!promex_dump_ts(appctx, prefix, metric.n, desc, metric.type,
					    &val, labels, out, max))
				goto full;

		next:
			ctx->p[2] = mod->next_ts(ctx->p[1], ctx->p[2], ctx->mod_field_num);
		}
		ctx->flags |= PROMEX_FL_METRIC_HDR;
	}
	ret = 1;

  end:
	if (ctx->p[1] && mod->stop_metrics_dump)
		mod->stop_metrics_dump(ctx->p[1]);
	ctx->p[1] = NULL;
	ctx->p[2] = NULL;
	return ret;

  full:
	return 0;
  error:
	ret = -1;
	goto end;

}

/* Dump metrics of referenced modules. It returns 1 on success, 0 if <htx> is
 * full and -1 in case of any error. */
static int promex_dump_ref_modules_metrics(struct appctx *appctx, struct htx *htx)
{
	struct promex_ctx *ctx = appctx->svcctx;
	struct promex_module_ref *ref = ctx->p[0];
	struct channel *chn = sc_ic(appctx_sc(appctx));
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	int ret = 1;

	if (!ref) {
		ref = LIST_NEXT(&ctx->modules, typeof(ref), list);
		ctx->mod_field_num = 0;
	}

	list_for_each_entry_from(ref, &ctx->modules, list) {
		ret = promex_dump_module_metrics(appctx, ref->mod, &out, max);
		if (ret <= 0) {
			if (ret == -1)
				return -1;
			goto full;
		}
		ctx->mod_field_num = 0;
	}

	ref = NULL;

  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}
	ctx->p[0] = ref;
	return ret;
  full:
	ret = 0;
	goto end;
}

/* Dump metrics of all registered modules. It returns 1 on success, 0 if <htx> is
 * full and -1 in case of any error. */
static int promex_dump_all_modules_metrics(struct appctx *appctx, struct htx *htx)
{
	struct promex_ctx *ctx = appctx->svcctx;
	struct promex_module *mod = ctx->p[0];
	struct channel *chn = sc_ic(appctx_sc(appctx));
	struct ist out = ist2(trash.area, 0);
	size_t max = htx_get_max_blksz(htx, channel_htx_recv_max(chn, htx));
	int ret = 1;

	if (!mod) {
		mod = LIST_NEXT(&promex_module_list, typeof(mod), list);
		ctx->mod_field_num = 0;
	}

	list_for_each_entry_from(mod, &promex_module_list, list) {
		ret = promex_dump_module_metrics(appctx, mod, &out, max);
		if (ret <= 0) {
			if (ret == -1)
				return -1;
			goto full;
		}
		ctx->mod_field_num = 0;
	}

	mod = NULL;

  end:
	if (out.len) {
		if (!htx_add_data_atonce(htx, out))
			return -1; /* Unexpected and unrecoverable error */
		channel_add_input(chn, out.len);
	}
	ctx->p[0] = mod;
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
static int promex_dump_metrics(struct appctx *appctx, struct stconn *sc, struct htx *htx)
{
	struct promex_ctx *ctx = appctx->svcctx;
	int ret;

	switch (appctx->st1) {
		case PROMEX_DUMPER_INIT:
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_INFO_METRIC);
			ctx->obj_state = 0;
			ctx->field_num = ST_I_INF_NAME;
			appctx->st1 = PROMEX_DUMPER_GLOBAL;
			__fallthrough;

		case PROMEX_DUMPER_GLOBAL:
			if (ctx->flags & PROMEX_FL_SCOPE_GLOBAL) {
				ret = promex_dump_global_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->flags &= ~PROMEX_FL_INFO_METRIC;
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_FRONT_METRIC);
			ctx->obj_state = 0;
			ctx->field_num = ST_I_PX_PXNAME;
			ctx->mod_field_num = 0;
			appctx->st1 = PROMEX_DUMPER_FRONT;
			__fallthrough;

		case PROMEX_DUMPER_FRONT:
			if (ctx->flags & PROMEX_FL_SCOPE_FRONT) {
				ret = promex_dump_front_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->flags &= ~PROMEX_FL_FRONT_METRIC;
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_LI_METRIC);
			ctx->obj_state = 0;
			ctx->field_num = ST_I_PX_PXNAME;
			ctx->mod_field_num = 0;
			appctx->st1 = PROMEX_DUMPER_LI;
			__fallthrough;

		case PROMEX_DUMPER_LI:
			if (ctx->flags & PROMEX_FL_SCOPE_LI) {
				ret = promex_dump_listener_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->flags &= ~PROMEX_FL_LI_METRIC;
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_BACK_METRIC);
			ctx->obj_state = 0;
			ctx->field_num = ST_I_PX_PXNAME;
			ctx->mod_field_num = 0;
			appctx->st1 = PROMEX_DUMPER_BACK;
			__fallthrough;

		case PROMEX_DUMPER_BACK:
			if (ctx->flags & PROMEX_FL_SCOPE_BACK) {
				ret = promex_dump_back_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->flags &= ~PROMEX_FL_BACK_METRIC;
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_SRV_METRIC);
			ctx->obj_state = 0;
			ctx->field_num = ST_I_PX_PXNAME;
			ctx->mod_field_num = 0;
			appctx->st1 = PROMEX_DUMPER_SRV;
			__fallthrough;

		case PROMEX_DUMPER_SRV:
			if (ctx->flags & PROMEX_FL_SCOPE_SERVER) {
				ret = promex_dump_srv_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->flags &= ~(PROMEX_FL_METRIC_HDR|PROMEX_FL_SRV_METRIC);
			ctx->flags |= (PROMEX_FL_METRIC_HDR|PROMEX_FL_MODULE_METRIC);
			ctx->field_num = 0;
			ctx->mod_field_num = 0;
			appctx->st1 = PROMEX_DUMPER_MODULES;
			__fallthrough;

		case PROMEX_DUMPER_MODULES:
			if (ctx->flags & PROMEX_FL_SCOPE_MODULE) {
				if (LIST_ISEMPTY(&ctx->modules))
					ret = promex_dump_all_modules_metrics(appctx, htx);
				else
					ret = promex_dump_ref_modules_metrics(appctx, htx);
				if (ret <= 0) {
					if (ret == -1)
						goto error;
					goto full;
				}
			}

			ctx->flags &= ~(PROMEX_FL_METRIC_HDR|PROMEX_FL_MODULE_METRIC);
			ctx->field_num = 0;
			ctx->mod_field_num = 0;
			appctx->st1 = PROMEX_DUMPER_DONE;
			__fallthrough;

		case PROMEX_DUMPER_DONE:
		default:
			break;
	}

	return 1;

  full:
	sc_need_room(sc, channel_htx_recv_max(sc_ic(appctx_sc(appctx)), htx) + 1);
	return 0;
  error:
	/* unrecoverable error */
	ctx->flags = 0;
	ctx->field_num = 0;
	ctx->mod_field_num = 0;
	appctx->st1 = PROMEX_DUMPER_DONE;
	return -1;
}

/* Parse the query string of request URI to filter the metrics. It returns 1 on
 * success and -1 on error. */
static int promex_parse_uri(struct appctx *appctx, struct stconn *sc)
{
	struct promex_ctx *ctx = appctx->svcctx;
	struct channel *req = sc_oc(sc);
	struct channel *res = sc_ic(sc);
	struct htx *req_htx, *res_htx;
	struct htx_sl *sl;
	char *p, *key, *value;
	const char *end;
	struct buffer *err;
	int default_scopes = PROMEX_FL_SCOPE_ALL;
	int default_metrics_filter = PROMEX_FL_INC_METRIC_BY_DEFAULT;
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
			else if (*value == '*' && *(value+1) == 0)
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
			else {
				struct promex_module *mod;
				struct promex_module_ref *ref;

				list_for_each_entry(mod, &promex_module_list, list) {
					if (strncmp(value, istptr(mod->name), istlen(mod->name)) == 0) {
						ref = pool_alloc(pool_head_promex_mod_ref);
						if (!ref)
							goto internal_error;
						ctx->flags |= PROMEX_FL_SCOPE_MODULE;
						ref->mod = mod;
						LIST_APPEND(&ctx->modules, &ref->list);
						break;
					}
				}
				if (!(ctx->flags & PROMEX_FL_SCOPE_MODULE))
					goto error;
			}
		}
		else if (strcmp(key, "metrics") == 0) {
			struct ist args;

			if (!value)
				goto error;

			for (args = ist(value); istlen(args); args = istadv(istfind(args, ','), 1)) {
				struct eb32_node *node;
				struct promex_metric_filter *flt;
				struct ist m = iststop(args, ',');
				unsigned int hash;
				int exclude = 0;

				if (!istlen(m))
					continue;

				if (*istptr(m) == '-') {
					m = istnext(m);
					if (!istlen(m))
						continue;
					exclude = 1;
				}
				else
					default_metrics_filter &= ~PROMEX_FL_INC_METRIC_BY_DEFAULT;


				hash = XXH32(istptr(m), istlen(m), 0);
				node = eb32_lookup(&ctx->filters, hash);
				if (node) {
					flt = container_of(node, typeof(*flt), node);
					flt->exclude = exclude;
					continue;
				}

				flt = pool_alloc(pool_head_promex_metric_flt);
				if (!flt)
					goto internal_error;
				flt->node.key = hash;
				flt->exclude = exclude;
				eb32_insert(&ctx->filters, &flt->node);
			}
		}
		else if (strcmp(key, "extra-counters") == 0) {
			ctx->flags |= PROMEX_FL_EXTRA_COUNTERS;
		}
		else if (strcmp(key, "no-maint") == 0)
			ctx->flags |= PROMEX_FL_NO_MAINT_SRV;
		else if (strcmp(key, "desc-labels") == 0)
			ctx->flags |= PROMEX_FL_DESC_LABELS;
	}

  end:
	ctx->flags |= (default_scopes | default_metrics_filter);
	return 1;

  error:
	err = &http_err_chunks[HTTP_ERR_400];
	channel_erase(res);
	res->buf.data = b_data(err);
	memcpy(res->buf.area, b_head(err), b_data(err));
	res_htx = htx_from_buf(&res->buf);
	channel_add_input(res, res_htx->data);
	return -1;

  internal_error:
	err = &http_err_chunks[HTTP_ERR_400];
	channel_erase(res);
	res->buf.data = b_data(err);
	memcpy(res->buf.area, b_head(err), b_data(err));
	res_htx = htx_from_buf(&res->buf);
	channel_add_input(res, res_htx->data);
	return -1;
}

/* Send HTTP headers of the response. It returns 1 on success and 0 if <htx> is
 * full. */
static int promex_send_headers(struct appctx *appctx, struct stconn *sc, struct htx *htx)
{
	struct channel *chn = sc_ic(sc);
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
	sc_need_room(sc, 0);
	return 0;
}

/* The function returns 1 if the initialisation is complete, 0 if
 * an errors occurs and -1 if more data are required for initializing
 * the applet.
 */
static int promex_appctx_init(struct appctx *appctx)
{
	struct promex_ctx *ctx;

	applet_reserve_svcctx(appctx, sizeof(struct promex_ctx));
	ctx = appctx->svcctx;
	memset(ctx->p, 0, sizeof(ctx->p));
	LIST_INIT(&ctx->modules);
	ctx->filters = EB_ROOT;
	appctx->st0 = PROMEX_ST_INIT;
	return 0;
}


/* Callback function that releases a promex applet. This happens when the
 * connection with the agent is closed. */
static void promex_appctx_release(struct appctx *appctx)
{
	struct promex_ctx *ctx = appctx->svcctx;
	struct promex_module_ref *ref, *back;
	struct promex_metric_filter *flt;
        struct eb32_node *node, *next;

	if (appctx->st1 == PROMEX_DUMPER_SRV) {
		struct server *srv = objt_server(ctx->p[1]);
		srv_drop(srv);
	}

	list_for_each_entry_safe(ref, back, &ctx->modules, list) {
		LIST_DELETE(&ref->list);
		pool_free(pool_head_promex_mod_ref, ref);
	}

	node = eb32_first(&ctx->filters);
	while (node) {
		next = eb32_next(node);
		eb32_delete(node);
		flt = container_of(node, typeof(*flt), node);
		pool_free(pool_head_promex_metric_flt, flt);
		node = next;
	}
}

/* The main I/O handler for the promex applet. */
static void promex_appctx_handle_io(struct appctx *appctx)
{
	struct stconn *sc = appctx_sc(appctx);
	struct stream *s = __sc_strm(sc);
	struct channel *req = sc_oc(sc);
	struct channel *res = sc_ic(sc);
	struct htx *req_htx, *res_htx;
	int ret;

	res_htx = htx_from_buf(&res->buf);

	if (unlikely(se_fl_test(appctx->sedesc, (SE_FL_EOS|SE_FL_ERROR|SE_FL_SHR|SE_FL_SHW))))
		goto out;

	/* Check if the input buffer is available. */
	if (!b_size(&res->buf)) {
		sc_need_room(sc, 0);
		goto out;
	}

	switch (appctx->st0) {
		case PROMEX_ST_INIT:
			if (!co_data(req)) {
				applet_need_more_data(appctx);
				goto out;
			}
			ret = promex_parse_uri(appctx, sc);
			if (ret <= 0) {
				if (ret == -1)
					goto error;
				goto out;
			}
			appctx->st0 = PROMEX_ST_HEAD;
			appctx->st1 = PROMEX_DUMPER_INIT;
			__fallthrough;

		case PROMEX_ST_HEAD:
			if (!promex_send_headers(appctx, sc, res_htx))
				goto out;
			appctx->st0 = ((s->txn->meth == HTTP_METH_HEAD) ? PROMEX_ST_DONE : PROMEX_ST_DUMP);
			__fallthrough;

		case PROMEX_ST_DUMP:
			ret = promex_dump_metrics(appctx, sc, res_htx);
			if (ret <= 0) {
				if (ret == -1)
					goto error;
				goto out;
			}
			appctx->st0 = PROMEX_ST_DONE;
			__fallthrough;

		case PROMEX_ST_DONE:
			/* no more data are expected. If the response buffer is
			 * empty, be sure to add something (EOT block in this
			 * case) to have something to send. It is important to
			 * be sure the EOM flags will be handled by the
			 * endpoint.
			 */
			if (htx_is_empty(res_htx)) {
				if (!htx_add_endof(res_htx, HTX_BLK_EOT)) {
					sc_need_room(sc, sizeof(struct htx_blk) + 1);
					goto out;
				}
				channel_add_input(res, 1);
			}
		        res_htx->flags |= HTX_FL_EOM;
			se_fl_set(appctx->sedesc, SE_FL_EOI);
			appctx->st0 = PROMEX_ST_END;
			__fallthrough;

		case PROMEX_ST_END:
			se_fl_set(appctx->sedesc, SE_FL_EOS);
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
	se_fl_set(appctx->sedesc, SE_FL_ERROR);
	goto out;
}

struct applet promex_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<PROMEX>", /* used for logging */
	.init = promex_appctx_init,
	.release = promex_appctx_release,
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
