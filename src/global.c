#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/protocol-t.h>
#include <haproxy/ticks.h>

/* global options */
struct global global = {
	.uid = -1, // not set
	.gid = -1, // not set
	.hard_stop_after = TICK_ETERNITY,
	.close_spread_time = TICK_ETERNITY,
	.close_spread_end = TICK_ETERNITY,
	.numa_cpu_mapping = 1,
	.nbthread = 0,
	.req_count = 0,
	.loggers = LIST_HEAD_INIT(global.loggers),
	.maxzlibmem = DEFAULT_MAXZLIBMEM * 1024U * 1024U,
	.comp_rate_lim = 0,
	.ssl_server_verify = SSL_SERVER_VERIFY_REQUIRED,
	.unix_bind = {
		 .ux = {
			 .uid = -1,
			 .gid = -1,
			 .mode = 0,
		 }
	},
	.tune = {
		.options = GTUNE_LISTENER_MQ_OPT,
		.bufsize = (BUFSIZE + 2*sizeof(void *) - 1) & -(2*sizeof(void *)),
		.bufsize_small = BUFSIZE_SMALL,
		.maxrewrite = MAXREWRITE,
		.reserved_bufs = RESERVED_BUFS,
		.pattern_cache = DEFAULT_PAT_LRU_SIZE,
		.pool_low_ratio  = 20,
		.pool_high_ratio = 25,
		.max_http_hdr = MAX_HTTP_HDR,
#ifdef USE_OPENSSL
		.sslcachesize = SSLCACHESIZE,
#endif
		.comp_maxlevel = 1,
		.glitch_kill_maxidle = 100,
#ifdef DEFAULT_IDLE_TIMER
		.idle_timer = DEFAULT_IDLE_TIMER,
#else
		.idle_timer = 1000, /* 1 second */
#endif
		.nb_stk_ctr = MAX_SESS_STKCTR,
		.default_shards = -2, /* by-group */
	},
#ifdef USE_OPENSSL
#ifdef DEFAULT_MAXSSLCONN
	.maxsslconn = DEFAULT_MAXSSLCONN,
#endif
#endif
	/* by default allow clients which use a privileged port for TCP only */
	.clt_privileged_ports = HA_PROTO_TCP,
	/* others NULL OK */
};

int stopping;	/* non zero means stopping in progress */
