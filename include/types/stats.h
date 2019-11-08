/*
 * include/types/stats.h
 * This file provides structures and types for stats.
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

#ifndef _TYPES_STATS_H
#define _TYPES_STATS_H

/* Flags for applet.ctx.stats.flags */
#define STAT_FMT_HTML   0x00000001      /* dump the stats in HTML format */
#define STAT_FMT_TYPED  0x00000002      /* use the typed output format */
#define STAT_FMT_JSON   0x00000004      /* dump the stats in JSON format */
#define STAT_HIDE_DOWN  0x00000008	/* hide 'down' servers in the stats page */
#define STAT_NO_REFRESH 0x00000010	/* do not automatically refresh the stats page */
#define STAT_ADMIN      0x00000020	/* indicate a stats admin level */
#define STAT_CHUNKED    0x00000040      /* use chunked encoding (HTTP/1.1) */
#define STAT_JSON_SCHM  0x00000080      /* dump the json schema */

#define STAT_HIDEVER    0x00000100      /* conf: do not report the version and reldate */
#define STAT_SHNODE     0x00000200      /* conf: show node name */
#define STAT_SHDESC     0x00000400      /* conf: show description */
#define STAT_SHLGNDS    0x00000800      /* conf: show legends */
#define STAT_SHOW_FDESC 0x00001000      /* show the field descriptions when possible */

#define STAT_BOUND      0x00800000	/* bound statistics to selected proxies/types/services */
#define STAT_STARTED    0x01000000	/* some output has occurred */

#define STAT_FMT_MASK   0x00000007

#define STATS_TYPE_FE  0
#define STATS_TYPE_BE  1
#define STATS_TYPE_SV  2
#define STATS_TYPE_SO  3

/* HTTP stats : applet.st0 */
enum {
	STAT_HTTP_INIT = 0,  /* Initial state */
	STAT_HTTP_HEAD,      /* send headers before dump */
	STAT_HTTP_DUMP,      /* dumping stats */
	STAT_HTTP_POST,      /* waiting post data */
	STAT_HTTP_LAST,      /* sending last chunk of response */
	STAT_HTTP_DONE,      /* dump is finished */
	STAT_HTTP_END,       /* finished */
};

/* status codes available for the stats admin page */
enum {
	STAT_STATUS_INIT = 0,
	STAT_STATUS_DENY,	/* action denied */
	STAT_STATUS_DONE,	/* the action is successful */
	STAT_STATUS_ERRP,	/* an error occurred due to invalid values in parameters */
	STAT_STATUS_EXCD,	/* an error occurred because the buffer couldn't store all data */
	STAT_STATUS_NONE,	/* nothing happened (no action chosen or servers state didn't change) */
	STAT_STATUS_PART,	/* the action is partially successful */
	STAT_STATUS_UNKN,	/* an unknown error occurred, shouldn't happen */
	STAT_STATUS_IVAL,       /* invalid requests (chunked or invalid post) */
	STAT_STATUS_SIZE
};

/* HTML form to limit output scope */
#define STAT_SCOPE_TXT_MAXLEN 20      /* max len for scope substring */
#define STAT_SCOPE_INPUT_NAME "scope" /* pattern form scope name <input> in html form */
#define STAT_SCOPE_PATTERN    "?" STAT_SCOPE_INPUT_NAME "="

/* Actions available for the stats admin forms */
enum {
	ST_ADM_ACTION_NONE = 0,

	/* enable/disable health checks */
	ST_ADM_ACTION_DHLTH,
	ST_ADM_ACTION_EHLTH,

	/* force health check status */
	ST_ADM_ACTION_HRUNN,
	ST_ADM_ACTION_HNOLB,
	ST_ADM_ACTION_HDOWN,

	/* enable/disable agent checks */
	ST_ADM_ACTION_DAGENT,
	ST_ADM_ACTION_EAGENT,

	/* force agent check status */
	ST_ADM_ACTION_ARUNN,
	ST_ADM_ACTION_ADOWN,

	/* set admin state */
	ST_ADM_ACTION_READY,
	ST_ADM_ACTION_DRAIN,
	ST_ADM_ACTION_MAINT,
	ST_ADM_ACTION_SHUTDOWN,
	/* these are the ancient actions, still available for compatibility */
	ST_ADM_ACTION_DISABLE,
	ST_ADM_ACTION_ENABLE,
	ST_ADM_ACTION_STOP,
	ST_ADM_ACTION_START,
};


/* data transmission states for the stats responses */
enum {
	STAT_ST_INIT = 0,
	STAT_ST_HEAD,
	STAT_ST_INFO,
	STAT_ST_LIST,
	STAT_ST_END,
	STAT_ST_FIN,
};

/* data transmission states for the stats responses inside a proxy */
enum {
	STAT_PX_ST_INIT = 0,
	STAT_PX_ST_TH,
	STAT_PX_ST_FE,
	STAT_PX_ST_LI,
	STAT_PX_ST_SV,
	STAT_PX_ST_BE,
	STAT_PX_ST_END,
	STAT_PX_ST_FIN,
};

/* This level of detail is needed to let the stats consumer know how to
 * aggregate them (eg: between processes or cluster nodes). Only a few
 * combinations are actually in use, though the mechanism tends to make
 * this easy to extend to future uses.
 *
 * Each reported stats element is typed based on 4 dimensions :
 *  - the field format : it indicates the validity range of the reported value,
 *    its limits and how to parse it. 6 types are currently supported :
 *    empty, signed 32-bit integer, unsigned 32-bit integer, signed 64-bit
 *    integer, unsigned 64-bit integer, string
 *
 *  - the field origin : how was the value retrieved and what it depends on.
 *    5 origins are currently defined : product (eg: haproxy version or
 *    release date), configuration (eg: a configured limit), key (identifier
 *    used to group values at a certain level), metric (a measure of something),
 *    status (something discrete which by definition cannot be averaged nor
 *    aggregated, such as "listening" versus "full").
 *
 *  - the field nature : what does the data represent, implying how to aggregate
 *    it. At least 9 different natures are expected : counter (an increasing
 *    positive counter that may wrap when its type is overflown such as a byte
 *    counter), gauge (a measure at any instant that may vary, such as a
 *    concurrent connection count), a limit (eg: maximum acceptable concurrent
 *    connections), a minimum (eg: minimum free memory over a period), a
 *    maximum (eg: highest queue length over a period), an event rate (eg:
 *    incoming connections per second), a duration that is often aggregated by
 *    taking the max (eg: service uptime), an age that generally reports the
 *    last time an event appeared and which generally is aggregated by taking
 *    the most recent event hence the smallest one, the time which reports a
 *    discrete instant and cannot obviously be averaged either, a name which
 *    will generally be the name of an entity (such as a server name or cookie
 *    name), an output which is mostly used for various unsafe strings that are
 *    retrieved (eg: last check output, product name, description, etc), and an
 *    average which indicates that the value is relative and meant to be averaged
 *    between all nodes (eg: response time, throttling, etc).
 *
 *  - the field scope : if the value is shared with other elements, which ones
 *    are expected to report the same value. The first scope with the least
 *    share is the process (most common one) where all data are only relevant
 *    to the process being consulted. The next one is the service, which is
 *    valid for all processes launched together (eg: shared SSL cache usage
 *    among processes). The next one is the system (such as the OS version)
 *    and which will report the same information for all instances running on
 *    the same node. The next one is the cluster, which indicates that the
 *    information are shared with other nodes being part of a same cluster.
 *    Stick-tables may carry such cluster-wide information. Larger scopes may
 *    be added in the future such as datacenter, country, continent, planet,
 *    galaxy, universe, etc.
 *
 * All these information will be encoded in the field as a bit field so that
 * it is easy to pass composite values by simply ORing elements above, and
 * to ease the definition of a few field types for the most common field
 * combinations.
 *
 * The enums try to be arranged so that most likely characteristics are
 * assigned the value zero, making it easier to add new fields.
 *
 * Field format has precedence over the other parts of the type. Please avoid
 * declaring extra formats unless absolutely needed. The first one, FF_EMPTY,
 * must absolutely have value zero so that it is what is returned after a
 * memset(0). Furthermore, the producer is responsible for ensuring that when
 * this format is set, all other bits of the type as well as the values in the
 * union only contain zeroes. This makes it easier for the consumer to use the
 * values as the expected type.
 */

enum field_format {
	FF_EMPTY    = 0x00000000,
	FF_S32      = 0x00000001,
	FF_U32      = 0x00000002,
	FF_S64      = 0x00000003,
	FF_U64      = 0x00000004,
	FF_STR      = 0x00000005,
	FF_FLT      = 0x00000006,
	FF_MASK     = 0x000000FF,
};

enum field_origin {
	FO_METRIC   = 0x00000000,
	FO_STATUS   = 0x00000100,
	FO_KEY      = 0x00000200,
	FO_CONFIG   = 0x00000300,
	FO_PRODUCT  = 0x00000400,
	FO_MASK     = 0x0000FF00,
};

enum field_nature {
	FN_GAUGE    = 0x00000000,
	FN_LIMIT    = 0x00010000,
	FN_MIN      = 0x00020000,
	FN_MAX      = 0x00030000,
	FN_RATE     = 0x00040000,
	FN_COUNTER  = 0x00050000,
	FN_DURATION = 0x00060000,
	FN_AGE      = 0x00070000,
	FN_TIME     = 0x00080000,
	FN_NAME     = 0x00090000,
	FN_OUTPUT   = 0x000A0000,
	FN_AVG      = 0x000B0000,
	FN_MASK     = 0x00FF0000,
};

enum field_scope {
	FS_PROCESS  = 0x00000000,
	FS_SERVICE  = 0x01000000,
	FS_SYSTEM   = 0x02000000,
	FS_CLUSTER  = 0x03000000,
	FS_MASK     = 0xFF000000,
};

/* Please consider updating stats_dump_fields_*(),
 * stats_dump_.*_info_fields() and stats_*_schema()
 * when modifying struct field or related enums.
 */
struct field {
	uint32_t type;
	union {
		int32_t     s32; /* FF_S32 */
		uint32_t    u32; /* FF_U32 */
		int64_t     s64; /* FF_S64 */
		uint64_t    u64; /* FF_U64 */
		double      flt; /* FF_FLT */
		const char *str; /* FF_STR */
	} u;
};

/* Show Info fields for CLI output. For any field added here, please add the text
 * representation in the info_field_names array below. Please only append at the end,
 * before the INF_TOTAL_FIELDS entry, and never insert anything in the middle
 * nor at the beginning.
 */
enum info_field {
	INF_NAME,
	INF_VERSION,
	INF_RELEASE_DATE,
	INF_NBTHREAD,
	INF_NBPROC,
	INF_PROCESS_NUM,
	INF_PID,
	INF_UPTIME,
	INF_UPTIME_SEC,
	INF_MEMMAX_MB,
	INF_POOL_ALLOC_MB,
	INF_POOL_USED_MB,
	INF_POOL_FAILED,
	INF_ULIMIT_N,
	INF_MAXSOCK,
	INF_MAXCONN,
	INF_HARD_MAXCONN,
	INF_CURR_CONN,
	INF_CUM_CONN,
	INF_CUM_REQ,
	INF_MAX_SSL_CONNS,
	INF_CURR_SSL_CONNS,
	INF_CUM_SSL_CONNS,
	INF_MAXPIPES,
	INF_PIPES_USED,
	INF_PIPES_FREE,
	INF_CONN_RATE,
	INF_CONN_RATE_LIMIT,
	INF_MAX_CONN_RATE,
	INF_SESS_RATE,
	INF_SESS_RATE_LIMIT,
	INF_MAX_SESS_RATE,
	INF_SSL_RATE,
	INF_SSL_RATE_LIMIT,
	INF_MAX_SSL_RATE,
	INF_SSL_FRONTEND_KEY_RATE,
	INF_SSL_FRONTEND_MAX_KEY_RATE,
	INF_SSL_FRONTEND_SESSION_REUSE_PCT,
	INF_SSL_BACKEND_KEY_RATE,
	INF_SSL_BACKEND_MAX_KEY_RATE,
	INF_SSL_CACHE_LOOKUPS,
	INF_SSL_CACHE_MISSES,
	INF_COMPRESS_BPS_IN,
	INF_COMPRESS_BPS_OUT,
	INF_COMPRESS_BPS_RATE_LIM,
	INF_ZLIB_MEM_USAGE,
	INF_MAX_ZLIB_MEM_USAGE,
	INF_TASKS,
	INF_RUN_QUEUE,
	INF_IDLE_PCT,
	INF_NODE,
	INF_DESCRIPTION,
	INF_STOPPING,
	INF_JOBS,
	INF_UNSTOPPABLE_JOBS,
	INF_LISTENERS,
	INF_ACTIVE_PEERS,
	INF_CONNECTED_PEERS,
	INF_DROPPED_LOGS,
	INF_BUSY_POLLING,
	INF_FAILED_RESOLUTIONS,
	INF_TOTAL_BYTES_OUT,
	INF_BYTES_OUT_RATE,
	INF_DEBUG_COMMANDS_ISSUED,

	/* must always be the last one */
	INF_TOTAL_FIELDS
};


/* Stats fields for CSV output. For any field added here, please add the text
 * representation in the stat_field_names array below. Please only append at the end,
 * before the ST_F_TOTAL_FIELDS entry, and never insert anything in the middle
 * nor at the beginning.
 */
enum stat_field {
	ST_F_PXNAME,
	ST_F_SVNAME,
	ST_F_QCUR,
	ST_F_QMAX,
	ST_F_SCUR,
	ST_F_SMAX,
	ST_F_SLIM,
	ST_F_STOT,
	ST_F_BIN ,
	ST_F_BOUT,
	ST_F_DREQ,
	ST_F_DRESP,
	ST_F_EREQ,
	ST_F_ECON,
	ST_F_ERESP,
	ST_F_WRETR,
	ST_F_WREDIS,
	ST_F_STATUS,
	ST_F_WEIGHT,
	ST_F_ACT,
	ST_F_BCK,
	ST_F_CHKFAIL,
	ST_F_CHKDOWN,
	ST_F_LASTCHG,
	ST_F_DOWNTIME,
	ST_F_QLIMIT,
	ST_F_PID,
	ST_F_IID,
	ST_F_SID,
	ST_F_THROTTLE,
	ST_F_LBTOT,
	ST_F_TRACKED,
	ST_F_TYPE,
	ST_F_RATE,
	ST_F_RATE_LIM,
	ST_F_RATE_MAX,
	ST_F_CHECK_STATUS,
	ST_F_CHECK_CODE,
	ST_F_CHECK_DURATION,
	ST_F_HRSP_1XX,
	ST_F_HRSP_2XX,
	ST_F_HRSP_3XX,
	ST_F_HRSP_4XX,
	ST_F_HRSP_5XX,
	ST_F_HRSP_OTHER,
	ST_F_HANAFAIL,
	ST_F_REQ_RATE,
	ST_F_REQ_RATE_MAX,
	ST_F_REQ_TOT,
	ST_F_CLI_ABRT,
	ST_F_SRV_ABRT,
	ST_F_COMP_IN,
	ST_F_COMP_OUT,
	ST_F_COMP_BYP,
	ST_F_COMP_RSP,
	ST_F_LASTSESS,
	ST_F_LAST_CHK,
	ST_F_LAST_AGT,
	ST_F_QTIME,
	ST_F_CTIME,
	ST_F_RTIME,
	ST_F_TTIME,
	ST_F_AGENT_STATUS,
	ST_F_AGENT_CODE,
	ST_F_AGENT_DURATION,
	ST_F_CHECK_DESC,
	ST_F_AGENT_DESC,
	ST_F_CHECK_RISE,
	ST_F_CHECK_FALL,
	ST_F_CHECK_HEALTH,
	ST_F_AGENT_RISE,
	ST_F_AGENT_FALL,
	ST_F_AGENT_HEALTH,
	ST_F_ADDR,
	ST_F_COOKIE,
	ST_F_MODE,
	ST_F_ALGO,
	ST_F_CONN_RATE,
	ST_F_CONN_RATE_MAX,
	ST_F_CONN_TOT,
	ST_F_INTERCEPTED,
	ST_F_DCON,
	ST_F_DSES,
	ST_F_WREW,
	ST_F_CONNECT,
	ST_F_REUSE,
	ST_F_CACHE_LOOKUPS,
	ST_F_CACHE_HITS,
	ST_F_SRV_ICUR,
	ST_F_SRV_ILIM,
	ST_F_QT_MAX,
	ST_F_CT_MAX,
	ST_F_RT_MAX,
	ST_F_TT_MAX,

	/* must always be the last one */
	ST_F_TOTAL_FIELDS
};


#endif /* _TYPES_STATS_H */
