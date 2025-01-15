#include <haproxy/stats-proxy.h>

#include <errno.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/backend.h>
#include <haproxy/check.h>
#include <haproxy/chunk.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/obj_type.h>
#include <haproxy/proxy.h>
#include <haproxy/stats.h>
#include <haproxy/stats-html.h>
#include <haproxy/server.h>
#include <haproxy/stconn.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

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
	[ST_I_PX_LASTCHG]       = ME_NEW_BE("lastchg",       FN_AGE,     FF_U32, last_change,            STATS_PX_CAP___BS, "How long ago the last server state changed, in seconds"),
	[ST_I_PX_DOWNTIME]                      = { .name = "downtime",                    .desc = "Total time spent in DOWN state, for server or backend" },
	[ST_I_PX_QLIMIT]                        = { .name = "qlimit",                      .desc = "Limit on the number of connections in queue, for servers only (maxqueue argument)" },
	[ST_I_PX_PID]                           = { .name = "pid",                         .desc = "Relative worker process number (1)" },
	[ST_I_PX_IID]                           = { .name = "iid",                         .desc = "Frontend or Backend numeric identifier ('id' setting)" },
	[ST_I_PX_SID]                           = { .name = "sid",                         .desc = "Server numeric identifier ('id' setting)" },
	[ST_I_PX_THROTTLE]                      = { .name = "throttle",                    .desc = "Throttling ratio applied to a server's maxconn and weight during the slowstart period (0 to 100%)" },
	[ST_I_PX_LBTOT]         = ME_NEW_BE("lbtot",         FN_COUNTER, FF_U64, cum_lbconn,             STATS_PX_CAP_LFBS, "Total number of requests routed by load balancing since the worker process started (ignores queue pop and stickiness)"),
	[ST_I_PX_TRACKED]                       = { .name = "tracked",                     .desc = "Name of the other server this server tracks for its state" },
	[ST_I_PX_TYPE]                          = { .name = "type",                        .desc = "Type of the object (Listener, Frontend, Backend, Server)" },
	[ST_I_PX_RATE]          = ME_NEW_PX("rate",          FN_RATE,    FF_U32, sess_per_sec,           STATS_PX_CAP__FBS, "Total number of sessions processed by this object over the last second (sessions for listeners/frontends, requests for backends/servers)"),
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
	[ST_I_PX_HANAFAIL]      = ME_NEW_BE("hanafail",      FN_COUNTER, FF_U64, failed_hana,            STATS_PX_CAP____S, "Total number of failed checks caused by an 'on-error' directive after an 'observe' condition matched"),
	[ST_I_PX_REQ_RATE]      = ME_NEW_FE("req_rate",      FN_RATE,    FF_U32, req_per_sec,            STATS_PX_CAP__F__, "Number of HTTP requests processed over the last second on this object"),
	[ST_I_PX_REQ_RATE_MAX]                  = { .name = "req_rate_max",                .desc = "Highest value of http requests observed since the worker process started" },
	/* Note: ST_I_PX_REQ_TOT is also diplayed on frontend but does not uses a raw counter value, see me_generate_field() for details. */
	[ST_I_PX_REQ_TOT]       = ME_NEW_BE("req_tot",       FN_COUNTER, FF_U64, p.http.cum_req,         STATS_PX_CAP___BS, "Total number of HTTP requests processed by this object since the worker process started"),
	[ST_I_PX_CLI_ABRT]      = ME_NEW_BE("cli_abrt",      FN_COUNTER, FF_U64, cli_aborts,             STATS_PX_CAP_LFBS, "Total number of requests or connections aborted by the client since the worker process started"),
	[ST_I_PX_SRV_ABRT]      = ME_NEW_BE("srv_abrt",      FN_COUNTER, FF_U64, srv_aborts,             STATS_PX_CAP_LFBS, "Total number of requests or connections aborted by the server since the worker process started"),
	[ST_I_PX_COMP_IN]       = ME_NEW_PX("comp_in",       FN_COUNTER, FF_U64, comp_in[COMP_DIR_RES],  STATS_PX_CAP__FB_, "Total number of bytes submitted to the HTTP compressor for this object since the worker process started"),
	[ST_I_PX_COMP_OUT]      = ME_NEW_PX("comp_out",      FN_COUNTER, FF_U64, comp_out[COMP_DIR_RES], STATS_PX_CAP__FB_, "Total number of bytes emitted by the HTTP compressor for this object since the worker process started"),
	[ST_I_PX_COMP_BYP]      = ME_NEW_PX("comp_byp",      FN_COUNTER, FF_U64, comp_byp[COMP_DIR_RES], STATS_PX_CAP__FB_, "Total number of bytes that bypassed HTTP compression for this object since the worker process started (CPU/memory/bandwidth limitation)"),
	[ST_I_PX_COMP_RSP]      = ME_NEW_PX("comp_rsp",      FN_COUNTER, FF_U64, p.http.comp_rsp,        STATS_PX_CAP__FB_, "Total number of HTTP responses that were compressed for this object since the worker process started"),
	[ST_I_PX_LASTSESS]      = ME_NEW_BE("lastsess",      FN_AGE,     FF_S32, last_sess,              STATS_PX_CAP___BS, "How long ago some traffic was seen on this object on this worker process, in seconds"),
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
	[ST_I_PX_MODE]                          = { .name = "mode",                        .desc = "'mode' setting (tcp/http/health/cli/spop)" },
	[ST_I_PX_ALGO]                          = { .name = "algo",                        .desc = "Backend's load balancing algorithm, shown only if show-legends is set, or at levels oper/admin for the CLI" },
	[ST_I_PX_CONN_RATE]     = ME_NEW_FE("conn_rate",     FN_RATE,    FF_U32, conn_per_sec,           STATS_PX_CAP__F__, "Number of new connections accepted over the last second on the frontend for this worker process"),
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
	case ST_I_PX_REQ_TOT:
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

	case ST_I_PX_LASTSESS:
		if (srv)
			return !srv->counters.last_sess;
		else if (px)
			return !px->be_counters.last_sess;
		else
			return 0;

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
	enum field_nature fn;
	struct field value;
	void *counter = NULL;
	int wrong_side = 0;

	/* Only generic stat column must be used as input. */
	BUG_ON(!stcol_is_generic(col));

	fn = stcol_nature(col);

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

	/* TODO Special case needed for ST_I_PX_REQ_TOT. It is defined as a
	 * generic column for backend side. Extra code required to diplay it on
	 * frontend side as an aggregate of values split by HTTP version.
	 */
	if (idx == ST_I_PX_REQ_TOT && cap == STATS_PX_CAP_FE && !stat_file) {
		struct proxy *px = __objt_proxy(objt);
		const size_t nb_reqs =
		  sizeof(px->fe_counters.p.http.cum_req) /
		  sizeof(*px->fe_counters.p.http.cum_req);
		uint64_t total_req = 0;
		int i;

		for (i = 0; i < nb_reqs; i++)
			total_req += px->fe_counters.p.http.cum_req[i];
		return mkf_u64(FN_COUNTER, total_req);
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
		if (!(col->cap & cap))
			return (struct field){ .type = FF_EMPTY };

		if (stcol_hide(idx, objt)) {
			if (fn == FN_AGE)
				return mkf_s32(FN_AGE, -1);
			else
				return (struct field){ .type = FF_EMPTY };
		}
	}

	if (fn == FN_COUNTER) {
		switch (stcol_format(col)) {
		case FF_U64:
			value = mkf_u64(FN_COUNTER, *(uint64_t *)counter);
			break;
		default:
			/* only FF_U64 counters currently use generic metric calculation */
			ABORT_NOW();
		}
	}
	else if (fn == FN_RATE) {
		/* freq-ctr always uses FF_U32 */
		BUG_ON(stcol_format(col) != FF_U32);
		value = mkf_u32(FN_RATE, read_freq_ctr(counter));
	}
	else if (fn == FN_AGE) {
		unsigned long age = *(unsigned long *)counter;
		if (age)
			age = ns_to_sec(now_ns) - age;

		switch (stcol_format(col)) {
		case FF_U32:
			value = mkf_u32(FN_AGE, age);
			break;
		case FF_S32:
			value = mkf_s32(FN_AGE, age);
			break;
		default:
			/* only FF_U32/FF+S32 for age as generic stat column */
			ABORT_NOW();
		}
	}
	else {
		/* No generic column available for other field nature. */
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
			case ST_I_PX_RATE_LIM:
				field = mkf_u32(FO_CONFIG|FN_LIMIT, px->fe_sps_lim);
				break;
			case ST_I_PX_RATE_MAX:
				field = mkf_u32(FN_MAX, px->fe_counters.sps_max);
				break;
			case ST_I_PX_REQ_RATE_MAX:
				field = mkf_u32(FN_MAX, px->fe_counters.p.http.rps_max);
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

		if (ctx->flags & STAT_F_FMT_FILE)
			continue;

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
					case AF_CUST_ABNS:
					case AF_CUST_ABNSZ:
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

		if (ctx->flags & STAT_F_FMT_FILE)
			continue;

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
				field = mkf_u32(0, sv->queueslength);
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
						case AF_CUST_ABNS:
						case AF_CUST_ABNSZ:
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

		if (ctx->flags & STAT_F_FMT_FILE)
			continue;

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
				field = mkf_u32(0, px->queueslength);
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

		if (ctx->flags & STAT_F_FMT_FILE)
			continue;

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
static int stats_dump_proxy_to_buffer(struct stconn *sc, struct buffer *buf,
                                      struct htx *htx, struct proxy *px)
{
	struct appctx *appctx = __sc_appctx(sc);
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;
	struct server *sv, *svs;	/* server and server-state, server-state=server or server->track */
	struct listener *l;
	struct uri_auth *uri = NULL;
	int current_field;

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

		/* for servers ctx.obj2 is set via watcher_attach() */
		watcher_attach(&ctx->srv_watch, px->srv);
		ctx->px_st = STAT_PX_ST_SV;

		__fallthrough;

	case STAT_PX_ST_SV:
		/* obj2 is updated and returned through watcher_next() */
		for (sv = ctx->obj2; sv;
		     sv = watcher_next(&ctx->srv_watch, sv->next)) {

			if (stats_is_full(appctx, buf, htx))
				goto full;

			if (ctx->flags & STAT_F_BOUND) {
				if (!(ctx->type & (1 << STATS_TYPE_SV))) {
					watcher_detach(&ctx->srv_watch);
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
int stats_dump_proxies(struct stconn *sc, struct buffer *buf, struct htx *htx)
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

void proxy_stats_clear_counters(int clrall, struct list *stat_modules)
{
	struct proxy *px;
	struct server *sv;
	struct listener *li;
	struct stats_module *mod;

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

	list_for_each_entry(mod, stat_modules, list) {
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
}
