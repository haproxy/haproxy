/*
 * General logging functions.
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/uio.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/cfgparse.h>
#include <haproxy/clock.h>
#include <haproxy/fd.h>
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/http_ana.h>
#include <haproxy/listener.h>
#include <haproxy/lb_chash.h>
#include <haproxy/lb_fwrr.h>
#include <haproxy/lb_map.h>
#include <haproxy/lb_ss.h>
#include <haproxy/log.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/sink.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/action.h>
#include <haproxy/time.h>
#include <haproxy/hash.h>
#include <haproxy/tools.h>
#include <haproxy/vecpair.h>

/* global recv logs counter */
int cum_log_messages;

/* log forward proxy list */
struct proxy *cfg_log_forward;

struct log_fmt_st {
	char *name;
};

static const struct log_fmt_st log_formats[LOG_FORMATS] = {
	[LOG_FORMAT_LOCAL] = {
		.name = "local",
	},
	[LOG_FORMAT_RFC3164] = {
		.name = "rfc3164",
	},
	[LOG_FORMAT_RFC5424] = {
		.name = "rfc5424",
	},
	[LOG_FORMAT_PRIO] = {
		.name = "priority",
	},
	[LOG_FORMAT_SHORT] = {
		.name = "short",
	},
	[LOG_FORMAT_TIMED] = {
		.name = "timed",
	},
	[LOG_FORMAT_ISO] = {
		.name = "iso",
	},
	[LOG_FORMAT_RAW] = {
		.name = "raw",
	},
};

/* list of extra log origins */
static struct list log_origins = LIST_HEAD_INIT(log_origins);
/* tree of extra log origins (lookup by id) */
static struct eb_root log_origins_per_id = EB_ROOT_UNIQUE;

/* get human readable representation for log_orig enum members */
const char *log_orig_to_str(enum log_orig_id orig)
{
	switch (orig) {
		case LOG_ORIG_SESS_ERROR:
			return "sess_error";
		case LOG_ORIG_SESS_KILL:
			return "sess_killed";
		case LOG_ORIG_TXN_ACCEPT:
			return "txn_accept";
		case LOG_ORIG_TXN_REQUEST:
			return "txn_request";
		case LOG_ORIG_TXN_CONNECT:
			return "txn_connect";
		case LOG_ORIG_TXN_RESPONSE:
			return "txn_response";
		case LOG_ORIG_TXN_CLOSE:
			return "txn_close";
		default:
		{
			/* catchall for extra log origins */
			struct log_origin_node *origin;

			/* lookup raw origin id */
			origin = container_of_safe(eb32_lookup(&log_origins_per_id, orig),
			                           struct log_origin_node, tree);
			if (origin)
				return origin->name;
			break;
		}
	}
	return "unspec";
}

/* Check if <orig> log origin is set for logging on <px>
 *
 * It is assumed that the caller already checked that log-steps were
 * enabled on the proxy (do_log special value LW_LOGSTEPS)
 *
 * Returns 1 for true and 0 for false
 */
int log_orig_proxy(enum log_orig_id orig, struct proxy *px)
{
	if (eb_is_empty(&px->conf.log_steps)) {
		/* empty tree means all log steps are enabled, thus
		 * all log origins are considered
		 */
		return 1;
	}
	/* selectively check if the current log origin is referenced in
	 * proxy log-steps
	 */
	return !!eb32_lookup(&px->conf.log_steps, orig);
}

/*
 * This map is used with all the FD_* macros to check whether a particular bit
 * is set or not. Each bit represents an ASCII code. ha_bit_set() sets those
 * bytes which should be escaped. When ha_bit_test() returns non-zero, it means
 * that the byte should be escaped. Be careful to always pass bytes from 0 to
 * 255 exclusively to the macros.
 */
long no_escape_map[(256/8) / sizeof(long)];
long rfc5424_escape_map[(256/8) / sizeof(long)];
long json_escape_map[(256/8) / sizeof(long)];
long hdr_encode_map[(256/8) / sizeof(long)];
long url_encode_map[(256/8) / sizeof(long)];
long http_encode_map[(256/8) / sizeof(long)];


const char *log_facilities[NB_LOG_FACILITIES] = {
	"kern", "user", "mail", "daemon",
	"auth", "syslog", "lpr", "news",
	"uucp", "cron", "auth2", "ftp",
	"ntp", "audit", "alert", "cron2",
	"local0", "local1", "local2", "local3",
	"local4", "local5", "local6", "local7"
};

const char *log_levels[NB_LOG_LEVELS] = {
	"emerg", "alert", "crit", "err",
	"warning", "notice", "info", "debug"
};

const char sess_term_cond[16] = "-LcCsSPRIDKUIIII"; /* normal, Local, CliTo, CliErr, SrvTo, SrvErr, PxErr, Resource, Internal, Down, Killed, Up, -- */
const char sess_fin_state[8]  = "-RCHDLQT";	/* cliRequest, srvConnect, srvHeader, Data, Last, Queue, Tarpit */
const struct buffer empty = { };


int prepare_addrsource(struct logformat_node *node, struct proxy *curproxy);

/* logformat alias types (internal use) */
enum logformat_alias_type {
	LOG_FMT_GLOBAL,
	LOG_FMT_ORIGIN,
	LOG_FMT_CLIENTIP,
	LOG_FMT_CLIENTPORT,
	LOG_FMT_BACKENDIP,
	LOG_FMT_BACKENDPORT,
	LOG_FMT_FRONTENDIP,
	LOG_FMT_FRONTENDPORT,
	LOG_FMT_SERVERPORT,
	LOG_FMT_SERVERIP,
	LOG_FMT_COUNTER,
	LOG_FMT_LOGCNT,
	LOG_FMT_PID,
	LOG_FMT_DATE,
	LOG_FMT_DATEGMT,
	LOG_FMT_DATELOCAL,
	LOG_FMT_TS,
	LOG_FMT_MS,
	LOG_FMT_FRONTEND,
	LOG_FMT_FRONTEND_XPRT,
	LOG_FMT_BACKEND,
	LOG_FMT_SERVER,
	LOG_FMT_BYTES,
	LOG_FMT_BYTES_UP,
	LOG_FMT_Ta,
	LOG_FMT_Th,
	LOG_FMT_Ti,
	LOG_FMT_TQ,
	LOG_FMT_TW,
	LOG_FMT_TC,
	LOG_FMT_Tr,
	LOG_FMT_tr,
	LOG_FMT_trg,
	LOG_FMT_trl,
	LOG_FMT_TR,
	LOG_FMT_TD,
	LOG_FMT_TT,
	LOG_FMT_TU,
	LOG_FMT_STATUS,
	LOG_FMT_CCLIENT,
	LOG_FMT_CSERVER,
	LOG_FMT_TERMSTATE,
	LOG_FMT_TERMSTATE_CK,
	LOG_FMT_ACTCONN,
	LOG_FMT_FECONN,
	LOG_FMT_BECONN,
	LOG_FMT_SRVCONN,
	LOG_FMT_RETRIES,
	LOG_FMT_SRVQUEUE,
	LOG_FMT_BCKQUEUE,
	LOG_FMT_HDRREQUEST,
	LOG_FMT_HDRRESPONS,
	LOG_FMT_HDRREQUESTLIST,
	LOG_FMT_HDRRESPONSLIST,
	LOG_FMT_REQ,
	LOG_FMT_HTTP_METHOD,
	LOG_FMT_HTTP_URI,
	LOG_FMT_HTTP_PATH,
	LOG_FMT_HTTP_PATH_ONLY,
	LOG_FMT_HTTP_QUERY,
	LOG_FMT_HTTP_VERSION,
	LOG_FMT_HOSTNAME,
	LOG_FMT_UNIQUEID,
	LOG_FMT_SSL_CIPHER,
	LOG_FMT_SSL_VERSION,
};

/* log_format alias names */
static const struct logformat_alias logformat_aliases[] = {
	{ "o", LOG_FMT_GLOBAL, PR_MODE_TCP, 0, NULL },  /* global option */
	{ "OG", LOG_FMT_ORIGIN, PR_MODE_TCP, 0, NULL }, /* human readable log origin */

	/* please keep these lines sorted ! */
	{ "B", LOG_FMT_BYTES, PR_MODE_TCP, LW_BYTES, NULL },     /* bytes from server to client */
	{ "CC", LOG_FMT_CCLIENT, PR_MODE_HTTP, LW_REQHDR, NULL },  /* client cookie */
	{ "CS", LOG_FMT_CSERVER, PR_MODE_HTTP, LW_RSPHDR, NULL },  /* server cookie */
	{ "H", LOG_FMT_HOSTNAME, PR_MODE_TCP, LW_INIT, NULL }, /* Hostname */
	{ "ID", LOG_FMT_UNIQUEID, PR_MODE_TCP, LW_BYTES, NULL }, /* Unique ID */
	{ "ST", LOG_FMT_STATUS, PR_MODE_TCP, LW_RESP, NULL },   /* status code */
	{ "T", LOG_FMT_DATEGMT, PR_MODE_TCP, LW_INIT, NULL },   /* date GMT */
	{ "Ta", LOG_FMT_Ta, PR_MODE_HTTP, LW_BYTES, NULL },      /* Time active (tr to end) */
	{ "Tc", LOG_FMT_TC, PR_MODE_TCP, LW_BYTES, NULL },       /* Tc */
	{ "Th", LOG_FMT_Th, PR_MODE_TCP, LW_BYTES, NULL },       /* Time handshake */
	{ "Ti", LOG_FMT_Ti, PR_MODE_HTTP, LW_BYTES, NULL },      /* Time idle */
	{ "Tl", LOG_FMT_DATELOCAL, PR_MODE_TCP, LW_INIT, NULL }, /* date local timezone */
	{ "Tq", LOG_FMT_TQ, PR_MODE_HTTP, LW_BYTES, NULL },      /* Tq=Th+Ti+TR */
	{ "Tr", LOG_FMT_Tr, PR_MODE_HTTP, LW_BYTES, NULL },      /* Tr */
	{ "TR", LOG_FMT_TR, PR_MODE_HTTP, LW_BYTES, NULL },      /* Time to receive a valid request */
	{ "Td", LOG_FMT_TD, PR_MODE_TCP, LW_BYTES, NULL },       /* Td = Tt - (Tq + Tw + Tc + Tr) */
	{ "Ts", LOG_FMT_TS, PR_MODE_TCP, LW_INIT, NULL },   /* timestamp GMT */
	{ "Tt", LOG_FMT_TT, PR_MODE_TCP, LW_BYTES, NULL },       /* Tt */
	{ "Tu", LOG_FMT_TU, PR_MODE_TCP, LW_BYTES, NULL },       /* Tu = Tt -Ti */
	{ "Tw", LOG_FMT_TW, PR_MODE_TCP, LW_BYTES, NULL },       /* Tw */
	{ "U", LOG_FMT_BYTES_UP, PR_MODE_TCP, LW_BYTES, NULL },  /* bytes from client to server */
	{ "ac", LOG_FMT_ACTCONN, PR_MODE_TCP, LW_BYTES, NULL },  /* actconn */
	{ "b", LOG_FMT_BACKEND, PR_MODE_TCP, LW_INIT, NULL },   /* backend */
	{ "bc", LOG_FMT_BECONN, PR_MODE_TCP, LW_BYTES, NULL },   /* beconn */
	{ "bi", LOG_FMT_BACKENDIP, PR_MODE_TCP, LW_BCKIP, prepare_addrsource }, /* backend source ip */
	{ "bp", LOG_FMT_BACKENDPORT, PR_MODE_TCP, LW_BCKIP, prepare_addrsource }, /* backend source port */
	{ "bq", LOG_FMT_BCKQUEUE, PR_MODE_TCP, LW_BYTES, NULL }, /* backend_queue */
	{ "ci", LOG_FMT_CLIENTIP, PR_MODE_TCP, LW_CLIP | LW_XPRT, NULL },  /* client ip */
	{ "cp", LOG_FMT_CLIENTPORT, PR_MODE_TCP, LW_CLIP | LW_XPRT, NULL }, /* client port */
	{ "f", LOG_FMT_FRONTEND, PR_MODE_TCP, LW_INIT, NULL },  /* frontend */
	{ "fc", LOG_FMT_FECONN, PR_MODE_TCP, LW_BYTES, NULL },   /* feconn */
	{ "fi", LOG_FMT_FRONTENDIP, PR_MODE_TCP, LW_FRTIP | LW_XPRT, NULL }, /* frontend ip */
	{ "fp", LOG_FMT_FRONTENDPORT, PR_MODE_TCP, LW_FRTIP | LW_XPRT, NULL }, /* frontend port */
	{ "ft", LOG_FMT_FRONTEND_XPRT, PR_MODE_TCP, LW_INIT, NULL },  /* frontend with transport mode */
	{ "hr", LOG_FMT_HDRREQUEST, PR_MODE_TCP, LW_REQHDR, NULL }, /* header request */
	{ "hrl", LOG_FMT_HDRREQUESTLIST, PR_MODE_TCP, LW_REQHDR, NULL }, /* header request list */
	{ "hs", LOG_FMT_HDRRESPONS, PR_MODE_TCP, LW_RSPHDR, NULL },  /* header response */
	{ "hsl", LOG_FMT_HDRRESPONSLIST, PR_MODE_TCP, LW_RSPHDR, NULL },  /* header response list */
	{ "HM", LOG_FMT_HTTP_METHOD, PR_MODE_HTTP, LW_REQ, NULL },  /* HTTP method */
	{ "HP", LOG_FMT_HTTP_PATH, PR_MODE_HTTP, LW_REQ, NULL },  /* HTTP relative or absolute path */
	{ "HPO", LOG_FMT_HTTP_PATH_ONLY, PR_MODE_HTTP, LW_REQ, NULL }, /* HTTP path only (without host nor query string) */
	{ "HQ", LOG_FMT_HTTP_QUERY, PR_MODE_HTTP, LW_REQ, NULL },  /* HTTP query */
	{ "HU", LOG_FMT_HTTP_URI, PR_MODE_HTTP, LW_REQ, NULL },  /* HTTP full URI */
	{ "HV", LOG_FMT_HTTP_VERSION, PR_MODE_HTTP, LW_REQ, NULL },  /* HTTP version */
	{ "lc", LOG_FMT_LOGCNT, PR_MODE_TCP, LW_INIT, NULL }, /* log counter */
	{ "ms", LOG_FMT_MS, PR_MODE_TCP, LW_INIT, NULL },       /* accept date millisecond */
	{ "pid", LOG_FMT_PID, PR_MODE_TCP, LW_INIT, NULL }, /* log pid */
	{ "r", LOG_FMT_REQ, PR_MODE_HTTP, LW_REQ, NULL },  /* request */
	{ "rc", LOG_FMT_RETRIES, PR_MODE_TCP, LW_BYTES, NULL },  /* retries */
	{ "rt", LOG_FMT_COUNTER, PR_MODE_TCP, LW_REQ, NULL }, /* request counter (HTTP or TCP session) */
	{ "s", LOG_FMT_SERVER, PR_MODE_TCP, LW_SVID, NULL },    /* server */
	{ "sc", LOG_FMT_SRVCONN, PR_MODE_TCP, LW_BYTES, NULL },  /* srv_conn */
	{ "si", LOG_FMT_SERVERIP, PR_MODE_TCP, LW_SVIP, NULL }, /* server destination ip */
	{ "sp", LOG_FMT_SERVERPORT, PR_MODE_TCP, LW_SVIP, NULL }, /* server destination port */
	{ "sq", LOG_FMT_SRVQUEUE, PR_MODE_TCP, LW_BYTES, NULL  }, /* srv_queue */
	{ "sslc", LOG_FMT_SSL_CIPHER, PR_MODE_TCP, LW_XPRT, NULL }, /* client-side SSL ciphers */
	{ "sslv", LOG_FMT_SSL_VERSION, PR_MODE_TCP, LW_XPRT, NULL }, /* client-side SSL protocol version */
	{ "t", LOG_FMT_DATE, PR_MODE_TCP, LW_INIT, NULL },      /* date */
	{ "tr", LOG_FMT_tr, PR_MODE_HTTP, LW_INIT, NULL },      /* date of start of request */
	{ "trg",LOG_FMT_trg, PR_MODE_HTTP, LW_INIT, NULL },     /* date of start of request, GMT */
	{ "trl",LOG_FMT_trl, PR_MODE_HTTP, LW_INIT, NULL },     /* date of start of request, local */
	{ "ts", LOG_FMT_TERMSTATE, PR_MODE_TCP, LW_BYTES, NULL },/* termination state */
	{ "tsc", LOG_FMT_TERMSTATE_CK, PR_MODE_TCP, LW_INIT, NULL },/* termination state */
	{ 0, 0, 0, 0, NULL }
};

char httpclient_log_format[] = "%ci:%cp [%tr] %ft -/- %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r";
char default_http_log_format[] = "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"; // default format
char default_https_log_format[] = "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r %[fc_err]/%[ssl_fc_err,hex]/%[ssl_c_err]/%[ssl_c_ca_err]/%[ssl_fc_is_resumed] %[ssl_fc_sni]/%sslv/%sslc";
char clf_http_log_format[] = "%{+Q}o %{-Q}ci - - [%trg] %r %ST %B \"\" \"\" %cp %ms %ft %b %s %TR %Tw %Tc %Tr %Ta %tsc %ac %fc %bc %sc %rc %sq %bq %CC %CS %hrl %hsl";
char default_tcp_log_format[] = "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq";
char clf_tcp_log_format[] = "%{+Q}o %{-Q}ci - - [%T] \"TCP \" 000 %B \"\" \"\" %cp %ms %ft %b %s %Th %Tw %Tc %Tt %U %ts-- %ac %fc %bc %sc %rc %sq %bq \"\" \"\" ";
char *log_format = NULL;

/* Default string used for structured-data part in RFC5424 formatted
 * syslog messages.
 */
char default_rfc5424_sd_log_format[] = "- ";

/* returns true if the input logformat string is one of the default ones declared
 * above
 */
static inline int logformat_str_isdefault(const char *str)
{
	return str == httpclient_log_format ||
	       str == default_http_log_format ||
	       str == default_https_log_format ||
	       str == clf_http_log_format ||
	       str == default_tcp_log_format ||
	       str == clf_tcp_log_format ||
	       str == default_rfc5424_sd_log_format;
}

/* free logformat str if it is not a default (static) one */
static inline void logformat_str_free(char **str)
{
	if (!logformat_str_isdefault(*str))
		ha_free(str);
}

/* duplicate and return logformat str if it is not a default (static)
 * one, else return the original one
 */
static inline char *logformat_str_dup(char *str)
{
	if (logformat_str_isdefault(str))
		return str;
	return strdup(str);
}

/* total number of dropped logs */
unsigned int dropped_logs = 0;

/* This is a global syslog message buffer, common to all outgoing
 * messages. It contains only the data part.
 */
THREAD_LOCAL char *logline = NULL;

/* Same as logline, but to build profile-specific log message
 * (when log profiles are used)
 */
THREAD_LOCAL char *logline_lpf = NULL;


/* A global syslog message buffer, common to all RFC5424 syslog messages.
 * Currently, it is used for generating the structured-data part.
 */
THREAD_LOCAL char *logline_rfc5424 = NULL;

/* Same as logline_rfc5424, but to build profile-specific log message
 * (when log profiles are used)
 */
THREAD_LOCAL char *logline_rfc5424_lpf = NULL;

struct logformat_node_args {
	char *name;
	int mask;
};

struct logformat_node_args node_args_list[] = {
// global
	{ "M", LOG_OPT_MANDATORY },
	{ "Q", LOG_OPT_QUOTE },
	{ "X", LOG_OPT_HEXA },
	{ "E", LOG_OPT_ESC },
	{ "bin", LOG_OPT_BIN },
	{ "json", LOG_OPT_ENCODE_JSON },
	{ "cbor", LOG_OPT_ENCODE_CBOR },
	{  0,  0 }
};

static struct list log_profile_list = LIST_HEAD_INIT(log_profile_list);

/*
 * callback used to configure addr source retrieval
 */
int prepare_addrsource(struct logformat_node *node, struct proxy *curproxy)
{
	if ((curproxy->flags & PR_FL_CHECKED))
		return 0;

	curproxy->options2 |= PR_O2_SRC_ADDR;
	return 1;
}


/*
 * Parse args in a logformat_node. Returns 0 in error
 * case, otherwise, it returns 1.
 */
int parse_logformat_node_args(char *args, struct logformat_node *node, char **err)
{
	int i = 0;
	int end = 0;
	int flags = 0;  // 1 = +  2 = -
	char *sp = NULL; // start pointer

	if (args == NULL) {
		memprintf(err, "internal error: parse_logformat_node_args() expects non null 'args'");
		return 0;
	}

	while (1) {
		if (*args == '\0')
			end = 1;

		if (*args == '+') {
			// add flag
			sp = args + 1;
			flags = 1;
		}
		if (*args == '-') {
			// delete flag
			sp = args + 1;
			flags = 2;
		}

		if (*args == '\0' || *args == ',') {
			*args = '\0';
			for (i = 0; sp && node_args_list[i].name; i++) {
				if (strcmp(sp, node_args_list[i].name) == 0) {
					if (flags == 1) {
						/* Ensure we don't mix encoding types, existing
						 * encoding type prevails over new ones
						 */
						if (node->options & LOG_OPT_ENCODE)
							node->options |= (node_args_list[i].mask & ~LOG_OPT_ENCODE);
						else
							node->options |= node_args_list[i].mask;
						break;
					} else if (flags == 2) {
						node->options &= ~node_args_list[i].mask;
						break;
					}
				}
			}
			sp = NULL;
			if (end)
				break;
		}
		args++;
	}
	return 1;
}

/*
 * Parse an alias '%aliasname' or '%{args}aliasname' in log-format. The caller
 * must pass the args part in the <arg> pointer with its length in <arg_len>,
 * and aliasname with its length in <alias> and <alias_len> respectively. <arg>
 * is ignored when arg_len is 0. Neither <alias> nor <alias_len> may be null.
 * Returns false in error case and err is filled, otherwise returns true.
 */
static int parse_logformat_alias(char *arg, int arg_len, char *name, int name_len, int typecast,
                                 char *alias, int alias_len, struct lf_expr *lf_expr,
                                 int *defoptions, char **err)
{
	int j;
	struct list *list_format= &lf_expr->nodes.list;
	struct logformat_node *node = NULL;

	for (j = 0; logformat_aliases[j].name; j++) { // search a log type
		if (strlen(logformat_aliases[j].name) == alias_len &&
		    strncmp(alias, logformat_aliases[j].name, alias_len) == 0) {
			node = calloc(1, sizeof(*node));
			if (!node) {
				memprintf(err, "out of memory error");
				goto error_free;
			}
			node->type = LOG_FMT_ALIAS;
			node->alias = &logformat_aliases[j];
			node->typecast = typecast;
			if (name && name_len)
				node->name = my_strndup(name, name_len);
			node->options = *defoptions;
			if (arg_len) {
				node->arg = my_strndup(arg, arg_len);
				if (!parse_logformat_node_args(node->arg, node, err))
					goto error_free;
			}
			if (node->alias->type == LOG_FMT_GLOBAL) {
				*defoptions = node->options;
				if (lf_expr->nodes.options == LOG_OPT_NONE)
					lf_expr->nodes.options = node->options;
				else {
					/* global options were previously set and were
					 * overwritten for nodes that appear after the
					 * current one.
					 *
					 * However, for lf_expr->nodes.options we must
					 * keep a track of options common to ALL nodes,
					 * thus we take previous global options into
					 * account to compute the new logformat
					 * expression wide (global) node options.
					 */
					lf_expr->nodes.options &= node->options;
				}
				free_logformat_node(node);
			} else {
				LIST_APPEND(list_format, &node->list);
			}
			return 1;
		}
	}

	j = alias[alias_len];
	alias[alias_len] = 0;
	memprintf(err, "no such format alias '%s'. If you wanted to emit the '%%' character verbatim, you need to use '%%%%'", alias);
	alias[alias_len] = j;

  error_free:
	free_logformat_node(node);
	return 0;
}

/*
 *  push to the logformat linked list
 *
 *  start: start pointer
 *  end: end text pointer
 *  type: string type
 *  lf_expr: destination logformat expr (list of fmt nodes)
 *
 *  LOG_TEXT: copy chars from start to end excluding end.
 *
*/
int add_to_logformat_list(char *start, char *end, int type, struct lf_expr *lf_expr, char **err)
{
	struct list *list_format = &lf_expr->nodes.list;
	char *str;

	if (type == LF_TEXT) { /* type text */
		struct logformat_node *node = calloc(1, sizeof(*node));
		if (!node) {
			memprintf(err, "out of memory error");
			return 0;
		}
		str = calloc(1, end - start + 1);
		strncpy(str, start, end - start);
		str[end - start] = '\0';
		node->arg = str;
		node->type = LOG_FMT_TEXT; // type string
		LIST_APPEND(list_format, &node->list);
	} else if (type == LF_SEPARATOR) {
		struct logformat_node *node = calloc(1, sizeof(*node));
		if (!node) {
			memprintf(err, "out of memory error");
			return 0;
		}
		node->type = LOG_FMT_SEPARATOR;
		LIST_APPEND(list_format, &node->list);
	}
	return 1;
}

/*
 * Parse the sample fetch expression <text> and add a node to <lf_expr> upon
 * success. The curpx->conf.args.ctx must be set by the caller. If an end pointer
 * is passed in <endptr>, it will be updated with the pointer to the first character
 * not part of the sample expression.
 *
 * In error case, the function returns 0, otherwise it returns 1.
 */
static int add_sample_to_logformat_list(char *text, char *name, int name_len, int typecast,
                                        char *arg, int arg_len, struct lf_expr *lf_expr,
                                        struct arg_list *al, int options, int cap, char **err, char **endptr)
{
	char *cmd[2];
	struct list *list_format = &lf_expr->nodes.list;
	struct sample_expr *expr = NULL;
	struct logformat_node *node = NULL;
	int cmd_arg;

	cmd[0] = text;
	cmd[1] = "";
	cmd_arg = 0;

	expr = sample_parse_expr(cmd, &cmd_arg, lf_expr->conf.file, lf_expr->conf.line, err,
				 al, endptr);
	if (!expr) {
		memprintf(err, "failed to parse sample expression <%s> : %s", text, *err);
		goto error_free;
	}

	node = calloc(1, sizeof(*node));
	if (!node) {
		release_sample_expr(expr);
		memprintf(err, "out of memory error");
		goto error_free;
	}
	if (name && name_len)
		node->name = my_strndup(name, name_len);
	node->type = LOG_FMT_EXPR;
	node->typecast = typecast;
	node->expr = expr;
	node->options = options;

	if (arg_len) {
		node->arg = my_strndup(arg, arg_len);
		if (!parse_logformat_node_args(node->arg, node, err))
			goto error_free;
	}
	if (expr->fetch->val & cap & SMP_VAL_REQUEST)
		node->options |= LOG_OPT_REQ_CAP; /* fetch method is request-compatible */

	if (expr->fetch->val & cap & SMP_VAL_RESPONSE)
		node->options |= LOG_OPT_RES_CAP; /* fetch method is response-compatible */

	if (!(expr->fetch->val & cap)) {
		memprintf(err, "sample fetch <%s> may not be reliably used here because it needs '%s' which is not available here",
		          text, sample_src_names(expr->fetch->use));
		goto error_free;
	}

	if ((options & LOG_OPT_HTTP) && (expr->fetch->use & (SMP_USE_L6REQ|SMP_USE_L6RES))) {
		ha_warning("parsing [%s:%d] : L6 sample fetch <%s> ignored in HTTP log-format string.\n",
			   lf_expr->conf.file, lf_expr->conf.line, text);
	}

	LIST_APPEND(list_format, &node->list);
	return 1;

  error_free:
	free_logformat_node(node);
	return 0;
}

/*
 * Compile logformat expression (from string to list of logformat nodes)
 *
 * Aliases are preceded by % and composed by characters [a-zA-Z0-9]* : %aliasname
 * Expressions are preceded by % and enclosed in square brackets: %[expr]
 * You can set arguments using { } : %{many arguments}aliasname
 *                                   %{many arguments}[expr]
 *
 *  lf_expr: the destination logformat expression (logformat_node list)
 *           which is supposed to be configured (str and conf set) but
 *           shouldn't be compiled (shouldn't contain any nodes)
 *  al: arg list where sample expr should store arg dependency (if the logformat
 *      expression involves sample expressions), may be NULL
 *  options: LOG_OPT_* to force on every node
 *  cap: all SMP_VAL_* flags supported by the consumer
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is filled.
 */
int lf_expr_compile(struct lf_expr *lf_expr,
                    struct arg_list *al, int options, int cap, char **err)
{
	char *fmt = lf_expr->str; /* will be freed unless default */
	char *sp, *str, *backfmt; /* start pointer for text parts */
	char *arg = NULL; /* start pointer for args */
	char *alias = NULL; /* start pointer for aliases */
	char *name = NULL; /* token name (optional) */
	char *typecast_str = NULL; /* token output type (if custom name is set) */
	int arg_len = 0;
	int alias_len = 0;
	int name_len = 0;
	int typecast = SMP_T_SAME; /* relaxed by default */
	int cformat; /* current token format */
	int pformat; /* previous token format */

	BUG_ON((lf_expr->flags & LF_FL_COMPILED));

	if (!fmt)
		return 1; // nothing to do

	sp = str = backfmt = strdup(fmt);
	if (!str) {
		memprintf(err, "out of memory error");
		return 0;
	}

	/* Prepare lf_expr nodes, past this lf_expr doesn't know about ->str
	 * anymore as ->str and ->nodes are part of the same union. ->str has
	 * been saved as local 'fmt' string pointer, so we must free it before
	 * returning.
	 */
	LIST_INIT(&lf_expr->nodes.list);
	lf_expr->nodes.options = LOG_OPT_NONE;
	/* we must set the compiled flag now for proper deinit in case of failure */
	lf_expr->flags |= LF_FL_COMPILED;

	for (cformat = LF_INIT; cformat != LF_END; str++) {
		pformat = cformat;

		if (!*str)
			cformat = LF_END;              // preset it to save all states from doing this

		/* The principle of the two-step state machine below is to first detect a change, and
		 * second have all common paths processed at one place. The common paths are the ones
		 * encountered in text areas (LF_INIT, LF_TEXT, LF_SEPARATOR) and at the end (LF_END).
		 * We use the common LF_INIT state to dispatch to the different final states.
		 */
		switch (pformat) {
		case LF_STARTALIAS:                    // text immediately following a '%'
			arg = NULL; alias = NULL;
			name = NULL;
			name_len = 0;
			typecast = SMP_T_SAME;
			arg_len = alias_len = 0;
			if (*str == '(') {             // custom output name
				cformat = LF_STONAME;
				name = str + 1;
			}
			else
				goto startalias;
			break;

		case LF_STONAME:                       // text immediately following '%('
		case LF_STOTYPE:
			if (cformat == LF_STONAME && *str == ':') { // start custom output type
				cformat = LF_STOTYPE;
				name_len = str -name;
				typecast_str = str + 1;
			}
			else if (*str == ')') {        // end of custom output name
				if (cformat == LF_STONAME)
					name_len = str - name;
				else {
					/* custom type */
					*str = 0; // so that typecast_str is 0 terminated
					typecast = type_to_smp(typecast_str);
					if (typecast != SMP_T_STR && typecast != SMP_T_SINT &&
					    typecast != SMP_T_BOOL) {
						memprintf(err, "unexpected output type '%.*s' at position %d line : '%s'. Supported types are: str, sint, bool", (int)(str - typecast_str), typecast_str, (int)(typecast_str - backfmt), fmt);
						goto fail;
					}
				}
				cformat = LF_EDONAME;
			} else if  (!isalnum((unsigned char)*str) && *str != '_' && *str != '-') {
				memprintf(err, "invalid character in custom name near '%c' at position %d line : '%s'",
				          *str, (int)(str - backfmt), fmt);

				goto fail;
			}
			break;

		case LF_EDONAME:                       // text immediately following %(name)
 startalias:
			if (*str == '{') {             // optional argument
				cformat = LF_STARG;
				arg = str + 1;
			}
			else if (*str == '[') {
				cformat = LF_STEXPR;
				alias = str + 1;       // store expr in alias name
			}
			else if (isalpha((unsigned char)*str)) { // alias name
				cformat = LF_ALIAS;
				alias = str;
			}
			else if (*str == '%')
				cformat = LF_TEXT;     // convert this character to a literal (useful for '%')
			else if (isdigit((unsigned char)*str) || *str == ' ' || *str == '\t') {
				/* single '%' followed by blank or digit, send them both */
				cformat = LF_TEXT;
				pformat = LF_TEXT; /* finally we include the previous char as well */
				sp = str - 1; /* send both the '%' and the current char */
				memprintf(err, "unexpected alias name near '%c' at position %d line : '%s'. Maybe you want to write a single '%%', use the syntax '%%%%'",
				          *str, (int)(str - backfmt), fmt);
				goto fail;

			}
			else
				cformat = LF_INIT;     // handle other cases of literals
			break;

		case LF_STARG:                         // text immediately following '%{'
			if (*str == '}') {             // end of arg
				cformat = LF_EDARG;
				arg_len = str - arg;
				*str = 0;              // used for reporting errors
			}
			break;

		case LF_EDARG:                         // text immediately following '%{arg}'
			if (*str == '[') {
				cformat = LF_STEXPR;
				alias = str + 1;         // store expr in alias name
				break;
			}
			else if (isalnum((unsigned char)*str)) { // alias name
				cformat = LF_ALIAS;
				alias = str;
				break;
			}
			memprintf(err, "parse argument modifier without alias name near '%%{%s}'", arg);
			goto fail;

		case LF_STEXPR:                        // text immediately following '%['
			/* the whole sample expression is parsed at once,
			 * returning the pointer to the first character not
			 * part of the expression, which MUST be the trailing
			 * angle bracket.
			 */
			if (!add_sample_to_logformat_list(alias, name, name_len, typecast, arg, arg_len, lf_expr, al, options, cap, err, &str))
				goto fail;

			if (*str == ']') {
				// end of arg, go on with next state
				cformat = pformat = LF_EDEXPR;
				sp = str;
			}
			else {
				char c = *str;
				*str = 0;
				if (isprint((unsigned char)c))
					memprintf(err, "expected ']' after '%s', but found '%c'", alias, c);
				else
					memprintf(err, "missing ']' after '%s'", alias);
				goto fail;
			}
			break;

		case LF_ALIAS:                         // text part of a alias name
			alias_len = str - alias;
			if (!isalnum((unsigned char)*str))
				cformat = LF_INIT;     // not alias name anymore
			break;

		default:                               // LF_INIT, LF_TEXT, LF_SEPARATOR, LF_END, LF_EDEXPR
			cformat = LF_INIT;
		}

		if (cformat == LF_INIT) { /* resynchronize state to text/sep/startalias */
			switch (*str) {
			case '%': cformat = LF_STARTALIAS;  break;
			case  0 : cformat = LF_END;       break;
			case ' ':
				if (options & LOG_OPT_MERGE_SPACES) {
					cformat = LF_SEPARATOR;
					break;
				}
				__fallthrough;
			default : cformat = LF_TEXT;      break;
			}
		}

		if (cformat != pformat || pformat == LF_SEPARATOR) {
			switch (pformat) {
			case LF_ALIAS:
				if (!parse_logformat_alias(arg, arg_len, name, name_len, typecast, alias, alias_len, lf_expr, &options, err))
					goto fail;
				break;
			case LF_TEXT:
			case LF_SEPARATOR:
				if (!add_to_logformat_list(sp, str, pformat, lf_expr, err))
					goto fail;
				break;
			}
			sp = str; /* new start of text at every state switch and at every separator */
		}
	}

	if (pformat == LF_STARTALIAS || pformat == LF_STARG || pformat == LF_STEXPR || pformat == LF_STONAME || pformat == LF_STOTYPE || pformat == LF_EDONAME) {
		memprintf(err, "truncated line after '%s'", alias ? alias : arg ? arg : "%");
		goto fail;
	}
	logformat_str_free(&fmt);
	ha_free(&backfmt);

	return 1;
 fail:
	logformat_str_free(&fmt);
	ha_free(&backfmt);
	return 0;
}

/* lf_expr_compile() helper: uses <curproxy> to deduce settings and
 * simplify function usage, mostly for legacy purpose
 *
 * curproxy->conf.args.ctx must be set by the caller.
 *
 * The logformat expression will be scheduled for postcheck on the proxy unless
 * the proxy was already checked, in which case all checks will be performed right
 * away.
 *
 * Returns 1 on success and 0 on failure. On failure: <lf_expr> will be cleaned
 * up and <err> will be set.
 */
int parse_logformat_string(const char *fmt, struct proxy *curproxy,
                           struct lf_expr *lf_expr,
                           int options, int cap, char **err)
{
	int ret;


	/* reinit lf_expr (if previously set) */
	lf_expr_deinit(lf_expr);

	lf_expr->str = strdup(fmt);
	if (!lf_expr->str) {
		memprintf(err, "out of memory error");
		goto fail;
	}

	/* Save some parsing infos to raise relevant error messages during
	 * postparsing if needed
	 */
	if (curproxy->conf.args.file) {
		lf_expr->conf.file = strdup(curproxy->conf.args.file);
		lf_expr->conf.line = curproxy->conf.args.line;
	}

	ret = lf_expr_compile(lf_expr, &curproxy->conf.args, options, cap, err);

	if (!ret)
		goto fail;

	if (!(curproxy->cap & PR_CAP_DEF) &&
	    !(curproxy->flags & PR_FL_CHECKED)) {
		/* add the lf_expr to the proxy checks to delay postparsing
		 * since config-related proxy properties are not stable yet
		 */
		LIST_APPEND(&curproxy->conf.lf_checks, &lf_expr->list);
	}
	else {
		/* default proxy, or regular proxy and probably called during
		 * runtime or with proxy already checked, perform the postcheck
		 * right away
		 */
		if (!lf_expr_postcheck(lf_expr, curproxy, err))
			goto fail;
	}
	return 1;

 fail:
	lf_expr_deinit(lf_expr);
	return 0;
}

/* automatically resolves incompatible LOG_OPT options by taking into
 * account current options and global options
 */
static inline void _lf_expr_postcheck_node_opt(int *options, int g_options)
{
	/* encoding is incompatible with HTTP option, so it is ignored
	 * if HTTP option is set, unless HTTP option wasn't set globally
	 * and encoding was set globally, which means encoding takes the
	 * precedence>
	 */
	if (*options & LOG_OPT_HTTP) {
		if ((g_options & (LOG_OPT_HTTP | LOG_OPT_ENCODE)) == LOG_OPT_ENCODE) {
			/* global encoding enabled and http enabled individually */
			*options &= ~LOG_OPT_HTTP;
		}
		else
			*options &= ~LOG_OPT_ENCODE;
	}

	if (*options & LOG_OPT_ENCODE) {
		/* when encoding is set, ignore +E option */
		*options &= ~LOG_OPT_ESC;
	}
}

/* Performs LOG_OPT postparsing check on logformat node <node> belonging to a
 * given logformat expression <lf_expr>
 *
 * It returns 1 on success and 0 on error, <err> will be set in case of error
 */
static int lf_expr_postcheck_node_opt(struct lf_expr *lf_expr, struct logformat_node *node, char **err)
{
	/* per-node encoding options cannot be disabled if already
	 * enabled globally
	 *
	 * Also, ensure we don't mix encoding types, global setting
	 * prevails over per-node one.
	 *
	 * Finally, only consider LOG_OPT_BIN if set globally
	 * (it is a global-only option)
	 */
	if (lf_expr->nodes.options & LOG_OPT_ENCODE) {
		node->options &= ~(LOG_OPT_BIN | LOG_OPT_ENCODE);
		node->options |= (lf_expr->nodes.options & (LOG_OPT_BIN | LOG_OPT_ENCODE));
	}
	else {
		node->options &= ~LOG_OPT_BIN;
		node->options |= (lf_expr->nodes.options & LOG_OPT_BIN);
	}

	_lf_expr_postcheck_node_opt(&node->options, lf_expr->nodes.options);

	return 1;
}

/* Performs a postparsing check on logformat expression <expr> for a given <px>
 * proxy. The function will behave differently depending on the proxy state
 * (during parsing we will try to adapt proxy configuration to make it
 * compatible with logformat expression, but once the proxy is checked, we
 * cannot help anymore so all we can do is raise a diag warning and hope that
 * the conditions will be met when executing the logformat expression)
 *
 * If the proxy is a default section, then allow the postcheck to succeed
 * without errors nor warnings: the logformat expression may or may not work
 * properly depending on the actual proxy that effectively runs it during
 * runtime, but we have to stay permissive since we cannot assume it won't work.
 *
 * It returns 1 on success (although diag_warnings may have been emitted) and 0
 * on error (cannot be recovered from), <err> will be set in case of error.
 */
int lf_expr_postcheck(struct lf_expr *lf_expr, struct proxy *px, char **err)
{
	struct logformat_node *lf;
	int default_px = (px->cap & PR_CAP_DEF);
	uint8_t http_mode = (px->mode == PR_MODE_HTTP || (px->options & PR_O_HTTP_UPG));

	if (!(px->flags & PR_FL_CHECKED))
		px->to_log |= LW_INIT;

	/* postcheck global node options */
	_lf_expr_postcheck_node_opt(&lf_expr->nodes.options, LOG_OPT_NONE);

	list_for_each_entry(lf, &lf_expr->nodes.list, list) {
		if (lf->type == LOG_FMT_EXPR) {
			struct sample_expr *expr = lf->expr;
			uint8_t http_needed = !!(expr->fetch->use & SMP_USE_HTTP_ANY);

			if (!default_px && !http_mode && http_needed)
				ha_diag_warning("parsing [%s:%d]: sample fetch '%s' used from %s '%s' may not work as expected (item depends on HTTP proxy mode).\n",
				                lf_expr->conf.file, lf_expr->conf.line,
				                expr->fetch->kw,
				                proxy_type_str(px), px->id);

			if ((px->flags & PR_FL_CHECKED)) {
				if (http_needed && !px->http_needed)
					ha_diag_warning("parsing [%s:%d]: sample fetch '%s' used from %s '%s' requires HTTP-specific proxy attributes, but the current proxy lacks them.\n",
					                lf_expr->conf.file, lf_expr->conf.line,
					                expr->fetch->kw,
			                                proxy_type_str(px), px->id);
				goto next_node;
			}
			/* check if we need to allocate an http_txn struct for HTTP parsing */
			/* Note, we may also need to set curpx->to_log with certain fetches */
			px->http_needed |= http_needed;

			/* FIXME: temporary workaround for missing LW_XPRT and LW_REQ flags
			 * needed with some sample fetches (eg: ssl*). We always set it for
			 * now on, but this will leave with sample capabilities soon.
			 */
			px->to_log |= LW_XPRT;
			if (px->http_needed)
				px->to_log |= LW_REQ;
		}
		else if (lf->type == LOG_FMT_ALIAS) {
			if (!default_px && !http_mode &&
			    (lf->alias->mode == PR_MODE_HTTP ||
			    (lf->alias->lw & ((LW_REQ | LW_RESP)))))
				ha_diag_warning("parsing [%s:%d]: format alias '%s' used from %s '%s' may not work as expected (item depends on HTTP proxy mode).\n",
		                                lf_expr->conf.file, lf_expr->conf.line,
				                lf->alias->name,
				                proxy_type_str(px), px->id);

			if (lf->alias->config_callback &&
			    !lf->alias->config_callback(lf, px)) {
				memprintf(err, "error while configuring format alias '%s'",
				          lf->alias->name);
				goto fail;
			}
			if (!(px->flags & PR_FL_CHECKED))
				px->to_log |= lf->alias->lw;
		}
 next_node:
		/* postcheck individual node's options */
		if (!lf_expr_postcheck_node_opt(lf_expr, lf, err))
			goto fail;
	}

	return 1;
 fail:
	return 0;
}

/* postparse logformats defined at <px> level */
static int postcheck_logformat_proxy(struct proxy *px)
{
	char *err = NULL;
	struct lf_expr *lf_expr, *back_lf;
	int err_code = ERR_NONE;

	list_for_each_entry_safe(lf_expr, back_lf, &px->conf.lf_checks, list) {
		BUG_ON(!(lf_expr->flags & LF_FL_COMPILED));
		if (!lf_expr_postcheck(lf_expr, px, &err))
			err_code |= ERR_FATAL | ERR_ALERT;
		/* check performed, ensure it doesn't get checked twice */
		LIST_DEL_INIT(&lf_expr->list);
		if (err_code & ERR_CODE)
			break;
	}

	if (err) {
		memprintf(&err, "error detected while postparsing logformat expression used by %s '%s' : %s", proxy_type_str(px), px->id, err);
		if (lf_expr->conf.file)
			memprintf(&err, "parsing [%s:%d] : %s.\n", lf_expr->conf.file, lf_expr->conf.line, err);
		ha_alert("%s", err);
		ha_free(&err);
	}

	return err_code;
}

/*
 * Parse the first range of indexes from a string made of a list of comma separated
 * ranges of indexes. Note that an index may be considered as a particular range
 * with a high limit to the low limit.
 */
int get_logger_smp_range(unsigned int *low, unsigned int *high, char **arg, char **err)
{
	char *end, *p;

	*low = *high = 0;

	p = *arg;
	end = strchr(p, ',');
	if (!end)
		end = p + strlen(p);

	*high = *low = read_uint((const char **)&p, end);
	if (!*low || (p != end && *p != '-'))
		goto err;

	if (p == end)
		goto done;

	p++;
	*high = read_uint((const char **)&p, end);
	if (!*high || *high <= *low || p != end)
		goto err;

 done:
	if (*end == ',')
		end++;
	*arg = end;
	return 1;

 err:
	memprintf(err, "wrong sample range '%s'", *arg);
	return 0;
}

/*
 * Returns 1 if the range defined by <low> and <high> overlaps
 * one of them in <rgs> array of ranges with <sz> the size of this
 * array, 0 if not.
 */
int smp_log_ranges_overlap(struct smp_log_range *rgs, size_t sz,
                           unsigned int low, unsigned int high, char **err)
{
	size_t i;

	for (i = 0; i < sz; i++) {
		if ((low  >= rgs[i].low && low  <= rgs[i].high) ||
		    (high >= rgs[i].low && high <= rgs[i].high)) {
			memprintf(err, "ranges are overlapping");
			return 1;
		}
	}

	return 0;
}

int smp_log_range_cmp(const void *a, const void *b)
{
	const struct smp_log_range *rg_a = a;
	const struct smp_log_range *rg_b = b;

	if (rg_a->high < rg_b->low)
		return -1;
	else if (rg_a->low > rg_b->high)
		return 1;

	return 0;
}

/* helper func */
static inline void init_log_target(struct log_target *target)
{
	target->type = 0;
	target->flags = LOG_TARGET_FL_NONE;
	target->addr = NULL;
	target->resolv_name = NULL;
}

void deinit_log_target(struct log_target *target)
{
	ha_free(&target->addr);
	if (!(target->flags & LOG_TARGET_FL_RESOLVED))
		ha_free(&target->resolv_name);
}

/* returns 0 on failure and positive value on success */
static int dup_log_target(struct log_target *def, struct log_target *cpy)
{
	BUG_ON((def->flags & LOG_TARGET_FL_RESOLVED)); /* postparsing already done, invalid use */
	init_log_target(cpy);
	if (def->addr) {
		cpy->addr = malloc(sizeof(*cpy->addr));
		if (!cpy->addr)
			goto error;
		*cpy->addr = *def->addr;
	}
	if (def->resolv_name) {
		cpy->resolv_name = strdup(def->resolv_name);
		if (!cpy->resolv_name)
			goto error;
	}
	cpy->type = def->type;
	return 1;
 error:
	deinit_log_target(cpy);
	return 0;
}

/* check that current configuration is compatible with "mode log" */
static int _postcheck_log_backend_compat(struct proxy *be)
{
	int err_code = ERR_NONE;
	int balance_algo = (be->lbprm.algo & BE_LB_ALGO);

	if (!LIST_ISEMPTY(&be->tcp_req.inspect_rules) ||
	    !LIST_ISEMPTY(&be->tcp_req.l4_rules) ||
	    !LIST_ISEMPTY(&be->tcp_req.l5_rules)) {
		ha_warning("Cannot use tcp-request rules with 'mode log' in %s '%s'. They will be ignored.\n",
			   proxy_type_str(be), be->id);

		err_code |= ERR_WARN;
		free_act_rules(&be->tcp_req.inspect_rules);
		free_act_rules(&be->tcp_req.l4_rules);
		free_act_rules(&be->tcp_req.l5_rules);
	}
	if (!LIST_ISEMPTY(&be->tcp_rep.inspect_rules)) {
		ha_warning("Cannot use tcp-response rules with 'mode log' in %s '%s'. They will be ignored.\n",
			   proxy_type_str(be), be->id);

		err_code |= ERR_WARN;
		free_act_rules(&be->tcp_rep.inspect_rules);
	}
	if (be->table) {
		ha_warning("Cannot use stick table with 'mode log' in %s '%s'. It will be ignored.\n",
			   proxy_type_str(be), be->id);

		err_code |= ERR_WARN;
		stktable_deinit(be->table);
		ha_free(&be->table);
	}
	if (!LIST_ISEMPTY(&be->storersp_rules) ||
	    !LIST_ISEMPTY(&be->sticking_rules)) {
		ha_warning("Cannot use sticking rules with 'mode log' in %s '%s'. They will be ignored.\n",
			   proxy_type_str(be), be->id);

		err_code |= ERR_WARN;
		free_stick_rules(&be->storersp_rules);
		free_stick_rules(&be->sticking_rules);
	}
	if (isttest(be->server_id_hdr_name)) {
		ha_warning("Cannot set \"http-send-name-header\" with 'mode log' in %s '%s'. It will be ignored.\n",
			   proxy_type_str(be), be->id);

		err_code |= ERR_WARN;
		istfree(&be->server_id_hdr_name);
	}
	if (be->dyncookie_key) {
		ha_warning("Cannot set \"dynamic-cookie-key\" with 'mode log' in %s '%s'. It will be ignored.\n",
			   proxy_type_str(be), be->id);

		err_code |= ERR_WARN;
		ha_free(&be->dyncookie_key);
	}
	if (!LIST_ISEMPTY(&be->server_rules)) {
		ha_warning("Cannot use \"use-server\" rules with 'mode log' in %s '%s'. They will be ignored.\n",
			   proxy_type_str(be), be->id);

		err_code |= ERR_WARN;
		free_server_rules(&be->server_rules);
	}
	if (be->to_log == LW_LOGSTEPS) {
		ha_warning("Cannot use \"log-steps\" with 'mode log' in %s '%s'. It will be ignored.\n",
			   proxy_type_str(be), be->id);

		err_code |= ERR_WARN;
		/* we don't have a convenient freeing function, let the proxy free it upon deinit */
	}
	if (balance_algo != BE_LB_ALGO_RR &&
	    balance_algo != BE_LB_ALGO_RND &&
	    balance_algo != BE_LB_ALGO_SS &&
	    balance_algo != BE_LB_ALGO_LH) {
		/* cannot correct the error since lbprm init was already performed
		 * in cfgparse.c, so fail loudly
		 */
		ha_alert("in %s '%s': \"balance\" only supports 'roundrobin', 'random', 'sticky' and 'log-hash'.\n", proxy_type_str(be), be->id);
		err_code |= ERR_ALERT | ERR_FATAL;
	}
	return err_code;
}

static int postcheck_log_backend(struct proxy *be)
{
	char *msg = NULL;
	struct server *srv;
	int err_code = ERR_NONE;
	int target_type = -1; // -1 is unused in log_tgt enum

	if (be->mode != PR_MODE_SYSLOG ||
	    (be->flags & (PR_FL_DISABLED|PR_FL_STOPPED)))
		return ERR_NONE; /* nothing to do */

	err_code |= _postcheck_log_backend_compat(be);
	if (err_code & ERR_CODE)
		return err_code;

	/* "log-balance hash" needs to compile its expression */
	if ((be->lbprm.algo & BE_LB_ALGO) == BE_LB_ALGO_LH) {
		struct sample_expr *expr;
		char *expr_str = NULL;
		char *err_str = NULL;
		int idx = 0;

		/* only map-based hash method is supported for now */
		if ((be->lbprm.algo & BE_LB_HASH_TYPE) != BE_LB_HASH_MAP) {
			memprintf(&msg, "unsupported hash method (from \"hash-type\")");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}

		/* a little bit of explanation about what we're going to do here:
		 * as the user gave us a list of converters, instead of the fetch+conv list
		 * tuple as we're used to, we need to insert a dummy fetch at the start of
		 * the converter list so that sample_parse_expr() is able to properly parse
		 * the expr. We're explicitly using str() as dummy fetch, since the input
		 * sample that will be passed to the converter list at runtime will be a
		 * string (the log message about to be sent). Doing so allows sample_parse_expr()
		 * to ensure that the provided converters will be compatible with string type.
		 */
		memprintf(&expr_str, "str(dummy),%s", be->lbprm.arg_str);
		if (!expr_str) {
			memprintf(&msg, "memory error during converter list argument parsing (from \"log-balance hash\")");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		expr = sample_parse_expr((char*[]){expr_str, NULL}, &idx,
		                         be->conf.file,
		                         be->conf.line,
		                         &err_str, NULL, NULL);
		if (!expr) {
			memprintf(&msg, "%s (from converter list argument in \"log-balance hash\")", err_str);
			ha_free(&err_str);
			err_code |= ERR_ALERT | ERR_FATAL;
			ha_free(&expr_str);
			goto end;
		}

		/* We expect the log_message->conv_list expr to resolve as a binary-compatible
		 * value because its output will be passed to gen_hash() to compute the hash.
		 *
		 * So we check the last converter's output type to ensure that it can be
		 * converted into the expected type. Invalid output type will result in an
		 * error to prevent unexpected results during runtime.
		 */
		if (sample_casts[smp_expr_output_type(expr)][SMP_T_BIN] == NULL) {
			memprintf(&msg, "invalid output type at the end of converter list for \"log-balance hash\" directive");
			err_code |= ERR_ALERT | ERR_FATAL;
			release_sample_expr(expr);
			ha_free(&expr_str);
			goto end;
		}
		ha_free(&expr_str);
		be->lbprm.expr = expr;
	}

	/* finish the initialization of proxy's servers */
	srv = be->srv;
	while (srv) {
		BUG_ON(srv->log_target);
		BUG_ON(srv->addr_type.proto_type != PROTO_TYPE_DGRAM &&
		       srv->addr_type.proto_type != PROTO_TYPE_STREAM);

		srv->log_target = malloc(sizeof(*srv->log_target));
		if (!srv->log_target) {
			memprintf(&msg, "memory error when allocating log server '%s'\n", srv->id);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		init_log_target(srv->log_target);
		if (srv->addr_type.proto_type == PROTO_TYPE_DGRAM) {
			srv->log_target->type = LOG_TARGET_DGRAM;
			/* Try to allocate log target addr (only used in DGRAM mode) */
			srv->log_target->addr = calloc(1, sizeof(*srv->log_target->addr));
			if (!srv->log_target->addr) {
				memprintf(&msg, "memory error when allocating log server '%s'\n", srv->id);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto end;
			}
			/* We must initialize it with known addr:svc_port, it will then
			 * be updated automatically by the server API for runtime changes
			 */
			ipcpy(&srv->addr, srv->log_target->addr);
			set_host_port(srv->log_target->addr, srv->svc_port);
		}
		else {
			/* for now BUFFER type only supports TCP server to it's almost
			 * explicit
			 */
			srv->log_target->type = LOG_TARGET_BUFFER;
			srv->log_target->sink = sink_new_from_srv(srv, "log backend");
			if (!srv->log_target->sink) {
				memprintf(&msg, "error when creating sink from '%s' log server", srv->id);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto end;
			}
		}

		if (target_type == -1)
			target_type = srv->log_target->type;

		if (target_type != srv->log_target->type) {
			memprintf(&msg, "cannot mix server types within a log backend, '%s' srv's network type differs from previous server", srv->id);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		srv->log_target->flags |= LOG_TARGET_FL_RESOLVED;
		srv = srv->next;
	}
 end:
	if (err_code & ERR_CODE) {
		ha_alert("log backend '%s': failed to initialize: %s.\n", be->id, msg);
		ha_free(&msg);
	}

	return err_code;
}

/* forward declaration */
static int log_profile_postcheck(struct proxy *px, struct log_profile *prof, char **err);

/* resolves a single logger entry (it is expected to be called
 * at postparsing stage)
 *
 * <px> is parent proxy, used for context (may be NULL)
 *
 * Returns err_code which defaults to ERR_NONE and can be set to a combination
 * of ERR_WARN, ERR_ALERT, ERR_FATAL and ERR_ABORT in case of errors.
 * <msg> could be set at any time (it will usually be set on error, but
 * could also be set when no error occurred to report a diag warning), thus is
 * up to the caller to check it and to free it.
 */
static int resolve_logger(struct proxy *px, struct logger *logger, char **msg)
{
	struct log_target *target = &logger->target;
	int err_code = ERR_NONE;

	/* resolve logger target */
	if (target->type == LOG_TARGET_BUFFER)
		err_code = sink_resolve_logger_buffer(logger, msg);
	else if (target->type == LOG_TARGET_BACKEND) {
		struct proxy *be;

		/* special case */
		be = proxy_find_by_name(target->be_name, PR_CAP_BE, 0);
		if (!be) {
			memprintf(msg, "uses unknown log backend '%s'", target->be_name);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
		else if (be->mode != PR_MODE_SYSLOG) {
			memprintf(msg, "uses incompatible log backend '%s'", target->be_name);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
		ha_free(&target->be_name); /* backend is resolved and will replace name hint */
		target->be = be;
	}

	target->flags |= LOG_TARGET_FL_RESOLVED;

	if (err_code & ERR_CODE)
		goto end;

	/* postcheck logger profile */
	if (logger->prof_str) {
		struct log_profile *prof;

		prof = log_profile_find_by_name(logger->prof_str);
		if (!prof) {
			memprintf(msg, "unknown log-profile '%s'", logger->prof_str);
			ha_free(&logger->prof_str);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		ha_free(&logger->prof_str);
		logger->prof = prof;

		if (!log_profile_postcheck(px, logger->prof, msg)) {
			memprintf(msg, "uses incompatible log-profile '%s': %s", logger->prof->id, *msg);
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}

 end:
	logger->flags |= LOGGER_FL_RESOLVED;
	return err_code;
}

/* tries to duplicate <def> logger
 * (only possible before the logger is resolved)
 *
 * Returns the newly allocated and duplicated logger or NULL
 * in case of error.
 */
struct logger *dup_logger(struct logger *def)
{
	struct logger *cpy;

	BUG_ON(def->flags & LOGGER_FL_RESOLVED);
	cpy = malloc(sizeof(*cpy));

	/* copy everything that can be easily copied */
	memcpy(cpy, def, sizeof(*cpy));

	/* default values */
	cpy->conf.file = NULL;
	cpy->lb.smp_rgs = NULL;
	LIST_INIT(&cpy->list);

	/* special members */
	if (dup_log_target(&def->target, &cpy->target) == 0)
		goto error;
	if (def->conf.file) {
		cpy->conf.file = strdup(def->conf.file);
		if (!cpy->conf.file)
			goto error;
	}
	if (def->lb.smp_rgs) {
		cpy->lb.smp_rgs = malloc(sizeof(*cpy->lb.smp_rgs) * def->lb.smp_rgs_sz);
		if (!cpy->lb.smp_rgs)
			goto error;
		memcpy(cpy->lb.smp_rgs, def->lb.smp_rgs,
		       sizeof(*cpy->lb.smp_rgs) * def->lb.smp_rgs_sz);
	}
	if (def->prof_str) {
		cpy->prof_str = strdup(def->prof_str);
		if (!cpy->prof_str)
			goto error;
	}

	/* inherit from original reference if set */
	cpy->ref = (def->ref) ? def->ref : def;

	return cpy;

 error:
	free_logger(cpy);
	return NULL;
}

/* frees <logger> after freeing all of its allocated fields. The
 * server must not belong to a list anymore. Logsrv may be NULL, which is
 * silently ignored.
 */
void free_logger(struct logger *logger)
{
	if (!logger)
		return;

	BUG_ON(LIST_INLIST(&logger->list));
	ha_free(&logger->conf.file);
	deinit_log_target(&logger->target);
	free(logger->lb.smp_rgs);
	if (!(logger->flags & LOGGER_FL_RESOLVED))
		ha_free(&logger->prof_str);
	free(logger);
}

/* Parse single log target
 * Returns 0 on failure and positive value on success
 */
static int parse_log_target(char *raw, struct log_target *target, char **err)
{
	int port1, port2, fd;
	struct protocol *proto;
	struct sockaddr_storage *sk;

	init_log_target(target);
	// target addr is NULL at this point

	if (strncmp(raw, "ring@", 5) == 0) {
		target->type = LOG_TARGET_BUFFER;
		target->ring_name = strdup(raw + 5);
		goto done;
	}
	else if (strncmp(raw, "backend@", 8) == 0) {
		target->type = LOG_TARGET_BACKEND;
		target->be_name = strdup(raw + 8);
		goto done;
	}

	/* try to allocate log target addr */
	target->addr = malloc(sizeof(*target->addr));
	if (!target->addr) {
		memprintf(err, "memory error");
		goto error;
	}

	target->type = LOG_TARGET_DGRAM; // default type

	/* parse the target address */
	sk = str2sa_range(raw, NULL, &port1, &port2, &fd, &proto, NULL,
	                  err, NULL, NULL, NULL,
	                  PA_O_RESOLVE | PA_O_PORT_OK | PA_O_RAW_FD | PA_O_DGRAM | PA_O_STREAM | PA_O_DEFAULT_DGRAM);
	if (!sk)
		goto error;
	if (fd != -1)
		target->type = LOG_TARGET_FD;
	*target->addr = *sk;

	if (sk->ss_family == AF_INET || sk->ss_family == AF_INET6) {
		if (!port1)
			set_host_port(target->addr, SYSLOG_PORT);
	}

	if (proto && proto->xprt_type == PROTO_TYPE_STREAM) {
		static unsigned long ring_ids;

		/* Implicit sink buffer will be initialized in post_check
		 * (target->addr is set in this case)
		 */
		target->type = LOG_TARGET_BUFFER;
		/* compute unique name for the ring */
		memprintf(&target->ring_name, "ring#%lu", ++ring_ids);
	}

 done:
	return 1;
 error:
	deinit_log_target(target);
	return 0;
}

/*
 * Parse "log" keyword and update <loggers> list accordingly.
 *
 * When <do_del> is set, it means the "no log" line was parsed, so all log
 * servers in <loggers> are released.
 *
 * Otherwise, we try to parse the "log" line. First of all, when the list is not
 * the global one, we look for the parameter "global". If we find it,
 * global.loggers is copied. Else we parse each arguments.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int parse_logger(char **args, struct list *loggers, int do_del, const char *file, int linenum, char **err)
{
	struct smp_log_range *smp_rgs = NULL;
	struct logger *logger = NULL;
	int cur_arg;

	/*
	 * "no log": delete previous herited or defined syslog
	 *           servers.
	 */
	if (do_del) {
		struct logger *back;

		if (*(args[1]) != 0) {
			memprintf(err, "'no log' does not expect arguments");
			goto error;
		}

		list_for_each_entry_safe(logger, back, loggers, list) {
			LIST_DEL_INIT(&logger->list);
			free_logger(logger);
		}
		return 1;
	}

	/*
	 * "log global": copy global.loggers linked list to the end of loggers
	 *               list. But first, we check (loggers != global.loggers).
	 */
	if (*(args[1]) && *(args[2]) == 0 && strcmp(args[1], "global") == 0) {
		if (loggers == &global.loggers) {
			memprintf(err, "'global' is not supported for a global syslog server");
			goto error;
		}
		list_for_each_entry(logger, &global.loggers, list) {
			struct logger *node;

			list_for_each_entry(node, loggers, list) {
				if (node->ref == logger)
					goto skip_logger;
			}

			/* duplicate logger from global */
			node = dup_logger(logger);
			if (!node) {
				memprintf(err, "out of memory error");
				goto error;
			}

			/* manually override some values */
			ha_free(&node->conf.file);
			node->conf.file = strdup(file);
			node->conf.line = linenum;

			/* add to list */
			LIST_APPEND(loggers, &node->list);

		  skip_logger:
			continue;
		}
		return 1;
	}

	/*
	* "log <address> ...: parse a syslog server line
	*/
	if (*(args[1]) == 0 || *(args[2]) == 0) {
		memprintf(err, "expects <address> and <facility> %s as arguments",
			  ((loggers == &global.loggers) ? "" : "or global"));
		goto error;
	}

	/* take care of "stdout" and "stderr" as regular aliases for fd@1 / fd@2 */
	if (strcmp(args[1], "stdout") == 0)
		args[1] = "fd@1";
	else if (strcmp(args[1], "stderr") == 0)
		args[1] = "fd@2";

	logger = calloc(1, sizeof(*logger));
	if (!logger) {
		memprintf(err, "out of memory");
		goto error;
	}
	LIST_INIT(&logger->list);
	logger->conf.file = strdup(file);
	logger->conf.line = linenum;

	/* skip address for now, it will be parsed at the end */
	cur_arg = 2;

	/* just after the address, a length may be specified */
	logger->maxlen = MAX_SYSLOG_LEN;
	if (strcmp(args[cur_arg], "len") == 0) {
		int len = atoi(args[cur_arg+1]);
		if (len < 80 || len > 65535) {
			memprintf(err, "invalid log length '%s', must be between 80 and 65535",
				  args[cur_arg+1]);
			goto error;
		}
		logger->maxlen = len;
		cur_arg += 2;
	}
	if (logger->maxlen > global.max_syslog_len)
		global.max_syslog_len = logger->maxlen;

	/* after the length, a format may be specified */
	if (strcmp(args[cur_arg], "format") == 0) {
		logger->format = get_log_format(args[cur_arg+1]);
		if (logger->format == LOG_FORMAT_UNSPEC) {
			memprintf(err, "unknown log format '%s'", args[cur_arg+1]);
			goto error;
		}
		cur_arg += 2;
	}

	if (strcmp(args[cur_arg], "sample") == 0) {
		unsigned low, high;
		char *p, *beg, *end, *smp_sz_str;
		size_t smp_rgs_sz = 0, smp_sz = 0, new_smp_sz;

		p = args[cur_arg+1];
		smp_sz_str = strchr(p, ':');
		if (!smp_sz_str) {
			memprintf(err, "Missing sample size");
			goto error;
		}

		*smp_sz_str++ = '\0';

		end = p + strlen(p);

		while (p != end) {
			if (!get_logger_smp_range(&low, &high, &p, err))
				goto error;

			if (smp_rgs && smp_log_ranges_overlap(smp_rgs, smp_rgs_sz, low, high, err))
				goto error;

			smp_rgs = my_realloc2(smp_rgs, (smp_rgs_sz + 1) * sizeof *smp_rgs);
			if (!smp_rgs) {
				memprintf(err, "out of memory error");
				goto error;
			}

			smp_rgs[smp_rgs_sz].low = low;
			smp_rgs[smp_rgs_sz].high = high;
			smp_rgs[smp_rgs_sz].sz = high - low + 1;
			if (smp_rgs[smp_rgs_sz].high > smp_sz)
				smp_sz = smp_rgs[smp_rgs_sz].high;
			smp_rgs_sz++;
		}

		if (smp_rgs == NULL) {
			memprintf(err, "no sampling ranges given");
			goto error;
		}

		beg = smp_sz_str;
		end = beg + strlen(beg);
		new_smp_sz = read_uint((const char **)&beg, end);
		if (!new_smp_sz || beg != end) {
			memprintf(err, "wrong sample size '%s' for sample range '%s'",
						   smp_sz_str, args[cur_arg+1]);
			goto error;
		}

		if (new_smp_sz < smp_sz) {
			memprintf(err, "sample size %zu should be greater or equal to "
						   "%zu the maximum of the high ranges limits",
						   new_smp_sz, smp_sz);
			goto error;
		}
		smp_sz = new_smp_sz;

		/* Let's order <smp_rgs> array. */
		qsort(smp_rgs, smp_rgs_sz, sizeof(struct smp_log_range), smp_log_range_cmp);

		logger->lb.smp_rgs = smp_rgs;
		logger->lb.smp_rgs_sz = smp_rgs_sz;
		logger->lb.smp_sz = smp_sz;

		cur_arg += 2;
	}

	if (strcmp(args[cur_arg], "profile") == 0) {
		char *prof_str;

		prof_str = args[cur_arg+1];
		if (!prof_str) {
			memprintf(err, "expected log-profile name");
			goto error;
		}
		logger->prof_str = strdup(prof_str);
		cur_arg += 2;
	}

	/* parse the facility */
	logger->facility = get_log_facility(args[cur_arg]);
	if (logger->facility < 0) {
		memprintf(err, "unknown log facility '%s'", args[cur_arg]);
		goto error;
	}
	cur_arg++;

	/* parse the max syslog level (default: debug) */
	logger->level = 7;
	if (*(args[cur_arg])) {
		logger->level = get_log_level(args[cur_arg]);
		if (logger->level < 0) {
			memprintf(err, "unknown optional log level '%s'", args[cur_arg]);
			goto error;
		}
		cur_arg++;
	}

	/* parse the limit syslog level (default: emerg) */
	logger->minlvl = 0;
	if (*(args[cur_arg])) {
		logger->minlvl = get_log_level(args[cur_arg]);
		if (logger->minlvl < 0) {
			memprintf(err, "unknown optional minimum log level '%s'", args[cur_arg]);
			goto error;
		}
		cur_arg++;
	}

	/* Too many args */
	if (*(args[cur_arg])) {
		memprintf(err, "cannot handle unexpected argument '%s'", args[cur_arg]);
		goto error;
	}

	/* now, back to the log target */
	if (!parse_log_target(args[1], &logger->target, err))
		goto error;

 done:
	LIST_APPEND(loggers, &logger->list);
	return 1;

  error:
	free(smp_rgs);
	free_logger(logger);
	return 0;
}


/*
 * returns log format, LOG_FORMAT_UNSPEC is return if not found.
 */
enum log_fmt get_log_format(const char *fmt)
{
	enum log_fmt format;

	format = LOG_FORMATS - 1;
	while (format > 0 && log_formats[format].name
	                  && strcmp(log_formats[format].name, fmt) != 0)
		format--;

	/* Note: 0 is LOG_FORMAT_UNSPEC */
	return format;
}

/*
 * returns log level for <lev> or -1 if not found.
 */
int get_log_level(const char *lev)
{
	int level;

	level = NB_LOG_LEVELS - 1;
	while (level >= 0 && strcmp(log_levels[level], lev) != 0)
		level--;

	return level;
}

/*
 * returns log facility for <fac> or -1 if not found.
 */
int get_log_facility(const char *fac)
{
	int facility;

	facility = NB_LOG_FACILITIES - 1;
	while (facility >= 0 && strcmp(log_facilities[facility], fac) != 0)
		facility--;

	return facility;
}

struct lf_buildctx {
	char _buf[256];/* fixed size buffer for building small strings */
	int options;   /* LOG_OPT_* options */
	int typecast;  /* same as logformat_node->typecast */
	int in_text;   /* inside variable-length text */
	union {
		struct cbor_encode_ctx cbor; /* cbor-encode specific ctx */
	} encode;
};

static THREAD_LOCAL struct lf_buildctx lf_buildctx;

/* helper to encode a single byte in hex form
 *
 * Returns the position of the last written byte on success and NULL on
 * error.
 */
static char *_encode_byte_hex(char *start, char *stop, unsigned char byte)
{
	/* hex form requires 2 bytes */
	if ((stop - start) < 2)
		return NULL;
	*start++ = hextab[(byte >> 4) & 15];
	*start++ = hextab[byte & 15];
	return start;
}

/* lf cbor function ptr used to encode a single byte according to RFC8949
 *
 * for now only hex form is supported.
 *
 * The function may only be called under CBOR context (that is when
 * LOG_OPT_ENCODE_CBOR option is set).
 *
 * Returns the position of the last written byte on success and NULL on
 * error.
 */
static char *_lf_cbor_encode_byte(struct cbor_encode_ctx *cbor_ctx,
                                  char *start, char *stop, unsigned char byte)
{
	struct lf_buildctx *ctx;

	BUG_ON(!cbor_ctx || !cbor_ctx->e_fct_ctx);
	ctx = cbor_ctx->e_fct_ctx;

	if (ctx->options & LOG_OPT_BIN) {
		/* raw output */
		if ((stop - start) < 1)
			return NULL;
		*start++ = byte;
		return start;
	}
	return _encode_byte_hex(start, stop, byte);
}

/* helper function to prepare lf_buildctx struct based on global options
 * and current node settings (may be NULL)
 */
static inline void lf_buildctx_prepare(struct lf_buildctx *ctx,
                                       int g_options,
                                       const struct logformat_node *node)
{
	if (node) {
		/* consider node's options and typecast setting */
		ctx->options = node->options;
		ctx->typecast = node->typecast;
	}
	else {
		ctx->options = g_options;
		ctx->typecast = SMP_T_SAME; /* default */
	}

	if (ctx->options & LOG_OPT_ENCODE_CBOR) {
		/* prepare cbor-specific encode ctx */
		ctx->encode.cbor.e_fct_byte = _lf_cbor_encode_byte;
		ctx->encode.cbor.e_fct_ctx = ctx;
	}
}

/* helper function for _lf_encode_bytes() to escape a single byte
 * with <escape>
 */
static inline char *_lf_escape_byte(char *start, char *stop,
                                    char byte, const char escape)
{
	if (start + 3 >= stop)
		return NULL;
	*start++ = escape;
	*start++ = hextab[(byte >> 4) & 15];
	*start++ = hextab[byte & 15];

	return start;
}

/* helper function for _lf_encode_bytes() to escape a single byte
 * with <escape> and deal with cbor-specific encoding logic
 */
static inline char *_lf_cbor_escape_byte(char *start, char *stop,
                                         char byte, const char escape,
                                         uint8_t cbor_string_prefix,
                                         struct lf_buildctx *ctx)
{
	char escaped_byte[3];

	escaped_byte[0] = escape;
	escaped_byte[1] = hextab[(byte >> 4) & 15];
	escaped_byte[2] = hextab[byte & 15];

	start = cbor_encode_bytes_prefix(&ctx->encode.cbor, start, stop,
	                                 escaped_byte, 3,
	                                 cbor_string_prefix);

	return start;
}

/* helper function for _lf_encode_bytes() to encode a single byte
 * and escape it with <escape> if found in <map>
 *
 * The function assumes that at least 1 byte is available for writing
 *
 * Returns the address of the last written byte on success, or NULL
 * on error
 */
static inline char *_lf_map_escape_byte(char *start, char *stop,
                                        const char *byte,
                                        const char escape, const long *map,
                                        const char **pending, uint8_t cbor_string_prefix,
                                        struct lf_buildctx *ctx)
{
	if (!ha_bit_test((unsigned char)(*byte), map))
		*start++ = *byte;
	else
		start = _lf_escape_byte(start, stop, *byte, escape);

	return start;
}

/* helper function for _lf_encode_bytes() to encode a single byte
 * and escape it with <escape> if found in <map> and deal with
 * cbor-specific encoding logic.
 *
 * The function assumes that at least 1 byte is available for writing
 *
 * Returns the address of the last written byte on success, or NULL
 * on error
 */
static inline char *_lf_cbor_map_escape_byte(char *start, char *stop,
                                             const char *byte,
                                             const char escape, const long *map,
                                             const char **pending, uint8_t cbor_string_prefix,
                                             struct lf_buildctx *ctx)
{
	/* We try our best to minimize the number of chunks produced for the
	 * indefinite-length byte string as each chunk has an extra overhead
	 * as per RFC8949.
	 *
	 * To achieve that, we try to emit consecutive bytes together
	 */
	if (!ha_bit_test((unsigned char)(*byte), map)) {
		/* do nothing and let the caller continue seeking data,
		 * pending data will be flushed later
		 */
	} else {
		/* first, flush pending unescaped bytes */
		start = cbor_encode_bytes_prefix(&ctx->encode.cbor, start, stop,
		                                 *pending, (byte - *pending),
		                                 cbor_string_prefix);
		if (start == NULL)
			return NULL;

		*pending = byte + 1;

		/* escape current matching byte */
		start = _lf_cbor_escape_byte(start, stop, *byte, escape,
		                             cbor_string_prefix,
		                             ctx);
	}

	return start;
}

/* helper function for _lf_encode_bytes() to encode a single byte
 * and escape it with <escape> if found in <map> or escape it with
 * '\' if found in rfc5424_escape_map
 *
 * The function assumes that at least 1 byte is available for writing
 *
 * Returns the address of the last written byte on success, or NULL
 * on error
 */
static inline char *_lf_rfc5424_escape_byte(char *start, char *stop,
                                            const char *byte,
                                            const char escape, const long *map,
                                            const char **pending, uint8_t cbor_string_prefix,
                                            struct lf_buildctx *ctx)
{
	if (!ha_bit_test((unsigned char)(*byte), map)) {
		if (!ha_bit_test((unsigned char)(*byte), rfc5424_escape_map))
			*start++ = *byte;
		else {
			if (start + 2 >= stop)
				return NULL;
			*start++ = '\\';
			*start++ = *byte;
		}
	}
	else
		start = _lf_escape_byte(start, stop, *byte, escape);

	return start;
}

/* helper function for _lf_encode_bytes() to encode a single byte
 * and escape it with <escape> if found in <map> or escape it with
 * '\' if found in json_escape_map
 *
 * The function assumes that at least 1 byte is available for writing
 *
 * Returns the address of the last written byte on success, or NULL
 * on error
 */
static inline char *_lf_json_escape_byte(char *start, char *stop,
                                         const char *byte,
                                         const char escape, const long *map,
                                         const char **pending, uint8_t cbor_string_prefix,
                                         struct lf_buildctx *ctx)
{
	if (!ha_bit_test((unsigned char)(*byte), map)) {
		if (!ha_bit_test((unsigned char)(*byte), json_escape_map))
			*start++ = *byte;
		else {
			if (start + 2 >= stop)
				return NULL;
			*start++ = '\\';
			*start++ = *byte;
		}
	}
	else
		start = _lf_escape_byte(start, stop, *byte, escape);

	return start;
}

/*
 * helper for lf_encode_{string,chunk}:
 * encode the input bytes, input <bytes> is processed until <bytes_stop>
 * is reached. If <bytes_stop> is NULL, <bytes> is expected to be NULL
 * terminated.
 *
 * When using the +E log format option, it will try to escape '"\]'
 * characters with '\' as prefix. The same prefix should not be used as
 * <escape>.
 *
 * When using json encoding, string will be escaped according to
 * json escape map
 *
 * When using cbor encoding, escape option is ignored. However bytes found
 * in <map> will still be escaped with <escape>.
 *
 * Return the address of the \0 character, or NULL on error
 */
static char *_lf_encode_bytes(char *start, char *stop,
                              const char escape, const long *map,
                              const char *bytes, const char *bytes_stop,
                              struct lf_buildctx *ctx)
{
	char *ret;
	const char *pending;
	uint8_t cbor_string_prefix = 0;
	char *(*encode_byte)(char *start, char *stop,
	                     const char *byte,
	                     const char escape, const long *map,
	                     const char **pending, uint8_t cbor_string_prefix,
	                     struct lf_buildctx *ctx);

	if (ctx->options & LOG_OPT_ENCODE_JSON)
		encode_byte = _lf_json_escape_byte;
	else if (ctx->options & LOG_OPT_ENCODE_CBOR)
		encode_byte = _lf_cbor_map_escape_byte;
	else if (ctx->options & LOG_OPT_ESC)
		encode_byte = _lf_rfc5424_escape_byte;
	else
		encode_byte = _lf_map_escape_byte;

	if (ctx->options & LOG_OPT_ENCODE_CBOR) {
		if (!bytes_stop) {
			/* printable chars: use cbor text */
			cbor_string_prefix = 0x60;
		}
		else {
			/* non printable chars: use cbor byte string */
			cbor_string_prefix = 0x40;
		}
	}

	if (start < stop) {
		stop--; /* reserve one byte for the final '\0' */

		if ((ctx->options & LOG_OPT_ENCODE_CBOR) && !ctx->in_text) {
			/* start indefinite-length cbor byte string or text */
			start = _lf_cbor_encode_byte(&ctx->encode.cbor, start, stop,
			                             (cbor_string_prefix | 0x1F));
			if (start == NULL)
				return NULL;
		}
		pending = bytes;

		/* we have 2 distinct loops to keep checks outside of the loop
		 * for better performance
		 */
		if (bytes && !bytes_stop) {
			while (start < stop && *bytes != '\0') {
				ret = encode_byte(start, stop, bytes, escape, map,
				                  &pending, cbor_string_prefix,
				                  ctx);
				if (ret == NULL)
					break;
				start = ret;
				bytes++;
			}
		} else if (bytes) {
			while (start < stop && bytes < bytes_stop) {
				ret = encode_byte(start, stop, bytes, escape, map,
				                  &pending, cbor_string_prefix,
				                  ctx);
				if (ret == NULL)
					break;
				start = ret;
				bytes++;
			}
		}

		if (ctx->options & LOG_OPT_ENCODE_CBOR) {
			if (pending != bytes) {
				/* flush pending unescaped bytes */
				start = cbor_encode_bytes_prefix(&ctx->encode.cbor, start, stop,
				                                 pending, (bytes - pending),
				                                 cbor_string_prefix);
				if (start == NULL)
					return NULL;
			}
			if (!ctx->in_text) {
				/* cbor break (to end indefinite-length text or byte string) */
				start = _lf_cbor_encode_byte(&ctx->encode.cbor, start, stop, 0xFF);
				if (start == NULL)
					return NULL;
			}
		}

		*start = '\0';
		return start;
	}

	return NULL;
}

/*
 * Encode the string.
 */
static char *lf_encode_string(char *start, char *stop,
                              const char escape, const long *map,
                              const char *string,
                              struct lf_buildctx *ctx)
{
	return _lf_encode_bytes(start, stop, escape, map,
	                        string, NULL, ctx);
}

/*
 * Encode the chunk.
 */
static char *lf_encode_chunk(char *start, char *stop,
                             const char escape, const long *map,
                             const struct buffer *chunk,
                             struct lf_buildctx *ctx)
{
	return _lf_encode_bytes(start, stop, escape, map,
	                        chunk->area, chunk->area + chunk->data,
	                        ctx);
}

/*
 * Write a raw string in the log string
 * Take care of escape option
 *
 * When using json encoding, string will be escaped according
 * to json escape map
 *
 * When using cbor encoding, escape option is ignored.
 *
 * Return the address of the \0 character, or NULL on error
 */
static inline char *_lf_text_len(char *dst, const char *src,
                                 size_t len, size_t size, struct lf_buildctx *ctx)
{
	const long *escape_map = NULL;
	char *ret;

	if (ctx->options & LOG_OPT_ENCODE_JSON)
		escape_map = json_escape_map;
	else if (ctx->options & LOG_OPT_ESC)
		escape_map = rfc5424_escape_map;

	if (src && len) {
		if (ctx->options & LOG_OPT_ENCODE_CBOR) {
			/* it's actually less costly to compute the actual text size to
			 * write a single fixed length text at once rather than emitting
			 * indefinite length text in cbor, because indefinite-length text
			 * has to be made of multiple chunks of known size as per RFC8949...
			 */
			len = strnlen2(src, len);

			ret = cbor_encode_text(&ctx->encode.cbor, dst, dst + size, src, len);
			if (ret == NULL)
				return NULL;
			len = ret - dst;
		}

		/* escape_string and strlcpy2 will both try to add terminating NULL-byte
		 * to dst
		 */
		else if (escape_map) {
			char *ret;

			ret = escape_string(dst, dst + size, '\\', escape_map, src, src + len);
			if (ret == NULL)
				return NULL;
			len = ret - dst;
		}
		else {
			if (++len > size)
				len = size;
			len = strlcpy2(dst, src, len);
		}
		dst += len;
		size -= len;
	}

	if (size < 1)
		return NULL;
	*dst = '\0';

	return dst;
}

/*
 * Quote a string, then leverage _lf_text_len() to write it
 */
static inline char *_lf_quotetext_len(char *dst, const char *src,
                                      size_t len, size_t size, struct lf_buildctx *ctx)
{
	if (size < 2)
		return NULL;

	*(dst++) = '"';
	size--;

	if (src && len) {
		char *ret;

		ret = _lf_text_len(dst, src, len, size, ctx);
		if (ret == NULL)
			return NULL;
		size -= (ret - dst);
		dst += (ret - dst);
	}

	if (size < 2)
		return NULL;
	*(dst++) = '"';

	*dst = '\0';
	return dst;
}

/*
 * Write a string in the log string
 * Take care of quote, mandatory and escape and encoding options
 *
 * Return the address of the \0 character, or NULL on error
 */
static char *lf_text_len(char *dst, const char *src, size_t len, size_t size, struct lf_buildctx *ctx)
{
	char *ret;

	if ((ctx->options & (LOG_OPT_QUOTE | LOG_OPT_ENCODE_JSON)))
		return _lf_quotetext_len(dst, src, len, size, ctx);

	ret = _lf_text_len(dst, src, len, size, ctx);
	if (dst != ret ||
	    (ctx->options & LOG_OPT_ENCODE_CBOR) ||
	    !(ctx->options & LOG_OPT_MANDATORY))
		return ret;

	/* empty output and "+M" option is set, try to print '-' */

	if (size < 2)
		return NULL;

	return _lf_text_len(dst, "-", 1, size, ctx);
}

/*
 * Same as lf_text_len() except that it ignores mandatory and quoting options.
 * Quoting is only performed when strictly required by the encoding method.
 */
static char *lf_rawtext_len(char *dst, const char *src, size_t len, size_t size, struct lf_buildctx *ctx)
{
	if (!ctx->in_text &&
	    (ctx->options & LOG_OPT_ENCODE_JSON))
		return _lf_quotetext_len(dst, src, len, size, ctx);
	return _lf_text_len(dst, src, len, size, ctx);
}

/* lf_text_len() helper when <src> is null-byte terminated */
static inline char *lf_text(char *dst, const char *src, size_t size, struct lf_buildctx *ctx)
{
	return lf_text_len(dst, src, size, size, ctx);
}

/* lf_rawtext_len() helper when <src> is null-byte terminated */
static inline char *lf_rawtext(char *dst, const char *src, size_t size, struct lf_buildctx *ctx)
{
	return lf_rawtext_len(dst, src, size, size, ctx);
}

/*
 * Write a IP address to the log string
 * +X option write in hexadecimal notation, most significant byte on the left
 */
static char *lf_ip(char *dst, const struct sockaddr *sockaddr, size_t size, struct lf_buildctx *ctx)
{
	char *ret = dst;
	int iret;
	char pn[INET6_ADDRSTRLEN];

	if (ctx->options & LOG_OPT_HEXA) {
		unsigned char *addr = NULL;
		switch (sockaddr->sa_family) {
		case AF_INET:
		{
			addr = (unsigned char *)&((struct sockaddr_in *)sockaddr)->sin_addr.s_addr;
			iret = snprintf(ctx->_buf, sizeof(ctx->_buf), "%02X%02X%02X%02X",
			                addr[0], addr[1], addr[2], addr[3]);
			if (iret < 0 || iret >= size)
				return NULL;
			ret = lf_rawtext(dst, ctx->_buf, size, ctx);

			break;
		}
		case AF_INET6:
		{
			addr = (unsigned char *)&((struct sockaddr_in6 *)sockaddr)->sin6_addr.s6_addr;
			iret = snprintf(ctx->_buf, sizeof(ctx->_buf),
			                "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			                addr[0], addr[1], addr[2], addr[3],
			                addr[4], addr[5], addr[6], addr[7],
			                addr[8], addr[9], addr[10], addr[11],
			                addr[12], addr[13], addr[14], addr[15]);
			if (iret < 0 || iret >= size)
				return NULL;
			ret = lf_rawtext(dst, ctx->_buf, size, ctx);

			break;
		}
		default:
			return NULL;
		}
	} else {
		addr_to_str((struct sockaddr_storage *)sockaddr, pn, sizeof(pn));
		ret = lf_text(dst, pn, size, ctx);
	}
	return ret;
}

/* Logformat expr wrapper to write a boolean according to node
 * encoding settings
 */
static char *lf_bool_encode(char *dst, size_t size, uint8_t value,
                            struct lf_buildctx *ctx)
{
	/* encode as a regular bool value */

	if (ctx->options & LOG_OPT_ENCODE_JSON) {
		char *ret = dst;
		int iret;

		if (value)
			iret = snprintf(dst, size, "true");
		else
			iret = snprintf(dst, size, "false");

		if (iret < 0 || iret >= size)
			return NULL;
		ret += iret;
		return ret;
	}
	if (ctx->options & LOG_OPT_ENCODE_CBOR) {
		if (value)
			return _lf_cbor_encode_byte(&ctx->encode.cbor, dst, dst + size, 0xF5);
		return _lf_cbor_encode_byte(&ctx->encode.cbor, dst, dst + size, 0xF4);
	}

	return NULL; /* not supported */
}

/* Logformat expr wrapper to write an integer according to node
 * encoding settings and typecast settings.
 */
static char *lf_int_encode(char *dst, size_t size, int64_t value,
                           struct lf_buildctx *ctx)
{
	if (ctx->typecast == SMP_T_BOOL) {
		/* either true or false */
		return lf_bool_encode(dst, size, !!value, ctx);
	}

	if (ctx->options & LOG_OPT_ENCODE_JSON) {
		char *ret = dst;
		int iret = 0;

		if (ctx->typecast == SMP_T_STR) {
			/* encode as a string number (base10 with "quotes"):
			 *   may be useful to work around the limited resolution
			 *   of JS number types for instance
			 */
			iret = snprintf(dst, size, "\"%lld\"", (long long int)value);
		}
		else {
			/* encode as a regular int64 number (base10) */
			iret = snprintf(dst, size, "%lld", (long long int)value);
		}

		if (iret < 0 || iret >= size)
			return NULL;
		ret += iret;

		return ret;
	}
	else if (ctx->options & LOG_OPT_ENCODE_CBOR) {
		/* Always print as a regular int64 number (STR typecast isn't
		 * supported)
		 */
		return cbor_encode_int64(&ctx->encode.cbor, dst, dst + size, value);
	}

	return NULL; /* not supported */
}

enum lf_int_hdl {
	LF_INT_LTOA = 0,
	LF_INT_LLTOA,
	LF_INT_ULTOA,
	LF_INT_UTOA_PAD_4,
};

/*
 * Logformat expr wrapper to write an integer, uses <dft_hdl> to know
 * how to encode the value by default (if no encoding is used)
 */
static inline char *lf_int(char *dst, size_t size, int64_t value,
                           struct lf_buildctx *ctx,
                           enum lf_int_hdl dft_hdl)
{
	if (ctx->options & LOG_OPT_ENCODE)
		return lf_int_encode(dst, size, value, ctx);

	switch (dft_hdl) {
		case LF_INT_LTOA:
			return ltoa_o(value, dst, size);
		case LF_INT_LLTOA:
			return lltoa(value, dst, size);
		case LF_INT_ULTOA:
			return ultoa_o(value, dst, size);
		case LF_INT_UTOA_PAD_4:
		{
			if (size < 4)
				return NULL;
			return utoa_pad(value, dst, 4);
		}
	}
	return NULL;
}

/*
 * Write a port to the log
 * +X option write in hexadecimal notation, most significant byte on the left
 */
static char *lf_port(char *dst, const struct sockaddr *sockaddr, size_t size, struct lf_buildctx *ctx)
{
	char *ret = dst;
	int iret;

	if (ctx->options & LOG_OPT_HEXA) {
		const unsigned char *port = (const unsigned char *)&((struct sockaddr_in *)sockaddr)->sin_port;

		iret = snprintf(ctx->_buf, sizeof(ctx->_buf), "%02X%02X", port[0], port[1]);
		if (iret < 0 || iret >= size)
			return NULL;
		ret = lf_rawtext(dst, ctx->_buf, size, ctx);
	} else {
		ret = lf_int(dst, size, get_host_port((struct sockaddr_storage *)sockaddr),
		             ctx, LF_INT_LTOA);
	}
	return ret;
}

/*
 * This function sends a syslog message.
 * <target> is the actual log target where log will be sent,
 *
 * Message will be prefixed by header according to <hdr> setting.
 * Final message will be truncated <maxlen> parameter and will be
 * terminated with an LF character.
 *
 * Does not return any error
 */
static inline void __do_send_log(struct log_target *target, struct log_header hdr,
                                 int nblogger, size_t maxlen,
                                 char *message, size_t size)
{
	static THREAD_LOCAL struct iovec iovec[NB_LOG_HDR_MAX_ELEMENTS+1+1] = { }; /* header elements + message + LF */
	static THREAD_LOCAL struct msghdr msghdr = {
		//.msg_iov = iovec,
		.msg_iovlen = NB_LOG_HDR_MAX_ELEMENTS+2
	};
	static THREAD_LOCAL int logfdunix = -1;	/* syslog to AF_UNIX socket */
	static THREAD_LOCAL int logfdinet = -1;	/* syslog to AF_INET socket */
	const struct protocol *proto;
	int *plogfd;
	int sent;
	size_t nbelem;
	struct ist *msg_header = NULL;

	msghdr.msg_iov = iovec;

	/* historically some messages used to already contain the trailing LF
	 * or Zero. Let's remove all trailing LF or Zero
	 */
	while (size && (message[size-1] == '\n' || (message[size-1] == 0)))
		size--;

	if (target->type == LOG_TARGET_BUFFER) {
		plogfd = NULL;
		goto send;
	}
	else if (target->addr->ss_family == AF_CUST_EXISTING_FD) {
		/* the socket's address is a file descriptor */
		plogfd = (int *)&((struct sockaddr_in *)target->addr)->sin_addr.s_addr;
	}
	else if (real_family(target->addr->ss_family) == AF_UNIX)
		plogfd = &logfdunix;
	else
		plogfd = &logfdinet;

	if (plogfd && unlikely(*plogfd < 0)) {
		/* socket not successfully initialized yet */

		/* WT: this is not compliant with AF_CUST_* usage but we don't use that
		 * with DNS at the moment.
		 */
		proto = protocol_lookup(target->addr->ss_family, PROTO_TYPE_DGRAM, 1);
		BUG_ON(!proto);
		if ((*plogfd = socket(proto->fam->sock_domain, proto->sock_type, proto->sock_prot)) < 0) {
			static char once;

			if (!once) {
				once = 1; /* note: no need for atomic ops here */
				ha_alert("socket() failed in logger #%d: %s (errno=%d)\n",
						 nblogger, strerror(errno), errno);
			}
			return;
		} else {
			/* we don't want to receive anything on this socket */
			setsockopt(*plogfd, SOL_SOCKET, SO_RCVBUF, &zero, sizeof(zero));
			/* we may want to adjust the output buffer (tune.sndbuf.backend) */
			if (global.tune.backend_sndbuf)
				setsockopt(*plogfd, SOL_SOCKET, SO_SNDBUF, &global.tune.backend_sndbuf, sizeof(global.tune.backend_sndbuf));
			/* does nothing under Linux, maybe needed for others */
			shutdown(*plogfd, SHUT_RD);
			fd_set_cloexec(*plogfd);
		}
	}

	msg_header = build_log_header(hdr, &nbelem);
 send:
	if (target->type == LOG_TARGET_BUFFER) {
		struct ist msg;
		size_t e_maxlen = maxlen;

		msg = ist2(message, size);

		/* make room for the final '\n' which may be forcefully inserted
		 * by tcp forwarder applet (sink_forward_io_handler)
		 */
		e_maxlen -= 1;

		sent = sink_write(target->sink, hdr, e_maxlen, &msg, 1);
	}
	else if (target->addr->ss_family == AF_CUST_EXISTING_FD) {
		struct ist msg;

		msg = ist2(message, size);

		sent = fd_write_frag_line(*plogfd, maxlen, msg_header, nbelem, &msg, 1, 1);
	}
	else {
		int i = 0;
		int totlen = maxlen - 1; /* save space for the final '\n' */

		for (i = 0 ; i < nbelem ; i++ ) {
			iovec[i].iov_base = msg_header[i].ptr;
			iovec[i].iov_len  = msg_header[i].len;
			if (totlen <= iovec[i].iov_len) {
				iovec[i].iov_len = totlen;
				totlen = 0;
				break;
			}
			totlen -= iovec[i].iov_len;
		}
		if (totlen) {
			iovec[i].iov_base = message;
			iovec[i].iov_len  = size;
			if (totlen <= iovec[i].iov_len)
				iovec[i].iov_len = totlen;
			i++;
		}
		iovec[i].iov_base = "\n"; /* insert a \n at the end of the message */
		iovec[i].iov_len = 1;
		i++;

		msghdr.msg_iovlen = i;
		msghdr.msg_name = (struct sockaddr *)target->addr;
		msghdr.msg_namelen = get_addr_len(target->addr);

		sent = sendmsg(*plogfd, &msghdr, MSG_DONTWAIT | MSG_NOSIGNAL);
	}

	if (sent < 0) {
		static char once;

		if (errno == EAGAIN || errno == EWOULDBLOCK)
			_HA_ATOMIC_INC(&dropped_logs);
		else if (!once) {
			once = 1; /* note: no need for atomic ops here */
			ha_alert("sendmsg()/writev() failed in logger #%d: %s (errno=%d)\n",
					 nblogger, strerror(errno), errno);
		}
	}
}

/* does the same as __do_send_log() does for a single target, but here the log
 * will be sent according to the log backend's lb settings. The function will
 * leverage __do_send_log() function to actually send the log messages.
 */
static inline void __do_send_log_backend(struct proxy *be, struct log_header hdr,
                                         int nblogger, size_t maxlen,
                                         char *message, size_t size)
{
	struct server *srv = NULL;

	/* log-balancing logic: */

	if ((be->lbprm.algo & BE_LB_ALGO) == BE_LB_ALGO_RR) {
		srv = fwrr_get_next_server(be, NULL);
	}
	else if ((be->lbprm.algo & BE_LB_ALGO) == BE_LB_ALGO_SS) {
		/* sticky mode: use first server in the pool, which will always stay
		 * first during dequeuing and requeuing, unless it becomes unavailable
		 * and will be replaced by another one
		 */
		srv = ss_get_server(be);
	}
	else if ((be->lbprm.algo & BE_LB_ALGO) == BE_LB_ALGO_RND) {
		unsigned int hash;

		hash = statistical_prng(); /* random */
		srv = chash_get_server_hash(be, hash, NULL);
	}
	else if ((be->lbprm.algo & BE_LB_ALGO) == BE_LB_ALGO_LH) {
		struct sample result;

		/* log-balance hash */
		memset(&result, 0, sizeof(result));
		result.data.type = SMP_T_STR;
		result.flags = SMP_F_CONST;
		result.data.u.str.area = message;
		result.data.u.str.data = size;
		result.data.u.str.size = size + 1; /* with terminating NULL byte */
		if (sample_process_cnv(be->lbprm.expr, &result)) {
			/* gen_hash takes binary input, ensure that we provide such value to it */
			if (result.data.type == SMP_T_BIN || sample_casts[result.data.type][SMP_T_BIN]) {
				unsigned int hash;

				sample_casts[result.data.type][SMP_T_BIN](&result);
				hash = gen_hash(be, result.data.u.str.area, result.data.u.str.data);
				srv = map_get_server_hash(be, hash);
			}
		}
	}

	if (!srv) {
		/* no srv available, can't log */
		goto drop;
	}

	__do_send_log(srv->log_target, hdr, nblogger, maxlen, message, size);
	return;

 drop:
	_HA_ATOMIC_INC(&dropped_logs);
}

static inline void __send_log_set_metadata_sd(struct ist *metadata, char *sd, size_t sd_size)
{
	metadata[LOG_META_STDATA] = ist2(sd, sd_size);

	/* Remove trailing space of structured data */
	while (metadata[LOG_META_STDATA].len && metadata[LOG_META_STDATA].ptr[metadata[LOG_META_STDATA].len-1] == ' ')
		metadata[LOG_META_STDATA].len--;
}

/* provided to low-level process_send_log() helper, may be NULL */
struct process_send_log_ctx {
	struct session *sess;
	struct stream *stream;
	struct log_orig origin;
};

static inline void _process_send_log_final(struct logger *logger, struct log_header hdr,
                                           char *message, size_t size, int nblogger)
{
	if (logger->target.type == LOG_TARGET_BACKEND) {
		__do_send_log_backend(logger->target.be, hdr, nblogger, logger->maxlen, message, size);
	}
	else {
		/* normal target */
		__do_send_log(&logger->target, hdr, nblogger, logger->maxlen, message, size);
	}
}

static inline void _process_send_log_override(struct process_send_log_ctx *ctx,
                                              struct logger *logger, struct log_header hdr,
                                              char *message, size_t size, int nblogger)
{
	struct log_profile *prof = logger->prof;
	struct log_profile_step *step = NULL;
	struct ist orig_tag = hdr.metadata[LOG_META_TAG];
	struct ist orig_sd = hdr.metadata[LOG_META_STDATA];
	enum log_orig_id orig = (ctx) ? ctx->origin.id : LOG_ORIG_UNSPEC;
	uint16_t orig_fl = (ctx) ? ctx->origin.flags : LOG_ORIG_FL_NONE;

	BUG_ON(!prof);

	if (!b_is_null(&prof->log_tag))
		hdr.metadata[LOG_META_TAG] = ist2(prof->log_tag.area, prof->log_tag.data);

	/* check if there is a profile step override matching
	 * current logging step
	 */
	switch (orig) {
		case LOG_ORIG_SESS_ERROR:
		case LOG_ORIG_SESS_KILL:
			if (prof->error)
				step = prof->error;
			break;
		case LOG_ORIG_TXN_ACCEPT:
			if (prof->accept)
				step = prof->accept;
			break;
		case LOG_ORIG_TXN_REQUEST:
			if (prof->request)
				step = prof->request;
			break;
		case LOG_ORIG_TXN_CONNECT:
			if (prof->connect)
				step = prof->connect;
			break;
		case LOG_ORIG_TXN_RESPONSE:
			if (prof->response)
				step = prof->response;
			break;
		case LOG_ORIG_TXN_CLOSE:
			if (prof->close)
				step = prof->close;
			break;
		default:
		{
			struct log_profile_step_extra *extra;

			/* catchall for extra log origins */
			if ((orig_fl & LOG_ORIG_FL_ERROR) && prof->error) {
				/* extra orig with explicit error flag, must be
				 * handled as an error
				 */
				step = prof->error;
				break;
			}

			/* check if there is a log step defined for this log origin */
			extra = container_of_safe(eb32_lookup(&prof->extra, orig),
			                          struct log_profile_step_extra, node);
			if (extra)
				step = &extra->step;
			break;
		}
	}

	if (!step && prof->any)
		step = prof->any;

	if (ctx && ctx->sess && step) {
		if (step->flags & LOG_PS_FL_DROP)
			goto end; // skip logging

		/* we may need to rebuild message using lf_expr from profile
		 * step and possibly sd metadata if provided on the profile
		 */
		if (!lf_expr_isempty(&step->logformat)) {
			size = sess_build_logline_orig(ctx->sess, ctx->stream,
			                               logline_lpf, global.max_syslog_len,
			                               &step->logformat,
			                               ctx->origin);
			if (size == 0)
				goto end;
			message = logline_lpf;
		}
		if (!lf_expr_isempty(&step->logformat_sd)) {
			size_t sd_size;

			sd_size = sess_build_logline_orig(ctx->sess, ctx->stream,
			                                  logline_rfc5424_lpf, global.max_syslog_len,
			                                  &step->logformat_sd,
			                                  ctx->origin);
			__send_log_set_metadata_sd(hdr.metadata, logline_rfc5424_lpf, sd_size);
		}
	}

	_process_send_log_final(logger, hdr, message, size, nblogger);

 end:
	/* restore original metadata values */
	hdr.metadata[LOG_META_TAG] = orig_tag;
	hdr.metadata[LOG_META_STDATA] = orig_sd;
}

/*
 * This function sends a syslog message.
 * It doesn't care about errors nor does it report them.
 * The argument <metadata> MUST be an array of size
 * LOG_META_FIELDS*sizeof(struct ist)  containing
 * data to build the header.
 */
static void process_send_log(struct process_send_log_ctx *ctx,
                             struct list *loggers, int level, int facility,
                             struct ist *metadata, char *message, size_t size)
{
	struct logger *logger;
	int nblogger;

	/* Send log messages to syslog server. */
	nblogger = 0;
	list_for_each_entry(logger, loggers, list) {
		int in_range = 1;

		/* we can filter the level of the messages that are sent to each logger */
		if (level > logger->level)
			continue;

		if (logger->lb.smp_rgs) {
			struct smp_log_range *smp_rg;
			uint next_idx, curr_rg;
			ullong curr_rg_idx, next_rg_idx;

			curr_rg_idx = _HA_ATOMIC_LOAD(&logger->lb.curr_rg_idx);
			do {
				next_idx = (curr_rg_idx & 0xFFFFFFFFU) + 1;
				curr_rg  = curr_rg_idx >> 32;
				smp_rg = &logger->lb.smp_rgs[curr_rg];

				/* check if the index we're going to take is within range  */
				in_range = smp_rg->low <= next_idx && next_idx <= smp_rg->high;
				if (in_range) {
					/* Let's consume this range. */
					if (next_idx == smp_rg->high) {
						/* If consumed, let's select the next range. */
						curr_rg = (curr_rg + 1) % logger->lb.smp_rgs_sz;
					}
				}

				next_idx = next_idx % logger->lb.smp_sz;
				next_rg_idx = ((ullong)curr_rg << 32) + next_idx;
			} while (!_HA_ATOMIC_CAS(&logger->lb.curr_rg_idx, &curr_rg_idx, next_rg_idx) &&
				 __ha_cpu_relax());
		}
		if (in_range) {
			struct log_header hdr;

			hdr.level = MAX(level, logger->minlvl);
			hdr.facility = (facility == -1) ? logger->facility : facility;
			hdr.format = logger->format;
			hdr.metadata = metadata;

			nblogger += 1;

			/* logger may use a profile to override a few things */
			if (unlikely(logger->prof))
				_process_send_log_override(ctx, logger, hdr, message, size, nblogger);
			else
				_process_send_log_final(logger, hdr, message, size, nblogger);
		}
	}
}

/*
 * This function sends a syslog message.
 * It doesn't care about errors nor does it report them.
 * The arguments <sd> and <sd_size> are used for the structured-data part
 * in RFC5424 formatted syslog messages.
 */
static void __send_log(struct process_send_log_ctx *ctx,
                       struct list *loggers, struct buffer *tagb, int level,
                       char *message, size_t size, char *sd, size_t sd_size)
{
	static THREAD_LOCAL pid_t curr_pid;
	static THREAD_LOCAL char pidstr[16];
	static THREAD_LOCAL struct ist metadata[LOG_META_FIELDS];

	if (loggers == NULL) {
		if (!LIST_ISEMPTY(&global.loggers)) {
			loggers = &global.loggers;
		}
	}
	if (!loggers || LIST_ISEMPTY(loggers))
		return;

	if (!metadata[LOG_META_HOST].len) {
		if (global.log_send_hostname)
			metadata[LOG_META_HOST] = ist(global.log_send_hostname);
	}

	if (!tagb || !tagb->area)
		tagb = &global.log_tag;

	if (tagb)
		metadata[LOG_META_TAG] = ist2(tagb->area, tagb->data);

	if (unlikely(curr_pid != getpid()))
		metadata[LOG_META_PID].len = 0;

	if (!metadata[LOG_META_PID].len) {
		curr_pid = getpid();
		ltoa_o(curr_pid, pidstr, sizeof(pidstr));
		metadata[LOG_META_PID] = ist2(pidstr, strlen(pidstr));
	}

	__send_log_set_metadata_sd(metadata, sd, sd_size);

	return process_send_log(ctx, loggers, level, -1, metadata, message, size);
}

/*
 * This function sends the syslog message using a printf format string. It
 * expects an LF-terminated message.
 */
void send_log(struct proxy *p, int level, const char *format, ...)
{
	va_list argp;
	int  data_len;

	if (level < 0 || format == NULL || logline == NULL)
		return;

	va_start(argp, format);
	data_len = vsnprintf(logline, global.max_syslog_len, format, argp);
	if (data_len < 0 || data_len > global.max_syslog_len)
		data_len = global.max_syslog_len;
	va_end(argp);

	__send_log(NULL, (p ? &p->loggers : NULL),
	           (p ? &p->log_tag : NULL), level,
		   logline, data_len, default_rfc5424_sd_log_format, 2);
}

/*
 * This function builds a log header according to <hdr> settings.
 *
 * If hdr.format is set to LOG_FORMAT_UNSPEC, it tries to determine
 * format based on hdr.metadata. It is useful for log-forwarding to be
 * able to forward any format without settings.
 *
 * This function returns a struct ist array of elements of the header
 * nbelem is set to the number of available elements.
 * This function returns currently a maximum of NB_LOG_HDR_IST_ELEMENTS
 * elements.
 */
struct ist *build_log_header(struct log_header hdr, size_t *nbelem)
{
	static THREAD_LOCAL struct {
		struct ist ist_vector[NB_LOG_HDR_MAX_ELEMENTS];
		char timestamp_buffer[LOG_LEGACYTIME_LEN+1+1];
		time_t cur_legacy_time;
		char priority_buffer[6];
	} hdr_ctx = { .priority_buffer = "<<<<>" };

	struct tm logtime;
	int len;
	int fac_level = 0;
	time_t time = date.tv_sec;
	struct ist *metadata = hdr.metadata;
	enum log_fmt format = hdr.format;
	int facility = hdr.facility;
	int level = hdr.level;

	*nbelem = 0;


	if (format == LOG_FORMAT_UNSPEC) {
		format = LOG_FORMAT_RAW;
		if (metadata) {
			/* If a hostname is set, it appears we want to perform syslog
			 * because only rfc5427 or rfc3164 support an hostname.
			 */
			if (metadata[LOG_META_HOST].len) {
				/* If a rfc5424 compliant timestamp is used we consider
				 * that output format is rfc5424, else legacy format
				 * is used as specified default for local logs
				 * in documentation.
				 */
				if ((metadata[LOG_META_TIME].len == 1 && metadata[LOG_META_TIME].ptr[0] == '-')
				    || (metadata[LOG_META_TIME].len >= LOG_ISOTIME_MINLEN))
					format = LOG_FORMAT_RFC5424;
				else
					format = LOG_FORMAT_RFC3164;
			}
			else if (metadata[LOG_META_TAG].len) {
				/* Tag is present but no hostname, we should
				 * consider we try to emit a local log
				 * in legacy format (analog to RFC3164 but
				 * with stripped hostname).
				 */
				format = LOG_FORMAT_LOCAL;
			}
			else if (metadata[LOG_META_PRIO].len) {
				/* the source seems a parsed message
				 * offering a valid level/prio prefix
				 * so we consider this format.
				 */
				format = LOG_FORMAT_PRIO;
			}
		}
	}

	/* prepare priority, stored into 1 single elem */
	switch (format) {
		case LOG_FORMAT_LOCAL:
		case LOG_FORMAT_RFC3164:
		case LOG_FORMAT_RFC5424:
		case LOG_FORMAT_PRIO:
			fac_level = facility << 3;
			/* further format ignore the facility */
			__fallthrough;
		case LOG_FORMAT_TIMED:
		case LOG_FORMAT_SHORT:
			fac_level += level;
			hdr_ctx.ist_vector[*nbelem].ptr = &hdr_ctx.priority_buffer[3]; /* last digit of the log level */
			do {
				*hdr_ctx.ist_vector[*nbelem].ptr = '0' + fac_level % 10;
				fac_level /= 10;
				hdr_ctx.ist_vector[*nbelem].ptr--;
			} while (fac_level && hdr_ctx.ist_vector[*nbelem].ptr > &hdr_ctx.priority_buffer[0]);
			*hdr_ctx.ist_vector[*nbelem].ptr = '<';
			hdr_ctx.ist_vector[(*nbelem)++].len = &hdr_ctx.priority_buffer[5] - hdr_ctx.ist_vector[0].ptr;
			break;
		case LOG_FORMAT_ISO:
		case LOG_FORMAT_RAW:
			break;
		case LOG_FORMAT_UNSPEC:
		case LOG_FORMATS:
			ABORT_NOW();
	}


	/* prepare timestamp, stored into a max of 4 elems */
	switch (format) {
		case LOG_FORMAT_LOCAL:
		case LOG_FORMAT_RFC3164:
			/* rfc3164 ex: 'Jan  1 00:00:00 ' */
			if (metadata && metadata[LOG_META_TIME].len == LOG_LEGACYTIME_LEN) {
				hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_TIME];
				hdr_ctx.ist_vector[(*nbelem)++] = ist2(" ", 1);
				/* time is set, break immediately */
				break;
			}
			else if (metadata && metadata[LOG_META_TIME].len >= LOG_ISOTIME_MINLEN) {
				int month;
				char *timestamp = metadata[LOG_META_TIME].ptr;

				/* iso time always begins like this: '1970-01-01T00:00:00' */

				/* compute month */
				month = 10*(timestamp[5] - '0') + (timestamp[6] - '0');
				if (month)
					month--;
				if (month <= 11) {
					/* builds log prefix ex: 'Jan  1 ' */
					len = snprintf(hdr_ctx.timestamp_buffer, sizeof(hdr_ctx.timestamp_buffer),
					               "%s %c%c ", monthname[month],
					               timestamp[8] != '0' ? timestamp[8] : ' ',
					               timestamp[9]);
					/* we reused the timestamp_buffer, signal that it does not
					 * contain local time anymore
					 */
					hdr_ctx.cur_legacy_time = 0;
					if (len == 7) {
						hdr_ctx.ist_vector[(*nbelem)++] = ist2(&hdr_ctx.timestamp_buffer[0], len);
						/* adds 'HH:MM:SS' from iso time */
						hdr_ctx.ist_vector[(*nbelem)++] = ist2(&timestamp[11], 8);
						hdr_ctx.ist_vector[(*nbelem)++] = ist2(" ", 1);
						/* we successfully reuse iso time, we can break */
						break;
					}
				}
				/* Failed to reuse isotime time, fallback to local legacy time */
			}

			if (unlikely(time != hdr_ctx.cur_legacy_time)) {
				/* re-builds timestamp from the current local time */
				get_localtime(time, &logtime);

				len = snprintf(hdr_ctx.timestamp_buffer, sizeof(hdr_ctx.timestamp_buffer),
				               "%s %2d %02d:%02d:%02d ",
				               monthname[logtime.tm_mon],
				               logtime.tm_mday, logtime.tm_hour, logtime.tm_min, logtime.tm_sec);
				if (len != LOG_LEGACYTIME_LEN+1)
					hdr_ctx.cur_legacy_time = 0;
				else
					hdr_ctx.cur_legacy_time = time;
			}
			if (likely(hdr_ctx.cur_legacy_time))
				hdr_ctx.ist_vector[(*nbelem)++] = ist2(&hdr_ctx.timestamp_buffer[0], LOG_LEGACYTIME_LEN+1);
			else
				hdr_ctx.ist_vector[(*nbelem)++] = ist2("Jan  1 00:00:00 ", LOG_LEGACYTIME_LEN+1);
			break;
		case LOG_FORMAT_RFC5424:
			/* adds rfc5425 version prefix */
			hdr_ctx.ist_vector[(*nbelem)++] = ist2("1 ", 2);
			if (metadata && metadata[LOG_META_TIME].len == 1 && metadata[LOG_META_TIME].ptr[0] == '-') {
				/* submitted len is NILVALUE, it is a valid timestamp for rfc5425 */
				hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_TIME];
				hdr_ctx.ist_vector[(*nbelem)++] = ist2(" ", 1);
				break;
			}
			/* let continue as 'timed' and 'iso' format for usual timestamp */
			__fallthrough;
		case LOG_FORMAT_TIMED:
		case LOG_FORMAT_ISO:
			/* ISO format ex: '1900:01:01T12:00:00.123456Z'
			 *                '1900:01:01T14:00:00+02:00'
			 *                '1900:01:01T10:00:00.123456-02:00'
			 */
			if (metadata && metadata[LOG_META_TIME].len >= LOG_ISOTIME_MINLEN) {
				hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_TIME];
				hdr_ctx.ist_vector[(*nbelem)++] = ist2(" ", 1);
				/* time is set, break immediately */
				break;
			}
			else if (metadata && metadata[LOG_META_TIME].len == LOG_LEGACYTIME_LEN) {
				int month;
				char *timestamp = metadata[LOG_META_TIME].ptr;

				for (month = 0; month < 12; month++)
					if (!memcmp(monthname[month], timestamp, 3))
						break;

				if (month < 12) {

					/* get local time to retrieve year */
					get_localtime(time, &logtime);

					/* year seems changed since log */
					if (logtime.tm_mon < month)
						logtime.tm_year--;

					/* builds rfc5424 prefix ex: '1900-01-01T' */
					len = snprintf(hdr_ctx.timestamp_buffer, sizeof(hdr_ctx.timestamp_buffer),
							   "%4d-%02d-%c%cT",
							   logtime.tm_year+1900, month+1,
							   timestamp[4] != ' ' ? timestamp[4] : '0',
							   timestamp[5]);

					/* we reused the timestamp_buffer, signal that it does not
					 * contain local time anymore
					 */
					hdr_ctx.cur_legacy_time = 0;
					if (len == 11) {
						hdr_ctx.ist_vector[(*nbelem)++] = ist2(&hdr_ctx.timestamp_buffer[0], len);
						/* adds HH:MM:SS from legacy timestamp */
						hdr_ctx.ist_vector[(*nbelem)++] = ist2(&timestamp[7], 8);
						/* skip secfraq because it is optional */
						/* according to rfc: -00:00 means we don't know the timezone */
						hdr_ctx.ist_vector[(*nbelem)++] = ist2("-00:00 ", 7);
						/* we successfully reuse legacy time, we can break */
						break;
					}
				}
				/* Failed to reuse legacy time, fallback to local iso time */
			}
			hdr_ctx.ist_vector[(*nbelem)++] = ist2(timeofday_as_iso_us(1), LOG_ISOTIME_MAXLEN + 1);
			break;
		case LOG_FORMAT_PRIO:
		case LOG_FORMAT_SHORT:
		case LOG_FORMAT_RAW:
			break;
		case LOG_FORMAT_UNSPEC:
		case LOG_FORMATS:
			ABORT_NOW();
	}

	/* prepare other meta data, stored into a max of 10 elems */
	switch (format) {
		case LOG_FORMAT_RFC3164:
			if (metadata && metadata[LOG_META_HOST].len) {
				hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_HOST];
				hdr_ctx.ist_vector[(*nbelem)++] = ist2(" ", 1);
			}
			else /* the caller MUST fill the hostname, this field is mandatory */
				hdr_ctx.ist_vector[(*nbelem)++] = ist2("localhost ", 10);
			__fallthrough;
		case LOG_FORMAT_LOCAL:
			if (!metadata || !metadata[LOG_META_TAG].len)
				break;

			hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_TAG];
			if (metadata[LOG_META_PID].len) {
				hdr_ctx.ist_vector[(*nbelem)++] = ist2("[", 1);
				hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_PID];
				hdr_ctx.ist_vector[(*nbelem)++] = ist2("]", 1);
			}
			hdr_ctx.ist_vector[(*nbelem)++] = ist2(": ", 2);
			break;
		case LOG_FORMAT_RFC5424:
			if (metadata && metadata[LOG_META_HOST].len) {
				hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_HOST];
				hdr_ctx.ist_vector[(*nbelem)++] = ist2(" ", 1);
			}
			else
				hdr_ctx.ist_vector[(*nbelem)++] = ist2("- ", 2);

			if (metadata && metadata[LOG_META_TAG].len) {
				hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_TAG];
				hdr_ctx.ist_vector[(*nbelem)++] = ist2(" ", 1);
			}
			else
				hdr_ctx.ist_vector[(*nbelem)++] = ist2("- ", 2);

			if (metadata && metadata[LOG_META_PID].len) {
				hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_PID];
				hdr_ctx.ist_vector[(*nbelem)++] = ist2(" ", 1);
			}
			else
				hdr_ctx.ist_vector[(*nbelem)++] = ist2("- ", 2);

			if (metadata && metadata[LOG_META_MSGID].len) {
				hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_MSGID];
				hdr_ctx.ist_vector[(*nbelem)++] = ist2(" ", 1);
			}
			else
				hdr_ctx.ist_vector[(*nbelem)++] = ist2("- ", 2);

			if (metadata && metadata[LOG_META_STDATA].len) {
				hdr_ctx.ist_vector[(*nbelem)++] = metadata[LOG_META_STDATA];
				hdr_ctx.ist_vector[(*nbelem)++] = ist2(" ", 1);
			}
			else
				hdr_ctx.ist_vector[(*nbelem)++] = ist2("- ", 2);
			break;
		case LOG_FORMAT_PRIO:
		case LOG_FORMAT_SHORT:
		case LOG_FORMAT_TIMED:
		case LOG_FORMAT_ISO:
		case LOG_FORMAT_RAW:
			break;
		case LOG_FORMAT_UNSPEC:
		case LOG_FORMATS:
			ABORT_NOW();
	}

	return hdr_ctx.ist_vector;
}

const char sess_cookie[8]     = "NIDVEOU7";	/* No cookie, Invalid cookie, cookie for a Down server, Valid cookie, Expired cookie, Old cookie, Unused, unknown */
const char sess_set_cookie[8] = "NPDIRU67";	/* No set-cookie, Set-cookie found and left unchanged (passive),
						   Set-cookie Deleted, Set-Cookie Inserted, Set-cookie Rewritten,
						   Set-cookie Updated, unknown, unknown */

/*
 * try to write a cbor byte if there is enough space, or goto out
 */
#define LOG_CBOR_BYTE(x) do {                                          \
			ret = _lf_cbor_encode_byte(&ctx->encode.cbor,  \
			                           tmplog,             \
			                           dst + maxsize,      \
			                           (x));               \
			if (ret == NULL)                               \
				goto out;                              \
			tmplog = ret;                                  \
		} while (0)

/*
 * try to write a character if there is enough space, or goto out
 */
#define LOGCHAR(x) do { \
			if ((ctx->options & LOG_OPT_ENCODE_CBOR) &&            \
			    ctx->in_text) {                                    \
				char _x[1];                                    \
				/* encode the char as text chunk since we      \
				 * cannot just throw random bytes and expect   \
				 * cbor decoder to know how to handle them     \
				 */                                            \
				_x[0] = (x);                                   \
				ret = cbor_encode_text(&ctx->encode.cbor,      \
				                       tmplog,                 \
				                       dst + maxsize,          \
				                       _x, sizeof(_x));        \
				if (ret == NULL)                               \
					goto out;                              \
				tmplog = ret;                                  \
				break;                                         \
			}                                                      \
			if (tmplog < dst + maxsize - 1) {                      \
				*(tmplog++) = (x);                             \
			} else {                                               \
				goto out;                                      \
			}                                                      \
		} while(0)

/* indicate that a new variable-length text is starting, sets in_text
 * variable to indicate that a var text was started and deals with
 * encoding and options to know if some special treatment is needed.
 */
#define LOG_VARTEXT_START() do {                                               \
			ctx->in_text = 1;                                      \
			if (ctx->options & LOG_OPT_ENCODE_CBOR) {              \
				/* start indefinite-length cbor text */        \
				LOG_CBOR_BYTE(0x7F);                           \
				break;                                         \
			}                                                      \
			/* put the text within quotes if JSON encoding         \
			 * is used or quoting is enabled                       \
			 */                                                    \
			if (ctx->options &                                     \
			    (LOG_OPT_QUOTE | LOG_OPT_ENCODE_JSON)) {           \
				LOGCHAR('"');                                  \
			}                                                      \
		} while (0)

/* properly finish a variable text that was started using LOG_VARTEXT_START
 * checks the in_text variable to know if a text was started or not, and
 * deals with encoding and options to know if some special treatment is
 * needed.
 */
#define LOG_VARTEXT_END() do {                                                 \
			if (!ctx->in_text)                                     \
				break;                                         \
			ctx->in_text = 0;                                      \
			if (ctx->options & LOG_OPT_ENCODE_CBOR) {              \
				/* end indefinite-length cbor text with break*/\
				LOG_CBOR_BYTE(0xFF);                           \
				break;                                         \
			}                                                      \
			/* add the ending quote if JSON encoding is            \
			 * used or quoting is enabled                          \
			 */                                                    \
			if (ctx->options &                                     \
			    (LOG_OPT_QUOTE | LOG_OPT_ENCODE_JSON)) {           \
				LOGCHAR('"');                                  \
			}                                                      \
		} while (0)

/* Prints additional logvalue hint represented by <chr>.
 * It is useful to express that <chr> is not part of the "raw" value and
 * should be considered as optional metadata instead.
 */
#define LOGMETACHAR(chr) do {                                          \
			/* ignored when encoding is used */            \
			if (ctx->options & LOG_OPT_ENCODE)             \
				break;                                 \
			LOGCHAR(chr);                                  \
		} while (0)

/* indicate the start of a string array */
#define LOG_STRARRAY_START() do {                                      \
			if (ctx->options & LOG_OPT_ENCODE_JSON)        \
				LOGCHAR('[');                          \
			if (ctx->options & LOG_OPT_ENCODE_CBOR) {      \
				/* start indefinite-length array */    \
				LOG_CBOR_BYTE(0x9F);                   \
			}                                              \
		} while (0)

/* indicate that a new element is added to the string array */
#define LOG_STRARRAY_NEXT() do {                                       \
			if (ctx->options & LOG_OPT_ENCODE_CBOR)        \
				break;                                 \
			if (ctx->options & LOG_OPT_ENCODE_JSON) {      \
				LOGCHAR(',');                          \
				LOGCHAR(' ');                          \
			}                                              \
			else                                           \
				LOGCHAR(' ');                          \
		} while (0)

/* indicate the end of a string array */
#define LOG_STRARRAY_END() do {                                        \
			if (ctx->options & LOG_OPT_ENCODE_JSON)        \
				LOGCHAR(']');                          \
			if (ctx->options & LOG_OPT_ENCODE_CBOR) {      \
				/* cbor break */                       \
				LOG_CBOR_BYTE(0xFF);                   \
			}                                              \
		} while (0)

/* Initializes some log data at boot */
static void init_log()
{
	char *tmp;
	int i;

	/* Initialize the no escape map, which may be used to bypass escaping */
	memset(no_escape_map, 0, sizeof(no_escape_map));

	/* Initialize the escape map for the RFC5424 structured-data : '"\]'
	 * inside PARAM-VALUE should be escaped with '\' as prefix.
	 * See https://tools.ietf.org/html/rfc5424#section-6.3.3 for more
	 * details.
	 */
	memset(rfc5424_escape_map, 0, sizeof(rfc5424_escape_map));

	tmp = "\"\\]";
	while (*tmp) {
		ha_bit_set(*tmp, rfc5424_escape_map);
		tmp++;
	}

	/* Initialize the escape map for JSON strings : '"\' */
	memset(json_escape_map, 0, sizeof(json_escape_map));

	tmp = "\"\\";
	while (*tmp) {
		ha_bit_set(*tmp, json_escape_map);
		tmp++;
	}

	/* initialize the log header encoding map : '{|}"#' should be encoded with
	 * '#' as prefix, as well as non-printable characters ( <32 or >= 127 ).
	 * URL encoding only requires '"', '#' to be encoded as well as non-
	 * printable characters above.
	 */
	memset(hdr_encode_map, 0, sizeof(hdr_encode_map));
	memset(url_encode_map, 0, sizeof(url_encode_map));
	for (i = 0; i < 32; i++) {
		ha_bit_set(i, hdr_encode_map);
		ha_bit_set(i, url_encode_map);
	}
	for (i = 127; i < 256; i++) {
		ha_bit_set(i, hdr_encode_map);
		ha_bit_set(i, url_encode_map);
	}

	tmp = "\"#{|}";
	while (*tmp) {
		ha_bit_set(*tmp, hdr_encode_map);
		tmp++;
	}

	tmp = "\"#";
	while (*tmp) {
		ha_bit_set(*tmp, url_encode_map);
		tmp++;
	}

	/* initialize the http header encoding map. The draft httpbis define the
	 * header content as:
	 *
	 *    HTTP-message   = start-line
	 *                     *( header-field CRLF )
	 *                     CRLF
	 *                     [ message-body ]
	 *    header-field   = field-name ":" OWS field-value OWS
	 *    field-value    = *( field-content / obs-fold )
	 *    field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
	 *    obs-fold       = CRLF 1*( SP / HTAB )
	 *    field-vchar    = VCHAR / obs-text
	 *    VCHAR          = %x21-7E
	 *    obs-text       = %x80-FF
	 *
	 * All the chars are encoded except "VCHAR", "obs-text", SP and HTAB.
	 * The encoded chars are form 0x00 to 0x08, 0x0a to 0x1f and 0x7f. The
	 * "obs-fold" is voluntarily forgotten because haproxy remove this.
	 */
	memset(http_encode_map, 0, sizeof(http_encode_map));
	for (i = 0x00; i <= 0x08; i++)
		ha_bit_set(i, http_encode_map);
	for (i = 0x0a; i <= 0x1f; i++)
		ha_bit_set(i, http_encode_map);
	ha_bit_set(0x7f, http_encode_map);
}

INITCALL0(STG_PREPARE, init_log);

/* Initialize log buffers used for syslog messages */
int init_log_buffers()
{
	logline = my_realloc2(logline, global.max_syslog_len + 1);
	logline_rfc5424 = my_realloc2(logline_rfc5424, global.max_syslog_len + 1);
	if (!logline || !logline_rfc5424)
		return 0;
	if (!LIST_ISEMPTY(&log_profile_list)) {
		logline_lpf = my_realloc2(logline_lpf, global.max_syslog_len + 1);
		logline_rfc5424_lpf = my_realloc2(logline_rfc5424_lpf, global.max_syslog_len + 1);
		if (!logline_lpf || !logline_rfc5424_lpf)
			return 0;
	}
	return 1;
}

/* Deinitialize log buffers used for syslog messages */
void deinit_log_buffers()
{
	free(logline);
	free(logline_lpf);
	free(logline_rfc5424);
	free(logline_rfc5424_lpf);
	logline             = NULL;
	logline_lpf         = NULL;
	logline_rfc5424     = NULL;
	logline_rfc5424_lpf = NULL;
}

/* Deinitialize log forwarder proxies used for syslog messages */
void deinit_log_forward()
{
	struct proxy *p, *p0;

	p = cfg_log_forward;
	/* we need to manually clean cfg_log_forward proxy list */
	while (p) {
		p0 = p;
		p = p->next;
		free_proxy(p0);
	}
}

/* Releases memory for a single log-format node */
void free_logformat_node(struct logformat_node *node)
{
	if (!node)
		return;

	release_sample_expr(node->expr);
	node->expr = NULL;
	ha_free(&node->name);
	ha_free(&node->arg);
	ha_free(&node);
}

/* Releases memory allocated for a log-format string */
void free_logformat_list(struct list *fmt)
{
	struct logformat_node *lf, *lfb;

	if ((fmt == NULL) || LIST_ISEMPTY(fmt))
		return;

	list_for_each_entry_safe(lf, lfb, fmt, list) {
		LIST_DELETE(&lf->list);
		free_logformat_node(lf);
	}
}

/* Prepares log-format expression struct */
void lf_expr_init(struct lf_expr *expr)
{
	LIST_INIT(&expr->list);
	expr->flags = LF_FL_NONE;
	expr->str = NULL;
	expr->conf.file = NULL;
	expr->conf.line = 0;
}

/* Releases and resets a log-format expression */
void lf_expr_deinit(struct lf_expr *expr)
{
	if ((expr->flags & LF_FL_COMPILED))
		free_logformat_list(&expr->nodes.list);
	else
		logformat_str_free(&expr->str);
	free(expr->conf.file);
	/* remove from parent list (if any) */
	LIST_DEL_INIT(&expr->list);

	lf_expr_init(expr);
}

/* Transfer a compiled log-format expression from <src> to <dst>
 * at the end of the operation, <src> is reset
 */
void lf_expr_xfer(struct lf_expr *src, struct lf_expr *dst)
{
	struct logformat_node *lf, *lfb;

	/* first, reset any existing expr */
	lf_expr_deinit(dst);

	BUG_ON(!(src->flags & LF_FL_COMPILED));

	/* then proceed with transfer between <src> and <dst> */
	dst->conf.file = src->conf.file;
	dst->conf.line = src->conf.line;

	dst->flags |= LF_FL_COMPILED;
	LIST_INIT(&dst->nodes.list);

	list_for_each_entry_safe(lf, lfb, &src->nodes.list, list) {
		LIST_DELETE(&lf->list);
		LIST_APPEND(&dst->nodes.list, &lf->list);
	}

	/* replace <src> with <dst> in <src>'s list by first adding
	 * <dst> after <src>, then removing <src>...
	 */
	LIST_INSERT(&src->list, &dst->list);
	LIST_DEL_INIT(&src->list);

	/* src is now empty, perform an explicit reset */
	lf_expr_init(src);
}

/* tries to duplicate an uncompiled logformat expression from <orig> to <dest>
 *
 * Returns 1 on success and 0 on failure.
 */
int lf_expr_dup(const struct lf_expr *orig, struct lf_expr *dest)
{
	BUG_ON((orig->flags & LF_FL_COMPILED));
	lf_expr_deinit(dest);
	if (orig->str) {
		dest->str = logformat_str_dup(orig->str);
		if (!dest->str)
			goto error;
	}
	if (orig->conf.file) {
		dest->conf.file = strdup(orig->conf.file);
		if (!dest->conf.file)
			goto error;
	}
	dest->conf.line = orig->conf.line;

	return 1;

 error:
	lf_expr_deinit(dest);
	return 0;
}

/* Builds a log line in <dst> based on <lf_expr>, and stops before reaching
 * <maxsize> characters. Returns the size of the output string in characters,
 * not counting the trailing zero which is always added if the resulting size
 * is not zero. It requires a valid session and optionally a stream. If the
 * stream is NULL, default values will be assumed for the stream part.
 */
int sess_build_logline_orig(struct session *sess, struct stream *s,
                            char *dst, size_t maxsize, struct lf_expr *lf_expr,
                            struct log_orig log_orig)
{
	struct lf_buildctx *ctx = &lf_buildctx;
	struct proxy *fe = sess->fe;
	struct proxy *be;
	struct http_txn *txn;
	const struct strm_logs *logs;
	struct connection *fe_conn, *be_conn;
	struct list *list_format = &lf_expr->nodes.list;
	unsigned int s_flags;
	unsigned int uniq_id;
	struct buffer chunk;
	char *uri;
	char *spc;
	char *qmark;
	char *end;
	struct tm tm;
	int t_request;
	int hdr;
	int last_isspace = 1;
	int nspaces = 0;
	char *tmplog;
	char *ret;
	int iret;
	int status;
	struct logformat_node *tmp;
	struct timeval tv;
	struct strm_logs tmp_strm_log;
	struct ist path;
	struct http_uri_parser parser;
	int g_options = lf_expr->nodes.options; /* global */
	int first_node = 1;

	/* FIXME: let's limit ourselves to frontend logging for now. */

	if (likely(s)) {
		be = s->be;
		txn = s->txn;
		be_conn = sc_conn(s->scb);
		status = (txn ? txn->status : 0);
		s_flags = s->flags;
		uniq_id = s->uniq_id;
		logs = &s->logs;
	} else {
		/* we have no stream so we first need to initialize a few
		 * things that are needed later. We do increment the request
		 * ID so that it's uniquely assigned to this request just as
		 * if the request had reached the point of being processed.
		 * A request error is reported as it's the only element we have
		 * here and which justifies emitting such a log.
		 */
		be = ((obj_type(sess->origin) == OBJ_TYPE_CHECK) ? __objt_check(sess->origin)->proxy : fe);
		txn = NULL;
		fe_conn = objt_conn(sess->origin);
		be_conn = ((obj_type(sess->origin) == OBJ_TYPE_CHECK) ? sc_conn(__objt_check(sess->origin)->sc) : NULL);
		status = 0;
		s_flags = SF_ERR_PRXCOND | SF_FINST_R;
		uniq_id = _HA_ATOMIC_FETCH_ADD(&global.req_count, 1);

		/* prepare a valid log structure */
		tmp_strm_log.accept_ts = sess->accept_ts;
		tmp_strm_log.accept_date = sess->accept_date;
		tmp_strm_log.t_handshake = sess->t_handshake;
		tmp_strm_log.t_idle = (sess->t_idle >= 0 ? sess->t_idle : 0);
		tmp_strm_log.request_ts = 0;
		tmp_strm_log.t_queue = -1;
		tmp_strm_log.t_connect = -1;
		tmp_strm_log.t_data = -1;
		tmp_strm_log.t_close = ns_to_ms(now_ns - sess->accept_ts);
		tmp_strm_log.bytes_in = 0;
		tmp_strm_log.bytes_out = 0;
		tmp_strm_log.prx_queue_pos = 0;
		tmp_strm_log.srv_queue_pos = 0;

		logs = &tmp_strm_log;

		if ((fe->mode == PR_MODE_HTTP) && fe_conn && fe_conn->mux && fe_conn->mux->ctl) {
			enum mux_exit_status es = fe_conn->mux->ctl(fe_conn, MUX_CTL_EXIT_STATUS, &status);

			switch (es) {
			case MUX_ES_SUCCESS:
				break;
			case MUX_ES_INVALID_ERR:
				status = (status ? status : 400);
				if ((fe_conn->flags & CO_FL_ERROR) || conn_xprt_read0_pending(fe_conn))
					s_flags = SF_ERR_CLICL | SF_FINST_R;
				else
					s_flags = SF_ERR_PRXCOND | SF_FINST_R;
				break;
			case MUX_ES_TOUT_ERR:
				status = (status ? status : 408);
				s_flags = SF_ERR_CLITO | SF_FINST_R;
				break;
			case MUX_ES_NOTIMPL_ERR:
				status = (status ? status : 501);
				s_flags = SF_ERR_PRXCOND | SF_FINST_R;
				break;
			case MUX_ES_INTERNAL_ERR:
				status = (status ? status : 500);
				s_flags = SF_ERR_INTERNAL | SF_FINST_R;
				break;
			default:
				break;
			}
		}
	}

	t_request = -1;
	if ((llong)(logs->request_ts - logs->accept_ts) >= 0)
		t_request = ns_to_ms(logs->request_ts - logs->accept_ts);

	tmplog = dst;

	/* reset static ctx struct */
	ctx->in_text = 0;

	/* start with global ctx by default */
	lf_buildctx_prepare(ctx, g_options, NULL);

	/* fill logbuffer */
	if (!(ctx->options & LOG_OPT_ENCODE) && lf_expr_isempty(lf_expr))
		return 0;

	if (ctx->options & LOG_OPT_ENCODE_JSON)
		LOGCHAR('{');
	else if (ctx->options & LOG_OPT_ENCODE_CBOR) {
		/* start indefinite-length map */
		LOG_CBOR_BYTE(0xBF);
	}

	list_for_each_entry(tmp, list_format, list) {
#ifdef USE_OPENSSL
		struct connection *conn;
#endif
		const struct sockaddr_storage *addr;
		const char *src = NULL;
		const char *value_beg = NULL;
		struct sample *key;

		/* first start with basic types (use continue statement to skip
		 * the current node)
		 */
		if (tmp->type == LOG_FMT_SEPARATOR) {
			if (g_options & LOG_OPT_ENCODE) {
				/* ignored when global encoding is set */
				continue;
			}
			if (!last_isspace) {
				LOGCHAR(' ');
				last_isspace = 1;
			}
			continue;
		}
		else if (tmp->type == LOG_FMT_TEXT) {
			/* text */
			if (g_options & LOG_OPT_ENCODE) {
				/* ignored when global encoding is set */
				continue;
			}
			src = tmp->arg;
			iret = strlcpy2(tmplog, src, dst + maxsize - tmplog);
			if (iret == 0)
				goto out;
			tmplog += iret;
			last_isspace = 0; /* data was written */
			continue;
		}

		/* dynamic types handling (use "goto next_fmt" statement to skip
		 * the current node)
		 */

		if (g_options & LOG_OPT_ENCODE) {
			/* only consider global ctx for key encoding */
			lf_buildctx_prepare(ctx, g_options, NULL);

			if (!tmp->name)
				goto next_fmt; /* cannot represent anonymous field, ignore */

			if (!first_node) {
				if (ctx->options & LOG_OPT_ENCODE_JSON) {
					LOGCHAR(',');
					LOGCHAR(' ');
				}
			}

			if (ctx->options & LOG_OPT_ENCODE_JSON) {
				LOGCHAR('"');
				iret = strlcpy2(tmplog, tmp->name, dst + maxsize - tmplog);
				if (iret == 0)
					goto out;
				tmplog += iret;
				LOGCHAR('"');
				LOGCHAR(':');
				LOGCHAR(' ');
			}
			else if (ctx->options & LOG_OPT_ENCODE_CBOR) {
				ret = cbor_encode_text(&ctx->encode.cbor, tmplog,
				                       dst + maxsize, tmp->name,
				                       strlen(tmp->name));
				if (ret == NULL)
					goto out;
				tmplog = ret;
			}

			first_node = 0;
		}
		value_beg = tmplog;

		/* get the chance to consider per-node options (if not already
		 * set globally) for printing the value
		 */
		lf_buildctx_prepare(ctx, g_options, tmp);

		if (tmp->type == LOG_FMT_EXPR) {
			/* sample expression, may be request or response */
			int type;

			key = NULL;
			if (ctx->options & LOG_OPT_REQ_CAP)
				key = sample_process(be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, tmp->expr, NULL);

			if (!key && (ctx->options & LOG_OPT_RES_CAP))
				key = sample_process(be, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL, tmp->expr, NULL);

			if (!key && !(ctx->options & (LOG_OPT_REQ_CAP|LOG_OPT_RES_CAP))) // cfg, cli
				key = sample_process(be, sess, s, SMP_OPT_FINAL, tmp->expr, NULL);

			type = SMP_T_STR; // default

			if (key && key->data.type == SMP_T_BIN &&
			    (ctx->options & LOG_OPT_BIN)) {
				/* output type is binary, and binary option is set:
				 * preserve output type unless typecast is set to
				 * force output type to string
				 */
				if (ctx->typecast != SMP_T_STR)
					type = SMP_T_BIN;
			}

			/* if encoding is set, try to preserve output type
			 * with respect to typecast settings
			 * (ie: str, sint, bool)
			 *
			 * Special case for cbor encoding: we also try to
			 * preserve bin output type since cbor encoders
			 * know how to deal with binary data.
			 */
			if (ctx->options & LOG_OPT_ENCODE) {
				if (ctx->typecast == SMP_T_STR ||
				    ctx->typecast == SMP_T_SINT ||
				    ctx->typecast == SMP_T_BOOL) {
					/* enforce type */
					type = ctx->typecast;
				}
				else if (key &&
				         (key->data.type == SMP_T_SINT ||
				          key->data.type == SMP_T_BOOL ||
				          ((ctx->options & LOG_OPT_ENCODE_CBOR) &&
				           key->data.type == SMP_T_BIN))) {
					/* preserve type */
					type = key->data.type;
				}
			}

			if (key && !sample_convert(key, type))
				key = NULL;
			if (ctx->options & LOG_OPT_HTTP)
				ret = lf_encode_chunk(tmplog, dst + maxsize,
				                      '%', http_encode_map, key ? &key->data.u.str : &empty, ctx);
			else {
				if (key && type == SMP_T_BIN)
					ret = lf_encode_chunk(tmplog, dst + maxsize,
					                      0, no_escape_map,
					                      &key->data.u.str,
					                      ctx);
				else if (key && type == SMP_T_SINT)
					ret = lf_int_encode(tmplog, dst + maxsize - tmplog,
					                    key->data.u.sint, ctx);
				else if (key && type == SMP_T_BOOL)
					ret = lf_bool_encode(tmplog, dst + maxsize - tmplog,
					                     key->data.u.sint, ctx);
				else
					ret = lf_text_len(tmplog,
					                  key ? key->data.u.str.area : NULL,
					                  key ? key->data.u.str.data : 0,
					                  dst + maxsize - tmplog,
					                  ctx);
			}
			if (ret == NULL)
				goto out;
			tmplog = ret;
			last_isspace = 0; /* consider that data was written */
			goto next_fmt;
		}

		BUG_ON(tmp->type != LOG_FMT_ALIAS);

		/* logformat alias */
		switch (tmp->alias->type) {
			case LOG_FMT_CLIENTIP:  // %ci
				addr = (s ? sc_src(s->scf) : sess_src(sess));
				if (addr)
					ret = lf_ip(tmplog, (struct sockaddr *)addr, dst + maxsize - tmplog, ctx);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, ctx);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_CLIENTPORT:  // %cp
				addr = (s ? sc_src(s->scf) : sess_src(sess));
				if (addr) {
					/* sess->listener is always defined when the session's owner is an inbound connections */
					if (real_family(addr->ss_family) == AF_UNIX)
						ret = lf_int(tmplog, dst + maxsize - tmplog,
						             sess->listener->luid, ctx, LF_INT_LTOA);
					else
						ret = lf_port(tmplog, (struct sockaddr *)addr, dst + maxsize - tmplog, ctx);
				}
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, ctx);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_FRONTENDIP: // %fi
				addr = (s ? sc_dst(s->scf) : sess_dst(sess));
				if (addr)
					ret = lf_ip(tmplog, (struct sockaddr *)addr, dst + maxsize - tmplog, ctx);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, ctx);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case  LOG_FMT_FRONTENDPORT: // %fp
				addr = (s ? sc_dst(s->scf) : sess_dst(sess));
				if (addr) {
					/* sess->listener is always defined when the session's owner is an inbound connections */
					if (real_family(addr->ss_family) == AF_UNIX)
						ret = lf_int(tmplog, dst + maxsize - tmplog,
						             sess->listener->luid, ctx, LF_INT_LTOA);
					else
						ret = lf_port(tmplog, (struct sockaddr *)addr, dst + maxsize - tmplog, ctx);
				}
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, ctx);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BACKENDIP:  // %bi
				if (be_conn && conn_get_src(be_conn))
					ret = lf_ip(tmplog, (const struct sockaddr *)be_conn->src, dst + maxsize - tmplog, ctx);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, ctx);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BACKENDPORT:  // %bp
				if (be_conn && conn_get_src(be_conn))
					ret = lf_port(tmplog, (struct sockaddr *)be_conn->src, dst + maxsize - tmplog, ctx);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, ctx);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_SERVERIP: // %si
				if (be_conn && conn_get_dst(be_conn))
					ret = lf_ip(tmplog, (struct sockaddr *)be_conn->dst, dst + maxsize - tmplog, ctx);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, ctx);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_SERVERPORT: // %sp
				if (be_conn && conn_get_dst(be_conn))
					ret = lf_port(tmplog, (struct sockaddr *)be_conn->dst, dst + maxsize - tmplog, ctx);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, ctx);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_DATE: // %t = accept date
			{
				// "26/Apr/2024:09:39:58.774"

				get_localtime(logs->accept_date.tv_sec, &tm);
				if (ctx->options & LOG_OPT_ENCODE) {
					if (!date2str_log(ctx->_buf, &tm, &logs->accept_date, sizeof(ctx->_buf)))
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				}
				else // speedup
					ret = date2str_log(tmplog, &tm, &logs->accept_date, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_tr: // %tr = start of request date
			{
				// "26/Apr/2024:09:39:58.774"

				/* Note that the timers are valid if we get here */
				tv_ms_add(&tv, &logs->accept_date, logs->t_idle >= 0 ? logs->t_idle + logs->t_handshake : 0);
				get_localtime(tv.tv_sec, &tm);
				if (ctx->options & LOG_OPT_ENCODE) {
					if (!date2str_log(ctx->_buf, &tm, &tv, sizeof(ctx->_buf)))
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				}
				else // speedup
					ret = date2str_log(tmplog, &tm, &tv, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_DATEGMT: // %T = accept date, GMT
			{
				// "26/Apr/2024:07:41:11 +0000"

				get_gmtime(logs->accept_date.tv_sec, &tm);
				if (ctx->options & LOG_OPT_ENCODE) {
					if (!gmt2str_log(ctx->_buf, &tm, sizeof(ctx->_buf)))
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				}
				else // speedup
					ret = gmt2str_log(tmplog, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_trg: // %trg = start of request date, GMT
			{
				// "26/Apr/2024:07:41:11 +0000"

				tv_ms_add(&tv, &logs->accept_date, logs->t_idle >= 0 ? logs->t_idle + logs->t_handshake : 0);
				get_gmtime(tv.tv_sec, &tm);
				if (ctx->options & LOG_OPT_ENCODE) {
					if (!gmt2str_log(ctx->_buf, &tm, sizeof(ctx->_buf)))
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				}
				else // speedup
					ret = gmt2str_log(tmplog, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_DATELOCAL: // %Tl = accept date, local
			{
				// "26/Apr/2024:09:42:32 +0200"

				get_localtime(logs->accept_date.tv_sec, &tm);
				if (ctx->options & LOG_OPT_ENCODE) {
					if (!localdate2str_log(ctx->_buf, logs->accept_date.tv_sec,
					                       &tm, sizeof(ctx->_buf)))
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				}
				else // speedup
					ret = localdate2str_log(tmplog, logs->accept_date.tv_sec,
					                        &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_trl: // %trl = start of request date, local
			{
				// "26/Apr/2024:09:42:32 +0200"

				tv_ms_add(&tv, &logs->accept_date, logs->t_idle >= 0 ? logs->t_idle + logs->t_handshake : 0);
				get_localtime(tv.tv_sec, &tm);
				if (ctx->options & LOG_OPT_ENCODE) {
					if (!localdate2str_log(ctx->_buf, tv.tv_sec, &tm, sizeof(ctx->_buf)))
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				}
				else // speedup
					ret = localdate2str_log(tmplog, tv.tv_sec, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_TS: // %Ts
			{
				unsigned long value = logs->accept_date.tv_sec;

				if (ctx->options & LOG_OPT_HEXA) {
					iret = snprintf(ctx->_buf, sizeof(ctx->_buf), "%04X", (unsigned int)value);
					if (iret < 0 || iret >= dst + maxsize - tmplog)
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				} else {
					ret = lf_int(tmplog, dst + maxsize - tmplog, value, ctx, LF_INT_LTOA);
				}
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_MS: // %ms
			{
				unsigned int value = (unsigned int)logs->accept_date.tv_usec/1000;

				if (ctx->options & LOG_OPT_HEXA) {
					iret = snprintf(ctx->_buf, sizeof(ctx->_buf), "%02X", value);
					if (iret < 0 || iret >= dst + maxsize - tmplog)
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				} else {
					ret = lf_int(tmplog, dst + maxsize - tmplog, value,
					             ctx, LF_INT_UTOA_PAD_4);
				}
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_FRONTEND: // %f
				src = fe->id;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_FRONTEND_XPRT: // %ft
				src = fe->id;
				LOG_VARTEXT_START();
				ret = lf_rawtext(tmplog, src, dst + maxsize - tmplog, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;

				/* sess->listener may be undefined if the session's owner is a health-check */
				if (sess->listener && sess->listener->bind_conf->xprt->get_ssl_sock_ctx)
					LOGCHAR('~');
				break;
#ifdef USE_OPENSSL
			case LOG_FMT_SSL_CIPHER: // %sslc
				src = NULL;
				conn = objt_conn(sess->origin);
				if (conn) {
					src = ssl_sock_get_cipher_name(conn);
				}
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_SSL_VERSION: // %sslv
				src = NULL;
				conn = objt_conn(sess->origin);
				if (conn) {
					src = ssl_sock_get_proto_version(conn);
				}
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
#endif
			case LOG_FMT_BACKEND: // %b
				src = be->id;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_SERVER: // %s
				switch (obj_type(s ? s->target : sess->origin)) {
				case OBJ_TYPE_SERVER:
					src = __objt_server(s->target)->id;
					break;
				case OBJ_TYPE_APPLET:
					src = __objt_applet(s->target)->name;
					break;
				case OBJ_TYPE_CHECK:
					src = (__objt_check(sess->origin)->server
					       ? __objt_check(sess->origin)->server->id
					       : "<NOSRV>");
					break;
				default:
					src = "<NOSRV>";
					break;
				}
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_Th: // %Th = handshake time
				ret = lf_int(tmplog, dst + maxsize - tmplog, logs->t_handshake, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_Ti: // %Ti = HTTP idle time
				ret = lf_int(tmplog, dst + maxsize - tmplog, logs->t_idle, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TR: // %TR = HTTP request time
			{
				long value = (t_request >= 0) ? t_request - logs->t_idle - logs->t_handshake : -1;

				ret = lf_int(tmplog, dst + maxsize - tmplog, value, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_TQ: // %Tq = Th + Ti + TR
				ret = lf_int(tmplog, dst + maxsize - tmplog, t_request, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TW: // %Tw
			{
				long value = (logs->t_queue >= 0) ? logs->t_queue - t_request : -1;

				ret = lf_int(tmplog, dst + maxsize - tmplog, value, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_TC: // %Tc
			{
				long value = (logs->t_connect >= 0) ? logs->t_connect - logs->t_queue : -1;

				ret = lf_int(tmplog, dst + maxsize - tmplog, value, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_Tr: // %Tr
			{
				long value = (logs->t_data >= 0) ? logs->t_data - logs->t_connect : -1;

				ret = lf_int(tmplog, dst + maxsize - tmplog, value, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_TD: // %Td
			{
				long value;

				if (be->mode == PR_MODE_HTTP)
					value = (logs->t_data >= 0) ? logs->t_close - logs->t_data : -1;
				else
					value = (logs->t_connect >= 0) ? logs->t_close - logs->t_connect : -1;

				ret = lf_int(tmplog, dst + maxsize - tmplog, value, ctx, LF_INT_LTOA);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_Ta:  // %Ta = active time = Tt - Th - Ti
			{
				long value = logs->t_close - (logs->t_idle >= 0 ? logs->t_idle + logs->t_handshake : 0);

				if (!(fe->to_log & LW_BYTES))
					LOGMETACHAR('+');
				ret = lf_int(tmplog, dst + maxsize - tmplog, value, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_TT:  // %Tt = total time
				if (!(fe->to_log & LW_BYTES))
					LOGMETACHAR('+');
				ret = lf_int(tmplog, dst + maxsize - tmplog, logs->t_close, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TU:  // %Tu = total time seen by user = Tt - Ti
			{
				long value = logs->t_close - (logs->t_idle >= 0 ? logs->t_idle : 0);

				if (!(fe->to_log & LW_BYTES))
					LOGMETACHAR('+');
				ret = lf_int(tmplog, dst + maxsize - tmplog, value, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_STATUS: // %ST
				ret = lf_int(tmplog, dst + maxsize - tmplog, status, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BYTES: // %B
				if (!(fe->to_log & LW_BYTES))
					LOGMETACHAR('+');
				ret = lf_int(tmplog, dst + maxsize - tmplog, logs->bytes_out, ctx, LF_INT_LLTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BYTES_UP: // %U
				ret = lf_int(tmplog, dst + maxsize - tmplog, logs->bytes_in, ctx, LF_INT_LLTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_CCLIENT: // %CC
				src = txn ? txn->cli_cookie : NULL;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_CSERVER: // %CS
				src = txn ? txn->srv_cookie : NULL;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TERMSTATE: // %ts
			{
				ctx->_buf[0] = sess_term_cond[(s_flags & SF_ERR_MASK) >> SF_ERR_SHIFT];
				ctx->_buf[1] = sess_fin_state[(s_flags & SF_FINST_MASK) >> SF_FINST_SHIFT];
				ret = lf_rawtext_len(tmplog, ctx->_buf, 2, maxsize - (tmplog - dst), ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_TERMSTATE_CK: // %tsc, same as TS with cookie state (for mode HTTP)
			{
				ctx->_buf[0] = sess_term_cond[(s_flags & SF_ERR_MASK) >> SF_ERR_SHIFT];
				ctx->_buf[1] = sess_fin_state[(s_flags & SF_FINST_MASK) >> SF_FINST_SHIFT];
				ctx->_buf[2] = (txn && (be->ck_opts & PR_CK_ANY)) ? sess_cookie[(txn->flags & TX_CK_MASK) >> TX_CK_SHIFT] : '-';
				ctx->_buf[3] = (txn && (be->ck_opts & PR_CK_ANY)) ? sess_set_cookie[(txn->flags & TX_SCK_MASK) >> TX_SCK_SHIFT] : '-';
				ret = lf_rawtext_len(tmplog, ctx->_buf, 4, maxsize - (tmplog - dst), ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_ACTCONN: // %ac
				ret = lf_int(tmplog, dst + maxsize - tmplog, actconn, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_FECONN:  // %fc
				ret = lf_int(tmplog, dst + maxsize - tmplog, fe->feconn, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BECONN:  // %bc
				ret = lf_int(tmplog, dst + maxsize - tmplog, be->beconn, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_SRVCONN:  // %sc
			{
				unsigned long value;

				switch (obj_type(s ? s->target : sess->origin)) {
				case OBJ_TYPE_SERVER:
					value = __objt_server(s->target)->cur_sess;
					break;
				case OBJ_TYPE_CHECK:
					value = (__objt_check(sess->origin)->server
					         ? __objt_check(sess->origin)->server->cur_sess
					         : 0);
					break;
				default:
					value = 0;
					break;
				}

				ret = lf_int(tmplog, dst + maxsize - tmplog, value, ctx, LF_INT_ULTOA);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_RETRIES:  // %rc
			{
				long int value = (s ? s->conn_retries : 0);

				if (s_flags & SF_REDISP)
					LOGMETACHAR('+');
				ret = lf_int(tmplog, dst + maxsize - tmplog, value, ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
			}

			case LOG_FMT_SRVQUEUE: // %sq
				ret = lf_int(tmplog, dst + maxsize - tmplog, logs->srv_queue_pos,
				             ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BCKQUEUE:  // %bq
				ret = lf_int(tmplog, dst + maxsize - tmplog, logs->prx_queue_pos,
				             ctx, LF_INT_LTOA);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_HDRREQUEST: // %hr
				/* request header */
				if (fe->nb_req_cap && s && s->req_cap) {
					LOG_VARTEXT_START();
					LOGCHAR('{');
					for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
						if (hdr)
							LOGCHAR('|');
						if (s->req_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->req_cap[hdr], ctx);
							if (ret == NULL)
								goto out;
							tmplog = ret;
						}
					}
					LOGCHAR('}');
				}
				break;

			case LOG_FMT_HDRREQUESTLIST: // %hrl
				/* request header list */
				if (fe->nb_req_cap && s && s->req_cap) {
					LOG_STRARRAY_START();
					for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
						if (hdr > 0)
							LOG_STRARRAY_NEXT();
						LOG_VARTEXT_START();
						if (s->req_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->req_cap[hdr], ctx);
							if (ret == NULL)
								goto out;
							tmplog = ret;
						} else if (!(ctx->options & LOG_OPT_QUOTE))
							LOGCHAR('-');
						/* Manually end variable text as we're emitting multiple
						 * texts at once
						 */
						LOG_VARTEXT_END();
					}
					LOG_STRARRAY_END();
				}
				break;


			case LOG_FMT_HDRRESPONS: // %hs
				/* response header */
				if (fe->nb_rsp_cap && s && s->res_cap) {
					LOG_VARTEXT_START();
					LOGCHAR('{');
					for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
						if (hdr)
							LOGCHAR('|');
						if (s->res_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->res_cap[hdr], ctx);
							if (ret == NULL)
								goto out;
							tmplog = ret;
						}
					}
					LOGCHAR('}');
				}
				break;

			case LOG_FMT_HDRRESPONSLIST: // %hsl
				/* response header list */
				if (fe->nb_rsp_cap && s && s->res_cap) {
					LOG_STRARRAY_START();
					for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
						if (hdr > 0)
							LOG_STRARRAY_NEXT();
						LOG_VARTEXT_START();
						if (s->res_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->res_cap[hdr], ctx);
							if (ret == NULL)
								goto out;
							tmplog = ret;
						} else if (!(ctx->options & LOG_OPT_QUOTE))
							LOGCHAR('-');
						/* Manually end variable text as we're emitting multiple
						 * texts at once
						 */
						LOG_VARTEXT_END();
					}
					LOG_STRARRAY_END();
				}
				break;

			case LOG_FMT_REQ: // %r
				/* Request */
				LOG_VARTEXT_START();
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";
				ret = lf_encode_string(tmplog, dst + maxsize,
				                       '#', url_encode_map, uri, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_HTTP_PATH: // %HP
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";

				LOG_VARTEXT_START();

				end = uri + strlen(uri);
				// look for the first whitespace character
				while (uri < end && !HTTP_IS_SPHT(*uri))
					uri++;

				// keep advancing past multiple spaces
				while (uri < end && HTTP_IS_SPHT(*uri)) {
					uri++; nspaces++;
				}

				// look for first space or question mark after url
				spc = uri;
				while (spc < end && *spc != '?' && !HTTP_IS_SPHT(*spc))
					spc++;

				if (!txn || !txn->uri || nspaces == 0) {
					chunk.area = "<BADREQ>";
					chunk.data = strlen("<BADREQ>");
				} else {
					chunk.area = uri;
					chunk.data = spc - uri;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, ctx);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_HTTP_PATH_ONLY: // %HPO
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";

				LOG_VARTEXT_START();

				end = uri + strlen(uri);

				// look for the first whitespace character
				while (uri < end && !HTTP_IS_SPHT(*uri))
					uri++;

				// keep advancing past multiple spaces
				while (uri < end && HTTP_IS_SPHT(*uri)) {
					uri++; nspaces++;
				}

				// look for first space after url
				spc = uri;
				while (spc < end && !HTTP_IS_SPHT(*spc))
					spc++;

				path = ist2(uri, spc - uri);

				// extract relative path without query params from url
				parser = http_uri_parser_init(path);
				path = iststop(http_parse_path(&parser), '?');
				if (!txn || !txn->uri || nspaces == 0) {
					chunk.area = "<BADREQ>";
					chunk.data = strlen("<BADREQ>");
				} else {
					chunk.area = path.ptr;
					chunk.data = path.len;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, ctx);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_HTTP_QUERY: // %HQ
				LOG_VARTEXT_START();

				if (!txn || !txn->uri) {
					chunk.area = "<BADREQ>";
					chunk.data = strlen("<BADREQ>");
				} else {
					uri = txn->uri;
					end = uri + strlen(uri);
					// look for the first question mark
					while (uri < end && *uri != '?')
						uri++;

					qmark = uri;
					// look for first space or question mark after url
					while (uri < end && !HTTP_IS_SPHT(*uri))
						uri++;

					chunk.area = qmark;
					chunk.data = uri - qmark;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, ctx);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_HTTP_URI: // %HU
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";

				LOG_VARTEXT_START();

				end = uri + strlen(uri);
				// look for the first whitespace character
				while (uri < end && !HTTP_IS_SPHT(*uri))
					uri++;

				// keep advancing past multiple spaces
				while (uri < end && HTTP_IS_SPHT(*uri)) {
					uri++; nspaces++;
				}

				// look for first space after url
				spc = uri;
				while (spc < end && !HTTP_IS_SPHT(*spc))
					spc++;

				if (!txn || !txn->uri || nspaces == 0) {
					chunk.area = "<BADREQ>";
					chunk.data = strlen("<BADREQ>");
				} else {
					chunk.area = uri;
					chunk.data = spc - uri;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, ctx);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_HTTP_METHOD: // %HM
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";
				LOG_VARTEXT_START();

				end = uri + strlen(uri);
				// look for the first whitespace character
				spc = uri;
				while (spc < end && !HTTP_IS_SPHT(*spc))
					spc++;

				if (spc == end) { // odd case, we have txn->uri, but we only got a verb
					chunk.area = "<BADREQ>";
					chunk.data = strlen("<BADREQ>");
				} else {
					chunk.area = uri;
					chunk.data = spc - uri;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, ctx);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_HTTP_VERSION: // %HV
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";
				LOG_VARTEXT_START();

				end = uri + strlen(uri);
				// look for the first whitespace character
				while (uri < end && !HTTP_IS_SPHT(*uri))
					uri++;

				// keep advancing past multiple spaces
				while (uri < end && HTTP_IS_SPHT(*uri)) {
					uri++; nspaces++;
				}

				// look for the next whitespace character
				while (uri < end && !HTTP_IS_SPHT(*uri))
					uri++;

				// keep advancing past multiple spaces
				while (uri < end && HTTP_IS_SPHT(*uri))
					uri++;

				if (!txn || !txn->uri || nspaces == 0) {
					chunk.area = "<BADREQ>";
					chunk.data = strlen("<BADREQ>");
				} else if (uri == end) {
					chunk.area = "HTTP/0.9";
					chunk.data = strlen("HTTP/0.9");
				} else {
					chunk.area = uri;
					chunk.data = end - uri;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, ctx);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_COUNTER: // %rt
				if (ctx->options & LOG_OPT_HEXA) {
					iret = snprintf(ctx->_buf, sizeof(ctx->_buf), "%04X", uniq_id);
					if (iret < 0 || iret >= dst + maxsize - tmplog)
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				} else {
					ret = lf_int(tmplog, dst + maxsize - tmplog, uniq_id, ctx, LF_INT_LTOA);
				}
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_LOGCNT: // %lc
				if (ctx->options & LOG_OPT_HEXA) {
					iret = snprintf(ctx->_buf, sizeof(ctx->_buf), "%04X", fe->log_count);
					if (iret < 0 || iret >= dst + maxsize - tmplog)
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				} else {
					ret = lf_int(tmplog, dst + maxsize - tmplog, fe->log_count,
					             ctx, LF_INT_ULTOA);
				}
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_HOSTNAME: // %H
				src = hostname;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_PID: // %pid
				if (ctx->options & LOG_OPT_HEXA) {
					iret = snprintf(ctx->_buf, sizeof(ctx->_buf), "%04X", pid);
					if (iret < 0 || iret >= dst + maxsize - tmplog)
						goto out;
					ret = lf_rawtext(tmplog, ctx->_buf, dst + maxsize - tmplog, ctx);
				} else {
					ret = lf_int(tmplog, dst + maxsize - tmplog, pid, ctx, LF_INT_LTOA);
				}
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_UNIQUEID: // %ID
				ret = NULL;
				if (s)
					ret = lf_text_len(tmplog, s->unique_id.ptr, s->unique_id.len, maxsize - (tmplog - dst), ctx);
				else
					ret = lf_text_len(tmplog, NULL, 0, maxsize - (tmplog - dst), ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_ORIGIN: // %OG
				ret = lf_text(tmplog, log_orig_to_str(log_orig.id),
				              dst + maxsize - tmplog, ctx);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

		}
 next_fmt:
		if (value_beg == tmplog) {
			/* handle the case where no data was generated for the value after
			 * the key was already announced
			 */
			if (ctx->options & LOG_OPT_ENCODE_JSON) {
				/* for JSON, we simply output 'null' */
				iret = snprintf(tmplog, dst + maxsize - tmplog, "null");
				if (iret < 0 || iret >= dst + maxsize - tmplog)
					goto out;
				tmplog += iret;
			}
			if (ctx->options & LOG_OPT_ENCODE_CBOR) {
				/* for CBOR, we have the '22' primitive which is known as
				 * NULL
				 */
				LOG_CBOR_BYTE(0xF6);
			}

		}

		/* if variable text was started for the current node data, we need
		 * to end it
		 */
		LOG_VARTEXT_END();
		if (tmplog != value_beg) {
			/* data was actually generated for the current dynamic
			 * node, reset the space hint so that a new space may
			 * now be emitted when relevant.
			 */
			last_isspace = 0;
		}
	}

	/* back to global ctx (some encoding types may need to output
	 * ending closure)
	*/
	lf_buildctx_prepare(ctx, g_options, NULL);

	if (ctx->options & LOG_OPT_ENCODE_JSON)
		LOGCHAR('}');
	else if (ctx->options & LOG_OPT_ENCODE_CBOR) {
		/* end indefinite-length map */
		LOG_CBOR_BYTE(0xFF);
	}

out:
	/* *tmplog is a unused character */
	*tmplog = '\0';
	return tmplog - dst;

}

/*
 * opportunistic log when at least the session is known to exist
 * <s> may be NULL
 *
 * Will not log if the frontend has no log defined. By default it will
 * try to emit the log as INFO, unless the stream already exists and
 * set-log-level was used.
 */
void do_log(struct session *sess, struct stream *s, struct log_orig origin)
{
	int size;
	int sd_size = 0;
	int level = -1;

	if (LIST_ISEMPTY(&sess->fe->loggers))
		return;

	if (s) {
		if (s->logs.level) { /* loglevel was overridden */
			if (s->logs.level == -1) {
				/* log disabled */
				return;
			}
			level = s->logs.level - 1;
		}
		/* if unique-id was not generated */
		if (!isttest(s->unique_id) && !lf_expr_isempty(&sess->fe->format_unique_id)) {
			stream_generate_unique_id(s, &sess->fe->format_unique_id);
		}
	}

	if (level == -1) {
		level = LOG_INFO;
		if ((origin.flags & LOG_ORIG_FL_ERROR) &&
		    (sess->fe->options2 & PR_O2_LOGERRORS))
			level = LOG_ERR;
	}

	if (!lf_expr_isempty(&sess->fe->logformat_sd)) {
		sd_size = sess_build_logline_orig(sess, s, logline_rfc5424, global.max_syslog_len,
		                                  &sess->fe->logformat_sd, origin);
	}

	size = sess_build_logline_orig(sess, s, logline, global.max_syslog_len, &sess->fe->logformat, origin);
	if (size > 0) {
		struct process_send_log_ctx ctx;

		ctx.origin = origin;
		ctx.sess = sess;
		ctx.stream = s;
		__send_log(&ctx, &sess->fe->loggers, &sess->fe->log_tag, level,
			   logline, size + 1, logline_rfc5424, sd_size);
	}
}

/*
 * send a log for the stream when we have enough info about it.
 * Will not log if the frontend has no log defined.
 */
void strm_log(struct stream *s, struct log_orig origin)
{
	struct session *sess = s->sess;
	int size, err, level;
	int sd_size = 0;

	/* if we don't want to log normal traffic, return now */
	err = (s->flags & SF_REDISP) ||
              ((s->flags & SF_ERR_MASK) > SF_ERR_LOCAL) ||
	      (((s->flags & SF_ERR_MASK) == SF_ERR_NONE) && s->conn_retries) ||
	      ((sess->fe->mode == PR_MODE_HTTP) && s->txn && s->txn->status >= 500) ||
	      (origin.flags & LOG_ORIG_FL_ERROR);

	if (!err && (sess->fe->options2 & PR_O2_NOLOGNORM))
		return;

	if (LIST_ISEMPTY(&sess->fe->loggers))
		return;

	if (s->logs.level) { /* loglevel was overridden */
		if (s->logs.level == -1) {
			s->logs.logwait = 0; /* logs disabled */
			return;
		}
		level = s->logs.level - 1;
	}
	else {
		level = LOG_INFO;
		if (err && (sess->fe->options2 & PR_O2_LOGERRORS))
			level = LOG_ERR;
	}

	/* if unique-id was not generated */
	if (!isttest(s->unique_id) && !lf_expr_isempty(&sess->fe->format_unique_id)) {
		stream_generate_unique_id(s, &sess->fe->format_unique_id);
	}

	if (!lf_expr_isempty(&sess->fe->logformat_sd)) {
		sd_size = build_logline_orig(s, logline_rfc5424, global.max_syslog_len,
		                             &sess->fe->logformat_sd, origin);
	}

	size = build_logline_orig(s, logline, global.max_syslog_len, &sess->fe->logformat, origin);
	if (size > 0) {
		struct process_send_log_ctx ctx;

		_HA_ATOMIC_INC(&sess->fe->log_count);
		ctx.origin = origin;
		ctx.sess = sess;
		ctx.stream = s;
		__send_log(&ctx, &sess->fe->loggers, &sess->fe->log_tag, level,
			   logline, size + 1, logline_rfc5424, sd_size);
		s->logs.logwait = 0;
	}
}

/*
 * send a minimalist log for the session. Will not log if the frontend has no
 * log defined. It is assumed that this is only used to report anomalies that
 * cannot lead to the creation of a regular stream. Because of this the log
 * level is LOG_INFO or LOG_ERR depending on the "log-separate-error" setting
 * in the frontend. The caller must simply know that it should not call this
 * function to report unimportant events. It is safe to call this function with
 * sess==NULL (will not do anything).
 *
 * if <embryonic> is set, then legacy error log payload will be generated unless
 * logformat_error is specified (ie: normal logformat is ignored in this case).
 *
 */
void _sess_log(struct session *sess, int embryonic)
{
	int size, level;
	int sd_size = 0;
	struct log_orig orig;

	if (!sess)
		return;

	if (embryonic)
		orig = log_orig(LOG_ORIG_SESS_KILL, LOG_ORIG_FL_NONE);
	else
		orig = log_orig(LOG_ORIG_SESS_ERROR, LOG_ORIG_FL_NONE);

	if (LIST_ISEMPTY(&sess->fe->loggers))
		return;

	level = LOG_INFO;
	if (sess->fe->options2 & PR_O2_LOGERRORS)
		level = LOG_ERR;

	if (!lf_expr_isempty(&sess->fe->logformat_sd)) {
		sd_size = sess_build_logline_orig(sess, NULL,
		                                  logline_rfc5424, global.max_syslog_len,
		                                  &sess->fe->logformat_sd,
		                                  orig);
	}

	if (!lf_expr_isempty(&sess->fe->logformat_error))
		size = sess_build_logline_orig(sess, NULL, logline,
		                               global.max_syslog_len, &sess->fe->logformat_error,
		                               orig);
	else if (!embryonic)
		size = sess_build_logline_orig(sess, NULL, logline,
		                               global.max_syslog_len, &sess->fe->logformat,
		                               orig);
	else { /* no logformat_error and embryonic==1 */
		struct buffer buf;

		buf = b_make(logline, global.max_syslog_len, 0, 0);
		session_embryonic_build_legacy_err(sess, &buf);
		size = buf.data;
	}
	if (size > 0) {
		struct process_send_log_ctx ctx;

		_HA_ATOMIC_INC(&sess->fe->log_count);
		ctx.origin = orig;
		ctx.sess = sess;
		ctx.stream = NULL;
		__send_log(&ctx, &sess->fe->loggers,
		           &sess->fe->log_tag, level,
			   logline, size + 1, logline_rfc5424, sd_size);
	}
}

void app_log(struct list *loggers, struct buffer *tag, int level, const char *format, ...)
{
	va_list argp;
	int  data_len;

	if (level < 0 || format == NULL || logline == NULL)
		return;

	va_start(argp, format);
	data_len = vsnprintf(logline, global.max_syslog_len, format, argp);
	if (data_len < 0 || data_len > global.max_syslog_len)
		data_len = global.max_syslog_len;
	va_end(argp);

	__send_log(NULL, loggers, tag, level, logline, data_len, default_rfc5424_sd_log_format, 2);
}
/*
 * This function parse a received log message <buf>, of size <buflen>
 * it fills <level>, <facility> and <metadata> depending of the detected
 * header format and message will point on remaining payload of <size>
 *
 * <metadata> must point on a preallocated array of LOG_META_FIELDS*sizeof(struct ist)
 * struct ist len will be set to 0 if field is not found
 * <level> and <facility> will be set to -1 if not found.
 */
void parse_log_message(char *buf, size_t buflen, int *level, int *facility,
                       struct ist *metadata, char **message, size_t *size)
{

	char *p;
	int fac_level = 0;

	*level = *facility = -1;

	*message = buf;
	*size = buflen;

	memset(metadata, 0, LOG_META_FIELDS*sizeof(struct ist));

	p = buf;
	if (*size < 2 || *p != '<')
		return;

	p++;
	while (*p != '>') {
		if (*p > '9' || *p < '0')
			return;
		fac_level = 10*fac_level + (*p - '0');
		p++;
		if ((p - buf) > buflen)
			return;
	}

	*facility = fac_level >> 3;
	*level = fac_level & 0x7;
	p++;

	metadata[LOG_META_PRIO] = ist2(buf, p - buf);

	buflen -= p - buf;
	buf = p;

	*size = buflen;
	*message = buf;

	/* for rfc5424, prio is always followed by '1' and ' ' */
	if ((*size > 2) && (p[0] == '1') && (p[1] == ' ')) {
		/* format is always '1 TIMESTAMP HOSTNAME TAG PID MSGID STDATA '
		 * followed by message.
		 * Each header field can present NILVALUE: '-'
		 */

		p += 2;
		*size -= 2;
		/* timestamp is NILVALUE '-' */
		if (*size > 2 && (p[0] == '-') && p[1] == ' ') {
			metadata[LOG_META_TIME] = ist2(p, 1);
			p++;
		}
		else if (*size > LOG_ISOTIME_MINLEN) {
			metadata[LOG_META_TIME].ptr = p;

			/* check if optional secfrac is present
			 * in timestamp.
			 * possible format are:
			 * ex: '1970-01-01T00:00:00.000000Z'
			 *     '1970-01-01T00:00:00.000000+00:00'
			 *     '1970-01-01T00:00:00.000000-00:00'
			 *     '1970-01-01T00:00:00Z'
			 *     '1970-01-01T00:00:00+00:00'
			 *     '1970-01-01T00:00:00-00:00'
			 */
			p += 19;
			if (*p == '.') {
				p++;
				if ((p - buf) >= buflen)
					goto bad_format;
				while (*p != 'Z' && *p != '+' && *p != '-') {
					if ((unsigned char)(*p - '0') > 9)
						goto bad_format;

					p++;
					if ((p - buf) >= buflen)
						goto bad_format;
				}
			}

			if (*p == 'Z')
				p++;
			else
				p += 6; /* case of '+00:00 or '-00:00' */

			if ((p - buf) >= buflen || *p != ' ')
				goto bad_format;
			metadata[LOG_META_TIME].len = p - metadata[LOG_META_TIME].ptr;
		}
		else
			goto bad_format;


		p++;
		if ((p - buf) >= buflen || *p == ' ')
			goto bad_format;

		metadata[LOG_META_HOST].ptr = p;
		while (*p != ' ') {
			p++;
			if ((p - buf) >= buflen)
				goto bad_format;
		}
		metadata[LOG_META_HOST].len = p - metadata[LOG_META_HOST].ptr;
		if (metadata[LOG_META_HOST].len == 1 && metadata[LOG_META_HOST].ptr[0] == '-')
			metadata[LOG_META_HOST].len = 0;

		p++;
		if ((p - buf) >= buflen || *p == ' ')
			goto bad_format;

		metadata[LOG_META_TAG].ptr = p;
		while (*p != ' ') {
			p++;
			if ((p - buf) >= buflen)
				goto bad_format;
		}
		metadata[LOG_META_TAG].len = p - metadata[LOG_META_TAG].ptr;
		if (metadata[LOG_META_TAG].len == 1 && metadata[LOG_META_TAG].ptr[0] == '-')
			metadata[LOG_META_TAG].len = 0;

		p++;
		if ((p - buf) >= buflen || *p == ' ')
			goto bad_format;

		metadata[LOG_META_PID].ptr = p;
		while (*p != ' ') {
			p++;
			if ((p - buf) >= buflen)
				goto bad_format;
		}
		metadata[LOG_META_PID].len = p - metadata[LOG_META_PID].ptr;
		if (metadata[LOG_META_PID].len == 1 && metadata[LOG_META_PID].ptr[0] == '-')
			metadata[LOG_META_PID].len = 0;

		p++;
		if ((p - buf) >= buflen || *p == ' ')
			goto bad_format;

		metadata[LOG_META_MSGID].ptr = p;
		while (*p != ' ') {
			p++;
			if ((p - buf) >= buflen)
				goto bad_format;
		}
		metadata[LOG_META_MSGID].len = p - metadata[LOG_META_MSGID].ptr;
		if (metadata[LOG_META_MSGID].len == 1 && metadata[LOG_META_MSGID].ptr[0] == '-')
			metadata[LOG_META_MSGID].len = 0;

		p++;
		if ((p - buf) >= buflen || *p == ' ')
			goto bad_format;

		/* structured data format is:
		 * ex:
		 *    '[key1=value1 key2=value2][key3=value3]'
		 *
		 * space is invalid outside [] because
		 * considered as the end of structured data field
		 */
		metadata[LOG_META_STDATA].ptr = p;
		if (*p == '[') {
			int elem = 0;

			while (1) {
				if (elem) {
					/* according to rfc this char is escaped in param values */
					if (*p == ']' && *(p-1) != '\\')
						elem = 0;
				}
				else {
					if (*p == '[')
						elem = 1;
					else if (*p == ' ')
						break;
					else
						goto bad_format;
				}
				p++;
				if ((p - buf) >= buflen)
					goto bad_format;
			}
		}
		else if (*p == '-') {
			/* case of NILVALUE */
			p++;
			if ((p - buf) >= buflen || *p != ' ')
				goto bad_format;
		}
		else
			goto bad_format;

		metadata[LOG_META_STDATA].len = p - metadata[LOG_META_STDATA].ptr;
		if (metadata[LOG_META_STDATA].len == 1 && metadata[LOG_META_STDATA].ptr[0] == '-')
			metadata[LOG_META_STDATA].len = 0;

		p++;

		buflen -= p - buf;
		buf = p;

		*size = buflen;
		*message = p;
	}
	else if (*size > LOG_LEGACYTIME_LEN) {
		int m;

		/* supported header format according to rfc3164.
		 * ex:
		 *  'Jan  1 00:00:00 HOSTNAME TAG[PID]: '
		 *  or 'Jan  1 00:00:00 HOSTNAME TAG: '
		 *  or 'Jan  1 00:00:00 HOSTNAME '
		 * Note: HOSTNAME is mandatory, and day
		 * of month uses a single space prefix if
		 * less than 10 to ensure hour offset is
		 * always the same.
		 */

		/* Check month to see if it correspond to a rfc3164
		 * header ex 'Jan  1 00:00:00' */
		for (m = 0; m < 12; m++)
			if (!memcmp(monthname[m], p, 3))
				break;
		/* Month not found */
		if (m == 12)
			goto bad_format;

		metadata[LOG_META_TIME] = ist2(p, LOG_LEGACYTIME_LEN);

		p += LOG_LEGACYTIME_LEN;
		if ((p - buf) >= buflen || *p != ' ')
			goto bad_format;

		p++;
		if ((p - buf) >= buflen || *p == ' ')
			goto bad_format;

		metadata[LOG_META_HOST].ptr = p;
		while (*p != ' ') {
			p++;
			if ((p - buf) >= buflen)
				goto bad_format;
		}
		metadata[LOG_META_HOST].len = p - metadata[LOG_META_HOST].ptr;

		/* TAG seems to no be mandatory */
		p++;

		buflen -= p - buf;
		buf = p;

		*size = buflen;
		*message = buf;

		if (!buflen)
			return;

		while (((p  - buf) < buflen) && *p != ' ' && *p != ':')
			p++;

		/* a tag must present a trailing ':' */
		if (((p - buf) >= buflen) || *p != ':')
			return;
		p++;
		/* followed by a space */
		if (((p - buf) >= buflen) || *p != ' ')
			return;

		/* rewind to parse tag and pid */
		p = buf;
		metadata[LOG_META_TAG].ptr = p;
		/* we have the guarantee that ':' will be reach before size limit */
		while (*p != ':') {
			if (*p == '[') {
				metadata[LOG_META_TAG].len = p - metadata[LOG_META_TAG].ptr;
				metadata[LOG_META_PID].ptr = p + 1;
			}
			else if (*p == ']' && isttest(metadata[LOG_META_PID])) {
				if (p[1] != ':')
					return;
				metadata[LOG_META_PID].len = p - metadata[LOG_META_PID].ptr;
			}
			p++;
		}
		if (!metadata[LOG_META_TAG].len)
			metadata[LOG_META_TAG].len = p - metadata[LOG_META_TAG].ptr;

		/* let pass ':' and ' ', we still have warranty size is large enough */
		p += 2;

		buflen -= p - buf;
		buf = p;

		*size = buflen;
		*message = buf;
	}

	return;

bad_format:
	/* bad syslog format, we reset all parsed syslog fields
	 * but priority is kept because we are able to re-build
	 * this message using LOF_FORMAT_PRIO.
	 */
	metadata[LOG_META_TIME].len = 0;
	metadata[LOG_META_HOST].len = 0;
	metadata[LOG_META_TAG].len = 0;
	metadata[LOG_META_PID].len = 0;
	metadata[LOG_META_MSGID].len = 0;
	metadata[LOG_META_STDATA].len = 0;

	return;
}

/*
 * UDP syslog fd handler
 */
void syslog_fd_handler(int fd)
{
	static THREAD_LOCAL struct ist metadata[LOG_META_FIELDS];
	ssize_t ret = 0;
	struct buffer *buf = get_trash_chunk();
	size_t size;
	char *message;
	int level;
	int facility;
	struct listener *l = objt_listener(fdtab[fd].owner);
	int max_accept;

	BUG_ON(!l);

	if (fdtab[fd].state & FD_POLL_IN) {

		if (!fd_recv_ready(fd))
			return;

		max_accept = l->bind_conf->maxaccept ? l->bind_conf->maxaccept : 1;

		do {
			/* Source address */
			struct sockaddr_storage saddr = {0};
			socklen_t saddrlen;

			saddrlen = sizeof(saddr);

			ret = recvfrom(fd, buf->area, buf->size, 0, (struct sockaddr *)&saddr, &saddrlen);
			if (ret < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					fd_cant_recv(fd);
				goto out;
			}
			buf->data = ret;

			/* update counters */
			_HA_ATOMIC_INC(&cum_log_messages);
			proxy_inc_fe_req_ctr(l, l->bind_conf->frontend, 0);

			parse_log_message(buf->area, buf->data, &level, &facility, metadata, &message, &size);

			process_send_log(NULL, &l->bind_conf->frontend->loggers, level, facility, metadata, message, size);

		} while (--max_accept);
	}

out:
	return;
}

/*
 * IO Handler to handle message exchange with a syslog tcp client
 */
static void syslog_io_handler(struct appctx *appctx)
{
	static THREAD_LOCAL struct ist metadata[LOG_META_FIELDS];
	struct stconn *sc = appctx_sc(appctx);
	struct stream *s = __sc_strm(sc);
	struct proxy *frontend = strm_fe(s);
	struct listener *l = strm_li(s);
	struct buffer *buf = get_trash_chunk();
	int max_accept;
	int to_skip;
	int facility;
	int level;
	char *message;
	size_t size;

	if (unlikely(se_fl_test(appctx->sedesc, (SE_FL_EOS|SE_FL_ERROR)))) {
		co_skip(sc_oc(sc), co_data(sc_oc(sc)));
		goto out;
	}

	max_accept = l->bind_conf->maxaccept ? l->bind_conf->maxaccept : 1;
	while (1) {
		char c;

		if (max_accept <= 0)
			goto missing_budget;
		max_accept--;

		to_skip = co_getchar(sc_oc(sc), &c);
		if (!to_skip)
			goto missing_data;
		else if (to_skip < 0)
			goto cli_abort;

		if (c == '<') {
			/* rfc-6587, Non-Transparent-Framing: messages separated by
			 * a trailing LF or CR LF
			 */
			to_skip = co_getline(sc_oc(sc), buf->area, buf->size);
			if (!to_skip)
				goto missing_data;
			else if (to_skip < 0)
				goto cli_abort;

			if (buf->area[to_skip - 1] != '\n')
				goto parse_error;

			buf->data = to_skip - 1;

			/* according to rfc-6587, some devices adds CR before LF */
			if (buf->data && buf->area[buf->data - 1] == '\r')
				buf->data--;

		}
		else if ((unsigned char)(c - '1') <= 8) {
			/* rfc-6587, Octet-Counting: message length in ASCII
			 * (first digit can not be ZERO), followed by a space
			 * and message length
			 */
			char *p = NULL;
			int msglen;

			to_skip = co_getword(sc_oc(sc), buf->area, buf->size, ' ');
			if (!to_skip)
				goto missing_data;
			else if (to_skip < 0)
				goto cli_abort;

			if (buf->area[to_skip - 1] != ' ')
				goto parse_error;

			msglen = strtol(buf->area, &p, 10);
			if (!msglen || p != &buf->area[to_skip - 1])
				goto parse_error;

			/* message seems too large */
			if (msglen > buf->size)
				goto parse_error;

			msglen = co_getblk(sc_oc(sc), buf->area, msglen, to_skip);
			if (!msglen)
				goto missing_data;
			else if (msglen < 0)
				goto cli_abort;


			buf->data = msglen;
			to_skip += msglen;
		}
		else
			goto parse_error;

		co_skip(sc_oc(sc), to_skip);

		/* update counters */
		_HA_ATOMIC_INC(&cum_log_messages);
		proxy_inc_fe_req_ctr(l, frontend, 0);

		parse_log_message(buf->area, buf->data, &level, &facility, metadata, &message, &size);

		process_send_log(NULL, &frontend->loggers, level, facility, metadata, message, size);

	}

missing_data:
	/* we need more data to read */
	applet_need_more_data(appctx);
	return;

missing_budget:
	/* it may remain some stuff to do, let's retry later */
	appctx_wakeup(appctx);
	return;

parse_error:
	if (l->counters)
		_HA_ATOMIC_INC(&l->counters->failed_req);
	_HA_ATOMIC_INC(&frontend->fe_counters.failed_req);

	goto error;

cli_abort:
	if (l->counters)
		_HA_ATOMIC_INC(&l->counters->cli_aborts);
	_HA_ATOMIC_INC(&frontend->fe_counters.cli_aborts);

error:
	se_fl_set(appctx->sedesc, SE_FL_ERROR);

out:
	return;
}

static struct applet syslog_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<SYSLOG>", /* used for logging */
	.fct = syslog_io_handler,
	.release = NULL,
};

/* Atomically append an event to applet >ctx>'s output, prepending it with its
 * size in decimal followed by a space. The line is read from vectors <v1> and
 * <v2> at offset <ofs> relative to the area's origin, for <len> bytes. It
 * returns the number of bytes consumed from the input vectors on success, -1
 * if it temporarily cannot (buffer full), -2 if it will never be able to (too
 * large msg). The input vectors are not modified. The caller is responsible for
 * making sure that there are at least ofs+len bytes in the input buffer.
 */
ssize_t syslog_applet_append_event(void *ctx, struct ist v1, struct ist v2, size_t ofs, size_t len)
{
	struct appctx *appctx = ctx;
	char *p;

	/* first, encode the message's size */
	chunk_reset(&trash);
	p = ulltoa(len, trash.area, b_size(&trash));
	if (p) {
		trash.data = p - trash.area;
		trash.area[trash.data++] = ' ';
	}

	/* check if the message has a chance to fit */
	if (unlikely(!p || trash.data + len > b_size(&trash)))
		return -2;

	/* try to transfer it or report full */
	trash.data += vp_peek_ofs(v1, v2, ofs, trash.area + trash.data, len);
	if (applet_putchk(appctx, &trash) == -1)
		return -1;

	/* OK done */
	return len;
}

/*
 * Parse "log-forward" section and create corresponding sink buffer.
 *
 * The function returns 0 in success case, otherwise, it returns error
 * flags.
 */
int cfg_parse_log_forward(const char *file, int linenum, char **args, int kwm)
{
	int err_code = ERR_NONE;
	struct proxy *px;
	char *errmsg = NULL;
	const char *err = NULL;

	if (strcmp(args[0], "log-forward") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for log-forward section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
			         file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		px = log_forward_by_name(args[1]);
		if (px) {
			ha_alert("Parsing [%s:%d]: log-forward section '%s' has the same name as another log-forward section declared at %s:%d.\n",
				 file, linenum, args[1], px->conf.file, px->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		px = proxy_find_by_name(args[1], 0, 0);
		if (px) {
			ha_alert("Parsing [%s:%d]: log forward section '%s' has the same name as %s '%s' declared at %s:%d.\n",
			         file, linenum, args[1], proxy_type_str(px),
			         px->id, px->conf.file, px->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		px = proxy_find_by_name(args[1], PR_CAP_DEF, 0);
		if (px) {
			/* collision with a "defaults" section */
			ha_warning("Parsing [%s:%d]: log-forward section '%s' has the same name as %s '%s' declared at %s:%d."
				   " This is dangerous and will not be supported anymore in version 3.3.\n",
				   file, linenum, args[1], proxy_type_str(px),
				   px->id, px->conf.file, px->conf.line);
			err_code |= ERR_WARN;
		}

		px = calloc(1, sizeof *px);
		if (!px) {
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		init_new_proxy(px);
		px->next = cfg_log_forward;
		cfg_log_forward = px;
		px->conf.file = copy_file_name(file);
		px->conf.line = linenum;
		px->mode = PR_MODE_SYSLOG;
		px->fe_counters.last_change = ns_to_sec(now_ns);
		px->cap = PR_CAP_FE;
		px->maxconn = 10;
		px->timeout.client = TICK_ETERNITY;
		px->accept = frontend_accept;
		px->default_target = &syslog_applet.obj_type;
		px->id = strdup(args[1]);
	}
	else if (strcmp(args[0], "maxconn") == 0) {  /* maxconn */
		if (warnifnotcap(cfg_log_forward, PR_CAP_FE, file, linenum, args[0], " Maybe you want 'fullconn' instead ?"))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		cfg_log_forward->maxconn = atol(args[1]);
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
	}
	else if (strcmp(args[0], "backlog") == 0) {  /* backlog */
		if (warnifnotcap(cfg_log_forward, PR_CAP_FE, file, linenum, args[0], NULL))
			err_code |= ERR_WARN;

		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		cfg_log_forward->backlog = atol(args[1]);
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
	}
	else if (strcmp(args[0], "bind") == 0) {
		int cur_arg;
		struct bind_conf *bind_conf;
		struct listener *l;
		int ret;

		cur_arg = 1;

		bind_conf = bind_conf_alloc(cfg_log_forward, file, linenum,
					    NULL, xprt_get(XPRT_RAW));
		if (!bind_conf) {
			ha_alert("parsing [%s:%d] : out of memory error.", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		bind_conf->maxaccept = global.tune.maxaccept ? global.tune.maxaccept : MAX_ACCEPT;
		bind_conf->accept = session_accept_fd;

		if (!str2listener(args[1], cfg_log_forward, bind_conf, file, linenum, &errmsg)) {
			if (errmsg && *errmsg) {
				indent_msg(&errmsg, 2);
				ha_alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
			}
			else {
				ha_alert("parsing [%s:%d] : '%s %s' : error encountered while parsing listening address %s.\n",
				         file, linenum, args[0], args[1], args[2]);
			}
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		list_for_each_entry(l, &bind_conf->listeners, by_bind) {
			global.maxsock++;
		}
		cur_arg++;

		ret = bind_parse_args_list(bind_conf, args, cur_arg, cursection, file, linenum);
		err_code |= ret;
		if (ret != 0) {
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "dgram-bind") == 0) {
		int cur_arg;
		struct bind_conf *bind_conf;
		struct bind_kw *kw;
		struct listener *l;

		cur_arg = 1;

		bind_conf = bind_conf_alloc(cfg_log_forward, file, linenum,
		                            NULL, xprt_get(XPRT_RAW));
		if (!bind_conf) {
			ha_alert("parsing [%s:%d] : out of memory error.", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		bind_conf->maxaccept = global.tune.maxaccept ? global.tune.maxaccept : MAX_ACCEPT;

		if (!str2receiver(args[1], cfg_log_forward, bind_conf, file, linenum, &errmsg)) {
			if (errmsg && *errmsg) {
				indent_msg(&errmsg, 2);
				ha_alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
			}
			else {
				ha_alert("parsing [%s:%d] : '%s %s' : error encountered while parsing listening address %s.\n",
				         file, linenum, args[0], args[1], args[2]);
			}
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		list_for_each_entry(l, &bind_conf->listeners, by_bind) {
			/* the fact that the sockets are of type dgram is guaranteed by str2receiver() */
			l->rx.iocb   = syslog_fd_handler;
			global.maxsock++;
		}
		cur_arg++;

		while (*args[cur_arg] && (kw = bind_find_kw(args[cur_arg]))) {
			int ret;

			ret = kw->parse(args, cur_arg, cfg_log_forward, bind_conf, &errmsg);
			err_code |= ret;
			if (ret) {
				if (errmsg && *errmsg) {
					indent_msg(&errmsg, 2);
					ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
				}
				else
					ha_alert("parsing [%s:%d]: error encountered while processing '%s'\n",
					         file, linenum, args[cur_arg]);
				if (ret & ERR_FATAL)
					goto out;
			}
			cur_arg += 1 + kw->skip;
		}
		if (*args[cur_arg] != 0) {
			const char *best = bind_find_best_kw(args[cur_arg]);
			if (best)
				ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section; did you mean '%s' maybe ?\n",
					 file, linenum, args[cur_arg], cursection, best);
			else
				ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section.\n",
					 file, linenum, args[cur_arg], cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "log") == 0) {
		if (!parse_logger(args, &cfg_log_forward->loggers, (kwm == KWM_NO), file, linenum, &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			         err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "timeout") == 0) {
		const char *res;
		unsigned timeout;

		if (strcmp(args[1], "client") != 0) {
			ha_alert("parsing [%s:%d] : unknown keyword '%s %s' in log-forward section.\n", file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (*args[2] == 0) {
			ha_alert("parsing [%s:%d] : missing timeout client value.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		res = parse_time_err(args[2], &timeout, TIME_UNIT_MS);
		if (res == PARSE_TIME_OVER) {
			memprintf(&errmsg, "timer overflow in argument '%s' to 'timeout client' (maximum value is 2147483647 ms or ~24.8 days)", args[2]);
		}
		else if (res == PARSE_TIME_UNDER) {
			memprintf(&errmsg, "timer underflow in argument '%s' to 'timeout client' (minimum non-null value is 1 ms)", args[2]);
		}
		else if (res) {
			memprintf(&errmsg, "unexpected character '%c' in 'timeout client'", *res);
		}

		if (res) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		cfg_log_forward->timeout.client = MS_TO_TICKS(timeout);
	}
	else {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in log-forward section.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_ABORT;
		goto out;
	}
out:
	ha_free(&errmsg);
	return err_code;
}

static inline void log_profile_step_init(struct log_profile_step *lprof_step)
{
	lf_expr_init(&lprof_step->logformat);
	lf_expr_init(&lprof_step->logformat_sd);
	lprof_step->flags = LOG_PS_FL_NONE;
}

static inline void log_profile_step_deinit(struct log_profile_step *lprof_step)
{
	if (!lprof_step)
		return;

	lf_expr_deinit(&lprof_step->logformat);
	lf_expr_deinit(&lprof_step->logformat_sd);
}

static inline void log_profile_step_free(struct log_profile_step *lprof_step)
{
	log_profile_step_deinit(lprof_step);
	free(lprof_step);
}

/* postcheck a single log profile step for a given <px> (it is expected to be
 * called at postparsing stage)
 *
 * Returns 1 on success and 0 on error, <msg> will be set on error.
 */
static inline int log_profile_step_postcheck(struct proxy *px, const char *step_name,
                                             struct log_profile_step *step,
                                             char **err)
{
	if (!step)
		return 1; // nothing to do

	if (!lf_expr_isempty(&step->logformat) &&
	    !lf_expr_postcheck(&step->logformat, px, err)) {
		memprintf(err, "'on %s format' in file '%s' at line %d: %s",
		          step_name,
		          step->logformat_sd.conf.file,
		          step->logformat_sd.conf.line,
		          *err);
		return 0;
	}
	if (!lf_expr_isempty(&step->logformat_sd) &&
	    !lf_expr_postcheck(&step->logformat_sd, px, err)) {
		memprintf(err, "'on %s sd' in file '%s' at line %d: %s",
		          step_name,
		          step->logformat_sd.conf.file,
		          step->logformat_sd.conf.line,
		          *err);
		return 0;
	}

	return 1;
}

/* postcheck a log profile struct for a given <px> (it is expected to be called
 * at postparsing stage)
 *
 * Returns 1 on success and 0 on error, <msg> will be set on error.
 */
static int log_profile_postcheck(struct proxy *px, struct log_profile *prof, char **err)
{
	struct eb32_node *node;
	struct log_profile_step_extra *extra;

	/* log profile steps are only relevant under proxy
	 * context
	 */
	if (!px)
		return 1; /* nothing to do */

	/* postcheck lf_expr for log profile steps */
	if (!log_profile_step_postcheck(px, "accept", prof->accept, err) ||
	    !log_profile_step_postcheck(px, "request", prof->request, err) ||
	    !log_profile_step_postcheck(px, "connect", prof->connect, err) ||
	    !log_profile_step_postcheck(px, "response", prof->response, err) ||
	    !log_profile_step_postcheck(px, "close", prof->close, err) ||
	    !log_profile_step_postcheck(px, "error", prof->error, err) ||
	    !log_profile_step_postcheck(px, "any", prof->any, err))
		return 0;

	/* postcheck extra steps (if any) */
	node = eb32_first(&prof->extra);
	while (node) {
		extra = eb32_entry(node, struct log_profile_step_extra, node);
		node = eb32_next(node);
		if (!log_profile_step_postcheck(px, extra->orig->name, &extra->step, err))
			return 0;
	}

	return 1;
}

static void log_profile_free(struct log_profile *prof)
{
	struct eb32_node *node;
	struct log_profile_step_extra *extra;

	ha_free(&prof->id);
	ha_free(&prof->conf.file);
	chunk_destroy(&prof->log_tag);

	log_profile_step_free(prof->accept);
	log_profile_step_free(prof->request);
	log_profile_step_free(prof->connect);
	log_profile_step_free(prof->response);
	log_profile_step_free(prof->close);
	log_profile_step_free(prof->error);
	log_profile_step_free(prof->any);

	/* free extra steps (if any) */
	node = eb32_first(&prof->extra);
	while (node) {
		extra = eb32_entry(node, struct log_profile_step_extra, node);
		node = eb32_next(node);
		eb32_delete(&extra->node);
		log_profile_step_deinit(&extra->step);
		free(extra);
	}

	ha_free(&prof);
}

/* Deinitialize all known log profiles */
static void deinit_log_profiles()
{
	struct log_profile *prof, *back;

	list_for_each_entry_safe(prof, back, &log_profile_list, list) {
		LIST_DEL_INIT(&prof->list);
		log_profile_free(prof);
	}
}

struct log_profile *log_profile_find_by_name(const char *name)
{
	struct log_profile *current;

	list_for_each_entry(current, &log_profile_list, list) {
		if (strcmp(current->id, name) == 0)
			return current;
	}
	return NULL;
}

/*
 * Parse "log-profile" section and register the corresponding profile
 * with its name
 *
 * The function returns 0 in success case, otherwise, it returns error
 * flags.
 */
int cfg_parse_log_profile(const char *file, int linenum, char **args, int kwm)
{
	int err_code = ERR_NONE;
	static struct log_profile *prof = NULL;
	char *errmsg = NULL;
	const char *err = NULL;

	if (strcmp(args[0], "log-profile") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for log-profile section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
			         file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		prof = log_profile_find_by_name(args[1]);
		if (prof) {
			ha_alert("Parsing [%s:%d]: log-profile section '%s' has the same name as another log-profile section declared at %s:%d.\n",
				 file, linenum, args[1], prof->conf.file, prof->conf.line);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		prof = calloc(1, sizeof(*prof));
		if (prof == NULL || !(prof->id = strdup(args[1]))) {
			ha_alert("Parsing [%s:%d]: cannot allocate memory for log-profile section '%s'.\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		prof->conf.file = strdup(file);
		prof->conf.line = linenum;
		prof->extra = EB_ROOT_UNIQUE;

		/* add to list */
		LIST_APPEND(&log_profile_list, &prof->list);
	}
	else if (strcmp(args[0], "log-tag") == 0) {  /* override log-tag */
		if (*(args[1]) == 0) {
			ha_alert("parsing [%s:%d] : '%s' expects a tag for use in syslog.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		chunk_destroy(&prof->log_tag);
		chunk_initlen(&prof->log_tag, strdup(args[1]), strlen(args[1]), strlen(args[1]));
		if (b_orig(&prof->log_tag) == NULL) {
			chunk_destroy(&prof->log_tag);
			ha_alert("parsing [%s:%d]: cannot allocate memory for '%s'.\n", file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "on") == 0) { /* log profile step */
		struct log_profile_step **target_step = NULL;
		struct log_profile_step *extra_step;
		struct lf_expr *target_lf;
		int cur_arg;

		/* get targeted log-profile step:
		 *   first try with native ones
		 */
		if (strcmp(args[1], "accept") == 0)
			target_step = &prof->accept;
		else if (strcmp(args[1], "request") == 0)
			target_step = &prof->request;
		else if (strcmp(args[1], "connect") == 0)
			target_step = &prof->connect;
		else if (strcmp(args[1], "response") == 0)
			target_step = &prof->response;
		else if (strcmp(args[1], "close") == 0)
			target_step = &prof->close;
		else if (strcmp(args[1], "error") == 0)
			target_step = &prof->error;
		else if (strcmp(args[1], "any") == 0)
			target_step = &prof->any;
		else {
			struct log_origin_node *cur;
			struct log_profile_step_extra *extra = NULL;

			/* then try extra ones (if any) */
			list_for_each_entry(cur, &log_origins, list) {
				if (strcmp(args[1], cur->name) == 0) {
					/* found matching one */
					extra = malloc(sizeof(*extra));
					if (extra == NULL) {
						ha_alert("parsing [%s:%d]: cannot allocate memory for '%s %s'.\n", file, linenum, args[0], args[1]);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					log_profile_step_init(&extra->step);
					extra->orig = cur;
					extra->node.key = cur->tree.key;
					eb32_insert(&prof->extra, &extra->node);
					extra_step = &extra->step;
					target_step = &extra_step;
					break;
				}
			}
		}

		if (target_step == NULL) {
			char *extra_origins = NULL;
			struct log_origin_node *cur;

			list_for_each_entry(cur, &log_origins, list) {
				if (extra_origins)
					memprintf(&extra_origins, "%s, '%s'", extra_origins, cur->name);
				else
					memprintf(&extra_origins, "'%s'", cur->name);
			}

			memprintf(&errmsg, "'%s' expects a log step.\n"
			                   "expected values are: 'accept', 'request', 'connect', "
			                   "'response', 'close', 'error' or 'any'.",
			                   args[0]);
			if (extra_origins)
				memprintf(&errmsg, "%s\nOr one of the additional log steps: %s.", errmsg, extra_origins);
			free(extra_origins);

			ha_alert("parsing [%s:%d]: %s\n", file, linenum, errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (*target_step == NULL) {
			/* first time */
			*target_step = malloc(sizeof(**target_step));
			if (*target_step == NULL) {
				ha_alert("parsing [%s:%d]: cannot allocate memory for '%s %s'.\n", file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			log_profile_step_init(*target_step);
		}

		cur_arg = 2;

		while (*(args[cur_arg]) != 0) {
			/* drop logs ? */
			if (strcmp(args[cur_arg], "drop") == 0) {
				if (cur_arg != 2)
					break;
				(*target_step)->flags |= LOG_PS_FL_DROP;
				cur_arg += 1;
				continue;
			}
			/* regular format or SD (structured-data) one? */
			else if (strcmp(args[cur_arg], "format") == 0)
				target_lf = &(*target_step)->logformat;
			else if (strcmp(args[cur_arg], "sd") == 0)
				target_lf = &(*target_step)->logformat_sd;
			else
				break;

			(*target_step)->flags &= ~LOG_PS_FL_DROP;

			/* parse and assign logformat expression */
			lf_expr_deinit(target_lf); /* if already configured */

			if (*(args[cur_arg + 1]) == 0) {
				ha_alert("parsing [%s:%d] : '%s %s %s' expects a logformat string.\n",
				         file, linenum, args[0], args[1], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			target_lf->str = strdup(args[cur_arg + 1]);
			target_lf->conf.file = strdup(file);
			target_lf->conf.line = linenum;

			if (!lf_expr_compile(target_lf, NULL,
			                     LOG_OPT_MANDATORY|LOG_OPT_MERGE_SPACES,
			                     SMP_VAL_FE_LOG_END, &errmsg)) {
				ha_alert("Parsing [%s:%d]: failed to parse logformat: %s.\n",
				         file, linenum, errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			cur_arg += 2;
		}
		if (cur_arg == 2 || *(args[cur_arg]) != 0) {
			ha_alert("parsing [%s:%d] : '%s %s' expects 'drop', 'format' or 'sd'.\n",
			         file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in log-profile section.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_ABORT;
		goto out;
	}
out:
	ha_free(&errmsg);
	return err_code;
}

/* suitable for use with INITCALL0(STG_PREPARE), may not be used anymore
 * once config parsing has started since it will depend on this.
 *
 * Returns the ID of the log origin on success and LOG_ORIG_UNSPEC on failure.
 * ID must be saved for later use (ie: inside static variable), in order
 * to use it as log origin during runtime.
 *
 * If the origin is already defined, the existing ID is returned.
 *
 * Don't forget to update the documentation when new log origins are added
 * (both %OG log alias and on <step> log-profile keyword are concerned)
 */
enum log_orig_id log_orig_register(const char *name)
{
	struct log_origin_node *cur;
	size_t last = 0;

	list_for_each_entry(cur, &log_origins, list) {
		if (strcmp(name, cur->name) == 0)
			return cur->tree.key;
		last = cur->tree.key;
	}
	/* not found, need to register new log origin */

	if (last == LOG_ORIG_EXTRA_SLOTS) {
		ha_alert("Reached maximum number of log origins. Please report to developers if you see this message.\n");
		goto out_error;
	}

	cur = malloc(sizeof(*cur));
	if (cur == NULL)
		goto out_oom;

	cur->name = strdup(name);
	if (!cur->name) {
		free(cur);
		goto out_oom;
	}
	cur->tree.key = LOG_ORIG_EXTRA + last;
	LIST_APPEND(&log_origins, &cur->list);
	eb32_insert(&log_origins_per_id, &cur->tree);
	return cur->tree.key;

 out_oom:
	ha_alert("Failed to register additional log origin. Out of memory\n");
 out_error:
	return LOG_ORIG_UNSPEC;
}

/* Deinitialize all extra log origins */
static void deinit_log_origins()
{
	struct log_origin_node *orig, *back;

	list_for_each_entry_safe(orig, back, &log_origins, list) {
		LIST_DEL_INIT(&orig->list);
		free((char *)orig->name);
		free(orig);
	}
}

/* function: post-resolve a single list of loggers
 *
 * Returns err_code which defaults to ERR_NONE and can be set to a combination
 * of ERR_WARN, ERR_ALERT, ERR_FATAL and ERR_ABORT in case of errors.
 */
int postresolve_logger_list(struct proxy *px, struct list *loggers,
                            const char *section, const char *section_name)
{
	int err_code = ERR_NONE;
	struct logger *logger;

	list_for_each_entry(logger, loggers, list) {
		int cur_code;
		char *msg = NULL;

		cur_code = resolve_logger(px, logger, &msg);
		if (msg) {
			void (*e_func)(const char *fmt, ...) = NULL;

			if (cur_code & ERR_ALERT)
				e_func = ha_alert;
			else if (cur_code & ERR_WARN)
				e_func = ha_warning;
			else
				e_func = ha_diag_warning;
			if (!section)
				e_func("global log directive declared in file %s at line '%d' %s.\n",
				       logger->conf.file, logger->conf.line, msg);
			else
				e_func("log directive declared in %s section '%s' in file '%s' at line %d %s.\n",
				       section, section_name, logger->conf.file, logger->conf.line, msg);
			ha_free(&msg);
		}
		err_code |= cur_code;
	}
	return err_code;
}

/* resolve default log directives at end of config. Returns 0 on success
 * otherwise error flags.
*/
static int postresolve_loggers()
{
	struct proxy *px;
	int err_code = ERR_NONE;

	/* global log directives */
	err_code |= postresolve_logger_list(NULL, &global.loggers, NULL, NULL);
	/* proxy log directives */
	for (px = proxies_list; px; px = px->next)
		err_code |= postresolve_logger_list(px, &px->loggers, "proxy", px->id);
	/* log-forward log directives */
	for (px = cfg_log_forward; px; px = px->next)
		err_code |= postresolve_logger_list(NULL, &px->loggers, "log-forward", px->id);

	return err_code;
}


/* config parsers for this section */
REGISTER_CONFIG_SECTION("log-forward", cfg_parse_log_forward, NULL);
REGISTER_CONFIG_SECTION("log-profile", cfg_parse_log_profile, NULL);

static int px_parse_log_steps(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	char *str;
	size_t cur_sep;
	int retval = -1;

	if (!(curpx->cap & PR_CAP_FE)) {
		memprintf(err, "%s will be ignored because %s '%s' has no frontend capability",
		          args[0], proxy_type_str(curpx), curpx->id);
		retval = 1;
		goto end;
	}

	if (args[1] == NULL) {
		memprintf(err, "%s: invalid arguments, expects 'all' or a composition of logging"
		               "steps separated by spaces.",
		          args[0]);
		goto end;
	}

	if (strcmp(args[1], "all") == 0) {
		/* enable all logging steps */
		curpx->to_log = LW_LOGSTEPS;
		retval = 0;
		goto end;
	}

	/* selectively enable logging steps */
	str = args[1];

	while (str[0]) {
		struct eb32_node *cur_step;
		enum log_orig_id cur_id;

		cur_sep = strcspn(str, ",");

		/* check for valid logging step */
                if (cur_sep == 6 && strncmp(str, "accept", cur_sep) == 0)
			cur_id = LOG_ORIG_TXN_ACCEPT;
                else if (cur_sep == 7 && strncmp(str, "request", cur_sep) == 0)
			cur_id = LOG_ORIG_TXN_REQUEST;
                else if (cur_sep == 7 && strncmp(str, "connect", cur_sep) == 0)
			cur_id = LOG_ORIG_TXN_CONNECT;
                else if (cur_sep == 8 && strncmp(str, "response", cur_sep) == 0)
			cur_id = LOG_ORIG_TXN_RESPONSE;
                else if (cur_sep == 5 && strncmp(str, "close", cur_sep) == 0)
			cur_id = LOG_ORIG_TXN_CLOSE;
		else {
			struct log_origin_node *cur;

			list_for_each_entry(cur, &log_origins, list) {
				if (cur_sep == strlen(cur->name) && strncmp(str, cur->name, cur_sep) == 0) {
					cur_id = cur->tree.key;
					break;
				}
			}

			memprintf(err,
			          "invalid log step name (%.*s). Expected values are: "
			          "accept, request, connect, response, close",
			          (int)cur_sep, str);
                        list_for_each_entry(cur, &log_origins, list)
				memprintf(err, "%s, %s", *err, cur->name);

			goto end;
		}

		cur_step = malloc(sizeof(*cur_step));
		if (!cur_step) {
			memprintf(err, "memory failure when trying to configure log-step (%.*s)",
			          (int)cur_sep, str);
			goto end;
		}
		cur_step->key = cur_id;
		eb32_insert(&curpx->conf.log_steps, cur_step);
 next:
		if (str[cur_sep])
			str += cur_sep + 1;
		else
			str += cur_sep;
	}

	curpx->to_log = LW_LOGSTEPS;
	retval = 0;

 end:
	return retval;
}

/* needed by do_log_parse_act() */
static enum act_return do_log_action(struct act_rule *rule, struct proxy *px,
                                     struct session *sess, struct stream *s, int flags)
{
	/* do_log() expects valid session pointer */
	BUG_ON(sess == NULL);

	do_log(sess, s, log_orig(rule->arg.expr_int.value, LOG_ORIG_FL_NONE));
	return ACT_RET_CONT;
}

/* Parse a "do_log" action. It doesn't take any argument
 * May be used from places where per-context actions are usually registered
 */
enum act_parse_ret do_log_parse_act(enum log_orig_id id,
                                    const char **args, int *orig_arg, struct proxy *px,
                                    struct act_rule *rule, char **err)
{
	rule->action_ptr = do_log_action;
	rule->action = ACT_CUSTOM;
	rule->release_ptr = NULL;
	rule->arg.expr_int.value = id;
	return ACT_RET_PRS_OK;
}

static struct cfg_kw_list cfg_kws_li = {ILH, {
	{ CFG_LISTEN, "log-steps",  px_parse_log_steps },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws_li);

REGISTER_POST_CHECK(postresolve_loggers);
REGISTER_POST_PROXY_CHECK(postcheck_log_backend);
REGISTER_POST_PROXY_CHECK(postcheck_logformat_proxy);

REGISTER_PER_THREAD_ALLOC(init_log_buffers);
REGISTER_PER_THREAD_FREE(deinit_log_buffers);

REGISTER_POST_DEINIT(deinit_log_forward);
REGISTER_POST_DEINIT(deinit_log_profiles);
REGISTER_POST_DEINIT(deinit_log_origins);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
