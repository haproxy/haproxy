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

/*
 * This map is used with all the FD_* macros to check whether a particular bit
 * is set or not. Each bit represents an ASCII code. ha_bit_set() sets those
 * bytes which should be escaped. When ha_bit_test() returns non-zero, it means
 * that the byte should be escaped. Be careful to always pass bytes from 0 to
 * 255 exclusively to the macros.
 */
long rfc5424_escape_map[(256/8) / sizeof(long)];
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


int prepare_addrsource(struct logformat_node *node, struct proxy *curproxy);

/* logformat tag types (internal use) */
enum logformat_tag_type {
	LOG_FMT_GLOBAL,
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

/* log_format tag names */
static const struct logformat_tag logformat_tags[] = {
	{ "o", LOG_FMT_GLOBAL, PR_MODE_TCP, 0, NULL },  /* global option */

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

/* A global syslog message buffer, common to all RFC5424 syslog messages.
 * Currently, it is used for generating the structured-data part.
 */
THREAD_LOCAL char *logline_rfc5424 = NULL;

struct logformat_tag_args {
	char *name;
	int mask;
};

struct logformat_tag_args tag_args_list[] = {
// global
	{ "M", LOG_OPT_MANDATORY },
	{ "Q", LOG_OPT_QUOTE },
	{ "X", LOG_OPT_HEXA },
	{ "E", LOG_OPT_ESC },
	{  0,  0 }
};

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
 * Parse args in a logformat_tag. Returns 0 in error
 * case, otherwise, it returns 1.
 */
int parse_logformat_tag_args(char *args, struct logformat_node *node, char **err)
{
	int i = 0;
	int end = 0;
	int flags = 0;  // 1 = +  2 = -
	char *sp = NULL; // start pointer

	if (args == NULL) {
		memprintf(err, "internal error: parse_logformat_tag_args() expects non null 'args'");
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
			for (i = 0; sp && tag_args_list[i].name; i++) {
				if (strcmp(sp, tag_args_list[i].name) == 0) {
					if (flags == 1) {
						node->options |= tag_args_list[i].mask;
						break;
					} else if (flags == 2) {
						node->options &= ~tag_args_list[i].mask;
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
 * Parse a tag '%tagname' or '%{args}tagname' in log-format. The caller
 * must pass the args part in the <arg> pointer with its length in <arg_len>,
 * and tagname with its length in <tag> and <tag_len> respectively. <arg> is
 * ignored when arg_len is 0. Neither <tag> nor <tag_len> may be null.
 * Returns false in error case and err is filled, otherwise returns true.
 */
static int parse_logformat_tag(char *arg, int arg_len, char *name, int name_len, int typecast,
                               char *tag, int tag_len, struct lf_expr *lf_expr,
                               int *defoptions, char **err)
{
	int j;
	struct list *list_format= &lf_expr->nodes.list;
	struct logformat_node *node = NULL;

	for (j = 0; logformat_tags[j].name; j++) { // search a log type
		if (strlen(logformat_tags[j].name) == tag_len &&
		    strncmp(tag, logformat_tags[j].name, tag_len) == 0) {
			node = calloc(1, sizeof(*node));
			if (!node) {
				memprintf(err, "out of memory error");
				goto error_free;
			}
			node->type = LOG_FMT_TAG;
			node->tag = &logformat_tags[j];
			node->typecast = typecast;
			if (name)
				node->name = my_strndup(name, name_len);
			node->options = *defoptions;
			if (arg_len) {
				node->arg = my_strndup(arg, arg_len);
				if (!parse_logformat_tag_args(node->arg, node, err))
					goto error_free;
			}
			if (node->tag->type == LOG_FMT_GLOBAL) {
				*defoptions = node->options;
				free_logformat_node(node);
			} else {
				LIST_APPEND(list_format, &node->list);
			}
			return 1;
		}
	}

	j = tag[tag_len];
	tag[tag_len] = 0;
	memprintf(err, "no such format tag '%s'. If you wanted to emit the '%%' character verbatim, you need to use '%%%%'", tag);
	tag[tag_len] = j;

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
		memprintf(err, "out of memory error");
		goto error_free;
	}
	if (name)
		node->name = my_strndup(name, name_len);
	node->type = LOG_FMT_EXPR;
	node->typecast = typecast;
	node->expr = expr;
	node->options = options;

	if (arg_len) {
		node->arg = my_strndup(arg, arg_len);
		if (!parse_logformat_tag_args(node->arg, node, err))
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
 * Tag name are preceded by % and composed by characters [a-zA-Z0-9]* : %tagname
 * You can set arguments using { } : %{many arguments}tagname.
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
	char *tag = NULL; /* start pointer for tags */
	char *name = NULL; /* token name (optional) */
	char *typecast_str = NULL; /* token output type (if custom name is set) */
	int arg_len = 0;
	int tag_len = 0;
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
		case LF_STARTTAG:                      // text immediately following a '%'
			arg = NULL; tag = NULL;
			name = NULL;
			name_len = 0;
			typecast = SMP_T_SAME;
			arg_len = tag_len = 0;
			if (*str == '(') {             // custom output name
				cformat = LF_STONAME;
				name = str + 1;
			}
			else
				goto starttag;
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
 starttag:
			if (*str == '{') {             // optional argument
				cformat = LF_STARG;
				arg = str + 1;
			}
			else if (*str == '[') {
				cformat = LF_STEXPR;
				tag = str + 1;         // store expr in tag name
			}
			else if (isalpha((unsigned char)*str)) { // tag name
				cformat = LF_TAG;
				tag = str;
			}
			else if (*str == '%')
				cformat = LF_TEXT;     // convert this character to a literal (useful for '%')
			else if (isdigit((unsigned char)*str) || *str == ' ' || *str == '\t') {
				/* single '%' followed by blank or digit, send them both */
				cformat = LF_TEXT;
				pformat = LF_TEXT; /* finally we include the previous char as well */
				sp = str - 1; /* send both the '%' and the current char */
				memprintf(err, "unexpected tag name near '%c' at position %d line : '%s'. Maybe you want to write a single '%%', use the syntax '%%%%'",
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
				tag = str + 1;         // store expr in tag name
				break;
			}
			else if (isalnum((unsigned char)*str)) { // tag name
				cformat = LF_TAG;
				tag = str;
				break;
			}
			memprintf(err, "parse argument modifier without tag name near '%%{%s}'", arg);
			goto fail;

		case LF_STEXPR:                        // text immediately following '%['
			/* the whole sample expression is parsed at once,
			 * returning the pointer to the first character not
			 * part of the expression, which MUST be the trailing
			 * angle bracket.
			 */
			if (!add_sample_to_logformat_list(tag, name, name_len, typecast, arg, arg_len, lf_expr, al, options, cap, err, &str))
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
					memprintf(err, "expected ']' after '%s', but found '%c'", tag, c);
				else
					memprintf(err, "missing ']' after '%s'", tag);
				goto fail;
			}
			break;

		case LF_TAG:                           // text part of a tag name
			tag_len = str - tag;
			if (!isalnum((unsigned char)*str))
				cformat = LF_INIT;     // not tag name anymore
			break;

		default:                               // LF_INIT, LF_TEXT, LF_SEPARATOR, LF_END, LF_EDEXPR
			cformat = LF_INIT;
		}

		if (cformat == LF_INIT) { /* resynchronize state to text/sep/starttag */
			switch (*str) {
			case '%': cformat = LF_STARTTAG;  break;
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
			case LF_TAG:
				if (!parse_logformat_tag(arg, arg_len, name, name_len, typecast, tag, tag_len, lf_expr, &options, err))
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

	if (pformat == LF_STARTTAG || pformat == LF_STARG || pformat == LF_STEXPR || pformat == LF_STONAME || pformat == LF_STOTYPE || pformat == LF_EDONAME) {
		memprintf(err, "truncated line after '%s'", tag ? tag : arg ? arg : "%");
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

	if (!(curproxy->flags & PR_FL_CHECKED)) {
		/* add the lf_expr to the proxy checks to delay postparsing
		 * since config-related proxy properties are not stable yet
		 */
		LIST_APPEND(&curproxy->conf.lf_checks, &lf_expr->list);
	}
	else {
		/* probably called during runtime or with proxy already checked,
		 * perform the postcheck right away
		 */
		if (!lf_expr_postcheck(lf_expr, curproxy, err))
			goto fail;
	}
	return 1;

 fail:
	lf_expr_deinit(lf_expr);
	return 0;
}

/* Performs a postparsing check on logformat expression <expr> for a given <px>
 * proxy. The function will behave differently depending on the proxy state
 * (during parsing we will try to adapt proxy configuration to make it
 * compatible with logformat expression, but once the proxy is checked, we fail
 * as soon as we face incompatibilities)
 *
 * It returns 1 on success and 0 on error, <err> will be set in case of error.
 */
int lf_expr_postcheck(struct lf_expr *lf_expr, struct proxy *px, char **err)
{
	struct logformat_node *lf;

	if (!(px->flags & PR_FL_CHECKED))
		px->to_log |= LW_INIT;

	list_for_each_entry(lf, &lf_expr->nodes.list, list) {
		if (lf->type == LOG_FMT_EXPR) {
			struct sample_expr *expr = lf->expr;
			uint8_t http_needed = !!(expr->fetch->use & SMP_USE_HTTP_ANY);

			if ((px->flags & PR_FL_CHECKED)) {
				/* fail as soon as proxy properties are not compatible */
				if (http_needed && !px->http_needed) {
					memprintf(err, "sample fetch '%s' requires HTTP enabled proxy which is not available here",
					          expr->fetch->kw);
					goto fail;
				}
				continue;
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
		else if (lf->type == LOG_FMT_TAG) {
			if (lf->tag->mode == PR_MODE_HTTP && px->mode != PR_MODE_HTTP) {
				memprintf(err, "format tag '%s' is reserved for HTTP mode",
				          lf->tag->name);
				goto fail;
			}
			if (lf->tag->config_callback &&
			    !lf->tag->config_callback(lf, px)) {
				memprintf(err, "cannot configure format tag '%s' in this context",
				          lf->tag->name);
				goto fail;
			}
			if (!(px->flags & PR_FL_CHECKED))
				px->to_log |= lf->tag->lw;
		}
	}
	if ((px->to_log & (LW_REQ | LW_RESP)) &&
	    (px->mode != PR_MODE_HTTP && !(px->options & PR_O_HTTP_UPG))) {
		memprintf(err, "logformat expression not usable here (at least one node depends on HTTP mode)");
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
		ha_warning("Cannot set \"server_id_hdr_name\" with 'mode log' in %s '%s'. It will be ignored.\n",
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

/* resolves a single logger entry (it is expected to be called
 * at postparsing stage)
 *
 * <logger> is parent logger used for implicit settings
 *
 * Returns err_code which defaults to ERR_NONE and can be set to a combination
 * of ERR_WARN, ERR_ALERT, ERR_FATAL and ERR_ABORT in case of errors.
 * <msg> could be set at any time (it will usually be set on error, but
 * could also be set when no error occurred to report a diag warning), thus is
 * up to the caller to check it and to free it.
 */
int resolve_logger(struct logger *logger, char **msg)
{
	struct log_target *target = &logger->target;
	int err_code = ERR_NONE;

	if (target->type == LOG_TARGET_BUFFER)
		err_code = sink_resolve_logger_buffer(logger, msg);
	else if (target->type == LOG_TARGET_BACKEND) {
		struct proxy *be;

		/* special case */
		be = proxy_find_by_name(target->be_name, PR_CAP_BE, 0);
		if (!be) {
			memprintf(msg, "uses unknown log backend '%s'", target->be_name);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		else if (be->mode != PR_MODE_SYSLOG) {
			memprintf(msg, "uses incompatible log backend '%s'", target->be_name);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		ha_free(&target->be_name); /* backend is resolved and will replace name hint */
		target->be = be;
	}

 end:
	target->flags |= LOG_TARGET_FL_RESOLVED;

	return err_code;
}

/* tries to duplicate <def> logger
 *
 * Returns the newly allocated and duplicated logger or NULL
 * in case of error.
 */
struct logger *dup_logger(struct logger *def)
{
	struct logger *cpy = malloc(sizeof(*cpy));

	/* copy everything that can be easily copied */
	memcpy(cpy, def, sizeof(*cpy));

	/* default values */
	cpy->conf.file = NULL;
	LIST_INIT(&cpy->list);

	/* special members */
	if (dup_log_target(&def->target, &cpy->target) == 0)
		goto error;
	if (def->conf.file) {
		cpy->conf.file = strdup(def->conf.file);
		if (!cpy->conf.file)
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
	                  err, NULL, NULL,
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

/*
 * Encode the string.
 *
 * When using the +E log format option, it will try to escape '"\]'
 * characters with '\' as prefix. The same prefix should not be used as
 * <escape>.
 *
 * Return the address of the \0 character, or NULL on error
 */
static char *lf_encode_string(char *start, char *stop,
                              const char escape, const long *map,
                              const char *string,
                              struct logformat_node *node)
{
	if (node->options & LOG_OPT_ESC) {
		if (start < stop) {
			stop--; /* reserve one byte for the final '\0' */
			while (start < stop && *string != '\0') {
				if (!ha_bit_test((unsigned char)(*string), map)) {
					if (!ha_bit_test((unsigned char)(*string), rfc5424_escape_map))
						*start++ = *string;
					else {
						if (start + 2 >= stop)
							break;
						*start++ = '\\';
						*start++ = *string;
					}
				}
				else {
					if (start + 3 >= stop)
						break;
					*start++ = escape;
					*start++ = hextab[(*string >> 4) & 15];
					*start++ = hextab[*string & 15];
				}
				string++;
			}
			*start = '\0';
			return start;
		}
	}
	else {
		return encode_string(start, stop, escape, map, string);
	}

	return NULL;
}

/*
 * Encode the chunk.
 *
 * When using the +E log format option, it will try to escape '"\]'
 * characters with '\' as prefix. The same prefix should not be used as
 * <escape>.
 *
 * Return the address of the \0 character, or NULL on error
 */
static char *lf_encode_chunk(char *start, char *stop,
                             const char escape, const long *map,
                             const struct buffer *chunk,
                             struct logformat_node *node)
{
	char *str, *end;

	if (node->options & LOG_OPT_ESC) {
		if (start < stop) {
			str = chunk->area;
			end = chunk->area + chunk->data;

			stop--; /* reserve one byte for the final '\0' */
			while (start < stop && str < end) {
				if (!ha_bit_test((unsigned char)(*str), map)) {
					if (!ha_bit_test((unsigned char)(*str), rfc5424_escape_map))
						*start++ = *str;
					else {
						if (start + 2 >= stop)
							break;
						*start++ = '\\';
						*start++ = *str;
					}
				}
				else {
					if (start + 3 >= stop)
						break;
					*start++ = escape;
					*start++ = hextab[(*str >> 4) & 15];
					*start++ = hextab[*str & 15];
				}
				str++;
			}
			*start = '\0';
			return start;
		}
	}
	else {
		return encode_chunk(start, stop, escape, map, chunk);
	}

	return NULL;
}

/*
 * Write a string in the log string
 * Take cares of quote and escape options
 *
 * Return the address of the \0 character, or NULL on error
 */
char *lf_text_len(char *dst, const char *src, size_t len, size_t size, const struct logformat_node *node)
{
	if (size < 2)
		return NULL;

	if (node->options & LOG_OPT_QUOTE) {
		*(dst++) = '"';
		size--;
	}

	if (src && len) {
		/* escape_string and strlcpy2 will both try to add terminating NULL-byte
		 * to dst
		 */
		if (node->options & LOG_OPT_ESC) {
			char *ret;

			ret = escape_string(dst, dst + size, '\\', rfc5424_escape_map, src, src + len);
			if (ret == NULL)
				return NULL;
			len = ret - dst;
		}
		else {
			if (++len > size)
				len = size;
			len = strlcpy2(dst, src, len);
		}

		size -= len;
		dst += len;
	}
	else if ((node->options & (LOG_OPT_QUOTE|LOG_OPT_MANDATORY)) == LOG_OPT_MANDATORY) {
		if (size < 2)
			return NULL;
		*(dst++) = '-';
		size -= 1;
	}

	if (node->options & LOG_OPT_QUOTE) {
		if (size < 2)
			return NULL;
		*(dst++) = '"';
	}

	*dst = '\0';
	return dst;
}

static inline char *lf_text(char *dst, const char *src, size_t size, const struct logformat_node *node)
{
	return lf_text_len(dst, src, size, size, node);
}

/*
 * Write a IP address to the log string
 * +X option write in hexadecimal notation, most significant byte on the left
 */
char *lf_ip(char *dst, const struct sockaddr *sockaddr, size_t size, const struct logformat_node *node)
{
	char *ret = dst;
	int iret;
	char pn[INET6_ADDRSTRLEN];

	if (node->options & LOG_OPT_HEXA) {
		unsigned char *addr = NULL;
		switch (sockaddr->sa_family) {
		case AF_INET:
			addr = (unsigned char *)&((struct sockaddr_in *)sockaddr)->sin_addr.s_addr;
			iret = snprintf(dst, size, "%02X%02X%02X%02X", addr[0], addr[1], addr[2], addr[3]);
			break;
		case AF_INET6:
			addr = (unsigned char *)&((struct sockaddr_in6 *)sockaddr)->sin6_addr.s6_addr;
			iret = snprintf(dst, size, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
			                addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
			break;
		default:
			return NULL;
		}
		if (iret < 0 || iret >= size)
			return NULL;
		ret += iret;
	} else {
		addr_to_str((struct sockaddr_storage *)sockaddr, pn, sizeof(pn));
		ret = lf_text(dst, pn, size, node);
		if (ret == NULL)
			return NULL;
	}
	return ret;
}

/*
 * Write a port to the log
 * +X option write in hexadecimal notation, most significant byte on the left
 */
char *lf_port(char *dst, const struct sockaddr *sockaddr, size_t size, const struct logformat_node *node)
{
	char *ret = dst;
	int iret;

	if (node->options & LOG_OPT_HEXA) {
		const unsigned char *port = (const unsigned char *)&((struct sockaddr_in *)sockaddr)->sin_port;
		iret = snprintf(dst, size, "%02X%02X", port[0], port[1]);
		if (iret < 0 || iret >= size)
			return NULL;
		ret += iret;
	} else {
		ret = ltoa_o(get_host_port((struct sockaddr_storage *)sockaddr), dst, size);
		if (ret == NULL)
			return NULL;
	}
	return ret;
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

	__send_log((p ? &p->loggers : NULL), (p ? &p->log_tag : NULL), level,
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
	else if (target->addr->ss_family == AF_UNIX)
		plogfd = &logfdunix;
	else
		plogfd = &logfdinet;

	if (plogfd && unlikely(*plogfd < 0)) {
		/* socket not successfully initialized yet */
		if ((*plogfd = socket(target->addr->ss_family, SOCK_DGRAM,
		                      (target->addr->ss_family == AF_UNIX) ? 0 : IPPROTO_UDP)) < 0) {
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

/*
 * This function sends a syslog message.
 * It doesn't care about errors nor does it report them.
 * The argument <metadata> MUST be an array of size
 * LOG_META_FIELDS*sizeof(struct ist)  containing
 * data to build the header.
 */
void process_send_log(struct list *loggers, int level, int facility,
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
			if (logger->target.type == LOG_TARGET_BACKEND) {
				__do_send_log_backend(logger->target.be, hdr, nblogger, logger->maxlen, message, size);
			}
			else {
				/* normal target */
				__do_send_log(&logger->target, hdr, nblogger, logger->maxlen, message, size);
			}
		}
	}
}

/*
 * This function sends a syslog message.
 * It doesn't care about errors nor does it report them.
 * The arguments <sd> and <sd_size> are used for the structured-data part
 * in RFC5424 formatted syslog messages.
 */
void __send_log(struct list *loggers, struct buffer *tagb, int level,
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

	metadata[LOG_META_STDATA] = ist2(sd, sd_size);

	/* Remove trailing space of structured data */
	while (metadata[LOG_META_STDATA].len && metadata[LOG_META_STDATA].ptr[metadata[LOG_META_STDATA].len-1] == ' ')
		metadata[LOG_META_STDATA].len--;

	return process_send_log(loggers, level, -1, metadata, message, size);
}

const char sess_cookie[8]     = "NIDVEOU7";	/* No cookie, Invalid cookie, cookie for a Down server, Valid cookie, Expired cookie, Old cookie, Unused, unknown */
const char sess_set_cookie[8] = "NPDIRU67";	/* No set-cookie, Set-cookie found and left unchanged (passive),
						   Set-cookie Deleted, Set-Cookie Inserted, Set-cookie Rewritten,
						   Set-cookie Updated, unknown, unknown */

/*
 * try to write a character if there is enough space, or goto out
 */
#define LOGCHAR(x) do { \
			if (tmplog < dst + maxsize - 1) { \
				*(tmplog++) = (x);                     \
			} else {                                       \
				goto out;                              \
			}                                              \
		} while(0)

/* start quoting the upcoming text if quoting is enabled. The final quote
 * will automatically be added (because quote is set to 1).
 */
#define LOGQUOTE_START() do {                                          \
			if (tmp->options & LOG_OPT_QUOTE) {            \
				LOGCHAR('"');                          \
				quote = 1;                             \
			}                                              \
		} while (0)

/* properly finish a quotation that was started using LOGQUOTE_START */
#define LOGQUOTE_END() do {                                            \
			if (quote) {                                   \
				LOGCHAR('"');                          \
				quote = 0;                             \
			}                                              \
		} while (0)

/* Prints additional logvalue hint represented by <chr>.
 * It is useful to express that <chr> is not part of the "raw" value and
 * should be considered as optional metadata instead.
 */
#define LOGMETACHAR(chr) do {                                          \
			LOGCHAR(chr);                                  \
		} while (0)

/* indicate the start of a string array */
#define LOG_STRARRAY_START() do {                                      \
		} while (0)

/* indicate that a new element is added to the string array */
#define LOG_STRARRAY_NEXT() do {                                       \
			LOGCHAR(' ');                                  \
		} while (0)

/* indicate the end of a string array */
#define LOG_STRARRAY_END() do {                                        \
		} while (0)

/* Initializes some log data at boot */
static void init_log()
{
	char *tmp;
	int i;

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
	return 1;
}

/* Deinitialize log buffers used for syslog messages */
void deinit_log_buffers()
{
	free(logline);
	free(logline_rfc5424);
	logline           = NULL;
	logline_rfc5424   = NULL;
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
int sess_build_logline(struct session *sess, struct stream *s, char *dst, size_t maxsize, struct lf_expr *lf_expr)
{
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

	/* fill logbuffer */
	if (lf_expr_isempty(lf_expr))
		return 0;

	list_for_each_entry(tmp, list_format, list) {
#ifdef USE_OPENSSL
		struct connection *conn;
#endif
		const struct sockaddr_storage *addr;
		const char *src = NULL;
		struct sample *key;
		const struct buffer empty = { };
		int quote = 0; /* inside quoted string */

		switch (tmp->type) {
			case LOG_FMT_SEPARATOR:
				if (!last_isspace) {
					LOGCHAR(' ');
					last_isspace = 1;
				}
				break;

			case LOG_FMT_TEXT: // text
				src = tmp->arg;
				iret = strlcpy2(tmplog, src, dst + maxsize - tmplog);
				if (iret == 0)
					goto out;
				tmplog += iret;
				break;

			case LOG_FMT_EXPR: // sample expression, may be request or response
				key = NULL;
				if (tmp->options & LOG_OPT_REQ_CAP)
					key = sample_fetch_as_type(be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, tmp->expr, SMP_T_STR);

				if (!key && (tmp->options & LOG_OPT_RES_CAP))
					key = sample_fetch_as_type(be, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL, tmp->expr, SMP_T_STR);

				if (!key && !(tmp->options & (LOG_OPT_REQ_CAP|LOG_OPT_RES_CAP))) // cfg, cli
					key = sample_fetch_as_type(be, sess, s, SMP_OPT_FINAL, tmp->expr, SMP_T_STR);

				if (tmp->options & LOG_OPT_HTTP)
					ret = lf_encode_chunk(tmplog, dst + maxsize,
					                      '%', http_encode_map, key ? &key->data.u.str : &empty, tmp);
				else
					ret = lf_text_len(tmplog,
							  key ? key->data.u.str.area : NULL,
							  key ? key->data.u.str.data : 0,
							  dst + maxsize - tmplog,
							  tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
		}

		if (tmp->type != LOG_FMT_TAG)
			goto next_fmt;

		/* logformat tag */
		switch (tmp->tag->type) {
			case LOG_FMT_CLIENTIP:  // %ci
				addr = (s ? sc_src(s->scf) : sess_src(sess));
				if (addr)
					ret = lf_ip(tmplog, (struct sockaddr *)addr, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_CLIENTPORT:  // %cp
				addr = (s ? sc_src(s->scf) : sess_src(sess));
				if (addr) {
					/* sess->listener is always defined when the session's owner is an inbound connections */
					if (addr->ss_family == AF_UNIX)
						ret = ltoa_o(sess->listener->luid, tmplog, dst + maxsize - tmplog);
					else
						ret = lf_port(tmplog, (struct sockaddr *)addr, dst + maxsize - tmplog, tmp);
				}
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_FRONTENDIP: // %fi
				addr = (s ? sc_dst(s->scf) : sess_dst(sess));
				if (addr)
					ret = lf_ip(tmplog, (struct sockaddr *)addr, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case  LOG_FMT_FRONTENDPORT: // %fp
				addr = (s ? sc_dst(s->scf) : sess_dst(sess));
				if (addr) {
					/* sess->listener is always defined when the session's owner is an inbound connections */
					if (addr->ss_family == AF_UNIX)
						ret = ltoa_o(sess->listener->luid, tmplog, dst + maxsize - tmplog);
					else
						ret = lf_port(tmplog, (struct sockaddr *)addr, dst + maxsize - tmplog, tmp);
				}
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BACKENDIP:  // %bi
				if (be_conn && conn_get_src(be_conn))
					ret = lf_ip(tmplog, (const struct sockaddr *)be_conn->src, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BACKENDPORT:  // %bp
				if (be_conn && conn_get_src(be_conn))
					ret = lf_port(tmplog, (struct sockaddr *)be_conn->src, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_SERVERIP: // %si
				if (be_conn && conn_get_dst(be_conn))
					ret = lf_ip(tmplog, (struct sockaddr *)be_conn->dst, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_SERVERPORT: // %sp
				if (be_conn && conn_get_dst(be_conn))
					ret = lf_port(tmplog, (struct sockaddr *)be_conn->dst, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_DATE: // %t = accept date
				get_localtime(logs->accept_date.tv_sec, &tm);
				ret = date2str_log(tmplog, &tm, &logs->accept_date, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_tr: // %tr = start of request date
				/* Note that the timers are valid if we get here */
				tv_ms_add(&tv, &logs->accept_date, logs->t_idle >= 0 ? logs->t_idle + logs->t_handshake : 0);
				get_localtime(tv.tv_sec, &tm);
				ret = date2str_log(tmplog, &tm, &tv, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_DATEGMT: // %T = accept date, GMT
				get_gmtime(logs->accept_date.tv_sec, &tm);
				ret = gmt2str_log(tmplog, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_trg: // %trg = start of request date, GMT
				tv_ms_add(&tv, &logs->accept_date, logs->t_idle >= 0 ? logs->t_idle + logs->t_handshake : 0);
				get_gmtime(tv.tv_sec, &tm);
				ret = gmt2str_log(tmplog, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_DATELOCAL: // %Tl = accept date, local
				get_localtime(logs->accept_date.tv_sec, &tm);
				ret = localdate2str_log(tmplog, logs->accept_date.tv_sec, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_trl: // %trl = start of request date, local
				tv_ms_add(&tv, &logs->accept_date, logs->t_idle >= 0 ? logs->t_idle + logs->t_handshake : 0);
				get_localtime(tv.tv_sec, &tm);
				ret = localdate2str_log(tmplog, tv.tv_sec, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TS: // %Ts
				if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%04X", (unsigned int)logs->accept_date.tv_sec);
					if (iret < 0 || iret >= dst + maxsize - tmplog)
						goto out;
					tmplog += iret;
				} else {
					ret = ltoa_o(logs->accept_date.tv_sec, tmplog, dst + maxsize - tmplog);
					if (ret == NULL)
						goto out;
					tmplog = ret;
				}
			break;

			case LOG_FMT_MS: // %ms
			if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%02X",(unsigned int)logs->accept_date.tv_usec/1000);
					if (iret < 0 || iret >= dst + maxsize - tmplog)
						goto out;
					tmplog += iret;
			} else {
				if ((dst + maxsize - tmplog) < 4)
					goto out;
				ret = utoa_pad((unsigned int)logs->accept_date.tv_usec/1000,
				               tmplog, 4);
				if (ret == NULL)
					goto out;
				tmplog = ret;
			}
			break;

			case LOG_FMT_FRONTEND: // %f
				src = fe->id;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_FRONTEND_XPRT: // %ft
				src = fe->id;
				LOGQUOTE_START();
				iret = strlcpy2(tmplog, src, dst + maxsize - tmplog);
				if (iret == 0)
					goto out;
				tmplog += iret;

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
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
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
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;
#endif
			case LOG_FMT_BACKEND: // %b
				src = be->id;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
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
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_Th: // %Th = handshake time
				ret = ltoa_o(logs->t_handshake, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_Ti: // %Ti = HTTP idle time
				ret = ltoa_o(logs->t_idle, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TR: // %TR = HTTP request time
				ret = ltoa_o((t_request >= 0) ? t_request - logs->t_idle - logs->t_handshake : -1,
				             tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TQ: // %Tq = Th + Ti + TR
				ret = ltoa_o(t_request, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TW: // %Tw
				ret = ltoa_o((logs->t_queue >= 0) ? logs->t_queue - t_request : -1,
						tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TC: // %Tc
				ret = ltoa_o((logs->t_connect >= 0) ? logs->t_connect - logs->t_queue : -1,
						tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_Tr: // %Tr
				ret = ltoa_o((logs->t_data >= 0) ? logs->t_data - logs->t_connect : -1,
						tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TD: // %Td
				if (be->mode == PR_MODE_HTTP)
					ret = ltoa_o((logs->t_data >= 0) ? logs->t_close - logs->t_data : -1,
					             tmplog, dst + maxsize - tmplog);
				else
					ret = ltoa_o((logs->t_connect >= 0) ? logs->t_close - logs->t_connect : -1,
					             tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_Ta:  // %Ta = active time = Tt - Th - Ti
				if (!(fe->to_log & LW_BYTES))
					LOGMETACHAR('+');
				ret = ltoa_o(logs->t_close - (logs->t_idle >= 0 ? logs->t_idle + logs->t_handshake : 0),
					     tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TT:  // %Tt = total time
				if (!(fe->to_log & LW_BYTES))
					LOGMETACHAR('+');
				ret = ltoa_o(logs->t_close, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TU:  // %Tu = total time seen by user = Tt - Ti
				if (!(fe->to_log & LW_BYTES))
					LOGMETACHAR('+');
				ret = ltoa_o(logs->t_close - (logs->t_idle >= 0 ? logs->t_idle : 0),
					     tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_STATUS: // %ST
				ret = ltoa_o(status, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BYTES: // %B
				if (!(fe->to_log & LW_BYTES))
					LOGMETACHAR('+');
				ret = lltoa(logs->bytes_out, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BYTES_UP: // %U
				ret = lltoa(logs->bytes_in, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_CCLIENT: // %CC
				src = txn ? txn->cli_cookie : NULL;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_CSERVER: // %CS
				src = txn ? txn->srv_cookie : NULL;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_TERMSTATE: // %ts
				LOGCHAR(sess_term_cond[(s_flags & SF_ERR_MASK) >> SF_ERR_SHIFT]);
				LOGCHAR(sess_fin_state[(s_flags & SF_FINST_MASK) >> SF_FINST_SHIFT]);
				*tmplog = '\0';
				break;

			case LOG_FMT_TERMSTATE_CK: // %tsc, same as TS with cookie state (for mode HTTP)
				LOGCHAR(sess_term_cond[(s_flags & SF_ERR_MASK) >> SF_ERR_SHIFT]);
				LOGCHAR(sess_fin_state[(s_flags & SF_FINST_MASK) >> SF_FINST_SHIFT]);
				LOGCHAR((txn && (be->ck_opts & PR_CK_ANY)) ? sess_cookie[(txn->flags & TX_CK_MASK) >> TX_CK_SHIFT] : '-');
				LOGCHAR((txn && (be->ck_opts & PR_CK_ANY)) ? sess_set_cookie[(txn->flags & TX_SCK_MASK) >> TX_SCK_SHIFT] : '-');
				break;

			case LOG_FMT_ACTCONN: // %ac
				ret = ltoa_o(actconn, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_FECONN:  // %fc
				ret = ltoa_o(fe->feconn, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BECONN:  // %bc
				ret = ltoa_o(be->beconn, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_SRVCONN:  // %sc
				switch (obj_type(s ? s->target : sess->origin)) {
				case OBJ_TYPE_SERVER:
					ret = ultoa_o(__objt_server(s->target)->cur_sess,
						      tmplog, dst + maxsize - tmplog);
					break;
				case OBJ_TYPE_CHECK:
					ret = ultoa_o(__objt_check(sess->origin)->server
						      ? __objt_check(sess->origin)->server->cur_sess
						      : 0, tmplog, dst + maxsize - tmplog);
					break;
				default:
					ret = ultoa_o(0, tmplog, dst + maxsize - tmplog);
					break;
				}

				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_RETRIES:  // %rc
				if (s_flags & SF_REDISP)
					LOGMETACHAR('+');
				ret = ltoa_o((s  ? s->conn_retries : 0), tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_SRVQUEUE: // %sq
				ret = ltoa_o(logs->srv_queue_pos, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_BCKQUEUE:  // %bq
				ret = ltoa_o(logs->prx_queue_pos, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_HDRREQUEST: // %hr
				/* request header */
				if (fe->nb_req_cap && s && s->req_cap) {
					LOGQUOTE_START();
					LOGCHAR('{');
					for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
						if (hdr)
							LOGCHAR('|');
						if (s->req_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->req_cap[hdr], tmp);
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
						LOGQUOTE_START();
						if (s->req_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->req_cap[hdr], tmp);
							if (ret == NULL)
								goto out;
							tmplog = ret;
						} else if (!(tmp->options & LOG_OPT_QUOTE))
							LOGCHAR('-');
						/* Manually end quotation as we're emitting multiple
						 * quoted texts at once
						 */
						LOGQUOTE_END();
					}
					LOG_STRARRAY_END();
				}
				break;


			case LOG_FMT_HDRRESPONS: // %hs
				/* response header */
				if (fe->nb_rsp_cap && s && s->res_cap) {
					LOGQUOTE_START();
					LOGCHAR('{');
					for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
						if (hdr)
							LOGCHAR('|');
						if (s->res_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->res_cap[hdr], tmp);
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
						LOGQUOTE_START();
						if (s->res_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->res_cap[hdr], tmp);
							if (ret == NULL)
								goto out;
							tmplog = ret;
						} else if (!(tmp->options & LOG_OPT_QUOTE))
							LOGCHAR('-');
						/* Manually end quotation as we're emitting multiple
						 * quoted texts at once
						 */
						LOGQUOTE_END();
					}
					LOG_STRARRAY_END();
				}
				break;

			case LOG_FMT_REQ: // %r
				/* Request */
				LOGQUOTE_START();
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";
				ret = lf_encode_string(tmplog, dst + maxsize,
				                       '#', url_encode_map, uri, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_HTTP_PATH: // %HP
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";

				LOGQUOTE_START();

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

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_HTTP_PATH_ONLY: // %HPO
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";

				LOGQUOTE_START();

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

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_HTTP_QUERY: // %HQ
				LOGQUOTE_START();

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

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_HTTP_URI: // %HU
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";

				LOGQUOTE_START();

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

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_HTTP_METHOD: // %HM
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";
				LOGQUOTE_START();

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

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_HTTP_VERSION: // %HV
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";
				LOGQUOTE_START();

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

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL)
					goto out;

				tmplog = ret;

				break;

			case LOG_FMT_COUNTER: // %rt
				if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%04X", uniq_id);
					if (iret < 0 || iret >= dst + maxsize - tmplog)
						goto out;
					tmplog += iret;
				} else {
					ret = ltoa_o(uniq_id, tmplog, dst + maxsize - tmplog);
					if (ret == NULL)
						goto out;
					tmplog = ret;
				}
				break;

			case LOG_FMT_LOGCNT: // %lc
				if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%04X", fe->log_count);
					if (iret < 0 || iret >= dst + maxsize - tmplog)
						goto out;
					tmplog += iret;
				} else {
					ret = ultoa_o(fe->log_count, tmplog, dst + maxsize - tmplog);
					if (ret == NULL)
						goto out;
					tmplog = ret;
				}
				break;

			case LOG_FMT_HOSTNAME: // %H
				src = hostname;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

			case LOG_FMT_PID: // %pid
				if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%04X", pid);
					if (iret < 0 || iret >= dst + maxsize - tmplog)
						goto out;
					tmplog += iret;
				} else {
					ret = ltoa_o(pid, tmplog, dst + maxsize - tmplog);
					if (ret == NULL)
						goto out;
					tmplog = ret;
				}
				break;

			case LOG_FMT_UNIQUEID: // %ID
				ret = NULL;
				if (s)
					ret = lf_text_len(tmplog, s->unique_id.ptr, s->unique_id.len, maxsize - (tmplog - dst), tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, maxsize - (tmplog - dst), tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				break;

		}
 next_fmt:
		if (tmp->type != LOG_FMT_SEPARATOR)
			last_isspace = 0; // not a separator, hence not a space

		/* if quotation was started for the current node data, we need
		 * to finish the quote
		 */
		LOGQUOTE_END();
	}

out:
	/* *tmplog is a unused character */
	*tmplog = '\0';
	return tmplog - dst;

}

/*
 * send a log for the stream when we have enough info about it.
 * Will not log if the frontend has no log defined.
 */
void strm_log(struct stream *s)
{
	struct session *sess = s->sess;
	int size, err, level;
	int sd_size = 0;

	/* if we don't want to log normal traffic, return now */
	err = (s->flags & SF_REDISP) ||
              ((s->flags & SF_ERR_MASK) > SF_ERR_LOCAL) ||
	      (((s->flags & SF_ERR_MASK) == SF_ERR_NONE) && s->conn_retries) ||
	      ((sess->fe->mode == PR_MODE_HTTP) && s->txn && s->txn->status >= 500);

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
		sd_size = build_logline(s, logline_rfc5424, global.max_syslog_len,
		                        &sess->fe->logformat_sd);
	}

	size = build_logline(s, logline, global.max_syslog_len, &sess->fe->logformat);
	if (size > 0) {
		_HA_ATOMIC_INC(&sess->fe->log_count);
		__send_log(&sess->fe->loggers, &sess->fe->log_tag, level,
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
 */
void sess_log(struct session *sess)
{
	int size, level;
	int sd_size = 0;

	if (!sess)
		return;

	if (LIST_ISEMPTY(&sess->fe->loggers))
		return;

	level = LOG_INFO;
	if (sess->fe->options2 & PR_O2_LOGERRORS)
		level = LOG_ERR;

	if (!lf_expr_isempty(&sess->fe->logformat_sd)) {
		sd_size = sess_build_logline(sess, NULL,
		                             logline_rfc5424, global.max_syslog_len,
		                             &sess->fe->logformat_sd);
	}

	if (!lf_expr_isempty(&sess->fe->logformat_error))
		size = sess_build_logline(sess, NULL, logline, global.max_syslog_len, &sess->fe->logformat_error);
	else
		size = sess_build_logline(sess, NULL, logline, global.max_syslog_len, &sess->fe->logformat);
	if (size > 0) {
		_HA_ATOMIC_INC(&sess->fe->log_count);
		__send_log(&sess->fe->loggers, &sess->fe->log_tag, level,
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

	__send_log(loggers, tag, level, logline, data_len, default_rfc5424_sd_log_format, 2);
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

			process_send_log(&l->bind_conf->frontend->loggers, level, facility, metadata, message, size);

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

		process_send_log(&frontend->loggers, level, facility, metadata, message, size);

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
	trash.data += vp_peek_ofs(v1, v2, ofs, trash.area, len);
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

		px = calloc(1, sizeof *px);
		if (!px) {
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		init_new_proxy(px);
		px->next = cfg_log_forward;
		cfg_log_forward = px;
		px->conf.file = strdup(file);
		px->conf.line = linenum;
		px->mode = PR_MODE_SYSLOG;
		px->last_change = ns_to_sec(now_ns);
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

/* function: post-resolve a single list of loggers
 *
 * Returns err_code which defaults to ERR_NONE and can be set to a combination
 * of ERR_WARN, ERR_ALERT, ERR_FATAL and ERR_ABORT in case of errors.
 */
int postresolve_logger_list(struct list *loggers, const char *section, const char *section_name)
{
	int err_code = ERR_NONE;
	struct logger *logger;

	list_for_each_entry(logger, loggers, list) {
		int cur_code;
		char *msg = NULL;

		cur_code = resolve_logger(logger, &msg);
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
	err_code |= postresolve_logger_list(&global.loggers, NULL, NULL);
	/* proxy log directives */
	for (px = proxies_list; px; px = px->next)
		err_code |= postresolve_logger_list(&px->loggers, "proxy", px->id);
	/* log-forward log directives */
	for (px = cfg_log_forward; px; px = px->next)
		err_code |= postresolve_logger_list(&px->loggers, "log-forward", px->id);

	return err_code;
}


/* config parsers for this section */
REGISTER_CONFIG_SECTION("log-forward", cfg_parse_log_forward, NULL);
REGISTER_POST_CHECK(postresolve_loggers);
REGISTER_POST_PROXY_CHECK(postcheck_log_backend);
REGISTER_POST_PROXY_CHECK(postcheck_logformat_proxy);

REGISTER_PER_THREAD_ALLOC(init_log_buffers);
REGISTER_PER_THREAD_FREE(deinit_log_buffers);

REGISTER_POST_DEINIT(deinit_log_forward);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
