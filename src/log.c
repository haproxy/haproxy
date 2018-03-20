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
#include <fcntl.h>
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

#include <common/config.h>
#include <common/compat.h>
#include <common/standard.h>
#include <common/time.h>

#include <types/cli.h>
#include <types/global.h>
#include <types/log.h>

#include <proto/applet.h>
#include <proto/cli.h>
#include <proto/frontend.h>
#include <proto/proto_http.h>
#include <proto/log.h>
#include <proto/sample.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#endif

struct log_fmt {
	char *name;
	struct {
		struct chunk sep1; /* first pid separator */
		struct chunk sep2; /* second pid separator */
	} pid;
};

static const struct log_fmt log_formats[LOG_FORMATS] = {
	[LOG_FORMAT_RFC3164] = {
		.name = "rfc3164",
		.pid = {
			.sep1 = { .str = "[",   .len = 1 },
			.sep2 = { .str = "]: ", .len = 3 }
		}
	},
	[LOG_FORMAT_RFC5424] = {
		.name = "rfc5424",
		.pid = {
			.sep1 = { .str = " ",   .len = 1 },
			.sep2 = { .str = " - ", .len = 3 }
		}
	}
};

#define FD_SETS_ARE_BITFIELDS
#ifdef FD_SETS_ARE_BITFIELDS
/*
 * This map is used with all the FD_* macros to check whether a particular bit
 * is set or not. Each bit represents an ACSII code. FD_SET() sets those bytes
 * which should be escaped. When FD_ISSET() returns non-zero, it means that the
 * byte should be escaped. Be careful to always pass bytes from 0 to 255
 * exclusively to the macros.
 */
fd_set rfc5424_escape_map[(sizeof(fd_set) > (256/8)) ? 1 : ((256/8) / sizeof(fd_set))];

#else
#error "Check if your OS uses bitfields for fd_sets"
#endif

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


/* log_format   */
struct logformat_type {
	char *name;
	int type;
	int mode;
	int lw; /* logwait bitsfield */
	int (*config_callback)(struct logformat_node *node, struct proxy *curproxy);
	const char *replace_by; /* new option to use instead of old one */
};

int prepare_addrsource(struct logformat_node *node, struct proxy *curproxy);

/* log_format variable names */
static const struct logformat_type logformat_keywords[] = {
	{ "o", LOG_FMT_GLOBAL, PR_MODE_TCP, 0, NULL },  /* global option */

	/* please keep these lines sorted ! */
	{ "B", LOG_FMT_BYTES, PR_MODE_TCP, LW_BYTES, NULL },     /* bytes from server to client */
	{ "CC", LOG_FMT_CCLIENT, PR_MODE_HTTP, LW_REQHDR, NULL },  /* client cookie */
	{ "CS", LOG_FMT_CSERVER, PR_MODE_HTTP, LW_RSPHDR, NULL },  /* server cookie */
	{ "H", LOG_FMT_HOSTNAME, PR_MODE_TCP, LW_INIT, NULL }, /* Hostname */
	{ "ID", LOG_FMT_UNIQUEID, PR_MODE_HTTP, LW_BYTES, NULL }, /* Unique ID */
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
	{ "HP", LOG_FMT_HTTP_PATH, PR_MODE_HTTP, LW_REQ, NULL },  /* HTTP path */
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

	/* The following tags are deprecated and will be removed soon */
	{ "Bi", LOG_FMT_BACKENDIP, PR_MODE_TCP, LW_BCKIP, prepare_addrsource, "bi" }, /* backend source ip */
	{ "Bp", LOG_FMT_BACKENDPORT, PR_MODE_TCP, LW_BCKIP, prepare_addrsource, "bp" }, /* backend source port */
	{ "Ci", LOG_FMT_CLIENTIP, PR_MODE_TCP, LW_CLIP | LW_XPRT, NULL, "ci" },  /* client ip */
	{ "Cp", LOG_FMT_CLIENTPORT, PR_MODE_TCP, LW_CLIP | LW_XPRT, NULL, "cp" }, /* client port */
	{ "Fi", LOG_FMT_FRONTENDIP, PR_MODE_TCP, LW_FRTIP | LW_XPRT, NULL, "fi" }, /* frontend ip */
	{ "Fp", LOG_FMT_FRONTENDPORT, PR_MODE_TCP, LW_FRTIP | LW_XPRT, NULL, "fp" }, /* frontend port */
	{ "Si", LOG_FMT_SERVERIP, PR_MODE_TCP, LW_SVIP, NULL, "si" }, /* server destination ip */
	{ "Sp", LOG_FMT_SERVERPORT, PR_MODE_TCP, LW_SVIP, NULL, "sp" }, /* server destination port */
	{ "cc", LOG_FMT_CCLIENT, PR_MODE_HTTP, LW_REQHDR, NULL, "CC" },  /* client cookie */
	{ "cs", LOG_FMT_CSERVER, PR_MODE_HTTP, LW_RSPHDR, NULL, "CS" },  /* server cookie */
	{ "st", LOG_FMT_STATUS, PR_MODE_HTTP, LW_RESP, NULL, "ST" },   /* status code */
	{ 0, 0, 0, 0, NULL }
};

char default_http_log_format[] = "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"; // default format
char clf_http_log_format[] = "%{+Q}o %{-Q}ci - - [%trg] %r %ST %B \"\" \"\" %cp %ms %ft %b %s %TR %Tw %Tc %Tr %Ta %tsc %ac %fc %bc %sc %rc %sq %bq %CC %CS %hrl %hsl";
char default_tcp_log_format[] = "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq";
char *log_format = NULL;

/* Default string used for structured-data part in RFC5424 formatted
 * syslog messages.
 */
char default_rfc5424_sd_log_format[] = "- ";

/* This is a global syslog header, common to all outgoing messages in
 * RFC3164 format. It begins with time-based part and is updated by
 * update_log_hdr().
 */
THREAD_LOCAL char *logheader = NULL;

/* This is a global syslog header for messages in RFC5424 format. It is
 * updated by update_log_hdr_rfc5424().
 */
THREAD_LOCAL char *logheader_rfc5424 = NULL;

/* This is a global syslog message buffer, common to all outgoing
 * messages. It contains only the data part.
 */
THREAD_LOCAL char *logline = NULL;

/* A global syslog message buffer, common to all RFC5424 syslog messages.
 * Currently, it is used for generating the structured-data part.
 */
THREAD_LOCAL char *logline_rfc5424 = NULL;

/* A global buffer used to store all startup alerts/warnings. It will then be
 * retrieve on the CLI. */
static THREAD_LOCAL char *startup_logs = NULL;

struct logformat_var_args {
	char *name;
	int mask;
};

struct logformat_var_args var_args_list[] = {
// global
	{ "M", LOG_OPT_MANDATORY },
	{ "Q", LOG_OPT_QUOTE },
	{ "X", LOG_OPT_HEXA },
	{ "E", LOG_OPT_ESC },
	{  0,  0 }
};

/* return the name of the directive used in the current proxy for which we're
 * currently parsing a header, when it is known.
 */
static inline const char *fmt_directive(const struct proxy *curproxy)
{
	switch (curproxy->conf.args.ctx) {
	case ARGC_ACL:
		return "acl";
	case ARGC_STK:
		return "stick";
	case ARGC_TRK:
		return "track-sc";
	case ARGC_LOG:
		return "log-format";
	case ARGC_LOGSD:
		return "log-format-sd";
	case ARGC_HRQ:
		return "http-request";
	case ARGC_HRS:
		return "http-response";
	case ARGC_UIF:
		return "unique-id-format";
	case ARGC_RDR:
		return "redirect";
	case ARGC_CAP:
		return "capture";
	case ARGC_SRV:
		return "server";
	case ARGC_SPOE:
		return "spoe-message";
	case ARGC_UBK:
		return "use_backend";
	default:
		return "undefined(please report this bug)"; /* must never happen */
	}
}

/*
 * callback used to configure addr source retrieval
 */
int prepare_addrsource(struct logformat_node *node, struct proxy *curproxy)
{
	curproxy->options2 |= PR_O2_SRC_ADDR;

	return 0;
}


/*
 * Parse args in a logformat_var. Returns 0 in error
 * case, otherwise, it returns 1.
 */
int parse_logformat_var_args(char *args, struct logformat_node *node, char **err)
{
	int i = 0;
	int end = 0;
	int flags = 0;  // 1 = +  2 = -
	char *sp = NULL; // start pointer

	if (args == NULL) {
		memprintf(err, "internal error: parse_logformat_var_args() expects non null 'args'");
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
			for (i = 0; sp && var_args_list[i].name; i++) {
				if (strcmp(sp, var_args_list[i].name) == 0) {
					if (flags == 1) {
						node->options |= var_args_list[i].mask;
						break;
					} else if (flags == 2) {
						node->options &= ~var_args_list[i].mask;
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
 * Parse a variable '%varname' or '%{args}varname' in log-format. The caller
 * must pass the args part in the <arg> pointer with its length in <arg_len>,
 * and varname with its length in <var> and <var_len> respectively. <arg> is
 * ignored when arg_len is 0. Neither <var> nor <var_len> may be null.
 * Returns false in error case and err is filled, otherwise returns true.
 */
int parse_logformat_var(char *arg, int arg_len, char *var, int var_len, struct proxy *curproxy, struct list *list_format, int *defoptions, char **err)
{
	int j;
	struct logformat_node *node;

	for (j = 0; logformat_keywords[j].name; j++) { // search a log type
		if (strlen(logformat_keywords[j].name) == var_len &&
		    strncmp(var, logformat_keywords[j].name, var_len) == 0) {
			if (logformat_keywords[j].mode != PR_MODE_HTTP || curproxy->mode == PR_MODE_HTTP) {
				node = calloc(1, sizeof(*node));
				if (!node) {
					memprintf(err, "out of memory error");
					return 0;
				}
				node->type = logformat_keywords[j].type;
				node->options = *defoptions;
				if (arg_len) {
					node->arg = my_strndup(arg, arg_len);
					if (!parse_logformat_var_args(node->arg, node, err))
						return 0;
				}
				if (node->type == LOG_FMT_GLOBAL) {
					*defoptions = node->options;
					free(node->arg);
					free(node);
				} else {
					if (logformat_keywords[j].config_callback &&
					    logformat_keywords[j].config_callback(node, curproxy) != 0) {
						return 0;
					}
					curproxy->to_log |= logformat_keywords[j].lw;
					LIST_ADDQ(list_format, &node->list);
				}
				if (logformat_keywords[j].replace_by)
					ha_warning("parsing [%s:%d] : deprecated variable '%s' in '%s', please replace it with '%s'.\n",
						   curproxy->conf.args.file, curproxy->conf.args.line,
						   logformat_keywords[j].name, fmt_directive(curproxy), logformat_keywords[j].replace_by);
				return 1;
			} else {
				memprintf(err, "format variable '%s' is reserved for HTTP mode",
				          logformat_keywords[j].name);
				return 0;
			}
		}
	}

	j = var[var_len];
	var[var_len] = 0;
	memprintf(err, "no such format variable '%s'. If you wanted to emit the '%%' character verbatim, you need to use '%%%%'", var);
	var[var_len] = j;
	return 0;
}

/*
 *  push to the logformat linked list
 *
 *  start: start pointer
 *  end: end text pointer
 *  type: string type
 *  list_format: destination list
 *
 *  LOG_TEXT: copy chars from start to end excluding end.
 *
*/
int add_to_logformat_list(char *start, char *end, int type, struct list *list_format, char **err)
{
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
		LIST_ADDQ(list_format, &node->list);
	} else if (type == LF_SEPARATOR) {
		struct logformat_node *node = calloc(1, sizeof(*node));
		if (!node) {
			memprintf(err, "out of memory error");
			return 0;
		}
		node->type = LOG_FMT_SEPARATOR;
		LIST_ADDQ(list_format, &node->list);
	}
	return 1;
}

/*
 * Parse the sample fetch expression <text> and add a node to <list_format> upon
 * success. At the moment, sample converters are not yet supported but fetch arguments
 * should work. The curpx->conf.args.ctx must be set by the caller.
 *
 * In error case, the function returns 0, otherwise it returns 1.
 */
int add_sample_to_logformat_list(char *text, char *arg, int arg_len, struct proxy *curpx, struct list *list_format, int options, int cap, char **err)
{
	char *cmd[2];
	struct sample_expr *expr;
	struct logformat_node *node;
	int cmd_arg;

	cmd[0] = text;
	cmd[1] = "";
	cmd_arg = 0;

	expr = sample_parse_expr(cmd, &cmd_arg, curpx->conf.args.file, curpx->conf.args.line, err, &curpx->conf.args);
	if (!expr) {
		memprintf(err, "failed to parse sample expression <%s> : %s", text, *err);
		return 0;
	}

	node = calloc(1, sizeof(*node));
	if (!node) {
		memprintf(err, "out of memory error");
		return 0;
	}
	node->type = LOG_FMT_EXPR;
	node->expr = expr;
	node->options = options;

	if (arg_len) {
		node->arg = my_strndup(arg, arg_len);
		if (!parse_logformat_var_args(node->arg, node, err))
			return 0;
	}
	if (expr->fetch->val & cap & SMP_VAL_REQUEST)
		node->options |= LOG_OPT_REQ_CAP; /* fetch method is request-compatible */

	if (expr->fetch->val & cap & SMP_VAL_RESPONSE)
		node->options |= LOG_OPT_RES_CAP; /* fetch method is response-compatible */

	if (!(expr->fetch->val & cap)) {
		free(node);
		node = NULL;
		memprintf(err, "sample fetch <%s> may not be reliably used here because it needs '%s' which is not available here",
		          text, sample_src_names(expr->fetch->use));
		return 0;
	}

	/* check if we need to allocate an hdr_idx struct for HTTP parsing */
	/* Note, we may also need to set curpx->to_log with certain fetches */
	curpx->http_needed |= !!(expr->fetch->use & SMP_USE_HTTP_ANY);

	/* FIXME: temporary workaround for missing LW_XPRT and LW_REQ flags
	 * needed with some sample fetches (eg: ssl*). We always set it for
	 * now on, but this will leave with sample capabilities soon.
	 */
	curpx->to_log |= LW_XPRT;
	curpx->to_log |= LW_REQ;
	LIST_ADDQ(list_format, &node->list);
	return 1;
}

/*
 * Parse the log_format string and fill a linked list.
 * Variable name are preceded by % and composed by characters [a-zA-Z0-9]* : %varname
 * You can set arguments using { } : %{many arguments}varname.
 * The curproxy->conf.args.ctx must be set by the caller.
 *
 *  str: the string to parse
 *  curproxy: the proxy affected
 *  list_format: the destination list
 *  options: LOG_OPT_* to force on every node
 *  cap: all SMP_VAL_* flags supported by the consumer
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is filled.
 */
int parse_logformat_string(const char *fmt, struct proxy *curproxy, struct list *list_format, int options, int cap, char **err)
{
	char *sp, *str, *backfmt; /* start pointer for text parts */
	char *arg = NULL; /* start pointer for args */
	char *var = NULL; /* start pointer for vars */
	int arg_len = 0;
	int var_len = 0;
	int cformat; /* current token format */
	int pformat; /* previous token format */
	struct logformat_node *tmplf, *back;

	sp = str = backfmt = strdup(fmt);
	if (!str) {
		memprintf(err, "out of memory error");
		return 0;
	}
	curproxy->to_log |= LW_INIT;

	/* flush the list first. */
	list_for_each_entry_safe(tmplf, back, list_format, list) {
		LIST_DEL(&tmplf->list);
		free(tmplf);
	}

	for (cformat = LF_INIT; cformat != LF_END; str++) {
		pformat = cformat;

		if (!*str)
			cformat = LF_END;              // preset it to save all states from doing this

		/* The prinicple of the two-step state machine below is to first detect a change, and
		 * second have all common paths processed at one place. The common paths are the ones
		 * encountered in text areas (LF_INIT, LF_TEXT, LF_SEPARATOR) and at the end (LF_END).
		 * We use the common LF_INIT state to dispatch to the different final states.
		 */
		switch (pformat) {
		case LF_STARTVAR:                      // text immediately following a '%'
			arg = NULL; var = NULL;
			arg_len = var_len = 0;
			if (*str == '{') {             // optional argument
				cformat = LF_STARG;
				arg = str + 1;
			}
			else if (*str == '[') {
				cformat = LF_STEXPR;
				var = str + 1;         // store expr in variable name
			}
			else if (isalpha((unsigned char)*str)) { // variable name
				cformat = LF_VAR;
				var = str;
			}
			else if (*str == '%')
				cformat = LF_TEXT;     // convert this character to a litteral (useful for '%')
			else if (isdigit((unsigned char)*str) || *str == ' ' || *str == '\t') {
				/* single '%' followed by blank or digit, send them both */
				cformat = LF_TEXT;
				pformat = LF_TEXT; /* finally we include the previous char as well */
				sp = str - 1; /* send both the '%' and the current char */
				memprintf(err, "unexpected variable name near '%c' at position %d line : '%s'. Maybe you want to write a single '%%', use the syntax '%%%%'",
				          *str, (int)(str - backfmt), fmt);
				return 0;

			}
			else
				cformat = LF_INIT;     // handle other cases of litterals
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
				var = str + 1;         // store expr in variable name
				break;
			}
			else if (isalnum((unsigned char)*str)) { // variable name
				cformat = LF_VAR;
				var = str;
				break;
			}
			memprintf(err, "parse argument modifier without variable name near '%%{%s}'", arg);
			return 0;

		case LF_STEXPR:                        // text immediately following '%['
			if (*str == ']') {             // end of arg
				cformat = LF_EDEXPR;
				var_len = str - var;
				*str = 0;              // needed for parsing the expression
			}
			break;

		case LF_VAR:                           // text part of a variable name
			var_len = str - var;
			if (!isalnum((unsigned char)*str))
				cformat = LF_INIT;     // not variable name anymore
			break;

		default:                               // LF_INIT, LF_TEXT, LF_SEPARATOR, LF_END, LF_EDEXPR
			cformat = LF_INIT;
		}

		if (cformat == LF_INIT) { /* resynchronize state to text/sep/startvar */
			switch (*str) {
			case '%': cformat = LF_STARTVAR;  break;
			case ' ': cformat = LF_SEPARATOR; break;
			case  0 : cformat = LF_END;       break;
			default : cformat = LF_TEXT;      break;
			}
		}

		if (cformat != pformat || pformat == LF_SEPARATOR) {
			switch (pformat) {
			case LF_VAR:
				if (!parse_logformat_var(arg, arg_len, var, var_len, curproxy, list_format, &options, err))
					return 0;
				break;
			case LF_STEXPR:
				if (!add_sample_to_logformat_list(var, arg, arg_len, curproxy, list_format, options, cap, err))
					return 0;
				break;
			case LF_TEXT:
			case LF_SEPARATOR:
				if (!add_to_logformat_list(sp, str, pformat, list_format, err))
					return 0;
				break;
			}
			sp = str; /* new start of text at every state switch and at every separator */
		}
	}

	if (pformat == LF_STARTVAR || pformat == LF_STARG || pformat == LF_STEXPR) {
		memprintf(err, "truncated line after '%s'", var ? var : arg ? arg : "%");
		return 0;
	}
	free(backfmt);

	return 1;
}

/* Generic function to display messages prefixed by a label */
static void print_message(const char *label, const char *fmt, va_list argp)
{
	struct tm tm;
	char *head, *msg;

	head = msg = NULL;

	get_localtime(date.tv_sec, &tm);
	memprintf(&head, "[%s] %03d/%02d%02d%02d (%d) : ",
		  label, tm.tm_yday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)getpid());
	memvprintf(&msg, fmt, argp);

	if (global.mode & MODE_STARTING)
		memprintf(&startup_logs, "%s%s%s", (startup_logs ? startup_logs : ""), head, msg);

	fprintf(stderr, "%s%s", head, msg);
	fflush(stderr);

	free(head);
	free(msg);
}

/*
 * Displays the message on stderr with the date and pid. Overrides the quiet
 * mode during startup.
 */
void ha_alert(const char *fmt, ...)
{
	va_list argp;

	if (!(global.mode & MODE_QUIET) || (global.mode & (MODE_VERBOSE | MODE_STARTING))) {
		va_start(argp, fmt);
		print_message("ALERT", fmt, argp);
		va_end(argp);
	}
}


/*
 * Displays the message on stderr with the date and pid.
 */
void ha_warning(const char *fmt, ...)
{
	va_list argp;

	if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
		va_start(argp, fmt);
		print_message("WARNING", fmt, argp);
		va_end(argp);
	}
}

/*
 * Displays the message on <out> only if quiet mode is not set.
 */
void qfprintf(FILE *out, const char *fmt, ...)
{
	va_list argp;

	if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
		va_start(argp, fmt);
		vfprintf(out, fmt, argp);
		fflush(out);
		va_end(argp);
	}
}

/*
 * returns log format for <fmt> or -1 if not found.
 */
int get_log_format(const char *fmt)
{
	int format;

	format = LOG_FORMATS - 1;
	while (format >= 0 && strcmp(log_formats[format].name, fmt))
		format--;

	return format;
}

/*
 * returns log level for <lev> or -1 if not found.
 */
int get_log_level(const char *lev)
{
	int level;

	level = NB_LOG_LEVELS - 1;
	while (level >= 0 && strcmp(log_levels[level], lev))
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
	while (facility >= 0 && strcmp(log_facilities[facility], fac))
		facility--;

	return facility;
}

/*
 * Encode the string.
 *
 * When using the +E log format option, it will try to escape '"\]'
 * characters with '\' as prefix. The same prefix should not be used as
 * <escape>.
 */
static char *lf_encode_string(char *start, char *stop,
                              const char escape, const fd_set *map,
                              const char *string,
                              struct logformat_node *node)
{
	if (node->options & LOG_OPT_ESC) {
		if (start < stop) {
			stop--; /* reserve one byte for the final '\0' */
			while (start < stop && *string != '\0') {
				if (!FD_ISSET((unsigned char)(*string), map)) {
					if (!FD_ISSET((unsigned char)(*string), rfc5424_escape_map))
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
		}
	}
	else {
		return encode_string(start, stop, escape, map, string);
	}

	return start;
}

/*
 * Encode the chunk.
 *
 * When using the +E log format option, it will try to escape '"\]'
 * characters with '\' as prefix. The same prefix should not be used as
 * <escape>.
 */
static char *lf_encode_chunk(char *start, char *stop,
                             const char escape, const fd_set *map,
                             const struct chunk *chunk,
                             struct logformat_node *node)
{
	char *str, *end;

	if (node->options & LOG_OPT_ESC) {
		if (start < stop) {
			str = chunk->str;
			end = chunk->str + chunk->len;

			stop--; /* reserve one byte for the final '\0' */
			while (start < stop && str < end) {
				if (!FD_ISSET((unsigned char)(*str), map)) {
					if (!FD_ISSET((unsigned char)(*str), rfc5424_escape_map))
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
		}
	}
	else {
		return encode_chunk(start, stop, escape, map, chunk);
	}

	return start;
}

/*
 * Write a string in the log string
 * Take cares of quote and escape options
 *
 * Return the adress of the \0 character, or NULL on error
 */
char *lf_text_len(char *dst, const char *src, size_t len, size_t size, struct logformat_node *node)
{
	if (size < 2)
		return NULL;

	if (node->options & LOG_OPT_QUOTE) {
		*(dst++) = '"';
		size--;
	}

	if (src && len) {
		if (++len > size)
			len = size;
		if (node->options & LOG_OPT_ESC) {
			char *ret;

			ret = escape_string(dst, dst + len, '\\', rfc5424_escape_map, src);
			if (ret == NULL || *ret != '\0')
				return NULL;
			len = ret - dst;
		}
		else {
			len = strlcpy2(dst, src, len);
		}

		size -= len;
		dst += len;
	}
	else if ((node->options & (LOG_OPT_QUOTE|LOG_OPT_MANDATORY)) == LOG_OPT_MANDATORY) {
		if (size < 2)
			return NULL;
		*(dst++) = '-';
	}

	if (node->options & LOG_OPT_QUOTE) {
		if (size < 2)
			return NULL;
		*(dst++) = '"';
	}

	*dst = '\0';
	return dst;
}

static inline char *lf_text(char *dst, const char *src, size_t size, struct logformat_node *node)
{
	return lf_text_len(dst, src, size, size, node);
}

/*
 * Write a IP adress to the log string
 * +X option write in hexadecimal notation, most signifant byte on the left
 */
char *lf_ip(char *dst, struct sockaddr *sockaddr, size_t size, struct logformat_node *node)
{
	char *ret = dst;
	int iret;
	char pn[INET6_ADDRSTRLEN];

	if (node->options & LOG_OPT_HEXA) {
		const unsigned char *addr = (const unsigned char *)&((struct sockaddr_in *)sockaddr)->sin_addr.s_addr;
		iret = snprintf(dst, size, "%02X%02X%02X%02X", addr[0], addr[1], addr[2], addr[3]);
		if (iret < 0 || iret > size)
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
 * +X option write in hexadecimal notation, most signifant byte on the left
 */
char *lf_port(char *dst, struct sockaddr *sockaddr, size_t size, struct logformat_node *node)
{
	char *ret = dst;
	int iret;

	if (node->options & LOG_OPT_HEXA) {
		const unsigned char *port = (const unsigned char *)&((struct sockaddr_in *)sockaddr)->sin_port;
		iret = snprintf(dst, size, "%02X%02X", port[0], port[1]);
		if (iret < 0 || iret > size)
			return NULL;
		ret += iret;
	} else {
		ret = ltoa_o(get_host_port((struct sockaddr_storage *)sockaddr), dst, size);
		if (ret == NULL)
			return NULL;
	}
	return ret;
}

/* Re-generate time-based part of the syslog header in RFC3164 format at
 * the beginning of logheader once a second and return the pointer to the
 * first character after it.
 */
static char *update_log_hdr(const time_t time)
{
	static THREAD_LOCAL long tvsec;
	static THREAD_LOCAL char *dataptr = NULL; /* backup of last end of header, NULL first time */
	static THREAD_LOCAL struct chunk host = { NULL, 0, 0 };
	static THREAD_LOCAL int sep = 0;

	if (unlikely(time != tvsec || dataptr == NULL)) {
		/* this string is rebuild only once a second */
		struct tm tm;
		int hdr_len;

		tvsec = time;
		get_localtime(tvsec, &tm);

		if (unlikely(global.log_send_hostname != host.str)) {
			host.str = global.log_send_hostname;
			host.len = host.str ? strlen(host.str) : 0;
			sep = host.len ? 1 : 0;
		}

		hdr_len = snprintf(logheader, global.max_syslog_len,
				   "<<<<>%s %2d %02d:%02d:%02d %.*s%*s",
				   monthname[tm.tm_mon],
				   tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
				   host.len, host.str, sep, "");
		/* WARNING: depending upon implementations, snprintf may return
		 * either -1 or the number of bytes that would be needed to store
		 * the total message. In both cases, we must adjust it.
		 */
		if (hdr_len < 0 || hdr_len > global.max_syslog_len)
			hdr_len = global.max_syslog_len;

		dataptr = logheader + hdr_len;
	}

	dataptr[0] = 0; // ensure we get rid of any previous attempt

	return dataptr;
}

/* Re-generate time-based part of the syslog header in RFC5424 format at
 * the beginning of logheader_rfc5424 once a second and return the pointer
 * to the first character after it.
 */
static char *update_log_hdr_rfc5424(const time_t time)
{
	static THREAD_LOCAL long tvsec;
	static THREAD_LOCAL char *dataptr = NULL; /* backup of last end of header, NULL first time */
	const char *gmt_offset;

	if (unlikely(time != tvsec || dataptr == NULL)) {
		/* this string is rebuild only once a second */
		struct tm tm;
		int hdr_len;

		tvsec = time;
		get_localtime(tvsec, &tm);
		gmt_offset = get_gmt_offset(time, &tm);

		hdr_len = snprintf(logheader_rfc5424, global.max_syslog_len,
				   "<<<<>1 %4d-%02d-%02dT%02d:%02d:%02d%.3s:%.2s %s ",
				   tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
				   tm.tm_hour, tm.tm_min, tm.tm_sec,
				   gmt_offset, gmt_offset+3,
				   global.log_send_hostname ? global.log_send_hostname : hostname);
		/* WARNING: depending upon implementations, snprintf may return
		 * either -1 or the number of bytes that would be needed to store
		 * the total message. In both cases, we must adjust it.
		 */
		if (hdr_len < 0 || hdr_len > global.max_syslog_len)
			hdr_len = global.max_syslog_len;

		dataptr = logheader_rfc5424 + hdr_len;
	}

	dataptr[0] = 0; // ensure we get rid of any previous attempt

	return dataptr;
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

	__send_log(p, level, logline, data_len, default_rfc5424_sd_log_format, 2);
}

/*
 * This function sends a syslog message.
 * It doesn't care about errors nor does it report them.
 * It overrides the last byte of the message vector with an LF character.
 * The arguments <sd> and <sd_size> are used for the structured-data part
 * in RFC5424 formatted syslog messages.
 */
void __send_log(struct proxy *p, int level, char *message, size_t size, char *sd, size_t sd_size)
{
	static THREAD_LOCAL struct iovec iovec[NB_MSG_IOVEC_ELEMENTS] = { };
	static THREAD_LOCAL struct msghdr msghdr = {
		//.msg_iov = iovec,
		.msg_iovlen = NB_MSG_IOVEC_ELEMENTS
	};
	static THREAD_LOCAL int logfdunix = -1;	/* syslog to AF_UNIX socket */
	static THREAD_LOCAL int logfdinet = -1;	/* syslog to AF_INET socket */
	static THREAD_LOCAL char *dataptr = NULL;
	int fac_level;
	struct list *logsrvs = NULL;
	struct logsrv *tmp = NULL;
	int nblogger;
	char *hdr, *hdr_ptr;
	size_t hdr_size;
	time_t time = date.tv_sec;
	struct chunk *tag = &global.log_tag;
	static THREAD_LOCAL int curr_pid;
	static THREAD_LOCAL char pidstr[100];
	static THREAD_LOCAL struct chunk pid;

	msghdr.msg_iov = iovec;

	dataptr = message;

	if (p == NULL) {
		if (!LIST_ISEMPTY(&global.logsrvs)) {
			logsrvs = &global.logsrvs;
		}
	} else {
		if (!LIST_ISEMPTY(&p->logsrvs)) {
			logsrvs = &p->logsrvs;
		}
		if (p->log_tag.str) {
			tag = &p->log_tag;
		}
	}

	if (!logsrvs)
		return;

	if (unlikely(curr_pid != getpid())) {
		curr_pid = getpid();
		ltoa_o(curr_pid, pidstr, sizeof(pidstr));
		chunk_initstr(&pid, pidstr);
	}

	/* Send log messages to syslog server. */
	nblogger = 0;
	list_for_each_entry(tmp, logsrvs, list) {
		const struct logsrv *logsrv = tmp;
		int *plogfd = logsrv->addr.ss_family == AF_UNIX ?
			&logfdunix : &logfdinet;
		char *pid_sep1 = NULL, *pid_sep2 = NULL;
		int sent;
		int maxlen;
		int hdr_max = 0;
		int tag_max = 0;
		int pid_sep1_max = 0;
		int pid_max = 0;
		int pid_sep2_max = 0;
		int sd_max = 0;
		int max = 0;

		nblogger++;

		/* we can filter the level of the messages that are sent to each logger */
		if (level > logsrv->level)
			continue;

		if (unlikely(*plogfd < 0)) {
			/* socket not successfully initialized yet */
			int proto = logsrv->addr.ss_family == AF_UNIX ? 0 : IPPROTO_UDP;

			if ((*plogfd = socket(logsrv->addr.ss_family, SOCK_DGRAM, proto)) < 0) {
				static char once;

				if (!once) {
					once = 1; /* note: no need for atomic ops here */
					ha_alert("socket for logger #%d failed: %s (errno=%d)\n",
					         nblogger, strerror(errno), errno);
				}
				continue;
			}
			/* we don't want to receive anything on this socket */
			setsockopt(*plogfd, SOL_SOCKET, SO_RCVBUF, &zero, sizeof(zero));
			/* does nothing under Linux, maybe needed for others */
			shutdown(*plogfd, SHUT_RD);
			fcntl(*plogfd, F_SETFD, fcntl(*plogfd, F_GETFD, FD_CLOEXEC) | FD_CLOEXEC);
		}

		switch (logsrv->format) {
		case LOG_FORMAT_RFC3164:
			hdr = logheader;
			hdr_ptr = update_log_hdr(time);
			break;

		case LOG_FORMAT_RFC5424:
			hdr = logheader_rfc5424;
			hdr_ptr = update_log_hdr_rfc5424(time);
			sd_max = sd_size; /* the SD part allowed only in RFC5424 */
			break;

		default:
			continue; /* must never happen */
		}

		hdr_size = hdr_ptr - hdr;

		/* For each target, we may have a different facility.
		 * We can also have a different log level for each message.
		 * This induces variations in the message header length.
		 * Since we don't want to recompute it each time, nor copy it every
		 * time, we only change the facility in the pre-computed header,
		 * and we change the pointer to the header accordingly.
		 */
		fac_level = (logsrv->facility << 3) + MAX(level, logsrv->minlvl);
		hdr_ptr = hdr + 3; /* last digit of the log level */
		do {
			*hdr_ptr = '0' + fac_level % 10;
			fac_level /= 10;
			hdr_ptr--;
		} while (fac_level && hdr_ptr > hdr);
		*hdr_ptr = '<';

		hdr_max = hdr_size - (hdr_ptr - hdr);

		/* time-based header */
		if (unlikely(hdr_size >= logsrv->maxlen)) {
			hdr_max = MIN(hdr_max, logsrv->maxlen) - 1;
			sd_max = 0;
			goto send;
		}

		maxlen = logsrv->maxlen - hdr_max;

		/* tag */
		tag_max = tag->len;
		if (unlikely(tag_max >= maxlen)) {
			tag_max = maxlen - 1;
			sd_max = 0;
			goto send;
		}

		maxlen -= tag_max;

		/* first pid separator */
		pid_sep1_max = log_formats[logsrv->format].pid.sep1.len;
		if (unlikely(pid_sep1_max >= maxlen)) {
			pid_sep1_max = maxlen - 1;
			sd_max = 0;
			goto send;
		}

		pid_sep1 = log_formats[logsrv->format].pid.sep1.str;
		maxlen -= pid_sep1_max;

		/* pid */
		pid_max = pid.len;
		if (unlikely(pid_max >= maxlen)) {
			pid_max = maxlen - 1;
			sd_max = 0;
			goto send;
		}

		maxlen -= pid_max;

		/* second pid separator */
		pid_sep2_max = log_formats[logsrv->format].pid.sep2.len;
		if (unlikely(pid_sep2_max >= maxlen)) {
			pid_sep2_max = maxlen - 1;
			sd_max = 0;
			goto send;
		}

		pid_sep2 = log_formats[logsrv->format].pid.sep2.str;
		maxlen -= pid_sep2_max;

		/* structured-data */
		if (sd_max >= maxlen) {
			sd_max = maxlen - 1;
			goto send;
		}

		max = MIN(size, maxlen - sd_max) - 1;
send:
		iovec[0].iov_base = hdr_ptr;
		iovec[0].iov_len  = hdr_max;
		iovec[1].iov_base = tag->str;
		iovec[1].iov_len  = tag_max;
		iovec[2].iov_base = pid_sep1;
		iovec[2].iov_len  = pid_sep1_max;
		iovec[3].iov_base = pid.str;
		iovec[3].iov_len  = pid_max;
		iovec[4].iov_base = pid_sep2;
		iovec[4].iov_len  = pid_sep2_max;
		iovec[5].iov_base = sd;
		iovec[5].iov_len  = sd_max;
		iovec[6].iov_base = dataptr;
		iovec[6].iov_len  = max;
		iovec[7].iov_base = "\n"; /* insert a \n at the end of the message */
		iovec[7].iov_len  = 1;

		msghdr.msg_name = (struct sockaddr *)&logsrv->addr;
		msghdr.msg_namelen = get_addr_len(&logsrv->addr);

		sent = sendmsg(*plogfd, &msghdr, MSG_DONTWAIT | MSG_NOSIGNAL);

		if (sent < 0) {
			static char once;

			if (!once) {
				once = 1; /* note: no need for atomic ops here */
				ha_alert("sendmsg logger #%d failed: %s (errno=%d)\n",
				         nblogger, strerror(errno), errno);
			}
		}
	}
}

extern fd_set hdr_encode_map[];
extern fd_set url_encode_map[];
extern fd_set http_encode_map[];


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


/* Initializes some log data.
 */
void init_log()
{
	char *tmp;

	/* Initialize the escape map for the RFC5424 structured-data : '"\]'
	 * inside PARAM-VALUE should be escaped with '\' as prefix.
	 * See https://tools.ietf.org/html/rfc5424#section-6.3.3 for more
	 * details.
	 */
	memset(rfc5424_escape_map, 0, sizeof(rfc5424_escape_map));

	tmp = "\"\\]";
	while (*tmp) {
		FD_SET(*tmp, rfc5424_escape_map);
		tmp++;
	}
}

static int init_log_buffers_per_thread()
{
	return init_log_buffers();
}

static void deinit_log_buffers_per_thread()
{
	deinit_log_buffers();
}

/* Initialize log buffers used for syslog messages */
int init_log_buffers()
{
	logheader = my_realloc2(logheader, global.max_syslog_len + 1);
	logheader_rfc5424 = my_realloc2(logheader_rfc5424, global.max_syslog_len + 1);
	logline = my_realloc2(logline, global.max_syslog_len + 1);
	logline_rfc5424 = my_realloc2(logline_rfc5424, global.max_syslog_len + 1);
	if (!logheader || !logline_rfc5424 || !logline || !logline_rfc5424)
		return 0;
	return 1;
}

/* Deinitialize log buffers used for syslog messages */
void deinit_log_buffers()
{
	free(logheader);
	free(logheader_rfc5424);
	free(logline);
	free(logline_rfc5424);
	free(startup_logs);
	logheader         = NULL;
	logheader_rfc5424 = NULL;
	logline           = NULL;
	logline_rfc5424   = NULL;
	startup_logs      = NULL;
}

/* Builds a log line in <dst> based on <list_format>, and stops before reaching
 * <maxsize> characters. Returns the size of the output string in characters,
 * not counting the trailing zero which is always added if the resulting size
 * is not zero.
 */
int build_logline(struct stream *s, char *dst, size_t maxsize, struct list *list_format)
{
	struct session *sess = strm_sess(s);
	struct proxy *fe = sess->fe;
	struct proxy *be = s->be;
	struct http_txn *txn = s->txn;
	struct chunk chunk;
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
	struct logformat_node *tmp;
	struct timeval tv;

	/* FIXME: let's limit ourselves to frontend logging for now. */

	t_request = -1;
	if (tv_isge(&s->logs.tv_request, &s->logs.tv_accept))
		t_request = tv_ms_elapsed(&s->logs.tv_accept, &s->logs.tv_request);

	tmplog = dst;

	/* fill logbuffer */
	if (LIST_ISEMPTY(list_format))
		return 0;

	list_for_each_entry(tmp, list_format, list) {
		struct connection *conn;
		const char *src = NULL;
		struct sample *key;
		const struct chunk empty = { NULL, 0, 0 };

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
				last_isspace = 0;
				break;

			case LOG_FMT_EXPR: // sample expression, may be request or response
				key = NULL;
				if (tmp->options & LOG_OPT_REQ_CAP)
					key = sample_fetch_as_type(be, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, tmp->expr, SMP_T_STR);
				if (!key && (tmp->options & LOG_OPT_RES_CAP))
					key = sample_fetch_as_type(be, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL, tmp->expr, SMP_T_STR);
				if (tmp->options & LOG_OPT_HTTP)
					ret = lf_encode_chunk(tmplog, dst + maxsize,
					                      '%', http_encode_map, key ? &key->data.u.str : &empty, tmp);
				else
					ret = lf_text_len(tmplog, key ? key->data.u.str.str : NULL, key ? key->data.u.str.len : 0, dst + maxsize - tmplog, tmp);
				if (ret == 0)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_CLIENTIP:  // %ci
				conn = objt_conn(sess->origin);
				if (conn)
					ret = lf_ip(tmplog, (struct sockaddr *)&conn->addr.from, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_CLIENTPORT:  // %cp
				conn = objt_conn(sess->origin);
				if (conn) {
					if (conn->addr.from.ss_family == AF_UNIX) {
						ret = ltoa_o(sess->listener->luid, tmplog, dst + maxsize - tmplog);
					} else {
						ret = lf_port(tmplog, (struct sockaddr *)&conn->addr.from,
						              dst + maxsize - tmplog, tmp);
					}
				}
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_FRONTENDIP: // %fi
				conn = objt_conn(sess->origin);
				if (conn) {
					conn_get_to_addr(conn);
					ret = lf_ip(tmplog, (struct sockaddr *)&conn->addr.to, dst + maxsize - tmplog, tmp);
				}
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case  LOG_FMT_FRONTENDPORT: // %fp
				conn = objt_conn(sess->origin);
				if (conn) {
					conn_get_to_addr(conn);
					if (conn->addr.to.ss_family == AF_UNIX)
						ret = ltoa_o(sess->listener->luid, tmplog, dst + maxsize - tmplog);
					else
						ret = lf_port(tmplog, (struct sockaddr *)&conn->addr.to, dst + maxsize - tmplog, tmp);
				}
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_BACKENDIP:  // %bi
				conn = cs_conn(objt_cs(s->si[1].end));
				if (conn)
					ret = lf_ip(tmplog, (struct sockaddr *)&conn->addr.from, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_BACKENDPORT:  // %bp
				conn = cs_conn(objt_cs(s->si[1].end));
				if (conn)
					ret = lf_port(tmplog, (struct sockaddr *)&conn->addr.from, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_SERVERIP: // %si
				conn = cs_conn(objt_cs(s->si[1].end));
				if (conn)
					ret = lf_ip(tmplog, (struct sockaddr *)&conn->addr.to, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_SERVERPORT: // %sp
				conn = cs_conn(objt_cs(s->si[1].end));
				if (conn)
					ret = lf_port(tmplog, (struct sockaddr *)&conn->addr.to, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_DATE: // %t = accept date
				get_localtime(s->logs.accept_date.tv_sec, &tm);
				ret = date2str_log(tmplog, &tm, &(s->logs.accept_date),
						   dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_tr: // %tr = start of request date
				/* Note that the timers are valid if we get here */
				tv_ms_add(&tv, &s->logs.accept_date, s->logs.t_idle >= 0 ? s->logs.t_idle + s->logs.t_handshake : 0);
				get_localtime(tv.tv_sec, &tm);
				ret = date2str_log(tmplog, &tm, &tv, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_DATEGMT: // %T = accept date, GMT
				get_gmtime(s->logs.accept_date.tv_sec, &tm);
				ret = gmt2str_log(tmplog, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_trg: // %trg = start of request date, GMT
				tv_ms_add(&tv, &s->logs.accept_date, s->logs.t_idle >= 0 ? s->logs.t_idle + s->logs.t_handshake : 0);
				get_gmtime(tv.tv_sec, &tm);
				ret = gmt2str_log(tmplog, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_DATELOCAL: // %Tl = accept date, local
				get_localtime(s->logs.accept_date.tv_sec, &tm);
				ret = localdate2str_log(tmplog, s->logs.accept_date.tv_sec, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_trl: // %trl = start of request date, local
				tv_ms_add(&tv, &s->logs.accept_date, s->logs.t_idle >= 0 ? s->logs.t_idle + s->logs.t_handshake : 0);
				get_localtime(tv.tv_sec, &tm);
				ret = localdate2str_log(tmplog, tv.tv_sec, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_TS: // %Ts
				get_gmtime(s->logs.accept_date.tv_sec, &tm);
				if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%04X", (unsigned int)s->logs.accept_date.tv_sec);
					if (iret < 0 || iret > dst + maxsize - tmplog)
						goto out;
					last_isspace = 0;
					tmplog += iret;
				} else {
					ret = ltoa_o(s->logs.accept_date.tv_sec, tmplog, dst + maxsize - tmplog);
					if (ret == NULL)
						goto out;
					tmplog = ret;
					last_isspace = 0;
				}
			break;

			case LOG_FMT_MS: // %ms
			if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%02X",(unsigned int)s->logs.accept_date.tv_usec/1000);
					if (iret < 0 || iret > dst + maxsize - tmplog)
						goto out;
					last_isspace = 0;
					tmplog += iret;
			} else {
				if ((dst + maxsize - tmplog) < 4)
					goto out;
				ret = utoa_pad((unsigned int)s->logs.accept_date.tv_usec/1000,
				               tmplog, 4);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
			}
			break;

			case LOG_FMT_FRONTEND: // %f
				src = fe->id;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_FRONTEND_XPRT: // %ft
				src = fe->id;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');
				iret = strlcpy2(tmplog, src, dst + maxsize - tmplog);
				if (iret == 0)
					goto out;
				tmplog += iret;
				if (sess->listener->bind_conf->xprt == xprt_get(XPRT_SSL))
					LOGCHAR('~');
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');
				last_isspace = 0;
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
				last_isspace = 0;
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
				last_isspace = 0;
				break;
#endif
			case LOG_FMT_BACKEND: // %b
				src = be->id;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_SERVER: // %s
				switch (obj_type(s->target)) {
				case OBJ_TYPE_SERVER:
					src = objt_server(s->target)->id;
					break;
				case OBJ_TYPE_APPLET:
					src = objt_applet(s->target)->name;
					break;
				default:
					src = "<NOSRV>";
					break;
				}
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_Th: // %Th = handshake time
				ret = ltoa_o(s->logs.t_handshake, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_Ti: // %Ti = HTTP idle time
				ret = ltoa_o(s->logs.t_idle, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_TR: // %TR = HTTP request time
				ret = ltoa_o((t_request >= 0) ? t_request - s->logs.t_idle - s->logs.t_handshake : -1,
				             tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_TQ: // %Tq = Th + Ti + TR
				ret = ltoa_o(t_request, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_TW: // %Tw
				ret = ltoa_o((s->logs.t_queue >= 0) ? s->logs.t_queue - t_request : -1,
						tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_TC: // %Tc
				ret = ltoa_o((s->logs.t_connect >= 0) ? s->logs.t_connect - s->logs.t_queue : -1,
						tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_Tr: // %Tr
				ret = ltoa_o((s->logs.t_data >= 0) ? s->logs.t_data - s->logs.t_connect : -1,
						tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_TD: // %Td
				if (s->be->mode == PR_MODE_HTTP)
					ret = ltoa_o((s->logs.t_data >= 0) ? s->logs.t_close - s->logs.t_data : -1,
					             tmplog, dst + maxsize - tmplog);
				else
					ret = ltoa_o((s->logs.t_connect >= 0) ? s->logs.t_close - s->logs.t_connect : -1,
					             tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_Ta:  // %Ta = active time = Tt - Th - Ti
				if (!(fe->to_log & LW_BYTES))
					LOGCHAR('+');
				ret = ltoa_o(s->logs.t_close - (s->logs.t_idle >= 0 ? s->logs.t_idle + s->logs.t_handshake : 0),
					     tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_TT:  // %Tt = total time
				if (!(fe->to_log & LW_BYTES))
					LOGCHAR('+');
				ret = ltoa_o(s->logs.t_close, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_STATUS: // %ST
				ret = ltoa_o(txn ? txn->status : 0, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_BYTES: // %B
				if (!(fe->to_log & LW_BYTES))
					LOGCHAR('+');
				ret = lltoa(s->logs.bytes_out, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_BYTES_UP: // %U
				ret = lltoa(s->logs.bytes_in, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_CCLIENT: // %CC
				src = txn ? txn->cli_cookie : NULL;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_CSERVER: // %CS
				src = txn ? txn->srv_cookie : NULL;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_TERMSTATE: // %ts
				LOGCHAR(sess_term_cond[(s->flags & SF_ERR_MASK) >> SF_ERR_SHIFT]);
				LOGCHAR(sess_fin_state[(s->flags & SF_FINST_MASK) >> SF_FINST_SHIFT]);
				*tmplog = '\0';
				last_isspace = 0;
				break;

			case LOG_FMT_TERMSTATE_CK: // %tsc, same as TS with cookie state (for mode HTTP)
				LOGCHAR(sess_term_cond[(s->flags & SF_ERR_MASK) >> SF_ERR_SHIFT]);
				LOGCHAR(sess_fin_state[(s->flags & SF_FINST_MASK) >> SF_FINST_SHIFT]);
				LOGCHAR((txn && (be->ck_opts & PR_CK_ANY)) ? sess_cookie[(txn->flags & TX_CK_MASK) >> TX_CK_SHIFT] : '-');
				LOGCHAR((txn && (be->ck_opts & PR_CK_ANY)) ? sess_set_cookie[(txn->flags & TX_SCK_MASK) >> TX_SCK_SHIFT] : '-');
				last_isspace = 0;
				break;

			case LOG_FMT_ACTCONN: // %ac
				ret = ltoa_o(actconn, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_FECONN:  // %fc
				ret = ltoa_o(fe->feconn, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_BECONN:  // %bc
				ret = ltoa_o(be->beconn, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_SRVCONN:  // %sc
				ret = ultoa_o(objt_server(s->target) ?
				                 objt_server(s->target)->cur_sess :
				                 0, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_RETRIES:  // %rq
				if (s->flags & SF_REDISP)
					LOGCHAR('+');
				ret = ltoa_o((s->si[1].conn_retries>0) ?
				                (be->conn_retries - s->si[1].conn_retries) :
				                be->conn_retries, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_SRVQUEUE: // %sq
				ret = ltoa_o(s->logs.srv_queue_size, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_BCKQUEUE:  // %bq
				ret = ltoa_o(s->logs.prx_queue_size, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_HDRREQUEST: // %hr
				/* request header */
				if (fe->nb_req_cap && s->req_cap) {
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
					LOGCHAR('{');
					for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
						if (hdr)
							LOGCHAR('|');
						if (s->req_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->req_cap[hdr], tmp);
							if (ret == NULL || *ret != '\0')
								goto out;
							tmplog = ret;
						}
					}
					LOGCHAR('}');
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
					last_isspace = 0;
				}
				break;

			case LOG_FMT_HDRREQUESTLIST: // %hrl
				/* request header list */
				if (fe->nb_req_cap && s->req_cap) {
					for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
						if (hdr > 0)
							LOGCHAR(' ');
						if (tmp->options & LOG_OPT_QUOTE)
							LOGCHAR('"');
						if (s->req_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->req_cap[hdr], tmp);
							if (ret == NULL || *ret != '\0')
								goto out;
							tmplog = ret;
						} else if (!(tmp->options & LOG_OPT_QUOTE))
							LOGCHAR('-');
						if (tmp->options & LOG_OPT_QUOTE)
							LOGCHAR('"');
						last_isspace = 0;
					}
				}
				break;


			case LOG_FMT_HDRRESPONS: // %hs
				/* response header */
				if (fe->nb_rsp_cap && s->res_cap) {
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
					LOGCHAR('{');
					for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
						if (hdr)
							LOGCHAR('|');
						if (s->res_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->res_cap[hdr], tmp);
							if (ret == NULL || *ret != '\0')
								goto out;
							tmplog = ret;
						}
					}
					LOGCHAR('}');
					last_isspace = 0;
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
				}
				break;

			case LOG_FMT_HDRRESPONSLIST: // %hsl
				/* response header list */
				if (fe->nb_rsp_cap && s->res_cap) {
					for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
						if (hdr > 0)
							LOGCHAR(' ');
						if (tmp->options & LOG_OPT_QUOTE)
							LOGCHAR('"');
						if (s->res_cap[hdr] != NULL) {
							ret = lf_encode_string(tmplog, dst + maxsize,
							                       '#', hdr_encode_map, s->res_cap[hdr], tmp);
							if (ret == NULL || *ret != '\0')
								goto out;
							tmplog = ret;
						} else if (!(tmp->options & LOG_OPT_QUOTE))
							LOGCHAR('-');
						if (tmp->options & LOG_OPT_QUOTE)
							LOGCHAR('"');
						last_isspace = 0;
					}
				}
				break;

			case LOG_FMT_REQ: // %r
				/* Request */
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";
				ret = lf_encode_string(tmplog, dst + maxsize,
				                       '#', url_encode_map, uri, tmp);
				if (ret == NULL || *ret != '\0')
					goto out;
				tmplog = ret;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');
				last_isspace = 0;
				break;

			case LOG_FMT_HTTP_PATH: // %HP
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";

				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

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
					chunk.str = "<BADREQ>";
					chunk.len = strlen("<BADREQ>");
				} else {
					chunk.str = uri;
					chunk.len = spc - uri;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL || *ret != '\0')
					goto out;

				tmplog = ret;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

				last_isspace = 0;
				break;

			case LOG_FMT_HTTP_QUERY: // %HQ
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

				if (!txn || !txn->uri) {
					chunk.str = "<BADREQ>";
					chunk.len = strlen("<BADREQ>");
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

					chunk.str = qmark;
					chunk.len = uri - qmark;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL || *ret != '\0')
					goto out;

				tmplog = ret;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

				last_isspace = 0;
				break;

			case LOG_FMT_HTTP_URI: // %HU
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";

				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

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
					chunk.str = "<BADREQ>";
					chunk.len = strlen("<BADREQ>");
				} else {
					chunk.str = uri;
					chunk.len = spc - uri;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL || *ret != '\0')
					goto out;

				tmplog = ret;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

				last_isspace = 0;
				break;

			case LOG_FMT_HTTP_METHOD: // %HM
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

				end = uri + strlen(uri);
				// look for the first whitespace character
				spc = uri;
				while (spc < end && !HTTP_IS_SPHT(*spc))
					spc++;

				if (spc == end) { // odd case, we have txn->uri, but we only got a verb
					chunk.str = "<BADREQ>";
					chunk.len = strlen("<BADREQ>");
				} else {
					chunk.str = uri;
					chunk.len = spc - uri;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL || *ret != '\0')
					goto out;

				tmplog = ret;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

				last_isspace = 0;
				break;

			case LOG_FMT_HTTP_VERSION: // %HV
				uri = txn && txn->uri ? txn->uri : "<BADREQ>";
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

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
					chunk.str = "<BADREQ>";
					chunk.len = strlen("<BADREQ>");
				} else if (uri == end) {
					chunk.str = "HTTP/0.9";
					chunk.len = strlen("HTTP/0.9");
				} else {
					chunk.str = uri;
					chunk.len = end - uri;
				}

				ret = lf_encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk, tmp);
				if (ret == NULL || *ret != '\0')
					goto out;

				tmplog = ret;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

				last_isspace = 0;
				break;

			case LOG_FMT_COUNTER: // %rt
				if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%04X", s->uniq_id);
					if (iret < 0 || iret > dst + maxsize - tmplog)
						goto out;
					last_isspace = 0;
					tmplog += iret;
				} else {
					ret = ltoa_o(s->uniq_id, tmplog, dst + maxsize - tmplog);
					if (ret == NULL)
						goto out;
					tmplog = ret;
					last_isspace = 0;
				}
				break;

			case LOG_FMT_LOGCNT: // %lc
				if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%04X", fe->log_count);
					if (iret < 0 || iret > dst + maxsize - tmplog)
						goto out;
					last_isspace = 0;
					tmplog += iret;
				} else {
					ret = ultoa_o(fe->log_count, tmplog, dst + maxsize - tmplog);
					if (ret == NULL)
						goto out;
					tmplog = ret;
					last_isspace = 0;
				}
				break;

			case LOG_FMT_HOSTNAME: // %H
				src = hostname;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_PID: // %pid
				if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%04X", pid);
					if (iret < 0 || iret > dst + maxsize - tmplog)
						goto out;
					last_isspace = 0;
					tmplog += iret;
				} else {
					ret = ltoa_o(pid, tmplog, dst + maxsize - tmplog);
					if (ret == NULL)
						goto out;
					tmplog = ret;
					last_isspace = 0;
				}
				break;

			case LOG_FMT_UNIQUEID: // %ID
				ret = NULL;
				src = s->unique_id;
				ret = lf_text(tmplog, src, maxsize - (tmplog - dst), tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

		}
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
	      (((s->flags & SF_ERR_MASK) == SF_ERR_NONE) &&
	       (s->si[1].conn_retries != s->be->conn_retries)) ||
	      ((sess->fe->mode == PR_MODE_HTTP) && s->txn && s->txn->status >= 500);

	if (!err && (sess->fe->options2 & PR_O2_NOLOGNORM))
		return;

	if (LIST_ISEMPTY(&sess->fe->logsrvs))
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
	if (!s->unique_id && !LIST_ISEMPTY(&sess->fe->format_unique_id)) {
		if ((s->unique_id = pool_alloc(pool_head_uniqueid)) != NULL)
			build_logline(s, s->unique_id, UNIQUEID_LEN, &sess->fe->format_unique_id);
	}

	if (!LIST_ISEMPTY(&sess->fe->logformat_sd)) {
		sd_size = build_logline(s, logline_rfc5424, global.max_syslog_len,
		                        &sess->fe->logformat_sd);
	}

	size = build_logline(s, logline, global.max_syslog_len, &sess->fe->logformat);
	if (size > 0) {
		HA_ATOMIC_ADD(&sess->fe->log_count, 1);
		__send_log(sess->fe, level, logline, size + 1, logline_rfc5424, sd_size);
		s->logs.logwait = 0;
	}
}

static int cli_io_handler_show_startup_logs(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	const char *msg = (startup_logs ? startup_logs : "No startup alerts/warnings.\n");

	if (ci_putstr(si_ic(si), msg) == -1) {
		si_applet_cant_put(si);
		return 0;
	}
	return 1;
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "startup-logs",  NULL },
	  "show startup-logs : report logs emitted during HAProxy startup",
	  NULL, cli_io_handler_show_startup_logs },
	{{},}
}};

__attribute__((constructor))
static void __log_init(void)
{
	hap_register_per_thread_init(init_log_buffers_per_thread);
	hap_register_per_thread_deinit(deinit_log_buffers_per_thread);
	cli_register_kw(&cli_kws);
}
/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
