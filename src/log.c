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

#include <common/config.h>
#include <common/compat.h>
#include <common/standard.h>
#include <common/time.h>

#include <types/global.h>
#include <types/log.h>

#include <proto/frontend.h>
#include <proto/proto_http.h>
#include <proto/log.h>
#include <proto/sample.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
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
	{ "Tc", LOG_FMT_TC, PR_MODE_TCP, LW_BYTES, NULL },       /* Tc */
	{ "Tl", LOG_FMT_DATELOCAL, PR_MODE_TCP, LW_INIT, NULL },   /* date local timezone */
	{ "Tq", LOG_FMT_TQ, PR_MODE_HTTP, LW_BYTES, NULL },       /* Tq */
	{ "Tr", LOG_FMT_TR, PR_MODE_HTTP, LW_BYTES, NULL },       /* Tr */
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
	{ "ci", LOG_FMT_CLIENTIP, PR_MODE_TCP, LW_CLIP, NULL },  /* client ip */
	{ "cp", LOG_FMT_CLIENTPORT, PR_MODE_TCP, LW_CLIP, NULL }, /* client port */
	{ "f", LOG_FMT_FRONTEND, PR_MODE_TCP, LW_INIT, NULL },  /* frontend */
	{ "fc", LOG_FMT_FECONN, PR_MODE_TCP, LW_BYTES, NULL },   /* feconn */
	{ "fi", LOG_FMT_FRONTENDIP, PR_MODE_TCP, LW_FRTIP, NULL }, /* frontend ip */
	{ "fp", LOG_FMT_FRONTENDPORT, PR_MODE_TCP, LW_FRTIP, NULL }, /* frontend port */
	{ "ft", LOG_FMT_FRONTEND_XPRT, PR_MODE_TCP, LW_INIT, NULL },  /* frontend with transport mode */
	{ "hr", LOG_FMT_HDRREQUEST, PR_MODE_TCP, LW_REQHDR, NULL }, /* header request */
	{ "hrl", LOG_FMT_HDRREQUESTLIST, PR_MODE_TCP, LW_REQHDR, NULL }, /* header request list */
	{ "hs", LOG_FMT_HDRRESPONS, PR_MODE_TCP, LW_RSPHDR, NULL },  /* header response */
	{ "hsl", LOG_FMT_HDRRESPONSLIST, PR_MODE_TCP, LW_RSPHDR, NULL },  /* header response list */
	{ "HM", LOG_FMT_HTTP_METHOD, PR_MODE_HTTP, LW_REQ, NULL },  /* HTTP method */
	{ "HP", LOG_FMT_HTTP_PATH, PR_MODE_HTTP, LW_REQ, NULL },  /* HTTP path */
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
	{ "ts", LOG_FMT_TERMSTATE, PR_MODE_TCP, LW_BYTES, NULL },/* termination state */
	{ "tsc", LOG_FMT_TERMSTATE_CK, PR_MODE_TCP, LW_INIT, NULL },/* termination state */

	/* The following tags are deprecated and will be removed soon */
	{ "Bi", LOG_FMT_BACKENDIP, PR_MODE_TCP, LW_BCKIP, prepare_addrsource, "bi" }, /* backend source ip */
	{ "Bp", LOG_FMT_BACKENDPORT, PR_MODE_TCP, LW_BCKIP, prepare_addrsource, "bp" }, /* backend source port */
	{ "Ci", LOG_FMT_CLIENTIP, PR_MODE_TCP, LW_CLIP, NULL, "ci" },  /* client ip */
	{ "Cp", LOG_FMT_CLIENTPORT, PR_MODE_TCP, LW_CLIP, NULL, "cp" }, /* client port */
	{ "Fi", LOG_FMT_FRONTENDIP, PR_MODE_TCP, LW_FRTIP, NULL, "fi" }, /* frontend ip */
	{ "Fp", LOG_FMT_FRONTENDPORT, PR_MODE_TCP, LW_FRTIP, NULL, "fp" }, /* frontend port */
	{ "Si", LOG_FMT_SERVERIP, PR_MODE_TCP, LW_SVIP, NULL, "si" }, /* server destination ip */
	{ "Sp", LOG_FMT_SERVERPORT, PR_MODE_TCP, LW_SVIP, NULL, "sp" }, /* server destination port */
	{ "cc", LOG_FMT_CCLIENT, PR_MODE_HTTP, LW_REQHDR, NULL, "CC" },  /* client cookie */
	{ "cs", LOG_FMT_CSERVER, PR_MODE_HTTP, LW_RSPHDR, NULL, "CS" },  /* server cookie */
	{ "st", LOG_FMT_STATUS, PR_MODE_HTTP, LW_RESP, NULL, "ST" },   /* status code */
	{ 0, 0, 0, 0, NULL }
};

char default_http_log_format[] = "%ci:%cp [%t] %ft %b/%s %Tq/%Tw/%Tc/%Tr/%Tt %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"; // default format
char clf_http_log_format[] = "%{+Q}o %{-Q}ci - - [%T] %r %ST %B \"\" \"\" %cp %ms %ft %b %s %Tq %Tw %Tc %Tr %Tt %tsc %ac %fc %bc %sc %rc %sq %bq %CC %CS %hrl %hsl";
char default_tcp_log_format[] = "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq";
char *log_format = NULL;

/* This is a global syslog line, common to all outgoing messages. It begins
 * with the syslog tag and the date that are updated by update_log_hdr().
 */
char *logline = NULL;

struct logformat_var_args {
	char *name;
	int mask;
};

struct logformat_var_args var_args_list[] = {
// global
	{ "M", LOG_OPT_MANDATORY },
	{ "Q", LOG_OPT_QUOTE },
	{ "X", LOG_OPT_HEXA },
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
 * Parse args in a logformat_var
 */
int parse_logformat_var_args(char *args, struct logformat_node *node)
{
	int i = 0;
	int end = 0;
	int flags = 0;  // 1 = +  2 = -
	char *sp = NULL; // start pointer

	if (args == NULL)
		return 1;

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
	return 0;
}

/*
 * Parse a variable '%varname' or '%{args}varname' in log-format. The caller
 * must pass the args part in the <arg> pointer with its length in <arg_len>,
 * and varname with its length in <var> and <var_len> respectively. <arg> is
 * ignored when arg_len is 0. Neither <var> nor <var_len> may be null.
 */
int parse_logformat_var(char *arg, int arg_len, char *var, int var_len, struct proxy *curproxy, struct list *list_format, int *defoptions)
{
	int j;
	struct logformat_node *node;

	for (j = 0; logformat_keywords[j].name; j++) { // search a log type
		if (strlen(logformat_keywords[j].name) == var_len &&
		    strncmp(var, logformat_keywords[j].name, var_len) == 0) {
			if (logformat_keywords[j].mode != PR_MODE_HTTP || curproxy->mode == PR_MODE_HTTP) {
				node = calloc(1, sizeof(struct logformat_node));
				node->type = logformat_keywords[j].type;
				node->options = *defoptions;
				if (arg_len) {
					node->arg = my_strndup(arg, arg_len);
					parse_logformat_var_args(node->arg, node);
				}
				if (node->type == LOG_FMT_GLOBAL) {
					*defoptions = node->options;
					free(node->arg);
					free(node);
				} else {
					if (logformat_keywords[j].config_callback &&
					    logformat_keywords[j].config_callback(node, curproxy) != 0) {
						return -1;
					}
					curproxy->to_log |= logformat_keywords[j].lw;
					LIST_ADDQ(list_format, &node->list);
				}
				if (logformat_keywords[j].replace_by)
					Warning("parsing [%s:%d] : deprecated variable '%s' in '%s', please replace it with '%s'.\n",
					        curproxy->conf.args.file, curproxy->conf.args.line,
					        logformat_keywords[j].name, fmt_directive(curproxy), logformat_keywords[j].replace_by);
				return 0;
			} else {
				Warning("parsing [%s:%d] : '%s' : format variable '%s' is reserved for HTTP mode.\n",
				        curproxy->conf.args.file, curproxy->conf.args.line, fmt_directive(curproxy),
				        logformat_keywords[j].name);
				return -1;
			}
		}
	}

	j = var[var_len];
	var[var_len] = 0;
	Warning("parsing [%s:%d] : no such format variable '%s' in '%s'. If you wanted to emit the '%%' character verbatim, you need to use '%%%%' in log-format expressions.\n",
	        curproxy->conf.args.file, curproxy->conf.args.line, var, fmt_directive(curproxy));
	var[var_len] = j;
	return -1;
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
void add_to_logformat_list(char *start, char *end, int type, struct list *list_format)
{
	char *str;

	if (type == LF_TEXT) { /* type text */
		struct logformat_node *node = calloc(1, sizeof(struct logformat_node));
		str = calloc(end - start + 1, 1);
		strncpy(str, start, end - start);
		str[end - start] = '\0';
		node->arg = str;
		node->type = LOG_FMT_TEXT; // type string
		LIST_ADDQ(list_format, &node->list);
	} else if (type == LF_SEPARATOR) {
		struct logformat_node *node = calloc(1, sizeof(struct logformat_node));
		node->type = LOG_FMT_SEPARATOR;
		LIST_ADDQ(list_format, &node->list);
	}
}

/*
 * Parse the sample fetch expression <text> and add a node to <list_format> upon
 * success. At the moment, sample converters are not yet supported but fetch arguments
 * should work. The curpx->conf.args.ctx must be set by the caller.
 */
void add_sample_to_logformat_list(char *text, char *arg, int arg_len, struct proxy *curpx, struct list *list_format, int options, int cap, const char *file, int line)
{
	char *cmd[2];
	struct sample_expr *expr;
	struct logformat_node *node;
	int cmd_arg;
	char *errmsg = NULL;

	cmd[0] = text;
	cmd[1] = "";
	cmd_arg = 0;

	expr = sample_parse_expr(cmd, &cmd_arg, file, line, &errmsg, &curpx->conf.args);
	if (!expr) {
		Warning("parsing [%s:%d] : '%s' : sample fetch <%s> failed with : %s\n",
		        curpx->conf.args.file, curpx->conf.args.line, fmt_directive(curpx),
		        text, errmsg);
		return;
	}

	node = calloc(1, sizeof(struct logformat_node));
	node->type = LOG_FMT_EXPR;
	node->expr = expr;
	node->options = options;

	if (arg_len) {
		node->arg = my_strndup(arg, arg_len);
		parse_logformat_var_args(node->arg, node);
	}
	if (expr->fetch->val & cap & SMP_VAL_REQUEST)
		node->options |= LOG_OPT_REQ_CAP; /* fetch method is request-compatible */

	if (expr->fetch->val & cap & SMP_VAL_RESPONSE)
		node->options |= LOG_OPT_RES_CAP; /* fetch method is response-compatible */

	if (!(expr->fetch->val & cap))
		Warning("parsing [%s:%d] : '%s' : sample fetch <%s> may not be reliably used here because it needs '%s' which is not available here.\n",
		        curpx->conf.args.file, curpx->conf.args.line, fmt_directive(curpx),
			text, sample_src_names(expr->fetch->use));

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
 */
void parse_logformat_string(const char *fmt, struct proxy *curproxy, struct list *list_format, int options, int cap, const char *file, int line)
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
				Warning("parsing [%s:%d] : Fixed missing '%%' before '%c' at position %d in %s line : '%s'. Please use '%%%%' when you need the '%%' character in a log-format expression.\n",
					curproxy->conf.args.file, curproxy->conf.args.line, *str, (int)(str - backfmt), fmt_directive(curproxy), fmt);

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
			Warning("parsing [%s:%d] : Skipping isolated argument in '%s' line : '%%{%s}'\n",
			        curproxy->conf.args.file, curproxy->conf.args.line, fmt_directive(curproxy), arg);
			cformat = LF_INIT;
			break;

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
				parse_logformat_var(arg, arg_len, var, var_len, curproxy, list_format, &options);
				break;
			case LF_STEXPR:
				add_sample_to_logformat_list(var, arg, arg_len, curproxy, list_format, options, cap, file, line);
				break;
			case LF_TEXT:
			case LF_SEPARATOR:
				add_to_logformat_list(sp, str, pformat, list_format);
				break;
			}
			sp = str; /* new start of text at every state switch and at every separator */
		}
	}

	if (pformat == LF_STARTVAR || pformat == LF_STARG || pformat == LF_STEXPR)
		Warning("parsing [%s:%d] : Ignoring end of truncated '%s' line after '%s'\n",
		        curproxy->conf.args.file, curproxy->conf.args.line, fmt_directive(curproxy),
		        var ? var : arg ? arg : "%");

	free(backfmt);
}

/*
 * Displays the message on stderr with the date and pid. Overrides the quiet
 * mode during startup.
 */
void Alert(const char *fmt, ...)
{
	va_list argp;
	struct tm tm;

	if (!(global.mode & MODE_QUIET) || (global.mode & (MODE_VERBOSE | MODE_STARTING))) {
		va_start(argp, fmt);

		get_localtime(date.tv_sec, &tm);
		fprintf(stderr, "[ALERT] %03d/%02d%02d%02d (%d) : ",
			tm.tm_yday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)getpid());
		vfprintf(stderr, fmt, argp);
		fflush(stderr);
		va_end(argp);
	}
}


/*
 * Displays the message on stderr with the date and pid.
 */
void Warning(const char *fmt, ...)
{
	va_list argp;
	struct tm tm;

	if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
		va_start(argp, fmt);

		get_localtime(date.tv_sec, &tm);
		fprintf(stderr, "[WARNING] %03d/%02d%02d%02d (%d) : ",
			tm.tm_yday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)getpid());
		vfprintf(stderr, fmt, argp);
		fflush(stderr);
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
 * Write a string in the log string
 * Take cares of quote options
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
		len = strlcpy2(dst, src, len);

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

/* Re-generate the syslog header at the beginning of logline once a second and
 * return the pointer to the first character after the header.
 */
static char *update_log_hdr(const char *log_tag)
{
	static long tvsec;
	static char *dataptr = NULL; /* backup of last end of header, NULL first time */
	int tag_len;

	if (unlikely(date.tv_sec != tvsec || dataptr == NULL)) {
		/* this string is rebuild only once a second */
		struct tm tm;
		int hdr_len;

		tvsec = date.tv_sec;
		get_localtime(tvsec, &tm);

		hdr_len = snprintf(logline, global.max_syslog_len,
				   "<<<<>%s %2d %02d:%02d:%02d %s",
				   monthname[tm.tm_mon],
				   tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
				   global.log_send_hostname ? global.log_send_hostname : "");
		/* WARNING: depending upon implementations, snprintf may return
		 * either -1 or the number of bytes that would be needed to store
		 * the total message. In both cases, we must adjust it.
		 */
		if (hdr_len < 0 || hdr_len > global.max_syslog_len)
			hdr_len = global.max_syslog_len;

		dataptr = logline + hdr_len;
	}

	dataptr[0] = 0; // ensure we get rid of any previous attempt

	tag_len = snprintf(dataptr, logline + global.max_syslog_len - dataptr, "%s[%d]: ", log_tag, pid);
	if (tag_len < 0 || tag_len > logline + global.max_syslog_len - dataptr)
		tag_len = logline + global.max_syslog_len - dataptr;

	return dataptr + tag_len;
}

/*
 * This function adds a header to the message and sends the syslog message
 * using a printf format string. It expects an LF-terminated message.
 */
void send_log(struct proxy *p, int level, const char *format, ...)
{
	va_list argp;
	char *dataptr;
	int  data_len;

	if (level < 0 || format == NULL || logline == NULL)
		return;

	dataptr = update_log_hdr(p && p->log_tag ? p->log_tag : global.log_tag); /* update log header and skip it */
	data_len = dataptr - logline;

	va_start(argp, format);
	data_len += vsnprintf(dataptr, logline + global.max_syslog_len - dataptr, format, argp);
	if (data_len < 0 || data_len > global.max_syslog_len)
		data_len = global.max_syslog_len;
	va_end(argp);

	__send_log(p, level, logline, data_len);
}

/*
 * This function sends a syslog message.
 * It doesn't care about errors nor does it report them.
 * It overrides the last byte (message[size-1]) with an LF character.
 */
void __send_log(struct proxy *p, int level, char *message, size_t size)
{
	static int logfdunix = -1;	/* syslog to AF_UNIX socket */
	static int logfdinet = -1;	/* syslog to AF_INET socket */
	static char *dataptr = NULL;
	int fac_level;
	struct list *logsrvs = NULL;
	struct logsrv *tmp = NULL;
	int nblogger;
	char *log_ptr;

	dataptr = message;

	if (p == NULL) {
		if (!LIST_ISEMPTY(&global.logsrvs)) {
			logsrvs = &global.logsrvs;
		}
	} else {
		if (!LIST_ISEMPTY(&p->logsrvs)) {
			logsrvs = &p->logsrvs;
		}
	}

	if (!logsrvs)
		return;

	/* Send log messages to syslog server. */
	nblogger = 0;
	list_for_each_entry(tmp, logsrvs, list) {
		const struct logsrv *logsrv = tmp;
		int *plogfd = logsrv->addr.ss_family == AF_UNIX ?
			&logfdunix : &logfdinet;
		int sent;
		int max;
		char backup;

		nblogger++;

		/* we can filter the level of the messages that are sent to each logger */
		if (level > logsrv->level)
			continue;

		if (unlikely(*plogfd < 0)) {
			/* socket not successfully initialized yet */
			int proto = logsrv->addr.ss_family == AF_UNIX ? 0 : IPPROTO_UDP;

			if ((*plogfd = socket(logsrv->addr.ss_family, SOCK_DGRAM, proto)) < 0) {
				Alert("socket for logger #%d failed: %s (errno=%d)\n",
				      nblogger, strerror(errno), errno);
				continue;
			}
			/* we don't want to receive anything on this socket */
			setsockopt(*plogfd, SOL_SOCKET, SO_RCVBUF, &zero, sizeof(zero));
			/* does nothing under Linux, maybe needed for others */
			shutdown(*plogfd, SHUT_RD);
		}

		/* For each target, we may have a different facility.
		 * We can also have a different log level for each message.
		 * This induces variations in the message header length.
		 * Since we don't want to recompute it each time, nor copy it every
		 * time, we only change the facility in the pre-computed header,
		 * and we change the pointer to the header accordingly.
		 */
		fac_level = (logsrv->facility << 3) + MAX(level, logsrv->minlvl);
		log_ptr = dataptr + 3; /* last digit of the log level */
		do {
			*log_ptr = '0' + fac_level % 10;
			fac_level /= 10;
			log_ptr--;
		} while (fac_level && log_ptr > dataptr);
		*log_ptr = '<';

		max = size - (log_ptr - dataptr);
		if (max > logsrv->maxlen)
			max = logsrv->maxlen;

		/* insert a \n at the end of the message, but save what was
		 * there first because we could have different max lengths
		 * for different log targets.
		 */
		backup = log_ptr[max - 1];
		log_ptr[max - 1] = '\n';

		sent = sendto(*plogfd, log_ptr, max,
			      MSG_DONTWAIT | MSG_NOSIGNAL,
			      (struct sockaddr *)&logsrv->addr, get_addr_len(&logsrv->addr));

		log_ptr[max - 1] = backup;

		if (sent < 0) {
			Alert("sendto logger #%d failed: %s (errno=%d)\n",
				nblogger, strerror(errno), errno);
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
					ret = encode_chunk(tmplog, dst + maxsize,
					                   '%', http_encode_map, key ? &key->data.str : &empty);
				else
					ret = lf_text_len(tmplog, key ? key->data.str.str : NULL, key ? key->data.str.len : 0, dst + maxsize - tmplog, tmp);
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
				conn = objt_conn(s->si[1].end);
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
				conn = objt_conn(s->si[1].end);
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
				conn = objt_conn(s->si[1].end);
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
				conn = objt_conn(s->si[1].end);
				if (conn)
					ret = lf_port(tmplog, (struct sockaddr *)&conn->addr.to, dst + maxsize - tmplog, tmp);
				else
					ret = lf_text_len(tmplog, NULL, 0, dst + maxsize - tmplog, tmp);

				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_DATE: // %t
				get_localtime(s->logs.accept_date.tv_sec, &tm);
				ret = date2str_log(tmplog, &tm, &(s->logs.accept_date),
						   dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_DATEGMT: // %T
				get_gmtime(s->logs.accept_date.tv_sec, &tm);
				ret = gmt2str_log(tmplog, &tm, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_DATELOCAL: // %Tl
				get_localtime(s->logs.accept_date.tv_sec, &tm);
				ret = localdate2str_log(tmplog, &tm, dst + maxsize - tmplog);
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
#ifdef USE_OPENSSL
				if (sess->listener->xprt == &ssl_sock)
					LOGCHAR('~');
#endif
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');
				last_isspace = 0;
				break;
#ifdef USE_OPENSSL
			case LOG_FMT_SSL_CIPHER: // %sslc
				src = NULL;
				conn = objt_conn(sess->origin);
				if (conn) {
					if (sess->listener->xprt == &ssl_sock)
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
					if (sess->listener->xprt == &ssl_sock)
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

			case LOG_FMT_TQ: // %Tq
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

			case LOG_FMT_TR: // %Tr
				ret = ltoa_o((s->logs.t_data >= 0) ? s->logs.t_data - s->logs.t_connect : -1,
						tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_TT:  // %Tt
				if (!(fe->to_log & LW_BYTES))
					LOGCHAR('+');
				ret = ltoa_o(s->logs.t_close, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_STATUS: // %ST
				ret = ltoa_o(txn->status, tmplog, dst + maxsize - tmplog);
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
				src = txn->cli_cookie;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_CSERVER: // %CS
				src = txn->srv_cookie;
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
				LOGCHAR((be->ck_opts & PR_CK_ANY) ? sess_cookie[(txn->flags & TX_CK_MASK) >> TX_CK_SHIFT] : '-');
				LOGCHAR((be->ck_opts & PR_CK_ANY) ? sess_set_cookie[(txn->flags & TX_SCK_MASK) >> TX_SCK_SHIFT] : '-');
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
							ret = encode_string(tmplog, dst + maxsize,
									       '#', hdr_encode_map, s->req_cap[hdr]);
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
							ret = encode_string(tmplog, dst + maxsize,
									       '#', hdr_encode_map, s->req_cap[hdr]);
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
							ret = encode_string(tmplog, dst + maxsize,
							                    '#', hdr_encode_map, s->res_cap[hdr]);
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
							ret = encode_string(tmplog, dst + maxsize,
							                    '#', hdr_encode_map, s->res_cap[hdr]);
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
				uri = txn->uri ? txn->uri : "<BADREQ>";
				ret = encode_string(tmplog, dst + maxsize,
						       '#', url_encode_map, uri);
				if (ret == NULL || *ret != '\0')
					goto out;
				tmplog = ret;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');
				last_isspace = 0;
				break;

			case LOG_FMT_HTTP_PATH: // %HP
				uri = txn->uri ? txn->uri : "<BADREQ>";

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

				if (!txn->uri || nspaces == 0) {
					chunk.str = "<BADREQ>";
					chunk.len = strlen("<BADREQ>");
				} else {
					chunk.str = uri;
					chunk.len = spc - uri;
				}

				ret = encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk);
				if (ret == NULL || *ret != '\0')
					goto out;

				tmplog = ret;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

				last_isspace = 0;
				break;

			case LOG_FMT_HTTP_URI: // %HU
				uri = txn->uri ? txn->uri : "<BADREQ>";

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

				if (!txn->uri || nspaces == 0) {
					chunk.str = "<BADREQ>";
					chunk.len = strlen("<BADREQ>");
				} else {
					chunk.str = uri;
					chunk.len = spc - uri;
				}

				ret = encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk);
				if (ret == NULL || *ret != '\0')
					goto out;

				tmplog = ret;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

				last_isspace = 0;
				break;

			case LOG_FMT_HTTP_METHOD: // %HM
				uri = txn->uri ? txn->uri : "<BADREQ>";
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

				ret = encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk);
				if (ret == NULL || *ret != '\0')
					goto out;

				tmplog = ret;
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');

				last_isspace = 0;
				break;

			case LOG_FMT_HTTP_VERSION: // %HV
				uri = txn->uri ? txn->uri : "<BADREQ>";
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

				if (!txn->uri || nspaces == 0) {
					chunk.str = "<BADREQ>";
					chunk.len = strlen("<BADREQ>");
				} else if (uri == end) {
					chunk.str = "HTTP/0.9";
					chunk.len = strlen("HTTP/0.9");
				} else {
					chunk.str = uri;
					chunk.len = end - uri;
				}

				ret = encode_chunk(tmplog, dst + maxsize, '#', url_encode_map, &chunk);
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
	char *tmplog;
	int size, err, level;

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
		if ((s->unique_id = pool_alloc2(pool2_uniqueid)) != NULL)
			build_logline(s, s->unique_id, UNIQUEID_LEN, &sess->fe->format_unique_id);
	}

	tmplog = update_log_hdr(sess->fe->log_tag ? sess->fe->log_tag : global.log_tag);
	size = tmplog - logline;
	size += build_logline(s, tmplog, global.max_syslog_len - size, &sess->fe->logformat);
	if (size > 0) {
		sess->fe->log_count++;
		__send_log(sess->fe, level, logline, size + 1);
		s->logs.logwait = 0;
	}
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
