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
#include <proto/log.h>
#include <proto/stream_interface.h>

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

const char sess_term_cond[10] = "-cCsSPRIDK";	/* normal, CliTo, CliErr, SrvTo, SrvErr, PxErr, Resource, Internal, Down, Killed */
const char sess_fin_state[8]  = "-RCHDLQT";	/* cliRequest, srvConnect, srvHeader, Data, Last, Queue, Tarpit */


/* log_format   */
struct logformat_type {
	char *name;
	int type;
	int mode;
	int lw; /* logwait bitsfield */
	int (*config_callback)(struct logformat_node *node, struct proxy *curproxy);
};

int prepare_addrsource(struct logformat_node *node, struct proxy *curproxy);

/* log_format variable names */
static const struct logformat_type logformat_keywords[] = {
	{ "o", LOG_FMT_GLOBAL, PR_MODE_TCP, 0, NULL },  /* global option */
	{ "Ci", LOG_FMT_CLIENTIP, PR_MODE_TCP, LW_CLIP, NULL },  /* client ip */
	{ "Cp", LOG_FMT_CLIENTPORT, PR_MODE_TCP, LW_CLIP, NULL }, /* client port */
	{ "Bp", LOG_FMT_BACKENDPORT, PR_MODE_TCP, LW_BCKIP, prepare_addrsource }, /* backend source port */
	{ "Bi", LOG_FMT_BACKENDIP, PR_MODE_TCP, LW_BCKIP, prepare_addrsource }, /* backend source ip */
	{ "Fp", LOG_FMT_FRONTENDPORT, PR_MODE_TCP, LW_FRTIP, NULL }, /* frontend port */
	{ "Fi", LOG_FMT_FRONTENDIP, PR_MODE_TCP, LW_FRTIP, NULL }, /* frontend ip */
	{ "Sp", LOG_FMT_SERVERPORT, PR_MODE_TCP, LW_SVIP, NULL }, /* server destination port */
	{ "Si", LOG_FMT_SERVERIP, PR_MODE_TCP, LW_SVIP, NULL }, /* server destination ip */
	{ "t", LOG_FMT_DATE, PR_MODE_TCP, LW_INIT, NULL },      /* date */
	{ "T", LOG_FMT_DATEGMT, PR_MODE_TCP, LW_INIT, NULL },   /* date GMT */
	{ "Ts", LOG_FMT_TS, PR_MODE_TCP, LW_INIT, NULL },   /* timestamp GMT */
	{ "ms", LOG_FMT_MS, PR_MODE_TCP, LW_INIT, NULL },       /* accept date millisecond */
	{ "f", LOG_FMT_FRONTEND, PR_MODE_TCP, LW_INIT, NULL },  /* frontend */
	{ "b", LOG_FMT_BACKEND, PR_MODE_TCP, LW_INIT, NULL },   /* backend */
	{ "s", LOG_FMT_SERVER, PR_MODE_TCP, LW_SVID, NULL },    /* server */
	{ "B", LOG_FMT_BYTES, PR_MODE_TCP, LW_BYTES, NULL },     /* bytes read */
	{ "Tq", LOG_FMT_TQ, PR_MODE_HTTP, LW_BYTES, NULL },       /* Tq */
	{ "Tw", LOG_FMT_TW, PR_MODE_TCP, LW_BYTES, NULL },       /* Tw */
	{ "Tc", LOG_FMT_TC, PR_MODE_TCP, LW_BYTES, NULL },       /* Tc */
	{ "Tr", LOG_FMT_TR, PR_MODE_HTTP, LW_BYTES, NULL },       /* Tr */
	{ "Tt", LOG_FMT_TT, PR_MODE_TCP, LW_BYTES, NULL },       /* Tt */
	{ "st", LOG_FMT_STATUS, PR_MODE_HTTP, LW_RESP, NULL },   /* status code */
	{ "cc", LOG_FMT_CCLIENT, PR_MODE_HTTP, LW_REQHDR, NULL },  /* client cookie */
	{ "cs", LOG_FMT_CSERVER, PR_MODE_HTTP, LW_RSPHDR, NULL },  /* server cookie */
	{ "ts", LOG_FMT_TERMSTATE, PR_MODE_TCP, LW_BYTES, NULL },/* termination state */
	{ "tsc", LOG_FMT_TERMSTATE_CK, PR_MODE_TCP, LW_INIT, NULL },/* termination state */
	{ "ac", LOG_FMT_ACTCONN, PR_MODE_TCP, LW_BYTES, NULL },  /* actconn */
	{ "fc", LOG_FMT_FECONN, PR_MODE_TCP, LW_BYTES, NULL },   /* feconn */
	{ "bc", LOG_FMT_BECONN, PR_MODE_TCP, LW_BYTES, NULL },   /* beconn */
	{ "sc", LOG_FMT_SRVCONN, PR_MODE_TCP, LW_BYTES, NULL },  /* srv_conn */
	{ "rc", LOG_FMT_RETRIES, PR_MODE_TCP, LW_BYTES, NULL },  /* retries */
	{ "sq", LOG_FMT_SRVQUEUE, PR_MODE_TCP, LW_BYTES, NULL  }, /* srv_queue */
	{ "bq", LOG_FMT_BCKQUEUE, PR_MODE_TCP, LW_BYTES, NULL }, /* backend_queue */
	{ "hr", LOG_FMT_HDRREQUEST, PR_MODE_HTTP, LW_REQHDR, NULL }, /* header request */
	{ "hs", LOG_FMT_HDRRESPONS, PR_MODE_HTTP, LW_RSPHDR, NULL },  /* header response */
	{ "hrl", LOG_FMT_HDRREQUESTLIST, PR_MODE_HTTP, LW_REQHDR, NULL }, /* header request list */
	{ "hsl", LOG_FMT_HDRRESPONSLIST, PR_MODE_HTTP, LW_RSPHDR, NULL },  /* header response list */
	{ "r", LOG_FMT_REQ, PR_MODE_HTTP, LW_REQ, NULL },  /* request */
	{ "pid", LOG_FMT_PID, PR_MODE_TCP, LW_INIT, NULL }, /* log pid */
	{ "rt", LOG_FMT_COUNTER, PR_MODE_HTTP, LW_REQ, NULL }, /* HTTP request counter */
	{ "H", LOG_FMT_HOSTNAME, PR_MODE_TCP, LW_INIT, NULL }, /* Hostname */
	{ "ID", LOG_FMT_UNIQUEID, PR_MODE_HTTP, LW_BYTES, NULL }, /* Unique ID */
	{ 0, 0, 0, 0, NULL }
};

char default_http_log_format[] = "%Ci:%Cp [%t] %f %b/%s %Tq/%Tw/%Tc/%Tr/%Tt %st %B %cc %cs %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"; // default format
char clf_http_log_format[] = "%{+Q}o %{-Q}Ci - - [%T] %r %st %B \"\" \"\" %Cp %ms %f %b %s %Tq %Tw %Tc %Tr %Tt %tsc %ac %fc %bc %sc %rc %sq %bq %cc %cs %hrl %hsl";
char default_tcp_log_format[] = "%Ci:%Cp [%t] %f %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq";
char *log_format = NULL;

/* This is a global syslog line, common to all outgoing messages. It begins
 * with the syslog tag and the date that are updated by update_log_hdr().
 */
static char logline[MAX_SYSLOG_LEN];

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
			for (i = 0; var_args_list[i].name; i++) {
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
 * Parse a variable '%varname' or '%{args}varname' in logformat
 *
 */
int parse_logformat_var(char *str, size_t len, struct proxy *curproxy, struct list *list_format, int *defoptions)
{
	int i, j;
	char *arg = NULL; // arguments
	int fparam = 0;
	char *name = NULL;
	struct logformat_node *node = NULL;
	char varname[255] = { 0 }; // variable name

	for (i = 1; i < len; i++) { // escape first char %
		if (!arg && str[i] == '{') {
			arg = str + i;
			fparam = 1;
		} else if (arg && str[i] == '}') {
			char *tmp = arg;
			arg = calloc(str + i - tmp, 1); // without {}
			strncpy(arg, tmp + 1, str + i - tmp - 1); // copy without { and }
			arg[str + i - tmp - 1] = '\0';
			fparam = 0;
		} else if (!name && !fparam) {
			strncpy(varname, str + i, len - i + 1);
			varname[len - i] = '\0';
			for (j = 0; logformat_keywords[j].name; j++) { // search a log type
				if (strcmp(varname, logformat_keywords[j].name) == 0) {
					if (!((logformat_keywords[j].mode == PR_MODE_HTTP) && (curproxy->mode == PR_MODE_TCP))) {
						node = calloc(1, sizeof(struct logformat_node));
						node->type = logformat_keywords[j].type;
						node->options = *defoptions;
						node->arg = arg;
						parse_logformat_var_args(node->arg, node);
						if (node->type == LOG_FMT_GLOBAL) {
							*defoptions = node->options;
							free(node);
						} else {
							if (logformat_keywords[j].config_callback != NULL) {
								if (logformat_keywords[j].config_callback(node, curproxy) != 0) {
									return -1;
								 }
							}
							curproxy->to_log |= logformat_keywords[j].lw;
							LIST_ADDQ(list_format, &node->list);
						}
						return 0;
					} else {
						Warning("Warning: No such variable name '%s' in this log mode\n", varname);
						if (arg)
							free(arg);
						return -1;
					}
				}
			}
			Warning("Warning: No such variable name '%s' in logformat\n", varname);
			if (arg)
				free(arg);
			return -1;
		}
	}
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

	if (type == LOG_FMT_TEXT) { /* type text */
		struct logformat_node *node = calloc(1, sizeof(struct logformat_node));
		str = calloc(end - start + 1, 1);
		strncpy(str, start, end - start);
		str[end - start] = '\0';
		node->arg = str;
		node->type = LOG_FMT_TEXT; // type string
		LIST_ADDQ(list_format, &node->list);
	} else if (type == LOG_FMT_SEPARATOR) {
		struct logformat_node *node = calloc(1, sizeof(struct logformat_node));
		node->type = LOG_FMT_SEPARATOR;
		LIST_ADDQ(list_format, &node->list);
	}
}

/*
 * Parse the log_format string and fill a linked list.
 * Variable name are preceded by % and composed by characters [a-zA-Z0-9]* : %varname
 * You can set arguments using { } : %{many arguments}varname
 *
 *  str: the string to parse
 *  curproxy: the proxy affected
 *  list_format: the destination list
 *  capabilities: PR_MODE_TCP_ | PR_MODE_HTTP
 */
void parse_logformat_string(char *str, struct proxy *curproxy, struct list *list_format, int capabilities)
{
	char *sp = str; /* start pointer */
	int cformat = -1; /* current token format : LOG_TEXT, LOG_SEPARATOR, LOG_VARIABLE */
	int pformat = -1; /* previous token format */
	struct logformat_node *tmplf, *back;
	int options = 0;

	curproxy->to_log = LW_INIT;

	/* flush the list first. */
	list_for_each_entry_safe(tmplf, back, list_format, list) {
		LIST_DEL(&tmplf->list);
		free(tmplf);
	}

	while (1) {

		// push the variable only if formats are different, not
		// within a variable, and not the first iteration
		if ((cformat != pformat && cformat != -1 && pformat != -1) || *str == '\0') {
			if (((pformat != LF_STARTVAR && cformat != LF_VAR) &&
			    (pformat != LF_STARTVAR && cformat != LF_STARG) &&
			    (pformat != LF_STARG && cformat !=  LF_VAR)) || *str == '\0') {
				if (pformat > LF_VAR) // unfinished string
					pformat = LF_TEXT;
				if (pformat == LF_VAR)
					parse_logformat_var(sp, str - sp, curproxy, list_format, &options);
				else
					add_to_logformat_list(sp, str, pformat, list_format);
				sp = str;
				if (*str == '\0')
					break;
			    }
		}

		if (cformat != -1)
			str++; // consume the string, except on the first tour

		pformat = cformat;

		if (*str == '\0') {
			cformat = LF_STARTVAR; // for breaking in all cases
			continue;
		}

		if (pformat == LF_STARTVAR) { // after a %
			if ( (*str >= 'a' && *str <= 'z') || // parse varname
			     (*str >= 'A' && *str <= 'Z') ||
			     (*str >= '0' && *str <= '9')) {
				cformat = LF_VAR; // varname
				continue;
			} else if (*str == '{') {
				cformat = LF_STARG; // variable arguments
				continue;
			} else { // another unexpected token
				pformat = LF_TEXT; // redefine the format of the previous token to TEXT
				cformat = LF_TEXT;
				continue;
			}

		} else if (pformat == LF_VAR) { // after a varname
			if ( (*str >= 'a' && *str <= 'z') || // parse varname
			     (*str >= 'A' && *str <= 'Z') ||
			     (*str >= '0' && *str <= '9')) {
				cformat = LF_VAR;
				continue;
			}
		} else if (pformat  == LF_STARG) { // inside variable arguments
			if (*str == '}') { // end of varname
				cformat = LF_EDARG;
				continue;
			} else { // all tokens are acceptable within { }
				cformat = LF_STARG;
				continue;
			}
		} else if (pformat == LF_EDARG) { //  after arguments
			if ( (*str >= 'a' && *str <= 'z') || // parse a varname
			     (*str >= 'A' && *str <= 'Z') ||
			     (*str >= '0' && *str <= '9')) {
				cformat = LF_VAR;
				continue;
			} else { // if no varname after arguments, transform in TEXT
				pformat = LF_TEXT;
				cformat = LF_TEXT;
			}
		}

		// others tokens that don't match previous conditions
		if (*str == '%') {
			cformat = LF_STARTVAR;
		} else if (*str == ' ') {
			cformat = LF_SEPARATOR;
		} else {
			cformat = LF_TEXT;
		}
	}
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
char *lf_text(char *dst, char *src, size_t size, struct logformat_node *node)
{
	int n;

	if (src == NULL || *src == '\0') {
		if (node->options & LOG_OPT_QUOTE) {
			if (size > 2) {
				*(dst++) = '"';
				*(dst++) = '"';
				*dst = '\0';
			} else {
				dst = NULL;
				return dst;
			}
		} else {
			if (size > 1) {
				*(dst++) = '-';
				*dst = '\0';
			} else { // error no space available
				dst = NULL;
				return dst;
			}
		}
	} else {
		if (node->options & LOG_OPT_QUOTE) {
			if (size-- > 1 ) {
				*(dst++) = '"';
			} else {
				dst = NULL;
				return NULL;
			}
			n = strlcpy2(dst, src, size);
			size -= n;
			dst += n;
			if (size > 1) {
				*(dst++) = '"';
				*dst = '\0';
			} else {
				dst = NULL;
			}
		} else {
			dst += strlcpy2(dst, src, size);
		}
	}
	return dst;
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
static char *update_log_hdr()
{
	static long tvsec;
	static char *dataptr = NULL; /* backup of last end of header, NULL first time */

	if (unlikely(date.tv_sec != tvsec || dataptr == NULL)) {
		/* this string is rebuild only once a second */
		struct tm tm;
		int hdr_len;

		tvsec = date.tv_sec;
		get_localtime(tvsec, &tm);

		hdr_len = snprintf(logline, MAX_SYSLOG_LEN,
				   "<<<<>%s %2d %02d:%02d:%02d %s%s[%d]: ",
				   monthname[tm.tm_mon],
				   tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
				   global.log_send_hostname ? global.log_send_hostname : "",
				   global.log_tag, pid);
		/* WARNING: depending upon implementations, snprintf may return
		 * either -1 or the number of bytes that would be needed to store
		 * the total message. In both cases, we must adjust it.
		 */
		if (hdr_len < 0 || hdr_len > MAX_SYSLOG_LEN)
			hdr_len = MAX_SYSLOG_LEN;

		dataptr = logline + hdr_len;
	}

	return dataptr;
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

	if (level < 0 || format == NULL)
		return;

	dataptr = update_log_hdr(); /* update log header and skip it */
	data_len = dataptr - logline;

	va_start(argp, format);
	data_len += vsnprintf(dataptr, logline + sizeof(logline) - dataptr, format, argp);
	if (data_len < 0 || data_len > MAX_SYSLOG_LEN)
		data_len =  MAX_SYSLOG_LEN;
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

	message[size - 1] = '\n';

	/* Lazily set up syslog sockets for protocol families of configured
	 * syslog servers. */
	nblogger = 0;
	list_for_each_entry(tmp, logsrvs, list) {
		const struct logsrv *logsrv = tmp;
		int proto, *plogfd;

		if (logsrv->addr.ss_family == AF_UNIX) {
			proto = 0;
			plogfd = &logfdunix;
		} else {
			proto = IPPROTO_UDP;
			plogfd = &logfdinet;
		}
		if (*plogfd >= 0) {
			/* socket already created. */
			continue;
		}
		if ((*plogfd = socket(logsrv->addr.ss_family, SOCK_DGRAM,
				proto)) < 0) {
			Alert("socket for logger #%d failed: %s (errno=%d)\n",
				nblogger + 1, strerror(errno), errno);
			return;
		}
		/* we don't want to receive anything on this socket */
		setsockopt(*plogfd, SOL_SOCKET, SO_RCVBUF, &zero, sizeof(zero));
		/* does nothing under Linux, maybe needed for others */
		shutdown(*plogfd, SHUT_RD);
		nblogger++;
	}

	/* Send log messages to syslog server. */
	nblogger = 0;
	list_for_each_entry(tmp, logsrvs, list) {
		const struct logsrv *logsrv = tmp;
		int *plogfd = logsrv->addr.ss_family == AF_UNIX ?
			&logfdunix : &logfdinet;
		int sent;

		/* we can filter the level of the messages that are sent to each logger */
		if (level > logsrv->level)
			continue;

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

		sent = sendto(*plogfd, log_ptr, size + log_ptr - dataptr,
			      MSG_DONTWAIT | MSG_NOSIGNAL,
			      (struct sockaddr *)&logsrv->addr, get_addr_len(&logsrv->addr));
		if (sent < 0) {
			Alert("sendto logger #%d failed: %s (errno=%d)\n",
				nblogger, strerror(errno), errno);
		}
		nblogger++;
	}
}

extern fd_set hdr_encode_map[];
extern fd_set url_encode_map[];


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



int build_logline(struct session *s, char *dst, size_t maxsize, struct list *list_format)
{
	struct proxy *fe = s->fe;
	struct proxy *be = s->be;
	struct http_txn *txn = &s->txn;
	int tolog;
	char *uri;
	const char *svid;
	struct tm tm;
	int t_request;
	int hdr;
	int last_isspace = 1;
	char *tmplog;
	char *ret;
	int iret;
	struct logformat_node *tmp;

	/* FIXME: let's limit ourselves to frontend logging for now. */
	tolog = fe->to_log;

	if (!(tolog & LW_SVID))
		svid = "-";
	else switch (s->target.type) {
	case TARG_TYPE_SERVER:
		svid = s->target.ptr.s->id;
		break;
	case TARG_TYPE_APPLET:
		svid = s->target.ptr.a->name;
		break;
	default:
		svid = "<NOSRV>";
		break;
	}

	t_request = -1;
	if (tv_isge(&s->logs.tv_request, &s->logs.tv_accept))
		t_request = tv_ms_elapsed(&s->logs.tv_accept, &s->logs.tv_request);

	tmplog = dst;

	/* fill logbuffer */
	if (LIST_ISEMPTY(list_format))
		return 0;

	list_for_each_entry(tmp, list_format, list) {
		char *src = NULL;
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

			case LOG_FMT_CLIENTIP:  // %Ci
				ret = lf_ip(tmplog, (struct sockaddr *)&s->req->prod->addr.from,
					    dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_CLIENTPORT:  // %Cp
				if (s->req->prod->addr.from.ss_family == AF_UNIX) {
					ret = ltoa_o(s->listener->luid, tmplog, dst + maxsize - tmplog);
				} else {
					ret = lf_port(tmplog, (struct sockaddr *)&s->req->prod->addr.from,
						      dst + maxsize - tmplog, tmp);
				}
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_FRONTENDIP: // %Fi
				get_frt_addr(s);
				ret = lf_ip(tmplog, (struct sockaddr *)&s->req->prod->addr.to,
					    dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case  LOG_FMT_FRONTENDPORT: // %Fp
				get_frt_addr(s);
				if (s->req->prod->addr.to.ss_family == AF_UNIX) {
					ret = ltoa_o(s->listener->luid,
						     tmplog, dst + maxsize - tmplog);
				} else {
					ret = lf_port(tmplog, (struct sockaddr *)&s->req->prod->addr.to,
						      dst + maxsize - tmplog, tmp);
				}
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_BACKENDIP:  // %Bi
				ret = lf_ip(tmplog, (struct sockaddr *)&s->req->cons->addr.from,
					    dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_BACKENDPORT:  // %Bp
				ret = lf_port(tmplog, (struct sockaddr *)&s->req->cons->addr.from,
					      dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_SERVERIP: // %Si
				ret = lf_ip(tmplog, (struct sockaddr *)&s->req->cons->addr.to,
					    dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_SERVERPORT: // %Sp
				ret = lf_port(tmplog, (struct sockaddr *)&s->req->cons->addr.to,
					      dst + maxsize - tmplog, tmp);
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
				tmplog = utoa_pad((unsigned int)s->logs.accept_date.tv_usec/1000,
						  tmplog, 4);
				if (!tmplog)
					goto out;
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

			case LOG_FMT_BACKEND: // %b
				src = be->id;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_SERVER: // %s
				src = (char *)svid;
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
				if (!(tolog & LW_BYTES))
					LOGCHAR('+');
				ret = ltoa_o(s->logs.t_close, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_STATUS: // %st
				ret = ltoa_o(txn->status, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_BYTES: // %B
				if (!(tolog & LW_BYTES))
					LOGCHAR('+');
				ret = lltoa(s->logs.bytes_out, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_CCLIENT: // %cc
				src = txn->cli_cookie;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_CSERVER: // %cs
				src = txn->srv_cookie;
				ret = lf_text(tmplog, src, dst + maxsize - tmplog, tmp);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_TERMSTATE: // %ts
				LOGCHAR(sess_term_cond[(s->flags & SN_ERR_MASK) >> SN_ERR_SHIFT]);
				LOGCHAR(sess_fin_state[(s->flags & SN_FINST_MASK) >> SN_FINST_SHIFT]);
				*tmplog = '\0';
				last_isspace = 0;
				break;

			case LOG_FMT_TERMSTATE_CK: // %tsc, same as TS with cookie state (for mode HTTP)
				LOGCHAR(sess_term_cond[(s->flags & SN_ERR_MASK) >> SN_ERR_SHIFT]);
				LOGCHAR(sess_fin_state[(s->flags & SN_FINST_MASK) >> SN_FINST_SHIFT]);
				LOGCHAR((be->options & PR_O_COOK_ANY) ? sess_cookie[(txn->flags & TX_CK_MASK) >> TX_CK_SHIFT] : '-');
				LOGCHAR((be->options & PR_O_COOK_ANY) ? sess_set_cookie[(txn->flags & TX_SCK_MASK) >> TX_SCK_SHIFT] : '-');
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
				ret = ultoa_o(target_srv(&s->target) ?
				                 target_srv(&s->target)->cur_sess :
				                 0, tmplog, dst + maxsize - tmplog);
				if (ret == NULL)
					goto out;
				tmplog = ret;
				last_isspace = 0;
				break;

			case LOG_FMT_RETRIES:  // %rq
				if (s->flags & SN_REDISP)
					LOGCHAR('+');
				ret = ltoa_o((s->req->cons->conn_retries>0) ?
				                (be->conn_retries - s->req->cons->conn_retries) :
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
				if (fe->to_log & LW_REQHDR && txn->req.cap) {
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
					LOGCHAR('{');
					for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
						if (hdr)
							LOGCHAR('|');
						if (txn->req.cap[hdr] != NULL) {
							ret = encode_string(tmplog, dst + maxsize,
									       '#', hdr_encode_map, txn->req.cap[hdr]);
							if (ret == NULL || *ret != '\0')
								goto out;
							tmplog = ret;
						}
					}
					LOGCHAR('}');
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
					last_isspace = 0;
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
				}
				break;

			case LOG_FMT_HDRREQUESTLIST: // %hrl
				/* request header list */
				if (fe->to_log & LW_REQHDR && txn->req.cap) {
					for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
						if (hdr > 0)
							LOGCHAR(' ');
						if (tmp->options & LOG_OPT_QUOTE)
							LOGCHAR('"');
						if (txn->req.cap[hdr] != NULL) {
							ret = encode_string(tmplog, dst + maxsize,
									       '#', hdr_encode_map, txn->req.cap[hdr]);
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
				if (fe->to_log & LW_RSPHDR &&
				    txn->rsp.cap) {
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
					LOGCHAR('{');
					for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
						if (hdr)
							LOGCHAR('|');
						if (txn->rsp.cap[hdr] != NULL) {
							ret = encode_string(tmplog, dst + maxsize,
							                    '#', hdr_encode_map, txn->rsp.cap[hdr]);
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
				if (fe->to_log & LW_RSPHDR && txn->rsp.cap) {
					for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
						if (hdr > 0)
							LOGCHAR(' ');
						if (tmp->options & LOG_OPT_QUOTE)
							LOGCHAR('"');
						if (txn->rsp.cap[hdr] != NULL) {
							ret = encode_string(tmplog, dst + maxsize,
							                    '#', hdr_encode_map, txn->rsp.cap[hdr]);
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

			case LOG_FMT_COUNTER: // %rt
				if (tmp->options & LOG_OPT_HEXA) {
					iret = snprintf(tmplog, dst + maxsize - tmplog, "%04X", global.req_count);
					if (iret < 0 || iret > dst + maxsize - tmplog)
						goto out;
					last_isspace = 0;
					tmplog += iret;
				} else {
					ret = ltoa_o(global.req_count, tmplog, dst + maxsize - tmplog);
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

	return tmplog - dst + 1;

}

/*
 * send a log for the session when we have enough info about it.
 * Will not log if the frontend has no log defined.
 */
void sess_log(struct session *s)
{
	char *tmplog;
	int size, err, level;

	/* if we don't want to log normal traffic, return now */
	err = (s->flags & (SN_ERR_MASK | SN_REDISP)) ||
		(s->req->cons->conn_retries != s->be->conn_retries) ||
			((s->fe->mode == PR_MODE_HTTP) && s->txn.status >= 500);

	if (!err && (s->fe->options2 & PR_O2_NOLOGNORM))
		return;

	if (LIST_ISEMPTY(&s->fe->logsrvs))
		return;

	level = LOG_INFO;
	if (err && (s->fe->options2 & PR_O2_LOGERRORS))
		level = LOG_ERR;

	tmplog = update_log_hdr();
	size = tmplog - logline;
	size += build_logline(s, tmplog, sizeof(logline) - size, &s->fe->logformat);
	if (size > 0) {
		__send_log(s->fe, level, logline, size);
		s->logs.logwait = 0;
	}
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
