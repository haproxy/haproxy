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
	int (*config_callback)(struct logformat_node *node, struct proxy *curproxy);
};

int prepare_addrsource(struct logformat_node *node, struct proxy *curproxy);

/* log_format variable names */
static const struct logformat_type logformat_keywords[] = {
	{ "o", LOG_GLOBAL, PR_MODE_TCP, NULL },  /* global option */
	{ "Ci", LOG_CLIENTIP, PR_MODE_TCP, NULL },  /* client ip */
	{ "Cp", LOG_CLIENTPORT, PR_MODE_TCP, NULL }, /* client port */
	{ "Bp", LOG_SOURCEPORT, PR_MODE_TCP, prepare_addrsource }, /* backend source port */
	{ "Bi", LOG_SOURCEIP, PR_MODE_TCP, prepare_addrsource }, /* backend source ip */
	{ "t", LOG_DATE, PR_MODE_TCP, NULL },      /* date */
	{ "T", LOG_DATEGMT, PR_MODE_TCP, NULL },   /* date GMT */
	{ "ms", LOG_MS, PR_MODE_TCP, NULL },       /* accept date millisecond */
	{ "f", LOG_FRONTEND, PR_MODE_TCP, NULL },  /* frontend */
	{ "b", LOG_BACKEND, PR_MODE_TCP, NULL },   /* backend */
	{ "s", LOG_SERVER, PR_MODE_TCP, NULL },    /* server */
	{ "B", LOG_BYTES, PR_MODE_TCP, NULL },     /* bytes read */
	{ "Tq", LOG_TQ, PR_MODE_HTTP, NULL },       /* Tq */
	{ "Tw", LOG_TW, PR_MODE_TCP, NULL },       /* Tw */
	{ "Tc", LOG_TC, PR_MODE_TCP, NULL },       /* Tc */
	{ "Tr", LOG_TR, PR_MODE_HTTP, NULL },       /* Tr */
	{ "Tt", LOG_TT, PR_MODE_TCP, NULL },       /* Tt */
	{ "st", LOG_STATUS, PR_MODE_HTTP, NULL },   /* status code */
	{ "cc", LOG_CCLIENT, PR_MODE_HTTP, NULL },  /* client cookie */
	{ "cs", LOG_CSERVER, PR_MODE_HTTP, NULL },  /* server cookie */
	{ "ts", LOG_TERMSTATE, PR_MODE_TCP, NULL },/* terminaison state */
	{ "ac", LOG_ACTCONN, PR_MODE_TCP, NULL },  /* actconn */
	{ "fc", LOG_FECONN, PR_MODE_TCP, NULL },   /* feconn */
	{ "bc", LOG_BECONN, PR_MODE_TCP, NULL },   /* beconn */
	{ "sc", LOG_SRVCONN, PR_MODE_TCP, NULL },  /* srv_conn */
	{ "rc", LOG_RETRIES, PR_MODE_TCP, NULL },  /* retries */
	{ "sq", LOG_SRVQUEUE, PR_MODE_TCP, NULL  }, /* srv_queue */
	{ "bq", LOG_BCKQUEUE, PR_MODE_TCP, NULL }, /* backend_queue */
	{ "hr", LOG_HDRREQUEST, PR_MODE_HTTP, NULL }, /* header request */
	{ "hs", LOG_HDRRESPONS, PR_MODE_HTTP, NULL },  /* header response */
	{ "hrl", LOG_HDRREQUESTLIST, PR_MODE_HTTP, NULL }, /* header request list */
	{ "hsl", LOG_HDRRESPONSLIST, PR_MODE_HTTP, NULL },  /* header response list */
	{ "r", LOG_REQ, PR_MODE_HTTP, NULL },  /* request */
	{ 0, 0, 0, NULL }
};

char default_http_log_format[] = "%Ci:%Cp [%t] %f %b/%s %Tq/%Tw/%Tc/%Tr/%Tt %st %B %cc %cs %ts %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"; // default format
char clf_http_log_format[] = "%{+Q}o %{-Q}Ci - - [%T] %r %st %B \"\" \"\" %Cp %ms %f %b %s %Tq %Tw %Tc %Tr %Tt %ts %ac %fc %bc %sc %rc %sq %bq %cc %cs %hrl %hsl";
char default_tcp_log_format[] = "%Ci:%Cp [%t] %f %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq";
char *log_format = NULL;

struct logformat_var_args {
	char *name;
	int mask;
};

struct logformat_var_args var_args_list[] = {
// global
	{ "M", LOG_OPT_MANDATORY },
	{ "Q", LOG_OPT_QUOTE },
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
int parse_logformat_var(char *str, size_t len, struct proxy *curproxy)
{
	int i, j;
	char *arg = NULL; // arguments
	int fparam = 0;
	char *name = NULL;
	struct logformat_node *node = NULL;
	char varname[255] = { 0 }; // variable name
	int logformat_options = 0x00000000;

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
						node->options = logformat_options;
						node->arg = arg;
						parse_logformat_var_args(node->arg, node);
						if (node->type == LOG_GLOBAL) {
							logformat_options = node->options;
							free(node);
						} else {
							if (logformat_keywords[j].config_callback != NULL) {
								if (logformat_keywords[j].config_callback(node, curproxy) != 0) {
									return -1;
								 }
							}
							LIST_ADDQ(&curproxy->logformat, &node->list);
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
 *
 *  LOG_TEXT: copy chars from start to end excluding end.
 *
*/
void add_to_logformat_list(char *start, char *end, int type, struct proxy *curproxy)
{
	char *str;

	if (type == LOG_TEXT) { /* type text */
		struct logformat_node *node = calloc(1, sizeof(struct logformat_node));

		str = calloc(end - start + 1, 1);
		strncpy(str, start, end - start);

		str[end - start] = '\0';
		node->arg = str;
		node->type = LOG_TEXT; // type string
		LIST_ADDQ(&curproxy->logformat, &node->list);
	} else if (type == LOG_VARIABLE) { /* type variable */
		parse_logformat_var(start, end - start, curproxy);
	} else if (type == LOG_SEPARATOR) {
		struct logformat_node *node = calloc(1, sizeof(struct logformat_node));
		node->type = LOG_SEPARATOR;
		LIST_ADDQ(&curproxy->logformat, &node->list);
	}
}

/*
 * Parse the log_format string and fill a linked list.
 * Variable name are preceded by % and composed by characters [a-zA-Z0-9]* : %varname
 * You can set arguments using { } : %{many arguments}varname
 */
void parse_logformat_string(char *str, struct proxy *curproxy)
{
	char *sp = str; /* start pointer */
	int cformat = -1; /* current token format : LOG_TEXT, LOG_SEPARATOR, LOG_VARIABLE */
	int pformat = -1; /* previous token format */
	struct logformat_node *tmplf, *back;

	/* flush the list first. */
	list_for_each_entry_safe(tmplf, back, &curproxy->logformat, list) {
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
				add_to_logformat_list(sp, str, pformat, curproxy);
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
 * Take cares of mandatory and quote options
 *
 * Return the adress of the \0 character, or NULL on error
 */
char *logformat_write_string(char *dst, char *src, size_t size, struct logformat_node *node)
{
	char *orig = dst;

	if (src == NULL || *src == '\0') {
		if (node->options & LOG_OPT_QUOTE) {
			if (size > 2) {
				*(dst++) = '"';
				*(dst++) = '"';
				*dst = '\0';
				node->options |= LOG_OPT_WRITTEN;
			} else {
				dst = NULL;
				return dst;
			}
		} else {
			if (size > 1) {
				*(dst++) = '-';
				*dst = '\0';
				node->options |= LOG_OPT_WRITTEN;
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
			dst += strlcpy2(dst, src, size);
			size -= orig - dst + 1;
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

/* generate the syslog header once a second */
char *hdr_log(char *dst)
{
	int hdr_len = 0;
	static long tvsec = -1;	/* to force the string to be initialized */
	static char *dataptr = NULL;

	if (unlikely(date.tv_sec != tvsec || dataptr == NULL)) {
		/* this string is rebuild only once a second */
		struct tm tm;

		tvsec = date.tv_sec;
		get_localtime(tvsec, &tm);

		hdr_len = snprintf(dst, MAX_SYSLOG_LEN,
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

		dataptr = dst + hdr_len;
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
	static char logmsg[MAX_SYSLOG_LEN];
	static char *dataptr = NULL;
	int  data_len = 0;

	if (level < 0 || format == NULL)
		return;

	dataptr = hdr_log(logmsg); /* create header */
	data_len = dataptr - logmsg;

	va_start(argp, format);
	data_len += vsnprintf(dataptr, MAX_SYSLOG_LEN, format, argp);
	if (data_len < 0 || data_len > MAX_SYSLOG_LEN)
		data_len =  MAX_SYSLOG_LEN;
	va_end(argp);

	__send_log(p, level, logmsg, data_len);
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

		sent = sendto(*plogfd, log_ptr, size,
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


const char sess_cookie[8]     = "NIDVEO67";	/* No cookie, Invalid cookie, cookie for a Down server, Valid cookie, Expired cookie, Old cookie, unknown */
const char sess_set_cookie[8] = "NPDIRU67";	/* No set-cookie, Set-cookie found and left unchanged (passive),
						   Set-cookie Deleted, Set-Cookie Inserted, Set-cookie Rewritten,
						   Set-cookie Updated, unknown, unknown */

#define LOGCHAR(x) do { \
			if (MAX_SYSLOG_LEN - (tmplog - logline) > 1) { \
				*(tmplog++) = (x);                     \
			} else {                                       \
				goto out;                              \
			}                                              \
		} while(0)

/*
 * send a log for the session when we have enough info about it.
 * Will not log if the frontend has no log defined.
 */
void sess_log(struct session *s)
{
	char pn[INET6_ADDRSTRLEN];
	char sn[INET6_ADDRSTRLEN];
	struct proxy *fe = s->fe;
	struct proxy *be = s->be;
	struct proxy *prx_log;
	struct http_txn *txn = &s->txn;
	int tolog, level, err;
	char *uri;
	const char *svid;
	struct tm tm;
	int t_request;
	int hdr;
	int last_isspace = 1;
	static char logline[MAX_SYSLOG_LEN] = { 0 };
	static char *tmplog;
	struct logformat_node *tmp;

	/* if we don't want to log normal traffic, return now */
	err = (s->flags & (SN_ERR_MASK | SN_REDISP)) ||
		(s->req->cons->conn_retries != be->conn_retries) ||
		((s->fe->mode == PR_MODE_HTTP) && txn->status >= 500);
	if (!err && (fe->options2 & PR_O2_NOLOGNORM))
		return;

	if (LIST_ISEMPTY(&fe->logsrvs))
		return;
	prx_log = fe;

	if (addr_to_str(&s->req->prod->addr.from, pn, sizeof(pn)) == AF_UNIX)
		snprintf(pn, sizeof(pn), "unix:%d", s->listener->luid);

	if (be->options2 & PR_O2_SRC_ADDR) {
	      if (addr_to_str(&s->req->cons->addr.from, sn, sizeof(sn)) == AF_UNIX)
		snprintf(sn, sizeof(sn), "unix:%d", s->listener->luid);
	}

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

	level = LOG_INFO;
	if (err && (fe->options2 & PR_O2_LOGERRORS))
		level = LOG_ERR;

	/* fill logbuffer */

	tmplog = logline;
	tmplog = hdr_log(tmplog);

	list_for_each_entry(tmp, &fe->logformat, list) {
		char *src = NULL;
		switch (tmp->type) {

			case LOG_SEPARATOR:
				if (!last_isspace) {
					LOGCHAR(' ');
					last_isspace = 1;
					*tmplog = '\0';
				}
				break;

			case LOG_TEXT: // text
				src = tmp->arg;
				tmplog += strlcpy2(tmplog, src, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_CLIENTIP:  // %Ci
				src = (s->req->prod->addr.from.ss_family == AF_UNIX) ? "unix" : pn;
				tmplog = logformat_write_string(tmplog, src, MAX_SYSLOG_LEN - (tmplog - logline), tmp);

				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_CLIENTPORT:  // %Cp
				tmplog = ltoa_o((s->req->prod->addr.from.ss_family == AF_UNIX) ? s->listener->luid : get_host_port(&s->req->prod->addr.from),
				                tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_SOURCEIP:  // Bi
				src = (s->req->cons->addr.from.ss_family == AF_UNIX) ? "unix" : sn;
				tmplog = logformat_write_string(tmplog, src, MAX_SYSLOG_LEN - (tmplog - logline), tmp);

				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_SOURCEPORT:  // %Bp
				tmplog = ltoa_o((s->req->cons->addr.from.ss_family == AF_UNIX) ? s->listener->luid : get_host_port(&s->req->cons->addr.from),
				                tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_DATE: // %t
				get_localtime(s->logs.accept_date.tv_sec, &tm);
				tmplog = date2str_log(tmplog, &tm, &(s->logs.accept_date), MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_DATEGMT: // %T
				get_gmtime(s->logs.accept_date.tv_sec, &tm);
				tmplog = gmt2str_log(tmplog, &tm, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_MS: // %ms
				if ((MAX_SYSLOG_LEN - (tmplog - logline)) < 4) {
					tmplog = NULL;
					goto out;
				}
				tmplog = utoa_pad((unsigned int)s->logs.accept_date.tv_usec/1000,
						  tmplog, 4);
				last_isspace = 0;

				break;

			case LOG_FRONTEND: // %f
				src = fe->id;
				tmplog = logformat_write_string(tmplog, src, MAX_SYSLOG_LEN - (tmplog - logline), tmp);
				if (!tmplog)
					goto out;
				last_isspace = 0 ;
				break;

			case LOG_BACKEND: // %b
				src = be->id;
				tmplog = logformat_write_string(tmplog, src, MAX_SYSLOG_LEN - (tmplog - logline), tmp);
				if (!tmplog)
					goto out;
				last_isspace = 0 ;
				break;

			case LOG_SERVER: // %s
				src = (char *)svid;
				tmplog = logformat_write_string(tmplog, src, MAX_SYSLOG_LEN - (tmplog - logline), tmp);
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_TQ: // %Tq
				tmplog = ltoa_o(t_request, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_TW: // %Tw
				tmplog = ltoa_o((s->logs.t_queue >= 0) ? s->logs.t_queue - t_request : -1, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_TC: // %Tc
				tmplog = ltoa_o((s->logs.t_connect >= 0) ? s->logs.t_connect - s->logs.t_queue : -1, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_TR: // %Tr
				tmplog = ltoa_o((s->logs.t_data >= 0) ? s->logs.t_data - s->logs.t_connect : -1, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_TT:  // %Tt
				if (!(tolog & LW_BYTES))
					*(tmplog++) = '+';
				tmplog = ltoa_o(s->logs.t_close, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_STATUS: // %st
				tmplog = ultoa_o(txn->status, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_BYTES: // %B
				if (!(tolog & LW_BYTES))
					*(tmplog++) = '+';
				tmplog = lltoa(s->logs.bytes_out, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_CCLIENT: // %cc
				src = txn->cli_cookie;
				tmplog = logformat_write_string(tmplog, src, MAX_SYSLOG_LEN - (tmplog - logline), tmp);
				last_isspace = 0;
				break;

			case LOG_CSERVER: // %cs
				src = txn->srv_cookie;
				tmplog = logformat_write_string(tmplog, src, MAX_SYSLOG_LEN - (tmplog - logline), tmp);
				last_isspace = 0;
				break;

			case LOG_TERMSTATE: // %ts

				LOGCHAR(sess_term_cond[(s->flags & SN_ERR_MASK) >> SN_ERR_SHIFT]);
				LOGCHAR(sess_fin_state[(s->flags & SN_FINST_MASK) >> SN_FINST_SHIFT]);
				if (fe->mode == PR_MODE_HTTP) {
					LOGCHAR((be->options & PR_O_COOK_ANY) ? sess_cookie[(txn->flags & TX_CK_MASK) >> TX_CK_SHIFT] : '-');
					LOGCHAR((be->options & PR_O_COOK_ANY) ? sess_set_cookie[(txn->flags & TX_SCK_MASK) >> TX_SCK_SHIFT] : '-');
				}
				*tmplog = '\0';
				last_isspace = 0;
				break;

			case LOG_ACTCONN: // %ac
				tmplog = ltoa_o(actconn, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_FECONN:  // %fc
				tmplog = ltoa_o(fe->feconn, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_BECONN:  // %bc
				tmplog = ltoa_o(be->beconn, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_SRVCONN:  // %sc
				tmplog = ultoa_o(target_srv(&s->target) ? target_srv(&s->target)->cur_sess : 0, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_RETRIES:  // %rq
				if (s->flags & SN_REDISP)
					*(tmplog++) = '+';
				tmplog = ltoa_o((s->req->cons->conn_retries>0)?(be->conn_retries - s->req->cons->conn_retries):be->conn_retries, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				last_isspace = 0;
				break;

			case LOG_SRVQUEUE: // %sq
				tmplog = ltoa_o(s->logs.srv_queue_size, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_BCKQUEUE:  // %bq
				tmplog = ltoa_o(s->logs.prx_queue_size, tmplog, MAX_SYSLOG_LEN - (tmplog - logline));
				if (!tmplog)
					goto out;
				last_isspace = 0;
				break;

			case LOG_HDRREQUEST: // %hr
				/* request header */
				if (fe->to_log & LW_REQHDR && txn->req.cap) {
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
					LOGCHAR('{');
					for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
						if (hdr)
							LOGCHAR('|');
						if (txn->req.cap[hdr] != NULL)
							tmplog = encode_string(tmplog, logline + MAX_SYSLOG_LEN,
									       '#', hdr_encode_map, txn->req.cap[hdr]);
					}
					LOGCHAR('}');
					last_isspace = 0;
				}
				*tmplog = '\0';
				break;

			case LOG_HDRREQUESTLIST: // %hrl
				/* request header list */
				if (fe->to_log & LW_REQHDR && txn->req.cap) {
					for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
						if (hdr > 0)
							LOGCHAR(' ');
						if (tmp->options & LOG_OPT_QUOTE)
							LOGCHAR('"');
						if (txn->req.cap[hdr] != NULL) {
							tmplog = encode_string(tmplog, logline + MAX_SYSLOG_LEN,
									       '#', hdr_encode_map, txn->req.cap[hdr]);
						} else if (!(tmp->options & LOG_OPT_QUOTE))
							LOGCHAR('-');
						if (tmp->options & LOG_OPT_QUOTE)
							LOGCHAR('"');
						*tmplog = '\0';
						last_isspace = 0;
					}
				}
				break;

			case LOG_HDRRESPONS: // %hs
				/* response header */
				if (fe->to_log & LW_RSPHDR &&
				    txn->rsp.cap) {
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
					LOGCHAR('{');
					for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
						if (hdr)
							LOGCHAR('|');
						if (txn->rsp.cap[hdr] != NULL)
							tmplog = encode_string(tmplog, logline + MAX_SYSLOG_LEN,
									       '#', hdr_encode_map, txn->rsp.cap[hdr]);
					}
					LOGCHAR('}');
					last_isspace = 0;
					if (tmp->options & LOG_OPT_QUOTE)
						LOGCHAR('"');
				}
				*tmplog = '\0';
				break;

			case LOG_HDRRESPONSLIST: // %hsl
				/* response header list */
				if (fe->to_log & LW_RSPHDR && txn->rsp.cap) {
					for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
						if (hdr > 0)
							LOGCHAR(' ');
						if (tmp->options & LOG_OPT_QUOTE)
							LOGCHAR('"');
						if (txn->rsp.cap[hdr] != NULL) {
							tmplog = encode_string(tmplog, logline + MAX_SYSLOG_LEN,
									       '#', hdr_encode_map, txn->rsp.cap[hdr]);
						} else if (!(tmp->options & LOG_OPT_QUOTE))
							LOGCHAR('-');
						if (tmp->options & LOG_OPT_QUOTE)
							LOGCHAR('"');
						*tmplog = '\0';
						last_isspace = 0;
					}
				}
				break;

			case LOG_REQ: // %r
				/* Request */
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');
				uri = txn->uri ? txn->uri : "<BADREQ>";
				tmplog = encode_string(tmplog, logline + MAX_SYSLOG_LEN,
						       '#', url_encode_map, uri);
				if (tmp->options & LOG_OPT_QUOTE)
					LOGCHAR('"');
				*tmplog = '\0';
				last_isspace = 0;
				break;
		}
	}

out:

	if (tmplog == NULL) // if previous error
		tmplog = logline + MAX_SYSLOG_LEN - 1;

	__send_log(prx_log, level, logline, tmplog - logline + 1);
	s->logs.logwait = 0;

}





/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
