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
};

/* log_format variable names */
static const struct logformat_type logformat_keywords[] = {
	{ "o", LOG_GLOBAL },  /* global option */
	{ "Ci", LOG_CLIENTIP },  /* client ip */
	{ "Cp", LOG_CLIENTPORT }, /* client port */
	{ "t", LOG_DATE },      /* date */
	{ "T", LOG_DATEGMT },   /* date GMT */
	{ "ms", LOG_MS },       /* accept date millisecond */
	{ "f", LOG_FRONTEND },  /* frontend */
	{ "b", LOG_BACKEND },   /* backend */
	{ "s", LOG_SERVER },    /* server */
	{ "B", LOG_BYTES },     /* bytes read */
	{ "Tq", LOG_TQ },       /* Tq */
	{ "Tw", LOG_TW },       /* Tw */
	{ "Tc", LOG_TC },       /* Tc */
	{ "Tr", LOG_TR },       /* Tr */
	{ "Tt", LOG_TT },       /* Tt */
	{ "st", LOG_STATUS },   /* status code */
	{ "cc", LOG_CCLIENT },  /* client cookie */
	{ "cs", LOG_CSERVER },  /* server cookie */
	{ "ts", LOG_TERMSTATE },/* terminaison state */
	{ "ac", LOG_ACTCONN },  /* actconn */
	{ "fc", LOG_FECONN },   /* feconn */
	{ "bc", LOG_BECONN },   /* beconn */
	{ "sc", LOG_SRVCONN },  /* srv_conn */
	{ "rc", LOG_RETRIES },  /* retries */
	{ "sq", LOG_SRVQUEUE }, /* srv_queue */
	{ "bq", LOG_BCKQUEUE }, /* backend_queue */
	{ "hr", LOG_HDRREQUEST }, /* header request */
	{ "hs", LOG_HDRRESPONS },  /* header response */
	{ "hrl", LOG_HDRREQUESTLIST }, /* header request list */
	{ "hsl", LOG_HDRRESPONSLIST },  /* header response list */
	{ "r", LOG_REQ },  /* request */
	{ 0, 0 }
};

char default_http_log_format[] = "%Ci:%Cp [%t] %f %b/%s %Tq/%Tw/%Tc/%Tr/%Tt %st %B %cc %cs %ts %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"; // default format
char clf_http_log_format[] = "%{+Q}o %{-Q}Ci - - [%T] %r %st %B \"\" \"\" %Cp %ms %f %b %s %Tq %Tw %Tc %Tr %Tt %ts %ac %fc %bc %sc %rc %sq %bq %cc %cs %hrl %hsl";
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
					node = calloc(1, sizeof(struct logformat_node));
					node->type = logformat_keywords[j].type;
					node->options = logformat_options;
					node->arg = arg;
					parse_logformat_var_args(node->arg, node);
					if (node->type == LOG_GLOBAL) {
						logformat_options = node->options;
						free(node);
					} else {
						LIST_ADDQ(&curproxy->logformat, &node->list);
					}
					return 0;
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


/*
 * send a log for the session when we have enough info about it
 */
void tcp_sess_log(struct session *s)
{
	char pn[INET6_ADDRSTRLEN];
	struct proxy *fe = s->fe;
	struct proxy *be = s->be;
	struct proxy *prx_log;
	int tolog, level, err;
	char *svid;
	struct tm tm;

	/* if we don't want to log normal traffic, return now */
	err = (s->flags & (SN_ERR_MASK | SN_REDISP)) || (s->req->cons->conn_retries != be->conn_retries);
	if (!err && (fe->options2 & PR_O2_NOLOGNORM))
		return;

	addr_to_str(&s->si[0].addr.from, pn, sizeof(pn));
	get_localtime(s->logs.tv_accept.tv_sec, &tm);

	if(LIST_ISEMPTY(&fe->logsrvs))
		return;

	prx_log = fe;
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

	level = LOG_INFO;
	if (err && (fe->options2 & PR_O2_LOGERRORS))
		level = LOG_ERR;

	send_log(prx_log, level, "%s:%d [%02d/%s/%04d:%02d:%02d:%02d.%03d]"
		 " %s %s/%s %ld/%ld/%s%ld %s%lld"
		 " %c%c %d/%d/%d/%d/%s%u %ld/%ld\n",
		 s->si[0].addr.from.ss_family == AF_UNIX ? "unix" : pn,
		 s->si[0].addr.from.ss_family == AF_UNIX ? s->listener->luid : get_host_port(&s->si[0].addr.from),
		 tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
		 tm.tm_hour, tm.tm_min, tm.tm_sec, (int)s->logs.tv_accept.tv_usec/1000,
		 fe->id, be->id, svid,
		 (s->logs.t_queue >= 0) ? s->logs.t_queue : -1,
		 (s->logs.t_connect >= 0) ? s->logs.t_connect - s->logs.t_queue : -1,
		 (tolog & LW_BYTES) ? "" : "+", s->logs.t_close,
		 (tolog & LW_BYTES) ? "" : "+", s->logs.bytes_out,
		 sess_term_cond[(s->flags & SN_ERR_MASK) >> SN_ERR_SHIFT],
		 sess_fin_state[(s->flags & SN_FINST_MASK) >> SN_FINST_SHIFT],
		 actconn, fe->feconn, be->beconn, target_srv(&s->target) ? target_srv(&s->target)->cur_sess : 0,
		 (s->flags & SN_REDISP)?"+":"",
		 (s->req->cons->conn_retries>0)?(be->conn_retries - s->req->cons->conn_retries):be->conn_retries,
		 s->logs.srv_queue_size, s->logs.prx_queue_size);

	s->logs.logwait = 0;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
