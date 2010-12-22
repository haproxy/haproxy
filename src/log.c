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

#include <proto/log.h>

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

const char *monthname[12] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

const char sess_term_cond[8]  = "-cCsSPRI";	/* normal, CliTo, CliErr, SrvTo, SrvErr, PxErr, Resource, Internal */
const char sess_fin_state[8]  = "-RCHDLQT";	/* cliRequest, srvConnect, srvHeader, Data, Last, Queue, Tarpit */

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
 * Return the length of the address endpoint, suitable for use with sendto().
 */
static inline int logsrv_addrlen(const struct logsrv *logsrv)
{
	switch (logsrv->u.addr.sa_family) {
	case AF_UNIX:
		return sizeof(logsrv->u.un);
	case AF_INET:
		return sizeof(logsrv->u.in);
	default:
		break;
	}
	return -1;
}

/*
 * This function sends a syslog message to both log servers of a proxy,
 * or to global log servers if the proxy is NULL.
 * It also tries not to waste too much time computing the message header.
 * It doesn't care about errors nor does it report them.
 */
void send_log(struct proxy *p, int level, const char *message, ...)
{
	static int logfdunix = -1;	/* syslog to AF_UNIX socket */
	static int logfdinet = -1;	/* syslog to AF_INET socket */
	static long tvsec = -1;	/* to force the string to be initialized */
	va_list argp;
	static char logmsg[MAX_SYSLOG_LEN];
	static char *dataptr = NULL;
	int fac_level;
	int hdr_len, data_len;
	struct logsrv *logsrvs[2];
	int facilities[2], loglevel[2], minlvl[2];
	int nblogger;
	int nbloggers = 0;
	char *log_ptr;

	if (level < 0 || message == NULL)
		return;

	if (unlikely(date.tv_sec != tvsec || dataptr == NULL)) {
		/* this string is rebuild only once a second */
		struct tm tm;

		tvsec = date.tv_sec;
		get_localtime(tvsec, &tm);

		hdr_len = snprintf(logmsg, sizeof(logmsg),
				   "<<<<>%s %2d %02d:%02d:%02d %s%s[%d]: ",
				   monthname[tm.tm_mon],
				   tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
				   global.log_send_hostname ? global.log_send_hostname : "",
				   global.log_tag, pid);
		/* WARNING: depending upon implementations, snprintf may return
		 * either -1 or the number of bytes that would be needed to store
		 * the total message. In both cases, we must adjust it.
		 */
		if (hdr_len < 0 || hdr_len > sizeof(logmsg))
			hdr_len = sizeof(logmsg);

		dataptr = logmsg + hdr_len;
	}

	va_start(argp, message);
	/*
	 * FIXME: we take a huge performance hit here. We might have to replace
	 * vsnprintf() for a hard-coded log writer.
	 */
	data_len = vsnprintf(dataptr, logmsg + sizeof(logmsg) - dataptr, message, argp);
	if (data_len < 0 || data_len > (logmsg + sizeof(logmsg) - dataptr))
		data_len = logmsg + sizeof(logmsg) - dataptr;
	va_end(argp);
	dataptr[data_len - 1] = '\n'; /* force a break on ultra-long lines */

	if (p == NULL) {
		if (global.logfac1 >= 0) {
			logsrvs[nbloggers] = &global.logsrv1;
			facilities[nbloggers] = global.logfac1;
			loglevel[nbloggers] = global.loglev1;
			minlvl[nbloggers] = global.minlvl1;
			nbloggers++;
		}
		if (global.logfac2 >= 0) {
			logsrvs[nbloggers] = &global.logsrv2;
			facilities[nbloggers] = global.logfac2;
			loglevel[nbloggers] = global.loglev2;
			minlvl[nbloggers] = global.minlvl2;
			nbloggers++;
		}
	} else {
		if (p->logfac1 >= 0) {
			logsrvs[nbloggers] = &p->logsrv1;
			facilities[nbloggers] = p->logfac1;
			loglevel[nbloggers] = p->loglev1;
			minlvl[nbloggers] = p->minlvl1;
			nbloggers++;
		}
		if (p->logfac2 >= 0) {
			logsrvs[nbloggers] = &p->logsrv2;
			facilities[nbloggers] = p->logfac2;
			loglevel[nbloggers] = p->loglev2;
			minlvl[nbloggers] = p->minlvl2;
			nbloggers++;
		}
	}

	/* Lazily set up syslog sockets for protocol families of configured
	 * syslog servers. */
	for (nblogger = 0; nblogger < nbloggers; nblogger++) {
		const struct logsrv *logsrv = logsrvs[nblogger];
		int proto, *plogfd;
		if (logsrv->u.addr.sa_family == AF_UNIX) {
			proto = 0;
			plogfd = &logfdunix;
		} else {
			/* sa_family == AF_INET */
			proto = IPPROTO_UDP;
			plogfd = &logfdinet;
		}
		if (*plogfd >= 0) {
			/* socket already created. */
			continue;
		}
		if ((*plogfd = socket(logsrv->u.addr.sa_family, SOCK_DGRAM,
				proto)) < 0) {
			Alert("socket for logger #%d failed: %s (errno=%d)\n",
				nblogger + 1, strerror(errno), errno);
			return;
		}
		/* we don't want to receive anything on this socket */
		setsockopt(*plogfd, SOL_SOCKET, SO_RCVBUF, &zero, sizeof(zero));
		/* does nothing under Linux, maybe needed for others */
		shutdown(*plogfd, SHUT_RD);
	}

	/* Send log messages to syslog server. */
	for (nblogger = 0; nblogger < nbloggers; nblogger++) {
		const struct logsrv *logsrv = logsrvs[nblogger];
		int *plogfd = logsrv->u.addr.sa_family == AF_UNIX ?
			&logfdunix : &logfdinet;
		int sent;

		/* we can filter the level of the messages that are sent to each logger */
		if (level > loglevel[nblogger])
			continue;
	
		/* For each target, we may have a different facility.
		 * We can also have a different log level for each message.
		 * This induces variations in the message header length.
		 * Since we don't want to recompute it each time, nor copy it every
		 * time, we only change the facility in the pre-computed header,
		 * and we change the pointer to the header accordingly.
		 */
		fac_level = (facilities[nblogger] << 3) + MAX(level, minlvl[nblogger]);
		log_ptr = logmsg + 3; /* last digit of the log level */
		do {
			*log_ptr = '0' + fac_level % 10;
			fac_level /= 10;
			log_ptr--;
		} while (fac_level && log_ptr > logmsg);
		*log_ptr = '<';
	
		/* the total syslog message now starts at logptr, for dataptr+data_len-logptr */
		sent = sendto(*plogfd, log_ptr, dataptr + data_len - log_ptr,
			MSG_DONTWAIT | MSG_NOSIGNAL, &logsrv->u.addr, logsrv_addrlen(logsrv));
		if (sent < 0) {
			Alert("sendto logger #%d failed: %s (errno=%d)\n",
				nblogger, strerror(errno), errno);
		}
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

	if (s->cli_addr.ss_family == AF_INET)
		inet_ntop(AF_INET,
			  (const void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
			  pn, sizeof(pn));
	else if (s->cli_addr.ss_family == AF_INET6)
		inet_ntop(AF_INET6,
			  (const void *)&((struct sockaddr_in6 *)(&s->cli_addr))->sin6_addr,
			  pn, sizeof(pn));

	get_localtime(s->logs.tv_accept.tv_sec, &tm);

	if (fe->logfac1 < 0 && fe->logfac2 < 0)
		return;

	prx_log = fe;
	tolog = fe->to_log;
	svid = (tolog & LW_SVID) ? (s->srv != NULL) ? s->srv->id : "<NOSRV>" : "-";

	level = LOG_INFO;
	if (err && (fe->options2 & PR_O2_LOGERRORS))
		level = LOG_ERR;

	send_log(prx_log, level, "%s:%d [%02d/%s/%04d:%02d:%02d:%02d.%03d]"
		 " %s %s/%s %ld/%ld/%s%ld %s%lld"
		 " %c%c %d/%d/%d/%d/%s%u %ld/%ld\n",
		 s->cli_addr.ss_family == AF_UNIX ? "unix" : pn,
		 s->cli_addr.ss_family == AF_UNIX ? s->listener->luid : (ntohs((s->cli_addr.ss_family == AF_INET) ?
		                                            ((struct sockaddr_in *)&s->cli_addr)->sin_port :
		                                            ((struct sockaddr_in6 *)&s->cli_addr)->sin6_port)),
		 tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
		 tm.tm_hour, tm.tm_min, tm.tm_sec, (int)s->logs.tv_accept.tv_usec/1000,
		 fe->id, be->id, svid,
		 (s->logs.t_queue >= 0) ? s->logs.t_queue : -1,
		 (s->logs.t_connect >= 0) ? s->logs.t_connect - s->logs.t_queue : -1,
		 (tolog & LW_BYTES) ? "" : "+", s->logs.t_close,
		 (tolog & LW_BYTES) ? "" : "+", s->logs.bytes_out,
		 sess_term_cond[(s->flags & SN_ERR_MASK) >> SN_ERR_SHIFT],
		 sess_fin_state[(s->flags & SN_FINST_MASK) >> SN_FINST_SHIFT],
		 actconn, fe->feconn, be->beconn, s->srv ? s->srv->cur_sess : 0,
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
