/*
 * General logging functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/time.h>

#include <common/config.h>
#include <common/standard.h>
#include <common/time.h>

#include <types/backend.h>
#include <types/global.h>
#include <types/log.h>
#include <types/proto_http.h>
#include <types/proxy.h>
#include <types/session.h>


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
const char sess_cookie[4]     = "NIDV";		/* No cookie, Invalid cookie, cookie for a Down server, Valid cookie */
const char sess_set_cookie[8] = "N1I3PD5R";	/* No set-cookie, unknown, Set-Cookie Inserted, unknown,
					    	   Set-cookie seen and left unchanged (passive), Set-cookie Deleted,
						   unknown, Set-cookie Rewritten */
void **pool_requri = NULL;


/*
 * Displays the message on stderr with the date and pid. Overrides the quiet
 * mode during startup.
 */
void Alert(const char *fmt, ...)
{
	va_list argp;
	struct tm *tm;

	if (!(global.mode & MODE_QUIET) || (global.mode & (MODE_VERBOSE | MODE_STARTING))) {
		va_start(argp, fmt);

		tm = localtime((time_t *)&now.tv_sec);
		fprintf(stderr, "[ALERT] %03d/%02d%02d%02d (%d) : ",
			tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)getpid());
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
	struct tm *tm;

	if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) {
		va_start(argp, fmt);

		tm = localtime((time_t *)&now.tv_sec);
		fprintf(stderr, "[WARNING] %03d/%02d%02d%02d (%d) : ",
			tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)getpid());
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


#define FD_SETS_ARE_BITFIELDS
#ifdef FD_SETS_ARE_BITFIELDS
/*
 * This map is used with all the FD_* macros to check whether a particular bit
 * is set or not. Each bit represents an ACSII code. FD_SET() sets those bytes
 * which should be encoded. When FD_ISSET() returns non-zero, it means that the
 * byte should be encoded. Be careful to always pass bytes from 0 to 255
 * exclusively to the macros.
 */
fd_set hdr_encode_map[(sizeof(fd_set) > (256/8)) ? 1 : ((256/8) / sizeof(fd_set))];
fd_set url_encode_map[(sizeof(fd_set) > (256/8)) ? 1 : ((256/8) / sizeof(fd_set))];

#else
#error "Check if your OS uses bitfields for fd_sets"
#endif

/*
 * This function sends a syslog message to both log servers of a proxy,
 * or to global log servers if the proxy is NULL.
 * It also tries not to waste too much time computing the message header.
 * It doesn't care about errors nor does it report them.
 */
void send_log(struct proxy *p, int level, const char *message, ...)
{
	static int logfd = -1;	/* syslog UDP socket */
	static long tvsec = -1;	/* to force the string to be initialized */
	va_list argp;
	static char logmsg[MAX_SYSLOG_LEN];
	static char *dataptr = NULL;
	int fac_level;
	int hdr_len, data_len;
	struct sockaddr_in *sa[2];
	int facilities[2], loglevel[2];
	int nbloggers = 0;
	char *log_ptr;

	if (logfd < 0) {
		if ((logfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
			return;
	}
    
	if (level < 0 || progname == NULL || message == NULL)
		return;

	if (now.tv_sec != tvsec || dataptr == NULL) {
		/* this string is rebuild only once a second */
		struct tm *tm = localtime((time_t *)&now.tv_sec);
		tvsec = now.tv_sec;

		hdr_len = snprintf(logmsg, sizeof(logmsg),
				   "<<<<>%s %2d %02d:%02d:%02d %s[%d]: ",
				   monthname[tm->tm_mon],
				   tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec,
				   progname, pid);
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
			sa[nbloggers] = &global.logsrv1;
			facilities[nbloggers] = global.logfac1;
			loglevel[nbloggers] = global.loglev1;
			nbloggers++;
		}
		if (global.logfac2 >= 0) {
			sa[nbloggers] = &global.logsrv2;
			facilities[nbloggers] = global.logfac2;
			loglevel[nbloggers] = global.loglev2;
			nbloggers++;
		}
	} else {
		if (p->logfac1 >= 0) {
			sa[nbloggers] = &p->logsrv1;
			facilities[nbloggers] = p->logfac1;
			loglevel[nbloggers] = p->loglev1;
			nbloggers++;
		}
		if (p->logfac2 >= 0) {
			sa[nbloggers] = &p->logsrv2;
			facilities[nbloggers] = p->logfac2;
			loglevel[nbloggers] = p->loglev2;
			nbloggers++;
		}
	}

	while (nbloggers-- > 0) {
		/* we can filter the level of the messages that are sent to each logger */
		if (level > loglevel[nbloggers])
			continue;
	
		/* For each target, we may have a different facility.
		 * We can also have a different log level for each message.
		 * This induces variations in the message header length.
		 * Since we don't want to recompute it each time, nor copy it every
		 * time, we only change the facility in the pre-computed header,
		 * and we change the pointer to the header accordingly.
		 */
		fac_level = (facilities[nbloggers] << 3) + level;
		log_ptr = logmsg + 3; /* last digit of the log level */
		do {
			*log_ptr = '0' + fac_level % 10;
			fac_level /= 10;
			log_ptr--;
		} while (fac_level && log_ptr > logmsg);
		*log_ptr = '<';
	
		/* the total syslog message now starts at logptr, for dataptr+data_len-logptr */

#ifndef MSG_NOSIGNAL
		sendto(logfd, log_ptr, dataptr + data_len - log_ptr, MSG_DONTWAIT,
		       (struct sockaddr *)sa[nbloggers], sizeof(**sa));
#else
		sendto(logfd, log_ptr, dataptr + data_len - log_ptr, MSG_DONTWAIT | MSG_NOSIGNAL,
		       (struct sockaddr *)sa[nbloggers], sizeof(**sa));
#endif
	}
}


/*
 * send a log for the session when we have enough info about it
 */
void sess_log(struct session *s)
{
	char pn[INET6_ADDRSTRLEN + strlen(":65535")];
	struct proxy *fe = s->fe;
	struct proxy *be = s->be;
	struct proxy *prx_log;
	struct http_req *hreq = &s->hreq;
	int log, tolog;
	char *uri;
	char *pxid;
	char *srv;
	struct tm *tm;

	/* This is a first attempt at a better logging system.
	 * For now, we rely on send_log() to provide the date, although it obviously
	 * is the date of the log and not of the request, and most fields are not
	 * computed.
	 */

	/* FIXME: let's limit ourselves to frontend logging for now. */
	tolog = (fe->to_log /*| be->to_log | be->beprm->to_log*/);

	log = tolog & ~s->logs.logwait;

	if (s->cli_addr.ss_family == AF_INET)
		inet_ntop(AF_INET,
			  (const void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
			  pn, sizeof(pn));
	else
		inet_ntop(AF_INET6,
			  (const void *)&((struct sockaddr_in6 *)(&s->cli_addr))->sin6_addr,
			  pn, sizeof(pn));

	uri = (log & LW_REQ) ? s->logs.uri ? s->logs.uri : "<BADREQ>" : "";
	pxid = be->beprm->id;
	srv = (tolog & LW_SVID) ?
		(s->data_source != DATA_SRC_STATS) ?
		(s->srv != NULL) ? s->srv->id : "<NOSRV>" : "<STATS>" : "-";

	tm = localtime((time_t *)&s->logs.tv_accept.tv_sec);

	if (fe->logfac1 >= 0)
		prx_log = fe;
	/*
	 * FIXME: should we fall back to the backend if the frontend did not
	 * define any log ? It seems like we should not permit such complex
	 * setups because they would induce a debugging nightmare for the
	 * admin.
	 */
	// else if (be->logfac1 >= 0)
	// prx_log = be;
	else
		prx_log = NULL; /* global */

	if (tolog & LW_REQ) {
		char tmpline[MAX_SYSLOG_LEN], *h;
		int hdr;
	
		h = tmpline;

		/* right now, header capture is limited to the frontend only */
		if (fe->to_log & LW_REQHDR &&
		    hreq->req.cap &&
		    (h < tmpline + sizeof(tmpline) - 10)) {
			*(h++) = ' ';
			*(h++) = '{';
			for (hdr = 0; hdr < fe->nb_req_cap; hdr++) {
				if (hdr)
					*(h++) = '|';
				if (hreq->req.cap[hdr] != NULL)
					h = encode_string(h, tmpline + sizeof(tmpline) - 7,
							  '#', hdr_encode_map, hreq->req.cap[hdr]);
			}
			*(h++) = '}';
		}

		if (fe->to_log & LW_RSPHDR &&
		    hreq->rsp.cap &&
		    (h < tmpline + sizeof(tmpline) - 7)) {
			*(h++) = ' ';
			*(h++) = '{';
			for (hdr = 0; hdr < fe->nb_rsp_cap; hdr++) {
				if (hdr)
					*(h++) = '|';
				if (hreq->rsp.cap[hdr] != NULL)
					h = encode_string(h, tmpline + sizeof(tmpline) - 4,
							  '#', hdr_encode_map, hreq->rsp.cap[hdr]);
			}
			*(h++) = '}';
		}

		if (h < tmpline + sizeof(tmpline) - 4) {
			*(h++) = ' ';
			*(h++) = '"';
			h = encode_string(h, tmpline + sizeof(tmpline) - 1,
					  '#', url_encode_map, uri);
			*(h++) = '"';
		}
		*h = '\0';

		send_log(prx_log, LOG_INFO,
			 "%s:%d [%02d/%s/%04d:%02d:%02d:%02d.%03d]"
			 " %s %s/%s %d/%d/%d/%d/%s%d %d %s%lld"
			 " %s %s %c%c%c%c %d/%d/%d/%d %d/%d%s\n",
			 pn,
			 (s->cli_addr.ss_family == AF_INET) ?
			 ntohs(((struct sockaddr_in *)&s->cli_addr)->sin_port) :
			 ntohs(((struct sockaddr_in6 *)&s->cli_addr)->sin6_port),
			 tm->tm_mday, monthname[tm->tm_mon], tm->tm_year+1900,
			 tm->tm_hour, tm->tm_min, tm->tm_sec, s->logs.tv_accept.tv_usec/1000,
			 fe->id, pxid, srv,
			 s->logs.t_request,
			 (s->logs.t_queue >= 0) ? s->logs.t_queue - s->logs.t_request : -1,
			 (s->logs.t_connect >= 0) ? s->logs.t_connect - s->logs.t_queue : -1,
			 (s->logs.t_data >= 0) ? s->logs.t_data - s->logs.t_connect : -1,
			 (tolog & LW_BYTES) ? "" : "+", s->logs.t_close,
			 s->logs.status,
			 (tolog & LW_BYTES) ? "" : "+", s->logs.bytes_in,
			 s->logs.cli_cookie ? s->logs.cli_cookie : "-",
			 s->logs.srv_cookie ? s->logs.srv_cookie : "-",
			 sess_term_cond[(s->flags & SN_ERR_MASK) >> SN_ERR_SHIFT],
			 sess_fin_state[(s->flags & SN_FINST_MASK) >> SN_FINST_SHIFT],
			 (be->beprm->options & PR_O_COOK_ANY) ? sess_cookie[(s->flags & SN_CK_MASK) >> SN_CK_SHIFT] : '-',
			 (be->beprm->options & PR_O_COOK_ANY) ? sess_set_cookie[(s->flags & SN_SCK_MASK) >> SN_SCK_SHIFT] : '-',
			 actconn, fe->feconn, be->beprm->beconn, s->srv ? s->srv->cur_sess : 0,
			 s->logs.srv_queue_size, s->logs.prx_queue_size, tmpline);
	}
	else {
		send_log(prx_log, LOG_INFO, "%s:%d [%02d/%s/%04d:%02d:%02d:%02d.%03d]"
			 " %s %s/%s %d/%d/%s%d %s%lld"
			 " %c%c %d/%d/%d/%d %d/%d\n",
			 pn,
			 (s->cli_addr.ss_family == AF_INET) ?
			 ntohs(((struct sockaddr_in *)&s->cli_addr)->sin_port) :
			 ntohs(((struct sockaddr_in6 *)&s->cli_addr)->sin6_port),
			 tm->tm_mday, monthname[tm->tm_mon], tm->tm_year+1900,
			 tm->tm_hour, tm->tm_min, tm->tm_sec, s->logs.tv_accept.tv_usec/1000,
			 fe->id, pxid, srv,
			 (s->logs.t_queue >= 0) ? s->logs.t_queue : -1,
			 (s->logs.t_connect >= 0) ? s->logs.t_connect - s->logs.t_queue : -1,
			 (tolog & LW_BYTES) ? "" : "+", s->logs.t_close,
			 (tolog & LW_BYTES) ? "" : "+", s->logs.bytes_in,
			 sess_term_cond[(s->flags & SN_ERR_MASK) >> SN_ERR_SHIFT],
			 sess_fin_state[(s->flags & SN_FINST_MASK) >> SN_FINST_SHIFT],
			 actconn, fe->feconn, be->beprm->beconn, s->srv ? s->srv->cur_sess : 0,
			 s->logs.srv_queue_size, s->logs.prx_queue_size);
	}

	s->logs.logwait = 0;
}


/*
 * Initializes some data needed later.
 */
void init_log()
{
	int i;
	char *tmp;

	/* initialize the log header encoding map : '{|}"#' should be encoded with
	 * '#' as prefix, as well as non-printable characters ( <32 or >= 127 ).
	 * URL encoding only requires '"', '#' to be encoded as well as non-
	 * printable characters above.
	 */
	memset(hdr_encode_map, 0, sizeof(hdr_encode_map));
	memset(url_encode_map, 0, sizeof(url_encode_map));
	for (i = 0; i < 32; i++) {
		FD_SET(i, hdr_encode_map);
		FD_SET(i, url_encode_map);
	}
	for (i = 127; i < 256; i++) {
		FD_SET(i, hdr_encode_map);
		FD_SET(i, url_encode_map);
	}

	tmp = "\"#{|}";
	while (*tmp) {
		FD_SET(*tmp, hdr_encode_map);
		tmp++;
	}

	tmp = "\"#";
	while (*tmp) {
		FD_SET(*tmp, url_encode_map);
		tmp++;
	}
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
