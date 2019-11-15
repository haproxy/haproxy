/*
  include/types/log.h
  This file contains definitions of log-related structures and macros.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _TYPES_LOG_H
#define _TYPES_LOG_H

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <common/config.h>
#include <common/hathreads.h>
#include <common/mini-clist.h>
#include <types/ring.h>

#define NB_LOG_FACILITIES       24
#define NB_LOG_LEVELS           8
#define NB_MSG_IOVEC_ELEMENTS   8
#define SYSLOG_PORT             514
#define UNIQUEID_LEN            128

/* 64kB to archive startup-logs seems way more than enough */
#ifndef STARTUP_LOG_SIZE
#define STARTUP_LOG_SIZE        65536
#endif

/* The array containing the names of the log levels. */
extern const char *log_levels[];

/* enum for log format */
enum {
	LOG_FORMAT_RFC3164 = 0,
	LOG_FORMAT_RFC5424,
	LOG_FORMAT_SHORT,
	LOG_FORMAT_RAW,
	LOG_FORMATS,          /* number of supported log formats, must always be last */
};

/* log target types */
enum log_tgt {
	LOG_TARGET_DGRAM = 0, // datagram address (udp, unix socket)
	LOG_TARGET_FD,        // file descriptor
	LOG_TARGET_BUFFER,    // ring buffer
};

/* lists of fields that can be logged */
enum {

	LOG_FMT_TEXT = 0, /* raw text */
	LOG_FMT_EXPR,     /* sample expression */
	LOG_FMT_SEPARATOR, /* separator replaced by one space */

	/* information fields */
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
	LOG_FMT_HTTP_QUERY,
	LOG_FMT_HTTP_VERSION,
	LOG_FMT_HOSTNAME,
	LOG_FMT_UNIQUEID,
	LOG_FMT_SSL_CIPHER,
	LOG_FMT_SSL_VERSION,
};

/* enum for parse_logformat_string */
enum {
	LF_INIT = 0,   // before first character
	LF_TEXT,       // normal text
	LF_SEPARATOR,  // a single separator
	LF_VAR,        // variable name, after '%' or '%{..}'
	LF_STARTVAR,   // % in text
	LF_STARG,      // after '%{' and berore '}'
	LF_EDARG,      // '}' after '%{'
	LF_STEXPR,     // after '%[' or '%{..}[' and berore ']'
	LF_EDEXPR,     // ']' after '%['
	LF_END,        // \0 found
};


struct logformat_node {
	struct list list;
	int type;      // LOG_FMT_*
	int options;   // LOG_OPT_*
	char *arg;     // text for LOG_FMT_TEXT, arg for others
	void *expr;    // for use with LOG_FMT_EXPR
};

#define LOG_OPT_HEXA		0x00000001
#define LOG_OPT_MANDATORY	0x00000002
#define LOG_OPT_QUOTE		0x00000004
#define LOG_OPT_REQ_CAP         0x00000008
#define LOG_OPT_RES_CAP         0x00000010
#define LOG_OPT_HTTP            0x00000020
#define LOG_OPT_ESC             0x00000040


/* Fields that need to be extracted from the incoming connection or request for
 * logging or for sending specific header information. They're set in px->to_log
 * and appear as flags in session->logs.logwait, which are removed once the
 * required information has been collected.
 */
#define LW_INIT		1	/* anything */
#define LW_CLIP		2	/* CLient IP */
#define LW_SVIP		4	/* SerVer IP */
#define LW_SVID		8	/* server ID */
#define	LW_REQ		16	/* http REQuest */
#define LW_RESP		32	/* http RESPonse */
#define LW_BYTES	256	/* bytes read from server */
#define LW_COOKIE	512	/* captured cookie */
#define LW_REQHDR	1024	/* request header(s) */
#define LW_RSPHDR	2048	/* response header(s) */
#define LW_BCKIP	4096	/* backend IP */
#define LW_FRTIP 	8192	/* frontend IP */
#define LW_XPRT		16384	/* transport layer information (eg: SSL) */

/* Range of indexes for log sampling. */
struct smp_log_range {
	unsigned int low;        /* Low limit of the indexes of this range. */
	unsigned int high;       /* High limit of the indexes of this range. */
	size_t sz;               /* The size of this range, or number of indexes in
	                          * this range.
	                          */
	unsigned int curr_idx;   /* The current index used to sample this range of
	                          *indexes.
	                          */
};

/* Log sampling information. */
struct smp_info {
	struct smp_log_range *smp_rgs; /* Array of ranges for log sampling. */
	size_t smp_rgs_sz;             /* The size of <smp_rgs> array. */
	size_t smp_sz;             /* The total number of logs to be sampled. */
	unsigned int curr_rg;      /* The current range to be sampled. */
	unsigned int curr_idx;     /* A counter to store the current index of the log
	                            * already sampled.
	                            */
};

struct logsrv {
	struct list list;
	struct sockaddr_storage addr;
	struct smp_info lb;
	struct ring *ring;
	enum log_tgt type;
	int format;
	int facility;
	int level;
	int minlvl;
	int maxlen;
	struct logsrv *ref;
	__decl_hathreads(HA_SPINLOCK_T lock);
};

#endif /* _TYPES_LOG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
