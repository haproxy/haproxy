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

#define MAX_SYSLOG_LEN          1024
#define NB_LOG_FACILITIES       24
#define NB_LOG_LEVELS           8
#define SYSLOG_PORT             514

/* lists of fields that can be logged */
enum {

	LOG_TEXT = 0, /* raw text */

	LOG_SEPARATOR, /* separator replaced by one space */
	LOG_VARIABLE,

	/* information fields */
	LOG_GLOBAL,
	LOG_CLIENTIP,
	LOG_CLIENTPORT,
	LOG_DATE,
	LOG_DATEGMT,
	LOG_MS,
	LOG_FRONTEND,
	LOG_BACKEND,
	LOG_SERVER,
	LOG_BYTES,
	LOG_T,
	LOG_TQ,
	LOG_TW,
	LOG_TC,
	LOG_TR,
	LOG_TT,
	LOG_STATUS,
	LOG_CCLIENT,
	LOG_CSERVER,
	LOG_TERMSTATE,
	LOG_CONN,
	LOG_ACTCONN,
	LOG_FECONN,
	LOG_BECONN,
	LOG_SRVCONN,
	LOG_RETRIES,
	LOG_QUEUES,
	LOG_SRVQUEUE,
	LOG_BCKQUEUE,
	LOG_HDRREQUEST,
	LOG_HDRRESPONS,
	LOG_HDRREQUESTLIST,
	LOG_HDRRESPONSLIST,
	LOG_REQ,
};

/* enum for parse_logformat */
enum {
	LF_TEXT = 0,
	LF_SEPARATOR,
	LF_VAR, // after %

	LF_STARTVAR,   // %
	LF_STARG, // { and within { }
	LF_EDARG, // end arg }
};


struct logformat_node {
	struct list list;
	int type;
	int options;
	char *arg;
};

#define LOG_OPT_WRITTEN 	0x00000001
#define LOG_OPT_MANDATORY	0x00000002
#define LOG_OPT_QUOTE		0x00000004



/* fields that need to be logged. They appear as flags in session->logs.logwait */
#define LW_DATE		1	/* date */
#define LW_CLIP		2	/* CLient IP */
#define LW_SVIP		4	/* SerVer IP */
#define LW_SVID		8	/* server ID */
#define	LW_REQ		16	/* http REQuest */
#define LW_RESP		32	/* http RESPonse */
#define LW_PXIP		64	/* proxy IP */
#define LW_PXID		128	/* proxy ID */
#define LW_BYTES	256	/* bytes read from server */
#define LW_COOKIE	512	/* captured cookie */
#define LW_REQHDR	1024	/* request header(s) */
#define LW_RSPHDR	2048	/* response header(s) */

struct logsrv {
	struct list list;
	struct sockaddr_storage addr;
	int facility;
	int level;
	int minlvl;
};

#endif /* _TYPES_LOG_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
