/*
 * Health-checks.
 *
 * Copyright 2008-2009 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _TYPES_CHECKS_H
#define _TYPES_CHECKS_H

#include <sys/time.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <common/regex.h>

#include <types/connection.h>
#include <types/obj_type.h>
#include <types/task.h>
#include <types/server.h>

/* enum used by check->result. Must remain in this order, as some code uses
 * result >= CHK_RES_PASSED to declare success.
 */
enum chk_result {
	CHK_RES_UNKNOWN = 0,            /* initialized to this by default */
	CHK_RES_NEUTRAL,                /* valid check but no status information */
	CHK_RES_FAILED,                 /* check failed */
	CHK_RES_PASSED,                 /* check succeeded and server is fully up again */
	CHK_RES_CONDPASS,               /* check reports the server doesn't want new sessions */
};

/* flags used by check->state */
#define CHK_ST_INPROGRESS       0x0001  /* a check is currently running */
#define CHK_ST_CONFIGURED       0x0002  /* this check is configured and may be enabled */
#define CHK_ST_ENABLED          0x0004  /* this check is currently administratively enabled */
#define CHK_ST_PAUSED           0x0008  /* checks are paused because of maintenance (health only) */
#define CHK_ST_AGENT            0x0010  /* check is an agent check (otherwise it's a health check) */

/* check status */
enum {
	HCHK_STATUS_UNKNOWN	 = 0,	/* Unknown */
	HCHK_STATUS_INI,		/* Initializing */
	HCHK_STATUS_START,		/* Check started - SPECIAL STATUS */

	/* Below we have finished checks */
	HCHK_STATUS_CHECKED,		/* DUMMY STATUS */

	HCHK_STATUS_HANA,		/* Health analyze detected enough consecutive errors */

	HCHK_STATUS_SOCKERR,		/* Socket error */

	HCHK_STATUS_L4OK,		/* L4 check passed, for example tcp connect */
	HCHK_STATUS_L4TOUT,		/* L4 timeout */
	HCHK_STATUS_L4CON,		/* L4 connection problem, for example: */
					/*  "Connection refused" (tcp rst) or "No route to host" (icmp) */

	HCHK_STATUS_L6OK,		/* L6 check passed */
	HCHK_STATUS_L6TOUT,		/* L6 (SSL) timeout */
	HCHK_STATUS_L6RSP,		/* L6 invalid response - protocol error */

	HCHK_STATUS_L7TOUT,		/* L7 (HTTP/SMTP) timeout */
	HCHK_STATUS_L7RSP,		/* L7 invalid response - protocol error */

	/* Below we have layer 5-7 data available */
	HCHK_STATUS_L57DATA,		/* DUMMY STATUS */
	HCHK_STATUS_L7OKD,		/* L7 check passed */
	HCHK_STATUS_L7OKCD,		/* L7 check conditionally passed */
	HCHK_STATUS_L7STS,		/* L7 response error, for example HTTP 5xx */

	HCHK_STATUS_SIZE
};


/* health status for response tracking */
enum {
	HANA_STATUS_UNKNOWN	= 0,

	HANA_STATUS_L4_OK,		/* L4 successful connection */
	HANA_STATUS_L4_ERR,		/* L4 unsuccessful connection */

	HANA_STATUS_HTTP_OK,		/* Correct http response */
	HANA_STATUS_HTTP_STS,		/* Wrong http response, for example HTTP 5xx */
	HANA_STATUS_HTTP_HDRRSP,	/* Invalid http response (headers) */
	HANA_STATUS_HTTP_RSP,		/* Invalid http response */

	HANA_STATUS_HTTP_READ_ERROR,	/* Read error */
	HANA_STATUS_HTTP_READ_TIMEOUT,	/* Read timeout */
	HANA_STATUS_HTTP_BROKEN_PIPE,	/* Unexpected close from server */

	HANA_STATUS_SIZE
};

enum {
	HANA_ONERR_UNKNOWN	= 0,

	HANA_ONERR_FASTINTER,		/* Force fastinter*/
	HANA_ONERR_FAILCHK,		/* Simulate a failed check */
	HANA_ONERR_SUDDTH,		/* Enters sudden death - one more failed check will mark this server down */
	HANA_ONERR_MARKDWN,		/* Mark this server down, now! */
};

enum {
	HANA_ONMARKEDDOWN_NONE	= 0,
	HANA_ONMARKEDDOWN_SHUTDOWNSESSIONS,	/* Shutdown peer sessions */
};

enum {
	HANA_ONMARKEDUP_NONE	= 0,
	HANA_ONMARKEDUP_SHUTDOWNBACKUPSESSIONS,	/* Shutdown peer sessions */
};

enum {
	HANA_OBS_NONE		= 0,

	HANA_OBS_LAYER4,		/* Observe L4 - for example tcp */
	HANA_OBS_LAYER7,		/* Observe L7 - for example http */

	HANA_OBS_SIZE
};

struct check {
	struct connection *conn;		/* connection state for health checks */
	unsigned short port;			/* the port to use for the health checks */
	struct buffer *bi, *bo;			/* input and output buffers to send/recv check */
	struct task *task;			/* the task associated to the health check processing, NULL if disabled */
	struct timeval start;			/* last health check start time */
	long duration;				/* time in ms took to finish last health check */
	short status, code;			/* check result, check code */
	char desc[HCHK_DESC_LEN];		/* health check descritpion */
	int use_ssl;				/* use SSL for health checks */
	int send_proxy;				/* send a PROXY protocol header with checks */
	struct tcpcheck_rule *current_step;     /* current step when using tcpcheck */
	struct tcpcheck_rule *last_started_step;/* pointer to latest tcpcheck rule started */
	int inter, fastinter, downinter;        /* checks: time in milliseconds */
	enum chk_result result;                 /* health-check result : CHK_RES_* */
	int state;				/* state of the check : CHK_ST_*   */
	int health;				/* 0 to rise-1 = bad;
						 * rise to rise+fall-1 = good */
	int rise, fall;				/* time in iterations */
	int type;				/* Check type, one of PR_O2_*_CHK */
	struct server *server;			/* back-pointer to server */
};

struct check_status {
	short result;			/* one of SRV_CHK_* */
	char *info;			/* human readable short info */
	char *desc;			/* long description */
};

struct analyze_status {
	char *desc;				/* description */
	unsigned char lr[HANA_OBS_SIZE];	/* result for l4/l7: 0 = ignore, 1 - error, 2 - OK */
};

/* possible actions for tcpcheck_rule->action */
enum {
	TCPCHK_ACT_SEND        = 0,             /* send action, regular string format */
	TCPCHK_ACT_EXPECT,                      /* expect action, either regular or binary string */
	TCPCHK_ACT_CONNECT,                     /* connect action, to probe a new port */
};

/* flags used by tcpcheck_rule->conn_opts */
#define TCPCHK_OPT_NONE         0x0000  /* no options specified, default */
#define TCPCHK_OPT_SEND_PROXY   0x0001  /* send proxy-protocol string */
#define TCPCHK_OPT_SSL          0x0002  /* SSL connection */

struct tcpcheck_rule {
	struct list list;                       /* list linked to from the proxy */
	int action;                             /* action: send or expect */
	/* match type uses NON-NULL pointer from either string or expect_regex below */
	/* sent string is string */
	char *string;                           /* sent or expected string */
	int string_len;                         /* string lenght */
	struct my_regex *expect_regex;          /* expected */
	int inverse;                            /* 0 = regular match, 1 = inverse match */
	unsigned short port;                    /* port to connect to */
	unsigned short conn_opts;               /* options when setting up a new connection */
};

#endif /* _TYPES_CHECKS_H */
