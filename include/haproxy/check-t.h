/*
 * include/haproxy/check-t.h
 * Health-checks definitions, enums, macros and bitfields.
 *
 * Copyright 2008-2009 Krzysztof Piotr Oledzki <ole@ans.pl>
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _HAPROXY_CHECKS_T_H
#define _HAPROXY_CHECKS_T_H

#include <import/ebpttree.h>
#include <import/ist.h>
#include <haproxy/api-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/dynbuf-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/vars-t.h>

/* Please note: this file tends to commonly be part of circular dependencies,
 * so it is important to keep its includes list to the minimum possible (i.e.
 * only types whose size needs to be known). Since there are no function
 * prototypes nor pointers here, forward declarations are not really necessary.
 * This file oughtt to be split into multiple parts, at least regular checks vs
 * tcp-checks.
 */

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
#define CHK_ST_PORT_MISS        0x0020  /* check can't be send because no port is configured to run it */
#define CHK_ST_IN_ALLOC         0x0040  /* check blocked waiting for input buffer allocation */
#define CHK_ST_OUT_ALLOC        0x0080  /* check blocked waiting for output buffer allocation */
#define CHK_ST_CLOSE_CONN       0x0100  /* check is waiting that the connection gets closed */

/* check status */
enum healthcheck_status {
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

	HCHK_STATUS_PROCERR,		/* External process check failure */
	HCHK_STATUS_PROCTOUT,		/* External process check timeout */
	HCHK_STATUS_PROCOK,		/* External process check passed */

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

struct tcpcheck_rule;
struct tcpcheck_rules;

struct check {
	enum obj_type obj_type;                 /* object type == OBJ_TYPE_CHECK */
	struct session *sess;			/* Health check session. */
	struct vars vars;			/* Health check dynamic variables. */
	struct xprt_ops *xprt;			/* transport layer operations for health checks */
	struct conn_stream *cs;			/* conn_stream state for health checks */
	struct buffer bi, bo;			/* input and output buffers to send/recv check */
	struct buffer_wait buf_wait;            /* Wait list for buffer allocation */
	struct task *task;			/* the task associated to the health check processing, NULL if disabled */
	struct timeval start;			/* last health check start time */
	long duration;				/* time in ms took to finish last health check */
	short status, code;			/* check result, check code */
	unsigned short port;			/* the port to use for the health checks */
	char desc[HCHK_DESC_LEN];		/* health check description */
	signed char use_ssl;			/* use SSL for health checks (1: on, 0: server mode, -1: off) */
	int send_proxy;				/* send a PROXY protocol header with checks */
	struct tcpcheck_rules *tcpcheck_rules;	/* tcp-check send / expect rules */
	struct tcpcheck_rule *current_step;     /* current step when using tcpcheck */
	int inter, fastinter, downinter;        /* checks: time in milliseconds */
	enum chk_result result;                 /* health-check result : CHK_RES_* */
	int state;				/* state of the check : CHK_ST_*   */
	int health;				/* 0 to rise-1 = bad;
						 * rise to rise+fall-1 = good */
	int rise, fall;				/* time in iterations */
	int type;				/* Check type, one of PR_O2_*_CHK */
	struct server *server;			/* back-pointer to server */
	struct proxy *proxy;                    /* proxy to be used */
	char **argv;				/* the arguments to use if running a process-based check */
	char **envp;				/* the environment to use if running a process-based check */
	struct pid_list *curpid;		/* entry in pid_list used for current process-based test, or -1 if not in test */
	struct sockaddr_storage addr;   	/* the address to check */
	struct wait_event wait_list;            /* Waiting for I/O events */
	char *sni;				/* Server name */
	char *alpn_str;                         /* ALPN to use for checks */
	int alpn_len;                           /* ALPN string length */
	const struct mux_proto_list *mux_proto; /* the mux to use for all outgoing connections (specified by the "proto" keyword) */
	int via_socks4;                         /* check the connection via socks4 proxy */
};

#endif /* _HAPROXY_CHECKS_T_H */
