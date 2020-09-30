/*
 * include/haproxy/session-t.h
 * This file defines everything related to sessions.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_SESSION_T_H
#define _HAPROXY_SESSION_T_H


#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <haproxy/api-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/stick_table-t.h>
#include <haproxy/task-t.h>
#include <haproxy/vars-t.h>


/* session flags */
enum {
	SESS_FL_NONE          = 0x00000000, /* nothing */
	SESS_FL_PREFER_LAST   = 0x00000001, /* NTML authent, we should reuse last conn */
};

/* max number of idle server connections kept attached to a session */
#define MAX_SRV_LIST	5

struct session {
	struct proxy *fe;               /* the proxy this session depends on for the client side */
	struct listener *listener;      /* the listener by which the request arrived */
	enum obj_type *origin;          /* the connection / applet which initiated this session */
	struct timeval accept_date;     /* date of the session's accept() in user date */
	struct timeval tv_accept;       /* date of the session's accept() in internal date (monotonic) */
	struct stkctr stkctr[MAX_SESS_STKCTR];  /* stick counters for tcp-connection */
	struct vars vars;               /* list of variables for the session scope. */
	struct task *task;              /* handshake timeout processing */
	long t_handshake;               /* handshake duration, -1 = not completed */
	long t_idle;                    /* idle duration, -1 if never occurs */
	int idle_conns;                 /* Number of connections we're currently responsible for that we are not using */
	unsigned int flags;             /* session flags, SESS_FL_* */
	struct list srv_list;           /* List of servers and the connections the session is currently responsible for */
};

struct sess_srv_list {
	void *target;
	struct list conn_list;          /* Head of the connections list */
	struct list srv_list;           /* Next element of the server list */
};

#endif /* _HAPROXY_SESSION_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
