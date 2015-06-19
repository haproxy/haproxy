/*
 * include/types/session.h
 * This file defines everything related to sessions.
 *
 * Copyright (C) 2000-2015 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_SESSION_H
#define _TYPES_SESSION_H


#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/config.h>
#include <common/mini-clist.h>

#include <types/obj_type.h>
#include <types/proxy.h>
#include <types/stick_table.h>
#include <types/task.h>
#include <types/vars.h>

struct session {
	struct proxy *fe;               /* the proxy this session depends on for the client side */
	struct listener *listener;      /* the listener by which the request arrived */
	enum obj_type *origin;          /* the connection / applet which initiated this session */
	struct timeval accept_date;     /* date of the session's accept() in user date */
	struct timeval tv_accept;       /* date of the session's accept() in internal date (monotonic) */
	struct stkctr stkctr[MAX_SESS_STKCTR];  /* stick counters for tcp-connection */
	struct vars vars;               /* list of variables for the session scope. */
};

#endif /* _TYPES_SESSION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
