/*
 * include/haproxy/mailer-t.h
 * This file defines everything related to mailer.
 *
 * Copyright 2015 Horms Solutions Ltd., Simon Horman <horms@verge.net.au>
 *
 * Based on include/haproxy/peers-t.h
 *
 * Copyright 2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#ifndef _HAPROXY_MAILERS_T_H
#define _HAPROXY_MAILERS_T_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <haproxy/check-t.h>
#include <haproxy/tcpcheck-t.h>
#include <haproxy/thread-t.h>

/* flags for proxy.email_alert.flags */
enum proxy_email_alert_flags {
	PR_EMAIL_ALERT_NONE = 0,
	PR_EMAIL_ALERT_SET,      /* set if email alert settings are present */
	PR_EMAIL_ALERT_RESOLVED, /* set if email alert settings were resolved */
};

struct mailer {
	char *id;
	struct mailers *mailers;
	struct {
		const char *file;	/* file where the section appears */
		int line;		/* line where the section appears */
	} conf;				/* config information */
	struct sockaddr_storage addr;	/* SMTP server address */
	struct protocol *proto;		/* SMTP server address's protocol */
	struct xprt_ops *xprt;		/* SMTP server socket operations at transport layer */
	void *sock_init_arg;		/* socket operations's opaque init argument if needed */
	struct mailer *next;		/* next mailer in the list */
};

struct mailers {
	char *id;			/* mailers section name */
	struct mailer *mailer_list;	/* mailers in this mailers section */
	struct {
		const char *file;	/* file where the section appears */
		int line;		/* line where the section appears */
	} conf;				/* config information */
	struct mailers *next;	        /* next mailers section */
	int count;			/* total number of mailers in this mailers section */
	int users;			/* number of users of this mailers section */
	struct {			/* time to: */
		int mail;		/*   try connecting to mailserver and sending a email */
	} timeout;
};

struct email_alert {
	struct list list;
	struct tcpcheck_rules rules;
	struct server *srv;
};

struct email_alertq {
	struct list email_alerts;
	struct check check;		/* Email alerts are implemented using existing check
					 * code even though they are not checks. This structure
					 * is as a parameter to the check code.
					 * Each check corresponds to a mailer */
	__decl_thread(HA_SPINLOCK_T lock);
};

#endif /* _HAPROXY_MAILERS_T_H */

