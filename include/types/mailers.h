/*
 * include/types/mailer.h
 * This file defines everything related to mailer.
 *
 * Copyright 2015 Horms Solutions Ltd., Simon Horman <horms@verge.net.au>
 *
 * Based on include/types/peers.h
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

#ifndef _TYPES_MAILERS_H
#define _TYPES_MAILERS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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


extern struct mailers *mailers;

#endif /* _TYPES_MAILERS_H */

