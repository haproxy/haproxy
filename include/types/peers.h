/*
 * include/types/peers.h
 * This file defines everything related to peers.
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

#ifndef _TYPES_PEERS_H
#define _TYPES_PEERS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/appsession.h>
#include <common/config.h>
#include <common/mini-clist.h>
#include <common/regex.h>
#include <common/sessionhash.h>
#include <common/tools.h>
#include <eb32tree.h>

struct peer_session {
	struct shared_table *table;   /* shared table */
	struct peer *peer;	      /* current peer */
	struct session *session;      /* current transport session */
	unsigned int flags; 	      /* peer session flags */
	unsigned int statuscode;      /* current/last session status code */
	unsigned int update;	      /* current peer acked update */
	unsigned int pushack;	      /* last commited update to ack */
	unsigned int lastack;	      /* last acked update */
	unsigned int lastpush;	      /* last pushed update */
	unsigned int confirm;	      /* confirm message counter */
	unsigned int pushed;	      /* equal to last pushed data or to table local update in case of total push
				       * or to teaching_origin if teaching is ended */
	unsigned int reconnect;	      /* next connect timer */
	unsigned int teaching_origin; /* resync teaching origine update */
	struct peer_session *next;
};

struct shared_table {
	struct stktable *table;		    /* stick table to sync */
	struct task *sync_task;		    /* main sync task */
	struct peer_session *local_session; /* local peer session */
	struct peer_session *sessions;	    /* peer sessions list */
	unsigned int flags;		    /* current table resync state */
	unsigned int resync_timeout;	    /* resync timeout timer */
	struct shared_table *next;	    /* next shared table in list */
};

struct peer {
	int local;		  /* proxy state */
	char *id;
	struct peers *peers;
	struct {
		const char *file; /* file where the section appears */
		int line;	  /* line where the section appears */
	} conf;		  	  /* config information */
	time_t last_change;
	struct sockaddr_storage addr;  /* peer address */
	struct protocol *proto;	       /* peer address protocol */
	struct xprt_ops *xprt;         /* peer socket operations at transport layer */
	void *sock_init_arg;           /* socket operations's opaque init argument if needed */
	struct peer *next;	  /* next peer in the list */
};


struct peers {
	int state;			 /* proxy state */
	char *id;			 /* peer section name */
	struct peer *remote;		 /* remote peers list */
	struct proxy *peers_fe;		 /* peer frontend */
	struct {
		const char *file;	 /* file where the section appears */
		int line;		 /* line where the section appears */
	} conf;				 /* config information */
	struct shared_table *tables;	 /* registered shared tables */
	time_t last_change;
	struct peers *next;		 /* next peer section */
	int count;			 /* total of peers */
};


extern struct peers *peers;

#endif /* _TYPES_PEERS_H */

