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

struct shared_table {
	struct stktable *table;		    /* stick table to sync */
	int local_id;
	int remote_id;
	int flags;
	uint64_t remote_data;
	unsigned int last_acked;
	unsigned int last_pushed;
	unsigned int last_get;
	unsigned int teaching_origin;
	unsigned int update;
	struct shared_table *next;	    /* next shared table in list */
};

struct peer {
	int local;		  /* proxy state */
	char *id;
	struct {
		const char *file; /* file where the section appears */
		int line;	  /* line where the section appears */
	} conf;		  	  /* config information */
	time_t last_change;
	struct sockaddr_storage addr;  /* peer address */
	struct protocol *proto;	       /* peer address protocol */
	struct xprt_ops *xprt;         /* peer socket operations at transport layer */
	void *sock_init_arg;           /* socket operations's opaque init argument if needed */
	unsigned int flags; 	      /* peer session flags */
	unsigned int statuscode;      /* current/last session status code */
	unsigned int reconnect;	      /* next connect timer */
	unsigned int confirm;         /* confirm message counter */
	struct stream *stream;        /* current transport stream */
	struct appctx *appctx;        /* the appctx running it */
	struct shared_table *remote_table;
	struct shared_table *last_local_table;
	struct shared_table *tables;
	struct peer *next;	  /* next peer in the list */
};


struct peers {
	int state;			 /* proxy state */
	char *id;			 /* peer section name */
	struct task *sync_task;		 /* main sync task */
	struct sig_handler *sighandler;	 /* signal handler */
	struct peer *remote;		 /* remote peers list */
	struct peer *local;		 /* local peer list */
	struct proxy *peers_fe;		 /* peer frontend */
	struct {
		const char *file;	 /* file where the section appears */
		int line;		 /* line where the section appears */
	} conf;				 /* config information */
	time_t last_change;
	struct peers *next;		 /* next peer section */
	unsigned int flags;		 /* current peers section resync state */
	unsigned int resync_timeout;	 /* resync timeout timer */
	int count;			 /* total of peers */
};


extern struct peers *peers;

#endif /* _TYPES_PEERS_H */

