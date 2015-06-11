/*
 * Peer synchro management.
 *
 * Copyright 2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/time.h>

#include <types/global.h>
#include <types/listener.h>
#include <types/obj_type.h>
#include <types/peers.h>

#include <proto/acl.h>
#include <proto/applet.h>
#include <proto/channel.h>
#include <proto/fd.h>
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/hdr_idx.h>
#include <proto/proto_tcp.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/signal.h>
#include <proto/stick_table.h>
#include <proto/stream_interface.h>
#include <proto/task.h>


/*******************************/
/* Current peer learning state */
/*******************************/

/******************************/
/* Current peers section resync state */
/******************************/
#define	PEERS_F_RESYNC_LOCAL		0x00000001 /* Learn from local finished or no more needed */
#define	PEERS_F_RESYNC_REMOTE		0x00000002 /* Learn from remote finished or no more needed */
#define	PEERS_F_RESYNC_ASSIGN		0x00000004 /* A peer was assigned to learn our lesson */
#define	PEERS_F_RESYNC_PROCESS		0x00000008 /* The assigned peer was requested for resync */
#define	PEERS_F_DONOTSTOP		0x00010000 /* Main table sync task block process during soft stop
						      to push data to new process */

#define	PEERS_RESYNC_STATEMASK		(PEERS_F_RESYNC_LOCAL|PEERS_F_RESYNC_REMOTE)
#define	PEERS_RESYNC_FROMLOCAL		0x00000000
#define	PEERS_RESYNC_FROMREMOTE		PEERS_F_RESYNC_LOCAL
#define	PEERS_RESYNC_FINISHED		(PEERS_F_RESYNC_LOCAL|PEERS_F_RESYNC_REMOTE)

/***********************************/
/* Current shared table sync state */
/***********************************/
#define SHTABLE_F_TEACH_STAGE1		0x00000001 /* Teach state 1 complete */
#define SHTABLE_F_TEACH_STAGE2		0x00000002 /* Teach state 2 complete */

/******************************/
/* Remote peer teaching state */
/******************************/
#define	PEER_F_TEACH_PROCESS		0x00000001 /* Teach a lesson to current peer */
#define	PEER_F_TEACH_FINISHED		0x00000008 /* Teach conclude, (wait for confirm) */
#define	PEER_F_TEACH_COMPLETE		0x00000010 /* All that we know already taught to current peer, used only for a local peer */
#define	PEER_F_LEARN_ASSIGN		0x00000100 /* Current peer was assigned for a lesson */
#define	PEER_F_LEARN_NOTUP2DATE		0x00000200 /* Learn from peer finished but peer is not up to date */

#define	PEER_TEACH_RESET		~(PEER_F_TEACH_PROCESS|PEER_F_TEACH_FINISHED) /* PEER_F_TEACH_COMPLETE should never be reset */
#define	PEER_LEARN_RESET		~(PEER_F_LEARN_ASSIGN|PEER_F_LEARN_NOTUP2DATE)

/*****************************/
/* Sync message class        */
/*****************************/
enum {
	PEER_MSG_CLASS_CONTROL = 0,
	PEER_MSG_CLASS_ERROR,
	PEER_MSG_CLASS_STICKTABLE = 10,
	PEER_MSG_CLASS_RESERVED = 255,
};

/*****************************/
/* control message types     */
/*****************************/
enum {
	PEER_MSG_CTRL_RESYNCREQ = 0,
	PEER_MSG_CTRL_RESYNCFINISHED,
	PEER_MSG_CTRL_RESYNCPARTIAL,
	PEER_MSG_CTRL_RESYNCCONFIRM,
};

/*****************************/
/* error message types       */
/*****************************/
enum {
	PEER_MSG_ERR_PROTOCOL = 0,
	PEER_MSG_ERR_SIZELIMIT,
};


/*******************************/
/* stick table sync mesg types */
/* Note: ids >= 128 contains   */
/* id message cotains data     */
/*******************************/
enum {
	PEER_MSG_STKT_UPDATE = 128,
	PEER_MSG_STKT_INCUPDATE,
	PEER_MSG_STKT_DEFINE,
	PEER_MSG_STKT_SWITCH,
	PEER_MSG_STKT_ACK,
};

/**********************************/
/* Peer Session IO handler states */
/**********************************/

enum {
	PEER_SESS_ST_ACCEPT = 0,     /* Initial state for session create by an accept, must be zero! */
	PEER_SESS_ST_GETVERSION,     /* Validate supported protocol version */
	PEER_SESS_ST_GETHOST,        /* Validate host ID correspond to local host id */
	PEER_SESS_ST_GETPEER,        /* Validate peer ID correspond to a known remote peer id */
	/* after this point, data were possibly exchanged */
	PEER_SESS_ST_SENDSUCCESS,    /* Send ret code 200 (success) and wait for message */
	PEER_SESS_ST_CONNECT,        /* Initial state for session create on a connect, push presentation into buffer */
	PEER_SESS_ST_GETSTATUS,      /* Wait for the welcome message */
	PEER_SESS_ST_WAITMSG,        /* Wait for data messages */
	PEER_SESS_ST_EXIT,           /* Exit with status code */
	PEER_SESS_ST_ERRPROTO,       /* Send error proto message before exit */
	PEER_SESS_ST_ERRSIZE,        /* Send error size message before exit */
	PEER_SESS_ST_END,            /* Killed session */
};

/***************************************************/
/* Peer Session status code - part of the protocol */
/***************************************************/

#define	PEER_SESS_SC_CONNECTCODE	100 /* connect in progress */
#define	PEER_SESS_SC_CONNECTEDCODE	110 /* tcp connect success */

#define	PEER_SESS_SC_SUCCESSCODE	200 /* accept or connect successful */

#define	PEER_SESS_SC_TRYAGAIN		300 /* try again later */

#define	PEER_SESS_SC_ERRPROTO		501 /* error protocol */
#define	PEER_SESS_SC_ERRVERSION		502 /* unknown protocol version */
#define	PEER_SESS_SC_ERRHOST		503 /* bad host name */
#define	PEER_SESS_SC_ERRPEER		504 /* unknown peer */

#define PEER_SESSION_PROTO_NAME         "HAProxyS"

struct peers *peers = NULL;
static void peer_session_forceshutdown(struct stream * stream);

int intencode(uint64_t i, char **str) {
	int idx = 0;
	unsigned char *msg;

	if (!*str)
		return 0;

	msg = (unsigned char *)*str;
	if (i < 240) {
		msg[0] = (unsigned char)i;
		*str = (char *)&msg[idx+1];
		return (idx+1);
	}

	msg[idx] =(unsigned char)i | 240;
	i = (i - 240) >> 4;
	while (i >= 128) {
		msg[++idx] = (unsigned char)i | 128;
		i = (i - 128) >> 7;
	}
	msg[++idx] = (unsigned char)i;
	*str = (char *)&msg[idx+1];
	return (idx+1);
}


/* This function returns the decoded integer or 0
   if decode failed
   *str point on the beginning of the integer to decode
   at the end of decoding *str point on the end of the
   encoded integer or to null if end is reached */
uint64_t intdecode(char **str, char *end) {
	uint64_t i;
	int idx = 0;
	unsigned char *msg;

	if (!*str)
		return 0;

	msg = (unsigned char *)*str;
	if (msg >= (unsigned char *)end) {
		*str = NULL;
		return 0;
	}

	if (msg[idx] < 240) {
		*str = (char *)&msg[idx+1];
		return msg[idx];
	}
	i = msg[idx];
	do {
		idx++;
		if (msg >= (unsigned char *)end) {
			*str = NULL;
			return 0;
		}
		i += (uint64_t)msg[idx] <<  (4 + 7*(idx-1));
	}
	while (msg[idx] > 128);
	*str = (char *)&msg[idx+1];
	return i;
}

/*
 * This prepare the data update message on the stick session <ts>, <st> is the considered
 * stick table.
 *  <msg> is a buffer of <size> to recieve data message content
 * If function returns 0, the caller should consider we were unable to encode this message (TODO:
 * check size)
 */
static int peer_prepare_updatemsg(struct stksess *ts, struct shared_table *st, char *msg, size_t size, int use_identifier)
{
	uint32_t netinteger;
	unsigned short datalen;
	char *cursor, *datamsg;
	unsigned int data_type;
	void *data_ptr;

	cursor = datamsg = msg + 1 + 5;

	/* construct message */

	/* check if we need to send the update identifer */
	if (st->last_pushed && ts->upd.key > st->last_pushed && (ts->upd.key - st->last_pushed) == 1) {
		use_identifier = 0;
	}

	/* encode update identifier if needed */
	if (use_identifier)  {
		netinteger = htonl(ts->upd.key);
		memcpy(cursor, &netinteger, sizeof(netinteger));
		cursor += sizeof(netinteger);
	}

	/* encode the key */
	if (st->table->type == STKTABLE_TYPE_STRING) {
		int stlen = strlen((char *)ts->key.key);

		intencode(stlen, &cursor);
		memcpy(cursor, ts->key.key, stlen);
		cursor += stlen;
	}
	else if (st->table->type == STKTABLE_TYPE_INTEGER) {
		netinteger = htonl(*((uint32_t *)ts->key.key));
		memcpy(cursor, &netinteger, sizeof(netinteger));
		cursor += sizeof(netinteger);
	}
	else {
		memcpy(cursor, ts->key.key, st->table->key_size);
		cursor += st->table->key_size;
	}

	/* encode values */
	for (data_type = 0 ; data_type < STKTABLE_DATA_TYPES ; data_type++) {

		data_ptr = stktable_data_ptr(st->table, ts, data_type);
		if (data_ptr) {
			switch (stktable_data_types[data_type].std_type) {
				case STD_T_SINT: {
					int data;

					data = stktable_data_cast(data_ptr, std_t_sint);
					intencode(data, &cursor);
					break;
				}
				case STD_T_UINT: {
					unsigned int data;

					data = stktable_data_cast(data_ptr, std_t_uint);
					intencode(data, &cursor);
					break;
				}
				case STD_T_ULL: {
					unsigned long long data;

					data = stktable_data_cast(data_ptr, std_t_ull);
					intencode(data, &cursor);
					break;
				}
				case STD_T_FRQP: {
					struct freq_ctr_period *frqp;

					frqp = &stktable_data_cast(data_ptr, std_t_frqp);
					intencode((unsigned int)(now_ms - frqp->curr_tick), &cursor);
					intencode(frqp->curr_ctr, &cursor);
					intencode(frqp->prev_ctr, &cursor);
					break;
				}
			}
		}
	}

	/* Compute datalen */
	datalen = (cursor - datamsg);

	/*  prepare message header */
	msg[0] = PEER_MSG_CLASS_STICKTABLE;
	if (use_identifier)
		msg[1] = PEER_MSG_STKT_UPDATE;
	else
		msg[1] = PEER_MSG_STKT_INCUPDATE;

	cursor = &msg[2];
	intencode(datalen, &cursor);

	/* move data after header */
	memmove(cursor, datamsg, datalen);

	/* return header size + data_len */
	return (cursor - msg) + datalen;
}

/*
 * This prepare the switch table message to targeted share table <st>.
 *  <msg> is a buffer of <size> to recieve data message content
 * If function returns 0, the caller should consider we were unable to encode this message (TODO:
 * check size)
 */
static int peer_prepare_switchmsg(struct shared_table *st, char *msg, size_t size)
{
	int len;
	unsigned short datalen;
	char *cursor, *datamsg;
	uint64_t data = 0;
	unsigned int data_type;

	cursor = datamsg = msg + 2 + 5;

	/* Encode data */

	/* encode local id */
	intencode(st->local_id, &cursor);

	/* encode table name */
	len = strlen(st->table->id);
	intencode(len, &cursor);
	memcpy(cursor, st->table->id, len);
	cursor += len;

	/* encode table type */

	intencode(st->table->type, &cursor);

	/* encode table key size */
	intencode(st->table->key_size, &cursor);

	/* encode available known data types in table */
	for (data_type = 0 ; data_type < STKTABLE_DATA_TYPES ; data_type++) {
		if (st->table->data_ofs[data_type]) {
			switch (stktable_data_types[data_type].std_type) {
				case STD_T_SINT:
				case STD_T_UINT:
				case STD_T_ULL:
				case STD_T_FRQP:
					data |= 1 << data_type;
					break;
			}
		}
	}
	intencode(data, &cursor);

	/* Compute datalen */
	datalen = (cursor - datamsg);

	/*  prepare message header */
	msg[0] = PEER_MSG_CLASS_STICKTABLE;
	msg[1] = PEER_MSG_STKT_DEFINE;
	cursor = &msg[2];
	intencode(datalen, &cursor);

	/* move data after header */
	memmove(cursor, datamsg, datalen);

	/* return header size + data_len */
	return (cursor - msg) + datalen;
}

/*
 * This prepare the acknowledge message on the stick session <ts>, <st> is the considered
 * stick table.
 *  <msg> is a buffer of <size> to recieve data message content
 * If function returns 0, the caller should consider we were unable to encode this message (TODO:
 * check size)
 */
static int peer_prepare_ackmsg(struct shared_table *st, char *msg, size_t size)
{
	unsigned short datalen;
	char *cursor, *datamsg;
	uint32_t netinteger;

	cursor = datamsg = trash.str + 2 + 5;

	intencode(st->remote_id, &cursor);
	netinteger = htonl(st->last_get);
	memcpy(cursor, &netinteger, sizeof(netinteger));
	cursor += sizeof(netinteger);

	/* Compute datalen */
	datalen = (cursor - datamsg);

	/*  prepare message header */
	msg[0] = PEER_MSG_CLASS_STICKTABLE;
	msg[1] = PEER_MSG_STKT_DEFINE;
	cursor = &msg[2];
	intencode(datalen, &cursor);

	/* move data after header */
	memmove(cursor, datamsg, datalen);

	/* return header size + data_len */
	return (cursor - msg) + datalen;
}

/*
 * Callback to release a session with a peer
 */
static void peer_session_release(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);
	struct peer *peer = (struct peer *)appctx->ctx.peers.ptr;
	struct peers *peers = (struct peers *)strm_fe(s)->parent;

	/* appctx->ctx.peers.ptr is not a peer session */
	if (appctx->st0 < PEER_SESS_ST_SENDSUCCESS)
		return;

	/* peer session identified */
	if (peer) {
		if (peer->stream == s) {
			peer->stream = NULL;
			peer->appctx = NULL;
			if (peer->flags & PEER_F_LEARN_ASSIGN) {
				/* unassign current peer for learning */
				peer->flags &= ~(PEER_F_LEARN_ASSIGN);
				peers->flags &= ~(PEERS_F_RESYNC_ASSIGN|PEERS_F_RESYNC_PROCESS);

				/* reschedule a resync */
				peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(5000));
			}
			/* reset teaching and learning flags to 0 */
			peer->flags &= PEER_TEACH_RESET;
			peer->flags &= PEER_LEARN_RESET;
		}
		task_wakeup(peers->sync_task, TASK_WOKEN_MSG);
	}
}


/*
 * IO Handler to handle message exchance with a peer
 */
static void peer_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);
	struct peers *curpeers = (struct peers *)strm_fe(s)->parent;
	int reql = 0;
	int repl = 0;

	while (1) {
switchstate:
		switch(appctx->st0) {
			case PEER_SESS_ST_ACCEPT:
				appctx->ctx.peers.ptr = NULL;
				appctx->st0 = PEER_SESS_ST_GETVERSION;
				/* fall through */
			case PEER_SESS_ST_GETVERSION:
				reql = bo_getline(si_oc(si), trash.str, trash.size);
				if (reql <= 0) { /* closed or EOL not found */
					if (reql == 0)
						goto out;
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				if (trash.str[reql-1] != '\n') {
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				else if (reql > 1 && (trash.str[reql-2] == '\r'))
					trash.str[reql-2] = 0;
				else
					trash.str[reql-1] = 0;

				bo_skip(si_oc(si), reql);

				/* test version */
				if (strcmp(PEER_SESSION_PROTO_NAME " 2.0", trash.str) != 0) {
					appctx->st0 = PEER_SESS_ST_EXIT;
					appctx->st1 = PEER_SESS_SC_ERRVERSION;
					/* test protocol */
					if (strncmp(PEER_SESSION_PROTO_NAME " ", trash.str, strlen(PEER_SESSION_PROTO_NAME)+1) != 0)
						appctx->st1 = PEER_SESS_SC_ERRPROTO;
					goto switchstate;
				}

				appctx->st0 = PEER_SESS_ST_GETHOST;
				/* fall through */
			case PEER_SESS_ST_GETHOST:
				reql = bo_getline(si_oc(si), trash.str, trash.size);
				if (reql <= 0) { /* closed or EOL not found */
					if (reql == 0)
						goto out;
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				if (trash.str[reql-1] != '\n') {
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				else if (reql > 1 && (trash.str[reql-2] == '\r'))
					trash.str[reql-2] = 0;
				else
					trash.str[reql-1] = 0;

				bo_skip(si_oc(si), reql);

				/* test hostname match */
				if (strcmp(localpeer, trash.str) != 0) {
					appctx->st0 = PEER_SESS_ST_EXIT;
					appctx->st1 = PEER_SESS_SC_ERRHOST;
					goto switchstate;
				}

				appctx->st0 = PEER_SESS_ST_GETPEER;
				/* fall through */
			case PEER_SESS_ST_GETPEER: {
				struct peer *curpeer;
				char *p;
				reql = bo_getline(si_oc(si), trash.str, trash.size);
				if (reql <= 0) { /* closed or EOL not found */
					if (reql == 0)
						goto out;
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				if (trash.str[reql-1] != '\n') {
					/* Incomplete line, we quit */
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				else if (reql > 1 && (trash.str[reql-2] == '\r'))
					trash.str[reql-2] = 0;
				else
					trash.str[reql-1] = 0;

				bo_skip(si_oc(si), reql);

				/* parse line "<peer name> <pid> <relative_pid>" */
				p = strchr(trash.str, ' ');
				if (!p) {
					appctx->st0 = PEER_SESS_ST_EXIT;
					appctx->st1 = PEER_SESS_SC_ERRPROTO;
					goto switchstate;
				}
				*p = 0;

				/* lookup known peer */
				for (curpeer = curpeers->remote; curpeer; curpeer = curpeer->next) {
					if (strcmp(curpeer->id, trash.str) == 0)
						break;
				}

				/* if unknown peer */
				if (!curpeer) {
					appctx->st0 = PEER_SESS_ST_EXIT;
					appctx->st1 = PEER_SESS_SC_ERRPEER;
					goto switchstate;
				}

				if (curpeer->stream && curpeer->stream != s) {
					if (curpeer->local) {
						/* Local connection, reply a retry */
						appctx->st0 = PEER_SESS_ST_EXIT;
						appctx->st1 = PEER_SESS_SC_TRYAGAIN;
						goto switchstate;
					}
					peer_session_forceshutdown(curpeer->stream);
				}
				curpeer->stream = s;
				curpeer->appctx = appctx;
				appctx->ctx.peers.ptr = curpeer;
				appctx->st0 = PEER_SESS_ST_SENDSUCCESS;
				/* fall through */
			}
			case PEER_SESS_ST_SENDSUCCESS: {
				struct peer *curpeer = (struct peer *)appctx->ctx.peers.ptr;
				struct shared_table *st;

				repl = snprintf(trash.str, trash.size, "%d\n", PEER_SESS_SC_SUCCESSCODE);
				repl = bi_putblk(si_ic(si), trash.str, repl);
				if (repl <= 0) {
					if (repl == -1)
						goto full;
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}

				/* Register status code */
				curpeer->statuscode = PEER_SESS_SC_SUCCESSCODE;

				/* Awake main task */
				task_wakeup(curpeers->sync_task, TASK_WOKEN_MSG);

				/* Init confirm counter */
				curpeer->confirm = 0;

				/* Init cursors */
				for (st = curpeer->tables; st ; st = st->next) {
					st->last_get = st->last_acked = 0;
					st->teaching_origin = st->last_pushed = st->update;
				}

				/* reset teaching and learning flags to 0 */
				curpeer->flags &= PEER_TEACH_RESET;
				curpeer->flags &= PEER_LEARN_RESET;

				/* if current peer is local */
                                if (curpeer->local) {
                                        /* if current host need resyncfrom local and no process assined  */
                                        if ((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMLOCAL &&
                                            !(peers->flags & PEERS_F_RESYNC_ASSIGN)) {
                                                /* assign local peer for a lesson, consider lesson already requested */
                                                curpeer->flags |= PEER_F_LEARN_ASSIGN;
                                                peers->flags |= (PEERS_F_RESYNC_ASSIGN|PEERS_F_RESYNC_PROCESS);
                                        }

                                }
                                else if ((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE &&
                                         !(peers->flags & PEERS_F_RESYNC_ASSIGN)) {
                                        /* assign peer for a lesson  */
                                        curpeer->flags |= PEER_F_LEARN_ASSIGN;
                                        peers->flags |= PEERS_F_RESYNC_ASSIGN;
                                }


				/* switch to waiting message state */
				appctx->st0 = PEER_SESS_ST_WAITMSG;
				goto switchstate;
			}
			case PEER_SESS_ST_CONNECT: {
				struct peer *curpeer = (struct peer *)appctx->ctx.peers.ptr;

				/* Send headers */
				repl = snprintf(trash.str, trash.size,
				                PEER_SESSION_PROTO_NAME " 2.0\n%s\n%s %d %d\n",
				                curpeer->id,
				                localpeer,
				                (int)getpid(),
						relative_pid);

				if (repl >= trash.size) {
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}

				repl = bi_putblk(si_ic(si), trash.str, repl);
				if (repl <= 0) {
					if (repl == -1)
						goto full;
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}

				/* switch to the waiting statuscode state */
				appctx->st0 = PEER_SESS_ST_GETSTATUS;
				/* fall through */
			}
			case PEER_SESS_ST_GETSTATUS: {
				struct peer *curpeer = (struct peer *)appctx->ctx.peers.ptr;
				struct shared_table *st;

				if (si_ic(si)->flags & CF_WRITE_PARTIAL)
					curpeer->statuscode = PEER_SESS_SC_CONNECTEDCODE;

				reql = bo_getline(si_oc(si), trash.str, trash.size);
				if (reql <= 0) { /* closed or EOL not found */
					if (reql == 0)
						goto out;
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				if (trash.str[reql-1] != '\n') {
					/* Incomplete line, we quit */
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				else if (reql > 1 && (trash.str[reql-2] == '\r'))
					trash.str[reql-2] = 0;
				else
					trash.str[reql-1] = 0;

				bo_skip(si_oc(si), reql);

				/* Register status code */
				curpeer->statuscode = atoi(trash.str);

				/* Awake main task */
				task_wakeup(peers->sync_task, TASK_WOKEN_MSG);

				/* If status code is success */
				if (curpeer->statuscode == PEER_SESS_SC_SUCCESSCODE) {
					/* Init cursors */
					for (st = curpeer->tables; st ; st = st->next) {
						st->last_get = st->last_acked = 0;
						st->teaching_origin = st->last_pushed = st->update;
					}

					/* Init confirm counter */
                                        curpeer->confirm = 0;

                                        /* reset teaching and learning flags to 0 */
                                        curpeer->flags &= PEER_TEACH_RESET;
                                        curpeer->flags &= PEER_LEARN_RESET;

                                        /* If current peer is local */
                                        if (curpeer->local) {
                                                /* flag to start to teach lesson */
                                                curpeer->flags |= PEER_F_TEACH_PROCESS;

                                        }
                                        else if ((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE &&
                                                    !(peers->flags & PEERS_F_RESYNC_ASSIGN)) {
                                                /* If peer is remote and resync from remote is needed,
                                                   and no peer currently assigned */

                                                /* assign peer for a lesson */
                                                curpeer->flags |= PEER_F_LEARN_ASSIGN;
						peers->flags |= PEERS_F_RESYNC_ASSIGN;
					}

				}
				else {
					/* Status code is not success, abort */
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				appctx->st0 = PEER_SESS_ST_WAITMSG;
				/* fall through */
			}
			case PEER_SESS_ST_WAITMSG: {
				struct peer *curpeer = (struct peer *)appctx->ctx.peers.ptr;
				struct stksess *ts, *newts = NULL;
				uint32_t msg_len = 0;
				char *msg_cur = trash.str;
				char *msg_end = trash.str;
				unsigned char msg_head[7];
				int totl = 0;

				reql = bo_getblk(si_oc(si), (char *)msg_head, 2*sizeof(unsigned char), totl);
				if (reql <= 0) /* closed or EOL not found */
					goto incomplete;

				totl += reql;

				if (msg_head[1] >= 128) {
					/* Read and Decode message length */
					reql = bo_getblk(si_oc(si), (char *)&msg_head[2], sizeof(unsigned char), totl);
					if (reql <= 0) /* closed */
						goto incomplete;

					totl += reql;

					if (msg_head[2] < 240) {
						msg_len = msg_head[2];
					}
					else {
						int i;
						char *cur;
						char *end;

						for (i = 3 ; i < sizeof(msg_head) ; i++) {
							reql = bo_getblk(si_oc(si), (char *)&msg_head[i], sizeof(char), totl);
							if (reql <= 0) /* closed */
								goto incomplete;

							totl += reql;

							if (!(msg_head[i] & 0x80))
								break;
						}

						if (i == sizeof(msg_head)) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;

						}
						end = (char *)msg_head + sizeof(msg_head);
						cur = (char *)&msg_head[2];
						msg_len = intdecode(&cur, end);
						if (!cur) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}
					}


					/* Read message content */
					if (msg_len) {
						if (msg_len > trash.size) {
							/* Status code is not success, abort */
							appctx->st0 = PEER_SESS_ST_ERRSIZE;
							goto switchstate;
						}

						reql = bo_getblk(si_oc(si), trash.str, msg_len, totl);
						if (reql <= 0) /* closed */
							goto incomplete;
						totl += reql;

						msg_end += msg_len;
					}
				}

				if (msg_head[0] == PEER_MSG_CLASS_CONTROL) {
					if (msg_head[1] == PEER_MSG_CTRL_RESYNCREQ) {
						struct shared_table *st;
						/* Reset message: remote need resync */

						/* prepare tables fot a global push */
						for (st = curpeer->tables; st; st = st->next) {
							st->teaching_origin = st->last_pushed = st->table->update;
							st->flags = 0;
						}

						/* reset teaching flags to 0 */
						curpeer->flags &= PEER_TEACH_RESET;

						/* flag to start to teach lesson */
						curpeer->flags |= PEER_F_TEACH_PROCESS;


					}
					else if (msg_head[1] == PEER_MSG_CTRL_RESYNCFINISHED) {

						if (curpeer->flags & PEER_F_LEARN_ASSIGN) {
							curpeer->flags &= ~PEER_F_LEARN_ASSIGN;
							peers->flags &= ~(PEERS_F_RESYNC_ASSIGN|PEERS_F_RESYNC_PROCESS);
							peers->flags |= (PEERS_F_RESYNC_LOCAL|PEERS_F_RESYNC_REMOTE);
						}
						curpeer->confirm++;
					}
					else if (msg_head[1] == PEER_MSG_CTRL_RESYNCPARTIAL) {

						if (curpeer->flags & PEER_F_LEARN_ASSIGN) {
							curpeer->flags &= ~PEER_F_LEARN_ASSIGN;
							peers->flags &= ~(PEERS_F_RESYNC_ASSIGN|PEERS_F_RESYNC_PROCESS);

							curpeer->flags |= PEER_F_LEARN_NOTUP2DATE;
							peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(5000));
							task_wakeup(peers->sync_task, TASK_WOKEN_MSG);
						}
						curpeer->confirm++;
					}
					else if (msg_head[1] == PEER_MSG_CTRL_RESYNCCONFIRM)  {

						/* If stopping state */
						if (stopping) {
							/* Close session, push resync no more needed */
							curpeer->flags |= PEER_F_TEACH_COMPLETE;
							appctx->st0 = PEER_SESS_ST_END;
							goto switchstate;
						}

						 /* reset teaching flags to 0 */
						curpeer->flags &= PEER_TEACH_RESET;
					}
				}
				else if (msg_head[0] == PEER_MSG_CLASS_STICKTABLE) {
					if (msg_head[1] == PEER_MSG_STKT_DEFINE) {
						int table_id_len;
						struct shared_table *st;
						int table_type;
						int table_keylen;
						int table_id;
						uint64_t table_data;

						table_id = intdecode(&msg_cur, msg_end);
						if (!msg_cur) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}

						table_id_len = intdecode(&msg_cur, msg_end);
						if (!msg_cur) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}

						curpeer->remote_table = NULL;
						if (!table_id_len || (msg_cur + table_id_len) >= msg_end) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}

						for (st = curpeer->tables; st; st = st->next) {
							/* Reset IDs */
							if (st->remote_id == table_id)
								st->remote_id = 0;

							if (!curpeer->remote_table
							    && (table_id_len == strlen(st->table->id))
							    && (memcmp(st->table->id, msg_cur, table_id_len) == 0)) {
								curpeer->remote_table = st;
							}
						}

						if (!curpeer->remote_table) {
							goto ignore_msg;
						}

						msg_cur += table_id_len;
						if (msg_cur >= msg_end) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}

						table_type = intdecode(&msg_cur, msg_end);
						if (!msg_cur) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}

						table_keylen = intdecode(&msg_cur, msg_end);
						if (!msg_cur) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}

						table_data = intdecode(&msg_cur, msg_end);
						if (!msg_cur) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}

						if (curpeer->remote_table->table->type != table_type
						    || curpeer->remote_table->table->key_size != table_keylen) {
							curpeer->remote_table = NULL;
							goto ignore_msg;
						}

						curpeer->remote_table->remote_data = table_data;
						curpeer->remote_table->remote_id = table_id;
					}
					else if (msg_head[1] == PEER_MSG_STKT_SWITCH) {
						struct shared_table *st;
						int table_id;

						table_id = intdecode(&msg_cur, msg_end);
						if (!msg_cur) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}
						curpeer->remote_table = NULL;
						for (st = curpeer->tables; st; st = st->next) {
							if (st->remote_id == table_id) {
								curpeer->remote_table = st;
								break;
							}
						}

					}
					else if (msg_head[1] == PEER_MSG_STKT_UPDATE
						 || msg_head[1] == PEER_MSG_STKT_INCUPDATE) {
						struct shared_table *st = curpeer->remote_table;
						uint32_t update;
						unsigned int data_type;
						void *data_ptr;

						/* Here we have data message */
						if (!st)
							goto ignore_msg;

						if (msg_head[1] == PEER_MSG_STKT_UPDATE) {
							if (msg_len < sizeof(update)) {
								/* malformed message */
								appctx->st0 = PEER_SESS_ST_ERRPROTO;
								goto switchstate;
							}
							memcpy(&update, msg_cur, sizeof(update));
							msg_cur += sizeof(update);
							st->last_get = htonl(update);
						}
						else {
							st->last_get++;
						}

						newts = stksess_new(st->table, NULL);
						if (!newts)
							goto ignore_msg;

						if (st->table->type == STKTABLE_TYPE_STRING) {
							unsigned int to_read, to_store;

							to_read = intdecode(&msg_cur, msg_end);
							if (!msg_cur) {
								/* malformed message */
								stksess_free(st->table, newts);
								appctx->st0 = PEER_SESS_ST_ERRPROTO;
								goto switchstate;
							}
							to_store = MIN(to_read, st->table->key_size - 1);
							if (msg_cur + to_store > msg_end) {
								/* malformed message */
								stksess_free(st->table, newts);
								appctx->st0 = PEER_SESS_ST_ERRPROTO;
								goto switchstate;
							}

							memcpy(newts->key.key, msg_cur, to_store);
							newts->key.key[to_store] = 0;
							msg_cur += to_read;
						}
						else if (st->table->type == STKTABLE_TYPE_INTEGER) {
							unsigned int netinteger;

							if (msg_cur + sizeof(netinteger) > msg_end) {
								/* malformed message */
								stksess_free(st->table, newts);
								appctx->st0 = PEER_SESS_ST_ERRPROTO;
								goto switchstate;
							}
							memcpy(&netinteger, msg_cur, sizeof(netinteger));
							netinteger = ntohl(netinteger);
							memcpy(newts->key.key, &netinteger, sizeof(netinteger));
							msg_cur += sizeof(netinteger);
						}
						else {
							if (msg_cur + st->table->key_size > msg_end) {
								/* malformed message */
								stksess_free(st->table, newts);
								appctx->st0 = PEER_SESS_ST_ERRPROTO;
								goto switchstate;
							}
							memcpy(newts->key.key, msg_cur, st->table->key_size);
							msg_cur += st->table->key_size;
						}

						/* lookup for existing entry */
						ts = stktable_lookup(st->table, newts);
						if (ts) {
							/* the entry already exist, we can free ours */
							stktable_touch(st->table, ts, 0);
							stksess_free(st->table, newts);
							newts = NULL;
						}
						else {
							struct eb32_node *eb;

							/* create new entry */
							ts = stktable_store(st->table, newts, 0);
							newts = NULL; /* don't reuse it */

							ts->upd.key= (++st->table->update)+(2^31);
							eb = eb32_insert(&st->table->updates, &ts->upd);
							if (eb != &ts->upd) {
								eb32_delete(eb);
								eb32_insert(&st->table->updates, &ts->upd);
							}
						}

						for (data_type = 0 ; data_type < STKTABLE_DATA_TYPES ; data_type++) {

							if ((1 << data_type) & st->remote_data) {
								switch (stktable_data_types[data_type].std_type) {
									case STD_T_SINT: {
										int data;

										data = intdecode(&msg_cur, msg_end);
										if (!msg_cur) {
											/* malformed message */
											appctx->st0 = PEER_SESS_ST_ERRPROTO;
											goto switchstate;
										}

										data_ptr = stktable_data_ptr(st->table, ts, data_type);
										if (data_ptr)
											stktable_data_cast(data_ptr, std_t_sint) = data;
										break;
									}
									case STD_T_UINT: {
										unsigned int data;

										data = intdecode(&msg_cur, msg_end);
										if (!msg_cur) {
											/* malformed message */
											appctx->st0 = PEER_SESS_ST_ERRPROTO;
											goto switchstate;
										}

										data_ptr = stktable_data_ptr(st->table, ts, data_type);
										if (data_ptr)
											stktable_data_cast(data_ptr, std_t_uint) = data;
										break;
									}
									case STD_T_ULL: {
										unsigned long long  data;

										data = intdecode(&msg_cur, msg_end);
										if (!msg_cur) {
											/* malformed message */
											appctx->st0 = PEER_SESS_ST_ERRPROTO;
											goto switchstate;
										}

										data_ptr = stktable_data_ptr(st->table, ts, data_type);
										if (data_ptr)
											stktable_data_cast(data_ptr, std_t_ull) = data;
										break;
									}
									case STD_T_FRQP: {
										struct freq_ctr_period data;

										data.curr_tick = tick_add(now_ms, intdecode(&msg_cur, msg_end));
										if (!msg_cur) {
											/* malformed message */
											appctx->st0 = PEER_SESS_ST_ERRPROTO;
											goto switchstate;
										}
										data.curr_ctr = intdecode(&msg_cur, msg_end);
										if (!msg_cur) {
											/* malformed message */
											appctx->st0 = PEER_SESS_ST_ERRPROTO;
											goto switchstate;
										}
										data.prev_ctr = intdecode(&msg_cur, msg_end);
										if (!msg_cur) {
											/* malformed message */
											appctx->st0 = PEER_SESS_ST_ERRPROTO;
											goto switchstate;
										}

										data_ptr = stktable_data_ptr(st->table, ts, data_type);
										if (data_ptr)
											stktable_data_cast(data_ptr, std_t_frqp) = data;
										break;
									}
								}
							}
						}
					}
					else if (msg_head[1] == PEER_MSG_STKT_ACK) {
						/* ack message */
						uint32_t table_id ;
						uint32_t update;
						struct shared_table *st;

						table_id = intdecode(&msg_cur, msg_end);
						if (!msg_cur || (msg_cur + sizeof(update) > msg_end)) {
							/* malformed message */
							appctx->st0 = PEER_SESS_ST_ERRPROTO;
							goto switchstate;
						}
						memcpy(&update, msg_cur, sizeof(update));
						update = ntohl(update);

						for (st = curpeer->tables; st; st = st->next) {
							if (st->local_id == table_id) {
								st->update = update;
								break;
							}
						}
					}
				}
				else if (msg_head[0] == PEER_MSG_CLASS_RESERVED) {
					appctx->st0 = PEER_SESS_ST_ERRPROTO;
					goto switchstate;
				}

ignore_msg:
				/* skip consumed message */
				bo_skip(si_oc(si), totl);
				/* loop on that state to peek next message */
				goto switchstate;

incomplete:
				/* we get here when a bo_getblk() returns <= 0 in reql */

				if (reql < 0) {
					/* there was an error */
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}


				/* Confirm finished or partial messages */
				while (curpeer->confirm) {
					unsigned char msg[2];

					/* There is a confirm messages to send */
					msg[0] = PEER_MSG_CLASS_CONTROL;
					msg[1] = PEER_MSG_CTRL_RESYNCCONFIRM;

					/* message to buffer */
					repl = bi_putblk(si_ic(si), (char *)msg, sizeof(msg));
					if (repl <= 0) {
						/* no more write possible */
						if (repl == -1)
							goto full;
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
					curpeer->confirm--;
				}


				/* Need to request a resync */
                                if ((curpeer->flags & PEER_F_LEARN_ASSIGN) &&
                                        (peers->flags & PEERS_F_RESYNC_ASSIGN) &&
                                        !(peers->flags & PEERS_F_RESYNC_PROCESS)) {
					unsigned char msg[2];

                                        /* Current peer was elected to request a resync */
					msg[0] = PEER_MSG_CLASS_CONTROL;
					msg[1] = PEER_MSG_CTRL_RESYNCREQ;

					/* message to buffer */
					repl = bi_putblk(si_ic(si), (char *)msg, sizeof(msg));
                                        if (repl <= 0) {
                                                /* no more write possible */
                                                if (repl == -1)
                                                        goto full;
                                                appctx->st0 = PEER_SESS_ST_END;
                                                goto switchstate;
                                        }
                                        peers->flags |= PEERS_F_RESYNC_PROCESS;
                                }

				/* Nothing to read, now we start to write */

				if (curpeer->tables) {
					struct shared_table *st;
					struct shared_table *last_local_table;

					last_local_table = curpeer->last_local_table;
					if (!last_local_table)
						last_local_table = curpeer->tables;
					st = last_local_table->next;

					while (1) {
						if (!st)
							 st = curpeer->tables;

						/* It remains some updates to ack */
						if (st->last_get != st->last_acked) {
							int msglen;

							msglen = peer_prepare_ackmsg(st, trash.str, trash.size);
							if (!msglen) {
								/* internal error: message does not fit in trash */
								appctx->st0 = PEER_SESS_ST_END;
								goto switchstate;
							}

							/* message to buffer */
							repl = bi_putblk(si_ic(si), trash.str, msglen);
							if (repl <= 0) {
								/* no more write possible */
								if (repl == -1) {
									goto full;
								}
								appctx->st0 = PEER_SESS_ST_END;
								goto switchstate;
							}
							st->last_acked = st->last_get;
						}

						if (!(curpeer->flags & PEER_F_TEACH_PROCESS)) {
							if (!(curpeer->flags & PEER_F_LEARN_ASSIGN) &&
							    ((int)(st->last_pushed - st->table->localupdate) < 0)) {
								struct eb32_node *eb;
								int new_pushed;

								if (st != curpeer->last_local_table) {
									int msglen;

									msglen = peer_prepare_switchmsg(st, trash.str, trash.size);
									if (!msglen) {
										/* internal error: message does not fit in trash */
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}

									/* message to buffer */
									repl = bi_putblk(si_ic(si), trash.str, msglen);
									if (repl <= 0) {
										/* no more write possible */
										if (repl == -1) {
											goto full;
										}
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}
									curpeer->last_local_table = st;
								}

								/* We force new pushed to 1 to force identifier in update message */
								new_pushed = 1;
								eb = eb32_lookup_ge(&st->table->updates, st->last_pushed+1);
								while (1) {
									uint32_t msglen;
									struct stksess *ts;

									/* push local updates */
									if (!eb) {
										eb = eb32_first(&st->table->updates);
										if (!eb || ((int)(eb->key - st->last_pushed) <= 0)) {
											st->table->commitupdate = st->last_pushed = st->table->localupdate;
											break;
										}
									}

									if ((int)(eb->key - st->table->localupdate) > 0) {
										st->table->commitupdate = st->last_pushed = st->table->localupdate;
										break;
									}

									ts = eb32_entry(eb, struct stksess, upd);
									msglen = peer_prepare_updatemsg(ts, st, trash.str, trash.size, new_pushed);
									if (!msglen) {
										/* internal error: message does not fit in trash */
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}

									/* message to buffer */
									repl = bi_putblk(si_ic(si), trash.str, msglen);
									if (repl <= 0) {
										/* no more write possible */
										if (repl == -1) {
											goto full;
										}
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}
									st->last_pushed = ts->upd.key;
									if ((int)(st->last_pushed - st->table->commitupdate) > 0)
											st->table->commitupdate = st->last_pushed;
									/* identifier may not needed in next update message */
									new_pushed = 0;

									eb = eb32_next(eb);
								}
							}
						}
						else {
							if (!(st->flags & SHTABLE_F_TEACH_STAGE1)) {
								struct eb32_node *eb;
								int new_pushed;

								if (st != curpeer->last_local_table) {
									int msglen;

									msglen = peer_prepare_switchmsg(st, trash.str, trash.size);
									if (!msglen) {
										/* internal error: message does not fit in trash */
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}

									/* message to buffer */
									repl = bi_putblk(si_ic(si), trash.str, msglen);
									if (repl <= 0) {
										/* no more write possible */
										if (repl == -1) {
											goto full;
										}
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}
									curpeer->last_local_table = st;
								}

								/* We force new pushed to 1 to force identifier in update message */
								new_pushed = 1;
								eb = eb32_lookup_ge(&st->table->updates, st->last_pushed+1);
								while (1) {
									uint32_t msglen;
									struct stksess *ts;

									/* push local updates */
									if (!eb) {
										st->flags |= SHTABLE_F_TEACH_STAGE1;
										eb = eb32_first(&st->table->updates);
										if (eb)
											st->last_pushed = eb->key - 1;
										break;
									}

									ts = eb32_entry(eb, struct stksess, upd);
									msglen = peer_prepare_updatemsg(ts, st, trash.str, trash.size, new_pushed);
									if (!msglen) {
										/* internal error: message does not fit in trash */
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}

									/* message to buffer */
									repl = bi_putblk(si_ic(si), trash.str, msglen);
									if (repl <= 0) {
										/* no more write possible */
										if (repl == -1) {
											goto full;
										}
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}
									st->last_pushed = ts->upd.key;
									/* identifier may not needed in next update message */
									new_pushed = 0;

									eb = eb32_next(eb);
								}
							}

							if (!(st->flags & SHTABLE_F_TEACH_STAGE2)) {
								struct eb32_node *eb;
								int new_pushed;

								if (st != curpeer->last_local_table) {
									int msglen;

									msglen = peer_prepare_switchmsg(st, trash.str, trash.size);
									if (!msglen) {
										/* internal error: message does not fit in trash */
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}

									/* message to buffer */
									repl = bi_putblk(si_ic(si), trash.str, msglen);
									if (repl <= 0) {
										/* no more write possible */
										if (repl == -1) {
											goto full;
										}
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}
									curpeer->last_local_table = st;
								}

								/* We force new pushed to 1 to force identifier in update message */
								new_pushed = 1;
								eb = eb32_lookup_ge(&st->table->updates, st->last_pushed+1);
								while (1) {
									uint32_t msglen;
									struct stksess *ts;

									/* push local updates */
									if (!eb || eb->key > st->teaching_origin) {
										st->flags |= SHTABLE_F_TEACH_STAGE2;
										eb = eb32_first(&st->table->updates);
										if (eb)
											st->last_pushed = eb->key - 1;
										break;
									}

									ts = eb32_entry(eb, struct stksess, upd);
									msglen = peer_prepare_updatemsg(ts, st, trash.str, trash.size, new_pushed);
									if (!msglen) {
										/* internal error: message does not fit in trash */
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}

									/* message to buffer */
									repl = bi_putblk(si_ic(si), trash.str, msglen);
									if (repl <= 0) {
										/* no more write possible */
										if (repl == -1) {
											goto full;
										}
										appctx->st0 = PEER_SESS_ST_END;
										goto switchstate;
									}
									st->last_pushed = ts->upd.key;
									/* identifier may not needed in next update message */
									new_pushed = 0;

									eb = eb32_next(eb);
								}
							}
						}

						if (st == last_local_table)
							break;
						st = st->next;
					}
				}


				if ((curpeer->flags & PEER_F_TEACH_PROCESS) && !(curpeer->flags & PEER_F_TEACH_FINISHED)) {
					unsigned char msg[2];

                                        /* Current peer was elected to request a resync */
					msg[0] = PEER_MSG_CLASS_CONTROL;
					msg[1] = ((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FINISHED) ? PEER_MSG_CTRL_RESYNCFINISHED : PEER_MSG_CTRL_RESYNCPARTIAL;
					/* process final lesson message */
					repl = bi_putblk(si_ic(si), (char *)msg, sizeof(msg));
					if (repl <= 0) {
						/* no more write possible */
						if (repl == -1)
							goto full;
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
					/* flag finished message sent */
					curpeer->flags |= PEER_F_TEACH_FINISHED;
				}

				/* noting more to do */
				goto out;
			}
			case PEER_SESS_ST_EXIT:
				repl = snprintf(trash.str, trash.size, "%d\n", appctx->st1);

				if (bi_putblk(si_ic(si), trash.str, repl) == -1)
					goto full;
				appctx->st0 = PEER_SESS_ST_END;
				goto switchstate;
			case PEER_SESS_ST_ERRSIZE: {
				unsigned char msg[2];

				msg[0] = PEER_MSG_CLASS_ERROR;
				msg[1] = PEER_MSG_ERR_SIZELIMIT;

				if (bi_putblk(si_ic(si), (char *)msg, sizeof(msg)) == -1)
					goto full;
				appctx->st0 = PEER_SESS_ST_END;
				goto switchstate;
			}
			case PEER_SESS_ST_ERRPROTO: {
				unsigned char msg[2];

				msg[0] = PEER_MSG_CLASS_ERROR;
				msg[1] = PEER_MSG_ERR_PROTOCOL;

				if (bi_putblk(si_ic(si), (char *)msg, sizeof(msg)) == -1)
					goto full;
				appctx->st0 = PEER_SESS_ST_END;
				/* fall through */
			}
			case PEER_SESS_ST_END: {
				si_shutw(si);
				si_shutr(si);
				si_ic(si)->flags |= CF_READ_NULL;
				goto out;
			}
		}
	}
out:
	si_oc(si)->flags |= CF_READ_DONTWAIT;
	return;
full:
	si_applet_cant_put(si);
	goto out;
}

static struct applet peer_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<PEER>", /* used for logging */
	.fct = peer_io_handler,
	.release = peer_session_release,
};

/*
 * Use this function to force a close of a peer session
 */
static void peer_session_forceshutdown(struct stream * stream)
{
	struct appctx *appctx = NULL;
	struct peer *ps;

	int i;

	for (i = 0; i <= 1; i++) {
		appctx = objt_appctx(stream->si[i].end);
		if (!appctx)
			continue;
		if (appctx->applet != &peer_applet)
			continue;
		break;
	}

	if (!appctx)
		return;

	ps = (struct peer *)appctx->ctx.peers.ptr;
	/* we're killing a connection, we must apply a random delay before
	 * retrying otherwise the other end will do the same and we can loop
	 * for a while.
	 */
	if (ps)
		ps->reconnect = tick_add(now_ms, MS_TO_TICKS(50 + random() % 2000));

	/* call release to reinit resync states if needed */
	peer_session_release(appctx);
	appctx->st0 = PEER_SESS_ST_END;
	appctx->ctx.peers.ptr = NULL;
	task_wakeup(stream->task, TASK_WOKEN_MSG);
}

/* Pre-configures a peers frontend to accept incoming connections */
void peers_setup_frontend(struct proxy *fe)
{
	fe->last_change = now.tv_sec;
	fe->cap = PR_CAP_FE;
	fe->maxconn = 0;
	fe->conn_retries = CONN_RETRIES;
	fe->timeout.client = MS_TO_TICKS(5000);
	fe->accept = frontend_accept;
	fe->default_target = &peer_applet.obj_type;
	fe->options2 |= PR_O2_INDEPSTR | PR_O2_SMARTCON | PR_O2_SMARTACC;
	fe->bind_proc = 0; /* will be filled by users */
}

/*
 * Create a new peer session in assigned state (connect will start automatically)
 */
static struct stream *peer_session_create(struct peers *peers, struct peer *peer)
{
	struct listener *l = LIST_NEXT(&peers->peers_fe->conf.listeners, struct listener *, by_fe);
	struct proxy *p = (struct proxy *)l->frontend; /* attached frontend */
	struct appctx *appctx;
	struct session *sess;
	struct stream *s;
	struct task *t;
	struct connection *conn;

	peer->reconnect = tick_add(now_ms, MS_TO_TICKS(5000));
	peer->statuscode = PEER_SESS_SC_CONNECTCODE;
	s = NULL;

	appctx = appctx_new(&peer_applet);
	if (!appctx)
		goto out_close;

	appctx->st0 = PEER_SESS_ST_CONNECT;
	appctx->ctx.peers.ptr = (void *)peer;

	sess = session_new(p, l, &appctx->obj_type);
	if (!sess) {
		Alert("out of memory in peer_session_create().\n");
		goto out_free_appctx;
	}

	if ((t = task_new()) == NULL) {
		Alert("out of memory in peer_session_create().\n");
		goto out_free_sess;
	}
	t->nice = l->nice;

	if ((s = stream_new(sess, t, &appctx->obj_type)) == NULL) {
		Alert("Failed to initialize stream in peer_session_create().\n");
		goto out_free_task;
	}

	/* The tasks below are normally what is supposed to be done by
	 * fe->accept().
	 */
	s->flags = SF_ASSIGNED|SF_ADDR_SET;

	/* applet is waiting for data */
	si_applet_cant_get(&s->si[0]);
	appctx_wakeup(appctx);

	/* initiate an outgoing connection */
	si_set_state(&s->si[1], SI_ST_ASS);

	/* automatically prepare the stream interface to connect to the
	 * pre-initialized connection in si->conn.
	 */
	if (unlikely((conn = conn_new()) == NULL))
		goto out_free_strm;

	conn_prepare(conn, peer->proto, peer->xprt);
	si_attach_conn(&s->si[1], conn);

	conn->target = s->target = &s->be->obj_type;
	memcpy(&conn->addr.to, &peer->addr, sizeof(conn->addr.to));
	s->do_log = NULL;
	s->uniq_id = 0;

	s->res.flags |= CF_READ_DONTWAIT;

	l->nbconn++; /* warning! right now, it's up to the handler to decrease this */
	p->feconn++;/* beconn will be increased later */
	jobs++;
	if (!(s->sess->listener->options & LI_O_UNLIMITED))
		actconn++;
	totalconn++;

	peer->appctx = appctx;
	peer->stream = s;
	return s;

	/* Error unrolling */
 out_free_strm:
	LIST_DEL(&s->list);
	pool_free2(pool2_stream, s);
 out_free_task:
	task_free(t);
 out_free_sess:
	session_free(sess);
 out_free_appctx:
	appctx_free(appctx);
 out_close:
	return s;
}

/*
 * Task processing function to manage re-connect and peer session
 * tasks wakeup on local update.
 */
static struct task *process_peer_sync(struct task * task)
{
	struct peers *peers = (struct peers *)task->context;
	struct peer *ps;
	struct shared_table *st;

	task->expire = TICK_ETERNITY;

	if (!peers->peers_fe) {
		/* this one was never started, kill it */
		signal_unregister_handler(peers->sighandler);
		peers->sync_task = NULL;
		task_delete(peers->sync_task);
		task_free(peers->sync_task);
		return NULL;
	}

	if (!stopping) {
		/* Normal case (not soft stop)*/

		if (((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMLOCAL) &&
		     (!nb_oldpids || tick_is_expired(peers->resync_timeout, now_ms)) &&
		     !(peers->flags & PEERS_F_RESYNC_ASSIGN)) {
			/* Resync from local peer needed
			   no peer was assigned for the lesson
			   and no old local peer found
			       or resync timeout expire */

			/* flag no more resync from local, to try resync from remotes */
			peers->flags |= PEERS_F_RESYNC_LOCAL;

			/* reschedule a resync */
			peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(5000));
		}

		/* For each session */
		for (ps = peers->remote; ps; ps = ps->next) {
			/* For each remote peers */
			if (!ps->local) {
				if (!ps->stream) {
					/* no active stream */
					if (ps->statuscode == 0 ||
					    ((ps->statuscode == PEER_SESS_SC_CONNECTCODE ||
					      ps->statuscode == PEER_SESS_SC_SUCCESSCODE ||
					      ps->statuscode == PEER_SESS_SC_CONNECTEDCODE) &&
					     tick_is_expired(ps->reconnect, now_ms))) {
						/* connection never tried
						 * or previous stream established with success
						 * or previous stream failed during connection
						 * and reconnection timer is expired */

						/* retry a connect */
						ps->stream = peer_session_create(peers, ps);
					}
					else if (!tick_is_expired(ps->reconnect, now_ms)) {
						/* If previous session failed during connection
						 * but reconnection timer is not expired */

						/* reschedule task for reconnect */
						task->expire = tick_first(task->expire, ps->reconnect);
					}
					/* else do nothing */
				} /* !ps->stream */
				else if (ps->statuscode == PEER_SESS_SC_SUCCESSCODE) {
					/* current stream is active and established */
					if (((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE) &&
					    !(peers->flags & PEERS_F_RESYNC_ASSIGN) &&
					    !(ps->flags & PEER_F_LEARN_NOTUP2DATE)) {
						/* Resync from a remote is needed
						 * and no peer was assigned for lesson
						 * and current peer may be up2date */

						/* assign peer for the lesson */
						ps->flags |= PEER_F_LEARN_ASSIGN;
						peers->flags |= PEERS_F_RESYNC_ASSIGN;

						/* awake peer stream task to handle a request of resync */
						appctx_wakeup(ps->appctx);
					}
					else {
						/* Awake session if there is data to push */
						for (st = ps->tables; st ; st = st->next) {
							if ((int)(st->last_pushed - st->table->localupdate) < 0) {
								/* awake peer stream task to push local updates */
								appctx_wakeup(ps->appctx);
								break;
							}
						}
					}
					/* else do nothing */
				} /* SUCCESSCODE */
			} /* !ps->peer->local */
		} /* for */

		/* Resync from remotes expired: consider resync is finished */
		if (((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE) &&
		    !(peers->flags & PEERS_F_RESYNC_ASSIGN) &&
		    tick_is_expired(peers->resync_timeout, now_ms)) {
			/* Resync from remote peer needed
			 * no peer was assigned for the lesson
			 * and resync timeout expire */

			/* flag no more resync from remote, consider resync is finished */
			peers->flags |= PEERS_F_RESYNC_REMOTE;
		}

		if ((peers->flags & PEERS_RESYNC_STATEMASK) != PEERS_RESYNC_FINISHED) {
			/* Resync not finished*/
			/* reschedule task to resync timeout, to ended resync if needed */
			task->expire = tick_first(task->expire, peers->resync_timeout);
		}
	} /* !stopping */
	else {
		/* soft stop case */
		if (task->state & TASK_WOKEN_SIGNAL) {
			/* We've just recieved the signal */
			if (!(peers->flags & PEERS_F_DONOTSTOP)) {
				/* add DO NOT STOP flag if not present */
				jobs++;
				peers->flags |= PEERS_F_DONOTSTOP;
				ps = peers->local;
				for (st = ps->tables; st ; st = st->next)
					st->table->syncing++;
			}

			/* disconnect all connected peers */
			for (ps = peers->remote; ps; ps = ps->next) {
				if (ps->stream) {
					peer_session_forceshutdown(ps->stream);
					ps->stream = NULL;
					ps->appctx = NULL;
				}
			}
		}

		ps = peers->local;
		if (ps->flags & PEER_F_TEACH_COMPLETE) {
			if (peers->flags & PEERS_F_DONOTSTOP) {
				/* resync of new process was complete, current process can die now */
				jobs--;
				peers->flags &= ~PEERS_F_DONOTSTOP;
				for (st = ps->tables; st ; st = st->next)
					st->table->syncing--;
			}
		}
		else if (!ps->stream) {
			/* If stream is not active */
			if (ps->statuscode == 0 ||
			    ps->statuscode == PEER_SESS_SC_SUCCESSCODE ||
			    ps->statuscode == PEER_SESS_SC_CONNECTEDCODE ||
			    ps->statuscode == PEER_SESS_SC_TRYAGAIN) {
				/* connection never tried
				 * or previous stream was successfully established
				 * or previous stream tcp connect success but init state incomplete
				 * or during previous connect, peer replies a try again statuscode */

				/* connect to the peer */
				peer_session_create(peers, ps);
			}
			else {
				/* Other error cases */
				if (peers->flags & PEERS_F_DONOTSTOP) {
					/* unable to resync new process, current process can die now */
					jobs--;
					peers->flags &= ~PEERS_F_DONOTSTOP;
					for (st = ps->tables; st ; st = st->next)
						st->table->syncing--;
				}
			}
		}
		else if (ps->statuscode == PEER_SESS_SC_SUCCESSCODE ) {
			/* current stream active and established
			   awake stream to push remaining local updates */
			for (st = ps->tables; st ; st = st->next) {
				if ((int)(st->last_pushed - st->table->localupdate) < 0) {
					/* awake peer stream task to push local updates */
					appctx_wakeup(ps->appctx);
					break;
				}
			}
		}
	} /* stopping */
	/* Wakeup for re-connect */
	return task;
}


/*
 *
 */
void peers_init_sync(struct peers *peers)
{
	struct peer * curpeer;
	struct listener *listener;

	for (curpeer = peers->remote; curpeer; curpeer = curpeer->next) {
		peers->peers_fe->maxconn += 3;
	}

	list_for_each_entry(listener, &peers->peers_fe->conf.listeners, by_fe)
		listener->maxconn = peers->peers_fe->maxconn;
	peers->sync_task = task_new();
	peers->sync_task->process = process_peer_sync;
	peers->sync_task->expire = TICK_ETERNITY;
	peers->sync_task->context = (void *)peers;
	peers->sighandler = signal_register_task(0, peers->sync_task, 0);
	task_wakeup(peers->sync_task, TASK_WOKEN_INIT);
}



/*
 * Function used to register a table for sync on a group of peers
 *
 */
void peers_register_table(struct peers *peers, struct stktable *table)
{
	struct shared_table *st;
	struct peer * curpeer;
	int id = 0;

	for (curpeer = peers->remote; curpeer; curpeer = curpeer->next) {
		st = (struct shared_table *)calloc(1,sizeof(struct shared_table));
		st->table = table;
		st->next = curpeer->tables;
		if (curpeer->tables)
			id = curpeer->tables->local_id;
		st->local_id = id + 1;

		curpeer->tables = st;
	}

	table->sync_task = peers->sync_task;
}

