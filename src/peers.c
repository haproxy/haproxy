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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <import/eb32tree.h>
#include <import/ebmbtree.h>
#include <import/ebpttree.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/cli.h>
#include <haproxy/dict.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/frontend.h>
#include <haproxy/net_helper.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/peers.h>
#include <haproxy/proxy.h>
#include <haproxy/sc_strm.h>
#include <haproxy/session-t.h>
#include <haproxy/signal.h>
#include <haproxy/stats-t.h>
#include <haproxy/stconn.h>
#include <haproxy/stick_table.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>

/***********************************/
/* Current shared table sync state */
/***********************************/
#define SHTABLE_F_TEACH_STAGE1      0x00000001 /* Teach state 1 complete */
#define SHTABLE_F_TEACH_STAGE2      0x00000002 /* Teach state 2 complete */


#define PEER_RESYNC_TIMEOUT         5000 /* 5 seconds */
#define PEER_RECONNECT_TIMEOUT      5000 /* 5 seconds */
#define PEER_LOCAL_RECONNECT_TIMEOUT 500 /* 500ms */
#define PEER_HEARTBEAT_TIMEOUT      3000 /* 3 seconds */

/* default maximum of updates sent at once */
#define PEER_DEF_MAX_UPDATES_AT_ONCE      200

/* flags for "show peers" */
#define PEERS_SHOW_F_DICT           0x00000001 /* also show the contents of the dictionary */

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
	PEER_MSG_CTRL_HEARTBEAT,
};

/*****************************/
/* error message types       */
/*****************************/
enum {
	PEER_MSG_ERR_PROTOCOL = 0,
	PEER_MSG_ERR_SIZELIMIT,
};

/* network key types;
 * network types were directly and mistakenly
 * mapped on sample types, to keep backward
 * compatiblitiy we keep those values but
 * we now use a internal/network mapping
 * to avoid further mistakes adding or
 * modifying internals types
 */
enum {
        PEER_KT_ANY = 0,  /* any type */
        PEER_KT_RESV1,    /* UNUSED */
        PEER_KT_SINT,     /* signed 64bits integer type */
        PEER_KT_RESV3,    /* UNUSED */
        PEER_KT_IPV4,     /* ipv4 type */
        PEER_KT_IPV6,     /* ipv6 type */
        PEER_KT_STR,      /* char string type */
        PEER_KT_BIN,      /* buffer type */
        PEER_KT_TYPES     /* number of types, must always be last */
};

/* Map used to retrieve network type from internal type
 * Note: Undeclared mapping maps entry to PEER_KT_ANY == 0
 */
static int peer_net_key_type[SMP_TYPES] = {
	[SMP_T_SINT] = PEER_KT_SINT,
	[SMP_T_IPV4] = PEER_KT_IPV4,
	[SMP_T_IPV6] = PEER_KT_IPV6,
	[SMP_T_STR]  = PEER_KT_STR,
	[SMP_T_BIN]  = PEER_KT_BIN,
};

/* Map used to retrieve internal type from external type
 * Note: Undeclared mapping maps entry to SMP_T_ANY == 0
 */
static int peer_int_key_type[PEER_KT_TYPES] = {
	[PEER_KT_SINT] = SMP_T_SINT,
	[PEER_KT_IPV4] = SMP_T_IPV4,
	[PEER_KT_IPV6] = SMP_T_IPV6,
	[PEER_KT_STR]  = SMP_T_STR,
	[PEER_KT_BIN]  = SMP_T_BIN,
};

/*
 * Parameters used by functions to build peer protocol messages. */
struct peer_prep_params {
	struct {
		struct peer *peer;
	} hello;
	struct {
		unsigned int st1;
	} error_status;
	struct {
		struct stksess *stksess;
		struct shared_table *shared_table;
		unsigned int updateid;
		int use_identifier;
		int use_timed;
		struct peer *peer;
	} updt;
	struct {
		struct shared_table *shared_table;
	} swtch;
	struct {
		struct shared_table *shared_table;
	} ack;
	struct {
		unsigned char head[2];
	} control;
	struct {
		unsigned char head[2];
	} error;
};

/*******************************/
/* stick table sync mesg types */
/* Note: ids >= 128 contains   */
/* id message contains data     */
/*******************************/
#define PEER_MSG_STKT_UPDATE           0x80
#define PEER_MSG_STKT_INCUPDATE        0x81
#define PEER_MSG_STKT_DEFINE           0x82
#define PEER_MSG_STKT_SWITCH           0x83
#define PEER_MSG_STKT_ACK              0x84
#define PEER_MSG_STKT_UPDATE_TIMED     0x85
#define PEER_MSG_STKT_INCUPDATE_TIMED  0x86
/* All the stick-table message identifiers abova have the #7 bit set */
#define PEER_MSG_STKT_BIT                 7
#define PEER_MSG_STKT_BIT_MASK         (1 << PEER_MSG_STKT_BIT)

/* The maximum length of an encoded data length. */
#define PEER_MSG_ENC_LENGTH_MAXLEN    5

/* Minimum 64-bits value encoded with 2 bytes */
#define PEER_ENC_2BYTES_MIN                                  0xf0 /*               0xf0 (or 240) */
/* 3 bytes */
#define PEER_ENC_3BYTES_MIN  ((1ULL << 11) | PEER_ENC_2BYTES_MIN) /*              0x8f0 (or 2288) */
/* 4 bytes */
#define PEER_ENC_4BYTES_MIN  ((1ULL << 18) | PEER_ENC_3BYTES_MIN) /*            0x408f0 (or 264432) */
/* 5 bytes */
#define PEER_ENC_5BYTES_MIN  ((1ULL << 25) | PEER_ENC_4BYTES_MIN) /*          0x20408f0 (or 33818864) */
/* 6 bytes */
#define PEER_ENC_6BYTES_MIN  ((1ULL << 32) | PEER_ENC_5BYTES_MIN) /*        0x1020408f0 (or 4328786160) */
/* 7 bytes */
#define PEER_ENC_7BYTES_MIN  ((1ULL << 39) | PEER_ENC_6BYTES_MIN) /*       0x81020408f0 (or 554084600048) */
/* 8 bytes */
#define PEER_ENC_8BYTES_MIN  ((1ULL << 46) | PEER_ENC_7BYTES_MIN) /*     0x4081020408f0 (or 70922828777712) */
/* 9 bytes */
#define PEER_ENC_9BYTES_MIN  ((1ULL << 53) | PEER_ENC_8BYTES_MIN) /*   0x204081020408f0 (or 9078122083518704) */
/* 10 bytes */
#define PEER_ENC_10BYTES_MIN ((1ULL << 60) | PEER_ENC_9BYTES_MIN) /* 0x10204081020408f0 (or 1161999626690365680) */

/* #7 bit used to detect the last byte to be encoded */
#define PEER_ENC_STOP_BIT         7
/* The byte minimum value with #7 bit set */
#define PEER_ENC_STOP_BYTE        (1 << PEER_ENC_STOP_BIT)
/* The left most number of bits set for PEER_ENC_2BYTES_MIN */
#define PEER_ENC_2BYTES_MIN_BITS  4

#define PEER_MSG_HEADER_LEN               2

#define PEER_STKT_CACHE_MAX_ENTRIES       128

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

#define PEER_SESS_SC_CONNECTCODE    100 /* connect in progress */
#define PEER_SESS_SC_CONNECTEDCODE  110 /* tcp connect success */

#define PEER_SESS_SC_SUCCESSCODE    200 /* accept or connect successful */

#define PEER_SESS_SC_TRYAGAIN       300 /* try again later */

#define PEER_SESS_SC_ERRPROTO       501 /* error protocol */
#define PEER_SESS_SC_ERRVERSION     502 /* unknown protocol version */
#define PEER_SESS_SC_ERRHOST        503 /* bad host name */
#define PEER_SESS_SC_ERRPEER        504 /* unknown peer */

#define PEER_SESSION_PROTO_NAME         "HAProxyS"
#define PEER_MAJOR_VER        2
#define PEER_MINOR_VER        1
#define PEER_DWNGRD_MINOR_VER 0

static size_t proto_len = sizeof(PEER_SESSION_PROTO_NAME) - 1;
struct peers *cfg_peers = NULL;
static int peers_max_updates_at_once = PEER_DEF_MAX_UPDATES_AT_ONCE;
static void peer_session_forceshutdown(struct peer *peer);

static struct ebpt_node *dcache_tx_insert(struct dcache *dc,
                                          struct dcache_tx_entry *i);
static inline void flush_dcache(struct peer *peer);

/* trace source and events */
static void peers_trace(enum trace_level level, uint64_t mask,
                        const struct trace_source *src,
                        const struct ist where, const struct ist func,
                        const void *a1, const void *a2, const void *a3, const void *a4);

static const struct trace_event peers_trace_events[] = {
#define PEERS_EV_UPDTMSG         (1 << 0)
	{ .mask = PEERS_EV_UPDTMSG,    .name = "updtmsg",      .desc = "update message received" },
#define PEERS_EV_ACKMSG          (1 << 1)
	{ .mask = PEERS_EV_ACKMSG,     .name = "ackmsg",       .desc = "ack message received" },
#define PEERS_EV_SWTCMSG         (1 << 2)
	{ .mask = PEERS_EV_SWTCMSG,    .name = "swtcmsg",      .desc = "switch message received" },
#define PEERS_EV_DEFMSG          (1 << 3)
	{ .mask = PEERS_EV_DEFMSG,     .name = "defmsg",       .desc = "definition message received" },
#define PEERS_EV_CTRLMSG         (1 << 4)
	{ .mask = PEERS_EV_CTRLMSG,    .name = "ctrlmsg",      .desc = "control message sent/received" },
#define PEERS_EV_SESSREL         (1 << 5)
	{ .mask = PEERS_EV_SESSREL,    .name = "sessrl",       .desc = "peer session releasing" },
#define PEERS_EV_PROTOERR        (1 << 6)
	{ .mask = PEERS_EV_PROTOERR,   .name = "protoerr",     .desc = "protocol error" },
	{ }
};

static const struct name_desc peers_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name="peers", .desc="Peers protocol" },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc peers_trace_decoding[] = {
#define PEERS_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
	{ /* end */ }
};


struct trace_source trace_peers = {
	.name = IST("peers"),
	.desc = "Peers protocol",
	.arg_def = TRC_ARG1_CONN,  /* TRACE()'s first argument is always a connection */
	.default_cb = peers_trace,
	.known_events = peers_trace_events,
	.lockon_args = peers_trace_lockon_args,
	.decoding = peers_trace_decoding,
	.report_events = ~0,  /* report everything by default */
};

/* Return peer control message types as strings (only for debugging purpose). */
static inline char *ctrl_msg_type_str(unsigned int type)
{
	switch (type) {
	case PEER_MSG_CTRL_RESYNCREQ:
		return "RESYNCREQ";
	case PEER_MSG_CTRL_RESYNCFINISHED:
		return "RESYNCFINISHED";
	case PEER_MSG_CTRL_RESYNCPARTIAL:
		return "RESYNCPARTIAL";
	case PEER_MSG_CTRL_RESYNCCONFIRM:
		return "RESYNCCONFIRM";
	case PEER_MSG_CTRL_HEARTBEAT:
		return "HEARTBEAT";
	default:
		return "???";
	}
}

#define TRACE_SOURCE    &trace_peers
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

static void peers_trace(enum trace_level level, uint64_t mask,
                        const struct trace_source *src,
                        const struct ist where, const struct ist func,
                        const void *a1, const void *a2, const void *a3, const void *a4)
{
	if (mask & (PEERS_EV_UPDTMSG|PEERS_EV_ACKMSG|PEERS_EV_SWTCMSG)) {
		if (a2) {
			const struct peer *peer = a2;

			chunk_appendf(&trace_buf, " peer=%s", peer->id);
		}
		if (a3) {
			const char *p = a3;

			chunk_appendf(&trace_buf, " @%p", p);
		}
		if (a4) {
			const size_t *val = a4;

			chunk_appendf(&trace_buf, " %llu", (unsigned long long)*val);
		}
	}

	if (mask & PEERS_EV_DEFMSG) {
		if (a2) {
			const struct peer *peer = a2;

			chunk_appendf(&trace_buf, " peer=%s", peer->id);
		}
		if (a3) {
			const char *p = a3;

			chunk_appendf(&trace_buf, " @%p", p);
		}
		if (a4) {
			const int *val = a4;

			chunk_appendf(&trace_buf, " %d", *val);
		}
	}

	if (mask & PEERS_EV_CTRLMSG) {
		if (a2) {
			const unsigned char *ctrl_msg_type = a2;

			chunk_appendf(&trace_buf, " %s", ctrl_msg_type_str(*ctrl_msg_type));

		}
		if (a3) {
			const char *local_peer = a3;

			chunk_appendf(&trace_buf, " %s", local_peer);
		}

		if (a4) {
			const char *remote_peer = a4;

			chunk_appendf(&trace_buf, " -> %s", remote_peer);
		}
	}

	if (mask & (PEERS_EV_SESSREL|PEERS_EV_PROTOERR)) {
		if (a2) {
			const struct peer *peer = a2;
			struct peers *peers = NULL;

			if (peer->appctx)
				peers = peer->peers;

			if (peers)
				chunk_appendf(&trace_buf, " %s", peers->local->id);
			chunk_appendf(&trace_buf, " -> %s", peer->id);
		}

		if (a3) {
			const int *prev_state = a3;

			chunk_appendf(&trace_buf, " prev_state=%d\n", *prev_state);
		}
	}
}

static const char *statuscode_str(int statuscode)
{
	switch (statuscode) {
	case PEER_SESS_SC_CONNECTCODE:
		return "CONN";
	case PEER_SESS_SC_CONNECTEDCODE:
		return "HSHK";
	case PEER_SESS_SC_SUCCESSCODE:
		return "ESTA";
	case PEER_SESS_SC_TRYAGAIN:
		return "RETR";
	case PEER_SESS_SC_ERRPROTO:
		return "PROT";
	case PEER_SESS_SC_ERRVERSION:
		return "VERS";
	case PEER_SESS_SC_ERRHOST:
		return "NAME";
	case PEER_SESS_SC_ERRPEER:
		return "UNKN";
	default:
		return "NONE";
	}
}

static const char *peer_app_state_str(enum peer_app_state appstate)
{
	switch (appstate) {
	case PEER_APP_ST_STOPPED:
		return "STOPPED";
	case PEER_APP_ST_STARTING:
		return "STARTING";
	case PEER_APP_ST_RUNNING:
		return "RUNNING";
	case PEER_APP_ST_STOPPING:
		return "STOPPING";
	default:
		return "UNKNOWN";
	}
}

static const char *peer_learn_state_str(enum peer_learn_state learnstate)
{
	switch (learnstate) {
	case PEER_LR_ST_NOTASSIGNED:
		return "NOTASSIGNED";
	case PEER_LR_ST_ASSIGNED:
		return "ASSIGNED";
	case PEER_LR_ST_PROCESSING:
		return "PROCESSING";
	case PEER_LR_ST_FINISHED:
		return "FINISHED";
	default:
		return "UNKNOWN";
	}
}

/* This function encode an uint64 to 'dynamic' length format.
   The encoded value is written at address *str, and the
   caller must assure that size after *str is large enough.
   At return, the *str is set at the next Byte after then
   encoded integer. The function returns then length of the
   encoded integer in Bytes */
int intencode(uint64_t i, char **str) {
	int idx = 0;
	unsigned char *msg;

	msg = (unsigned char *)*str;
	if (i < PEER_ENC_2BYTES_MIN) {
		msg[0] = (unsigned char)i;
		*str = (char *)&msg[idx+1];
		return (idx+1);
	}

	msg[idx] =(unsigned char)i | PEER_ENC_2BYTES_MIN;
	i = (i - PEER_ENC_2BYTES_MIN) >> PEER_ENC_2BYTES_MIN_BITS;
	while (i >= PEER_ENC_STOP_BYTE) {
		msg[++idx] = (unsigned char)i | PEER_ENC_STOP_BYTE;
		i = (i - PEER_ENC_STOP_BYTE) >> PEER_ENC_STOP_BIT;
	}
	msg[++idx] = (unsigned char)i;
	*str = (char *)&msg[idx+1];
	return (idx+1);
}


/* This function returns a decoded 64bits unsigned integer
 * from a varint
 *
 * Calling:
 * - *str must point on the first byte of the buffer to decode.
 * - end must point on the next byte after the end of the buffer
 *   we are authorized to parse (buf + buflen)
 *
 * At return:
 *
 * On success *str will point at the byte following
 * the fully decoded integer into the buffer. and
 * the decoded value is returned.
 *
 * If end is reached before the integer was fully decoded,
 * *str is set to NULL and the caller have to check this
 * to know  there is a decoding error. In this case
 * the returned integer is also forced to 0
 */
uint64_t intdecode(char **str, char *end)
{
	unsigned char *msg;
	uint64_t i;
	int shift;

	if (!*str)
		return 0;

	msg = (unsigned char *)*str;
	if (msg >= (unsigned char *)end)
		goto fail;

	i = *(msg++);
	if (i >= PEER_ENC_2BYTES_MIN) {
		shift = PEER_ENC_2BYTES_MIN_BITS;
		do {
			if (msg >= (unsigned char *)end)
				goto fail;
			i += (uint64_t)*msg << shift;
			shift += PEER_ENC_STOP_BIT;
		} while (*(msg++) >= PEER_ENC_STOP_BYTE);
	}
	*str = (char *)msg;
	return i;

 fail:
	*str = NULL;
	return 0;
}

/*
 * Build a "hello" peer protocol message.
 * Return the number of written bytes written to build this messages if succeeded,
 * 0 if not.
 */
static int peer_prepare_hellomsg(char *msg, size_t size, struct peer_prep_params *p)
{
	int min_ver, ret;
	struct peer *peer;

	peer = p->hello.peer;
	min_ver = (peer->flags & PEER_F_DWNGRD) ? PEER_DWNGRD_MINOR_VER : PEER_MINOR_VER;
	/* Prepare headers */
	ret = snprintf(msg, size, PEER_SESSION_PROTO_NAME " %d.%d\n%s\n%s %d %d\n",
		       (int)PEER_MAJOR_VER, min_ver, peer->id, localpeer, (int)getpid(), (int)1);
	if (ret >= size)
		return 0;

	return ret;
}

/*
 * Build a "handshake succeeded" status message.
 * Return the number of written bytes written to build this messages if succeeded,
 * 0 if not.
 */
static int peer_prepare_status_successmsg(char *msg, size_t size, struct peer_prep_params *p)
{
	int ret;

	ret = snprintf(msg, size, "%d\n", (int)PEER_SESS_SC_SUCCESSCODE);
	if (ret >= size)
		return 0;

	return ret;
}

/*
 * Build an error status message.
 * Return the number of written bytes written to build this messages if succeeded,
 * 0 if not.
 */
static int peer_prepare_status_errormsg(char *msg, size_t size, struct peer_prep_params *p)
{
	int ret;
	unsigned int st1;

	st1 = p->error_status.st1;
	ret = snprintf(msg, size, "%u\n", st1);
	if (ret >= size)
		return 0;

	return ret;
}

/* Set the stick-table UPDATE message type byte at <msg_type> address,
 * depending on <use_identifier> and <use_timed> boolean parameters.
 * Always successful.
 */
static inline void peer_set_update_msg_type(char *msg_type, int use_identifier, int use_timed)
{
	if (use_timed) {
		if (use_identifier)
			*msg_type = PEER_MSG_STKT_UPDATE_TIMED;
		else
			*msg_type = PEER_MSG_STKT_INCUPDATE_TIMED;
	}
	else {
		if (use_identifier)
			*msg_type = PEER_MSG_STKT_UPDATE;
		else
			*msg_type = PEER_MSG_STKT_INCUPDATE;
	}
}
/*
 * This prepare the data update message on the stick session <ts>, <st> is the considered
 * stick table.
 *  <msg> is a buffer of <size> to receive data message content
 * If function returns 0, the caller should consider we were unable to encode this message (TODO:
 * check size)
 */
static int peer_prepare_updatemsg(char *msg, size_t size, struct peer_prep_params *p)
{
	uint32_t netinteger;
	unsigned short datalen;
	char *cursor, *datamsg;
	unsigned int data_type;
	void *data_ptr;
	struct stksess *ts;
	struct shared_table *st;
	unsigned int updateid;
	int use_identifier;
	int use_timed;
	struct peer *peer;

	ts = p->updt.stksess;
	st = p->updt.shared_table;
	updateid = p->updt.updateid;
	use_identifier = p->updt.use_identifier;
	use_timed = p->updt.use_timed;
	peer = p->updt.peer;

	cursor = datamsg = msg + PEER_MSG_HEADER_LEN + PEER_MSG_ENC_LENGTH_MAXLEN;

	/* construct message */

	/* check if we need to send the update identifier */
	if (!st->last_pushed || updateid < st->last_pushed || ((updateid - st->last_pushed) != 1)) {
		use_identifier = 1;
	}

	/* encode update identifier if needed */
	if (use_identifier)  {
		netinteger = htonl(updateid);
		memcpy(cursor, &netinteger, sizeof(netinteger));
		cursor += sizeof(netinteger);
	}

	if (use_timed) {
		netinteger = htonl(tick_remain(now_ms, ts->expire));
		memcpy(cursor, &netinteger, sizeof(netinteger));
		cursor += sizeof(netinteger);
	}

	/* encode the key */
	if (st->table->type == SMP_T_STR) {
		int stlen = strlen((char *)ts->key.key);

		intencode(stlen, &cursor);
		memcpy(cursor, ts->key.key, stlen);
		cursor += stlen;
	}
	else if (st->table->type == SMP_T_SINT) {
		netinteger = htonl(read_u32(ts->key.key));
		memcpy(cursor, &netinteger, sizeof(netinteger));
		cursor += sizeof(netinteger);
	}
	else {
		memcpy(cursor, ts->key.key, st->table->key_size);
		cursor += st->table->key_size;
	}

	HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &ts->lock);
	/* encode values */
	for (data_type = 0 ; data_type < STKTABLE_DATA_TYPES ; data_type++) {

		data_ptr = stktable_data_ptr(st->table, ts, data_type);
		if (data_ptr) {
			/* in case of array all elements use
			 * the same std_type and they are linearly
			 * encoded.
			 */
			if (stktable_data_types[data_type].is_array) {
				unsigned int idx = 0;

				switch (stktable_data_types[data_type].std_type) {
				case STD_T_SINT: {
					int data;

					do {
						data = stktable_data_cast(data_ptr, std_t_sint);
						intencode(data, &cursor);

						data_ptr = stktable_data_ptr_idx(st->table, ts, data_type, ++idx);
					} while(data_ptr);
					break;
				}
				case STD_T_UINT: {
					unsigned int data;

					do {
						data = stktable_data_cast(data_ptr, std_t_uint);
						intencode(data, &cursor);

						data_ptr = stktable_data_ptr_idx(st->table, ts, data_type, ++idx);
					} while(data_ptr);
					break;
				}
				case STD_T_ULL: {
					unsigned long long data;

					do {
						data = stktable_data_cast(data_ptr, std_t_ull);
						intencode(data, &cursor);

						data_ptr = stktable_data_ptr_idx(st->table, ts, data_type, ++idx);
					} while(data_ptr);
					break;
				}
				case STD_T_FRQP: {
					struct freq_ctr *frqp;

					do {
						frqp = &stktable_data_cast(data_ptr, std_t_frqp);
						intencode((unsigned int)(now_ms - frqp->curr_tick), &cursor);
						intencode(frqp->curr_ctr, &cursor);
						intencode(frqp->prev_ctr, &cursor);

						data_ptr = stktable_data_ptr_idx(st->table, ts, data_type, ++idx);
					} while(data_ptr);
					break;
				}
				}

				/* array elements fully encoded
				 * proceed next data_type.
				 */
				continue;
			}
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
					struct freq_ctr *frqp;

					frqp = &stktable_data_cast(data_ptr, std_t_frqp);
					intencode((unsigned int)(now_ms - frqp->curr_tick), &cursor);
					intencode(frqp->curr_ctr, &cursor);
					intencode(frqp->prev_ctr, &cursor);
					break;
				}
				case STD_T_DICT: {
					struct dict_entry *de;
					struct ebpt_node *cached_de;
					struct dcache_tx_entry cde = { };
					char *beg, *end;
					size_t value_len, data_len;
					struct dcache *dc;

					de = stktable_data_cast(data_ptr, std_t_dict);
					if (!de) {
						/* No entry */
						intencode(0, &cursor);
						break;
					}

					dc = peer->dcache;
					cde.entry.key = de;
					cached_de = dcache_tx_insert(dc, &cde);
					if (cached_de == &cde.entry) {
						if (cde.id + 1 >= PEER_ENC_2BYTES_MIN)
							break;
						/* Encode the length of the remaining data -> 1 */
						intencode(1, &cursor);
						/* Encode the cache entry ID */
						intencode(cde.id + 1, &cursor);
					}
					else {
						/* Leave enough room to encode the remaining data length. */
						end = beg = cursor + PEER_MSG_ENC_LENGTH_MAXLEN;
						/* Encode the dictionary entry key */
						intencode(cde.id + 1, &end);
						/* Encode the length of the dictionary entry data */
						value_len = de->len;
						intencode(value_len, &end);
						/* Copy the data */
						memcpy(end, de->value.key, value_len);
						end += value_len;
						/* Encode the length of the data */
						data_len = end - beg;
						intencode(data_len, &cursor);
						memmove(cursor, beg, data_len);
						cursor += data_len;
					}
					break;
				}
			}
		}
	}
	HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);

	/* Compute datalen */
	datalen = (cursor - datamsg);

	/*  prepare message header */
	msg[0] = PEER_MSG_CLASS_STICKTABLE;
	peer_set_update_msg_type(&msg[1], use_identifier, use_timed);
	cursor = &msg[2];
	intencode(datalen, &cursor);

	/* move data after header */
	memmove(cursor, datamsg, datalen);

	/* return header size + data_len */
	return (cursor - msg) + datalen;
}

/*
 * This prepare the switch table message to targeted share table <st>.
 *  <msg> is a buffer of <size> to receive data message content
 * If function returns 0, the caller should consider we were unable to encode this message (TODO:
 * check size)
 */
static int peer_prepare_switchmsg(char *msg, size_t size, struct peer_prep_params *params)
{
	int len;
	unsigned short datalen;
	struct buffer *chunk;
	char *cursor, *datamsg, *chunkp, *chunkq;
	uint64_t data = 0;
	unsigned int data_type;
	struct shared_table *st;

	st = params->swtch.shared_table;
	cursor = datamsg = msg + PEER_MSG_HEADER_LEN + PEER_MSG_ENC_LENGTH_MAXLEN;

	/* Encode data */

	/* encode local id */
	intencode(st->local_id, &cursor);

	/* encode table name */
	len = strlen(st->table->nid);
	intencode(len, &cursor);
	memcpy(cursor, st->table->nid, len);
	cursor += len;

	/* encode table type */

	intencode(peer_net_key_type[st->table->type], &cursor);

	/* encode table key size */
	intencode(st->table->key_size, &cursor);

	chunk = get_trash_chunk();
	chunkp = chunkq = chunk->area;
	/* encode available known data types in table */
	for (data_type = 0 ; data_type < STKTABLE_DATA_TYPES ; data_type++) {
		if (st->table->data_ofs[data_type]) {
			/* stored data types parameters are all linearly encoded
			 * at the end of the 'table definition' message.
			 *
			 * Currently only array data_types and and data_types
			 * using freq_counter base type have parameters:
			 *
			 * - array has always at least one parameter set to the
			 *   number of elements.
			 *
			 * - array of base-type freq_counters has an additional
			 *  parameter set to the period used to compute those
			 *  freq_counters.
			 *
			 * - simple freq counter has a parameter set to the period
			 *   used to compute
			 *
			 *  A set of parameter for a datatype MUST BE prefixed
			 *  by the data-type id itself:
			 *  This is useless because the data_types are ordered and
			 *  the data_type bitfield already gives the information of
			 *  stored types, but it was designed this way when the
			 *  push of period parameter was added for freq counters
			 *  and we don't want to break the compatibility.
			 *
			 */
			if (stktable_data_types[data_type].is_array) {
				/* This is an array type so we first encode
				 * the data_type itself to prefix parameters
				 */
				intencode(data_type, &chunkq);

				/* We encode the first parameter which is
				 * the number of elements of this array
				 */
				intencode(st->table->data_nbelem[data_type], &chunkq);

				/* for array of freq counters, there is an additional
				 * period parameter to encode
				 */
				if (stktable_data_types[data_type].std_type == STD_T_FRQP)
					intencode(st->table->data_arg[data_type].u, &chunkq);
			}
			else if (stktable_data_types[data_type].std_type == STD_T_FRQP) {
				/* this datatype is a simple freq counter not part
				 * of an array. We encode the data_type itself
				 * to prefix the 'period' parameter
				 */
				intencode(data_type, &chunkq);
				intencode(st->table->data_arg[data_type].u, &chunkq);
			}
			/* set the bit corresponding to stored data type */
			data |= 1ULL << data_type;
		}
	}
	intencode(data, &cursor);

	/* Encode stick-table entries duration. */
	intencode(st->table->expire, &cursor);

	if (chunkq > chunkp) {
		chunk->data = chunkq - chunkp;
		memcpy(cursor, chunk->area, chunk->data);
		cursor += chunk->data;
	}

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
 *  <msg> is a buffer of <size> to receive data message content
 * If function returns 0, the caller should consider we were unable to encode this message (TODO:
 * check size)
 */
static int peer_prepare_ackmsg(char *msg, size_t size, struct peer_prep_params *p)
{
	unsigned short datalen;
	char *cursor, *datamsg;
	uint32_t netinteger;
	struct shared_table *st;

	cursor = datamsg = msg + PEER_MSG_HEADER_LEN + PEER_MSG_ENC_LENGTH_MAXLEN;

	st = p->ack.shared_table;
	intencode(st->remote_id, &cursor);
	netinteger = htonl(st->last_get);
	memcpy(cursor, &netinteger, sizeof(netinteger));
	cursor += sizeof(netinteger);

	/* Compute datalen */
	datalen = (cursor - datamsg);

	/*  prepare message header */
	msg[0] = PEER_MSG_CLASS_STICKTABLE;
	msg[1] = PEER_MSG_STKT_ACK;
	cursor = &msg[2];
	intencode(datalen, &cursor);

	/* move data after header */
	memmove(cursor, datamsg, datalen);

	/* return header size + data_len */
	return (cursor - msg) + datalen;
}

/*
 * Function to deinit connected peer
 */
void __peer_session_deinit(struct peer *peer)
{
	struct peers *peers = peer->peers;
	int thr;

	if (!peers || !peer->appctx)
		return;

	thr = peer->appctx->t->tid;
	HA_ATOMIC_DEC(&peers->applet_count[thr]);

	if (peer->appctx->st0 == PEER_SESS_ST_WAITMSG)
		HA_ATOMIC_DEC(&connected_peers);

	HA_ATOMIC_DEC(&active_peers);

	flush_dcache(peer);

	/* Re-init current table pointers to force announcement on re-connect */
	peer->remote_table = peer->last_local_table = peer->stop_local_table = NULL;
	peer->appctx = NULL;

        /* reset teaching flags to 0 */
        peer->flags &= ~PEER_TEACH_FLAGS;

	/* Mark the peer as stopping and wait for the sync task */
	peer->flags |= PEER_F_WAIT_SYNCTASK_ACK;
	peer->appstate = PEER_APP_ST_STOPPING;

	task_wakeup(peers->sync_task, TASK_WOKEN_MSG);
}

static int peer_session_init(struct appctx *appctx)
{
	struct peer *peer = appctx->svcctx;
	struct stream *s;
	struct sockaddr_storage *addr = NULL;

	if (!sockaddr_alloc(&addr, &peer->srv->addr, sizeof(peer->srv->addr)))
		goto out_error;
	set_host_port(addr, peer->srv->svc_port);

	if (appctx_finalize_startup(appctx, peer->peers->peers_fe, &BUF_NULL) == -1)
		goto out_free_addr;

	s = appctx_strm(appctx);
	/* applet is waiting for data */
	applet_need_more_data(appctx);
	appctx_wakeup(appctx);

	/* initiate an outgoing connection */
	s->scb->dst = addr;
	s->scb->flags |= (SC_FL_RCV_ONCE|SC_FL_NOLINGER);
	s->flags = SF_ASSIGNED;
	s->target = peer_session_target(peer, s);

	s->do_log = NULL;
	s->uniq_id = 0;

	_HA_ATOMIC_INC(&active_peers);
	return 0;

 out_free_addr:
	sockaddr_free(&addr);
 out_error:
	return -1;
}

/*
 * Callback to release a session with a peer
 */
static void peer_session_release(struct appctx *appctx)
{
	struct peer *peer = appctx->svcctx;

	TRACE_PROTO("releasing peer session", PEERS_EV_SESSREL, NULL, peer);
	/* appctx->svcctx is not a peer session */
	if (appctx->st0 < PEER_SESS_ST_SENDSUCCESS)
		return;

	/* peer session identified */
	if (peer) {
		HA_SPIN_LOCK(PEER_LOCK, &peer->lock);
		if (peer->appctx == appctx)
			__peer_session_deinit(peer);
		peer->flags &= ~PEER_F_ALIVE;
		HA_SPIN_UNLOCK(PEER_LOCK, &peer->lock);
	}
}

/* Retrieve the major and minor versions of peers protocol
 * announced by a remote peer. <str> is a null-terminated
 * string with the following format: "<maj_ver>.<min_ver>".
 */
static int peer_get_version(const char *str,
                            unsigned int *maj_ver, unsigned int *min_ver)
{
	unsigned int majv, minv;
	const char *pos, *saved;
	const char *end;

	saved = pos = str;
	end = str + strlen(str);

	majv = read_uint(&pos, end);
	if (saved == pos || *pos++ != '.')
		return -1;

	saved = pos;
	minv = read_uint(&pos, end);
	if (saved == pos || pos != end)
		return -1;

	*maj_ver = majv;
	*min_ver = minv;

	return 0;
}

/*
 * Parse a line terminated by an optional '\r' character, followed by a mandatory
 * '\n' character.
 * Returns 1 if succeeded or 0 if a '\n' character could not be found, and -1 if
 * a line could not be read because the communication channel is closed.
 */
static inline int peer_getline(struct appctx  *appctx)
{
	struct stconn *sc = appctx_sc(appctx);
	int n;

	n = co_getline(sc_oc(sc), trash.area, trash.size);
	if (!n)
		return 0;

	if (n < 0 || trash.area[n - 1] != '\n') {
		appctx->st0 = PEER_SESS_ST_END;
		return -1;
	}

	if (n > 1 && (trash.area[n - 2] == '\r'))
		trash.area[n - 2] = 0;
	else
		trash.area[n - 1] = 0;

	co_skip(sc_oc(sc), n);

	return n;
}

/*
 * Send a message after having called <peer_prepare_msg> to build it.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_msg(struct appctx *appctx,
                                int (*peer_prepare_msg)(char *, size_t, struct peer_prep_params *),
                                struct peer_prep_params *params)
{
	int ret, msglen;

	msglen = peer_prepare_msg(trash.area, trash.size, params);
	if (!msglen) {
		/* internal error: message does not fit in trash */
		appctx->st0 = PEER_SESS_ST_END;
		return 0;
	}

	/* message to buffer */
	ret = applet_putblk(appctx, trash.area, msglen);
	if (ret <= 0) {
		if (ret != -1)
			appctx->st0 = PEER_SESS_ST_END;
	}

	return ret;
}

/*
 * Send a hello message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_hellomsg(struct appctx *appctx, struct peer *peer)
{
	struct peer_prep_params p = {
		.hello.peer = peer,
	};

	return peer_send_msg(appctx, peer_prepare_hellomsg, &p);
}

/*
 * Send a success peer handshake status message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_status_successmsg(struct appctx *appctx)
{
	return peer_send_msg(appctx, peer_prepare_status_successmsg, NULL);
}

/*
 * Send a peer handshake status error message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_status_errormsg(struct appctx *appctx)
{
	struct peer_prep_params p = {
		.error_status.st1 = appctx->st1,
	};

	return peer_send_msg(appctx, peer_prepare_status_errormsg, &p);
}

/*
 * Send a stick-table switch message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_switchmsg(struct shared_table *st, struct appctx *appctx)
{
	struct peer_prep_params p = {
		.swtch.shared_table = st,
	};

	return peer_send_msg(appctx, peer_prepare_switchmsg, &p);
}

/*
 * Send a stick-table update acknowledgement message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_ackmsg(struct shared_table *st, struct appctx *appctx)
{
	struct peer_prep_params p = {
		.ack.shared_table = st,
	};

	return peer_send_msg(appctx, peer_prepare_ackmsg, &p);
}

/*
 * Send a stick-table update message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_updatemsg(struct shared_table *st, struct appctx *appctx, struct stksess *ts,
                                      unsigned int updateid, int use_identifier, int use_timed)
{
	struct peer_prep_params p = {
		.updt = {
			.stksess = ts,
			.shared_table = st,
			.updateid = updateid,
			.use_identifier = use_identifier,
			.use_timed = use_timed,
			.peer = appctx->svcctx,
		},
	};

	return peer_send_msg(appctx, peer_prepare_updatemsg, &p);
}

/*
 * Build a peer protocol control class message.
 * Returns the number of written bytes used to build the message if succeeded,
 * 0 if not.
 */
static int peer_prepare_control_msg(char *msg, size_t size, struct peer_prep_params *p)
{
	if (size < sizeof p->control.head)
		return 0;

	msg[0] = p->control.head[0];
	msg[1] = p->control.head[1];

	return 2;
}

/*
 * Send a stick-table synchronization request message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appctx st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_resync_reqmsg(struct appctx *appctx,
                                          struct peer *peer, struct peers *peers)
{
	struct peer_prep_params p = {
		.control.head = { PEER_MSG_CLASS_CONTROL, PEER_MSG_CTRL_RESYNCREQ, },
	};

	TRACE_PROTO("send control message", PEERS_EV_CTRLMSG,
	            NULL, &p.control.head[1], peers->local->id, peer->id);

	return peer_send_msg(appctx, peer_prepare_control_msg, &p);
}

/*
 * Send a stick-table synchronization confirmation message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appctx st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_resync_confirmsg(struct appctx *appctx,
                                             struct peer *peer, struct peers *peers)
{
	struct peer_prep_params p = {
		.control.head = { PEER_MSG_CLASS_CONTROL, PEER_MSG_CTRL_RESYNCCONFIRM, },
	};

	TRACE_PROTO("send control message", PEERS_EV_CTRLMSG,
	            NULL, &p.control.head[1], peers->local->id, peer->id);

	return peer_send_msg(appctx, peer_prepare_control_msg, &p);
}

/*
 * Send a stick-table synchronization finished message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appctx st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_resync_finishedmsg(struct appctx *appctx,
                                               struct peer *peer, struct peers *peers)
{
	struct peer_prep_params p = {
		.control.head = { PEER_MSG_CLASS_CONTROL, },
	};

	p.control.head[1] = (HA_ATOMIC_LOAD(&peers->flags) & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FINISHED ?
		PEER_MSG_CTRL_RESYNCFINISHED : PEER_MSG_CTRL_RESYNCPARTIAL;

	TRACE_PROTO("send control message", PEERS_EV_CTRLMSG,
	            NULL, &p.control.head[1], peers->local->id, peer->id);

	return peer_send_msg(appctx, peer_prepare_control_msg, &p);
}

/*
 * Send a heartbeat message.
 * Return 0 if the message could not be built modifying the appctx st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appctx st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_heartbeatmsg(struct appctx *appctx,
                                         struct peer *peer, struct peers *peers)
{
	struct peer_prep_params p = {
		.control.head = { PEER_MSG_CLASS_CONTROL, PEER_MSG_CTRL_HEARTBEAT, },
	};

	TRACE_PROTO("send control message", PEERS_EV_CTRLMSG,
	            NULL, &p.control.head[1], peers->local->id, peer->id);

	return peer_send_msg(appctx, peer_prepare_control_msg, &p);
}

/*
 * Build a peer protocol error class message.
 * Returns the number of written bytes used to build the message if succeeded,
 * 0 if not.
 */
static int peer_prepare_error_msg(char *msg, size_t size, struct peer_prep_params *p)
{
	if (size < sizeof p->error.head)
		return 0;

	msg[0] = p->error.head[0];
	msg[1] = p->error.head[1];

	return 2;
}

/*
 * Send a "size limit reached" error message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appctx st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_error_size_limitmsg(struct appctx *appctx)
{
	struct peer_prep_params p = {
		.error.head = { PEER_MSG_CLASS_ERROR, PEER_MSG_ERR_SIZELIMIT, },
	};

	return peer_send_msg(appctx, peer_prepare_error_msg, &p);
}

/*
 * Send a "peer protocol" error message.
 * Return 0 if the message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appctx st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_error_protomsg(struct appctx *appctx)
{
	struct peer_prep_params p = {
		.error.head = { PEER_MSG_CLASS_ERROR, PEER_MSG_ERR_PROTOCOL, },
	};

	return peer_send_msg(appctx, peer_prepare_error_msg, &p);
}

/*
 * Function used to lookup for recent stick-table updates associated with
 * <st> shared stick-table when a lesson must be taught a peer (learn state is not PEER_LR_ST_NOTASSIGNED).
 */
static inline struct stksess *peer_teach_process_stksess_lookup(struct shared_table *st)
{
	struct eb32_node *eb;
	struct stksess *ret;

	eb = eb32_lookup_ge(&st->table->updates, st->last_pushed+1);
	if (!eb) {
		eb = eb32_first(&st->table->updates);
		if (!eb || (eb->key == st->last_pushed)) {
			st->table->commitupdate = st->last_pushed = st->table->localupdate;
			return NULL;
		}
	}

	/* if distance between the last pushed and the retrieved key
	 * is greater than the distance last_pushed and the local_update
	 * this means we are beyond localupdate.
	 */
	if ((eb->key - st->last_pushed) > (st->table->localupdate - st->last_pushed)) {
		st->table->commitupdate = st->last_pushed = st->table->localupdate;
		return NULL;
	}

	ret = eb32_entry(eb, struct stksess, upd);
	if (!_HA_ATOMIC_LOAD(&ret->seen))
		_HA_ATOMIC_STORE(&ret->seen, 1);
	return ret;
}

/*
 * Function used to lookup for recent stick-table updates associated with
 * <st> shared stick-table during teach state 1 step.
 */
static inline struct stksess *peer_teach_stage1_stksess_lookup(struct shared_table *st)
{
	struct eb32_node *eb;
	struct stksess *ret;

	eb = eb32_lookup_ge(&st->table->updates, st->last_pushed+1);
	if (!eb) {
		st->flags |= SHTABLE_F_TEACH_STAGE1;
		eb = eb32_first(&st->table->updates);
		if (eb)
			st->last_pushed = eb->key - 1;
		return NULL;
	}

	ret = eb32_entry(eb, struct stksess, upd);
	if (!_HA_ATOMIC_LOAD(&ret->seen))
		_HA_ATOMIC_STORE(&ret->seen, 1);
	return ret;
}

/*
 * Function used to lookup for recent stick-table updates associated with
 * <st> shared stick-table during teach state 2 step.
 */
static inline struct stksess *peer_teach_stage2_stksess_lookup(struct shared_table *st)
{
	struct eb32_node *eb;
	struct stksess *ret;

	eb = eb32_lookup_ge(&st->table->updates, st->last_pushed+1);
	if (!eb || eb->key > st->teaching_origin) {
		st->flags |= SHTABLE_F_TEACH_STAGE2;
		return NULL;
	}

	ret = eb32_entry(eb, struct stksess, upd);
	if (!_HA_ATOMIC_LOAD(&ret->seen))
		_HA_ATOMIC_STORE(&ret->seen, 1);
	return ret;
}

/*
 * Generic function to emit update messages for <st> stick-table when a lesson must
 * be taught to the peer <p>.
 *
 * This function temporary unlock/lock <st> when it sends stick-table updates or
 * when decrementing its refcount in case of any error when it sends this updates.
 * It must be called with the stick-table lock released.
 *
 * Return 0 if any message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 * If it returns 0 or -1, this function leave <st> locked if already locked when entering this function
 * unlocked if not already locked when entering this function.
 */
static inline int peer_send_teachmsgs(struct appctx *appctx, struct peer *p,
                                      struct stksess *(*peer_stksess_lookup)(struct shared_table *),
                                      struct shared_table *st)
{
	int ret, new_pushed, use_timed;
	int updates_sent = 0;

	ret = 1;
	use_timed = 0;
	if (st != p->last_local_table) {
		ret = peer_send_switchmsg(st, appctx);
		if (ret <= 0)
			return ret;

		p->last_local_table = st;
	}

	if (peer_stksess_lookup != peer_teach_process_stksess_lookup)
		use_timed = !(p->flags & PEER_F_DWNGRD);

	/* We force new pushed to 1 to force identifier in update message */
	new_pushed = 1;

	HA_RWLOCK_RDLOCK(STK_TABLE_LOCK, &st->table->updt_lock);

	while (1) {
		struct stksess *ts;
		unsigned updateid;

		/* push local updates */
		ts = peer_stksess_lookup(st);
		if (!ts) {
			ret = 1; // done
			break;
		}

		updateid = ts->upd.key;
		if (p->srv->shard && ts->shard != p->srv->shard) {
			/* Skip this entry */
			st->last_pushed = updateid;
			new_pushed = 1;
			continue;
		}

		HA_ATOMIC_INC(&ts->ref_cnt);
		HA_RWLOCK_RDUNLOCK(STK_TABLE_LOCK, &st->table->updt_lock);

		ret = peer_send_updatemsg(st, appctx, ts, updateid, new_pushed, use_timed);
		HA_RWLOCK_RDLOCK(STK_TABLE_LOCK, &st->table->updt_lock);
		HA_ATOMIC_DEC(&ts->ref_cnt);
		if (ret <= 0)
			break;

		st->last_pushed = updateid;

		if (peer_stksess_lookup == peer_teach_process_stksess_lookup) {
			uint commitid = _HA_ATOMIC_LOAD(&st->table->commitupdate);

			while ((int)(updateid - commitid) > 0) {
				if (_HA_ATOMIC_CAS(&st->table->commitupdate, &commitid, updateid))
					break;
				__ha_cpu_relax();
			}
		}

		/* identifier may not needed in next update message */
		new_pushed = 0;

		updates_sent++;
		if (updates_sent >= peers_max_updates_at_once) {
			applet_have_more_data(appctx);
			ret = -1;
			break;
		}
	}

 out:
	HA_RWLOCK_RDUNLOCK(STK_TABLE_LOCK, &st->table->updt_lock);
	return ret;
}

/*
 * Function to emit update messages for <st> stick-table when a lesson must
 * be taught to the peer <p> (learn state is not PEER_LR_ST_NOTASSIGNED).
 *
 * Note that <st> shared stick-table is locked when calling this function, and
 * the lock is dropped then re-acquired.
 *
 * Return 0 if any message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_teach_process_msgs(struct appctx *appctx, struct peer *p,
                                               struct shared_table *st)
{
	return peer_send_teachmsgs(appctx, p, peer_teach_process_stksess_lookup, st);
}

/*
 * Function to emit update messages for <st> stick-table when a lesson must
 * be taught to the peer <p> during teach state 1 step. It must be called with
 * the stick-table lock released.
 *
 * Return 0 if any message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_teach_stage1_msgs(struct appctx *appctx, struct peer *p,
                                              struct shared_table *st)
{
	return peer_send_teachmsgs(appctx, p, peer_teach_stage1_stksess_lookup, st);
}

/*
 * Function to emit update messages for <st> stick-table when a lesson must
 * be taught to the peer <p> during teach state 1 step. It must be called with
 * the stick-table lock released.
 *
 * Return 0 if any message could not be built modifying the appcxt st0 to PEER_SESS_ST_END value.
 * Returns -1 if there was not enough room left to send the message,
 * any other negative returned value must  be considered as an error with an appcxt st0
 * returned value equal to PEER_SESS_ST_END.
 */
static inline int peer_send_teach_stage2_msgs(struct appctx *appctx, struct peer *p,
                                              struct shared_table *st)
{
	return peer_send_teachmsgs(appctx, p, peer_teach_stage2_stksess_lookup, st);
}


/*
 * Function used to parse a stick-table update message after it has been received
 * by <p> peer with <msg_cur> as address of the pointer to the position in the
 * receipt buffer with <msg_end> being position of the end of the stick-table message.
 * Update <msg_curr> accordingly to the peer protocol specs if no peer protocol error
 * was encountered.
 * <exp> must be set if the stick-table entry expires.
 * <updt> must be set for  PEER_MSG_STKT_UPDATE or PEER_MSG_STKT_UPDATE_TIMED stick-table
 * messages, in this case the stick-table update message is received with a stick-table
 * update ID.
 * <totl> is the length of the stick-table update message computed upon receipt.
 */
static int peer_treat_updatemsg(struct appctx *appctx, struct peer *p, int updt, int exp,
                                char **msg_cur, char *msg_end, int msg_len, int totl)
{
	struct shared_table *st = p->remote_table;
	struct stktable *table;
	struct stksess *ts, *newts;
	struct stksess *wts = NULL; /* write_to stksess */
	uint32_t update;
	int expire;
	unsigned int data_type;
	size_t keylen;
	void *data_ptr;
	char *msg_save;

	TRACE_ENTER(PEERS_EV_UPDTMSG, NULL, p);
	/* Here we have data message */
	if (!st)
		goto ignore_msg;

	table = st->table;

	expire = MS_TO_TICKS(table->expire);

	if (updt) {
		if (msg_len < sizeof(update)) {
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
			goto malformed_exit;
		}

		memcpy(&update, *msg_cur, sizeof(update));
		*msg_cur += sizeof(update);
		st->last_get = htonl(update);
	}
	else {
		st->last_get++;
	}

	if (exp) {
		size_t expire_sz = sizeof expire;

		if (*msg_cur + expire_sz > msg_end) {
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
			            NULL, p, *msg_cur);
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
			            NULL, p, msg_end, &expire_sz);
			goto malformed_exit;
		}

		memcpy(&expire, *msg_cur, expire_sz);
		*msg_cur += expire_sz;
		expire = ntohl(expire);
	}

	newts = stksess_new(table, NULL);
	if (!newts)
		goto ignore_msg;

	if (table->type == SMP_T_STR) {
		unsigned int to_read, to_store;

		to_read = intdecode(msg_cur, msg_end);
		if (!*msg_cur) {
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
			goto malformed_free_newts;
		}

		to_store = MIN(to_read, table->key_size - 1);
		if (*msg_cur + to_store > msg_end) {
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
			            NULL, p, *msg_cur);
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
			            NULL, p, msg_end, &to_store);
			goto malformed_free_newts;
		}

		keylen = to_store;
		memcpy(newts->key.key, *msg_cur, keylen);
		newts->key.key[keylen] = 0;
		*msg_cur += to_read;
	}
	else if (table->type == SMP_T_SINT) {
		unsigned int netinteger;

		if (*msg_cur + sizeof(netinteger) > msg_end) {
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
			            NULL, p, *msg_cur);
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
			            NULL, p, msg_end);
			goto malformed_free_newts;
		}

		keylen = sizeof(netinteger);
		memcpy(&netinteger, *msg_cur, keylen);
		netinteger = ntohl(netinteger);
		memcpy(newts->key.key, &netinteger, keylen);
		*msg_cur += keylen;
	}
	else {
		if (*msg_cur + table->key_size > msg_end) {
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
			            NULL, p, *msg_cur);
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
			            NULL, p, msg_end, &table->key_size);
			goto malformed_free_newts;
		}

		keylen = table->key_size;
		memcpy(newts->key.key, *msg_cur, keylen);
		*msg_cur += keylen;
	}

	newts->shard = stktable_get_key_shard(table, newts->key.key, keylen);

	/* lookup for existing entry */
	ts = stktable_set_entry(table, newts);
	if (ts != newts) {
		stksess_free(table, newts);
		newts = NULL;
	}

	msg_save = *msg_cur;

 update_wts:

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

	for (data_type = 0 ; data_type < STKTABLE_DATA_TYPES ; data_type++) {
		uint64_t decoded_int;
		unsigned int idx;
		int ignore = 0;

		if (!((1ULL << data_type) & st->remote_data))
			continue;

		/* We shouldn't learn local-only values unless the table is
		 * considered as "recv-only". Also, when handling the write_to
		 * table we must ignore types that can be processed so we don't
		 * interfere with any potential arithmetic logic performed on
		 * them (ie: cumulative counters).
		 */
		if ((stktable_data_types[data_type].is_local &&
		     !(table->flags & STK_FL_RECV_ONLY)) ||
		    (table != st->table && !stktable_data_types[data_type].as_is))
			ignore = 1;

		if (stktable_data_types[data_type].is_array) {
			/* in case of array all elements
			 * use the same std_type and they
			 * are linearly encoded.
			 * The number of elements was provided
			 * by table definition message
			 */
			switch (stktable_data_types[data_type].std_type) {
			case STD_T_SINT:
				for (idx = 0; idx < st->remote_data_nbelem[data_type]; idx++) {
					decoded_int = intdecode(msg_cur, msg_end);
					if (!*msg_cur) {
						TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
						goto malformed_unlock;
					}

					data_ptr = stktable_data_ptr_idx(table, ts, data_type, idx);
					if (data_ptr && !ignore)
						stktable_data_cast(data_ptr, std_t_sint) = decoded_int;
				}
				break;
			case STD_T_UINT:
				for (idx = 0; idx < st->remote_data_nbelem[data_type]; idx++) {
					decoded_int = intdecode(msg_cur, msg_end);
					if (!*msg_cur) {
						TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
						goto malformed_unlock;
					}

					data_ptr = stktable_data_ptr_idx(table, ts, data_type, idx);
					if (data_ptr && !ignore)
						stktable_data_cast(data_ptr, std_t_uint) = decoded_int;
				}
				break;
			case STD_T_ULL:
				for (idx = 0; idx < st->remote_data_nbelem[data_type]; idx++) {
					decoded_int = intdecode(msg_cur, msg_end);
					if (!*msg_cur) {
						TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
						goto malformed_unlock;
					}

					data_ptr = stktable_data_ptr_idx(table, ts, data_type, idx);
					if (data_ptr && !ignore)
						stktable_data_cast(data_ptr, std_t_ull) = decoded_int;
				}
				break;
			case STD_T_FRQP:
				for (idx = 0; idx < st->remote_data_nbelem[data_type]; idx++) {
					struct freq_ctr data;

					/* First bit is reserved for the freq_ctr lock
					 * Note: here we're still protected by the stksess lock
					 * so we don't need to update the update the freq_ctr
					 * using its internal lock.
					 */

					decoded_int = intdecode(msg_cur, msg_end);
					if (!*msg_cur) {
						TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
						goto malformed_unlock;
					}

					data.curr_tick = tick_add(now_ms, -decoded_int) & ~0x1;
					data.curr_ctr = intdecode(msg_cur, msg_end);
					if (!*msg_cur) {
						TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
						goto malformed_unlock;
					}

					data.prev_ctr = intdecode(msg_cur, msg_end);
					if (!*msg_cur) {
						TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
						goto malformed_unlock;
					}

					data_ptr = stktable_data_ptr_idx(table, ts, data_type, idx);
					if (data_ptr && !ignore)
						stktable_data_cast(data_ptr, std_t_frqp) = data;
				}
				break;
			}

			/* array is fully decoded
			 * proceed next data_type.
			 */
			continue;
		}
		decoded_int = intdecode(msg_cur, msg_end);
		if (!*msg_cur) {
			TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
			goto malformed_unlock;
		}

		switch (stktable_data_types[data_type].std_type) {
		case STD_T_SINT:
			data_ptr = stktable_data_ptr(table, ts, data_type);
			if (data_ptr && !ignore)
				stktable_data_cast(data_ptr, std_t_sint) = decoded_int;
			break;

		case STD_T_UINT:
			data_ptr = stktable_data_ptr(table, ts, data_type);
			if (data_ptr && !ignore)
				stktable_data_cast(data_ptr, std_t_uint) = decoded_int;
			break;

		case STD_T_ULL:
			data_ptr = stktable_data_ptr(table, ts, data_type);
			if (data_ptr && !ignore)
				stktable_data_cast(data_ptr, std_t_ull) = decoded_int;
			break;

		case STD_T_FRQP: {
			struct freq_ctr data;

			/* First bit is reserved for the freq_ctr lock
			Note: here we're still protected by the stksess lock
			so we don't need to update the update the freq_ctr
			using its internal lock.
			*/

			data.curr_tick = tick_add(now_ms, -decoded_int) & ~0x1;
			data.curr_ctr = intdecode(msg_cur, msg_end);
			if (!*msg_cur) {
				TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
				goto malformed_unlock;
			}

			data.prev_ctr = intdecode(msg_cur, msg_end);
			if (!*msg_cur) {
				TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG, NULL, p);
				goto malformed_unlock;
			}

			data_ptr = stktable_data_ptr(table, ts, data_type);
			if (data_ptr && !ignore)
				stktable_data_cast(data_ptr, std_t_frqp) = data;
			break;
		}
		case STD_T_DICT: {
			struct buffer *chunk;
			size_t data_len, value_len;
			unsigned int id;
			struct dict_entry *de;
			struct dcache *dc;
			char *end;

			if (!decoded_int) {
				/* No entry. */
				break;
			}
			data_len = decoded_int;
			if (*msg_cur + data_len > msg_end) {
				TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
				            NULL, p, *msg_cur);
				TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
				            NULL, p, msg_end, &data_len);
				goto malformed_unlock;
			}

			/* Compute the end of the current data, <msg_end> being at the end of
			 * the entire message.
			 */
			end = *msg_cur + data_len;
			id = intdecode(msg_cur, end);
			if (!*msg_cur || !id) {
				TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
				            NULL, p, *msg_cur, &id);
				goto malformed_unlock;
			}

			dc = p->dcache;
			if (*msg_cur == end) {
				/* Dictionary entry key without value. */
				if (id > dc->max_entries) {
					TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
					            NULL, p, NULL, &id);
					goto malformed_unlock;
				}
				/* IDs sent over the network are numbered from 1. */
				de = dc->rx[id - 1].de;
			}
			else {
				chunk = get_trash_chunk();
				value_len = intdecode(msg_cur, end);
				if (!*msg_cur || *msg_cur + value_len > end ||
					unlikely(value_len + 1 >= chunk->size)) {
					TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
					            NULL, p, *msg_cur, &value_len);
					TRACE_PROTO("malformed message", PEERS_EV_UPDTMSG,
					            NULL, p, end, &chunk->size);
					goto malformed_unlock;
				}

				chunk_memcpy(chunk, *msg_cur, value_len);
				chunk->area[chunk->data] = '\0';
				*msg_cur += value_len;

				de = dict_insert(&server_key_dict, chunk->area);
				dict_entry_unref(&server_key_dict, dc->rx[id - 1].de);
				dc->rx[id - 1].de = de;
			}
			if (de) {
				data_ptr = stktable_data_ptr(table, ts, data_type);
				if (data_ptr && !ignore) {
					HA_ATOMIC_INC(&de->refcount);
					stktable_data_cast(data_ptr, std_t_dict) = de;
				}
			}
			break;
		}
		}
	}

	if (st->table->write_to.t && table != st->table->write_to.t) {
		struct stktable_key stkey = { .key = ts->key.key, .key_len = keylen };

		/* While we're still under the main ts lock, try to get related
		 * write_to stksess with main ts key
		 */
		wts = stktable_get_entry(st->table->write_to.t, &stkey);
	}

	/* Force new expiration */
	ts->expire = tick_add(now_ms, expire);

	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
	stktable_touch_remote(table, ts, 1);

	/* Entry was just learned from a peer, we want to notify this peer
	 * if we happen to modify it. Thus let's consider at least one
	 * peer has seen the update (ie: the peer that sent us the update)
	 */
	HA_ATOMIC_STORE(&ts->seen, 1);

	if (wts) {
		/* Start over the message decoding for wts as we got a valid stksess
		 * for write_to table, so we need to refresh the entry with supported
		 * values.
		 *
		 * We prefer to do the decoding a second time even though it might
		 * cost a bit more than copying from main ts to wts, but doing so
		 * enables us to get rid of main ts lock: we only need the wts lock
		 * since upstream data is still available in msg_cur
		 */
		ts = wts;
		table = st->table->write_to.t;
		wts = NULL; /* so we don't get back here */
		*msg_cur = msg_save;
		goto update_wts;
	}

 ignore_msg:
	TRACE_LEAVE(PEERS_EV_UPDTMSG, NULL, p);
	return 1;

 malformed_unlock:
	/* malformed message */
	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
	stktable_touch_remote(st->table, ts, 1);
	appctx->st0 = PEER_SESS_ST_ERRPROTO;
	TRACE_DEVEL("leaving in error", PEERS_EV_UPDTMSG);
	return 0;

 malformed_free_newts:
	/* malformed message */
	stksess_free(st->table, newts);
 malformed_exit:
	appctx->st0 = PEER_SESS_ST_ERRPROTO;
	TRACE_DEVEL("leaving in error", PEERS_EV_UPDTMSG);
	return 0;
}

/*
 * Function used to parse a stick-table update acknowledgement message after it
 * has been received by <p> peer with <msg_cur> as address of the pointer to the position in the
 * receipt buffer with <msg_end> being the position of the end of the stick-table message.
 * Update <msg_curr> accordingly to the peer protocol specs if no peer protocol error
 * was encountered.
 * Return 1 if succeeded, 0 if not with the appctx state st0 set to PEER_SESS_ST_ERRPROTO.
 */
static inline int peer_treat_ackmsg(struct appctx *appctx, struct peer *p,
                                    char **msg_cur, char *msg_end)
{
	/* ack message */
	uint32_t table_id ;
	uint32_t update;
	struct shared_table *st;

	/* ignore ack during teaching process */
	if (p->flags & PEER_F_TEACH_PROCESS)
		return 1;

	table_id = intdecode(msg_cur, msg_end);
	if (!*msg_cur || (*msg_cur + sizeof(update) > msg_end)) {
		/* malformed message */

		TRACE_PROTO("malformed message", PEERS_EV_ACKMSG,
					NULL, p, *msg_cur);
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	memcpy(&update, *msg_cur, sizeof(update));
	update = ntohl(update);

	for (st = p->tables; st; st = st->next) {
		if (st->local_id == table_id) {
			st->update = update;
			break;
		}
	}

	return 1;
}

/*
 * Function used to parse a stick-table switch message after it has been received
 * by <p> peer with <msg_cur> as address of the pointer to the position in the
 * receipt buffer with <msg_end> being the position of the end of the stick-table message.
 * Update <msg_curr> accordingly to the peer protocol specs if no peer protocol error
 * was encountered.
 * Return 1 if succeeded, 0 if not with the appctx state st0 set to PEER_SESS_ST_ERRPROTO.
 */
static inline int peer_treat_switchmsg(struct appctx *appctx, struct peer *p,
                                      char **msg_cur, char *msg_end)
{
	struct shared_table *st;
	int table_id;

	table_id = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		TRACE_PROTO("malformed message", PEERS_EV_SWTCMSG, NULL, p);
		/* malformed message */
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	p->remote_table = NULL;
	for (st = p->tables; st; st = st->next) {
		if (st->remote_id == table_id) {
			p->remote_table = st;
			break;
		}
	}

	return 1;
}

/*
 * Function used to parse a stick-table definition message after it has been received
 * by <p> peer with <msg_cur> as address of the pointer to the position in the
 * receipt buffer with <msg_end> being the position of the end of the stick-table message.
 * Update <msg_curr> accordingly to the peer protocol specs if no peer protocol error
 * was encountered.
 * <totl> is the length of the stick-table update message computed upon receipt.
 * Return 1 if succeeded, 0 if not with the appctx state st0 set to PEER_SESS_ST_ERRPROTO.
 */
static inline int peer_treat_definemsg(struct appctx *appctx, struct peer *p,
                                      char **msg_cur, char *msg_end, int totl)
{
	int table_id_len;
	struct shared_table *st;
	int table_type;
	int table_keylen;
	int table_id;
	uint64_t table_data;

	table_id = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		TRACE_PROTO("malformed message", PEERS_EV_DEFMSG, NULL, p);
		goto malformed_exit;
	}

	table_id_len = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		TRACE_PROTO("malformed message", PEERS_EV_DEFMSG, NULL, p, *msg_cur);
		goto malformed_exit;
	}

	p->remote_table = NULL;
	if (!table_id_len || (*msg_cur + table_id_len) >= msg_end) {
		TRACE_PROTO("malformed message", PEERS_EV_DEFMSG, NULL, p, *msg_cur, &table_id_len);
		goto malformed_exit;
	}

	for (st = p->tables; st; st = st->next) {
		/* Reset IDs */
		if (st->remote_id == table_id)
			st->remote_id = 0;

		if (!p->remote_table && (table_id_len == strlen(st->table->nid)) &&
		    (memcmp(st->table->nid, *msg_cur, table_id_len) == 0))
			p->remote_table = st;
	}

	if (!p->remote_table) {
		TRACE_PROTO("ignored message", PEERS_EV_DEFMSG, NULL, p);
		goto ignore_msg;
	}

	*msg_cur += table_id_len;
	if (*msg_cur >= msg_end) {
		TRACE_PROTO("malformed message", PEERS_EV_DEFMSG, NULL, p);
		goto malformed_exit;
	}

	table_type = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		TRACE_PROTO("malformed message", PEERS_EV_DEFMSG, NULL, p);
		goto malformed_exit;
	}

	table_keylen = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		TRACE_PROTO("malformed message", PEERS_EV_DEFMSG, NULL, p);
		goto malformed_exit;
	}

	table_data = intdecode(msg_cur, msg_end);
	if (!*msg_cur) {
		TRACE_PROTO("malformed message", PEERS_EV_DEFMSG, NULL, p);
		goto malformed_exit;
	}

	if (p->remote_table->table->type != peer_int_key_type[table_type]
		|| p->remote_table->table->key_size != table_keylen) {
		p->remote_table = NULL;
		TRACE_PROTO("ignored message", PEERS_EV_DEFMSG, NULL, p);
		goto ignore_msg;
	}

	/* Check if there there is the additional expire data */
	intdecode(msg_cur, msg_end);
	if (*msg_cur) {
		uint64_t data_type;
		uint64_t type;

		/* This define contains the expire data so we consider
		 * it also contain all data_types parameters.
		 */
		for (data_type = 0; data_type < STKTABLE_DATA_TYPES; data_type++) {
			if (table_data & (1ULL << data_type)) {
				if (stktable_data_types[data_type].is_array) {
					/* This should be an array
					 * so we parse the data_type prefix
					 * because we must have parameters.
					 */
					type = intdecode(msg_cur, msg_end);
					if (!*msg_cur) {
						p->remote_table = NULL;
						TRACE_PROTO("missing meta data for array", PEERS_EV_DEFMSG, NULL, p);
						goto ignore_msg;
					}

					/* check if the data_type match the current from the bitfield */
					if (type != data_type) {
						p->remote_table = NULL;
						TRACE_PROTO("meta data mismatch type", PEERS_EV_DEFMSG, NULL, p);
						goto ignore_msg;
					}

					/* decode the nbelem of the array */
					p->remote_table->remote_data_nbelem[type] = intdecode(msg_cur, msg_end);
					if (!*msg_cur) {
						p->remote_table = NULL;
						TRACE_PROTO("missing array size meta data for array", PEERS_EV_DEFMSG, NULL, p);
						goto ignore_msg;
					}

					/* if it is an array of frqp, we must also have the period to decode */
					if (stktable_data_types[data_type].std_type == STD_T_FRQP) {
						intdecode(msg_cur, msg_end);
						if (!*msg_cur) {
							p->remote_table = NULL;
							TRACE_PROTO("missing period for frqp", PEERS_EV_DEFMSG, NULL, p);
							goto ignore_msg;
						}
					}
				}
				else if (stktable_data_types[data_type].std_type == STD_T_FRQP) {
					/* This should be a std freq counter data_type
					 * so we parse the data_type prefix
					 * because we must have parameters.
					 */
					type = intdecode(msg_cur, msg_end);
					if (!*msg_cur) {
						p->remote_table = NULL;
						TRACE_PROTO("missing meta data for frqp", PEERS_EV_DEFMSG, NULL, p);
						goto ignore_msg;
					}

					/* check if the data_type match the current from the bitfield */
					if (type != data_type) {
						p->remote_table = NULL;
						TRACE_PROTO("meta data mismatch type", PEERS_EV_DEFMSG, NULL, p);
						goto ignore_msg;
					}

					/* decode the period */
					intdecode(msg_cur, msg_end);
					if (!*msg_cur) {
						p->remote_table = NULL;
						TRACE_PROTO("missing period for frqp", PEERS_EV_DEFMSG, NULL, p);
						goto ignore_msg;
					}
				}
			}
		}
	}
	else {
		uint64_t data_type;

		/* There is not additional data but
		 * array size parameter is mandatory to parse array
		 * so we consider an error if an array data_type is define
		 * but there is no additional data.
		 */
		for (data_type = 0; data_type < STKTABLE_DATA_TYPES; data_type++) {
			if (table_data & (1ULL << data_type)) {
				if (stktable_data_types[data_type].is_array) {
					p->remote_table = NULL;
					TRACE_PROTO("missing array size meta data for array", PEERS_EV_DEFMSG, NULL, p);
					goto ignore_msg;
				}
			}
		}
	}

	p->remote_table->remote_data = table_data;
	p->remote_table->remote_id = table_id;

 ignore_msg:
	return 1;

 malformed_exit:
	/* malformed message */
	appctx->st0 = PEER_SESS_ST_ERRPROTO;
	return 0;
}

/*
 * Receive a stick-table message or pre-parse any other message.
 * The message's header will be sent into <msg_head> which must be at least
 * <msg_head_sz> bytes long (at least 7 to store 32-bit variable lengths).
 * The first two bytes are always read, and the rest is only read if the
 * first bytes indicate a stick-table message. If the message is a stick-table
 * message, the varint is decoded and the equivalent number of bytes will be
 * copied into the trash at trash.area. <totl> is incremented by the number of
 * bytes read EVEN IN CASE OF INCOMPLETE MESSAGES.
 * Returns 1 if there was no error, if not, returns 0 if not enough data were available,
 * -1 if there was an error updating the appctx state st0 accordingly.
 */
static inline int peer_recv_msg(struct appctx *appctx, char *msg_head, size_t msg_head_sz,
                                uint32_t *msg_len, int *totl)
{
	int reql;
	struct stconn *sc = appctx_sc(appctx);
	char *cur;

	reql = co_getblk(sc_oc(sc), msg_head, 2 * sizeof(char), *totl);
	if (reql <= 0) /* closed or EOL not found */
		goto incomplete;

	*totl += reql;

	if (!(msg_head[1] & PEER_MSG_STKT_BIT_MASK))
		return 1;

	/* This is a stick-table message, let's go on */

	/* Read and Decode message length */
	msg_head    += *totl;
	msg_head_sz -= *totl;
	reql = co_data(sc_oc(sc)) - *totl;
	if (reql > msg_head_sz)
		reql = msg_head_sz;

	reql = co_getblk(sc_oc(sc), msg_head, reql, *totl);
	if (reql <= 0) /* closed */
		goto incomplete;

	cur = msg_head;
	*msg_len = intdecode(&cur, cur + reql);
	if (!cur) {
		/* the number is truncated, did we read enough ? */
		if (reql < msg_head_sz)
			goto incomplete;

		/* malformed message */
		TRACE_PROTO("malformed message: too large length encoding", PEERS_EV_UPDTMSG);
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return -1;
	}
	*totl += cur - msg_head;

	/* Read message content */
	if (*msg_len) {
		if (*msg_len > trash.size) {
			/* Status code is not success, abort */
			appctx->st0 = PEER_SESS_ST_ERRSIZE;
			return -1;
		}

		reql = co_getblk(sc_oc(sc), trash.area, *msg_len, *totl);
		if (reql <= 0) /* closed */
			goto incomplete;
		*totl += reql;
	}

	return 1;

 incomplete:
	if (reql < 0 || (sc->flags & (SC_FL_SHUT_DONE|SC_FL_SHUT_WANTED))) {
		/* there was an error or the message was truncated */
		appctx->st0 = PEER_SESS_ST_END;
		return -1;
	}

	return 0;
}

/*
 * Treat the awaited message with <msg_head> as header.*
 * Return 1 if succeeded, 0 if not.
 */
static inline int peer_treat_awaited_msg(struct appctx *appctx, struct peer *peer, unsigned char *msg_head,
                                         char **msg_cur, char *msg_end, int msg_len, int totl)
{
	struct peers *peers = peer->peers;

	if (msg_head[0] == PEER_MSG_CLASS_CONTROL) {
		if (msg_head[1] == PEER_MSG_CTRL_RESYNCREQ) {
			struct shared_table *st;
			/* Reset message: remote need resync */

			TRACE_PROTO("received control message", PEERS_EV_CTRLMSG,
			            NULL, &msg_head[1], peers->local->id, peer->id);
			/* prepare tables for a global push */
			for (st = peer->tables; st; st = st->next) {
				st->teaching_origin = st->last_pushed = st->update;
				st->flags = 0;
			}

			/* reset teaching flags to 0 */
			peer->flags &= ~PEER_TEACH_FLAGS;

			/* flag to start to teach lesson */
			peer->flags |= (PEER_F_TEACH_PROCESS|PEER_F_DBG_RESYNC_REQUESTED);
		}
		else if (msg_head[1] == PEER_MSG_CTRL_RESYNCFINISHED) {
			TRACE_PROTO("received control message", PEERS_EV_CTRLMSG,
			            NULL, &msg_head[1], peers->local->id, peer->id);
			if (peer->learnstate == PEER_LR_ST_PROCESSING) {
				peer->learnstate = PEER_LR_ST_FINISHED;
				peer->flags |= PEER_F_WAIT_SYNCTASK_ACK;
				task_wakeup(peers->sync_task, TASK_WOKEN_MSG);
			}
			peer->confirm++;
		}
		else if (msg_head[1] == PEER_MSG_CTRL_RESYNCPARTIAL) {
			TRACE_PROTO("received control message", PEERS_EV_CTRLMSG,
			            NULL, &msg_head[1], peers->local->id, peer->id);
			if (peer->learnstate == PEER_LR_ST_PROCESSING) {
				peer->learnstate = PEER_LR_ST_FINISHED;
				peer->flags |= (PEER_F_LEARN_NOTUP2DATE|PEER_F_WAIT_SYNCTASK_ACK);
				task_wakeup(peers->sync_task, TASK_WOKEN_MSG);
			}
			peer->confirm++;
		}
		else if (msg_head[1] == PEER_MSG_CTRL_RESYNCCONFIRM)  {
			struct shared_table *st;

			TRACE_PROTO("received control message", PEERS_EV_CTRLMSG,
			            NULL, &msg_head[1], peers->local->id, peer->id);
			/* If stopping state */
			if (stopping) {
				/* Close session, push resync no more needed */
				peer->flags |= PEER_F_LOCAL_TEACH_COMPLETE;
				appctx->st0 = PEER_SESS_ST_END;
				return 0;
			}
			for (st = peer->tables; st; st = st->next) {
				st->update = st->last_pushed = st->teaching_origin;
				st->flags = 0;
			}

			/* reset teaching flags to 0 */
			peer->flags &= ~PEER_TEACH_FLAGS;
		}
		else if (msg_head[1] == PEER_MSG_CTRL_HEARTBEAT) {
			TRACE_PROTO("received control message", PEERS_EV_CTRLMSG,
			            NULL, &msg_head[1], peers->local->id, peer->id);
			peer->reconnect = tick_add(now_ms, MS_TO_TICKS(PEER_RECONNECT_TIMEOUT));
			peer->rx_hbt++;
		}
	}
	else if (msg_head[0] == PEER_MSG_CLASS_STICKTABLE) {
		if (msg_head[1] == PEER_MSG_STKT_DEFINE) {
			if (!peer_treat_definemsg(appctx, peer, msg_cur, msg_end, totl))
				return 0;
		}
		else if (msg_head[1] == PEER_MSG_STKT_SWITCH) {
			if (!peer_treat_switchmsg(appctx, peer, msg_cur, msg_end))
				return 0;
		}
		else if (msg_head[1] == PEER_MSG_STKT_UPDATE ||
		         msg_head[1] == PEER_MSG_STKT_INCUPDATE ||
		         msg_head[1] == PEER_MSG_STKT_UPDATE_TIMED ||
		         msg_head[1] == PEER_MSG_STKT_INCUPDATE_TIMED) {
			int update, expire;

			update = msg_head[1] == PEER_MSG_STKT_UPDATE || msg_head[1] == PEER_MSG_STKT_UPDATE_TIMED;
			expire = msg_head[1] == PEER_MSG_STKT_UPDATE_TIMED || msg_head[1] == PEER_MSG_STKT_INCUPDATE_TIMED;
			if (!peer_treat_updatemsg(appctx, peer, update, expire,
			                          msg_cur, msg_end, msg_len, totl))
				return 0;

		}
		else if (msg_head[1] == PEER_MSG_STKT_ACK) {
			if (!peer_treat_ackmsg(appctx, peer, msg_cur, msg_end))
				return 0;
		}
	}
	else if (msg_head[0] == PEER_MSG_CLASS_RESERVED) {
		appctx->st0 = PEER_SESS_ST_ERRPROTO;
		return 0;
	}

	return 1;
}


/*
 * Send any message to <peer> peer.
 * Returns 1 if succeeded, or -1 or 0 if failed.
 * -1 means an internal error occurred, 0 is for a peer protocol error leading
 * to a peer state change (from the peer I/O handler point of view).
 *
 *   - peer->last_local_table is the last table for which we send an update
 *                            messages.
 *
 *   - peer->stop_local_table is the last evaluated table. It is unset when the
 *                            teaching process starts. But we use it as a
 *                            restart point when the loop is interrupted. It is
 *                            especially useful when the number of tables exceeds
 *                            peers_max_updates_at_once value.
 *
 * When a teaching lopp is started, the peer's last_local_table is saved in a
 * local variable. This variable is used as a finish point. When the crrent
 * table is equal to it, it means all tables were evaluated, all updates where
 * sent and the teaching process is finished.
 *
 * peer->stop_local_table is always NULL when the teaching process begins. It is
 * only reset at the end. In the mean time, it always point on a table.
 */

static inline int peer_send_msgs(struct appctx *appctx,
                                 struct peer *peer, struct peers *peers)
{
	int repl;

	/* Need to request a resync (only possible for a remote peer at this stage) */
	if (peer->learnstate == PEER_LR_ST_ASSIGNED) {
		BUG_ON(peer->local);
		repl = peer_send_resync_reqmsg(appctx, peer, peers);
		if (repl <= 0)
			return repl;
		peer->learnstate = PEER_LR_ST_PROCESSING;
	}

	/* Nothing to read, now we start to write */
	if (peer->tables) {
		struct shared_table *st;
		struct shared_table *last_local_table;
		int updates = 0;

		last_local_table = peer->last_local_table;
		if (!last_local_table)
			last_local_table = peer->tables;
		if (!peer->stop_local_table)
			peer->stop_local_table = last_local_table;
		st = peer->stop_local_table->next;

		while (1) {
			if (!st)
				st = peer->tables;
			/* It remains some updates to ack */
			if (st->last_get != st->last_acked) {
				repl = peer_send_ackmsg(st, appctx);
				if (repl <= 0)
					return repl;

				st->last_acked = st->last_get;
			}

			if (!(peer->flags & PEER_F_TEACH_PROCESS)) {
				int must_send;

				HA_RWLOCK_RDLOCK(STK_TABLE_LOCK, &st->table->updt_lock);
				must_send = (peer->learnstate == PEER_LR_ST_NOTASSIGNED) && (st->last_pushed != st->table->localupdate);
				HA_RWLOCK_RDUNLOCK(STK_TABLE_LOCK, &st->table->updt_lock);

				if (must_send) {
					repl = peer_send_teach_process_msgs(appctx, peer, st);
					if (repl <= 0) {
						peer->stop_local_table = peer->last_local_table;
						return repl;
					}
				}
			}
			else if (!(peer->flags & PEER_F_TEACH_FINISHED)) {
				if (!(st->flags & SHTABLE_F_TEACH_STAGE1)) {
					repl = peer_send_teach_stage1_msgs(appctx, peer, st);
					if (repl <= 0) {
						peer->stop_local_table = peer->last_local_table;
						return repl;
					}
				}

				if (!(st->flags & SHTABLE_F_TEACH_STAGE2)) {
					repl = peer_send_teach_stage2_msgs(appctx, peer, st);
					if (repl <= 0) {
						peer->stop_local_table = peer->last_local_table;
						return repl;
					}
				}
			}

			if (st == last_local_table) {
				peer->stop_local_table = NULL;
				break;
			}

			/* This one is to be sure to restart from <st->next> if we are interrupted
			 * because of peer_send_teach_stage2_msgs or because buffer is full
			 * when sedning an ackmsg. In both cases current <st> was evaluated and
			 * we must restart from <st->next>
			 */
			peer->stop_local_table = st;

			updates++;
			if (updates >= peers_max_updates_at_once) {
				applet_have_more_data(appctx);
				return -1;
			}

			st = st->next;
		}
	}

	if ((peer->flags & PEER_F_TEACH_PROCESS) && !(peer->flags & PEER_F_TEACH_FINISHED)) {
		repl = peer_send_resync_finishedmsg(appctx, peer, peers);
		if (repl <= 0)
			return repl;

		/* flag finished message sent */
		peer->flags |= PEER_F_TEACH_FINISHED;
	}

	/* Confirm finished or partial messages */
	while (peer->confirm) {
		repl = peer_send_resync_confirmsg(appctx, peer, peers);
		if (repl <= 0)
			return repl;

		peer->confirm--;
	}

	return 1;
}

/*
 * Read and parse a first line of a "hello" peer protocol message.
 * Returns 0 if could not read a line, -1 if there was a read error or
 * the line is malformed, 1 if succeeded.
 */
static inline int peer_getline_version(struct appctx *appctx,
                                       unsigned int *maj_ver, unsigned int *min_ver)
{
	int reql;

	reql = peer_getline(appctx);
	if (!reql)
		return 0;

	if (reql < 0)
		return -1;

	/* test protocol */
	if (strncmp(PEER_SESSION_PROTO_NAME " ", trash.area, proto_len + 1) != 0) {
		appctx->st0 = PEER_SESS_ST_EXIT;
		appctx->st1 = PEER_SESS_SC_ERRPROTO;
		return -1;
	}
	if (peer_get_version(trash.area + proto_len + 1, maj_ver, min_ver) == -1 ||
		*maj_ver != PEER_MAJOR_VER || *min_ver > PEER_MINOR_VER) {
		appctx->st0 = PEER_SESS_ST_EXIT;
		appctx->st1 = PEER_SESS_SC_ERRVERSION;
		return -1;
	}

	return 1;
}

/*
 * Read and parse a second line of a "hello" peer protocol message.
 * Returns 0 if could not read a line, -1 if there was a read error or
 * the line is malformed, 1 if succeeded.
 */
static inline int peer_getline_host(struct appctx *appctx)
{
	int reql;

	reql = peer_getline(appctx);
	if (!reql)
		return 0;

	if (reql < 0)
		return -1;

	/* test hostname match */
	if (strcmp(localpeer, trash.area) != 0) {
		appctx->st0 = PEER_SESS_ST_EXIT;
		appctx->st1 = PEER_SESS_SC_ERRHOST;
		return -1;
	}

	return 1;
}

/*
 * Read and parse a last line of a "hello" peer protocol message.
 * Returns 0 if could not read a character, -1 if there was a read error or
 * the line is malformed, 1 if succeeded.
 * Set <curpeer> accordingly (the remote peer sending the "hello" message).
 */
static inline int peer_getline_last(struct appctx *appctx, struct peer **curpeer)
{
	char *p;
	int reql;
	struct peer *peer;
	struct stream *s = appctx_strm(appctx);
	struct peers *peers = strm_fe(s)->parent;

	reql = peer_getline(appctx);
	if (!reql)
		return 0;

	if (reql < 0)
		return -1;

	/* parse line "<peer name> <pid> <relative_pid>" */
	p = strchr(trash.area, ' ');
	if (!p) {
		appctx->st0 = PEER_SESS_ST_EXIT;
		appctx->st1 = PEER_SESS_SC_ERRPROTO;
		return -1;
	}
	*p = 0;

	/* lookup known peer */
	for (peer = peers->remote; peer; peer = peer->next) {
		if (strcmp(peer->id, trash.area) == 0)
			break;
	}

	/* if unknown peer */
	if (!peer) {
		appctx->st0 = PEER_SESS_ST_EXIT;
		appctx->st1 = PEER_SESS_SC_ERRPEER;
		return -1;
	}
	*curpeer = peer;

	return 1;
}

/*
 * Init <peer> peer after validating a connection at peer protocol level. It may
 * a incoming or outgoing connection. The peer init must be acknowledge by the
 * sync task. Message processing is blocked in the meanwhile.
 */
static inline void init_connected_peer(struct peer *peer, struct peers *peers)
{
	struct shared_table *st;

	peer->heartbeat = tick_add(now_ms, MS_TO_TICKS(PEER_HEARTBEAT_TIMEOUT));

	/* Init cursors */
	for (st = peer->tables; st ; st = st->next) {
		uint updateid, commitid;

		st->last_get = st->last_acked = 0;
		HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &st->table->updt_lock);
		/* if st->update appears to be in future it means
		 * that the last acked value is very old and we
		 * remain unconnected a too long time to use this
		 * acknowledgement as a reset.
		 * We should update the protocol to be able to
		 * signal the remote peer that it needs a full resync.
		 * Here a partial fix consist to set st->update at
		 * the max past value.
		 */
		if ((int)(st->table->localupdate - st->update) < 0)
			st->update = st->table->localupdate + (2147483648U);
		st->teaching_origin = st->last_pushed = st->update;
		st->flags = 0;

		updateid = st->last_pushed;
		commitid = _HA_ATOMIC_LOAD(&st->table->commitupdate);

		while ((int)(updateid - commitid) > 0) {
			if (_HA_ATOMIC_CAS(&st->table->commitupdate, &commitid, updateid))
				break;
			__ha_cpu_relax();
		}

		HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &st->table->updt_lock);
	}

	/* Awake main task to ack the new peer state */
	task_wakeup(peers->sync_task, TASK_WOKEN_MSG);

	/* Init confirm counter */
	peer->confirm = 0;

        /* reset teaching flags to 0 */
        peer->flags &= ~PEER_TEACH_FLAGS;

	if (peer->local && !(appctx_is_back(peer->appctx))) {
		/* If the local peer has established the connection (appctx is
		 * on the frontend side), flag it to start to teach lesson.
		 */
                peer->flags |= PEER_F_TEACH_PROCESS;
	}

	/* Mark the peer as starting and wait the sync task */
	peer->flags |= PEER_F_WAIT_SYNCTASK_ACK;
	peer->appstate = PEER_APP_ST_STARTING;
}

/*
 * IO Handler to handle message exchange with a peer
 */
static void peer_io_handler(struct appctx *appctx)
{
	struct stconn *sc = appctx_sc(appctx);
	struct stream *s = __sc_strm(sc);
	struct peers *curpeers = strm_fe(s)->parent;
	struct peer *curpeer = NULL;
	int reql = 0;
	int repl = 0;
	unsigned int maj_ver, min_ver;
	int prev_state;

	if (unlikely(se_fl_test(appctx->sedesc, (SE_FL_EOS|SE_FL_ERROR)))) {
		co_skip(sc_oc(sc), co_data(sc_oc(sc)));
		goto out;
	}

	/* Check if the input buffer is available. */
	if (sc_ib(sc)->size == 0) {
		sc_need_room(sc, 0);
		goto out;
	}

	while (1) {
		prev_state = appctx->st0;
switchstate:
		maj_ver = min_ver = (unsigned int)-1;
		switch(appctx->st0) {
			case PEER_SESS_ST_ACCEPT:
				prev_state = appctx->st0;
				appctx->svcctx = NULL;
				appctx->st0 = PEER_SESS_ST_GETVERSION;
				__fallthrough;
			case PEER_SESS_ST_GETVERSION:
				prev_state = appctx->st0;
				reql = peer_getline_version(appctx, &maj_ver, &min_ver);
				if (reql <= 0) {
					if (!reql)
						goto out;
					goto switchstate;
				}

				appctx->st0 = PEER_SESS_ST_GETHOST;
				__fallthrough;
			case PEER_SESS_ST_GETHOST:
				prev_state = appctx->st0;
				reql = peer_getline_host(appctx);
				if (reql <= 0) {
					if (!reql)
						goto out;
					goto switchstate;
				}

				appctx->st0 = PEER_SESS_ST_GETPEER;
				__fallthrough;
			case PEER_SESS_ST_GETPEER: {
				prev_state = appctx->st0;
				reql = peer_getline_last(appctx, &curpeer);
				if (reql <= 0) {
					if (!reql)
						goto out;
					goto switchstate;
				}

				HA_SPIN_LOCK(PEER_LOCK, &curpeer->lock);
				if (curpeer->appctx && curpeer->appctx != appctx) {
					if (curpeer->local) {
						/* Local connection, reply a retry */
						appctx->st0 = PEER_SESS_ST_EXIT;
						appctx->st1 = PEER_SESS_SC_TRYAGAIN;
						goto switchstate;
					}

					/* we're killing a connection, we must apply a random delay before
					 * retrying otherwise the other end will do the same and we can loop
					 * for a while.
					 */
					curpeer->reconnect = tick_add(now_ms, MS_TO_TICKS(50 + ha_random() % 2000));
					peer_session_forceshutdown(curpeer);

					curpeer->heartbeat = TICK_ETERNITY;
					curpeer->coll++;
				}
				if (maj_ver != (unsigned int)-1 && min_ver != (unsigned int)-1) {
					if (min_ver == PEER_DWNGRD_MINOR_VER) {
						curpeer->flags |= PEER_F_DWNGRD;
					}
					else {
						curpeer->flags &= ~PEER_F_DWNGRD;
					}
				}
				curpeer->appctx = appctx;
				curpeer->flags |= PEER_F_ALIVE;
				appctx->svcctx = curpeer;
				appctx->st0 = PEER_SESS_ST_SENDSUCCESS;
				_HA_ATOMIC_INC(&active_peers);
			}
			__fallthrough;
			case PEER_SESS_ST_SENDSUCCESS: {
				prev_state = appctx->st0;
				if (!curpeer) {
					curpeer = appctx->svcctx;
					HA_SPIN_LOCK(PEER_LOCK, &curpeer->lock);
					if (curpeer->appctx != appctx) {
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
				}

				repl = peer_send_status_successmsg(appctx);
				if (repl <= 0) {
					if (repl == -1)
						goto out;
					goto switchstate;
				}

				/* Register status code */
				curpeer->statuscode = PEER_SESS_SC_SUCCESSCODE;
				curpeer->last_hdshk = now_ms;

				init_connected_peer(curpeer, curpeers);

				/* switch to waiting message state */
				_HA_ATOMIC_INC(&connected_peers);
				appctx->st0 = PEER_SESS_ST_WAITMSG;
				goto switchstate;
			}
			case PEER_SESS_ST_CONNECT: {
				prev_state = appctx->st0;
				if (!curpeer) {
					curpeer = appctx->svcctx;
					HA_SPIN_LOCK(PEER_LOCK, &curpeer->lock);
					if (curpeer->appctx != appctx) {
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
				}

				repl = peer_send_hellomsg(appctx, curpeer);
				if (repl <= 0) {
					if (repl == -1)
						goto out;
					goto switchstate;
				}

				/* switch to the waiting statuscode state */
				appctx->st0 = PEER_SESS_ST_GETSTATUS;
			}
			__fallthrough;
			case PEER_SESS_ST_GETSTATUS: {
				prev_state = appctx->st0;
				if (!curpeer) {
					curpeer = appctx->svcctx;
					HA_SPIN_LOCK(PEER_LOCK, &curpeer->lock);
					if (curpeer->appctx != appctx) {
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
				}

				if (sc_ic(sc)->flags & CF_WROTE_DATA)
					curpeer->statuscode = PEER_SESS_SC_CONNECTEDCODE;

				reql = peer_getline(appctx);
				if (!reql)
					goto out;

				if (reql < 0)
					goto switchstate;

				/* Register status code */
				curpeer->statuscode = atoi(trash.area);
				curpeer->last_hdshk = now_ms;

				/* Awake main task */
				task_wakeup(curpeers->sync_task, TASK_WOKEN_MSG);

				/* If status code is success */
				if (curpeer->statuscode == PEER_SESS_SC_SUCCESSCODE) {
					init_connected_peer(curpeer, curpeers);
				}
				else {
					if (curpeer->statuscode == PEER_SESS_SC_ERRVERSION)
						curpeer->flags |= PEER_F_DWNGRD;
					/* Status code is not success, abort */
					appctx->st0 = PEER_SESS_ST_END;
					goto switchstate;
				}
				_HA_ATOMIC_INC(&connected_peers);
				appctx->st0 = PEER_SESS_ST_WAITMSG;
			}
			__fallthrough;
			case PEER_SESS_ST_WAITMSG: {
				uint32_t msg_len = 0;
				char *msg_cur = trash.area;
				char *msg_end = trash.area;
				unsigned char msg_head[7]; // 2 + 5 for varint32
				int totl = 0;

				prev_state = appctx->st0;
				if (!curpeer) {
					curpeer = appctx->svcctx;
					HA_SPIN_LOCK(PEER_LOCK, &curpeer->lock);
					if (curpeer->appctx != appctx) {
						appctx->st0 = PEER_SESS_ST_END;
						goto switchstate;
					}
				}

				if (curpeer->flags & PEER_F_WAIT_SYNCTASK_ACK) {
					applet_wont_consume(appctx);
					goto out;
				}
				applet_will_consume(appctx);

				/* local peer is assigned of a lesson, start it */
				if (curpeer->learnstate == PEER_LR_ST_ASSIGNED && curpeer->local)
					curpeer->learnstate = PEER_LR_ST_PROCESSING;

				reql = peer_recv_msg(appctx, (char *)msg_head, sizeof msg_head, &msg_len, &totl);
				if (reql <= 0) {
					if (reql == -1)
						goto switchstate;
					goto send_msgs;
				}

				msg_end += msg_len;
				if (!peer_treat_awaited_msg(appctx, curpeer, msg_head, &msg_cur, msg_end, msg_len, totl))
					goto switchstate;

				curpeer->flags |= PEER_F_ALIVE;

				/* skip consumed message */
				co_skip(sc_oc(sc), totl);
				/* loop on that state to peek next message */
				goto switchstate;

send_msgs:
				if (curpeer->flags & PEER_F_HEARTBEAT) {
					curpeer->flags &= ~PEER_F_HEARTBEAT;
					repl = peer_send_heartbeatmsg(appctx, curpeer, curpeers);
					if (repl <= 0) {
						if (repl == -1)
							goto out;
						goto switchstate;
					}
					curpeer->tx_hbt++;
				}
				/* we get here when a peer_recv_msg() returns 0 in reql */
				repl = peer_send_msgs(appctx, curpeer, curpeers);
				if (repl <= 0) {
					if (repl == -1)
						goto out;
					goto switchstate;
				}

				/* noting more to do */
				goto out;
			}
			case PEER_SESS_ST_EXIT:
				if (prev_state == PEER_SESS_ST_WAITMSG)
					_HA_ATOMIC_DEC(&connected_peers);
				prev_state = appctx->st0;
				if (peer_send_status_errormsg(appctx) == -1)
					goto out;
				appctx->st0 = PEER_SESS_ST_END;
				goto switchstate;
			case PEER_SESS_ST_ERRSIZE: {
				if (prev_state == PEER_SESS_ST_WAITMSG)
					_HA_ATOMIC_DEC(&connected_peers);
				prev_state = appctx->st0;
				if (peer_send_error_size_limitmsg(appctx) == -1)
					goto out;
				appctx->st0 = PEER_SESS_ST_END;
				goto switchstate;
			}
			case PEER_SESS_ST_ERRPROTO: {
				TRACE_PROTO("protocol error", PEERS_EV_PROTOERR,
				            NULL, curpeer, &prev_state);
				if (curpeer)
					curpeer->proto_err++;
				if (prev_state == PEER_SESS_ST_WAITMSG)
					_HA_ATOMIC_DEC(&connected_peers);
				prev_state = appctx->st0;
				if (peer_send_error_protomsg(appctx) == -1) {
					TRACE_PROTO("could not send error message", PEERS_EV_PROTOERR);
					goto out;
				}
				appctx->st0 = PEER_SESS_ST_END;
				prev_state = appctx->st0;
			}
			__fallthrough;
			case PEER_SESS_ST_END: {
				if (prev_state == PEER_SESS_ST_WAITMSG)
					_HA_ATOMIC_DEC(&connected_peers);
				prev_state = appctx->st0;
				if (curpeer) {
					HA_SPIN_UNLOCK(PEER_LOCK, &curpeer->lock);
					curpeer = NULL;
				}
				se_fl_set(appctx->sedesc, SE_FL_EOS|SE_FL_EOI);
				co_skip(sc_oc(sc), co_data(sc_oc(sc)));
				goto out;
			}
		}
	}
out:
	sc_opposite(sc)->flags |= SC_FL_RCV_ONCE;

	if (curpeer)
		HA_SPIN_UNLOCK(PEER_LOCK, &curpeer->lock);
	return;
}

static struct applet peer_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<PEER>", /* used for logging */
	.fct = peer_io_handler,
	.init = peer_session_init,
	.release = peer_session_release,
};


/*
 * Use this function to force a close of a peer session
 */
static void peer_session_forceshutdown(struct peer *peer)
{
	struct appctx *appctx = peer->appctx;

	/* Note that the peer sessions which have just been created
	 * (->st0 == PEER_SESS_ST_CONNECT) must not
	 * be shutdown, if not, the TCP session will never be closed
	 * and stay in CLOSE_WAIT state after having been closed by
	 * the remote side.
	 */
	if (!appctx || appctx->st0 == PEER_SESS_ST_CONNECT)
		return;

	if (appctx->applet != &peer_applet)
		return;

	__peer_session_deinit(peer);

	appctx->st0 = PEER_SESS_ST_END;
	appctx_wakeup(appctx);
}

/* Pre-configures a peers frontend to accept incoming connections */
void peers_setup_frontend(struct proxy *fe)
{
	fe->fe_counters.last_change = ns_to_sec(now_ns);
	fe->cap = PR_CAP_FE | PR_CAP_BE;
	fe->mode = PR_MODE_PEERS;
	fe->maxconn = 0;
	fe->conn_retries = CONN_RETRIES;
	fe->timeout.connect = MS_TO_TICKS(1000);
	fe->timeout.client = MS_TO_TICKS(5000);
	fe->timeout.server = MS_TO_TICKS(5000);
	fe->accept = frontend_accept;
	fe->default_target = &peer_applet.obj_type;
	fe->options2 |= PR_O2_INDEPSTR | PR_O2_SMARTCON | PR_O2_SMARTACC;
}

/*
 * Create a new peer session in assigned state (connect will start automatically)
 */
static struct appctx *peer_session_create(struct peers *peers, struct peer *peer)
{
	struct appctx *appctx;
	unsigned int thr = 0;
	int idx;

	peer->new_conn++;
	peer->reconnect = tick_add(now_ms, (stopping ? MS_TO_TICKS(PEER_LOCAL_RECONNECT_TIMEOUT) : MS_TO_TICKS(PEER_RECONNECT_TIMEOUT)));
	peer->heartbeat = TICK_ETERNITY;
	peer->statuscode = PEER_SESS_SC_CONNECTCODE;
	peer->last_hdshk = now_ms;

	for (idx = 0; idx < global.nbthread; idx++)
		thr = peers->applet_count[idx] < peers->applet_count[thr] ? idx : thr;
	appctx = appctx_new_on(&peer_applet, NULL, thr);
	if (!appctx)
		goto out_close;
	appctx->svcctx = (void *)peer;

	appctx->st0 = PEER_SESS_ST_CONNECT;
	peer->appctx = appctx;

	HA_ATOMIC_INC(&peers->applet_count[thr]);
	appctx_wakeup(appctx);
	return appctx;

 out_close:
	return NULL;
}

/* Clear LEARN flags to a given peer, dealing with aborts if it was assigned for
 * learning. In this case, the resync timeout is re-armed.
 */
static void clear_peer_learning_status(struct peer *peer)
{
	if (peer->learnstate != PEER_LR_ST_NOTASSIGNED) {
		struct peers *peers = peer->peers;

		/* unassign current peer for learning */
		HA_ATOMIC_AND(&peers->flags, ~PEERS_F_RESYNC_ASSIGN);
		HA_ATOMIC_OR(&peers->flags, (peer->local ? PEERS_F_DBG_RESYNC_LOCALABORT : PEERS_F_DBG_RESYNC_REMOTEABORT));

		/* reschedule a resync */
		peer->peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(5000));
		peer->learnstate = PEER_LR_ST_NOTASSIGNED;
	}
	peer->flags &= ~PEER_F_LEARN_NOTUP2DATE;
}

static void sync_peer_learn_state(struct peers *peers, struct peer *peer)
{
	unsigned int flags = 0;

	if (peer->learnstate != PEER_LR_ST_FINISHED)
		return;

	/* The learning process is now finished */
	if (peer->flags & PEER_F_LEARN_NOTUP2DATE) {
		/* Partial resync */
		flags |= (peer->local ? PEERS_F_DBG_RESYNC_LOCALPARTIAL : PEERS_F_DBG_RESYNC_REMOTEPARTIAL);
		peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(PEER_RESYNC_TIMEOUT));
	}
	else {
		/* Full resync */
		struct peer *rem_peer;
		int commit_a_finish = 1;

		if (peer->srv->shard) {
			flags |= PEERS_F_DBG_RESYNC_REMOTEPARTIAL;
			peer->flags |= PEER_F_LEARN_NOTUP2DATE;
			for (rem_peer = peers->remote; rem_peer; rem_peer = rem_peer->next) {
				if (rem_peer->srv->shard && rem_peer != peer) {
					HA_SPIN_LOCK(PEER_LOCK, &rem_peer->lock);
					if (rem_peer->srv->shard == peer->srv->shard) {
						/* flag all peers from same shard
						 * notup2date to disable request
						 * of a resync frm them
						 */
						rem_peer->flags |= PEER_F_LEARN_NOTUP2DATE;
					}
					else if (!(rem_peer->flags & PEER_F_LEARN_NOTUP2DATE)) {
						/* it remains some other shards not requested
						 * we don't commit a resync finish to request
						 * the other shards
						 */
						commit_a_finish = 0;
					}
					HA_SPIN_UNLOCK(PEER_LOCK, &rem_peer->lock);
				}
			}

			if (!commit_a_finish) {
				/* it remains some shard to request, we schedule a new request */
				peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(PEER_RESYNC_TIMEOUT));
			}
		}

		if (commit_a_finish) {
			flags |= (PEERS_F_RESYNC_LOCAL_FINISHED|PEERS_F_RESYNC_REMOTE_FINISHED);
			flags |= (peer->local ? PEERS_F_DBG_RESYNC_LOCALFINISHED : PEERS_F_DBG_RESYNC_REMOTEFINISHED);
		}
	}
	peer->learnstate = PEER_LR_ST_NOTASSIGNED;
	HA_ATOMIC_AND(&peers->flags, ~PEERS_F_RESYNC_ASSIGN);
	HA_ATOMIC_OR(&peers->flags, flags);

	if (peer->appctx)
		appctx_wakeup(peer->appctx);
}

/* Synchronise the peer applet state with its associated peers section. This
 * function handles STARTING->RUNNING and STOPPING->STOPPED transitions.
 */
static void sync_peer_app_state(struct peers *peers, struct peer *peer)
{
	if (peer->appstate == PEER_APP_ST_STOPPING) {
		clear_peer_learning_status(peer);
		peer->appstate = PEER_APP_ST_STOPPED;
	}
	else if (peer->appstate == PEER_APP_ST_STARTING) {
		clear_peer_learning_status(peer);
		if (peer->local & appctx_is_back(peer->appctx)) {
			/* if local peer has accepted the connection (appctx is
			 * on the backend side), flag it to learn a lesson and
			 * be sure it will start immediately. This only happens
			 * if no resync is in progress and if the lacal resync
			 * was not already performed.
			 */
			if ((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMLOCAL &&
			    !(peers->flags & PEERS_F_RESYNC_ASSIGN)) {
				/* assign local peer for a lesson */
				peer->learnstate = PEER_LR_ST_ASSIGNED;
				HA_ATOMIC_OR(&peers->flags, PEERS_F_RESYNC_ASSIGN|PEERS_F_DBG_RESYNC_LOCALASSIGN);
			}
		}
		else if (!peer->local) {
			/* If a connection was validated for a remote peer, flag
			 * it to learn a lesson but don't start it yet. The peer
			 * must request it explicitly.  This only happens if no
			 * resync is in progress and if the remote resync was
			 * not already performed.
			 */
			if ((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE &&
			    !(peers->flags & PEERS_F_RESYNC_ASSIGN)) {
				/* assign remote peer for a lesson */
				peer->learnstate = PEER_LR_ST_ASSIGNED;
				HA_ATOMIC_OR(&peers->flags, PEERS_F_RESYNC_ASSIGN|PEERS_F_DBG_RESYNC_REMOTEASSIGN);
			}
		}
		peer->appstate = PEER_APP_ST_RUNNING;
		appctx_wakeup(peer->appctx);
	}
}

/* Process the sync task for a running process.  It is called from process_peer_sync() only */
static void __process_running_peer_sync(struct task *task, struct peers *peers, unsigned int state)
{
	struct peer *peer;
	struct shared_table *st;

	/* resync timeout set to TICK_ETERNITY means we just start
	 * a new process and timer was not initialized.
	 * We must arm this timer to switch to a request to a remote
	 * node if incoming connection from old local process never
	 * comes.
	 */
	if (peers->resync_timeout == TICK_ETERNITY)
		peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(PEER_RESYNC_TIMEOUT));

	if (((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMLOCAL) &&
	    (!nb_oldpids || tick_is_expired(peers->resync_timeout, now_ms)) &&
	    !(peers->flags & PEERS_F_RESYNC_ASSIGN)) {
		/* Resync from local peer needed
		   no peer was assigned for the lesson
		   and no old local peer found
		   or resync timeout expire */

		/* flag no more resync from local, to try resync from remotes */
		HA_ATOMIC_OR(&peers->flags, PEERS_F_RESYNC_LOCAL_FINISHED|PEERS_F_DBG_RESYNC_LOCALTIMEOUT);

		/* reschedule a resync */
		peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(PEER_RESYNC_TIMEOUT));
	}

	/* For each session */
	for (peer = peers->remote; peer; peer = peer->next) {
		HA_SPIN_LOCK(PEER_LOCK, &peer->lock);

		sync_peer_learn_state(peers, peer);
		sync_peer_app_state(peers, peer);

		/* Peer changes, if any, were now ack by the sync task. Unblock
		 * the peer (any wakeup should already be performed, no need to
		 * do it here)
		 */
		peer->flags &= ~PEER_F_WAIT_SYNCTASK_ACK;

		/* For each remote peers */
		if (!peer->local) {
			if (!peer->appctx) {
				/* no active peer connection */
				if (peer->statuscode == 0 ||
				    ((peer->statuscode == PEER_SESS_SC_CONNECTCODE ||
				      peer->statuscode == PEER_SESS_SC_SUCCESSCODE ||
				      peer->statuscode == PEER_SESS_SC_CONNECTEDCODE) &&
				     tick_is_expired(peer->reconnect, now_ms))) {
					/* connection never tried
					 * or previous peer connection established with success
					 * or previous peer connection failed while connecting
					 * and reconnection timer is expired */

					/* retry a connect */
					peer->appctx = peer_session_create(peers, peer);
				}
				else if (!tick_is_expired(peer->reconnect, now_ms)) {
					/* If previous session failed during connection
					 * but reconnection timer is not expired */

					/* reschedule task for reconnect */
					task->expire = tick_first(task->expire, peer->reconnect);
				}
				/* else do nothing */
			} /* !peer->appctx */
			else if (peer->statuscode == PEER_SESS_SC_SUCCESSCODE) {
				/* current peer connection is active and established */
				if (((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE) &&
				    !(peers->flags & PEERS_F_RESYNC_ASSIGN) &&
				    !(peer->flags & PEER_F_LEARN_NOTUP2DATE)) {
					/* Resync from a remote is needed
					 * and no peer was assigned for lesson
					 * and current peer may be up2date */

					/* assign peer for the lesson */
					peer->learnstate = PEER_LR_ST_ASSIGNED;
					HA_ATOMIC_OR(&peers->flags, PEERS_F_RESYNC_ASSIGN|PEERS_F_DBG_RESYNC_REMOTEASSIGN);

					/* wake up peer handler to handle a request of resync */
					appctx_wakeup(peer->appctx);
				}
				else {
					int update_to_push = 0;

					/* Awake session if there is data to push */
					for (st = peer->tables; st ; st = st->next) {
						if (st->last_pushed != st->table->localupdate) {
							/* wake up the peer handler to push local updates */
							update_to_push = 1;
							/* There is no need to send a heartbeat message
							 * when some updates must be pushed. The remote
							 * peer will consider <peer> peer as alive when it will
							 * receive these updates.
							 */
							peer->flags &= ~PEER_F_HEARTBEAT;
							/* Re-schedule another one later. */
							peer->heartbeat = tick_add(now_ms, MS_TO_TICKS(PEER_HEARTBEAT_TIMEOUT));
							/* Refresh reconnect if necessary */
							if (tick_is_expired(peer->reconnect, now_ms))
								peer->reconnect = tick_add(now_ms, MS_TO_TICKS(PEER_RECONNECT_TIMEOUT));
							/* We are going to send updates, let's ensure we will
							 * come back to send heartbeat messages or to reconnect.
							 */
							task->expire = tick_first(peer->reconnect, peer->heartbeat);
							appctx_wakeup(peer->appctx);
							break;
						}
					}
					/* When there are updates to send we do not reconnect
					 * and do not send heartbeat message either.
					 */
					if (!update_to_push) {
						if (tick_is_expired(peer->reconnect, now_ms)) {
							if (peer->flags & PEER_F_ALIVE) {
								/* This peer was alive during a 'reconnect' period.
								 * Flag it as not alive again for the next period.
								 */
								peer->flags &= ~PEER_F_ALIVE;
								peer->reconnect = tick_add(now_ms, MS_TO_TICKS(PEER_RECONNECT_TIMEOUT));
							}
							else  {
								peer->reconnect = tick_add(now_ms, MS_TO_TICKS(50 + ha_random() % 2000));
								peer->heartbeat = TICK_ETERNITY;
								peer_session_forceshutdown(peer);
								sync_peer_app_state(peers, peer);
								peer->no_hbt++;
							}
						}
						else if (tick_is_expired(peer->heartbeat, now_ms)) {
							peer->heartbeat = tick_add(now_ms, MS_TO_TICKS(PEER_HEARTBEAT_TIMEOUT));
							peer->flags |= PEER_F_HEARTBEAT;
							appctx_wakeup(peer->appctx);
						}
						task->expire = tick_first(peer->reconnect, peer->heartbeat);
					}
				}
				/* else do nothing */
			} /* SUCCESSCODE */
		} /* !peer->peer->local */

		HA_SPIN_UNLOCK(PEER_LOCK, &peer->lock);
	} /* for */

	/* Resync from remotes expired or no remote peer: consider resync is finished */
	if (((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FROMREMOTE) &&
	    !(peers->flags & PEERS_F_RESYNC_ASSIGN) &&
	    (tick_is_expired(peers->resync_timeout, now_ms) || !peers->remote->next)) {
		/* Resync from remote peer needed
		 * no peer was assigned for the lesson
		 * and resync timeout expire */

		/* flag no more resync from remote, consider resync is finished */
		HA_ATOMIC_OR(&peers->flags, PEERS_F_RESYNC_REMOTE_FINISHED|PEERS_F_DBG_RESYNC_REMOTETIMEOUT);
	}

	if ((peers->flags & PEERS_RESYNC_STATEMASK) != PEERS_RESYNC_FINISHED) {
		/* Resync not finished*/
		/* reschedule task to resync timeout if not expired, to ended resync if needed */
		if (!tick_is_expired(peers->resync_timeout, now_ms))
			task->expire = tick_first(task->expire, peers->resync_timeout);
	}
}

/* Process the sync task for a stopping process. It is called from process_peer_sync() only */
static void __process_stopping_peer_sync(struct task *task, struct peers *peers, unsigned int state)
{
	struct peer *peer;
	struct shared_table *st;
	static int dont_stop = 0;

	/* For each peer */
	for (peer = peers->remote; peer; peer = peer->next) {
		HA_SPIN_LOCK(PEER_LOCK, &peer->lock);

		sync_peer_learn_state(peers, peer);
		sync_peer_app_state(peers, peer);

		/* Peer changes, if any, were now ack by the sync task. Unblock
		 * the peer (any wakeup should already be performed, no need to
		 * do it here)
		 */
		peer->flags &= ~PEER_F_WAIT_SYNCTASK_ACK;

		if ((state & TASK_WOKEN_SIGNAL) && !dont_stop) {
			/* we're killing a connection, we must apply a random delay before
			 * retrying otherwise the other end will do the same and we can loop
			 * for a while.
			 */
			peer->reconnect = tick_add(now_ms, MS_TO_TICKS(50 + ha_random() % 2000));
			if (peer->appctx) {
				peer_session_forceshutdown(peer);
				sync_peer_app_state(peers, peer);
			}
		}

		HA_SPIN_UNLOCK(PEER_LOCK, &peer->lock);
	}

	/* We've just received the signal */
	if (state & TASK_WOKEN_SIGNAL) {
		if (!dont_stop) {
			/* add DO NOT STOP flag if not present */
			_HA_ATOMIC_INC(&jobs);
			dont_stop = 1;

			/* Set resync timeout for the local peer and request a immediate reconnect */
			peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(PEER_RESYNC_TIMEOUT));
			peers->local->reconnect = tick_add(now_ms, 0);
		}
	}

	peer = peers->local;
	HA_SPIN_LOCK(PEER_LOCK, &peer->lock);
	if (peer->flags & PEER_F_LOCAL_TEACH_COMPLETE) {
		if (dont_stop) {
			/* resync of new process was complete, current process can die now */
			_HA_ATOMIC_DEC(&jobs);
			dont_stop = 0;
			for (st = peer->tables; st ; st = st->next)
				HA_ATOMIC_DEC(&st->table->refcnt);
		}
	}
	else if (!peer->appctx) {
		/* Re-arm resync timeout if necessary */
		if (!tick_isset(peers->resync_timeout))
			peers->resync_timeout = tick_add(now_ms, MS_TO_TICKS(PEER_RESYNC_TIMEOUT));

		/* If there's no active peer connection */
		if ((peers->flags & PEERS_RESYNC_STATEMASK) == PEERS_RESYNC_FINISHED &&
		    !tick_is_expired(peers->resync_timeout, now_ms) &&
		    (peer->statuscode == 0 ||
		     peer->statuscode == PEER_SESS_SC_SUCCESSCODE ||
		     peer->statuscode == PEER_SESS_SC_CONNECTEDCODE ||
		     peer->statuscode == PEER_SESS_SC_TRYAGAIN)) {
			/* The resync is finished for the local peer and
			 *   the resync timeout is not expired and
			 *   connection never tried
			 *   or previous peer connection was successfully established
			 *   or previous tcp connect succeeded but init state incomplete
			 *   or during previous connect, peer replies a try again statuscode */

			if (!tick_is_expired(peer->reconnect, now_ms)) {
				/* reconnection timer is not expired. reschedule task for reconnect */
				task->expire = tick_first(task->expire, peer->reconnect);
			}
			else  {
				/* connect to the local peer if we must push a local sync */
				if (dont_stop) {
					peer_session_create(peers, peer);
				}
			}
		}
		else {
			/* Other error cases */
			if (dont_stop) {
				/* unable to resync new process, current process can die now */
				_HA_ATOMIC_DEC(&jobs);
				dont_stop = 0;
				for (st = peer->tables; st ; st = st->next)
					HA_ATOMIC_DEC(&st->table->refcnt);
			}
		}
	}
	else if (peer->statuscode == PEER_SESS_SC_SUCCESSCODE ) {
		/* Reset resync timeout during a resync */
		peers->resync_timeout = TICK_ETERNITY;

		/* current peer connection is active and established
		 * wake up all peer handlers to push remaining local updates */
		for (st = peer->tables; st ; st = st->next) {
			if (st->last_pushed != st->table->localupdate) {
				appctx_wakeup(peer->appctx);
				break;
			}
		}
	}
	HA_SPIN_UNLOCK(PEER_LOCK, &peer->lock);
}

/*
 * Task processing function to manage re-connect, peer session
 * tasks wakeup on local update and heartbeat. Let's keep it exported so that it
 * resolves in stack traces and "show tasks".
 */
struct task *process_peer_sync(struct task * task, void *context, unsigned int state)
{
	struct peers *peers = context;

	task->expire = TICK_ETERNITY;

	if (!stopping) {
		/* Normal case (not soft stop)*/
		__process_running_peer_sync(task, peers, state);

	}
	else {
		/* soft stop case */
		__process_stopping_peer_sync(task, peers, state);
	} /* stopping */

	/* Wakeup for re-connect */
	return task;
}


/*
 * returns 0 in case of error.
 */
int peers_init_sync(struct peers *peers)
{
	struct peer * curpeer;

	for (curpeer = peers->remote; curpeer; curpeer = curpeer->next) {
		peers->peers_fe->maxconn += 3;
	}

	peers->sync_task = task_new_anywhere();
	if (!peers->sync_task)
		return 0;

	memset(peers->applet_count, 0, sizeof(peers->applet_count));
	peers->sync_task->process = process_peer_sync;
	peers->sync_task->context = (void *)peers;
	peers->sighandler = signal_register_task(0, peers->sync_task, 0);
	task_wakeup(peers->sync_task, TASK_WOKEN_INIT);
	return 1;
}

/*
 * Allocate a cache a dictionary entries used upon transmission.
 */
static struct dcache_tx *new_dcache_tx(size_t max_entries)
{
	struct dcache_tx *d;
	struct ebpt_node *entries;

	d = malloc(sizeof *d);
	entries = calloc(max_entries, sizeof *entries);
	if (!d || !entries)
		goto err;

	d->lru_key = 0;
	d->prev_lookup = NULL;
	d->cached_entries = EB_ROOT_UNIQUE;
	d->entries = entries;

	return d;

 err:
	free(d);
	free(entries);
	return NULL;
}

/*
 * Allocate a cache of dictionary entries with <name> as name and <max_entries>
 * as maximum of entries.
 * Return the dictionary cache if succeeded, NULL if not.
 * Must be deallocated calling free_dcache().
 */
static struct dcache *new_dcache(size_t max_entries)
{
	struct dcache_tx *dc_tx;
	struct dcache *dc;
	struct dcache_rx *dc_rx;

	dc = calloc(1, sizeof *dc);
	dc_tx = new_dcache_tx(max_entries);
	dc_rx = calloc(max_entries, sizeof *dc_rx);
	if (!dc || !dc_tx || !dc_rx)
		goto err;

	dc->tx = dc_tx;
	dc->rx = dc_rx;
	dc->max_entries = max_entries;

	return dc;

 err:
	free(dc);
	free(dc_tx);
	free(dc_rx);
	return NULL;
}

/*
 * Look for the dictionary entry with the value of <i> in <d> cache of dictionary
 * entries used upon transmission.
 * Return the entry if found, NULL if not.
 */
static struct ebpt_node *dcache_tx_lookup_value(struct dcache_tx *d,
                                                struct dcache_tx_entry *i)
{
	return ebpt_lookup(&d->cached_entries, i->entry.key);
}

/*
 * Flush <dc> cache.
 * Always succeeds.
 */
static inline void flush_dcache(struct peer *peer)
{
	int i;
	struct dcache *dc = peer->dcache;

	for (i = 0; i < dc->max_entries; i++) {
		ebpt_delete(&dc->tx->entries[i]);
		dc->tx->entries[i].key = NULL;
		dict_entry_unref(&server_key_dict, dc->rx[i].de);
		dc->rx[i].de = NULL;
	}
	dc->tx->prev_lookup = NULL;
	dc->tx->lru_key = 0;

	memset(dc->rx, 0, dc->max_entries * sizeof *dc->rx);
}

/*
 * Insert a dictionary entry in <dc> cache part used upon transmission (->tx)
 * with information provided by <i> dictionary cache entry (especially the value
 * to be inserted if not already). Return <i> if already present in the cache
 * or something different of <i> if not.
 */
static struct ebpt_node *dcache_tx_insert(struct dcache *dc, struct dcache_tx_entry *i)
{
	struct dcache_tx *dc_tx;
	struct ebpt_node *o;

	dc_tx = dc->tx;

	if (dc_tx->prev_lookup && dc_tx->prev_lookup->key == i->entry.key) {
		o = dc_tx->prev_lookup;
	} else {
		o = dcache_tx_lookup_value(dc_tx, i);
		if (o) {
			/* Save it */
			dc_tx->prev_lookup = o;
		}
	}

	if (o) {
		/* Copy the ID. */
		i->id = o - dc->tx->entries;
		return &i->entry;
	}

	/* The new entry to put in cache */
	dc_tx->prev_lookup = o = &dc_tx->entries[dc_tx->lru_key];

	ebpt_delete(o);
	o->key = i->entry.key;
	ebpt_insert(&dc_tx->cached_entries, o);
	i->id = dc_tx->lru_key;

	/* Update the index for the next entry to put in cache */
	dc_tx->lru_key = (dc_tx->lru_key + 1) & (dc->max_entries - 1);

	return o;
}

/*
 * Allocate a dictionary cache for each peer of <peers> section.
 * Return 1 if succeeded, 0 if not.
 */
int peers_alloc_dcache(struct peers *peers)
{
	struct peer *p;

	for (p = peers->remote; p; p = p->next) {
		p->dcache = new_dcache(PEER_STKT_CACHE_MAX_ENTRIES);
		if (!p->dcache)
			return 0;
	}

	return 1;
}

/*
 * Function used to register a table for sync on a group of peers
 * Returns 0 in case of success.
 */
int peers_register_table(struct peers *peers, struct stktable *table)
{
	struct shared_table *st;
	struct peer * curpeer;
	int id = 0;
	int retval = 0;

	for (curpeer = peers->remote; curpeer; curpeer = curpeer->next) {
		st = calloc(1,sizeof(*st));
		if (!st) {
			retval = 1;
			break;
		}
		st->table = table;
		st->next = curpeer->tables;
		if (curpeer->tables)
			id = curpeer->tables->local_id;
		st->local_id = id + 1;

		/* If peer is local we inc table
		 * refcnt to protect against flush
		 * until this process pushed all
		 * table content to the new one
		 */
		if (curpeer->local)
			HA_ATOMIC_INC(&st->table->refcnt);
		curpeer->tables = st;
	}

	table->sync_task = peers->sync_task;

	return retval;
}

/* context used by a "show peers" command */
struct show_peers_ctx {
	void *target;           /* if non-null, dump only this section and stop */
	struct peers *peers;    /* "peers" section being currently dumped. */
	struct peer *peer;      /* "peer" being currently dumped. */
	int flags;              /* non-zero if "dict" dump requested */
	enum {
		STATE_HEAD = 0, /* dump the section's header */
		STATE_PEER,     /* dump the whole peer */
		STATE_DONE,     /* finished */
	} state;                /* parser's state */
};

/*
 * Parse the "show peers" command arguments.
 * Returns 0 if succeeded, 1 if not with the ->msg of the appctx set as
 * error message.
 */
static int cli_parse_show_peers(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_peers_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (strcmp(args[2], "dict") == 0) {
		/* show the dictionaries (large dump) */
		ctx->flags |= PEERS_SHOW_F_DICT;
		args++;
	} else if (strcmp(args[2], "-") == 0)
		args++; // allows to show a section called "dict"

	if (*args[2]) {
		struct peers *p;

		for (p = cfg_peers; p; p = p->next) {
			if (strcmp(p->id, args[2]) == 0) {
				ctx->target = p;
				break;
			}
		}

		if (!p)
			return cli_err(appctx, "No such peers\n");
	}

	/* where to start from */
	ctx->peers = ctx->target ? ctx->target : cfg_peers;
	return 0;
}

/*
 * This function dumps the peer state information of <peers> "peers" section.
 * Returns 0 if the output buffer is full and needs to be called again, non-zero if not.
 * Dedicated to be called by cli_io_handler_show_peers() cli I/O handler.
 */
static int peers_dump_head(struct buffer *msg, struct appctx *appctx, struct peers *peers)
{
	struct tm tm;

	get_localtime(peers->last_change, &tm);
	chunk_appendf(msg, "%p: [%02d/%s/%04d:%02d:%02d:%02d] id=%s disabled=%d flags=0x%x resync_timeout=%s task_calls=%u\n",
	              peers,
	              tm.tm_mday, monthname[tm.tm_mon], tm.tm_year+1900,
	              tm.tm_hour, tm.tm_min, tm.tm_sec,
	              peers->id, peers->disabled, HA_ATOMIC_LOAD(&peers->flags),
	              peers->resync_timeout ?
			             tick_is_expired(peers->resync_timeout, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(peers->resync_timeout - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>",
	              peers->sync_task ? peers->sync_task->calls : 0);

	if (applet_putchk(appctx, msg) == -1)
		return 0;

	return 1;
}

/*
 * This function dumps <peer> state information.
 * Returns 0 if the output buffer is full and needs to be called again, non-zero
 * if not. Dedicated to be called by cli_io_handler_show_peers() cli I/O handler.
 */
static int peers_dump_peer(struct buffer *msg, struct appctx *appctx, struct peer *peer, int flags)
{
	struct connection *conn;
	char pn[INET6_ADDRSTRLEN];
	struct stconn *peer_cs;
	struct stream *peer_s;
	struct shared_table *st;

	addr_to_str(&peer->srv->addr, pn, sizeof pn);
	chunk_appendf(msg, "  %p: id=%s(%s,%s) addr=%s:%d app_state=%s learn_state=%s last_status=%s",
	              peer, peer->id,
	              peer->local ? "local" : "remote",
	              peer->appctx ? "active" : "inactive",
	              pn, peer->srv->svc_port,
		      peer_app_state_str(peer->appstate),
		      peer_learn_state_str(peer->learnstate),
	              statuscode_str(peer->statuscode));

	chunk_appendf(msg, " last_hdshk=%s\n",
	              peer->last_hdshk ? human_time(TICKS_TO_MS(now_ms - peer->last_hdshk),
	                                            TICKS_TO_MS(1000)) : "<NEVER>");

	chunk_appendf(msg, "        reconnect=%s",
	              peer->reconnect ?
			             tick_is_expired(peer->reconnect, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(peer->reconnect - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>");

	chunk_appendf(msg, " heartbeat=%s",
	              peer->heartbeat ?
			             tick_is_expired(peer->heartbeat, now_ms) ? "<PAST>" :
			                     human_time(TICKS_TO_MS(peer->heartbeat - now_ms),
			                     TICKS_TO_MS(1000)) : "<NEVER>");

	chunk_appendf(msg, " confirm=%u tx_hbt=%u rx_hbt=%u no_hbt=%u new_conn=%u proto_err=%u coll=%u\n",
	              peer->confirm, peer->tx_hbt, peer->rx_hbt,
	              peer->no_hbt, peer->new_conn, peer->proto_err, peer->coll);

	chunk_appendf(&trash, "        flags=0x%x", peer->flags);

	if (!peer->appctx)
		goto table_info;

	chunk_appendf(&trash, " appctx:%p st0=%d st1=%d task_calls=%u",
	              peer->appctx, peer->appctx->st0, peer->appctx->st1,
	              peer->appctx->t ? peer->appctx->t->calls : 0);

	peer_cs = appctx_sc(peer->appctx);
	if (!peer_cs) {
		/* the appctx might exist but not yet be initialized due to
		 * deferred initialization used to balance applets across
		 * threads.
		 */
		goto table_info;
	}

	peer_s = __sc_strm(peer_cs);

	chunk_appendf(&trash, " state=%s", sc_state_str(sc_opposite(peer_cs)->state));

	conn = objt_conn(strm_orig(peer_s));
	if (conn)
		chunk_appendf(&trash, "\n        xprt=%s", conn_get_xprt_name(conn));

	switch (conn && conn_get_src(conn) ? addr_to_str(conn->src, pn, sizeof(pn)) : AF_UNSPEC) {
	case AF_INET:
	case AF_INET6:
		chunk_appendf(&trash, " src=%s:%d", pn, get_host_port(conn->src));
		break;
	case AF_UNIX:
	case AF_CUST_ABNS:
	case AF_CUST_ABNSZ:
		chunk_appendf(&trash, " src=unix:%d", strm_li(peer_s)->luid);
		break;
	}

	switch (conn && conn_get_dst(conn) ? addr_to_str(conn->dst, pn, sizeof(pn)) : AF_UNSPEC) {
	case AF_INET:
	case AF_INET6:
		chunk_appendf(&trash, " addr=%s:%d", pn, get_host_port(conn->dst));
		break;
	case AF_UNIX:
	case AF_CUST_ABNS:
	case AF_CUST_ABNSZ:
		chunk_appendf(&trash, " addr=unix:%d", strm_li(peer_s)->luid);
		break;
	}

 table_info:
	if (peer->remote_table)
		chunk_appendf(&trash, "\n        remote_table:%p id=%s local_id=%d remote_id=%d",
		              peer->remote_table,
		              peer->remote_table->table->id,
		              peer->remote_table->local_id,
		              peer->remote_table->remote_id);

	if (peer->last_local_table)
		chunk_appendf(&trash, "\n        last_local_table:%p id=%s local_id=%d remote_id=%d",
		              peer->last_local_table,
		              peer->last_local_table->table->id,
		              peer->last_local_table->local_id,
		              peer->last_local_table->remote_id);

	if (peer->tables) {
		chunk_appendf(&trash, "\n        shared tables:");
		for (st = peer->tables; st; st = st->next) {
			int i, count;
			struct stktable *t;
			struct dcache *dcache;

			t = st->table;
			dcache = peer->dcache;

			chunk_appendf(&trash, "\n          %p local_id=%d remote_id=%d "
			              "flags=0x%x remote_data=0x%llx",
			              st, st->local_id, st->remote_id,
			              st->flags, (unsigned long long)st->remote_data);
			chunk_appendf(&trash, "\n              last_acked=%u last_pushed=%u last_get=%u"
			              " teaching_origin=%u update=%u",
			              st->last_acked, st->last_pushed, st->last_get,
			              st->teaching_origin, st->update);
			chunk_appendf(&trash, "\n              table:%p id=%s update=%u localupdate=%u"
			              " commitupdate=%u refcnt=%u",
			              t, t->id, t->update, t->localupdate, _HA_ATOMIC_LOAD(&t->commitupdate), t->refcnt);
			if (flags & PEERS_SHOW_F_DICT) {
				chunk_appendf(&trash, "\n        TX dictionary cache:");
				count = 0;
				for (i = 0; i < dcache->max_entries; i++) {
					struct ebpt_node *node;
					struct dict_entry *de;

					node = &dcache->tx->entries[i];
					if (!node->key)
						break;

					if (!count++)
						chunk_appendf(&trash, "\n        ");
					de = node->key;
					chunk_appendf(&trash, "  %3u -> %s", i, (char *)de->value.key);
					count &= 0x3;
				}
				chunk_appendf(&trash, "\n        RX dictionary cache:");
				count = 0;
				for (i = 0; i < dcache->max_entries; i++) {
					if (!count++)
						chunk_appendf(&trash, "\n        ");
					chunk_appendf(&trash, "  %3u -> %s", i,
						      dcache->rx[i].de ?
						      (char *)dcache->rx[i].de->value.key : "-");
					count &= 0x3;
				}
			} else {
				chunk_appendf(&trash, "\n        Dictionary cache not dumped (use \"show peers dict\")");
			}
		}
	}

 end:
	chunk_appendf(&trash, "\n");
	if (applet_putchk(appctx, msg) == -1)
		return 0;

	return 1;
}

/*
 * This function dumps all the peers of "peers" section.
 * Returns 0 if the output buffer is full and needs to be called
 * again, non-zero if not. It proceeds in an isolated thread, so
 * there is no thread safety issue here.
 */
static int cli_io_handler_show_peers(struct appctx *appctx)
{
	struct show_peers_ctx *ctx = appctx->svcctx;
	int ret = 0, first_peers = 1;

	thread_isolate();

	chunk_reset(&trash);

	while (ctx->state != STATE_DONE) {
		switch (ctx->state) {
		case STATE_HEAD:
			if (!ctx->peers) {
				/* No more peers list. */
				ctx->state = STATE_DONE;
			}
			else {
				if (!first_peers)
					chunk_appendf(&trash, "\n");
				else
					first_peers = 0;
				if (!peers_dump_head(&trash, appctx, ctx->peers))
					goto out;

				ctx->peer = ctx->peers->remote;
				ctx->peers = ctx->peers->next;
				ctx->state = STATE_PEER;
			}
			break;

		case STATE_PEER:
			if (!ctx->peer) {
				/* End of peer list */
				if (!ctx->target)
					ctx->state = STATE_HEAD; // next one
			    else
					ctx->state = STATE_DONE;
			}
			else {
				if (!peers_dump_peer(&trash, appctx, ctx->peer, ctx->flags))
					goto out;

				ctx->peer = ctx->peer->next;
			}
			break;

		default:
			break;
		}
	}
	ret = 1;
 out:
	thread_release();
	return ret;
}


struct peers_kw_list peers_keywords = {
	.list = LIST_HEAD_INIT(peers_keywords.list)
};

void peers_register_keywords(struct peers_kw_list *pkwl)
{
	LIST_APPEND(&peers_keywords.list, &pkwl->list);
}

/* config parser for global "tune.peers.max-updates-at-once" */
static int cfg_parse_max_updt_at_once(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	int arg = -1;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) != 0)
		arg = atoi(args[1]);

	if (arg < 1) {
		memprintf(err, "'%s' expects an integer argument greater than 0.", args[0]);
		return -1;
	}

	peers_max_updates_at_once = arg;
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.peers.max-updates-at-once",  cfg_parse_max_updt_at_once },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/*
 * CLI keywords.
 */
static struct cli_kw_list cli_kws = {{ }, {
	{ { "show", "peers", NULL }, "show peers [dict|-] [section]           : dump some information about all the peers or this peers section", cli_parse_show_peers, cli_io_handler_show_peers, },
	{},
}};

/* Register cli keywords */
INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
