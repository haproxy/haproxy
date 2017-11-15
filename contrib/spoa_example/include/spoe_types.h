/*
 * include/spoe_types.h
 * Macros, variables and structures for the SPOE filter.
 *
 * Copyright (C) 2017 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _SPOE_TYPES_H
#define _SPOE_TYPES_H

#include <mini-clist.h>

// Taken from HAProxy's defaults.h
/* Maximum host name length */
#ifndef MAX_HOSTNAME_LEN
#if MAXHOSTNAMELEN
#define MAX_HOSTNAME_LEN	MAXHOSTNAMELEN
#else
#define MAX_HOSTNAME_LEN	64
#endif // MAXHOSTNAMELEN
#endif // MAX_HOSTNAME_LEN

/* Flags set on the SPOE agent */
#define SPOE_FL_CONT_ON_ERR       0x00000001 /* Do not stop events processing when an error occurred */
#define SPOE_FL_PIPELINING        0x00000002 /* Set when SPOE agent supports pipelining (set by default) */
#define SPOE_FL_ASYNC             0x00000004 /* Set when SPOE agent supports async (set by default) */
#define SPOE_FL_SND_FRAGMENTATION 0x00000008 /* Set when SPOE agent supports sending fragmented payload */
#define SPOE_FL_RCV_FRAGMENTATION 0x00000010 /* Set when SPOE agent supports receiving fragmented payload */

/* Flags set on the SPOE context */
#define SPOE_CTX_FL_CLI_CONNECTED 0x00000001 /* Set after that on-client-session event was processed */
#define SPOE_CTX_FL_SRV_CONNECTED 0x00000002 /* Set after that on-server-session event was processed */
#define SPOE_CTX_FL_REQ_PROCESS   0x00000004 /* Set when SPOE is processing the request */
#define SPOE_CTX_FL_RSP_PROCESS   0x00000008 /* Set when SPOE is processing the response */
#define SPOE_CTX_FL_FRAGMENTED    0x00000010 /* Set when a fragmented frame is processing */

#define SPOE_CTX_FL_PROCESS (SPOE_CTX_FL_REQ_PROCESS|SPOE_CTX_FL_RSP_PROCESS)

/* Flags set on the SPOE applet */
#define SPOE_APPCTX_FL_PIPELINING    0x00000001 /* Set if pipelining is supported */
#define SPOE_APPCTX_FL_ASYNC         0x00000002 /* Set if asynchronus frames is supported */
#define SPOE_APPCTX_FL_FRAGMENTATION 0x00000004 /* Set if fragmentation is supported */
#define SPOE_APPCTX_FL_PERSIST       0x00000008 /* Set if the applet is persistent */

#define SPOE_APPCTX_ERR_NONE    0x00000000 /* no error yet, leave it to zero */
#define SPOE_APPCTX_ERR_TOUT    0x00000001 /* SPOE applet timeout */

/* Flags set on the SPOE frame */
#define SPOE_FRM_FL_FIN         0x00000001
#define SPOE_FRM_FL_ABRT        0x00000002

/* All supported SPOE actions */
enum spoe_action_type {
	SPOE_ACT_T_SET_VAR = 1,
	SPOE_ACT_T_UNSET_VAR,
	SPOE_ACT_TYPES,
};

/* All supported SPOE events */
enum spoe_event {
	SPOE_EV_NONE = 0,

	/* Request events */
	SPOE_EV_ON_CLIENT_SESS = 1,
	SPOE_EV_ON_TCP_REQ_FE,
	SPOE_EV_ON_TCP_REQ_BE,
	SPOE_EV_ON_HTTP_REQ_FE,
	SPOE_EV_ON_HTTP_REQ_BE,

	/* Response events */
	SPOE_EV_ON_SERVER_SESS,
	SPOE_EV_ON_TCP_RSP,
	SPOE_EV_ON_HTTP_RSP,

	SPOE_EV_EVENTS
};

/* Errors triggered by streams */
enum spoe_context_error {
	SPOE_CTX_ERR_NONE = 0,
	SPOE_CTX_ERR_TOUT,
	SPOE_CTX_ERR_RES,
	SPOE_CTX_ERR_TOO_BIG,
	SPOE_CTX_ERR_FRAG_FRAME_ABRT,
	SPOE_CTX_ERR_UNKNOWN = 255,
	SPOE_CTX_ERRS,
};

/* Errors triggerd by SPOE applet */
enum spoe_frame_error {
	SPOE_FRM_ERR_NONE = 0,
	SPOE_FRM_ERR_IO,
	SPOE_FRM_ERR_TOUT,
	SPOE_FRM_ERR_TOO_BIG,
	SPOE_FRM_ERR_INVALID,
	SPOE_FRM_ERR_NO_VSN,
	SPOE_FRM_ERR_NO_FRAME_SIZE,
	SPOE_FRM_ERR_NO_CAP,
	SPOE_FRM_ERR_BAD_VSN,
	SPOE_FRM_ERR_BAD_FRAME_SIZE,
	SPOE_FRM_ERR_FRAG_NOT_SUPPORTED,
	SPOE_FRM_ERR_INTERLACED_FRAMES,
	SPOE_FRM_ERR_FRAMEID_NOTFOUND,
	SPOE_FRM_ERR_RES,
	SPOE_FRM_ERR_UNKNOWN = 99,
	SPOE_FRM_ERRS,
};

/* Scopes used for variables set by agents. It is a way to be agnotic to vars
 * scope. */
enum spoe_vars_scope {
	SPOE_SCOPE_PROC = 0, /* <=> SCOPE_PROC  */
	SPOE_SCOPE_SESS,     /* <=> SCOPE_SESS */
	SPOE_SCOPE_TXN,      /* <=> SCOPE_TXN  */
	SPOE_SCOPE_REQ,      /* <=> SCOPE_REQ  */
	SPOE_SCOPE_RES,      /* <=> SCOPE_RES  */
};


/* Describe an argument that will be linked to a message. It is a sample fetch,
 * with an optional name. */
struct spoe_arg {
	char               *name;     /* Name of the argument, may be NULL */
	unsigned int        name_len; /* The name length, 0 if NULL */
	struct sample_expr *expr;     /* Sample expression */
	struct list         list;     /* Used to chain SPOE args */
};

/* Used during the config parsing only because, when a SPOE agent section is
 * parsed, messages can be undefined. */
struct spoe_msg_placeholder {
	char       *id;    /* SPOE message placeholder id */
	struct list list;  /* Use to chain SPOE message placeholders */
};

/* Describe a message that will be sent in a NOTIFY frame. A message has a name,
 * an argument list (see above) and it is linked to a specific event. */
struct spoe_message {
	char              *id;      /* SPOE message id */
	unsigned int       id_len;  /* The message id length */
	struct spoe_agent *agent;   /* SPOE agent owning this SPOE message */
        struct {
                char      *file;    /* file where the SPOE message appears */
                int        line;    /* line where the SPOE message appears */
        } conf;                     /* config information */
	unsigned int       nargs;   /* # of arguments */
	struct list        args;    /* Arguments added when the SPOE messages is sent */
	struct list        list;    /* Used to chain SPOE messages */

	enum spoe_event    event;   /* SPOE_EV_* */
};

enum spoe_frame_type {
	SPOE_FRM_T_UNSET = 0,

	/* Frames sent by HAProxy */
	SPOE_FRM_T_HAPROXY_HELLO = 1,
	SPOE_FRM_T_HAPROXY_DISCON,
	SPOE_FRM_T_HAPROXY_NOTIFY,

	/* Frames sent by the agents */
	SPOE_FRM_T_AGENT_HELLO = 101,
	SPOE_FRM_T_AGENT_DISCON,
	SPOE_FRM_T_AGENT_ACK
};

/* All supported data types */
enum spoe_data_type {
	SPOE_DATA_T_NULL = 0,
	SPOE_DATA_T_BOOL,
	SPOE_DATA_T_INT32,
	SPOE_DATA_T_UINT32,
	SPOE_DATA_T_INT64,
	SPOE_DATA_T_UINT64,
	SPOE_DATA_T_IPV4,
	SPOE_DATA_T_IPV6,
	SPOE_DATA_T_STR,
	SPOE_DATA_T_BIN,
	SPOE_DATA_TYPES
};

/* a memory block of arbitrary size, or a string */
struct chunk {
	char   *ptr;
	size_t  len;
};

/* all data types that may be encoded/decoded for each spoe_data_type */
union spoe_data {
	bool            boolean;
	int32_t         int32;
	uint32_t        uint32;
	int64_t         int64;
	uint64_t        uint64;
	struct in_addr  ipv4;
	struct in6_addr ipv6;
	struct chunk    chk;     /* types STR and BIN */
};

/* Masks to get data type or flags value */
#define SPOE_DATA_T_MASK  0x0F
#define SPOE_DATA_FL_MASK 0xF0

/* Flags to set Boolean values */
#define SPOE_DATA_FL_FALSE 0x00
#define SPOE_DATA_FL_TRUE  0x10


#endif /* _TYPES_SPOE_H */
