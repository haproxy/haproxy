/*
 * include/types/spoe.h
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

#ifndef _TYPES_SPOE_H
#define _TYPES_SPOE_H

#include <sys/time.h>

#include <common/buffer.h>
#include <common/mini-clist.h>
#include <common/hathreads.h>

#include <types/filters.h>
#include <types/freq_ctr.h>
#include <types/log.h>
#include <types/proxy.h>
#include <types/sample.h>
#include <types/stream.h>
#include <types/task.h>

/* Type of list of messages */
#define SPOE_MSGS_BY_EVENT 0x01
#define SPOE_MSGS_BY_GROUP 0x02

/* Flags set on the SPOE agent */
#define SPOE_FL_CONT_ON_ERR       0x00000001 /* Do not stop events processing when an error occurred */
#define SPOE_FL_PIPELINING        0x00000002 /* Set when SPOE agent supports pipelining (set by default) */
#define SPOE_FL_ASYNC             0x00000004 /* Set when SPOE agent supports async (set by default) */
#define SPOE_FL_SND_FRAGMENTATION 0x00000008 /* Set when SPOE agent supports sending fragmented payload */
#define SPOE_FL_RCV_FRAGMENTATION 0x00000010 /* Set when SPOE agent supports receiving fragmented payload */
#define SPOE_FL_FORCE_SET_VAR     0x00000020 /* Set when SPOE agent will set all variables from agent (and not only known variables) */

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

#define SPOE_APPCTX_ERR_NONE    0x00000000 /* no error yet, leave it to zero */
#define SPOE_APPCTX_ERR_TOUT    0x00000001 /* SPOE applet timeout */

/* Flags set on the SPOE frame */
#define SPOE_FRM_FL_FIN         0x00000001
#define SPOE_FRM_FL_ABRT        0x00000002

/* All possible states for a SPOE context */
enum spoe_ctx_state {
	SPOE_CTX_ST_NONE = 0,
	SPOE_CTX_ST_READY,
	SPOE_CTX_ST_ENCODING_MSGS,
	SPOE_CTX_ST_SENDING_MSGS,
	SPOE_CTX_ST_WAITING_ACK,
	SPOE_CTX_ST_DONE,
	SPOE_CTX_ST_ERROR,
};

/* All possible states for a SPOE applet */
enum spoe_appctx_state {
	SPOE_APPCTX_ST_CONNECT = 0,
	SPOE_APPCTX_ST_CONNECTING,
	SPOE_APPCTX_ST_IDLE,
	SPOE_APPCTX_ST_PROCESSING,
	SPOE_APPCTX_ST_SENDING_FRAG_NOTIFY,
	SPOE_APPCTX_ST_WAITING_SYNC_ACK,
	SPOE_APPCTX_ST_DISCONNECT,
	SPOE_APPCTX_ST_DISCONNECTING,
	SPOE_APPCTX_ST_EXIT,
	SPOE_APPCTX_ST_END,
};

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
	SPOE_CTX_ERR_INTERRUPT,
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
 * parsed, messages/groups can be undefined. */
struct spoe_placeholder {
	char       *id;    /* SPOE placeholder id */
	struct list list;  /* Use to chain SPOE placeholders */
};

/* Used during the config parsing, when SPOE agent section is parsed, to
 * register some variable names. */
struct spoe_var_placeholder {
	char        *name;  /* The variable name */
	struct list  list;  /* Use to chain SPOE var placeholders */
};

/* Describe a message that will be sent in a NOTIFY frame. A message has a name,
 * an argument list (see above) and it is linked to a specific event. */
struct spoe_message {
	char               *id;     /* SPOE message id */
	unsigned int        id_len; /* The message id length */
	struct spoe_agent  *agent;  /* SPOE agent owning this SPOE message */
	struct spoe_group  *group;  /* SPOE group owning this SPOE message (can be NULL) */
        struct {
                char       *file;   /* file where the SPOE message appears */
                int         line;   /* line where the SPOE message appears */
        } conf;                     /* config information */
	unsigned int        nargs;  /* # of arguments */
	struct list         args;   /* Arguments added when the SPOE messages is sent */
	struct list         list;   /* Used to chain SPOE messages */
	struct list         by_evt; /* By event list */
	struct list         by_grp; /* By group list */

	struct list         acls;   /* ACL declared on this message */
	struct acl_cond    *cond;   /* acl condition to meet */
	enum spoe_event     event;  /* SPOE_EV_* */
};

/* Describe a group of messages that will be sent in a NOTIFY frame. A group has
 * a name and a list of messages. It can be used by HAProxy, outside events
 * processing, mainly in (tcp|http) rules. */
struct spoe_group {
	char              *id;      /* SPOE group id */
	struct spoe_agent *agent;   /* SPOE agent owning this SPOE group */
        struct {
                char      *file;    /* file where the SPOE group appears */
                int        line;    /* line where the SPOE group appears */
        } conf;                     /* config information */

	struct list phs;      /* List of placeholders used during conf parsing */
	struct list messages; /* List of SPOE messages that will be sent by this
			       * group */

	struct list list;     /* Used to chain SPOE groups */
};

/* Describe a SPOE agent. */
struct spoe_agent {
	char                 *id;             /* SPOE agent id (name) */
        struct {
                char         *file;           /* file where the SPOE agent appears */
                int           line;           /* line where the SPOE agent appears */
        } conf;                               /* config information */
	union {
		struct proxy *be;             /* Backend used by this agent */
		char         *name;           /* Backend name used during conf parsing */
	} b;
	struct {
		unsigned int  hello;          /* Max time to receive AGENT-HELLO frame (in SPOE applet) */
		unsigned int  idle;           /* Max Idle timeout  (in SPOE applet) */
		unsigned int  processing;     /* Max time to process an event (in the main stream) */
	} timeout;

	/* Config info */
	char                 *var_pfx;        /* Prefix used for vars set by the agent */
	char                 *var_on_error;   /* Variable to set when an error occurred, in the TXN scope */
	char                 *var_t_process;  /* Variable to set to report the processing time of the last event/group, in the TXN scope */
	char                 *var_t_total;    /* Variable to set to report the cumulative processing time, in the TXN scope */
	unsigned int          flags;          /* SPOE_FL_* */
	unsigned int          cps_max;        /* Maximum # of connections per second */
	unsigned int          eps_max;        /* Maximum # of errors per second */
	unsigned int          max_frame_size; /* Maximum frame size for this agent, before any negotiation */
	unsigned int          max_fpa;        /* Maximum # of frames handled per applet at once */

	struct list events[SPOE_EV_EVENTS];   /* List of SPOE messages that will be sent
					       * for each supported events */

	struct list groups;                   /* List of available SPOE groups */

	struct list messages;                 /* list of all messages attached to this SPOE agent */

	/* running info */
	struct {
		char           *engine_id;      /* engine-id string */
		unsigned int    frame_size;     /* current maximum frame size, only used to encode messages */
		unsigned int    processing;
		struct freq_ctr processing_per_sec;

		struct freq_ctr conn_per_sec;   /* connections per second */
		struct freq_ctr err_per_sec;    /* connetion errors per second */

		struct eb_root  idle_applets;   /* idle SPOE applets available to process data */
		struct list     applets;        /* all SPOE applets for this agent */
		struct list     sending_queue;  /* Queue of streams waiting to send data */
		struct list     waiting_queue;  /* Queue of streams waiting for a ack, in async mode */
		__decl_hathreads(HA_SPINLOCK_T lock);
	} *rt;

	struct {
		unsigned int applets;            /* # of SPOE applets */
		unsigned int idles;              /* # of idle applets */
		unsigned int nb_sending;         /* # of streams waiting to send data */
		unsigned int nb_waiting;         /* # of streams waiting for a ack */
		unsigned long long nb_processed; /* # of frames processed by the SPOE */
		unsigned long long nb_errors;    /* # of errors during the processing */
	} counters;
};

/* SPOE filter configuration */
struct spoe_config {
	char              *id;          /* The SPOE engine name. If undefined in HAProxy config,
					 * it will be set with the SPOE agent name */
	struct proxy      *proxy;       /* Proxy owning the filter */
	struct spoe_agent *agent;       /* Agent used by this filter */
	struct proxy       agent_fe;    /* Agent frontend */
};

/* SPOE context attached to a stream. It is the main structure that handles the
 * processing offload */
struct spoe_context {
	struct filter      *filter;       /* The SPOE filter */
	struct stream      *strm;         /* The stream that should be offloaded */

	struct list        *events;       /* List of messages that will be sent during the stream processing */
	struct list        *groups;       /* List of available SPOE group */

	struct buffer       buffer;       /* Buffer used to store a encoded messages */
	struct buffer_wait  buffer_wait;  /* position in the list of ressources waiting for a buffer */
	struct list         list;

	enum spoe_ctx_state state;        /* SPOE_CTX_ST_* */
	unsigned int        flags;        /* SPOE_CTX_FL_* */
	unsigned int        status_code;  /* SPOE_CTX_ERR_* */

	unsigned int        stream_id;    /* stream_id and frame_id are used */
	unsigned int        frame_id;     /* to map NOTIFY and ACK frames */
	unsigned int        process_exp;  /* expiration date to process an event */

	struct spoe_appctx *spoe_appctx; /* SPOE appctx sending the current frame */
	struct {
		struct spoe_message *curmsg;      /* SPOE message from which to resume encoding */
		struct spoe_arg     *curarg;      /* SPOE arg in <curmsg> from which to resume encoding */
		unsigned int         curoff;      /* offset in <curarg> from which to resume encoding */
		unsigned int         curlen;      /* length of <curarg> need to be encode, for SMP_F_MAY_CHANGE data */
		unsigned int         flags;       /* SPOE_FRM_FL_* */
	} frag_ctx; /* Info about fragmented frames, valid on if SPOE_CTX_FL_FRAGMENTED is set */

	struct {
		struct timeval tv_start;    /* start date of the current event/group */
		struct timeval tv_request;  /* date the frame processing starts (reset for each frag) */
		struct timeval tv_queue;    /* date the frame is queued (reset for each frag) */
		struct timeval tv_wait;     /* date the stream starts waiting for a response */
		struct timeval tv_response; /* date the response processing starts */
		long           t_request;   /* delay to encode and push the frame in queue (cumulative for frags) */
		long           t_queue;     /* delay before the frame gets out the sending queue (cumulative for frags) */
		long           t_waiting;   /* delay before the response is reveived */
		long           t_response;  /* delay to process the response (from the stream pov) */
		long           t_process;   /* processing time of the last event/group */
		unsigned long  t_total;     /* cumulative processing time */
	} stats; /* Stats for this stream */
};

/* SPOE context inside a appctx */
struct spoe_appctx {
	struct appctx      *owner;          /* the owner */
	struct task        *task;           /* task to handle applet timeouts */
	struct spoe_agent  *agent;          /* agent on which the applet is attached */

	unsigned int        version;        /* the negotiated version */
	unsigned int        max_frame_size; /* the negotiated max-frame-size value */
	unsigned int        flags;          /* SPOE_APPCTX_FL_* */

	unsigned int        status_code;    /* SPOE_FRM_ERR_* */
#if defined(DEBUG_SPOE) || defined(DEBUG_FULL)
	char               *reason;         /* Error message, used for debugging only */
	int                 rlen;           /* reason length */
#endif

	struct buffer       buffer;         /* Buffer used to store a encoded messages */
	struct buffer_wait  buffer_wait;    /* position in the list of ressources waiting for a buffer */
	struct list         waiting_queue;  /* list of streams waiting for a ACK frame, in sync and pipelining mode */
	struct list         list;           /* next spoe appctx for the same agent */
	struct eb32_node    node;           /* node used for applets tree */
	unsigned int        cur_fpa;

	struct {
		struct spoe_context *ctx;    /* SPOE context owning the fragmented frame */
		unsigned int         cursid; /* stream-id of the fragmented frame. used if the processing is aborted */
		unsigned int         curfid; /* frame-id of the fragmented frame. used if the processing is aborted */
	} frag_ctx; /* Info about fragmented frames, unused for unfragmented frames */
};

/* Frame Types sent by HAProxy and by agents */
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

/* Masks to get data type or flags value */
#define SPOE_DATA_T_MASK  0x0F
#define SPOE_DATA_FL_MASK 0xF0

/* Flags to set Boolean values */
#define SPOE_DATA_FL_FALSE 0x00
#define SPOE_DATA_FL_TRUE  0x10


#endif /* _TYPES_SPOE_H */
