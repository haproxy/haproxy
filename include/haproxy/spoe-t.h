/*
 * include/haproxy/spoe-t.h
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

#ifndef _HAPROXY_SPOE_T_H
#define _HAPROXY_SPOE_T_H

#include <sys/time.h>

#include <haproxy/buf-t.h>
#include <haproxy/dynbuf-t.h>
#include <haproxy/filters-t.h>
#include <haproxy/freq_ctr-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/sample-t.h>
#include <haproxy/stream-t.h>
#include <haproxy/task-t.h>
#include <haproxy/thread-t.h>

/* Reserved 4 bytes to the frame size. So a frame and its size can be written
 * together in a buffer */
#define SPOP_MAX_FRAME_SIZE     global.tune.bufsize - 4

/* The minimum size for a frame */
#define SPOP_MIN_FRAME_SIZE     256

/* Reserved for the metadata and the frame type.
 * So <SPOP_MAX_FRAME_SIZE> - <FRAME_HDR_SIZE> is the maximum payload size */
#define SPOP_FRAME_HDR_SIZE     32

/* Flags set on the SPOP frame */
#define SPOP_FRM_FL_FIN         0x00000001
#define SPOP_FRM_FL_ABRT        0x00000002


/* All supported SPOP actions */
enum spoe_action_type {
	SPOP_ACT_T_SET_VAR = 1,
	SPOP_ACT_T_UNSET_VAR,
	SPOP_ACT_TYPES,
};

/* SPOP Errors */
enum spop_error {
        SPOP_ERR_NONE               = 0x00,
        SPOP_ERR_IO                 = 0x01,
        SPOP_ERR_TOUT               = 0x02,
        SPOP_ERR_TOO_BIG            = 0x03,
        SPOP_ERR_INVALID            = 0x04,
        SPOP_ERR_NO_VSN             = 0x05,
        SPOP_ERR_NO_FRAME_SIZE      = 0x06,
        SPOP_ERR_NO_CAP             = 0x07,
        SPOP_ERR_BAD_VSN            = 0x08,
        SPOP_ERR_BAD_FRAME_SIZE     = 0x09,
        SPOP_ERR_FRAG_NOT_SUPPORTED = 0x0a,
        SPOP_ERR_INTERLACED_FRAMES  = 0x0b,
        SPOP_ERR_FRAMEID_NOTFOUND   = 0x0c,
        SPOP_ERR_RES                = 0x0d,
        SPOP_ERR_UNKNOWN            = 0x63,
	SPOP_ERR_ENTRIES,
};

/* Scopes used for variables set by agents. It is a way to be agnotic to vars
 * scope. */
enum spop_vars_scope {
	SPOP_SCOPE_PROC = 0, /* <=> SCOPE_PROC  */
	SPOP_SCOPE_SESS,     /* <=> SCOPE_SESS */
	SPOP_SCOPE_TXN,      /* <=> SCOPE_TXN  */
	SPOP_SCOPE_REQ,      /* <=> SCOPE_REQ  */
	SPOP_SCOPE_RES,      /* <=> SCOPE_RES  */
};

/* Masks to get SPOP data type or flags value */
#define SPOP_DATA_T_MASK  0x0F
#define SPOP_DATA_FL_MASK 0xF0

/* SPOP data flags to set Boolean values */
#define SPOP_DATA_FL_FALSE 0x00
#define SPOP_DATA_FL_TRUE  0x10

/* All supported SPOP data types */
enum spop_data_type {
	SPOP_DATA_T_NULL = 0,
	SPOP_DATA_T_BOOL,
	SPOP_DATA_T_INT32,
	SPOP_DATA_T_UINT32,
	SPOP_DATA_T_INT64,
	SPOP_DATA_T_UINT64,
	SPOP_DATA_T_IPV4,
	SPOP_DATA_T_IPV6,
	SPOP_DATA_T_STR,
	SPOP_DATA_T_BIN,
	SPOP_DATA_TYPES
};

/* SPOP Frame Types */
enum spop_frame_type {
	SPOP_FRM_T_UNSET = 0,

	/* Frames sent by HAProxy */
	SPOP_FRM_T_HAPROXY_HELLO = 1,
	SPOP_FRM_T_HAPROXY_DISCON,
	SPOP_FRM_T_HAPROXY_NOTIFY,

	/* Frames sent by the agents */
	SPOP_FRM_T_AGENT_HELLO = 101,
	SPOP_FRM_T_AGENT_DISCON,
	SPOP_FRM_T_AGENT_ACK
};

/* SPOE agent flags */
#define SPOE_FL_CONT_ON_ERR       0x00000001 /* Do not stop events processing when an error occurred */
#define SPOE_FL_PIPELINING        0x00000002 /* Set when SPOE agent supports pipelining (set by default) */
/* unused 0x00000004..0x00000010 */
#define SPOE_FL_FORCE_SET_VAR     0x00000020 /* Set when SPOE agent will set all variables from agent (and not only known variables) */

/* Type of list of messages */
#define SPOE_MSGS_BY_EVENT 0x01
#define SPOE_MSGS_BY_GROUP 0x02

/* Flags set on the SPOE context */
#define SPOE_CTX_FL_CLI_CONNECTED 0x00000001 /* Set after that on-client-session event was processed */
#define SPOE_CTX_FL_SRV_CONNECTED 0x00000002 /* Set after that on-server-session event was processed */
#define SPOE_CTX_FL_REQ_PROCESS   0x00000004 /* Set when SPOE is processing the request */
#define SPOE_CTX_FL_RSP_PROCESS   0x00000008 /* Set when SPOE is processing the response */
/* unsued 0x00000010 */

#define SPOE_CTX_FL_PROCESS (SPOE_CTX_FL_REQ_PROCESS|SPOE_CTX_FL_RSP_PROCESS)

/* Flags set on the SPOE applet */
#define SPOE_APPCTX_FL_PIPELINING    0x00000001 /* Set if pipelining is supported */
/* unused 0x00000002 */
/* unused 0x00000004 */

#define SPOE_APPCTX_ERR_NONE    0x00000000 /* no error yet, leave it to zero */
#define SPOE_APPCTX_ERR_TOUT    0x00000001 /* SPOE applet timeout */


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
	SPOE_APPCTX_ST_WAITING_SYNC_ACK,
	SPOE_APPCTX_ST_DISCONNECT,
	SPOE_APPCTX_ST_DISCONNECTING,
	SPOE_APPCTX_ST_EXIT,
	SPOE_APPCTX_ST_END,
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
	SPOE_CTX_ERR_INTERRUPT,
	SPOE_CTX_ERR_UNKNOWN = 255,
	SPOE_CTX_ERRS,
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
	struct spoe_config  *spoe_conf;       /* SPOE filter config */
	char                 *var_pfx;        /* Prefix used for vars set by the agent */
	char                 *var_on_error;   /* Variable to set when an error occurred, in the TXN scope */
	char                 *var_t_process;  /* Variable to set to report the processing time of the last event/group, in the TXN scope */
	char                 *var_t_total;    /* Variable to set to report the cumulative processing time, in the TXN scope */
	unsigned int          flags;          /* SPOE_FL_* */
	unsigned int          max_frame_size; /* Maximum frame size for this agent, before any negotiation */

	struct list *events;                  /* List of SPOE messages that will be sent
					       * for each supported events */

	struct list groups;                   /* List of available SPOE groups */

	struct list messages;                 /* list of all messages attached to this SPOE agent */

	char *engine_id;                      /* engine-id string */

	struct {
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
	struct buffer_wait  buffer_wait;  /* position in the list of resources waiting for a buffer */

	enum spoe_ctx_state state;        /* SPOE_CTX_ST_* */
	unsigned int        flags;        /* SPOE_CTX_FL_* */
	unsigned int        status_code;  /* SPOE_CTX_ERR_* */

	unsigned int        stream_id;    /* stream_id and frame_id are used */
	unsigned int        frame_id;     /* to map NOTIFY and ACK frames */
	unsigned int        process_exp;  /* expiration date to process an event */

	struct spoe_appctx *spoe_appctx; /* SPOE appctx sending the current frame */

	struct {
		ullong         start_ts;    /* start date of the current event/group */
		long           t_process;   /* processing time of the last event/group */
		unsigned long  t_total;     /* cumulative processing time */
	} stats; /* Stats for this stream */
};

/* SPOE context inside a appctx */
struct spoe_appctx {
	struct appctx      *owner;          /* the owner */
	struct spoe_agent  *agent;          /* agent on which the applet is attached */

	unsigned int        version;        /* the negotiated version */
	unsigned int        max_frame_size; /* the negotiated max-frame-size value */
	unsigned int        flags;          /* SPOE_APPCTX_FL_* */

	unsigned int        status_code;    /* SPOE_FRM_ERR_* */

	struct buffer       buffer;         /* Buffer used to store a encoded messages */
	struct buffer_wait  buffer_wait;    /* position in the list of resources waiting for a buffer */

	struct spoe_context *spoe_ctx;      /* The SPOE context to handle */
};

#endif /* _HAPROXY_SPOE_T_H */
