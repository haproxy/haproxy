/*
 * Stream processing offload engine management.
 *
 * Copyright 2016 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <ctype.h>
#include <errno.h>

#include <common/buffer.h>
#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/time.h>

#include <types/arg.h>
#include <types/filters.h>
#include <types/global.h>
#include <types/proxy.h>
#include <types/sample.h>
#include <types/stream.h>

#include <proto/arg.h>
#include <proto/backend.h>
#include <proto/filters.h>
#include <proto/freq_ctr.h>
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/session.h>
#include <proto/signal.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/vars.h>

#if defined(DEBUG_SPOE) || defined(DEBUG_FULL)
#define SPOE_PRINTF(x...) fprintf(x)
#else
#define SPOE_PRINTF(x...)
#endif

/* Reserved 4 bytes to the frame size. So a frame and its size can be written
 * together in a buffer */
#define MAX_FRAME_SIZE     global.tune.bufsize - 4

/* The minimum size for a frame */
#define MIN_FRAME_SIZE     256

/* Reserved for the metadata and the frame type.
 * So <MAX_FRAME_SIZE> - <FRAME_HDR_SIZE> is the maximum payload size */
#define FRAME_HDR_SIZE     32

/* Flags set on the SPOE agent */
#define SPOE_FL_CONT_ON_ERR       0x00000001 /* Do not stop events processing when an error occurred */

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
	char                 *engine_id;      /* engine-id string */
	char                 *var_pfx;        /* Prefix used for vars set by the agent */
	char                 *var_on_error;   /* Variable to set when an error occured, in the TXN scope */
	unsigned int          flags;          /* SPOE_FL_* */
	unsigned int          cps_max;        /* Maximum # of connections per second */
	unsigned int          eps_max;        /* Maximum # of errors per second */
	unsigned int          max_frame_size; /* Maximum frame size for this agent, before any negotiation */
	unsigned int          min_applets;    /* Minimum # applets alive at a time */
	unsigned int          max_fpa;        /* Maximum # of frames handled per applet at once */

	struct list messages[SPOE_EV_EVENTS]; /* List of SPOE messages that will be sent
					       * for each supported events */

	/* running info */
	unsigned int          frame_size;     /* current maximum frame size, only used to encode messages */
	unsigned int          applets_act;    /* # of applets alive at a time */
	unsigned int          applets_idle;   /* # of applets in the state SPOE_APPCTX_ST_IDLE */
	unsigned int          sending_rate;   /* the global sending rate */

	struct freq_ctr       conn_per_sec;   /* connections per second */
	struct freq_ctr       err_per_sec;    /* connetion errors per second */

	struct list           applets;        /* List of available SPOE applets */
	struct list           sending_queue;  /* Queue of streams waiting to send data */
	struct list           waiting_queue;  /* Queue of streams waiting for a ack, in async mode */

};

/* SPOE filter configuration */
struct spoe_config {
	struct proxy      *proxy;       /* Proxy owning the filter */
	struct spoe_agent *agent;       /* Agent used by this filter */
	struct proxy       agent_fe;    /* Agent frontend */
};

/* SPOE context attached to a stream. It is the main structure that handles the
 * processing offload */
struct spoe_context {
	struct filter      *filter;       /* The SPOE filter */
	struct stream      *strm;         /* The stream that should be offloaded */

	struct list        *messages;     /* List of messages that will be sent during the stream processing */
	struct buffer      *buffer;       /* Buffer used to store a encoded messages */
	struct buffer_wait  buffer_wait;  /* position in the list of ressources waiting for a buffer */
	struct list         list;

	enum spoe_ctx_state state;        /* SPOE_CTX_ST_* */
	unsigned int        flags;        /* SPOE_CTX_FL_* */
	unsigned int        status_code;  /* SPOE_CTX_ERR_* */

	unsigned int        stream_id;    /* stream_id and frame_id are used */
	unsigned int        frame_id;     /* to map NOTIFY and ACK frames */
	unsigned int        process_exp;  /* expiration date to process an event */

	struct {
		struct spoe_appctx  *spoe_appctx; /* SPOE appctx sending the fragmented frame */
		struct spoe_message *curmsg;      /* SPOE message from which to resume encoding */
		struct spoe_arg     *curarg;      /* SPOE arg in <curmsg> from which to resume encoding */
		unsigned int         curoff;      /* offset in <curarg> from which to resume encoding */
		unsigned int         flags;       /* SPOE_FRM_FL_* */
	} frag_ctx; /* Info about fragmented frames, valid on if SPOE_CTX_FL_FRAGMENTED is set */
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
	struct buffer      *buffer;         /* Buffer used to store a encoded messages */
	struct buffer_wait  buffer_wait;    /* position in the list of ressources waiting for a buffer */
	struct list         waiting_queue;  /* list of streams waiting for a ACK frame, in sync and pipelining mode */
	struct list         list;           /* next spoe appctx for the same agent */

	struct {
		struct spoe_context *ctx;    /* SPOE context owning the fragmented frame */
		unsigned int         cursid; /* stream-id of the fragmented frame. used if the processing is aborted */
		unsigned int         curfid; /* frame-id of the fragmented frame. used if the processing is aborted */
	} frag_ctx; /* Info about fragmented frames, unused for unfragmented frames */
};


/* Helper to get SPOE ctx inside an appctx */
#define SPOE_APPCTX(appctx) ((struct spoe_appctx *)((appctx)->ctx.spoe.ptr))

/* SPOE filter id. Used to identify SPOE filters */
const char *spoe_filter_id = "SPOE filter";

/* Set if the handle on SIGUSR1 is registered */
static int sighandler_registered = 0;

/* proxy used during the parsing */
struct proxy *curproxy = NULL;

/* The name of the SPOE engine, used during the parsing */
char *curengine = NULL;

/* SPOE agent used during the parsing */
struct spoe_agent *curagent = NULL;

/* SPOE message used during the parsing */
struct spoe_message *curmsg = NULL;

/* list of SPOE messages and placeholders used during the parsing */
struct list curmsgs;
struct list curmps;

/* Pools used to allocate SPOE structs */
static struct pool_head *pool2_spoe_ctx = NULL;
static struct pool_head *pool2_spoe_appctx = NULL;

/* Temporary variables used to ease error processing */
int  spoe_status_code = SPOE_FRM_ERR_NONE;
char spoe_reason[256];

struct flt_ops spoe_ops;

static int  queue_spoe_context(struct spoe_context *ctx);
static int  acquire_spoe_buffer(struct buffer **buf, struct buffer_wait *buffer_wait);
static void release_spoe_buffer(struct buffer **buf, struct buffer_wait *buffer_wait);

/********************************************************************
 * helper functions/globals
 ********************************************************************/
static void
release_spoe_msg_placeholder(struct spoe_msg_placeholder *mp)
{
	if (!mp)
		return;
	free(mp->id);
	free(mp);
}


static void
release_spoe_message(struct spoe_message *msg)
{
	struct spoe_arg *arg, *back;

	if (!msg)
		return;
	free(msg->id);
	free(msg->conf.file);
	list_for_each_entry_safe(arg, back, &msg->args, list) {
		release_sample_expr(arg->expr);
		free(arg->name);
		LIST_DEL(&arg->list);
		free(arg);
	}
	free(msg);
}

static void
release_spoe_agent(struct spoe_agent *agent)
{
	struct spoe_message *msg, *back;
	int                  i;

	if (!agent)
		return;
	free(agent->id);
	free(agent->conf.file);
	free(agent->var_pfx);
	free(agent->engine_id);
	free(agent->var_on_error);
	for (i = 0; i < SPOE_EV_EVENTS; ++i) {
		list_for_each_entry_safe(msg, back, &agent->messages[i], list) {
			LIST_DEL(&msg->list);
			release_spoe_message(msg);
		}
	}
	free(agent);
}

static const char *spoe_frm_err_reasons[SPOE_FRM_ERRS] = {
	[SPOE_FRM_ERR_NONE]               = "normal",
	[SPOE_FRM_ERR_IO]                 = "I/O error",
	[SPOE_FRM_ERR_TOUT]               = "a timeout occurred",
	[SPOE_FRM_ERR_TOO_BIG]            = "frame is too big",
	[SPOE_FRM_ERR_INVALID]            = "invalid frame received",
	[SPOE_FRM_ERR_NO_VSN]             = "version value not found",
	[SPOE_FRM_ERR_NO_FRAME_SIZE]      = "max-frame-size value not found",
	[SPOE_FRM_ERR_NO_CAP]             = "capabilities value not found",
	[SPOE_FRM_ERR_BAD_VSN]            = "unsupported version",
	[SPOE_FRM_ERR_BAD_FRAME_SIZE]     = "max-frame-size too big or too small",
	[SPOE_FRM_ERR_FRAG_NOT_SUPPORTED] = "fragmentation not supported",
	[SPOE_FRM_ERR_INTERLACED_FRAMES]  = "invalid interlaced frames",
	[SPOE_FRM_ERR_RES]                = "resource allocation error",
	[SPOE_FRM_ERR_UNKNOWN]            = "an unknown error occurred",
};

static const char *spoe_event_str[SPOE_EV_EVENTS] = {
	[SPOE_EV_ON_CLIENT_SESS] = "on-client-session",
	[SPOE_EV_ON_TCP_REQ_FE]  = "on-frontend-tcp-request",
	[SPOE_EV_ON_TCP_REQ_BE]  = "on-backend-tcp-request",
	[SPOE_EV_ON_HTTP_REQ_FE] = "on-frontend-http-request",
	[SPOE_EV_ON_HTTP_REQ_BE] = "on-backend-http-request",

	[SPOE_EV_ON_SERVER_SESS] = "on-server-session",
	[SPOE_EV_ON_TCP_RSP]     = "on-tcp-response",
	[SPOE_EV_ON_HTTP_RSP]    = "on-http-response",
};


#if defined(DEBUG_SPOE) || defined(DEBUG_FULL)

static const char *spoe_ctx_state_str[SPOE_CTX_ST_ERROR+1] = {
	[SPOE_CTX_ST_NONE]          = "NONE",
	[SPOE_CTX_ST_READY]         = "READY",
	[SPOE_CTX_ST_ENCODING_MSGS] = "ENCODING_MSGS",
	[SPOE_CTX_ST_SENDING_MSGS]  = "SENDING_MSGS",
	[SPOE_CTX_ST_WAITING_ACK]   = "WAITING_ACK",
	[SPOE_CTX_ST_DONE]          = "DONE",
	[SPOE_CTX_ST_ERROR]         = "ERROR",
};

static const char *spoe_appctx_state_str[SPOE_APPCTX_ST_END+1] = {
	[SPOE_APPCTX_ST_CONNECT]             = "CONNECT",
	[SPOE_APPCTX_ST_CONNECTING]          = "CONNECTING",
	[SPOE_APPCTX_ST_IDLE]                = "IDLE",
	[SPOE_APPCTX_ST_PROCESSING]          = "PROCESSING",
	[SPOE_APPCTX_ST_SENDING_FRAG_NOTIFY] = "SENDING_FRAG_NOTIFY",
	[SPOE_APPCTX_ST_WAITING_SYNC_ACK]    = "WAITING_SYNC_ACK",
	[SPOE_APPCTX_ST_DISCONNECT]          = "DISCONNECT",
	[SPOE_APPCTX_ST_DISCONNECTING]       = "DISCONNECTING",
	[SPOE_APPCTX_ST_EXIT]                = "EXIT",
	[SPOE_APPCTX_ST_END]                 = "END",
};

#endif

static char *
generate_pseudo_uuid()
{
	static int init = 0;

	const char uuid_fmt[] = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
	const char uuid_chr[] = "0123456789ABCDEF-";
	char *uuid;
	int i;

	if ((uuid = calloc(1, sizeof(uuid_fmt))) == NULL)
		return NULL;

	if (!init) {
		srand(now_ms);
		init = 1;
	}

	for (i = 0; i < sizeof(uuid_fmt)-1; i++) {
		int r = rand () % 16;

		switch (uuid_fmt[i]) {
			case 'x' : uuid[i] = uuid_chr[r]; break;
			case 'y' : uuid[i] = uuid_chr[(r & 0x03) | 0x08]; break;
			default  : uuid[i] = uuid_fmt[i]; break;
		}
	}
	return uuid;
}

static inline unsigned int
min_applets_act(struct spoe_agent *agent)
{
	unsigned int nbsrv;

	if (agent->min_applets)
		return agent->min_applets;

	nbsrv = (agent->b.be->srv_act ? agent->b.be->srv_act : agent->b.be->srv_bck);
	return 2*nbsrv;
}

/********************************************************************
 * Functions that encode/decode SPOE frames
 ********************************************************************/
/* Frame Types sent by HAProxy and by agents */
enum spoe_frame_type {
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

/* Helper to get static string length, excluding the terminating null byte */
#define SLEN(str) (sizeof(str)-1)

/* Predefined key used in HELLO/DISCONNECT frames */
#define SUPPORTED_VERSIONS_KEY     "supported-versions"
#define VERSION_KEY                "version"
#define MAX_FRAME_SIZE_KEY         "max-frame-size"
#define CAPABILITIES_KEY           "capabilities"
#define ENGINE_ID_KEY              "engine-id"
#define HEALTHCHECK_KEY            "healthcheck"
#define STATUS_CODE_KEY            "status-code"
#define MSG_KEY                    "message"

struct spoe_version {
	char *str;
	int   min;
	int   max;
};

/* All supported versions */
static struct spoe_version supported_versions[] = {
	{"1.0", 1000, 1000},
	{NULL,  0, 0}
};

/* Comma-separated list of supported versions */
#define SUPPORTED_VERSIONS_VAL  "1.0"

/* Comma-separated list of supported capabilities (none for now) */
//#define CAPABILITIES_VAL ""
#define CAPABILITIES_VAL "pipelining,async"

static int
decode_spoe_version(const char *str, size_t len)
{
	char   tmp[len+1], *start, *end;
	double d;
	int    vsn = -1;

	memcpy(tmp, str, len);
	tmp[len] = 0;

	start = tmp;
	while (isspace(*start))
		start++;

	d = strtod(start, &end);
	if (d == 0 || start == end)
		goto out;

	if (*end) {
		while (isspace(*end))
			end++;
		if (*end)
			goto out;
	}
	vsn = (int)(d * 1000);
  out:
	return vsn;
}

/* Encode a variable-length integer. This function never fails and returns the
 * number of written bytes. */
static int
encode_spoe_varint(uint64_t i, char *buf)
{
	int idx;

	if (i < 240) {
		buf[0] = (unsigned char)i;
		return 1;
	}

	buf[0] = (unsigned char)i | 240;
	i = (i - 240) >> 4;
	for (idx = 1; i >= 128; ++idx) {
		buf[idx] = (unsigned char)i | 128;
		i = (i - 128) >> 7;
	}
	buf[idx++] = (unsigned char)i;
	return idx;
}

/* Decode a varable-length integer. If the decoding fails, -1 is returned. This
 * happens when the buffer's end in reached. On success, the number of read
 * bytes is returned. */
static int
decode_spoe_varint(const char *buf, const char *end, uint64_t *i)
{
	unsigned char *msg = (unsigned char *)buf;
	int            idx = 0;

	if (msg >= (unsigned char *)end)
		return -1;

	if (msg[0] < 240) {
		*i = msg[0];
		return 1;
	}
	*i = msg[0];
	do {
		++idx;
		if (msg+idx >= (unsigned char *)end)
			return -1;
		*i += (uint64_t)msg[idx] <<  (4 + 7 * (idx-1));
	} while (msg[idx] >= 128);
	return (idx + 1);
}

/* Encode a string. The string will be prefix by its length, encoded as a
 * variable-length integer. This function never fails and returns the number of
 * written bytes. */
static int
encode_spoe_string(const char *str, size_t len, char *dst)
{
	int idx = 0;

	if (!len) {
		dst[0] = 0;
		return 1;
	}

	idx += encode_spoe_varint(len, dst);
	memcpy(dst+idx, str, len);
	return (idx + len);
}

/* Encode first part of a fragmented string. The string will be prefix by its
 * length, encoded as a variable-length integer. This function never fails and
 * returns the number of written bytes. */
static int
encode_frag_spoe_string(const char *str, size_t sz, size_t len, char *dst)
{
	int idx = 0;

	if (!sz) {
		dst[0] = 0;
		return 1;
	}

	idx += encode_spoe_varint(sz, dst);
	memcpy(dst+idx, str, len);
	return (idx + len);
}

/* Decode a string. Its length is decoded first as a variable-length integer. If
 * it succeeds, and if the string length is valid, the begin of the string is
 * saved in <*str>, its length is saved in <*len> and the total numbre of bytes
 * read is returned. If an error occurred, -1 is returned and <*str> remains
 * NULL. */
static int
decode_spoe_string(char *buf, char *end, char **str, uint64_t *len)
{
	int i, idx = 0;

	*str = NULL;
	*len = 0;

	if ((i = decode_spoe_varint(buf, end, len)) == -1)
		goto error;
	idx += i;
	if (buf + idx + *len > end)
		goto error;

	*str = buf+idx;
	return (idx + *len);

  error:
	return -1;
}

/* Skip a typed data. If an error occurred, -1 is returned, otherwise the number
 * of bytes read is returned. A types data is composed of a type (1 byte) and
 * corresponding data:
 *  - boolean: non additional data (0 bytes)
 *  - integers: a variable-length integer (see decode_spoe_varint)
 *  - ipv4: 4 bytes
 *  - ipv6: 16 bytes
 *  - binary and string: a buffer prefixed by its size, a variable-length
 *    integer (see decode_spoe_string) */
static int
skip_spoe_data(char *frame, char *end)
{
	uint64_t sz = 0;
	int      i, idx = 0;

	if (frame > end)
		return -1;

	switch (frame[idx++] & SPOE_DATA_T_MASK) {
		case SPOE_DATA_T_BOOL:
			break;
		case SPOE_DATA_T_INT32:
		case SPOE_DATA_T_INT64:
		case SPOE_DATA_T_UINT32:
		case SPOE_DATA_T_UINT64:
			if ((i = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			idx += i;
			break;
		case SPOE_DATA_T_IPV4:
			idx += 4;
			break;
		case SPOE_DATA_T_IPV6:
			idx += 16;
			break;
		case SPOE_DATA_T_STR:
		case SPOE_DATA_T_BIN:
			if ((i = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			idx += i + sz;
			break;
	}

	if (frame+idx > end)
		return -1;
	return idx;
}

/* Decode a typed data. If an error occurred, -1 is returned, otherwise the
 * number of read bytes is returned. See skip_spoe_data for details. */
static int
decode_spoe_data(char *frame, char *end, struct sample *smp)
{
	uint64_t sz = 0;
	int      type, i, idx = 0;

	if (frame > end)
		return -1;

	type = frame[idx++];
	switch (type & SPOE_DATA_T_MASK) {
		case SPOE_DATA_T_BOOL:
			smp->data.u.sint = ((type & SPOE_DATA_FL_TRUE) == SPOE_DATA_FL_TRUE);
			smp->data.type = SMP_T_BOOL;
			break;
		case SPOE_DATA_T_INT32:
		case SPOE_DATA_T_INT64:
		case SPOE_DATA_T_UINT32:
		case SPOE_DATA_T_UINT64:
			if ((i = decode_spoe_varint(frame+idx, end, (uint64_t *)&smp->data.u.sint)) == -1)
				return -1;
			idx += i;
			smp->data.type = SMP_T_SINT;
			break;
		case SPOE_DATA_T_IPV4:
			if (frame+idx+4 > end)
				return -1;
			memcpy(&smp->data.u.ipv4, frame+idx, 4);
			smp->data.type = SMP_T_IPV4;
			idx += 4;
			break;
		case SPOE_DATA_T_IPV6:
			if (frame+idx+16 > end)
				return -1;
			memcpy(&smp->data.u.ipv6, frame+idx, 16);
			smp->data.type = SMP_T_IPV6;
			idx += 16;
			break;
		case SPOE_DATA_T_STR:
			if ((i = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			idx += i;
			if (frame+idx+sz > end)
				return -1;
			smp->data.u.str.str = frame+idx;
			smp->data.u.str.len = sz;
			smp->data.type = SMP_T_STR;
			idx += sz;
			break;
		case SPOE_DATA_T_BIN:
			if ((i = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			idx += i;
			if (frame+idx+sz > end)
				return -1;
			smp->data.u.str.str = frame+idx;
			smp->data.u.str.len = sz;
			smp->data.type = SMP_T_BIN;
			idx += sz;
			break;
	}

	if (frame+idx > end)
		return -1;
	return idx;
}

/* Skip an action in a frame received from an agent. If an error occurred, -1 is
 * returned, otherwise the number of read bytes is returned. An action is
 * composed of the action type followed by a typed data. */
static int
skip_spoe_action(char *frame, char *end)
{
	int n, i, idx = 0;

	if (frame+2 > end)
		return -1;

	idx++; /* Skip the action type */
	n = frame[idx++];
	while (n-- > 0) {
		if ((i = skip_spoe_data(frame+idx, end)) == -1)
			return -1;
		idx += i;
	}

	if (frame+idx > end)
		return -1;
	return idx;
}

/* Encode HELLO frame sent by HAProxy to an agent. It returns the frame size on
 * success, 0 if the frame can be ignored and -1 if an error occurred. */
static int
prepare_spoe_hahello_frame(struct appctx *appctx, char *frame, size_t size)
{
	struct spoe_agent *agent = SPOE_APPCTX(appctx)->agent;
	unsigned int flags = SPOE_FRM_FL_FIN;
	int          idx = 0;
	size_t       max = (7   /* TYPE + METADATA */
			    + 1 + SLEN(SUPPORTED_VERSIONS_KEY) + 1 + 1 + SLEN(SUPPORTED_VERSIONS_VAL)
			    + 1 + SLEN(MAX_FRAME_SIZE_KEY) + 1 + 4
			    + 1 + SLEN(CAPABILITIES_KEY) + 1 + 1 + SLEN(CAPABILITIES_VAL)
			    + 1 + SLEN(ENGINE_ID_KEY) + 1 + 1 + 36);

	if (size < max) {
		spoe_status_code = SPOE_FRM_ERR_TOO_BIG;
		return -1;
	}

	/* Frame type */
	frame[idx++] = SPOE_FRM_T_HAPROXY_HELLO;

	/* Set flags */
	//flags = htonl(flags);
	memcpy(frame+idx, (char *)&flags, 4);
	idx += 4;

	/* No stream-id and frame-id for HELLO frames */
	frame[idx++] = 0;
	frame[idx++] = 0;

	/* There are 3 mandatory items: "supported-versions", "max-frame-size"
	 * and "capabilities" */

	/* "supported-versions" K/V item */
	idx += encode_spoe_string(SUPPORTED_VERSIONS_KEY, SLEN(SUPPORTED_VERSIONS_KEY), frame+idx);
	frame[idx++] = SPOE_DATA_T_STR;
	idx += encode_spoe_string(SUPPORTED_VERSIONS_VAL, SLEN(SUPPORTED_VERSIONS_VAL), frame+idx);

	/* "max-fram-size" K/V item */
	idx += encode_spoe_string(MAX_FRAME_SIZE_KEY, SLEN(MAX_FRAME_SIZE_KEY), frame+idx);
	frame[idx++] = SPOE_DATA_T_UINT32;
	idx += encode_spoe_varint(SPOE_APPCTX(appctx)->max_frame_size, frame+idx);

	/* "capabilities" K/V item */
	idx += encode_spoe_string(CAPABILITIES_KEY, SLEN(CAPABILITIES_KEY), frame+idx);
	frame[idx++] = SPOE_DATA_T_STR;
	idx += encode_spoe_string(CAPABILITIES_VAL, SLEN(CAPABILITIES_VAL), frame+idx);

	/* "engine-id" K/V item */
	if (agent != NULL && agent->engine_id != NULL) {
		idx += encode_spoe_string(ENGINE_ID_KEY, SLEN(ENGINE_ID_KEY), frame+idx);
		frame[idx++] = SPOE_DATA_T_STR;
		idx += encode_spoe_string(agent->engine_id, strlen(agent->engine_id), frame+idx);
	}

	return idx;
}

/* Encode DISCONNECT frame sent by HAProxy to an agent. It returns the frame
 * size on success, 0 if the frame can be ignored and -1 if an error
 * occurred. */
static int
prepare_spoe_hadiscon_frame(struct appctx *appctx, char *frame, size_t size)
{
	const char *reason;
	unsigned int flags = SPOE_FRM_FL_FIN;
	int          rlen, idx = 0;
	size_t       max = (7   /* TYPE + METADATA */
			    + 1 + SLEN(STATUS_CODE_KEY) + 1 + 2
			    + 1 + SLEN(MSG_KEY) + 1 + 2 + 255);

	if (size < max)
		return -1;

	/* Get the message corresponding to the status code */
	if (spoe_status_code >= SPOE_FRM_ERRS)
		spoe_status_code = SPOE_FRM_ERR_UNKNOWN;
	reason = spoe_frm_err_reasons[spoe_status_code];
	rlen   = strlen(reason);

	 /* Frame type */
	frame[idx++] = SPOE_FRM_T_HAPROXY_DISCON;

	/* Set flags */
	memcpy(frame+idx, (char *)&flags, 4);
	idx += 4;

	/* No stream-id and frame-id for DISCONNECT frames */
	frame[idx++] = 0;
	frame[idx++] = 0;

	/* There are 2 mandatory items: "status-code" and "message" */

	/* "status-code" K/V item */
	idx += encode_spoe_string(STATUS_CODE_KEY, SLEN(STATUS_CODE_KEY), frame+idx);
	frame[idx++] = SPOE_DATA_T_UINT32;
	idx += encode_spoe_varint(spoe_status_code, frame+idx);

	/* "message" K/V item */
	idx += encode_spoe_string(MSG_KEY, SLEN(MSG_KEY), frame+idx);
	frame[idx++] = SPOE_DATA_T_STR;
	idx += encode_spoe_string(reason, rlen, frame+idx);

	return idx;
}

/* Encode NOTIFY frame sent by HAProxy to an agent. It returns the frame size on
 * success, 0 if the frame can be ignored and -1 if an error occurred. */
static int
prepare_spoe_hanotify_frame(struct appctx *appctx, struct spoe_context *ctx,
			    char *frame, size_t size)
{
	int          idx = 0;
	unsigned int stream_id, frame_id, flags = SPOE_FRM_FL_FIN;

	frame[idx++] = SPOE_FRM_T_HAPROXY_NOTIFY;

	if (ctx == NULL) {
		flags    |= SPOE_FRM_FL_ABRT;
		stream_id = SPOE_APPCTX(appctx)->frag_ctx.cursid;
		frame_id  = SPOE_APPCTX(appctx)->frag_ctx.curfid;
	}
	else {
		stream_id = ctx->stream_id;
		frame_id  = ctx->frame_id;

		if (ctx->flags & SPOE_CTX_FL_FRAGMENTED) {
			if (!(SPOE_APPCTX(appctx)->flags & SPOE_APPCTX_FL_FRAGMENTATION)) {
				spoe_status_code = SPOE_FRM_ERR_FRAG_NOT_SUPPORTED;
				return 0;
			}
			flags = ctx->frag_ctx.flags;
		}
	}

	/* Set flags */
	memcpy(frame+idx, (char *)&flags, 4);
	idx += 4;

	/* Set stream-id and frame-id */
	idx += encode_spoe_varint(stream_id, frame+idx);
	idx += encode_spoe_varint(frame_id, frame+idx);

	/* check the buffer size */
	if (idx + SPOE_APPCTX(appctx)->buffer->i > size) {
		spoe_status_code = SPOE_FRM_ERR_TOO_BIG;
		return 0;
	}

	/* Copy encoded messages */
	memcpy(frame+idx, SPOE_APPCTX(appctx)->buffer->p, SPOE_APPCTX(appctx)->buffer->i);
	idx += SPOE_APPCTX(appctx)->buffer->i;
	return idx;
}

/* Decode HELLO frame sent by an agent. It returns the number of by read bytes
 * on success, 0 if the frame can be ignored and -1 if an error occurred. */
static int
handle_spoe_agenthello_frame(struct appctx *appctx, char *frame, size_t size)
{
	int          vsn, max_frame_size, i, idx = 0;
	unsigned int flags;
	size_t       min_size = (7   /* TYPE + METADATA */
				 + 1 + SLEN(VERSION_KEY) + 1 + 1 + 3
				 + 1 + SLEN(MAX_FRAME_SIZE_KEY) + 1 + 1
				 + 1 + SLEN(CAPABILITIES_KEY) + 1 + 1 + 0);

	/* Check frame type */
	if (frame[idx++] != SPOE_FRM_T_AGENT_HELLO)
		return 0;

	if (size < min_size) {
		spoe_status_code = SPOE_FRM_ERR_INVALID;
		return -1;
	}

	/* Retrieve flags */
	memcpy((char *)&flags, frame+idx, 4);
	idx += 4;

	/* Fragmentation is not supported for HELLO frame */
	if (!(flags & SPOE_FRM_FL_FIN)) {
		spoe_status_code = SPOE_FRM_ERR_FRAG_NOT_SUPPORTED;
		return -1;
	}

	/* stream-id and frame-id must be cleared */
	if (frame[idx] != 0 || frame[idx+1] != 0) {
		spoe_status_code = SPOE_FRM_ERR_INVALID;
		return -1;
	}
	idx += 2;

	/* There are 3 mandatory items: "version", "max-frame-size" and
	 * "capabilities" */

	/* Loop on K/V items */
	vsn = max_frame_size = flags = 0;
	while (idx < size) {
		char     *str;
		uint64_t  sz;

		/* Decode the item key */
		idx += decode_spoe_string(frame+idx, frame+size, &str, &sz);
		if (str == NULL) {
			spoe_status_code = SPOE_FRM_ERR_INVALID;
			return -1;
		}
		/* Check "version" K/V item */
		if (!memcmp(str, VERSION_KEY, sz)) {
			/* The value must be a string */
			if ((frame[idx++] & SPOE_DATA_T_MASK) != SPOE_DATA_T_STR) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}
			idx += decode_spoe_string(frame+idx, frame+size, &str, &sz);
			if (str == NULL) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}

			vsn = decode_spoe_version(str, sz);
			if (vsn == -1) {
				spoe_status_code = SPOE_FRM_ERR_BAD_VSN;
				return -1;
			}
			for (i = 0; supported_versions[i].str != NULL; ++i) {
				if (vsn >= supported_versions[i].min &&
				    vsn <= supported_versions[i].max)
					break;
			}
			if (supported_versions[i].str == NULL) {
				spoe_status_code = SPOE_FRM_ERR_BAD_VSN;
				return -1;
			}
		}
		/* Check "max-frame-size" K/V item */
		else if (!memcmp(str, MAX_FRAME_SIZE_KEY, sz)) {
			int type;

			/* The value must be integer */
			type = frame[idx++];
			if ((type & SPOE_DATA_T_MASK) != SPOE_DATA_T_INT32 &&
			    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_INT64 &&
			    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_UINT32 &&
			    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_UINT64) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}
			if ((i = decode_spoe_varint(frame+idx, frame+size, &sz)) == -1) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}
			idx += i;
			if (sz < MIN_FRAME_SIZE || sz > SPOE_APPCTX(appctx)->max_frame_size) {
				spoe_status_code = SPOE_FRM_ERR_BAD_FRAME_SIZE;
				return -1;
			}
			max_frame_size = sz;
		}
		/* Check "capabilities" K/V item */
		else if (!memcmp(str, CAPABILITIES_KEY, sz)) {
			int i;

			/* The value must be a string */
			if ((frame[idx++] & SPOE_DATA_T_MASK) != SPOE_DATA_T_STR) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}
			idx += decode_spoe_string(frame+idx, frame+size, &str, &sz);
			if (str == NULL)
				continue;

			i = 0;
			while (i < sz) {
				char *delim;

				/* Skip leading spaces */
				for (; isspace(str[i]) && i < sz; i++);

				if (sz - i >= 10 && !strncmp(str + i, "pipelining", 10)) {
					i += 10;
					if (sz == i || isspace(str[i]) || str[i] == ',')
						flags |= SPOE_APPCTX_FL_PIPELINING;
				}
				else if (sz - i >= 5 && !strncmp(str + i, "async", 5)) {
					i += 5;
					if (sz == i || isspace(str[i]) || str[i] == ',')
						flags |= SPOE_APPCTX_FL_ASYNC;
				}
				else if (sz - i >= 13 && !strncmp(str + i, "fragmentation", 13)) {
					i += 13;
					if (sz == i || isspace(str[i]) || str[i] == ',')
						flags |= SPOE_APPCTX_FL_FRAGMENTATION;
				}

				if (sz == i || (delim = memchr(str + i, ',', sz-i)) == NULL)
					break;
				i = (delim - str) + 1;
			}
		}
		else {
			/* Silently ignore unknown item */
			if ((i = skip_spoe_data(frame+idx, frame+size)) == -1) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}
			idx += i;
		}
	}

	/* Final checks */
	if (!vsn) {
		spoe_status_code = SPOE_FRM_ERR_NO_VSN;
		return -1;
	}
	if (!max_frame_size) {
		spoe_status_code = SPOE_FRM_ERR_NO_FRAME_SIZE;
		return -1;
	}

	SPOE_APPCTX(appctx)->version        = (unsigned int)vsn;
	SPOE_APPCTX(appctx)->max_frame_size = (unsigned int)max_frame_size;
	SPOE_APPCTX(appctx)->flags         |= flags;
	return idx;
}

/* Decode DISCONNECT frame sent by an agent. It returns the number of by read
 * bytes on success, 0 if the frame can be ignored and -1 if an error
 * occurred. */
static int
handle_spoe_agentdiscon_frame(struct appctx *appctx, char *frame, size_t size)
{
	int          i, idx = 0;
	unsigned int flags;
	size_t       min_size = (7   /* TYPE + METADATA */
				 + 1 + SLEN(STATUS_CODE_KEY) + 1 + 1
				 + 1 + SLEN(MSG_KEY) + 1 + 1);

	/* Check frame type */
	if (frame[idx++] != SPOE_FRM_T_AGENT_DISCON)
		return 0;

	if (size < min_size) {
		spoe_status_code = SPOE_FRM_ERR_INVALID;
		return -1;
	}

	/* Retrieve flags */
	memcpy((char *)&flags, frame+idx, 4);
	idx += 4;

	/* Fragmentation is not supported for DISCONNECT frame */
	if (!(flags & SPOE_FRM_FL_FIN)) {
		spoe_status_code = SPOE_FRM_ERR_FRAG_NOT_SUPPORTED;
		return -1;
	}

	/* stream-id and frame-id must be cleared */
	if (frame[idx] != 0 || frame[idx+1] != 0) {
		spoe_status_code = SPOE_FRM_ERR_INVALID;
		return -1;
	}
	idx += 2;

	/* There are 2 mandatory items: "status-code" and "message" */

	/* Loop on K/V items */
	while (idx < size) {
		char     *str;
		uint64_t  sz;

		/* Decode the item key */
		idx += decode_spoe_string(frame+idx, frame+size, &str, &sz);
		if (str == NULL) {
			spoe_status_code = SPOE_FRM_ERR_INVALID;
			return -1;
		}

		/* Check "status-code" K/V item */
		if (!memcmp(str, STATUS_CODE_KEY, sz)) {
			int type;

			/* The value must be an integer */
			type = frame[idx++];
			if ((type & SPOE_DATA_T_MASK) != SPOE_DATA_T_INT32 &&
			    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_INT64 &&
			    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_UINT32 &&
			    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_UINT64) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}
			if ((i = decode_spoe_varint(frame+idx, frame+size, &sz)) == -1) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}
			idx += i;
			spoe_status_code = sz;
		}

		/* Check "message" K/V item */
		else if (sz && !memcmp(str, MSG_KEY, sz)) {
			/* The value must be a string */
			if ((frame[idx++] & SPOE_DATA_T_MASK) != SPOE_DATA_T_STR) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}
			idx += decode_spoe_string(frame+idx, frame+size, &str, &sz);
			if (str == NULL || sz > 255) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}
			memcpy(spoe_reason, str, sz);
			spoe_reason[sz] = 0;
		}
		else {
			/* Silently ignore unknown item */
			if ((i = skip_spoe_data(frame+idx, frame+size)) == -1) {
				spoe_status_code = SPOE_FRM_ERR_INVALID;
				return -1;
			}
			idx += i;
		}
	}

	return idx;
}


/* Decode ACK frame sent by an agent. It returns the number of read bytes on
 * success, 0 if the frame can be ignored and -1 if an error occurred. */
static int
handle_spoe_agentack_frame(struct appctx *appctx, struct spoe_context **ctx,
			   char *frame, size_t size)
{
	struct spoe_agent *agent = SPOE_APPCTX(appctx)->agent;
	uint64_t           stream_id, frame_id;
	int                i, idx = 0;
	unsigned int       flags;
	size_t             min_size = (7  /* TYPE + METADATA */);

	/* Check frame type */
	if (frame[idx++] != SPOE_FRM_T_AGENT_ACK)
		return 0;

	if (size < min_size) {
		spoe_status_code = SPOE_FRM_ERR_INVALID;
		return -1;
	}

	/* Retrieve flags */
	memcpy((char *)&flags, frame+idx, 4);
	idx += 4;

	/* Fragmentation is not supported for now */
	if (!(flags & SPOE_FRM_FL_FIN)) {
		spoe_status_code = SPOE_FRM_ERR_FRAG_NOT_SUPPORTED;
		return -1;
	}

	/* Get the stream-id and the frame-id */
	if ((i = decode_spoe_varint(frame+idx, frame+size, &stream_id)) == -1)
		return 0;
	idx += i;
	if ((i= decode_spoe_varint(frame+idx, frame+size, &frame_id)) == -1)
		return 0;
	idx += i;

	if (SPOE_APPCTX(appctx)->flags & SPOE_APPCTX_FL_ASYNC) {
		list_for_each_entry((*ctx), &agent->waiting_queue, list) {
			if ((*ctx)->stream_id == (unsigned int)stream_id &&
			    (*ctx)->frame_id  == (unsigned int)frame_id)
				goto found;
		}
	}
	else {
		list_for_each_entry((*ctx), &SPOE_APPCTX(appctx)->waiting_queue, list) {
			if ((*ctx)->stream_id == (unsigned int)stream_id &&
			     (*ctx)->frame_id  == (unsigned int)frame_id)
				goto found;
		}
	}

	/* FIXME: check if ABRT bit is set for a unfinished fragmented frame */

	/* No Stream found, ignore the frame */
	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: appctx=%p - Ignore ACK frame"
		    " - stream-id=%u - frame-id=%u\n",
		    (int)now.tv_sec, (int)now.tv_usec, agent->id,
		    __FUNCTION__, appctx,
		    (unsigned int)stream_id, (unsigned int)frame_id);

	*ctx = NULL;
	return 0;

  found:
	if (!acquire_spoe_buffer(&SPOE_APPCTX(appctx)->buffer, &SPOE_APPCTX(appctx)->buffer_wait)) {
		*ctx = NULL;
		return 1; /* Retry later */
	}

	/* Copy encoded actions */
	memcpy(SPOE_APPCTX(appctx)->buffer->p, frame+idx, size-idx);
	SPOE_APPCTX(appctx)->buffer->i = size-idx;

	/* Transfer the buffer ownership to the SPOE context */
	(*ctx)->buffer = SPOE_APPCTX(appctx)->buffer;
	SPOE_APPCTX(appctx)->buffer = &buf_empty;

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: appctx=%p"
		    " - ACK frame received - ctx=%p - stream-id=%u - frame-id=%u\n",
		    (int)now.tv_sec, (int)now.tv_usec, agent->id,
		    __FUNCTION__, appctx,
		    *ctx, (*ctx)->stream_id, (*ctx)->frame_id);
	return idx;
}

/* This function is used in cfgparse.c and declared in proto/checks.h. It
 * prepare the request to send to agents during a healthcheck. It returns 0 on
 * success and -1 if an error occurred. */
int
prepare_spoe_healthcheck_request(char **req, int *len)
{
	struct appctx       appctx;
	struct spoe_appctx  spoe_appctx;
	char               *frame, buf[MAX_FRAME_SIZE+4];
	unsigned int        framesz;
	int	            idx;

	memset(&appctx, 0, sizeof(appctx));
	memset(&spoe_appctx, 0, sizeof(spoe_appctx));
	memset(buf, 0, sizeof(buf));

	appctx.ctx.spoe.ptr = &spoe_appctx;
	SPOE_APPCTX(&appctx)->max_frame_size = MAX_FRAME_SIZE;

	frame = buf+4;
	idx = prepare_spoe_hahello_frame(&appctx, frame, MAX_FRAME_SIZE);
	if (idx <= 0)
		return -1;
	if (idx + SLEN(HEALTHCHECK_KEY) + 1 > MAX_FRAME_SIZE)
		return -1;

	/* "healthcheck" K/V item */
	idx += encode_spoe_string(HEALTHCHECK_KEY, SLEN(HEALTHCHECK_KEY), frame+idx);
	frame[idx++] = (SPOE_DATA_T_BOOL | SPOE_DATA_FL_TRUE);

	framesz = htonl(idx);
	memcpy(buf, (char *)&framesz, 4);

	if ((*req = malloc(idx+4)) == NULL)
		return -1;
	memcpy(*req, buf, idx+4);
	*len = idx+4;
	return 0;
}

/* This function is used in checks.c and declared in proto/checks.h. It decode
 * the response received from an agent during a healthcheck. It returns 0 on
 * success and -1 if an error occurred. */
int
handle_spoe_healthcheck_response(char *frame, size_t size, char *err, int errlen)
{
	struct appctx      appctx;
	struct spoe_appctx spoe_appctx;
	int                r;

	memset(&appctx, 0, sizeof(appctx));
	memset(&spoe_appctx, 0, sizeof(spoe_appctx));

	appctx.ctx.spoe.ptr = &spoe_appctx;
	SPOE_APPCTX(&appctx)->max_frame_size = MAX_FRAME_SIZE;

	if (handle_spoe_agentdiscon_frame(&appctx, frame, size) != 0)
		goto error;
	if ((r = handle_spoe_agenthello_frame(&appctx, frame, size)) <= 0) {
		if (r == 0)
			spoe_status_code = SPOE_FRM_ERR_INVALID;
		goto error;
	}

	return 0;

  error:
	if (spoe_status_code >= SPOE_FRM_ERRS)
		spoe_status_code = SPOE_FRM_ERR_UNKNOWN;
	strncpy(err, spoe_frm_err_reasons[spoe_status_code], errlen);
	return -1;
}

/* Send a SPOE frame to an agent. It returns -1 when an error occurred, 0 when
 * the frame can be ignored, 1 to retry later, and the frame legnth on
 * success. */
static int
send_spoe_frame(struct appctx *appctx, char *buf, size_t framesz)
{
	struct stream_interface *si = appctx->owner;
	int                      ret;
	uint32_t                 netint;

	if (si_ic(si)->buf == &buf_empty)
		return 1;

	netint = htonl(framesz);
	memcpy(buf, (char *)&netint, 4);
	ret = bi_putblk(si_ic(si), buf, framesz+4);

	if (ret <= 0) {
		if (ret == -1)
			return 1; /* retry */
		spoe_status_code = SPOE_FRM_ERR_IO;
		return -1; /* error */
	}
	return framesz;
}

/* Receive a SPOE frame from an agent. It return -1 when an error occurred, 0
 * when the frame can be ignored, 1 to retry later and the frame length on
 * success. */
static int
recv_spoe_frame(struct appctx *appctx, char *buf, size_t framesz)
{
	struct stream_interface *si = appctx->owner;
	int                      ret;
	uint32_t                 netint;

	if (si_oc(si)->buf == &buf_empty)
		return 1;

	ret = bo_getblk(si_oc(si), (char *)&netint, 4, 0);
	if (ret > 0) {
		framesz = ntohl(netint);
		if (framesz > SPOE_APPCTX(appctx)->max_frame_size) {
			spoe_status_code = SPOE_FRM_ERR_TOO_BIG;
			return -1;
		}
		ret = bo_getblk(si_oc(si), trash.str, framesz, 4);
	}
	if (ret <= 0) {
		if (ret == 0)
			return 1; /* retry */
		spoe_status_code = SPOE_FRM_ERR_IO;
		return -1; /* error */
	}
	return framesz;
}

/********************************************************************
 * Functions that manage the SPOE applet
 ********************************************************************/
static int
wakeup_spoe_appctx(struct appctx *appctx)
{
	si_applet_want_get(appctx->owner);
	si_applet_want_put(appctx->owner);
	appctx_wakeup(appctx);
	return 1;
}

/* Callback function that catches applet timeouts. If a timeout occurred, we set
 * <appctx->st1> flag and the SPOE applet is woken up. */
static struct task *
process_spoe_applet(struct task * task)
{
	struct appctx *appctx = task->context;

	appctx->st1 = SPOE_APPCTX_ERR_NONE;
	if (tick_is_expired(task->expire, now_ms)) {
		task->expire = TICK_ETERNITY;
		appctx->st1 = SPOE_APPCTX_ERR_TOUT;
	}
	wakeup_spoe_appctx(appctx);
	return task;
}

/* Callback function that releases a SPOE applet. This happens when the
 * connection with the agent is closed. */
static void
release_spoe_applet(struct appctx *appctx)
{
	struct stream_interface *si    = appctx->owner;
	struct spoe_agent       *agent = SPOE_APPCTX(appctx)->agent;
	struct spoe_context     *ctx, *back;
	struct spoe_appctx      *spoe_appctx;

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: appctx=%p\n",
		    (int)now.tv_sec, (int)now.tv_usec, agent->id,
		    __FUNCTION__, appctx);

	agent->applets_act--;
	if (!LIST_ISEMPTY(&SPOE_APPCTX(appctx)->list)) {
		LIST_DEL(&SPOE_APPCTX(appctx)->list);
		LIST_INIT(&SPOE_APPCTX(appctx)->list);
	}

	if (appctx->st0 != SPOE_APPCTX_ST_END) {
		if (appctx->st0 == SPOE_APPCTX_ST_IDLE)
			agent->applets_idle--;

		si_shutw(si);
		si_shutr(si);
		si_ic(si)->flags |= CF_READ_NULL;
		appctx->st0 = SPOE_APPCTX_ST_END;
		if (SPOE_APPCTX(appctx)->status_code == SPOE_FRM_ERR_NONE)
			SPOE_APPCTX(appctx)->status_code = SPOE_FRM_ERR_IO;
	}

	if (SPOE_APPCTX(appctx)->task) {
		task_delete(SPOE_APPCTX(appctx)->task);
		task_free(SPOE_APPCTX(appctx)->task);
	}

	list_for_each_entry_safe(ctx, back, &SPOE_APPCTX(appctx)->waiting_queue, list) {
		LIST_DEL(&ctx->list);
		LIST_INIT(&ctx->list);
		ctx->state = SPOE_CTX_ST_ERROR;
		ctx->status_code = (SPOE_APPCTX(appctx)->status_code + 0x100);
		task_wakeup(ctx->strm->task, TASK_WOKEN_MSG);
	}

	if (SPOE_APPCTX(appctx)->frag_ctx.ctx) {
		ctx = SPOE_APPCTX(appctx)->frag_ctx.ctx;
		ctx->frag_ctx.spoe_appctx = NULL;
		ctx->state = SPOE_CTX_ST_ERROR;
		ctx->status_code = (SPOE_APPCTX(appctx)->status_code + 0x100);
		task_wakeup(ctx->strm->task, TASK_WOKEN_MSG);
	}

	release_spoe_buffer(&SPOE_APPCTX(appctx)->buffer, &SPOE_APPCTX(appctx)->buffer_wait);
	pool_free2(pool2_spoe_appctx, SPOE_APPCTX(appctx));

	if (!LIST_ISEMPTY(&agent->applets))
		goto end;

	list_for_each_entry_safe(ctx, back, &agent->sending_queue, list) {
		LIST_DEL(&ctx->list);
		LIST_INIT(&ctx->list);
		ctx->state = SPOE_CTX_ST_ERROR;
		ctx->status_code = (SPOE_APPCTX(appctx)->status_code + 0x100);
		task_wakeup(ctx->strm->task, TASK_WOKEN_MSG);
	}

	list_for_each_entry_safe(ctx, back, &agent->waiting_queue, list) {
		LIST_DEL(&ctx->list);
		LIST_INIT(&ctx->list);
		ctx->state = SPOE_CTX_ST_ERROR;
		ctx->status_code = (SPOE_APPCTX(appctx)->status_code + 0x100);
		task_wakeup(ctx->strm->task, TASK_WOKEN_MSG);
	}

  end:
	/* Update runtinme agent info */
	agent->frame_size = agent->max_frame_size;
	list_for_each_entry(spoe_appctx, &agent->applets, list)
		agent->frame_size = MIN(spoe_appctx->max_frame_size, agent->frame_size);
}

static int
handle_connect_spoe_applet(struct appctx *appctx)
{
	struct stream_interface *si    = appctx->owner;
	struct spoe_agent       *agent = SPOE_APPCTX(appctx)->agent;
	char *frame = trash.str;
	int   ret;

	if (si->state <= SI_ST_CON) {
		si_applet_want_put(si);
		task_wakeup(si_strm(si)->task, TASK_WOKEN_MSG);
		goto stop;
	}
	if (si->state != SI_ST_EST) {
		spoe_status_code = SPOE_FRM_ERR_IO;
		goto exit;
	}

	if (appctx->st1 == SPOE_APPCTX_ERR_TOUT) {
		SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: appctx=%p - Connection timed out\n",
			    (int)now.tv_sec, (int)now.tv_usec, agent->id, __FUNCTION__, appctx);
		spoe_status_code = SPOE_FRM_ERR_TOUT;
		goto exit;
	}

	if (SPOE_APPCTX(appctx)->task->expire == TICK_ETERNITY)
		SPOE_APPCTX(appctx)->task->expire = tick_add_ifset(now_ms, agent->timeout.hello);

	ret = prepare_spoe_hahello_frame(appctx, frame+4, SPOE_APPCTX(appctx)->max_frame_size);
	if (ret > 1)
		ret = send_spoe_frame(appctx, frame, ret);

	switch (ret) {
		case -1: /* error */
			goto exit;

		case  0: /* ignore => an error, cannot be ignored */
			goto exit;

		case  1: /* retry later */
			si_applet_cant_put(si);
			goto stop;

		default: /* CONNECT frame successfully sent */
			appctx->st0 = SPOE_APPCTX_ST_CONNECTING;
			goto next;
	}

  next:
	return 0;
  stop:
	return 1;
  exit:
	SPOE_APPCTX(appctx)->status_code = spoe_status_code;
	appctx->st0 = SPOE_APPCTX_ST_EXIT;
	return 0;
}

static int
handle_connecting_spoe_applet(struct appctx *appctx)
{
	struct stream_interface *si     = appctx->owner;
	struct spoe_agent       *agent  = SPOE_APPCTX(appctx)->agent;
	char *frame = trash.str;
	int   ret, framesz = 0;


	if (si->state == SI_ST_CLO || si_opposite(si)->state == SI_ST_CLO) {
		spoe_status_code = SPOE_FRM_ERR_IO;
		goto exit;
	}

	if (appctx->st1 == SPOE_APPCTX_ERR_TOUT) {
		SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: appctx=%p - Connection timed out\n",
			    (int)now.tv_sec, (int)now.tv_usec, agent->id, __FUNCTION__, appctx);
		spoe_status_code = SPOE_FRM_ERR_TOUT;
		goto exit;
	}

	ret = recv_spoe_frame(appctx, frame, SPOE_APPCTX(appctx)->max_frame_size);
	if (ret > 1) {
		if (*frame == SPOE_FRM_T_AGENT_DISCON) {
			appctx->st0 = SPOE_APPCTX_ST_DISCONNECTING;
			goto next;
		}
		framesz = ret;
		ret = handle_spoe_agenthello_frame(appctx, frame, framesz);
	}

	switch (ret) {
		case -1: /* error */
			if (framesz)
				bo_skip(si_oc(si), framesz+4);
			appctx->st0 = SPOE_APPCTX_ST_DISCONNECT;
			goto next;

		case 0: /* ignore */
			if (framesz)
				bo_skip(si_oc(si), framesz+4);
			appctx->st0 = SPOE_APPCTX_ST_DISCONNECT;
			goto next;

		case 1: /* retry later */
			goto stop;

		default:
			/* hello handshake is finished, set the idle timeout,
			 * Add the appctx in the agent cache, decrease the
			 * number of new applets and wake up waiting streams. */
			if (framesz)
				bo_skip(si_oc(si), framesz+4);
			agent->applets_idle++;
			appctx->st0 = SPOE_APPCTX_ST_IDLE;
			LIST_DEL(&SPOE_APPCTX(appctx)->list);
			LIST_ADD(&agent->applets, &SPOE_APPCTX(appctx)->list);

			/* Update runtinme agent info */
			agent->frame_size = MIN(SPOE_APPCTX(appctx)->max_frame_size, agent->frame_size);
			goto next;
	}

  next:
	SPOE_APPCTX(appctx)->task->expire = tick_add_ifset(now_ms, agent->timeout.idle);
	return 0;
  stop:
	return 1;
  exit:
	SPOE_APPCTX(appctx)->status_code = spoe_status_code;
	appctx->st0 = SPOE_APPCTX_ST_EXIT;
	return 0;
}

static int
handle_processing_spoe_applet(struct appctx *appctx)
{
	struct stream_interface *si    = appctx->owner;
	struct spoe_agent       *agent = SPOE_APPCTX(appctx)->agent;
	struct spoe_context     *ctx   = NULL;
	char         *frame = trash.str;
	unsigned int  fpa = 0;
	int           ret, framesz = 0, skip_sending = 0, skip_receiving = 0;

	if (si->state == SI_ST_CLO || si_opposite(si)->state == SI_ST_CLO) {
		spoe_status_code = SPOE_FRM_ERR_IO;
		goto exit;
	}

	if (appctx->st1 == SPOE_APPCTX_ERR_TOUT) {
		spoe_status_code = SPOE_FRM_ERR_TOUT;
		appctx->st0      = SPOE_APPCTX_ST_DISCONNECT;
		appctx->st1      = SPOE_APPCTX_ERR_NONE;
		goto next;
	}

  process:
	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: appctx=%p"
		    " - process: fpa=%u/%u - skip_sending=%d - skip_receiving=%d"
		    " - appctx-state=%s\n",
		    (int)now.tv_sec, (int)now.tv_usec, agent->id,
		    __FUNCTION__, appctx, fpa, agent->max_fpa,
		    skip_sending, skip_receiving, spoe_appctx_state_str[appctx->st0]);

	if (fpa > agent->max_fpa || (skip_sending && skip_receiving))
		goto stop;
	else if (appctx->st0 == SPOE_APPCTX_ST_WAITING_SYNC_ACK) {
		if (skip_receiving)
			goto stop;
		goto recv_frame;
	}
	else if (skip_sending)
		goto recv_frame;
	else if (appctx->st0 == SPOE_APPCTX_ST_SENDING_FRAG_NOTIFY) {
		ctx = SPOE_APPCTX(appctx)->frag_ctx.ctx;
		goto send_frame;
	}
	else if (LIST_ISEMPTY(&agent->sending_queue)) {
		skip_sending = 1;
		goto recv_frame;
	}
	ctx = LIST_NEXT(&agent->sending_queue, typeof(ctx), list);

  send_frame:
	/* Transfer the buffer ownership to the SPOE appctx */
	if (ctx) {
		SPOE_APPCTX(appctx)->buffer = ctx->buffer;
		ctx->buffer = &buf_empty;
	}

	ret = prepare_spoe_hanotify_frame(appctx, ctx, frame+4, SPOE_APPCTX(appctx)->max_frame_size);
	if (ret > 1)
		ret = send_spoe_frame(appctx, frame, ret);

	switch (ret) {
		case -1: /* error */
			appctx->st0 = SPOE_APPCTX_ST_DISCONNECT;
			goto next;

		case 0: /* ignore */
			release_spoe_buffer(&SPOE_APPCTX(appctx)->buffer, &SPOE_APPCTX(appctx)->buffer_wait);
			agent->sending_rate++;
			fpa++;

			LIST_DEL(&ctx->list);
			LIST_INIT(&ctx->list);
			ctx->state = SPOE_CTX_ST_ERROR;
			ctx->status_code = (spoe_status_code + 0x100);
			task_wakeup(ctx->strm->task, TASK_WOKEN_MSG);
			break;

		case 1: /* retry */
			si_applet_cant_put(si);
			skip_sending = 1;
			break;

		default:
			release_spoe_buffer(&SPOE_APPCTX(appctx)->buffer, &SPOE_APPCTX(appctx)->buffer_wait);
			agent->sending_rate++;
			fpa++;

			if (ctx == NULL) {
				appctx->st0 = SPOE_APPCTX_ST_PROCESSING;
				SPOE_APPCTX(appctx)->frag_ctx.ctx    = NULL;
				SPOE_APPCTX(appctx)->frag_ctx.cursid = 0;
				SPOE_APPCTX(appctx)->frag_ctx.curfid = 0;
				break;
			}
			LIST_DEL(&ctx->list);
			LIST_INIT(&ctx->list);

			if (ctx->flags & SPOE_CTX_FL_FRAGMENTED) {
				if (ctx->frag_ctx.flags & SPOE_FRM_FL_FIN) {
					if (SPOE_APPCTX(appctx)->flags & SPOE_APPCTX_FL_ASYNC) {
						appctx->st0 = SPOE_APPCTX_ST_PROCESSING;
						LIST_ADDQ(&agent->waiting_queue, &ctx->list);
					}
					else if (SPOE_APPCTX(appctx)->flags & SPOE_APPCTX_FL_PIPELINING) {
						appctx->st0 = SPOE_APPCTX_ST_PROCESSING;
						LIST_ADDQ(&SPOE_APPCTX(appctx)->waiting_queue, &ctx->list);
					}
					else {
						appctx->st0 = SPOE_APPCTX_ST_WAITING_SYNC_ACK;
						LIST_ADDQ(&SPOE_APPCTX(appctx)->waiting_queue, &ctx->list);
					}
					SPOE_APPCTX(appctx)->frag_ctx.ctx    = NULL;
					SPOE_APPCTX(appctx)->frag_ctx.cursid = 0;
					SPOE_APPCTX(appctx)->frag_ctx.curfid = 0;

					ctx->frag_ctx.spoe_appctx = NULL;
					ctx->state = SPOE_CTX_ST_WAITING_ACK;
				}
				else {
					appctx->st0 = SPOE_APPCTX_ST_SENDING_FRAG_NOTIFY;
					SPOE_APPCTX(appctx)->frag_ctx.ctx    = ctx;
					SPOE_APPCTX(appctx)->frag_ctx.cursid = ctx->stream_id;
					SPOE_APPCTX(appctx)->frag_ctx.curfid = ctx->frame_id;

					ctx->frag_ctx.spoe_appctx = SPOE_APPCTX(appctx);
					ctx->state = SPOE_CTX_ST_ENCODING_MSGS;
					task_wakeup(ctx->strm->task, TASK_WOKEN_MSG);
					skip_sending = 1;
				}
			}
			else {
				if (SPOE_APPCTX(appctx)->flags & SPOE_APPCTX_FL_ASYNC) {
					appctx->st0 = SPOE_APPCTX_ST_PROCESSING;
					LIST_ADDQ(&agent->waiting_queue, &ctx->list);
				}
				else if (SPOE_APPCTX(appctx)->flags & SPOE_APPCTX_FL_PIPELINING) {
					appctx->st0 = SPOE_APPCTX_ST_PROCESSING;
					LIST_ADDQ(&SPOE_APPCTX(appctx)->waiting_queue, &ctx->list);
				}
				else {
					appctx->st0 = SPOE_APPCTX_ST_WAITING_SYNC_ACK;
					LIST_ADDQ(&SPOE_APPCTX(appctx)->waiting_queue, &ctx->list);
				}

				ctx->state = SPOE_CTX_ST_WAITING_ACK;
			}
	}

	if (fpa > agent->max_fpa)
		goto stop;

  recv_frame:
	if (skip_receiving)
		goto process;

	framesz = 0;
	ret = recv_spoe_frame(appctx, frame, SPOE_APPCTX(appctx)->max_frame_size);
	if (ret > 1) {
		if (*frame == SPOE_FRM_T_AGENT_DISCON) {
			appctx->st0 = SPOE_APPCTX_ST_DISCONNECTING;
			goto next;
		}
		framesz = ret;
		ret = handle_spoe_agentack_frame(appctx, &ctx, frame, framesz);
	}
	switch (ret) {
		case -1: /* error */
			if (framesz)
				bo_skip(si_oc(si), framesz+4);
			appctx->st0 = SPOE_APPCTX_ST_DISCONNECT;
			goto next;

		case 0: /* ignore */
			if (framesz)
				bo_skip(si_oc(si), framesz+4);
			fpa++;
			break;

		case 1: /* retry */
			skip_receiving = 1;
			break;

		default:
			if (framesz)
				bo_skip(si_oc(si), framesz+4);
			fpa++;

			LIST_DEL(&ctx->list);
			LIST_INIT(&ctx->list);

			if (appctx->st0 == SPOE_APPCTX_ST_WAITING_SYNC_ACK)
				appctx->st0 = SPOE_APPCTX_ST_PROCESSING;

			ctx->state = SPOE_CTX_ST_DONE;
			task_wakeup(ctx->strm->task, TASK_WOKEN_MSG);
	}
	goto process;

  next:
	SPOE_APPCTX(appctx)->task->expire = tick_add_ifset(now_ms, agent->timeout.idle);
	return 0;
  stop:
	if (appctx->st0 == SPOE_APPCTX_ST_PROCESSING) {
		appctx->st0 = SPOE_APPCTX_ST_IDLE;
		agent->applets_idle++;
	}
	if (fpa || (SPOE_APPCTX(appctx)->flags & SPOE_APPCTX_FL_PERSIST)) {
		LIST_DEL(&SPOE_APPCTX(appctx)->list);
		LIST_ADD(&agent->applets, &SPOE_APPCTX(appctx)->list);
		if (fpa)
			SPOE_APPCTX(appctx)->task->expire = tick_add_ifset(now_ms, agent->timeout.idle);
	}
	return 1;

  exit:
	SPOE_APPCTX(appctx)->status_code = spoe_status_code;
	appctx->st0 = SPOE_APPCTX_ST_EXIT;
	return 0;
}

static int
handle_disconnect_spoe_applet(struct appctx *appctx)
{
	struct stream_interface *si    = appctx->owner;
	struct spoe_agent       *agent = SPOE_APPCTX(appctx)->agent;
	char *frame = trash.str;
	int ret;

	SPOE_APPCTX(appctx)->status_code = spoe_status_code;

	if (si->state == SI_ST_CLO || si_opposite(si)->state == SI_ST_CLO)
		goto exit;

	if (appctx->st1 == SPOE_APPCTX_ERR_TOUT)
		goto exit;

	ret = prepare_spoe_hadiscon_frame(appctx, frame+4, SPOE_APPCTX(appctx)->max_frame_size);
	if (ret > 1)
		ret = send_spoe_frame(appctx, frame, ret);

	switch (ret) {
		case -1: /* error */
			goto exit;

		case  0: /* ignore */
			goto exit;

		case 1: /* retry */
			si_applet_cant_put(si);
			goto stop;

		default:
			SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: appctx=%p"
				    " - disconnected by HAProxy (%d): %s\n",
				    (int)now.tv_sec, (int)now.tv_usec, agent->id,
				    __FUNCTION__, appctx, spoe_status_code,
				    spoe_frm_err_reasons[spoe_status_code]);

			appctx->st0 = SPOE_APPCTX_ST_DISCONNECTING;
			goto next;
	}

  next:
	SPOE_APPCTX(appctx)->task->expire = tick_add_ifset(now_ms, agent->timeout.idle);
	return 0;
  stop:
	return 1;
  exit:
	appctx->st0 = SPOE_APPCTX_ST_EXIT;
	return 0;
}

static int
handle_disconnecting_spoe_applet(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	char *frame = trash.str;
	int   ret, framesz = 0;

	if (si->state == SI_ST_CLO || si_opposite(si)->state == SI_ST_CLO) {
		spoe_status_code = SPOE_FRM_ERR_IO;
		goto exit;
	}

	if (appctx->st1 == SPOE_APPCTX_ERR_TOUT) {
		spoe_status_code = SPOE_FRM_ERR_TOUT;
		goto exit;
	}

	framesz = 0;
	ret = recv_spoe_frame(appctx, frame, SPOE_APPCTX(appctx)->max_frame_size);
	if (ret > 1) {
		framesz = ret;
		ret = handle_spoe_agentdiscon_frame(appctx, frame, framesz);
	}

	switch (ret) {
		case -1: /* error  */
			if (framesz)
				bo_skip(si_oc(si), framesz+4);
			SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: appctx=%p"
				    " - error on frame (%s)\n",
				    (int)now.tv_sec, (int)now.tv_usec,
				    ((struct spoe_agent *)SPOE_APPCTX(appctx)->agent)->id,
				    __FUNCTION__, appctx,
				    spoe_frm_err_reasons[spoe_status_code]);
			goto exit;

		case  0: /* ignore */
			if (framesz)
				bo_skip(si_oc(si), framesz+4);
			goto next;

		case  1: /* retry */
			goto stop;

		default:
			if (framesz)
				bo_skip(si_oc(si), framesz+4);
			SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: appctx=%p"
				    " - disconnected by peer (%d): %s\n",
				    (int)now.tv_sec, (int)now.tv_usec,
				    ((struct spoe_agent *)SPOE_APPCTX(appctx)->agent)->id,
				    __FUNCTION__, appctx, spoe_status_code,
				    spoe_reason);
			goto exit;
	}

  next:
	return 0;
  stop:
	return 1;
  exit:
	if (SPOE_APPCTX(appctx)->status_code == SPOE_FRM_ERR_NONE)
		SPOE_APPCTX(appctx)->status_code = spoe_status_code;
	appctx->st0 = SPOE_APPCTX_ST_EXIT;
	return 0;
}

/* I/O Handler processing messages exchanged with the agent */
static void
handle_spoe_applet(struct appctx *appctx)
{
	struct stream_interface *si    = appctx->owner;
	struct spoe_agent       *agent = SPOE_APPCTX(appctx)->agent;

	spoe_status_code = SPOE_FRM_ERR_NONE;

  switchstate:
	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: appctx=%p"
		    " - appctx-state=%s\n",
		    (int)now.tv_sec, (int)now.tv_usec, agent->id,
		    __FUNCTION__, appctx, spoe_appctx_state_str[appctx->st0]);

	switch (appctx->st0) {
		case SPOE_APPCTX_ST_CONNECT:
			if (handle_connect_spoe_applet(appctx))
				goto out;
			goto switchstate;

		case SPOE_APPCTX_ST_CONNECTING:
			if (handle_connecting_spoe_applet(appctx))
				goto out;
			goto switchstate;

		case SPOE_APPCTX_ST_IDLE:
			if (stopping &&
			    LIST_ISEMPTY(&agent->sending_queue) &&
			    LIST_ISEMPTY(&SPOE_APPCTX(appctx)->waiting_queue)) {
				SPOE_APPCTX(appctx)->task->expire = tick_add_ifset(now_ms, agent->timeout.idle);
				appctx->st0 = SPOE_APPCTX_ST_DISCONNECT;
				goto switchstate;
			}
			agent->applets_idle--;
			appctx->st0 = SPOE_APPCTX_ST_PROCESSING;
			/* fall through */

		case SPOE_APPCTX_ST_PROCESSING:
		case SPOE_APPCTX_ST_SENDING_FRAG_NOTIFY:
		case SPOE_APPCTX_ST_WAITING_SYNC_ACK:
			if (handle_processing_spoe_applet(appctx))
				goto out;
			goto switchstate;

		case SPOE_APPCTX_ST_DISCONNECT:
			if (handle_disconnect_spoe_applet(appctx))
				goto out;
			goto switchstate;

		case SPOE_APPCTX_ST_DISCONNECTING:
			if (handle_disconnecting_spoe_applet(appctx))
				goto out;
			goto switchstate;

		case SPOE_APPCTX_ST_EXIT:
			si_shutw(si);
			si_shutr(si);
			si_ic(si)->flags |= CF_READ_NULL;
			appctx->st0 = SPOE_APPCTX_ST_END;
			SPOE_APPCTX(appctx)->task->expire = TICK_ETERNITY;
			/* fall through */

		case SPOE_APPCTX_ST_END:
			return;
	}
  out:
	if (SPOE_APPCTX(appctx)->task->expire != TICK_ETERNITY)
		task_queue(SPOE_APPCTX(appctx)->task);
	si_oc(si)->flags |= CF_READ_DONTWAIT;
	task_wakeup(si_strm(si)->task, TASK_WOKEN_IO);
}

struct applet spoe_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<SPOE>", /* used for logging */
	.fct = handle_spoe_applet,
	.release = release_spoe_applet,
};

/* Create a SPOE applet. On success, the created applet is returned, else
 * NULL. */
static struct appctx *
create_spoe_appctx(struct spoe_config *conf)
{
	struct appctx      *appctx;
	struct session     *sess;
	struct task        *task;
	struct stream      *strm;

	if ((appctx = appctx_new(&spoe_applet)) == NULL)
		goto out_error;

	appctx->ctx.spoe.ptr = pool_alloc_dirty(pool2_spoe_appctx);
	if (SPOE_APPCTX(appctx) == NULL)
		goto out_free_appctx;
	memset(appctx->ctx.spoe.ptr, 0, pool2_spoe_appctx->size);

	appctx->st0 = SPOE_APPCTX_ST_CONNECT;
	if ((SPOE_APPCTX(appctx)->task = task_new()) == NULL)
		goto out_free_spoe_appctx;

	SPOE_APPCTX(appctx)->owner           = appctx;
	SPOE_APPCTX(appctx)->task->process   = process_spoe_applet;
	SPOE_APPCTX(appctx)->task->expire    = TICK_ETERNITY;
	SPOE_APPCTX(appctx)->task->context   = appctx;
	SPOE_APPCTX(appctx)->agent           = conf->agent;
	SPOE_APPCTX(appctx)->version         = 0;
	SPOE_APPCTX(appctx)->max_frame_size  = conf->agent->max_frame_size;
	SPOE_APPCTX(appctx)->flags           = 0;
	SPOE_APPCTX(appctx)->status_code     = SPOE_FRM_ERR_NONE;
	SPOE_APPCTX(appctx)->buffer          = &buf_empty;

	LIST_INIT(&SPOE_APPCTX(appctx)->buffer_wait.list);
	SPOE_APPCTX(appctx)->buffer_wait.target = appctx;
	SPOE_APPCTX(appctx)->buffer_wait.wakeup_cb = (int (*)(void *))wakeup_spoe_appctx;

	LIST_INIT(&SPOE_APPCTX(appctx)->list);
	LIST_INIT(&SPOE_APPCTX(appctx)->waiting_queue);

	sess = session_new(&conf->agent_fe, NULL, &appctx->obj_type);
	if (!sess)
		goto out_free_spoe;

	if ((task = task_new()) == NULL)
		goto out_free_sess;

	if ((strm = stream_new(sess, task, &appctx->obj_type)) == NULL)
		goto out_free_task;

	stream_set_backend(strm, conf->agent->b.be);

	/* applet is waiting for data */
	si_applet_cant_get(&strm->si[0]);
	appctx_wakeup(appctx);

	strm->do_log = NULL;
	strm->res.flags |= CF_READ_DONTWAIT;

	conf->agent_fe.feconn++;
	jobs++;
	totalconn++;

	task_wakeup(SPOE_APPCTX(appctx)->task, TASK_WOKEN_INIT);
	LIST_ADDQ(&conf->agent->applets, &SPOE_APPCTX(appctx)->list);
	conf->agent->applets_act++;
	return appctx;

	/* Error unrolling */
 out_free_task:
	task_free(task);
 out_free_sess:
	session_free(sess);
 out_free_spoe:
	task_free(SPOE_APPCTX(appctx)->task);
 out_free_spoe_appctx:
	pool_free2(pool2_spoe_appctx, SPOE_APPCTX(appctx));
 out_free_appctx:
	appctx_free(appctx);
 out_error:
	return NULL;
}

static int
queue_spoe_context(struct spoe_context *ctx)
{
	struct spoe_config *conf = FLT_CONF(ctx->filter);
	struct spoe_agent  *agent = conf->agent;
	struct appctx      *appctx;
	struct spoe_appctx *spoe_appctx;
	unsigned int        min_applets;

	min_applets = min_applets_act(agent);

	/* Check if we need to create a new SPOE applet or not. */
	if (agent->applets_act >= min_applets && agent->applets_idle && agent->sending_rate)
		goto end;

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
		    " - try to create new SPOE appctx\n",
		    (int)now.tv_sec, (int)now.tv_usec, agent->id, __FUNCTION__,
		    ctx->strm);

	/* Do not try to create a new applet if there is no server up for the
	 * agent's backend. */
	if (!agent->b.be->srv_act && !agent->b.be->srv_bck) {
		SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
			    " - cannot create SPOE appctx: no server up\n",
			    (int)now.tv_sec, (int)now.tv_usec, agent->id,
			    __FUNCTION__, ctx->strm);
		goto end;
	}

	/* Do not try to create a new applet if we have reached the maximum of
	 * connection per seconds */
	if (agent->cps_max > 0) {
		if (!freq_ctr_remain(&agent->conn_per_sec, agent->cps_max, 0)) {
			SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
				    " - cannot create SPOE appctx: max CPS reached\n",
				    (int)now.tv_sec, (int)now.tv_usec, agent->id,
				    __FUNCTION__, ctx->strm);
			goto end;
		}
	}

	appctx = create_spoe_appctx(conf);
	if (appctx == NULL) {
		SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
			    " - failed to create SPOE appctx\n",
			    (int)now.tv_sec, (int)now.tv_usec, agent->id,
			    __FUNCTION__, ctx->strm);
		send_log(ctx->strm->be, LOG_EMERG,
			 "SPOE: [%s] failed to create SPOE applet\n",
			 agent->id);

		goto end;
	}
	if (agent->applets_act <= min_applets)
		SPOE_APPCTX(appctx)->flags |= SPOE_APPCTX_FL_PERSIST;

	/* Increase the per-process number of cumulated connections */
	if (agent->cps_max > 0)
		update_freq_ctr(&agent->conn_per_sec, 1);

  end:
	/* The only reason to return an error is when there is no applet */
	if (LIST_ISEMPTY(&agent->applets)) {
		ctx->status_code = SPOE_CTX_ERR_RES;
		return -1;
	}

	/* Add the SPOE context in the sending queue and update all running
	 * info */
	LIST_ADDQ(&agent->sending_queue, &ctx->list);
	if (agent->sending_rate)
		agent->sending_rate--;

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
		    " - Add stream in sending queue - applets_act=%u - applets_idle=%u"
		    " - sending_rate=%u\n",
		    (int)now.tv_sec, (int)now.tv_usec, agent->id, __FUNCTION__,
		    ctx->strm, agent->applets_act, agent->applets_idle, agent->sending_rate);

	/* Finally try to wakeup the first IDLE applet found and move it at the
	 * end of the list. */
	list_for_each_entry(spoe_appctx, &agent->applets, list) {
		appctx = spoe_appctx->owner;
		if (appctx->st0 == SPOE_APPCTX_ST_IDLE) {
			wakeup_spoe_appctx(appctx);
			LIST_DEL(&spoe_appctx->list);
			LIST_ADDQ(&agent->applets, &spoe_appctx->list);
			break;
		}
	}
	return 1;
}

/***************************************************************************
 * Functions that encode SPOE messages
 **************************************************************************/
static inline int
encode_spoe_arg_string(struct spoe_context *ctx, struct sample *smp,
		       char *p, size_t max_size)
{
	struct chunk *chk = &smp->data.u.str;
	int           idx = 0;

	/* Here, we need to know if the sample has already been partially
	 * encoded. If yes, we only need to encode the remaining, <curoff>
	 * reprensenting the number of bytes already encoded in previous
	 * frames. Else, <curoff> == 0 */

	if (!ctx->frag_ctx.curoff) {
		/* First evaluation of the sample : encode the type (string or
		 * binary) and check its size against <max_size> */

		/* the string/binary length must not exceed 4 Gb. So 5 bytes is
		 * reserved to encode its size. */
		if (max_size < 6)
			return 0;

		p[idx++] = (smp->data.type == SMP_T_STR) ? SPOE_DATA_T_STR : SPOE_DATA_T_BIN;
		max_size -= (idx + 5);

		if (chk->len > max_size) {
			/* The sample is too big, we will fragment it. <curoff>
			 * will be updated accordingly. */
			idx += encode_frag_spoe_string(chk->str, chk->len, max_size, p+idx);
			ctx->frag_ctx.curoff = max_size;
		}
		else {
			/* No fragmentation needed, all the sample is encoded
			 * and <curoff> remains 0 */
			idx += encode_spoe_string(chk->str, chk->len, p+idx);
		}
	}
	else {
		/* Continue the sample fragmentation, the type was already set
		 * in a previous frame. So just do a copy of data. */

		idx = chk->len - ctx->frag_ctx.curoff; /* Remaining data */
		if (idx > max_size) {
			/* The sample still needs to be fragmented. <curoff>
			 * will be incremented accordingly. */
			memcpy(p, chk->str + ctx->frag_ctx.curoff, max_size);
			idx = max_size;
			ctx->frag_ctx.curoff += max_size;
		}
		else {
			/* Finish the fragmentation. <curoff> will be reset. */
			memcpy(p, chk->str + ctx->frag_ctx.curoff, idx);
			ctx->frag_ctx.curoff = 0;
		}
	}
	return idx;
}

static inline int
encode_spoe_arg_method(struct spoe_context *ctx, struct sample *smp,
		       char *p, size_t max_size)
{
	int idx = 0;

	/* method length must not exceed 2288 bytes. So 3 bytes is reserved to
	 * encode its size. */

	if (smp->data.u.meth.meth != HTTP_METH_OTHER) {
		const struct http_method_name *meth =
			&http_known_methods[smp->data.u.meth.meth];

		if (meth->len + 3 > max_size)
			return 0;
		p[idx++] = SPOE_DATA_T_STR;
		idx += encode_spoe_string(meth->name, meth->len, p+idx);
	}
	else {
		struct chunk *meth = &smp->data.u.meth.str;

		if (meth->len + 3 > max_size)
			return 0;
		p[idx++] = SPOE_DATA_T_STR;
		idx += encode_spoe_string(meth->str, meth->len, p+idx);
	}
	return idx;
}

static inline int
encode_spoe_arg_ipv6(struct spoe_context *ctx, struct sample *smp,
		     char *p, size_t max_size)
{
	int idx = 0;

	if (max_size < 17)
		return 0;
	p[idx++] = SPOE_DATA_T_IPV6;
	memcpy(p+idx, &smp->data.u.ipv6, 16);
	idx += 16;
	return idx;
}


static inline int
encode_spoe_arg_ipv4(struct spoe_context *ctx, struct sample *smp,
		     char *p, size_t max_size)
{
	int idx = 0;

	if (max_size < 5)
		return 0;
	p[idx++] = SPOE_DATA_T_IPV4;
	memcpy(p+idx, &smp->data.u.ipv6, 4);
	idx += 4;
	return idx;
}

static inline int
encode_spoe_arg_sint(struct spoe_context *ctx, struct sample *smp,
		     char *p, size_t max_size)
{
	int idx = 0;

	if (max_size < 9)
		return 0;
	p[idx++] = SPOE_DATA_T_INT64;
	idx += encode_spoe_varint(smp->data.u.sint, p+idx);

	return idx;
}

static inline int
encode_spoe_arg_bool(struct spoe_context *ctx, struct sample *smp,
		     char *p, size_t max_size)
{
	int flag, idx = 0;

	if (max_size < 1)
		return 0;
	flag = ((!smp->data.u.sint) ? SPOE_DATA_FL_FALSE : SPOE_DATA_FL_TRUE);
	p[idx++] = (SPOE_DATA_T_BOOL | flag);

	return idx;
}

/* Encode SPOE messages for a specific event.
 *
 *
 * It returns 0 if During the processing, it returns
 * 0 and it returns 1 when the processing is finished. If an error occurred, -1
 * is returned. */
static int
encode_spoe_messages(struct stream *s, struct spoe_context *ctx,
		     struct list *messages, int dir)
{
	struct spoe_config  *conf = FLT_CONF(ctx->filter);
	struct spoe_agent   *agent = conf->agent;
	struct spoe_message *msg;
	struct sample       *smp;
	struct spoe_arg     *arg;
	char    *p;
	size_t  max_size;
	int     r, idx = 0;

	max_size = agent->frame_size - FRAME_HDR_SIZE;

	p = ctx->buffer->p;

	/* Resume encoding of a SPOE message */
	if (ctx->frag_ctx.curmsg != NULL) {
		msg = ctx->frag_ctx.curmsg;
		goto encode_message;
	}

	/* Loop on messages */
	list_for_each_entry(msg, messages, list) {
		ctx->frag_ctx.curmsg = msg;
		ctx->frag_ctx.curarg = NULL;
		ctx->frag_ctx.curoff = UINT_MAX;

	  encode_message:
		/* Resume encoding of a SPOE argument */
		if (ctx->frag_ctx.curarg != NULL) {
			arg = ctx->frag_ctx.curarg;
			goto encode_argument;
		}

		if (ctx->frag_ctx.curoff != UINT_MAX)
			goto encode_msg_payload;

		/* <idx> + <string> + <nb-args>.
		 * Implies <id_len> is encoded on 2 bytes, at most (< 2288). */
		if (idx + 3 + msg->id_len + 1 > max_size)
			goto too_big;

		/* Set the message name */
		idx += encode_spoe_string(msg->id, msg->id_len, p+idx);

		/* Store the number of arguments for this message */
		p[idx++] = msg->nargs;

		ctx->frag_ctx.curoff = 0;
	  encode_msg_payload:

		/* Loop on arguments */
		list_for_each_entry(arg, &msg->args, list) {
			ctx->frag_ctx.curarg = arg;
			ctx->frag_ctx.curoff = UINT_MAX;

		  encode_argument:
			if (ctx->frag_ctx.curoff != UINT_MAX)
				goto encode_arg_value;

			/* <idx> + <string>.
			 * Implies <name_len> is encoded on 2 bytes, at most (< 2288). */
			if (idx + 3 + arg->name_len > max_size)
				goto too_big;

			/* Encode the arguement name as a string. It can by NULL */
			idx += encode_spoe_string(arg->name, arg->name_len, p+idx);

			ctx->frag_ctx.curoff = 0;
		  encode_arg_value:

			if (idx + 1 > max_size)
				goto too_big;

			/* Fetch the arguement value */
			smp = sample_process(s->be, s->sess, s, dir|SMP_OPT_FINAL, arg->expr, NULL);
			if (!smp) {
				/* If no value is available, set it to NULL */
				p[idx++] = SPOE_DATA_T_NULL;
				continue;
			}

			/* Else, encode the arguement value */
			switch (smp->data.type) {
				case SMP_T_BOOL:
					if (!(r = encode_spoe_arg_bool(ctx, smp, p+idx, max_size-idx)))
						goto too_big;
					idx += r;
					break;

				case SMP_T_SINT:
					if (!(r = encode_spoe_arg_sint(ctx, smp, p+idx, max_size-idx)))
						goto too_big;
					idx += r;
					break;

				case SMP_T_IPV4:
					if (!(r = encode_spoe_arg_ipv4(ctx, smp, p+idx, max_size-idx)))
						goto too_big;
					idx += r;
					break;

				case SMP_T_IPV6:
					if (!(r = encode_spoe_arg_ipv6(ctx, smp, p+idx, max_size-idx)))
						goto too_big;
					idx += r;
					break;

				case SMP_T_STR:
				case SMP_T_BIN:
					idx += encode_spoe_arg_string(ctx, smp, p+idx, max_size-idx);
					if (ctx->frag_ctx.curoff)
						goto too_big;
					break;

				case SMP_T_METH:
					if (!(r = encode_spoe_arg_method(ctx, smp, p+idx, max_size-idx)))
						goto too_big;
					idx += r;
					break;

				default:
					p[idx++] = SPOE_DATA_T_NULL;
			}
		}
	}

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
		    " - encode %s messages - spoe_appctx=%p - max_size=%lu - idx=%u\n",
		    (int)now.tv_sec, (int)now.tv_usec,
		    agent->id, __FUNCTION__, s,
		    ((ctx->flags & SPOE_CTX_FL_FRAGMENTED) ? "last fragment of" : "unfragmented"),
		    ctx->frag_ctx.spoe_appctx, max_size, idx);

	ctx->buffer->i = idx;
	ctx->frag_ctx.curmsg = NULL;
	ctx->frag_ctx.curarg = NULL;
	ctx->frag_ctx.curoff = 0;
	ctx->frag_ctx.flags  = SPOE_FRM_FL_FIN;
	return 1;

  too_big:
	// FIXME: if fragmentation not supported =>
	//  ctx->status_code = SPOE_CTX_ERR_TOO_BIG;
	//  return -1;

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
		    " - encode fragmented messages - spoe_appctx=%p - curmsg=%p - curarg=%p - curoff=%u"
		    " - max_size=%lu - idx=%u\n",
		    (int)now.tv_sec, (int)now.tv_usec,
		    agent->id, __FUNCTION__, s, ctx->frag_ctx.spoe_appctx,
		    ctx->frag_ctx.curmsg, ctx->frag_ctx.curarg, ctx->frag_ctx.curoff,
		    max_size, idx);

	ctx->buffer->i = idx;
	ctx->flags |= SPOE_CTX_FL_FRAGMENTED;
	ctx->frag_ctx.flags &= ~SPOE_FRM_FL_FIN;
	return 1;
}


/***************************************************************************
 * Functions that handle SPOE actions
 **************************************************************************/
/* Helper function to set a variable */
static void
set_spoe_var(struct spoe_context *ctx, char *scope, char *name, int len,
	     struct sample *smp)
{
	struct spoe_config *conf = FLT_CONF(ctx->filter);
	struct spoe_agent  *agent = conf->agent;
	char                varname[64];

	memset(varname, 0, sizeof(varname));
	len = snprintf(varname, sizeof(varname), "%s.%s.%.*s",
		       scope, agent->var_pfx, len, name);
	vars_set_by_name_ifexist(varname, len, smp);
}

/* Helper function to unset a variable */
static void
unset_spoe_var(struct spoe_context *ctx, char *scope, char *name, int len,
	       struct sample *smp)
{
	struct spoe_config *conf = FLT_CONF(ctx->filter);
	struct spoe_agent  *agent = conf->agent;
	char                varname[64];

	memset(varname, 0, sizeof(varname));
	len = snprintf(varname, sizeof(varname), "%s.%s.%.*s",
		       scope, agent->var_pfx, len, name);
	vars_unset_by_name_ifexist(varname, len, smp);
}


/* Process SPOE actions for a specific event. During the processing, it returns
 * 0 and it returns 1 when the processing is finished. If an error occurred, -1
 * is returned. */
static int
process_spoe_actions(struct stream *s, struct spoe_context *ctx,
		     enum spoe_event ev, int dir)
{
	char  *p;
	size_t size;
	int    off, i, idx = 0;

	p    = ctx->buffer->p;
	size = ctx->buffer->i;

	while (idx < size)  {
		char                 *str;
		uint64_t              sz;
		struct sample         smp;
		enum spoe_action_type type;

		off = idx;
		if (idx+2 > size)
			goto skip;

		type = p[idx++];
		switch (type) {
			case SPOE_ACT_T_SET_VAR: {
				char *scope;

				if (p[idx++] != 3)
					goto skip_action;

				switch (p[idx++]) {
					case SPOE_SCOPE_PROC: scope = "proc"; break;
					case SPOE_SCOPE_SESS: scope = "sess"; break;
					case SPOE_SCOPE_TXN : scope = "txn";  break;
					case SPOE_SCOPE_REQ : scope = "req";  break;
					case SPOE_SCOPE_RES : scope = "res";  break;
					default: goto skip;
				}

				idx += decode_spoe_string(p+idx, p+size, &str, &sz);
				if (str == NULL)
					goto skip;
				memset(&smp, 0, sizeof(smp));
				smp_set_owner(&smp, s->be, s->sess, s, dir|SMP_OPT_FINAL);

				if ((i = decode_spoe_data(p+idx, p+size, &smp)) == -1)
					goto skip;
				idx += i;

				SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
					    " - set-var '%s.%s.%.*s'\n",
					    (int)now.tv_sec, (int)now.tv_usec,
					    ((struct spoe_config *)FLT_CONF(ctx->filter))->agent->id,
					    __FUNCTION__, s, scope,
					    ((struct spoe_config *)FLT_CONF(ctx->filter))->agent->var_pfx,
					    (int)sz, str);

				set_spoe_var(ctx, scope, str, sz, &smp);
				break;
			}

			case SPOE_ACT_T_UNSET_VAR: {
				char *scope;

				if (p[idx++] != 2)
					goto skip_action;

				switch (p[idx++]) {
					case SPOE_SCOPE_PROC: scope = "proc"; break;
					case SPOE_SCOPE_SESS: scope = "sess"; break;
					case SPOE_SCOPE_TXN : scope = "txn";  break;
					case SPOE_SCOPE_REQ : scope = "req";  break;
					case SPOE_SCOPE_RES : scope = "res";  break;
					default: goto skip;
				}

				idx += decode_spoe_string(p+idx, p+size, &str, &sz);
				if (str == NULL)
					goto skip;
				memset(&smp, 0, sizeof(smp));
				smp_set_owner(&smp, s->be, s->sess, s, dir|SMP_OPT_FINAL);

				SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
					    " - unset-var '%s.%s.%.*s'\n",
					    (int)now.tv_sec, (int)now.tv_usec,
					    ((struct spoe_config *)FLT_CONF(ctx->filter))->agent->id,
					    __FUNCTION__, s, scope,
					    ((struct spoe_config *)FLT_CONF(ctx->filter))->agent->var_pfx,
					    (int)sz, str);

				unset_spoe_var(ctx, scope, str, sz, &smp);
				break;
			}

			default:
			  skip_action:
				if ((i = skip_spoe_action(p+off, p+size)) == -1)
					goto skip;
				idx += i;
		}
	}

	return 1;
  skip:
	return 0;
}

/***************************************************************************
 * Functions that process SPOE events
 **************************************************************************/
static inline int
start_event_processing(struct spoe_context *ctx, int dir)
{
	/* If a process is already started for this SPOE context, retry
	 * later. */
	if (ctx->flags & SPOE_CTX_FL_PROCESS)
		return 0;

	/* Set the right flag to prevent request and response processing
	 * in same time. */
	ctx->flags |= ((dir == SMP_OPT_DIR_REQ)
		       ? SPOE_CTX_FL_REQ_PROCESS
		       : SPOE_CTX_FL_RSP_PROCESS);
	return 1;
}

static inline void
stop_event_processing(struct spoe_context *ctx)
{
	struct spoe_appctx *sa = ctx->frag_ctx.spoe_appctx;

	if (sa) {
		sa->frag_ctx.ctx = NULL;
		wakeup_spoe_appctx(sa->owner);
	}

	/* Reset the flag to allow next processing */
	ctx->flags &= ~(SPOE_CTX_FL_PROCESS|SPOE_CTX_FL_FRAGMENTED);

	ctx->status_code = 0;

	/* Reset processing timer */
	ctx->process_exp = TICK_ETERNITY;

	release_spoe_buffer(&ctx->buffer, &ctx->buffer_wait);

	ctx->frag_ctx.spoe_appctx = NULL;
	ctx->frag_ctx.curmsg      = NULL;
	ctx->frag_ctx.curarg      = NULL;
	ctx->frag_ctx.curoff      = 0;
	ctx->frag_ctx.flags       = 0;

	if (!LIST_ISEMPTY(&ctx->list)) {
		LIST_DEL(&ctx->list);
		LIST_INIT(&ctx->list);
	}
}

/* Process a SPOE event. First, this functions will process messages attached to
 * this event and send them to an agent in a NOTIFY frame. Then, it will wait a
 * ACK frame to process corresponding actions. During all the processing, it
 * returns 0 and it returns 1 when the processing is finished. If an error
 * occurred, -1 is returned. */
static int
process_spoe_event(struct stream *s, struct spoe_context *ctx,
		   enum spoe_event ev)
{
	struct spoe_config *conf = FLT_CONF(ctx->filter);
	struct spoe_agent  *agent = conf->agent;
	int                 dir, ret = 1;

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
		    " - ctx-state=%s - event=%s\n",
		    (int)now.tv_sec, (int)now.tv_usec,
		    agent->id, __FUNCTION__, s, spoe_ctx_state_str[ctx->state],
		    spoe_event_str[ev]);

	dir = ((ev < SPOE_EV_ON_SERVER_SESS) ? SMP_OPT_DIR_REQ : SMP_OPT_DIR_RES);

	if (LIST_ISEMPTY(&(ctx->messages[ev])))
		goto out;

	if (ctx->state == SPOE_CTX_ST_ERROR)
		goto error;

	if (tick_is_expired(ctx->process_exp, now_ms) && ctx->state != SPOE_CTX_ST_DONE) {
		SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
			    " - failed to process event '%s': timeout\n",
			    (int)now.tv_sec, (int)now.tv_usec,
			    agent->id, __FUNCTION__, s, spoe_event_str[ev]);
		ctx->status_code = SPOE_CTX_ERR_TOUT;
		goto error;
	}

	if (ctx->state == SPOE_CTX_ST_READY) {
		if (agent->eps_max > 0) {
			if (!freq_ctr_remain(&agent->err_per_sec, agent->eps_max, 0)) {
				SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
					    " - skip event '%s': max EPS reached\n",
					    (int)now.tv_sec, (int)now.tv_usec,
					    agent->id, __FUNCTION__, s, spoe_event_str[ev]);
				goto skip;
			}
		}

		if (!tick_isset(ctx->process_exp)) {
			ctx->process_exp = tick_add_ifset(now_ms, agent->timeout.processing);
			s->task->expire  = tick_first((tick_is_expired(s->task->expire, now_ms) ? 0 : s->task->expire),
						      ctx->process_exp);
		}
		ret = start_event_processing(ctx, dir);
		if (!ret)
			goto out;

		if (queue_spoe_context(ctx) < 0)
			goto error;

		ctx->state = SPOE_CTX_ST_ENCODING_MSGS;
		/* fall through */
	}

	if (ctx->state == SPOE_CTX_ST_ENCODING_MSGS) {
		if (!acquire_spoe_buffer(&ctx->buffer, &ctx->buffer_wait))
			goto out;
		ret = encode_spoe_messages(s, ctx, &(ctx->messages[ev]), dir);
		if (ret < 0)
			goto error;
		ctx->state = SPOE_CTX_ST_SENDING_MSGS;
	}

	if (ctx->state == SPOE_CTX_ST_SENDING_MSGS) {
		if (ctx->frag_ctx.spoe_appctx)
			wakeup_spoe_appctx(ctx->frag_ctx.spoe_appctx->owner);
		ret = 0;
		goto out;
	}

	if (ctx->state == SPOE_CTX_ST_WAITING_ACK) {
		ret = 0;
		goto out;
	}

	if (ctx->state == SPOE_CTX_ST_DONE) {
		ret = process_spoe_actions(s, ctx, ev, dir);
		if (!ret)
			goto skip;
		ctx->frame_id++;
		ctx->state = SPOE_CTX_ST_READY;
		goto end;
	}

  out:
	return ret;

  error:
	if (agent->eps_max > 0)
		update_freq_ctr(&agent->err_per_sec, 1);

	if (agent->var_on_error) {
		struct sample smp;

		memset(&smp, 0, sizeof(smp));
		smp_set_owner(&smp, s->be, s->sess, s, dir|SMP_OPT_FINAL);
		smp.data.u.sint = ctx->status_code;
		smp.data.type   = SMP_T_BOOL;

		set_spoe_var(ctx, "txn", agent->var_on_error,
			     strlen(agent->var_on_error), &smp);
	}
	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
		    " - failed to create process event '%s': code=%u\n",
		    (int)now.tv_sec, (int)now.tv_usec, agent->id,
		    __FUNCTION__, ctx->strm, spoe_event_str[ev],
		    ctx->status_code);
	send_log(ctx->strm->be, LOG_WARNING,
		 "SPOE: [%s] failed to process event '%s': code=%u\n",
		 agent->id, spoe_event_str[ev], ctx->status_code);

	ctx->state = ((agent->flags & SPOE_FL_CONT_ON_ERR)
		      ? SPOE_CTX_ST_READY
		      : SPOE_CTX_ST_NONE);
	ret = 1;
	goto end;

  skip:
	ctx->state = SPOE_CTX_ST_READY;
	ret = 1;

  end:
	stop_event_processing(ctx);
	return ret;
}

/***************************************************************************
 * Functions that create/destroy SPOE contexts
 **************************************************************************/
static int
acquire_spoe_buffer(struct buffer **buf, struct buffer_wait *buffer_wait)
{
	if (*buf != &buf_empty)
		return 1;

	if (!LIST_ISEMPTY(&buffer_wait->list)) {
		LIST_DEL(&buffer_wait->list);
		LIST_INIT(&buffer_wait->list);
	}

	if (b_alloc_margin(buf, global.tune.reserved_bufs))
		return 1;

	LIST_ADDQ(&buffer_wq, &buffer_wait->list);
	return 0;
}

static void
release_spoe_buffer(struct buffer **buf, struct buffer_wait *buffer_wait)
{
	if (!LIST_ISEMPTY(&buffer_wait->list)) {
		LIST_DEL(&buffer_wait->list);
		LIST_INIT(&buffer_wait->list);
	}

	/* Release the buffer if needed */
	if (*buf != &buf_empty) {
		b_free(buf);
		offer_buffers(buffer_wait->target,
			      tasks_run_queue + applets_active_queue);
	}
}

static int
wakeup_spoe_context(struct spoe_context *ctx)
{
	task_wakeup(ctx->strm->task, TASK_WOKEN_MSG);
	return 1;
}

static struct spoe_context *
create_spoe_context(struct filter *filter)
{
	struct spoe_config  *conf = FLT_CONF(filter);
	struct spoe_context *ctx;

	ctx = pool_alloc_dirty(pool2_spoe_ctx);
	if (ctx == NULL) {
		return NULL;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->filter      = filter;
	ctx->state       = SPOE_CTX_ST_NONE;
	ctx->status_code = SPOE_CTX_ERR_NONE;
	ctx->flags       = 0;
	ctx->messages    = conf->agent->messages;
	ctx->buffer      = &buf_empty;
	LIST_INIT(&ctx->buffer_wait.list);
	ctx->buffer_wait.target = ctx;
	ctx->buffer_wait.wakeup_cb = (int (*)(void *))wakeup_spoe_context;
	LIST_INIT(&ctx->list);

	ctx->stream_id   = 0;
	ctx->frame_id    = 1;
	ctx->process_exp = TICK_ETERNITY;

	return ctx;
}

static void
destroy_spoe_context(struct spoe_context *ctx)
{
	if (!ctx)
		return;

	if (!LIST_ISEMPTY(&ctx->buffer_wait.list))
		LIST_DEL(&ctx->buffer_wait.list);
	if (!LIST_ISEMPTY(&ctx->list))
		LIST_DEL(&ctx->list);
	pool_free2(pool2_spoe_ctx, ctx);
}

static void
reset_spoe_context(struct spoe_context *ctx)
{
	ctx->state  = SPOE_CTX_ST_READY;
	ctx->flags &= ~SPOE_CTX_FL_PROCESS;
}


/***************************************************************************
 * Hooks that manage the filter lifecycle (init/check/deinit)
 **************************************************************************/
/* Signal handler: Do a soft stop, wakeup SPOE applet */
static void
sig_stop_spoe(struct sig_handler *sh)
{
	struct proxy *p;

	p = proxy;
	while (p) {
		struct flt_conf *fconf;

		list_for_each_entry(fconf, &p->filter_configs, list) {
			struct spoe_config *conf;
			struct spoe_agent  *agent;
			struct spoe_appctx *spoe_appctx;

			if (fconf->id != spoe_filter_id)
				continue;

			conf  = fconf->conf;
			agent = conf->agent;

			list_for_each_entry(spoe_appctx, &agent->applets, list) {
				wakeup_spoe_appctx(spoe_appctx->owner);
			}
		}
		p = p->next;
	}
}


/* Initialize the SPOE filter. Returns -1 on error, else 0. */
static int
spoe_init(struct proxy *px, struct flt_conf *fconf)
{
	struct spoe_config *conf = fconf->conf;

        memset(&conf->agent_fe, 0, sizeof(conf->agent_fe));
        init_new_proxy(&conf->agent_fe);
        conf->agent_fe.parent = conf->agent;
        conf->agent_fe.last_change = now.tv_sec;
        conf->agent_fe.id = conf->agent->id;
        conf->agent_fe.cap = PR_CAP_FE;
        conf->agent_fe.mode = PR_MODE_TCP;
        conf->agent_fe.maxconn = 0;
        conf->agent_fe.options2 |= PR_O2_INDEPSTR;
        conf->agent_fe.conn_retries = CONN_RETRIES;
        conf->agent_fe.accept = frontend_accept;
        conf->agent_fe.srv = NULL;
        conf->agent_fe.timeout.client = TICK_ETERNITY;
	conf->agent_fe.default_target = &spoe_applet.obj_type;
	conf->agent_fe.fe_req_ana = AN_REQ_SWITCHING_RULES;

	if (!sighandler_registered) {
		signal_register_fct(0, sig_stop_spoe, 0);
		sighandler_registered = 1;
	}

	return 0;
}

/* Free ressources allocated by the SPOE filter. */
static void
spoe_deinit(struct proxy *px, struct flt_conf *fconf)
{
	struct spoe_config *conf = fconf->conf;

	if (conf) {
		struct spoe_agent *agent = conf->agent;
		struct listener   *l = LIST_NEXT(&conf->agent_fe.conf.listeners,
						 struct listener *, by_fe);

		free(l);
		release_spoe_agent(agent);
		free(conf);
	}
	fconf->conf = NULL;
}

/* Check configuration of a SPOE filter for a specified proxy.
 * Return 1 on error, else 0. */
static int
spoe_check(struct proxy *px, struct flt_conf *fconf)
{
	struct spoe_config *conf = fconf->conf;
	struct proxy       *target;

	target = proxy_be_by_name(conf->agent->b.name);
	if (target == NULL) {
		Alert("Proxy %s : unknown backend '%s' used by SPOE agent '%s'"
		      " declared at %s:%d.\n",
		      px->id, conf->agent->b.name, conf->agent->id,
		      conf->agent->conf.file, conf->agent->conf.line);
		return 1;
	}
	if (target->mode != PR_MODE_TCP) {
		Alert("Proxy %s : backend '%s' used by SPOE agent '%s' declared"
		      " at %s:%d does not support HTTP mode.\n",
		      px->id, target->id, conf->agent->id,
		      conf->agent->conf.file, conf->agent->conf.line);
		return 1;
	}

	free(conf->agent->b.name);
	conf->agent->b.name = NULL;
	conf->agent->b.be = target;
	return 0;
}

/**************************************************************************
 * Hooks attached to a stream
 *************************************************************************/
/* Called when a filter instance is created and attach to a stream. It creates
 * the context that will be used to process this stream. */
static int
spoe_start(struct stream *s, struct filter *filter)
{
	struct spoe_config  *conf  = FLT_CONF(filter);
	struct spoe_agent   *agent = conf->agent;
	struct spoe_context *ctx;

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p\n",
		    (int)now.tv_sec, (int)now.tv_usec, agent->id,
		    __FUNCTION__, s);

	ctx = create_spoe_context(filter);
	if (ctx == NULL) {
		SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p"
			    " - failed to create SPOE context\n",
			    (int)now.tv_sec, (int)now.tv_usec, agent->id,
			    __FUNCTION__, ctx->strm);
		send_log(s->be, LOG_EMERG,
			 "SPOE: [%s] failed to create SPOE context\n",
			 agent->id);
		return 0;
	}

	ctx->strm   = s;
	ctx->state  = SPOE_CTX_ST_READY;
	filter->ctx = ctx;

	if (!LIST_ISEMPTY(&ctx->messages[SPOE_EV_ON_TCP_REQ_FE]))
		filter->pre_analyzers |= AN_REQ_INSPECT_FE;

	if (!LIST_ISEMPTY(&ctx->messages[SPOE_EV_ON_TCP_REQ_BE]))
		filter->pre_analyzers |= AN_REQ_INSPECT_BE;

	if (!LIST_ISEMPTY(&ctx->messages[SPOE_EV_ON_TCP_RSP]))
		filter->pre_analyzers |= AN_RES_INSPECT;

	if (!LIST_ISEMPTY(&ctx->messages[SPOE_EV_ON_HTTP_REQ_FE]))
		filter->pre_analyzers |= AN_REQ_HTTP_PROCESS_FE;

	if (!LIST_ISEMPTY(&ctx->messages[SPOE_EV_ON_HTTP_REQ_BE]))
		filter->pre_analyzers |= AN_REQ_HTTP_PROCESS_BE;

	if (!LIST_ISEMPTY(&ctx->messages[SPOE_EV_ON_HTTP_RSP]))
		filter->pre_analyzers |= AN_RES_HTTP_PROCESS_FE;

	return 1;
}

/* Called when a filter instance is detached from a stream. It release the
 * attached SPOE context. */
static void
spoe_stop(struct stream *s, struct filter *filter)
{
	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p\n",
		    (int)now.tv_sec, (int)now.tv_usec,
		    ((struct spoe_config *)FLT_CONF(filter))->agent->id,
		    __FUNCTION__, s);
	destroy_spoe_context(filter->ctx);
}


/*
 * Called when the stream is woken up because of expired timer.
 */
static void
spoe_check_timeouts(struct stream *s, struct filter *filter)
{
	struct spoe_context *ctx = filter->ctx;

	if (tick_is_expired(ctx->process_exp, now_ms)) {
		s->pending_events |= TASK_WOKEN_MSG;
		release_spoe_buffer(&ctx->buffer, &ctx->buffer_wait);
	}
}

/* Called when we are ready to filter data on a channel */
static int
spoe_start_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct spoe_context *ctx = filter->ctx;
	int                  ret = 1;

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p - ctx-state=%s"
		    " - ctx-flags=0x%08x\n",
		    (int)now.tv_sec, (int)now.tv_usec,
		    ((struct spoe_config *)FLT_CONF(filter))->agent->id,
		    __FUNCTION__, s, spoe_ctx_state_str[ctx->state], ctx->flags);

	if (ctx->state == SPOE_CTX_ST_NONE)
		goto out;

	if (!(chn->flags & CF_ISRESP)) {
		if (filter->pre_analyzers & AN_REQ_INSPECT_FE)
			chn->analysers |= AN_REQ_INSPECT_FE;
		if (filter->pre_analyzers & AN_REQ_INSPECT_BE)
			chn->analysers |= AN_REQ_INSPECT_BE;

		if (ctx->flags & SPOE_CTX_FL_CLI_CONNECTED)
			goto out;

		ctx->stream_id = s->uniq_id;
		ret = process_spoe_event(s, ctx, SPOE_EV_ON_CLIENT_SESS);
		if (!ret)
			goto out;
		ctx->flags |= SPOE_CTX_FL_CLI_CONNECTED;
	}
	else {
		if (filter->pre_analyzers & SPOE_EV_ON_TCP_RSP)
			chn->analysers |= AN_RES_INSPECT;

		if (ctx->flags & SPOE_CTX_FL_SRV_CONNECTED)
			goto out;

		ret = process_spoe_event(s, ctx, SPOE_EV_ON_SERVER_SESS);
		if (!ret) {
			channel_dont_read(chn);
			channel_dont_close(chn);
			goto out;
		}
		ctx->flags |= SPOE_CTX_FL_SRV_CONNECTED;
	}

  out:
	return ret;
}

/* Called before a processing happens on a given channel */
static int
spoe_chn_pre_analyze(struct stream *s, struct filter *filter,
		     struct channel *chn, unsigned an_bit)
{
	struct spoe_context *ctx = filter->ctx;
	int                  ret = 1;

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p - ctx-state=%s"
		    " - ctx-flags=0x%08x - ana=0x%08x\n",
		    (int)now.tv_sec, (int)now.tv_usec,
		    ((struct spoe_config *)FLT_CONF(filter))->agent->id,
		    __FUNCTION__, s, spoe_ctx_state_str[ctx->state],
		    ctx->flags, an_bit);

	if (ctx->state == SPOE_CTX_ST_NONE)
		goto out;

	switch (an_bit) {
		case AN_REQ_INSPECT_FE:
			ret = process_spoe_event(s, ctx, SPOE_EV_ON_TCP_REQ_FE);
			break;
		case AN_REQ_INSPECT_BE:
			ret = process_spoe_event(s, ctx, SPOE_EV_ON_TCP_REQ_BE);
			break;
		case AN_RES_INSPECT:
			ret = process_spoe_event(s, ctx, SPOE_EV_ON_TCP_RSP);
			break;
		case AN_REQ_HTTP_PROCESS_FE:
			ret = process_spoe_event(s, ctx, SPOE_EV_ON_HTTP_REQ_FE);
			break;
		case AN_REQ_HTTP_PROCESS_BE:
			ret = process_spoe_event(s, ctx, SPOE_EV_ON_HTTP_REQ_BE);
			break;
		case AN_RES_HTTP_PROCESS_FE:
			ret = process_spoe_event(s, ctx, SPOE_EV_ON_HTTP_RSP);
			break;
	}

  out:
	if (!ret) {
                channel_dont_read(chn);
                channel_dont_close(chn);
	}
	return ret;
}

/* Called when the filtering on the channel ends. */
static int
spoe_end_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct spoe_context *ctx = filter->ctx;

	SPOE_PRINTF(stderr, "%d.%06d [SPOE/%-15s] %s: stream=%p - ctx-state=%s"
		    " - ctx-flags=0x%08x\n",
		    (int)now.tv_sec, (int)now.tv_usec,
		    ((struct spoe_config *)FLT_CONF(filter))->agent->id,
		    __FUNCTION__, s, spoe_ctx_state_str[ctx->state], ctx->flags);

	if (!(ctx->flags & SPOE_CTX_FL_PROCESS)) {
		reset_spoe_context(ctx);
	}

	return 1;
}

/********************************************************************
 * Functions that manage the filter initialization
 ********************************************************************/
struct flt_ops spoe_ops = {
	/* Manage SPOE filter, called for each filter declaration */
	.init   = spoe_init,
	.deinit = spoe_deinit,
	.check  = spoe_check,

	/* Handle start/stop of SPOE */
	.attach         = spoe_start,
	.detach         = spoe_stop,
	.check_timeouts = spoe_check_timeouts,

	/* Handle channels activity */
	.channel_start_analyze = spoe_start_analyze,
	.channel_pre_analyze   = spoe_chn_pre_analyze,
	.channel_end_analyze   = spoe_end_analyze,
};


static int
cfg_parse_spoe_agent(const char *file, int linenum, char **args, int kwm)
{
	const char *err;
	int         i, err_code = 0;

	if ((cfg_scope == NULL && curengine != NULL) ||
	    (cfg_scope != NULL && curengine == NULL) ||
	    strcmp(curengine, cfg_scope))
		goto out;

	if (!strcmp(args[0], "spoe-agent")) { /* new spoe-agent section */
		if (!*args[1]) {
			Alert("parsing [%s:%d] : missing name for spoe-agent section.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if (*args[2]) {
			Alert("parsing [%s:%d] : cannot handle unexpected argument '%s'.\n",
			      file, linenum, args[2]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
			      file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (curagent != NULL) {
			Alert("parsing [%s:%d] : another spoe-agent section previously defined.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if ((curagent = calloc(1, sizeof(*curagent))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curagent->id              = strdup(args[1]);

		curagent->conf.file       = strdup(file);
		curagent->conf.line       = linenum;

		curagent->timeout.hello      = TICK_ETERNITY;
		curagent->timeout.idle       = TICK_ETERNITY;
		curagent->timeout.processing = TICK_ETERNITY;

		curagent->engine_id      = NULL;
		curagent->var_pfx        = NULL;
		curagent->var_on_error   = NULL;
		curagent->flags          = 0;
		curagent->cps_max        = 0;
		curagent->eps_max        = 0;
		curagent->max_frame_size = MAX_FRAME_SIZE;
		curagent->min_applets    = 0;
		curagent->max_fpa        = 100;

		for (i = 0; i < SPOE_EV_EVENTS; ++i)
			LIST_INIT(&curagent->messages[i]);

		curagent->frame_size   = curagent->max_frame_size;
		curagent->applets_act  = 0;
		curagent->applets_idle = 0;
		curagent->sending_rate = 0;

		LIST_INIT(&curagent->applets);
		LIST_INIT(&curagent->sending_queue);
		LIST_INIT(&curagent->waiting_queue);
	}
	else if (!strcmp(args[0], "use-backend")) {
		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects a backend name.\n",
			      file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (*args[2]) {
			Alert("parsing [%s:%d] : cannot handle unexpected argument '%s'.\n",
			      file, linenum, args[2]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		free(curagent->b.name);
		curagent->b.name = strdup(args[1]);
	}
	else if (!strcmp(args[0], "messages")) {
		int cur_arg = 1;
		while (*args[cur_arg]) {
			struct spoe_msg_placeholder *mp = NULL;

			list_for_each_entry(mp, &curmps, list) {
				if (!strcmp(mp->id, args[cur_arg])) {
					Alert("parsing [%s:%d]: spoe-message message '%s' already declared.\n",
					      file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}

			if ((mp = calloc(1, sizeof(*mp))) == NULL) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
			mp->id = strdup(args[cur_arg]);
			LIST_ADDQ(&curmps, &mp->list);
			cur_arg++;
		}
	}
	else if (!strcmp(args[0], "timeout")) {
		unsigned int *tv = NULL;
		const char   *res;
		unsigned      timeout;

		if (!*args[1]) {
			Alert("parsing [%s:%d] : 'timeout' expects 'connect', 'idle' and 'ack'.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (!strcmp(args[1], "hello"))
			tv = &curagent->timeout.hello;
		else if (!strcmp(args[1], "idle"))
			tv = &curagent->timeout.idle;
		else if (!strcmp(args[1], "processing"))
			tv = &curagent->timeout.processing;
		else {
			Alert("parsing [%s:%d] : 'timeout' supports 'connect', 'idle' or 'processing' (got %s).\n",
			      file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (!*args[2]) {
			Alert("parsing [%s:%d] : 'timeout %s' expects an integer value (in milliseconds).\n",
			      file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		res = parse_time_err(args[2], &timeout, TIME_UNIT_MS);
		if (res) {
			Alert("parsing [%s:%d] : unexpected character '%c' in 'timeout %s'.\n",
			      file, linenum, *res, args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if (*args[3]) {
			Alert("parsing [%s:%d] : cannot handle unexpected argument '%s'.\n",
			      file, linenum, args[3]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		*tv = MS_TO_TICKS(timeout);
	}
	else if (!strcmp(args[0], "option")) {
		if (!*args[1]) {
                        Alert("parsing [%s:%d]: '%s' expects an option name.\n",
                              file, linenum, args[0]);
                        err_code |= ERR_ALERT | ERR_FATAL;
                        goto out;
                }
		if (!strcmp(args[1], "var-prefix")) {
			char *tmp;

			if (!*args[2]) {
				Alert("parsing [%s:%d]: '%s %s' expects a value.\n",
				      file, linenum, args[0],
				      args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			tmp = args[2];
			while (*tmp) {
				if (!isalnum(*tmp) && *tmp != '_' && *tmp != '.') {
					Alert("parsing [%s:%d]: '%s %s' only supports [a-zA-Z_-.] chars.\n",
					      file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tmp++;
			}
			curagent->var_pfx = strdup(args[2]);
		}
		else if (!strcmp(args[1], "continue-on-error")) {
			if (*args[2]) {
				Alert("parsing [%s:%d] : cannot handle unexpected argument '%s'.\n",
				      file, linenum, args[2]);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
			curagent->flags |= SPOE_FL_CONT_ON_ERR;
		}
		else if (!strcmp(args[1], "set-on-error")) {
			char *tmp;

			if (!*args[2]) {
				Alert("parsing [%s:%d]: '%s %s' expects a value.\n",
				      file, linenum, args[0],
				      args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			tmp = args[2];
			while (*tmp) {
				if (!isalnum(*tmp) && *tmp != '_' && *tmp != '.') {
					Alert("parsing [%s:%d]: '%s %s' only supports [a-zA-Z_-.] chars.\n",
					      file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tmp++;
			}
			curagent->var_on_error = strdup(args[2]);
		}
		else {
			Alert("parsing [%s:%d]: option '%s' is not supported.\n",
			      file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!strcmp(args[0], "maxconnrate")) {
		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n",
                              file, linenum, args[0]);
                        err_code |= ERR_ALERT | ERR_FATAL;
                        goto out;
                }
		if (*args[2]) {
			Alert("parsing [%s:%d] : cannot handle unexpected argument '%s'.\n",
			      file, linenum, args[2]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		curagent->cps_max = atol(args[1]);
	}
	else if (!strcmp(args[0], "maxerrrate")) {
		if (!*args[1]) {
			Alert("parsing [%s:%d] : '%s' expects an integer argument.\n",
                              file, linenum, args[0]);
                        err_code |= ERR_ALERT | ERR_FATAL;
                        goto out;
                }
		if (*args[2]) {
			Alert("parsing [%s:%d] : cannot handle unexpected argument '%s'.\n",
			      file, linenum, args[2]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		curagent->eps_max = atol(args[1]);
	}
	else if (*args[0]) {
		Alert("parsing [%s:%d] : unknown keyword '%s' in spoe-agent section.\n",
		      file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
 out:
	return err_code;
}

static int
cfg_parse_spoe_message(const char *file, int linenum, char **args, int kwm)
{
	struct spoe_message *msg;
	struct spoe_arg     *arg;
	const char          *err;
	char                *errmsg   = NULL;
	int                  err_code = 0;

	if ((cfg_scope == NULL && curengine != NULL) ||
	    (cfg_scope != NULL && curengine == NULL) ||
	    strcmp(curengine, cfg_scope))
		goto out;

	if (!strcmp(args[0], "spoe-message")) { /* new spoe-message section */
		if (!*args[1]) {
			Alert("parsing [%s:%d] : missing name for spoe-message section.\n",
			      file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if (*args[2]) {
			Alert("parsing [%s:%d] : cannot handle unexpected argument '%s'.\n",
			      file, linenum, args[2]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			Alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
			      file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		list_for_each_entry(msg, &curmsgs, list) {
			if (!strcmp(msg->id, args[1])) {
				Alert("parsing [%s:%d]: spoe-message section '%s' has the same"
				      " name as another one declared at %s:%d.\n",
				      file, linenum, args[1], msg->conf.file, msg->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		if ((curmsg = calloc(1, sizeof(*curmsg))) == NULL) {
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curmsg->id = strdup(args[1]);
		curmsg->id_len = strlen(curmsg->id);
		curmsg->event  = SPOE_EV_NONE;
		curmsg->conf.file = strdup(file);
		curmsg->conf.line = linenum;
		curmsg->nargs = 0;
		LIST_INIT(&curmsg->args);
		LIST_ADDQ(&curmsgs, &curmsg->list);
	}
	else if (!strcmp(args[0], "args")) {
		int cur_arg = 1;

		curproxy->conf.args.ctx  = ARGC_SPOE;
		curproxy->conf.args.file = file;
		curproxy->conf.args.line = linenum;
		while (*args[cur_arg]) {
			char *delim = strchr(args[cur_arg], '=');
			int   idx = 0;

			if ((arg = calloc(1, sizeof(*arg))) == NULL) {
				Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			if (!delim) {
				arg->name = NULL;
				arg->name_len  = 0;
				delim = args[cur_arg];
			}
			else {
				arg->name = my_strndup(args[cur_arg], delim - args[cur_arg]);
				arg->name_len = delim - args[cur_arg];
				delim++;
			}
			arg->expr = sample_parse_expr((char*[]){delim, NULL},
						      &idx, file, linenum, &errmsg,
						      &curproxy->conf.args);
			if (arg->expr == NULL) {
				Alert("parsing [%s:%d] : '%s': %s.\n", file, linenum, args[0], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				free(arg->name);
				free(arg);
				goto out;
			}
			curmsg->nargs++;
			LIST_ADDQ(&curmsg->args, &arg->list);
			cur_arg++;
		}
		curproxy->conf.args.file = NULL;
		curproxy->conf.args.line = 0;
	}
	else if (!strcmp(args[0], "event")) {
		if (!*args[1]) {
			Alert("parsing [%s:%d] : missing event name.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if (!strcmp(args[1], spoe_event_str[SPOE_EV_ON_CLIENT_SESS]))
			curmsg->event = SPOE_EV_ON_CLIENT_SESS;
		else if (!strcmp(args[1], spoe_event_str[SPOE_EV_ON_SERVER_SESS]))
			curmsg->event = SPOE_EV_ON_SERVER_SESS;

		else if (!strcmp(args[1], spoe_event_str[SPOE_EV_ON_TCP_REQ_FE]))
			curmsg->event = SPOE_EV_ON_TCP_REQ_FE;
		else if (!strcmp(args[1], spoe_event_str[SPOE_EV_ON_TCP_REQ_BE]))
			curmsg->event = SPOE_EV_ON_TCP_REQ_BE;
		else if (!strcmp(args[1], spoe_event_str[SPOE_EV_ON_TCP_RSP]))
			curmsg->event = SPOE_EV_ON_TCP_RSP;

		else if (!strcmp(args[1], spoe_event_str[SPOE_EV_ON_HTTP_REQ_FE]))
			curmsg->event = SPOE_EV_ON_HTTP_REQ_FE;
		else if (!strcmp(args[1], spoe_event_str[SPOE_EV_ON_HTTP_REQ_BE]))
			curmsg->event = SPOE_EV_ON_HTTP_REQ_BE;
		else if (!strcmp(args[1], spoe_event_str[SPOE_EV_ON_HTTP_RSP]))
			curmsg->event = SPOE_EV_ON_HTTP_RSP;
		else {
			Alert("parsing [%s:%d] : unkown event '%s'.\n",
			      file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
	}
	else if (!*args[0]) {
		Alert("parsing [%s:%d] : unknown keyword '%s' in spoe-message section.\n",
		      file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
 out:
	free(errmsg);
	return err_code;
}

/* Return -1 on error, else 0 */
static int
parse_spoe_flt(char **args, int *cur_arg, struct proxy *px,
                struct flt_conf *fconf, char **err, void *private)
{
	struct list backup_sections;
	struct spoe_config          *conf;
	struct spoe_message         *msg, *msgback;
	struct spoe_msg_placeholder *mp, *mpback;
	char                        *file = NULL, *engine = NULL;
	int                          ret, pos = *cur_arg + 1;

	conf = calloc(1, sizeof(*conf));
	if (conf == NULL) {
		memprintf(err, "%s: out of memory", args[*cur_arg]);
		goto error;
	}
	conf->proxy = px;

	while (*args[pos]) {
		if (!strcmp(args[pos], "config")) {
			if (!*args[pos+1]) {
				memprintf(err, "'%s' : '%s' option without value",
					  args[*cur_arg], args[pos]);
				goto error;
			}
			file = args[pos+1];
			pos += 2;
		}
		else if (!strcmp(args[pos], "engine")) {
			if (!*args[pos+1]) {
				memprintf(err, "'%s' : '%s' option without value",
					  args[*cur_arg], args[pos]);
				goto error;
			}
			engine = args[pos+1];
			pos += 2;
		}
		else {
			memprintf(err, "unknown keyword '%s'", args[pos]);
			goto error;
		}
	}
	if (file == NULL) {
		memprintf(err, "'%s' : missing config file", args[*cur_arg]);
		goto error;
	}

	/* backup sections and register SPOE sections */
	LIST_INIT(&backup_sections);
	cfg_backup_sections(&backup_sections);
	cfg_register_section("spoe-agent",   cfg_parse_spoe_agent);
	cfg_register_section("spoe-message", cfg_parse_spoe_message);

	/* Parse SPOE filter configuration file */
	curengine = engine;
	curproxy  = px;
	curagent  = NULL;
	curmsg    = NULL;
	ret = readcfgfile(file);
	curproxy = NULL;

	/* unregister SPOE sections and restore previous sections */
	cfg_unregister_sections();
	cfg_restore_sections(&backup_sections);

	if (ret == -1) {
		memprintf(err, "Could not open configuration file %s : %s",
			  file, strerror(errno));
		goto error;
	}
	if (ret & (ERR_ABORT|ERR_FATAL)) {
		memprintf(err, "Error(s) found in configuration file %s", file);
		goto error;
	}

	/* Check SPOE agent */
	if (curagent == NULL) {
		memprintf(err, "No SPOE agent found in file %s", file);
		goto error;
	}
	if (curagent->b.name == NULL) {
		memprintf(err, "No backend declared for SPOE agent '%s' declared at %s:%d",
			  curagent->id, curagent->conf.file, curagent->conf.line);
		goto error;
	}
	if (curagent->timeout.hello      == TICK_ETERNITY ||
	    curagent->timeout.idle       == TICK_ETERNITY ||
	    curagent->timeout.processing == TICK_ETERNITY) {
		Warning("Proxy '%s': missing timeouts for SPOE agent '%s' declare at %s:%d.\n"
			"   | While not properly invalid, you will certainly encounter various problems\n"
			"   | with such a configuration. To fix this, please ensure that all following\n"
			"   | timeouts are set to a non-zero value: 'hello', 'idle', 'processing'.\n",
			px->id, curagent->id, curagent->conf.file, curagent->conf.line);
	}
	if (curagent->var_pfx == NULL) {
		char *tmp = curagent->id;

		while (*tmp) {
			if (!isalnum(*tmp) && *tmp != '_' && *tmp != '.') {
				memprintf(err, "Invalid variable prefix '%s' for SPOE agent '%s' declared at %s:%d. "
					  "Use 'option var-prefix' to set it. Only [a-zA-Z0-9_.] chars are supported.\n",
					  curagent->id, curagent->id, curagent->conf.file, curagent->conf.line);
				goto error;
			}
			tmp++;
		}
		curagent->var_pfx = strdup(curagent->id);
	}
	if (curagent->engine_id == NULL)
		curagent->engine_id = generate_pseudo_uuid();

	if (LIST_ISEMPTY(&curmps)) {
		Warning("Proxy '%s': No message used by SPOE agent '%s' declared at %s:%d.\n",
			px->id, curagent->id, curagent->conf.file, curagent->conf.line);
		goto finish;
	}

	list_for_each_entry_safe(mp, mpback, &curmps, list) {
		list_for_each_entry_safe(msg, msgback, &curmsgs, list) {
			struct spoe_arg *arg;
			unsigned int     where;

			if (!strcmp(msg->id, mp->id)) {
				if ((px->cap & (PR_CAP_FE|PR_CAP_BE)) == (PR_CAP_FE|PR_CAP_BE)) {
					if (msg->event == SPOE_EV_ON_TCP_REQ_BE)
						msg->event = SPOE_EV_ON_TCP_REQ_FE;
					if (msg->event == SPOE_EV_ON_HTTP_REQ_BE)
						msg->event = SPOE_EV_ON_HTTP_REQ_FE;
				}
				if (!(px->cap & PR_CAP_FE) && (msg->event == SPOE_EV_ON_CLIENT_SESS ||
							       msg->event == SPOE_EV_ON_TCP_REQ_FE ||
							       msg->event == SPOE_EV_ON_HTTP_REQ_FE)) {
					Warning("Proxy '%s': frontend event used on a backend proxy at %s:%d.\n",
						px->id, msg->conf.file, msg->conf.line);
					goto next;
				}
				if (msg->event == SPOE_EV_NONE) {
					Warning("Proxy '%s': Ignore SPOE message without event at %s:%d.\n",
						px->id, msg->conf.file, msg->conf.line);
					goto next;
				}

				where = 0;
				switch (msg->event) {
					case SPOE_EV_ON_CLIENT_SESS:
						where |= SMP_VAL_FE_CON_ACC;
						break;

					case SPOE_EV_ON_TCP_REQ_FE:
						where |= SMP_VAL_FE_REQ_CNT;
						break;

					case SPOE_EV_ON_HTTP_REQ_FE:
						where |= SMP_VAL_FE_HRQ_HDR;
						break;

					case SPOE_EV_ON_TCP_REQ_BE:
						if (px->cap & PR_CAP_FE)
							where |= SMP_VAL_FE_REQ_CNT;
						if (px->cap & PR_CAP_BE)
							where |= SMP_VAL_BE_REQ_CNT;
						break;

					case SPOE_EV_ON_HTTP_REQ_BE:
						if (px->cap & PR_CAP_FE)
							where |= SMP_VAL_FE_HRQ_HDR;
						if (px->cap & PR_CAP_BE)
							where |= SMP_VAL_BE_HRQ_HDR;
						break;

					case SPOE_EV_ON_SERVER_SESS:
						where |= SMP_VAL_BE_SRV_CON;
						break;

					case SPOE_EV_ON_TCP_RSP:
						if (px->cap & PR_CAP_FE)
							where |= SMP_VAL_FE_RES_CNT;
						if (px->cap & PR_CAP_BE)
							where |= SMP_VAL_BE_RES_CNT;
						break;

					case SPOE_EV_ON_HTTP_RSP:
						if (px->cap & PR_CAP_FE)
							where |= SMP_VAL_FE_HRS_HDR;
						if (px->cap & PR_CAP_BE)
							where |= SMP_VAL_BE_HRS_HDR;
						break;

					default:
						break;
				}

				list_for_each_entry(arg, &msg->args, list) {
					if (!(arg->expr->fetch->val & where)) {
						Warning("Proxy '%s': Ignore SPOE message at %s:%d: "
							"some args extract information from '%s', "
							"none of which is available here ('%s').\n",
							px->id, msg->conf.file, msg->conf.line,
							sample_ckp_names(arg->expr->fetch->use),
							sample_ckp_names(where));
						goto next;
					}
				}

				msg->agent = curagent;
				LIST_DEL(&msg->list);
				LIST_ADDQ(&curagent->messages[msg->event], &msg->list);
				goto next;
			}
		}
		memprintf(err, "SPOE agent '%s' try to use undefined SPOE message '%s' at %s:%d",
			  curagent->id, mp->id, curagent->conf.file, curagent->conf.line);
		goto error;
	  next:
		continue;
	}

 finish:
	conf->agent = curagent;
	list_for_each_entry_safe(mp, mpback, &curmps, list) {
		LIST_DEL(&mp->list);
		release_spoe_msg_placeholder(mp);
	}
	list_for_each_entry_safe(msg, msgback, &curmsgs, list) {
		Warning("Proxy '%s': Ignore unused SPOE messages '%s' declared at %s:%d.\n",
			px->id, msg->id, msg->conf.file, msg->conf.line);
		LIST_DEL(&msg->list);
		release_spoe_message(msg);
	}

	*cur_arg    = pos;
	fconf->id   = spoe_filter_id;
	fconf->ops  = &spoe_ops;
	fconf->conf = conf;
	return 0;

 error:
	release_spoe_agent(curagent);
	list_for_each_entry_safe(mp, mpback, &curmps, list) {
		LIST_DEL(&mp->list);
		release_spoe_msg_placeholder(mp);
	}
	list_for_each_entry_safe(msg, msgback, &curmsgs, list) {
		LIST_DEL(&msg->list);
		release_spoe_message(msg);
	}
	free(conf);
	return -1;
}


/* Declare the filter parser for "spoe" keyword */
static struct flt_kw_list flt_kws = { "SPOE", { }, {
		{ "spoe", parse_spoe_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

__attribute__((constructor))
static void __spoe_init(void)
{
	flt_register_keywords(&flt_kws);

	LIST_INIT(&curmsgs);
	LIST_INIT(&curmps);
	pool2_spoe_ctx = create_pool("spoe_ctx", sizeof(struct spoe_context), MEM_F_SHARED);
	pool2_spoe_appctx = create_pool("spoe_appctx", sizeof(struct spoe_appctx), MEM_F_SHARED);
}

__attribute__((destructor))
static void
__spoe_deinit(void)
{
	pool_destroy2(pool2_spoe_ctx);
	pool_destroy2(pool2_spoe_appctx);
}
