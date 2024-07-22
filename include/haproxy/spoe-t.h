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

struct spop_version {
	char *str;
	int   min;
	int   max;
};

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

/* Describe a SPOE agent. */
struct spoe_agent {
	char                 *id;             /* SPOE agent id (name) */
        struct {
                char         *file;           /* file where the SPOE agent appears */
                int           line;           /* line where the SPOE agent appears */
        } conf;                               /* config information */
	struct proxy       fe;                /* Agent frontend */
	union {
		struct proxy *be;             /* Backend used by this agent */
		char         *name;           /* Backend name used during conf parsing */
	} b;
	struct {
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

#endif /* _HAPROXY_SPOE_T_H */
